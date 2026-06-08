mod codex_transform;
mod error;
mod filesystem;
mod helper;
mod process;
mod responses;
mod shell_effects;

#[cfg(test)]
pub(super) use codex_transform::codex_linux_sandbox_transform_for_test;
pub(super) use error::LinuxRunError;
#[cfg(test)]
pub(super) use filesystem::build_bwrap_args;
pub(crate) use helper::codex_linux_sandbox_path;

use raxcell_protocol::{
    BackendFamily, BackendLoweringArtifact, Denial, DenialCode, FileSystemLoweringReport,
    LoweredRoot, PrepareRunResponse, ProbeResponse, RunRequest, RunResponse,
};
use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use wait_timeout::ChildExt;

use codex_transform::codex_linux_sandbox_transform;
use error::{make_environment_gap, sandbox_denied};
use filesystem::{filesystem_lowering_report, runtime_roots_report};
use helper::{
    codex_linux_sandbox_artifact, transformed_sandbox_command, validate_codex_linux_sandbox_helper,
};
use process::{kill_child_process_group, put_child_in_new_process_group, timeout_duration};
use responses::{
    fail, fail_environment_gap, fail_policy_decision_required, fail_prepare,
    fail_prepare_environment_gap, fail_prepare_from_linux_error,
    fail_prepare_policy_decision_required,
};
use shell_effects::{reject_unresolved_dynamic_redirect_paths, require_shell_effect_grants};

struct ExecutionOutput {
    output: std::process::Output,
    timed_out: bool,
    filesystem_lowering: FileSystemLoweringReport,
    backend_artifacts: Vec<BackendLoweringArtifact>,
}

struct PrepareOutput {
    filesystem_lowering: FileSystemLoweringReport,
    backend_artifacts: Vec<BackendLoweringArtifact>,
}

pub fn run(request: RunRequest, capability_report: ProbeResponse) -> RunResponse {
    if !cfg!(target_os = "linux") {
        return fail_environment_gap(
            request,
            capability_report,
            DenialCode::CapabilityMismatch,
            make_environment_gap(
                "host-platform-mismatch",
                None,
                vec!["platform.linux"],
                "linux-bubblewrap can only run on Linux hosts",
            ),
        );
    }
    let Ok(helper_path) = codex_linux_sandbox_path() else {
        return fail_environment_gap(
            request,
            capability_report,
            DenialCode::BackendUnavailable,
            make_environment_gap(
                "missing-backend-dependency",
                Some("codex-linux-sandbox"),
                vec!["dependency.binary.codex-linux-sandbox"],
                "linux-bubblewrap requires the `codex-linux-sandbox` helper",
            ),
        );
    };
    let Ok(_) = which::which("bwrap") else {
        return fail_environment_gap(
            request,
            capability_report,
            DenialCode::BackendUnavailable,
            make_environment_gap(
                "missing-backend-dependency",
                Some("dependency.binary.bwrap"),
                vec!["dependency.binary.bwrap"],
                "codex-linux-sandbox requires the `bwrap` binary",
            ),
        );
    };
    if !capability_report.ready {
        return fail_environment_gap(
            request,
            capability_report,
            DenialCode::CapabilityMismatch,
            make_environment_gap(
                "backend-capability-gap",
                None,
                vec!["backend.ready"],
                "linux-bubblewrap capability probe is not ready",
            ),
        );
    }

    run_with_helper_path(request, capability_report, &helper_path)
}

#[cfg(test)]
pub(super) fn run_with_helper_path_for_test(
    request: RunRequest,
    capability_report: ProbeResponse,
    helper_path: &Path,
) -> RunResponse {
    run_with_helper_path(request, capability_report, helper_path)
}

#[cfg(test)]
pub(super) fn prepare_run_with_helper_path_for_test(
    request: RunRequest,
    capability_report: ProbeResponse,
    helper_path: &Path,
) -> PrepareRunResponse {
    if let Err(error) = prepare_static_policy_check(&request) {
        return fail_prepare_from_linux_error(
            request,
            capability_report,
            error,
            DenialCode::CapabilityMismatch,
        );
    }
    if let Err(error) = validate_codex_linux_sandbox_helper(helper_path) {
        return fail_prepare_from_linux_error(
            request,
            capability_report,
            error,
            DenialCode::BackendUnavailable,
        );
    }
    match prepare_inner(&request, helper_path) {
        Ok(prepared) => PrepareRunResponse {
            kind: "raxcell.prepareRunResult.v1".to_string(),
            ok: true,
            backend: Some(BackendFamily::LinuxBubblewrap),
            denial: None,
            environment_gap: None,
            policy_decision: None,
            filesystem_lowering: Some(prepared.filesystem_lowering),
            backend_artifacts: prepared.backend_artifacts,
            capability_report: Some(capability_report),
        },
        Err(LinuxRunError::SandboxDenied(message)) => fail_prepare(
            request,
            capability_report,
            DenialCode::SandboxDenied,
            message,
        ),
        Err(LinuxRunError::EnvironmentGap(gap)) => fail_prepare_environment_gap(
            request,
            capability_report,
            DenialCode::CapabilityMismatch,
            gap,
        ),
        Err(LinuxRunError::PolicyDecisionRequired(decision)) => {
            fail_prepare_policy_decision_required(request, capability_report, decision)
        }
    }
}

fn run_with_helper_path(
    request: RunRequest,
    capability_report: ProbeResponse,
    helper_path: &Path,
) -> RunResponse {
    if let Err(error) = validate_codex_linux_sandbox_helper(helper_path) {
        return match error {
            LinuxRunError::EnvironmentGap(gap) => fail_environment_gap(
                request,
                capability_report,
                DenialCode::BackendUnavailable,
                gap,
            ),
            LinuxRunError::SandboxDenied(message) => fail(
                request,
                capability_report,
                DenialCode::SandboxDenied,
                message,
            ),
            LinuxRunError::PolicyDecisionRequired(decision) => {
                fail_policy_decision_required(request, capability_report, decision)
            }
        };
    }
    match run_inner(&request, helper_path) {
        Ok(execution) => {
            let denial = if execution.timed_out {
                Some(Denial {
                    code: DenialCode::Timeout,
                    message: format!(
                        "sandboxed command timed out; actionId={}",
                        request.action.action_id
                    ),
                    public_safe: true,
                })
            } else {
                None
            };
            RunResponse {
                kind: "raxcell.runResult.v1".to_string(),
                ok: !execution.timed_out,
                backend: Some(BackendFamily::LinuxBubblewrap),
                exit_code: execution.output.status.code(),
                stdout: String::from_utf8_lossy(&execution.output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&execution.output.stderr).into_owned(),
                timed_out: execution.timed_out,
                denial,
                environment_gap: None,
                policy_decision: None,
                filesystem_lowering: Some(execution.filesystem_lowering),
                backend_artifacts: execution.backend_artifacts,
                fallback: None,
                capability_report: Some(capability_report),
            }
        }
        Err(LinuxRunError::SandboxDenied(message)) => fail(
            request,
            capability_report,
            DenialCode::SandboxDenied,
            message,
        ),
        Err(LinuxRunError::EnvironmentGap(gap)) => fail_environment_gap(
            request,
            capability_report,
            DenialCode::CapabilityMismatch,
            gap,
        ),
        Err(LinuxRunError::PolicyDecisionRequired(decision)) => {
            fail_policy_decision_required(request, capability_report, decision)
        }
    }
}

pub fn prepare_run(request: RunRequest, capability_report: ProbeResponse) -> PrepareRunResponse {
    if !cfg!(target_os = "linux") {
        return fail_prepare_environment_gap(
            request,
            capability_report,
            DenialCode::CapabilityMismatch,
            make_environment_gap(
                "host-platform-mismatch",
                None,
                vec!["platform.linux"],
                "linux-bubblewrap can only prepare on Linux hosts",
            ),
        );
    }
    if let Err(error) = prepare_static_policy_check(&request) {
        return fail_prepare_from_linux_error(
            request,
            capability_report,
            error,
            DenialCode::CapabilityMismatch,
        );
    }
    let Ok(helper_path) = codex_linux_sandbox_path() else {
        return fail_prepare_environment_gap(
            request,
            capability_report,
            DenialCode::BackendUnavailable,
            make_environment_gap(
                "missing-backend-dependency",
                Some("codex-linux-sandbox"),
                vec!["dependency.binary.codex-linux-sandbox"],
                "linux-bubblewrap prepare requires the `codex-linux-sandbox` helper",
            ),
        );
    };
    let Ok(_) = which::which("bwrap") else {
        return fail_prepare_environment_gap(
            request,
            capability_report,
            DenialCode::BackendUnavailable,
            make_environment_gap(
                "missing-backend-dependency",
                Some("dependency.binary.bwrap"),
                vec!["dependency.binary.bwrap"],
                "codex-linux-sandbox prepare requires the `bwrap` binary",
            ),
        );
    };
    if !capability_report.ready {
        return fail_prepare_environment_gap(
            request,
            capability_report,
            DenialCode::CapabilityMismatch,
            make_environment_gap(
                "backend-capability-gap",
                None,
                vec!["backend.ready"],
                "linux-bubblewrap capability probe is not ready",
            ),
        );
    }
    if let Err(error) = validate_codex_linux_sandbox_helper(&helper_path) {
        return fail_prepare_from_linux_error(
            request,
            capability_report,
            error,
            DenialCode::BackendUnavailable,
        );
    }

    match prepare_inner(&request, &helper_path) {
        Ok(prepared) => PrepareRunResponse {
            kind: "raxcell.prepareRunResult.v1".to_string(),
            ok: true,
            backend: Some(BackendFamily::LinuxBubblewrap),
            denial: None,
            environment_gap: None,
            policy_decision: None,
            filesystem_lowering: Some(prepared.filesystem_lowering),
            backend_artifacts: prepared.backend_artifacts,
            capability_report: Some(capability_report),
        },
        Err(LinuxRunError::SandboxDenied(message)) => fail_prepare(
            request,
            capability_report,
            DenialCode::SandboxDenied,
            message,
        ),
        Err(LinuxRunError::EnvironmentGap(gap)) => fail_prepare_environment_gap(
            request,
            capability_report,
            DenialCode::CapabilityMismatch,
            gap,
        ),
        Err(LinuxRunError::PolicyDecisionRequired(decision)) => {
            fail_prepare_policy_decision_required(request, capability_report, decision)
        }
    }
}

pub(crate) fn explain_runtime_roots() -> Vec<LoweredRoot> {
    runtime_roots_report(&[])
}

fn run_inner(request: &RunRequest, helper_path: &Path) -> Result<ExecutionOutput, LinuxRunError> {
    let argv = &request.command.argv;
    if argv.first().is_none() {
        return Err(sandbox_denied(
            "command argv must contain at least one item",
        ));
    };

    let cwd = std::fs::canonicalize(&request.command.cwd)
        .map_err(|err| sandbox_denied(format!("failed to resolve command cwd: {err}")))?;
    let transformed = codex_linux_sandbox_transform(request, helper_path, &cwd)?;
    let backend_artifacts = vec![codex_linux_sandbox_artifact(&transformed.command)];
    let mut command = transformed_sandbox_command(&transformed.command);
    command.args(&transformed.command.args);
    command.current_dir(&transformed.command.cwd);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    command.env_clear();
    if request.command.stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    for (key, value) in &transformed.command.env {
        command.env(key, value);
    }
    put_child_in_new_process_group(&mut command);

    let mut child = command.spawn().map_err(|err| {
        sandbox_denied(format!("failed to spawn linux-bubblewrap backend: {err}"))
    })?;
    if let Some(stdin) = &request.command.stdin
        && let Some(mut child_stdin) = child.stdin.take()
    {
        child_stdin
            .write_all(stdin.as_bytes())
            .map_err(|err| sandbox_denied(format!("failed to write command stdin: {err}")))?;
    }
    if let Some(timeout) = timeout_duration(request)? {
        match child.wait_timeout(timeout).map_err(|err| {
            sandbox_denied(format!(
                "failed to wait for sandboxed command timeout: {err}"
            ))
        })? {
            Some(_) => {
                return child
                    .wait_with_output()
                    .map(|output| ExecutionOutput {
                        output,
                        timed_out: false,
                        filesystem_lowering: transformed.filesystem_lowering,
                        backend_artifacts: backend_artifacts.clone(),
                    })
                    .map_err(|err| {
                        sandbox_denied(format!("failed to collect sandboxed command output: {err}"))
                    });
            }
            None => {
                kill_child_process_group(&mut child).map_err(|err| {
                    sandbox_denied(format!("failed to kill timed out sandboxed command: {err}"))
                })?;
                return child
                    .wait_with_output()
                    .map(|output| ExecutionOutput {
                        output,
                        timed_out: true,
                        filesystem_lowering: transformed.filesystem_lowering,
                        backend_artifacts: backend_artifacts.clone(),
                    })
                    .map_err(|err| {
                        sandbox_denied(format!(
                            "failed to collect timed out sandboxed command output: {err}"
                        ))
                    });
            }
        }
    }
    child
        .wait_with_output()
        .map(|output| ExecutionOutput {
            output,
            timed_out: false,
            filesystem_lowering: transformed.filesystem_lowering,
            backend_artifacts,
        })
        .map_err(|err| sandbox_denied(format!("failed to wait for sandboxed command: {err}")))
}

fn prepare_inner(request: &RunRequest, helper_path: &Path) -> Result<PrepareOutput, LinuxRunError> {
    let cwd = std::fs::canonicalize(&request.command.cwd)
        .map_err(|err| sandbox_denied(format!("failed to resolve command cwd: {err}")))?;
    let transformed = codex_linux_sandbox_transform(request, helper_path, &cwd)?;
    Ok(PrepareOutput {
        filesystem_lowering: transformed.filesystem_lowering,
        backend_artifacts: vec![codex_linux_sandbox_artifact(&transformed.command)],
    })
}

fn prepare_static_policy_check(request: &RunRequest) -> Result<(), LinuxRunError> {
    let cwd = std::fs::canonicalize(&request.command.cwd)
        .map_err(|err| sandbox_denied(format!("failed to resolve command cwd: {err}")))?;
    reject_unresolved_dynamic_redirect_paths(&request.command.argv)?;
    let filesystem_lowering = filesystem_lowering_report(request, &cwd)?;
    require_shell_effect_grants(request, &cwd, &filesystem_lowering)
}
