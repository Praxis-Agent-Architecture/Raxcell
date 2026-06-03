use raxcell_protocol::{
    BackendFamily, BackendLoweringArtifact, Denial, DenialCode, FileSystemLoweringReport,
    LoweredRoot, LoweredRootAccess, LoweredRootSource, PolicyDecisionRequired, PrepareRunResponse,
    ProbeResponse, RunRequest, RunResponse,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

struct ExecutionOutput {
    output: std::process::Output,
    timed_out: bool,
    filesystem_lowering: FileSystemLoweringReport,
}

struct PrepareOutput {
    filesystem_lowering: FileSystemLoweringReport,
    backend_artifacts: Vec<BackendLoweringArtifact>,
}

#[derive(Debug)]
pub(super) enum LinuxRunError {
    SandboxDenied(String),
    PolicyDecisionRequired(PolicyDecisionRequired),
}

pub fn run(request: RunRequest, capability_report: ProbeResponse) -> RunResponse {
    if !cfg!(target_os = "linux") {
        return fail(
            request,
            capability_report,
            DenialCode::CapabilityMismatch,
            "linux-bubblewrap can only run on Linux hosts".to_string(),
        );
    }
    let Ok(bwrap_path) = which::which("bwrap") else {
        return fail(
            request,
            capability_report,
            DenialCode::BackendUnavailable,
            "linux-bubblewrap requires the `bwrap` binary".to_string(),
        );
    };
    if !capability_report.ready {
        return fail(
            request,
            capability_report,
            DenialCode::CapabilityMismatch,
            "linux-bubblewrap capability probe is not ready".to_string(),
        );
    }

    match run_inner(&request, &bwrap_path) {
        Ok(execution) => RunResponse {
            kind: "raxcell.runResult.v1".to_string(),
            ok: execution.output.status.success() && !execution.timed_out,
            backend: Some(BackendFamily::LinuxBubblewrap),
            exit_code: execution.output.status.code(),
            stdout: String::from_utf8_lossy(&execution.output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&execution.output.stderr).into_owned(),
            timed_out: execution.timed_out,
            denial: if execution.output.status.success() && !execution.timed_out {
                None
            } else if execution.timed_out {
                Some(Denial {
                    code: DenialCode::Timeout,
                    message: format!(
                        "sandboxed command timed out; actionId={}",
                        request.action.action_id
                    ),
                    public_safe: true,
                })
            } else {
                Some(Denial {
                    code: DenialCode::ExecutionFailed,
                    message: format!(
                        "sandboxed command exited unsuccessfully; actionId={}",
                        request.action.action_id
                    ),
                    public_safe: true,
                })
            },
            policy_decision: None,
            filesystem_lowering: Some(execution.filesystem_lowering),
            fallback: None,
            capability_report: Some(capability_report),
        },
        Err(LinuxRunError::SandboxDenied(message)) => fail(
            request,
            capability_report,
            DenialCode::SandboxDenied,
            message,
        ),
        Err(LinuxRunError::PolicyDecisionRequired(decision)) => {
            fail_policy_decision_required(request, capability_report, decision)
        }
    }
}

pub fn prepare_run(request: RunRequest, capability_report: ProbeResponse) -> PrepareRunResponse {
    if !cfg!(target_os = "linux") {
        return fail_prepare(
            request,
            capability_report,
            DenialCode::CapabilityMismatch,
            "linux-bubblewrap can only prepare on Linux hosts".to_string(),
        );
    }
    let Ok(bwrap_path) = which::which("bwrap") else {
        return fail_prepare(
            request,
            capability_report,
            DenialCode::BackendUnavailable,
            "linux-bubblewrap prepare requires the `bwrap` binary".to_string(),
        );
    };
    if !capability_report.ready {
        return fail_prepare(
            request,
            capability_report,
            DenialCode::CapabilityMismatch,
            "linux-bubblewrap capability probe is not ready".to_string(),
        );
    }

    match prepare_inner(&request, &bwrap_path) {
        Ok(prepared) => PrepareRunResponse {
            kind: "raxcell.prepareRunResult.v1".to_string(),
            ok: true,
            backend: Some(BackendFamily::LinuxBubblewrap),
            denial: None,
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
        Err(LinuxRunError::PolicyDecisionRequired(decision)) => {
            fail_prepare_policy_decision_required(request, capability_report, decision)
        }
    }
}

pub(crate) fn explain_runtime_roots() -> Vec<LoweredRoot> {
    runtime_roots_report(&[])
}

fn run_inner(request: &RunRequest, bwrap_path: &Path) -> Result<ExecutionOutput, LinuxRunError> {
    let argv = &request.command.argv;
    let Some(program) = argv.first() else {
        return Err(sandbox_denied(
            "command argv must contain at least one item",
        ));
    };

    let cwd = std::fs::canonicalize(&request.command.cwd)
        .map_err(|err| sandbox_denied(format!("failed to resolve command cwd: {err}")))?;
    let (args, filesystem_lowering) = build_bwrap_args(request, &cwd)?;
    let mut command = Command::new(bwrap_path);
    command.args(args);
    command.arg(program);
    command.args(argv.iter().skip(1));
    command.current_dir(&cwd);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    command.env_clear();
    if request.command.stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    for (key, value) in &request.command.env {
        command.env(key, value);
    }

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
                        filesystem_lowering,
                    })
                    .map_err(|err| {
                        sandbox_denied(format!("failed to collect sandboxed command output: {err}"))
                    });
            }
            None => {
                child.kill().map_err(|err| {
                    sandbox_denied(format!("failed to kill timed out sandboxed command: {err}"))
                })?;
                return child
                    .wait_with_output()
                    .map(|output| ExecutionOutput {
                        output,
                        timed_out: true,
                        filesystem_lowering,
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
            filesystem_lowering,
        })
        .map_err(|err| sandbox_denied(format!("failed to wait for sandboxed command: {err}")))
}

fn prepare_inner(request: &RunRequest, bwrap_path: &Path) -> Result<PrepareOutput, LinuxRunError> {
    let cwd = std::fs::canonicalize(&request.command.cwd)
        .map_err(|err| sandbox_denied(format!("failed to resolve command cwd: {err}")))?;
    let (args, filesystem_lowering) = build_bwrap_args(request, &cwd)?;
    Ok(PrepareOutput {
        filesystem_lowering,
        backend_artifacts: vec![bubblewrap_artifact(bwrap_path, args)],
    })
}

fn bubblewrap_artifact(bwrap_path: &Path, args: Vec<OsString>) -> BackendLoweringArtifact {
    let mut data = BTreeMap::new();
    data.insert(
        "executable".to_string(),
        serde_json::json!(bwrap_path.to_string_lossy()),
    );
    BackendLoweringArtifact {
        backend: BackendFamily::LinuxBubblewrap,
        format: "linux-bubblewrap-argv".to_string(),
        arguments: args
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect(),
        data,
        warnings: Vec::new(),
    }
}

pub(super) fn build_bwrap_args(
    request: &RunRequest,
    cwd: &Path,
) -> Result<(Vec<OsString>, FileSystemLoweringReport), LinuxRunError> {
    let mut args = vec![OsString::from("--die-with-parent")];
    if request.enforcement.network.as_deref() == Some("deny") {
        args.push(OsString::from("--unshare-net"));
    }

    let mounts = filesystem_mounts(request, cwd)?;
    bind_runtime_paths(&mut args);
    args.push(OsString::from("--dev"));
    args.push(OsString::from("/dev"));
    args.push(OsString::from("--proc"));
    args.push(OsString::from("/proc"));
    args.push(OsString::from("--tmpfs"));
    args.push(OsString::from("/tmp"));
    for root in mounts.read_roots {
        if mounts
            .write_roots
            .iter()
            .any(|write_root| write_root == &root)
        {
            continue;
        }
        args.push(OsString::from("--ro-bind"));
        args.push(root.as_os_str().to_os_string());
        args.push(root.as_os_str().to_os_string());
    }
    for root in mounts.write_roots {
        args.push(OsString::from("--bind"));
        args.push(root.as_os_str().to_os_string());
        args.push(root.as_os_str().to_os_string());
    }
    args.push(OsString::from("--chdir"));
    args.push(cwd.as_os_str().to_os_string());
    Ok((args, mounts.report))
}

struct FilesystemMounts {
    read_roots: Vec<PathBuf>,
    write_roots: Vec<PathBuf>,
    report: FileSystemLoweringReport,
}

fn filesystem_mounts(request: &RunRequest, cwd: &Path) -> Result<FilesystemMounts, LinuxRunError> {
    let mut read_roots = canonical_roots(request, "read")?;
    let mut write_roots = canonical_roots(request, "write")?;
    let grant_roots = if is_covered(cwd, &read_roots) || is_covered(cwd, &write_roots) {
        Vec::new()
    } else {
        apply_cwd_grants(request, cwd, &mut read_roots, &mut write_roots)?
    };
    let (read_roots, write_roots) = normalize_mount_roots(read_roots, write_roots);
    if !is_covered(cwd, &read_roots) && !is_covered(cwd, &write_roots) {
        return Err(LinuxRunError::PolicyDecisionRequired(PolicyDecisionRequired {
            reason: "cwd-outside-declared-roots".to_string(),
            path: cwd.to_string_lossy().into_owned(),
            required: vec!["filesystem.read".to_string()],
            public_safe_message:
                "command cwd is outside declared filesystem roots; upper policy decision required"
                    .to_string(),
        }));
    }
    let report = lowering_report(&read_roots, &write_roots, &grant_roots, request);
    Ok(FilesystemMounts {
        read_roots,
        write_roots,
        report,
    })
}

fn canonical_roots(request: &RunRequest, key: &str) -> Result<Vec<PathBuf>, LinuxRunError> {
    let Some(roots) = request.enforcement.filesystem.get(key) else {
        return Ok(Vec::new());
    };
    roots
        .iter()
        .map(|root| {
            std::fs::canonicalize(root).map_err(|err| {
                sandbox_denied(format!(
                    "declared filesystem {key} root `{root}` is not available: {err}"
                ))
            })
        })
        .collect()
}

fn apply_cwd_grants(
    request: &RunRequest,
    cwd: &Path,
    read_roots: &mut Vec<PathBuf>,
    write_roots: &mut Vec<PathBuf>,
) -> Result<Vec<LoweredRoot>, LinuxRunError> {
    let mut grant_roots = Vec::new();
    for grant in request
        .policy_grants
        .iter()
        .filter(|grant| grant.reason == "cwd-outside-declared-roots")
    {
        let granted_path = std::fs::canonicalize(&grant.path).map_err(|err| {
            sandbox_denied(format!(
                "policy grant path `{}` is not available: {err}",
                grant.path
            ))
        })?;
        if granted_path != cwd {
            continue;
        }
        if grant.access.iter().any(|access| access == "write") {
            push_unique_root(write_roots, granted_path);
            grant_roots.push(lowered_root(
                cwd,
                LoweredRootAccess::Write,
                LoweredRootSource::PolicyGrant,
            ));
        } else {
            push_unique_root(read_roots, granted_path);
            grant_roots.push(lowered_root(
                cwd,
                LoweredRootAccess::Read,
                LoweredRootSource::PolicyGrant,
            ));
        }
    }
    Ok(grant_roots)
}

fn push_unique_root(roots: &mut Vec<PathBuf>, root: PathBuf) {
    if !roots.iter().any(|existing| existing == &root) {
        roots.push(root);
    }
}

fn is_covered(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| path.starts_with(root))
}

fn normalize_mount_roots(
    read_roots: Vec<PathBuf>,
    write_roots: Vec<PathBuf>,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let write_roots = dedup_roots(write_roots);
    let read_roots = dedup_roots(read_roots)
        .into_iter()
        .filter(|read_root| {
            !write_roots
                .iter()
                .any(|write_root| read_root.starts_with(write_root))
        })
        .collect();
    (read_roots, write_roots)
}

fn dedup_roots(roots: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = Vec::new();
    for root in roots {
        if !seen.iter().any(|existing| existing == &root) {
            seen.push(root);
        }
    }
    seen
}

fn lowering_report(
    read_roots: &[PathBuf],
    write_roots: &[PathBuf],
    grant_roots: &[LoweredRoot],
    request: &RunRequest,
) -> FileSystemLoweringReport {
    let mut declared_roots = Vec::new();
    declared_roots.extend(read_roots.iter().map(|root| {
        lowered_root(
            root,
            LoweredRootAccess::Read,
            source_for_root(root, &LoweredRootAccess::Read, grant_roots),
        )
    }));
    declared_roots.extend(write_roots.iter().map(|root| {
        lowered_root(
            root,
            LoweredRootAccess::Write,
            source_for_root(root, &LoweredRootAccess::Write, grant_roots),
        )
    }));
    let runtime_roots = runtime_roots_report(&declared_roots);
    FileSystemLoweringReport {
        declared_roots,
        runtime_roots,
        policy_grants: request.policy_grants.clone(),
        warnings: grant_roots
            .iter()
            .map(|root| raxcell_protocol::PolicyResolutionWarning {
                code: "POLICY_GRANT_MOUNTED".to_string(),
                message: format!(
                    "policy grant mounted `{}` with `{}` access",
                    root.path,
                    lowered_access_name(&root.access)
                ),
            })
            .collect(),
    }
}

fn source_for_root(
    path: &Path,
    access: &LoweredRootAccess,
    grant_roots: &[LoweredRoot],
) -> LoweredRootSource {
    let path = path.to_string_lossy();
    if grant_roots
        .iter()
        .any(|root| root.path == path && root.access == *access)
    {
        LoweredRootSource::PolicyGrant
    } else {
        LoweredRootSource::Declared
    }
}

fn runtime_roots_report(effective_roots: &[LoweredRoot]) -> Vec<LoweredRoot> {
    let mut roots = Vec::new();
    push_runtime_root_if_exists(&mut roots, effective_roots, "/usr", LoweredRootAccess::Read);
    push_runtime_root_if_exists(&mut roots, effective_roots, "/etc", LoweredRootAccess::Read);
    push_runtime_root_if_exists(
        &mut roots,
        effective_roots,
        "/proc",
        LoweredRootAccess::Runtime,
    );
    push_runtime_root_if_exists(
        &mut roots,
        effective_roots,
        "/dev",
        LoweredRootAccess::Runtime,
    );
    push_runtime_root_if_exists(
        &mut roots,
        effective_roots,
        "/tmp",
        LoweredRootAccess::Scratch,
    );
    push_root_link_or_runtime_read(&mut roots, effective_roots, "/bin");
    push_root_link_or_runtime_read(&mut roots, effective_roots, "/lib");
    push_root_link_or_runtime_read(&mut roots, effective_roots, "/lib64");
    push_root_link_or_runtime_read(&mut roots, effective_roots, "/sbin");
    roots
}

fn push_runtime_root_if_exists(
    roots: &mut Vec<LoweredRoot>,
    effective_roots: &[LoweredRoot],
    path: &str,
    access: LoweredRootAccess,
) {
    if Path::new(path).exists() && !runtime_root_is_covered(path, effective_roots) {
        roots.push(LoweredRoot {
            path: path.to_string(),
            access,
            source: LoweredRootSource::BackendRuntime,
        });
    }
}

fn push_root_link_or_runtime_read(
    roots: &mut Vec<LoweredRoot>,
    effective_roots: &[LoweredRoot],
    path: &str,
) {
    if !Path::new(path).exists() || runtime_root_is_covered(path, effective_roots) {
        return;
    }
    let access = if std::fs::read_link(path).is_ok() {
        LoweredRootAccess::RuntimeLink
    } else {
        LoweredRootAccess::Read
    };
    roots.push(LoweredRoot {
        path: path.to_string(),
        access,
        source: LoweredRootSource::BackendRuntime,
    });
}

fn runtime_root_is_covered(path: &str, effective_roots: &[LoweredRoot]) -> bool {
    let path = Path::new(path);
    effective_roots
        .iter()
        .any(|root| path.starts_with(Path::new(&root.path)))
}

fn lowered_root(path: &Path, access: LoweredRootAccess, source: LoweredRootSource) -> LoweredRoot {
    LoweredRoot {
        path: path.to_string_lossy().into_owned(),
        access,
        source,
    }
}

fn lowered_access_name(access: &LoweredRootAccess) -> &'static str {
    match access {
        LoweredRootAccess::Read => "read",
        LoweredRootAccess::Write => "write",
        LoweredRootAccess::Runtime => "runtime",
        LoweredRootAccess::Scratch => "scratch",
        LoweredRootAccess::RuntimeLink => "runtime-link",
    }
}

fn bind_runtime_paths(args: &mut Vec<OsString>) {
    ro_bind_if_exists(args, "/usr");
    ro_bind_if_exists(args, "/etc");
    symlink_if_root_symlink(args, "/bin");
    symlink_if_root_symlink(args, "/lib");
    symlink_if_root_symlink(args, "/lib64");
    symlink_if_root_symlink(args, "/sbin");
}

fn ro_bind_if_exists(args: &mut Vec<OsString>, path: &str) {
    if Path::new(path).exists() {
        args.push(OsString::from("--ro-bind"));
        args.push(OsString::from(path));
        args.push(OsString::from(path));
    }
}

fn symlink_if_root_symlink(args: &mut Vec<OsString>, path: &str) {
    let Ok(target) = std::fs::read_link(path) else {
        ro_bind_if_exists(args, path);
        return;
    };
    let Some(name) = Path::new(path).file_name() else {
        return;
    };
    args.push(OsString::from("--symlink"));
    args.push(normalize_relative_root_target(target));
    args.push(OsString::from(format!("/{}", name.to_string_lossy())));
}

fn normalize_relative_root_target(target: PathBuf) -> OsString {
    if let Ok(stripped) = target.strip_prefix("/") {
        return stripped.as_os_str().to_os_string();
    }
    target.into_os_string()
}

fn timeout_duration(request: &RunRequest) -> Result<Option<Duration>, LinuxRunError> {
    let Some(value) = request.enforcement.resources.get("timeoutMs") else {
        return Ok(None);
    };
    let Some(timeout_ms) = value.as_u64() else {
        return Err(sandbox_denied(
            "resources.timeoutMs must be an unsigned integer",
        ));
    };
    if timeout_ms == 0 {
        return Ok(None);
    }
    Ok(Some(Duration::from_millis(timeout_ms)))
}

fn sandbox_denied(message: impl Into<String>) -> LinuxRunError {
    LinuxRunError::SandboxDenied(message.into())
}

fn fail(
    request: RunRequest,
    capability_report: ProbeResponse,
    code: DenialCode,
    message: String,
) -> RunResponse {
    RunResponse {
        kind: "raxcell.runResult.v1".to_string(),
        ok: false,
        backend: Some(BackendFamily::LinuxBubblewrap),
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        timed_out: false,
        denial: Some(Denial {
            code,
            message: format!("{message}; actionId={}", request.action.action_id),
            public_safe: true,
        }),
        policy_decision: None,
        filesystem_lowering: None,
        fallback: None,
        capability_report: Some(capability_report),
    }
}

fn fail_policy_decision_required(
    request: RunRequest,
    capability_report: ProbeResponse,
    decision: PolicyDecisionRequired,
) -> RunResponse {
    RunResponse {
        kind: "raxcell.runResult.v1".to_string(),
        ok: false,
        backend: Some(BackendFamily::LinuxBubblewrap),
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        timed_out: false,
        denial: Some(Denial {
            code: DenialCode::PolicyDecisionRequired,
            message: format!(
                "{}; actionId={}",
                decision.public_safe_message, request.action.action_id
            ),
            public_safe: true,
        }),
        policy_decision: Some(decision),
        filesystem_lowering: None,
        fallback: None,
        capability_report: Some(capability_report),
    }
}

fn fail_prepare(
    request: RunRequest,
    capability_report: ProbeResponse,
    code: DenialCode,
    message: String,
) -> PrepareRunResponse {
    PrepareRunResponse {
        kind: "raxcell.prepareRunResult.v1".to_string(),
        ok: false,
        backend: Some(BackendFamily::LinuxBubblewrap),
        denial: Some(Denial {
            code,
            message: format!("{message}; actionId={}", request.action.action_id),
            public_safe: true,
        }),
        policy_decision: None,
        filesystem_lowering: None,
        backend_artifacts: Vec::new(),
        capability_report: Some(capability_report),
    }
}

fn fail_prepare_policy_decision_required(
    request: RunRequest,
    capability_report: ProbeResponse,
    decision: PolicyDecisionRequired,
) -> PrepareRunResponse {
    PrepareRunResponse {
        kind: "raxcell.prepareRunResult.v1".to_string(),
        ok: false,
        backend: Some(BackendFamily::LinuxBubblewrap),
        denial: Some(Denial {
            code: DenialCode::PolicyDecisionRequired,
            message: format!(
                "{}; actionId={}",
                decision.public_safe_message, request.action.action_id
            ),
            public_safe: true,
        }),
        policy_decision: Some(decision),
        filesystem_lowering: None,
        backend_artifacts: Vec::new(),
        capability_report: Some(capability_report),
    }
}
