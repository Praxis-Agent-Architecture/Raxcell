use raxcell_codex_protocol::{
    AdditionalPermissionProfile, FileSystemAccessMode, FileSystemPath, FileSystemPermissions,
    FileSystemSandboxEntry, FileSystemSandboxPolicy, FileSystemSpecialPath, NetworkSandboxPolicy,
    PermissionProfile,
};
use raxcell_codex_sandboxing::{
    SandboxCommand, SandboxError, SandboxManager, SandboxTransformRequest, SandboxType,
    TransformedSandboxCommand,
};
use raxcell_protocol::{
    BackendFamily, BackendLoweringArtifact, Denial, DenialCode, FileSystemLoweringReport,
    LoweredRoot, LoweredRootAccess, LoweredRootSource, PolicyDecisionRequired, PolicyGrant,
    PrepareRunResponse, ProbeResponse, RunRequest, RunResponse,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

const CODEX_LINUX_SANDBOX_ARG0: &str = "codex-linux-sandbox";
const RAXCELL_CODEX_LINUX_SANDBOX_BIN: &str = "raxcell-codex-linux-sandbox";

struct ExecutionOutput {
    output: std::process::Output,
    timed_out: bool,
    filesystem_lowering: FileSystemLoweringReport,
}

struct PrepareOutput {
    filesystem_lowering: FileSystemLoweringReport,
    backend_artifacts: Vec<BackendLoweringArtifact>,
}

pub(super) struct CodexLinuxSandboxTransform {
    pub(super) command: TransformedSandboxCommand,
    pub(super) filesystem_lowering: FileSystemLoweringReport,
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
    let Ok(helper_path) = codex_linux_sandbox_path() else {
        return fail(
            request,
            capability_report,
            DenialCode::BackendUnavailable,
            "linux-bubblewrap requires the `codex-linux-sandbox` helper".to_string(),
        );
    };
    let Ok(_) = which::which("bwrap") else {
        return fail(
            request,
            capability_report,
            DenialCode::BackendUnavailable,
            "codex-linux-sandbox requires the `bwrap` binary".to_string(),
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
    if let Err(LinuxRunError::SandboxDenied(message)) =
        validate_codex_linux_sandbox_helper(helper_path)
    {
        return fail_prepare(
            request,
            capability_report,
            DenialCode::SandboxDenied,
            message,
        );
    }
    match prepare_inner(&request, helper_path) {
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

fn run_with_helper_path(
    request: RunRequest,
    capability_report: ProbeResponse,
    helper_path: &Path,
) -> RunResponse {
    if let Err(LinuxRunError::SandboxDenied(message)) =
        validate_codex_linux_sandbox_helper(helper_path)
    {
        return fail(
            request,
            capability_report,
            DenialCode::SandboxDenied,
            message,
        );
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
                policy_decision: None,
                filesystem_lowering: Some(execution.filesystem_lowering),
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
    let Ok(helper_path) = codex_linux_sandbox_path() else {
        return fail_prepare(
            request,
            capability_report,
            DenialCode::BackendUnavailable,
            "linux-bubblewrap prepare requires the `codex-linux-sandbox` helper".to_string(),
        );
    };
    let Ok(_) = which::which("bwrap") else {
        return fail_prepare(
            request,
            capability_report,
            DenialCode::BackendUnavailable,
            "codex-linux-sandbox prepare requires the `bwrap` binary".to_string(),
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
    if let Err(LinuxRunError::SandboxDenied(message)) =
        validate_codex_linux_sandbox_helper(&helper_path)
    {
        return fail_prepare(
            request,
            capability_report,
            DenialCode::SandboxDenied,
            message,
        );
    }

    match prepare_inner(&request, &helper_path) {
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
                        filesystem_lowering: transformed.filesystem_lowering,
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

fn codex_linux_sandbox_artifact(command: &TransformedSandboxCommand) -> BackendLoweringArtifact {
    let mut data = BTreeMap::new();
    data.insert(
        "executable".to_string(),
        serde_json::json!(command.program.to_string_lossy()),
    );
    data.insert(
        "engine".to_string(),
        serde_json::json!("codex-linux-sandbox"),
    );
    BackendLoweringArtifact {
        backend: BackendFamily::LinuxBubblewrap,
        format: "codex-linux-sandbox-argv".to_string(),
        arguments: command.args.clone(),
        data,
        warnings: Vec::new(),
    }
}

fn validate_codex_linux_sandbox_helper(helper_path: &Path) -> Result<(), LinuxRunError> {
    let output = codex_linux_sandbox_command(helper_path)
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .output()
        .map_err(|err| {
            sandbox_denied(format!(
                "failed to run codex-linux-sandbox helper preflight: {err}"
            ))
        })?;
    if output.status.success() {
        let help_text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !help_text.contains(CODEX_LINUX_SANDBOX_ARG0)
            || !help_text.contains("--sandbox-policy-cwd")
        {
            return Err(sandbox_denied(
                "codex-linux-sandbox helper preflight help output does not match expected helper shape",
            ));
        }
        return validate_codex_linux_sandbox_hidden_args(helper_path);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let message = stderr.trim();
    Err(sandbox_denied(format!(
        "codex-linux-sandbox helper preflight failed with exit code {:?}: {}",
        output.status.code(),
        if message.is_empty() {
            "no stderr"
        } else {
            message
        }
    )))
}

fn validate_codex_linux_sandbox_hidden_args(helper_path: &Path) -> Result<(), LinuxRunError> {
    let output = codex_linux_sandbox_command(helper_path)
        .args([
            "--sandbox-policy-cwd",
            ".",
            "--command-cwd",
            ".",
            "--permission-profile",
            "{not-json",
            "--",
            "/bin/true",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env_clear()
        .output()
        .map_err(|err| {
            sandbox_denied(format!(
                "failed to run codex-linux-sandbox hidden-argument preflight: {err}"
            ))
        })?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success()
        && stderr.contains("--permission-profile")
        && stderr.contains("invalid permission profile JSON")
    {
        return Ok(());
    }
    Err(sandbox_denied(format!(
        "codex-linux-sandbox helper preflight did not validate hidden sandbox arguments: {}",
        if stderr.trim().is_empty() {
            "no stderr"
        } else {
            stderr.trim()
        }
    )))
}

fn codex_linux_sandbox_command(helper_path: &Path) -> Command {
    let mut command = Command::new(helper_path);
    apply_codex_linux_sandbox_arg0(&mut command, helper_path);
    command
}

fn transformed_sandbox_command(transformed: &TransformedSandboxCommand) -> Command {
    let mut command = Command::new(&transformed.program);
    apply_transformed_arg0(&mut command, transformed.arg0_override.as_deref());
    command
}

#[cfg(unix)]
fn apply_codex_linux_sandbox_arg0(command: &mut Command, helper_path: &Path) {
    let arg0 = if helper_path.file_name().and_then(|name| name.to_str())
        == Some(CODEX_LINUX_SANDBOX_ARG0)
    {
        helper_path.to_string_lossy().into_owned()
    } else {
        CODEX_LINUX_SANDBOX_ARG0.to_string()
    };
    apply_transformed_arg0(command, Some(&arg0));
}

#[cfg(not(unix))]
fn apply_codex_linux_sandbox_arg0(_command: &mut Command, _helper_path: &Path) {}

#[cfg(unix)]
fn apply_transformed_arg0(command: &mut Command, arg0_override: Option<&str>) {
    use std::os::unix::process::CommandExt;

    if let Some(arg0) = arg0_override {
        command.arg0(arg0);
    }
}

#[cfg(not(unix))]
fn apply_transformed_arg0(_command: &mut Command, _arg0_override: Option<&str>) {}

fn codex_linux_sandbox_transform(
    request: &RunRequest,
    helper_path: &Path,
    cwd: &Path,
) -> Result<CodexLinuxSandboxTransform, LinuxRunError> {
    let filesystem_lowering = filesystem_lowering_report(request, cwd)?;
    require_shell_effect_grants(request, cwd, &filesystem_lowering)?;
    let permission_profile = codex_permission_profile(request, helper_path, &filesystem_lowering)?;
    let additional_permissions = codex_additional_permissions(request)?;
    let mut env = request.command.env.clone();
    env.entry("PATH".to_string())
        .or_insert_with(|| "/usr/bin:/bin:/usr/sbin:/sbin".to_string());
    let program = request
        .command
        .argv
        .first()
        .ok_or_else(|| sandbox_denied("command argv must contain at least one item"))?;
    let command = SandboxCommand {
        program: PathBuf::from(program),
        args: request.command.argv.iter().skip(1).cloned().collect(),
        cwd: cwd.to_path_buf(),
        env,
        additional_permissions,
    };
    let command = SandboxManager::new()
        .transform(SandboxTransformRequest {
            command,
            permission_profile,
            sandbox_type: SandboxType::LinuxSeccomp,
            sandbox_policy_cwd: cwd.to_path_buf(),
            codex_linux_sandbox_exe: Some(helper_path.to_path_buf()),
            use_legacy_landlock: false,
            allow_network_for_proxy: false,
        })
        .map_err(sandbox_transform_denied)?;
    Ok(CodexLinuxSandboxTransform {
        command,
        filesystem_lowering,
    })
}

#[cfg(test)]
pub(super) fn codex_linux_sandbox_transform_for_test(
    request: &RunRequest,
    helper_path: &Path,
    cwd: &Path,
) -> Result<CodexLinuxSandboxTransform, LinuxRunError> {
    codex_linux_sandbox_transform(request, helper_path, cwd)
}

fn codex_permission_profile(
    request: &RunRequest,
    helper_path: &Path,
    filesystem_lowering: &FileSystemLoweringReport,
) -> Result<PermissionProfile, LinuxRunError> {
    let mut entries = vec![FileSystemSandboxEntry {
        path: FileSystemPath::Special {
            value: FileSystemSpecialPath::Minimal,
        },
        access: FileSystemAccessMode::Read,
    }];
    let helper_path =
        std::fs::canonicalize(helper_path).unwrap_or_else(|_| helper_path.to_path_buf());
    entries.push(FileSystemSandboxEntry {
        path: FileSystemPath::Path { path: helper_path },
        access: FileSystemAccessMode::Read,
    });
    for root in &filesystem_lowering.declared_roots {
        if root.source == LoweredRootSource::PolicyGrant {
            continue;
        }
        if let Some(entry) = codex_file_system_entry(root) {
            entries.push(entry);
        }
    }
    Ok(PermissionProfile::from_runtime_permissions(
        &FileSystemSandboxPolicy::restricted(entries),
        codex_network_policy(request),
    ))
}

fn codex_additional_permissions(
    request: &RunRequest,
) -> Result<Vec<AdditionalPermissionProfile>, LinuxRunError> {
    let entries: Vec<FileSystemSandboxEntry> = request
        .policy_grants
        .iter()
        .map(codex_policy_grant_entry)
        .collect::<Result<_, _>>()?;
    if entries.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(vec![AdditionalPermissionProfile {
            network: None,
            file_system: Some(FileSystemPermissions {
                entries,
                glob_scan_max_depth: None,
            }),
        }])
    }
}

fn codex_policy_grant_entry(grant: &PolicyGrant) -> Result<FileSystemSandboxEntry, LinuxRunError> {
    let path = std::fs::canonicalize(&grant.path).map_err(|err| {
        sandbox_denied(format!(
            "policy grant path `{}` is not available: {err}",
            grant.path
        ))
    })?;
    let access = if grant.access.iter().any(|access| access == "write") {
        FileSystemAccessMode::Write
    } else {
        FileSystemAccessMode::Read
    };
    Ok(FileSystemSandboxEntry {
        path: FileSystemPath::Path { path },
        access,
    })
}

fn codex_file_system_entry(root: &LoweredRoot) -> Option<FileSystemSandboxEntry> {
    let access = match root.access {
        LoweredRootAccess::Read => FileSystemAccessMode::Read,
        LoweredRootAccess::Write => FileSystemAccessMode::Write,
        LoweredRootAccess::Runtime
        | LoweredRootAccess::Scratch
        | LoweredRootAccess::RuntimeLink => return None,
    };
    Some(FileSystemSandboxEntry {
        path: FileSystemPath::Path {
            path: PathBuf::from(&root.path),
        },
        access,
    })
}

fn codex_network_policy(request: &RunRequest) -> NetworkSandboxPolicy {
    if request.enforcement.network.as_deref() == Some("allow") {
        NetworkSandboxPolicy::Enabled
    } else {
        NetworkSandboxPolicy::Restricted
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShellEffectAccess {
    Read,
    Write,
}

struct ShellEffect {
    path: PathBuf,
    access: ShellEffectAccess,
}

fn require_shell_effect_grants(
    request: &RunRequest,
    cwd: &Path,
    filesystem_lowering: &FileSystemLoweringReport,
) -> Result<(), LinuxRunError> {
    for effect in shell_effects(&request.command.argv, cwd)? {
        if shell_effect_is_allowed(&effect, request, filesystem_lowering)? {
            continue;
        }
        let required = match effect.access {
            ShellEffectAccess::Read => "filesystem.read",
            ShellEffectAccess::Write => "filesystem.write",
        };
        return Err(LinuxRunError::PolicyDecisionRequired(
            PolicyDecisionRequired {
                reason: "shell-effect-outside-declared-roots".to_string(),
                path: effect.path.to_string_lossy().into_owned(),
                required: vec![required.to_string()],
                public_safe_message:
                    "command references filesystem paths outside declared roots; upper policy decision required"
                        .to_string(),
            },
        ));
    }
    Ok(())
}

fn shell_effect_is_allowed(
    effect: &ShellEffect,
    request: &RunRequest,
    filesystem_lowering: &FileSystemLoweringReport,
) -> Result<bool, LinuxRunError> {
    let read_roots: Vec<PathBuf> = filesystem_lowering
        .declared_roots
        .iter()
        .filter(|root| root.access == LoweredRootAccess::Read)
        .map(|root| PathBuf::from(&root.path))
        .collect();
    let write_roots: Vec<PathBuf> = filesystem_lowering
        .declared_roots
        .iter()
        .filter(|root| root.access == LoweredRootAccess::Write)
        .map(|root| PathBuf::from(&root.path))
        .collect();
    if is_covered(&effect.path, &write_roots) {
        return Ok(true);
    }
    if effect.access == ShellEffectAccess::Read && is_covered(&effect.path, &read_roots) {
        return Ok(true);
    }
    for grant in &request.policy_grants {
        let grant_path = std::fs::canonicalize(&grant.path).map_err(|err| {
            sandbox_denied(format!(
                "policy grant path `{}` is not available: {err}",
                grant.path
            ))
        })?;
        if !effect.path.starts_with(&grant_path) {
            continue;
        }
        if grant.access.iter().any(|access| access == "write") {
            return Ok(true);
        }
        if effect.access == ShellEffectAccess::Read
            && grant.access.iter().any(|access| access == "read")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn shell_effects(argv: &[String], cwd: &Path) -> Result<Vec<ShellEffect>, LinuxRunError> {
    let Some(script) = shell_script_from_argv(argv) else {
        return command_effects(argv, cwd);
    };
    command_effects(&tokenize_shell_script(script), cwd)
}

fn shell_script_from_argv(argv: &[String]) -> Option<&str> {
    let executable = Path::new(argv.first()?).file_name()?.to_str()?;
    if !matches!(executable, "sh" | "bash" | "dash" | "zsh") {
        return None;
    }
    argv.iter()
        .enumerate()
        .find(|(index, arg)| *index > 0 && matches!(arg.as_str(), "-c" | "-lc" | "-cl"))
        .and_then(|(index, _)| argv.get(index + 1).map(String::as_str))
}

fn tokenize_shell_script(script: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = script.chars().peekable();
    while let Some(ch) = chars.next() {
        if let Some(active_quote) = quote {
            if ch == active_quote {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            ' ' | '\t' | '\n' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            '>' | '<' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                let mut op = ch.to_string();
                if chars.peek() == Some(&ch) {
                    op.push(chars.next().expect("peeked char exists"));
                }
                tokens.push(op);
            }
            ';' | '|' | '&' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                tokens.push(ch.to_string());
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    split_numbered_redirects(tokens)
}

fn split_numbered_redirects(tokens: Vec<String>) -> Vec<String> {
    let mut split = Vec::new();
    for token in tokens {
        if token.len() > 1
            && token.chars().next().is_some_and(|ch| ch.is_ascii_digit())
            && token[1..].chars().all(|ch| ch == '>' || ch == '<')
        {
            split.push(token[1..].to_string());
        } else {
            split.push(token);
        }
    }
    split
}

fn command_effects(argv: &[String], cwd: &Path) -> Result<Vec<ShellEffect>, LinuxRunError> {
    let mut effects = Vec::new();
    let mut index = 0;
    while index < argv.len() {
        let token = &argv[index];
        if matches!(token.as_str(), ";" | "|" | "&") {
            index += 1;
            continue;
        }
        if let Some(access) = redirect_access(token) {
            if let Some(target) = argv.get(index + 1) {
                effects.push(ShellEffect {
                    path: normalize_effect_path(target, cwd)?,
                    access,
                });
            }
            index += 2;
            continue;
        }
        let command = Path::new(token)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(token);
        if command == "cat" {
            for arg in non_option_args(&argv[index + 1..]) {
                effects.push(ShellEffect {
                    path: normalize_effect_path(arg, cwd)?,
                    access: ShellEffectAccess::Read,
                });
            }
        } else if matches!(command, "touch" | "mkdir" | "rm" | "rmdir") {
            for arg in non_option_args(&argv[index + 1..]) {
                effects.push(ShellEffect {
                    path: normalize_effect_path(arg, cwd)?,
                    access: ShellEffectAccess::Write,
                });
            }
        }
        index += 1;
    }
    Ok(effects)
}

fn redirect_access(token: &str) -> Option<ShellEffectAccess> {
    match token {
        ">" | ">>" | "<>" => Some(ShellEffectAccess::Write),
        "<" | "<<" => Some(ShellEffectAccess::Read),
        _ => None,
    }
}

fn non_option_args(args: &[String]) -> impl Iterator<Item = &String> {
    args.iter()
        .take_while(|arg| !matches!(arg.as_str(), ";" | "|" | "&"))
        .filter(|arg| !arg.starts_with('-'))
}

fn normalize_effect_path(raw: &str, cwd: &Path) -> Result<PathBuf, LinuxRunError> {
    let path = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        cwd.join(raw)
    };
    if let Ok(canonical) = std::fs::canonicalize(&path) {
        return Ok(canonical);
    }
    let Some(parent) = path.parent() else {
        return Err(sandbox_denied(format!(
            "failed to resolve shell effect path `{raw}`"
        )));
    };
    let parent = std::fs::canonicalize(parent).map_err(|err| {
        sandbox_denied(format!(
            "failed to resolve shell effect parent `{}`: {err}",
            parent.to_string_lossy()
        ))
    })?;
    let Some(file_name) = path.file_name() else {
        return Ok(parent);
    };
    Ok(parent.join(file_name))
}

fn sandbox_transform_denied(error: SandboxError) -> LinuxRunError {
    sandbox_denied(format!(
        "failed to transform codex linux sandbox command: {error}"
    ))
}

pub(crate) fn codex_linux_sandbox_path() -> Result<PathBuf, which::Error> {
    if let Some(path) = std::env::var_os("RAXCELL_CODEX_LINUX_SANDBOX_BIN") {
        return Ok(PathBuf::from(path));
    }
    if let Ok(current_exe) = std::env::current_exe()
        && let Some(dir) = current_exe.parent()
    {
        let sibling = dir.join("raxcell-codex-linux-sandbox");
        if sibling.exists() {
            return Ok(sibling);
        }
        let codex_named_sibling = dir.join("codex-linux-sandbox");
        if codex_named_sibling.exists() {
            return Ok(codex_named_sibling);
        }
    }
    if let Ok(path) = which::which(RAXCELL_CODEX_LINUX_SANDBOX_BIN) {
        return Ok(path);
    }
    which::which("codex-linux-sandbox")
}

#[allow(dead_code)]
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

fn filesystem_lowering_report(
    request: &RunRequest,
    cwd: &Path,
) -> Result<FileSystemLoweringReport, LinuxRunError> {
    filesystem_mounts(request, cwd).map(|mounts| mounts.report)
}

struct FilesystemMounts {
    #[allow(dead_code)]
    read_roots: Vec<PathBuf>,
    #[allow(dead_code)]
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

#[allow(dead_code)]
fn bind_runtime_paths(args: &mut Vec<OsString>) {
    ro_bind_if_exists(args, "/usr");
    ro_bind_if_exists(args, "/etc");
    symlink_if_root_symlink(args, "/bin");
    symlink_if_root_symlink(args, "/lib");
    symlink_if_root_symlink(args, "/lib64");
    symlink_if_root_symlink(args, "/sbin");
}

#[allow(dead_code)]
fn ro_bind_if_exists(args: &mut Vec<OsString>, path: &str) {
    if Path::new(path).exists() {
        args.push(OsString::from("--ro-bind"));
        args.push(OsString::from(path));
        args.push(OsString::from(path));
    }
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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
