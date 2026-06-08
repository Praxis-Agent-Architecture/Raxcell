use raxcell_codex_sandboxing::TransformedSandboxCommand;
use raxcell_protocol::{BackendFamily, BackendLoweringArtifact};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::error::{LinuxRunError, environment_gap};

const CODEX_LINUX_SANDBOX_ARG0: &str = "codex-linux-sandbox";
const RAXCELL_CODEX_LINUX_SANDBOX_BIN: &str = "raxcell-codex-linux-sandbox";

pub(super) fn codex_linux_sandbox_artifact(
    command: &TransformedSandboxCommand,
) -> BackendLoweringArtifact {
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

pub(super) fn validate_codex_linux_sandbox_helper(helper_path: &Path) -> Result<(), LinuxRunError> {
    let output = codex_linux_sandbox_command(helper_path)
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .output()
        .map_err(|err| {
            environment_gap(
                "missing-backend-dependency",
                Some("codex-linux-sandbox"),
                vec!["dependency.binary.codex-linux-sandbox"],
                format!("failed to run codex-linux-sandbox helper preflight: {err}"),
            )
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
            return Err(environment_gap(
                "backend-capability-gap",
                Some("codex-linux-sandbox"),
                vec!["backend.codex-linux-sandbox.hidden-arguments"],
                "codex-linux-sandbox helper preflight help output does not match expected helper shape",
            ));
        }
        return validate_codex_linux_sandbox_hidden_args(helper_path);
    }
    Err(environment_gap(
        "backend-capability-gap",
        Some("codex-linux-sandbox"),
        vec!["backend.codex-linux-sandbox.preflight"],
        "codex-linux-sandbox helper preflight failed",
    ))
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
            environment_gap(
                "missing-backend-dependency",
                Some("codex-linux-sandbox"),
                vec!["dependency.binary.codex-linux-sandbox"],
                format!("failed to run codex-linux-sandbox hidden-argument preflight: {err}"),
            )
        })?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success()
        && stderr.contains("--permission-profile")
        && stderr.contains("invalid permission profile JSON")
    {
        return Ok(());
    }
    Err(environment_gap(
        "backend-capability-gap",
        Some("codex-linux-sandbox"),
        vec!["backend.codex-linux-sandbox.hidden-arguments"],
        "codex-linux-sandbox helper preflight did not validate hidden sandbox arguments",
    ))
}

fn codex_linux_sandbox_command(helper_path: &Path) -> Command {
    let mut command = Command::new(helper_path);
    apply_codex_linux_sandbox_arg0(&mut command, helper_path);
    command
}

pub(super) fn transformed_sandbox_command(transformed: &TransformedSandboxCommand) -> Command {
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
