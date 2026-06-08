use raxcell_codex_protocol::PermissionProfile;
use std::path::Path;

/// Basename used when invoking the Codex Linux sandbox helper through arg0.
pub const CODEX_LINUX_SANDBOX_ARG0: &str = "codex-linux-sandbox";

pub fn create_linux_sandbox_command_args_for_permission_profile(
    command: Vec<String>,
    command_cwd: &Path,
    permission_profile: &PermissionProfile,
    sandbox_policy_cwd: &Path,
    use_legacy_landlock: bool,
    allow_network_for_proxy: bool,
) -> Result<Vec<String>, serde_json::Error> {
    let permission_profile_json = serde_json::to_string(permission_profile)?;
    let sandbox_policy_cwd = sandbox_policy_cwd.to_string_lossy().into_owned();
    let command_cwd = command_cwd.to_string_lossy().into_owned();

    let mut linux_cmd = vec![
        "--sandbox-policy-cwd".to_string(),
        sandbox_policy_cwd,
        "--command-cwd".to_string(),
        command_cwd,
        "--permission-profile".to_string(),
        permission_profile_json,
    ];
    if use_legacy_landlock {
        linux_cmd.push("--use-legacy-landlock".to_string());
    }
    if allow_network_for_proxy {
        linux_cmd.push("--allow-network-for-proxy".to_string());
    }
    linux_cmd.push("--".to_string());
    linux_cmd.extend(command);
    Ok(linux_cmd)
}
