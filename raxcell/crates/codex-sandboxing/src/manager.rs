use crate::landlock::{
    CODEX_LINUX_SANDBOX_ARG0, create_linux_sandbox_command_args_for_permission_profile,
};
use crate::seatbelt;
use raxcell_codex_protocol::{
    AdditionalPermissionProfile, ManagedFileSystemPermissions, NetworkSandboxPolicy,
    PermissionProfile,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxType {
    None,
    MacosSeatbelt,
    LinuxSeccomp,
    WindowsRestrictedToken,
}

impl SandboxType {
    pub fn as_metric_tag(self) -> &'static str {
        match self {
            SandboxType::None => "none",
            SandboxType::MacosSeatbelt => "seatbelt",
            SandboxType::LinuxSeccomp => "seccomp",
            SandboxType::WindowsRestrictedToken => "windows_sandbox",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxablePreference {
    Auto,
    Require,
    Forbid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub additional_permissions: Vec<AdditionalPermissionProfile>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxTransformRequest {
    pub command: SandboxCommand,
    pub permission_profile: PermissionProfile,
    pub sandbox_type: SandboxType,
    pub sandbox_policy_cwd: PathBuf,
    pub codex_linux_sandbox_exe: Option<PathBuf>,
    pub use_legacy_landlock: bool,
    pub allow_network_for_proxy: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransformedSandboxCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub sandbox_type: SandboxType,
    pub permission_profile: PermissionProfile,
    pub arg0_override: Option<String>,
}

impl TransformedSandboxCommand {
    pub fn argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(1 + self.args.len());
        argv.push(
            self.arg0_override
                .clone()
                .unwrap_or_else(|| self.program.to_string_lossy().into_owned()),
        );
        argv.extend(self.args.clone());
        argv
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SandboxError {
    #[error("missing codex-linux-sandbox executable path")]
    MissingLinuxSandboxExecutable,
    #[error("seatbelt sandbox is only available on macOS")]
    SeatbeltUnavailable,
    #[error("unsupported seatbelt policy: {0}")]
    UnsupportedSeatbeltPolicy(String),
    #[error("failed to serialize permission profile: {0}")]
    PermissionProfileSerialization(String),
}

#[derive(Default)]
pub struct SandboxManager;

impl SandboxManager {
    pub fn new() -> Self {
        Self
    }

    pub fn transform(
        &self,
        request: SandboxTransformRequest,
    ) -> Result<TransformedSandboxCommand, SandboxError> {
        let SandboxTransformRequest {
            command,
            permission_profile,
            sandbox_type,
            sandbox_policy_cwd,
            codex_linux_sandbox_exe,
            use_legacy_landlock,
            allow_network_for_proxy,
        } = request;
        let effective_permission_profile =
            effective_permission_profile(permission_profile, &command.additional_permissions);
        let original_argv = command_argv(&command);

        let (program, args, arg0_override) = match sandbox_type {
            SandboxType::None | SandboxType::WindowsRestrictedToken => {
                (command.program.clone(), command.args.clone(), None)
            }
            SandboxType::LinuxSeccomp => {
                let exe =
                    codex_linux_sandbox_exe.ok_or(SandboxError::MissingLinuxSandboxExecutable)?;
                let args = create_linux_sandbox_command_args_for_permission_profile(
                    original_argv,
                    command.cwd.as_path(),
                    &effective_permission_profile,
                    sandbox_policy_cwd.as_path(),
                    use_legacy_landlock,
                    allow_network_for_proxy,
                )
                .map_err(|err| SandboxError::PermissionProfileSerialization(err.to_string()))?;
                let arg0_override = Some(linux_sandbox_arg0_override(exe.as_path()));
                (exe, args, arg0_override)
            }
            SandboxType::MacosSeatbelt => seatbelt::create_seatbelt_command(
                command_argv(&command),
                &effective_permission_profile,
            )?,
        };

        Ok(TransformedSandboxCommand {
            program,
            args,
            cwd: command.cwd,
            env: command.env,
            sandbox_type,
            permission_profile: effective_permission_profile,
            arg0_override,
        })
    }
}

fn effective_permission_profile(
    mut profile: PermissionProfile,
    additional_permissions: &[AdditionalPermissionProfile],
) -> PermissionProfile {
    for additional_permission in additional_permissions {
        if let Some(network) = &additional_permission.network
            && let Some(enabled) = network.enabled
        {
            apply_network_permissions(&mut profile, enabled);
        }
        if let Some(file_system) = &additional_permission.file_system {
            match &mut profile {
                PermissionProfile::Managed {
                    file_system:
                        ManagedFileSystemPermissions::Restricted {
                            entries,
                            glob_scan_max_depth,
                        },
                    ..
                } => {
                    entries.extend(file_system.entries.clone());
                    if file_system.glob_scan_max_depth.is_some() {
                        *glob_scan_max_depth = file_system.glob_scan_max_depth;
                    }
                }
                PermissionProfile::Managed {
                    file_system: ManagedFileSystemPermissions::Unrestricted,
                    ..
                }
                | PermissionProfile::Disabled
                | PermissionProfile::External { .. } => {}
            }
        }
    }
    profile
}

fn apply_network_permissions(profile: &mut PermissionProfile, enabled: bool) {
    let network = if enabled {
        NetworkSandboxPolicy::Enabled
    } else {
        NetworkSandboxPolicy::Restricted
    };
    match profile {
        PermissionProfile::Managed {
            network: profile_network,
            ..
        }
        | PermissionProfile::External {
            network: profile_network,
        } => *profile_network = network,
        PermissionProfile::Disabled => {}
    }
}

fn command_argv(command: &SandboxCommand) -> Vec<String> {
    let mut argv = Vec::with_capacity(1 + command.args.len());
    argv.push(command.program.to_string_lossy().into_owned());
    argv.extend(command.args.clone());
    argv
}

fn linux_sandbox_arg0_override(exe: &Path) -> String {
    if exe.file_name().and_then(|name| name.to_str()) == Some(CODEX_LINUX_SANDBOX_ARG0) {
        exe.to_string_lossy().into_owned()
    } else {
        CODEX_LINUX_SANDBOX_ARG0.to_string()
    }
}
