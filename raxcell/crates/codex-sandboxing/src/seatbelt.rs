use crate::SandboxError;
use raxcell_codex_protocol::{
    FileSystemAccessMode, FileSystemPath, FileSystemSpecialPath, ManagedFileSystemPermissions,
    NetworkSandboxPolicy, PermissionProfile,
};
use std::path::PathBuf;

/// Canonical system path used by Codex for macOS Seatbelt execution.
pub const MACOS_PATH_TO_SEATBELT_EXECUTABLE: &str = "/usr/bin/sandbox-exec";

#[cfg(target_os = "macos")]
pub fn create_seatbelt_command(
    command: Vec<String>,
    permission_profile: &PermissionProfile,
) -> Result<(PathBuf, Vec<String>, Option<String>), SandboxError> {
    let args = create_seatbelt_command_args(command, permission_profile)?;
    Ok((PathBuf::from(MACOS_PATH_TO_SEATBELT_EXECUTABLE), args, None))
}

#[cfg(not(target_os = "macos"))]
pub fn create_seatbelt_command(
    _command: Vec<String>,
    _permission_profile: &PermissionProfile,
) -> Result<(PathBuf, Vec<String>, Option<String>), SandboxError> {
    Err(SandboxError::SeatbeltUnavailable)
}

pub fn create_seatbelt_command_args(
    command: Vec<String>,
    permission_profile: &PermissionProfile,
) -> Result<Vec<String>, SandboxError> {
    let mut args = vec!["-p".to_string(), seatbelt_policy(permission_profile)?];
    args.extend(command);
    Ok(args)
}

fn seatbelt_policy(permission_profile: &PermissionProfile) -> Result<String, SandboxError> {
    let mut policy = String::from("(version 1)\n(deny default)\n");
    policy.push_str("(allow process*)\n");
    push_filesystem_policy(&mut policy, permission_profile)?;
    if matches!(
        permission_profile.network_sandbox_policy(),
        NetworkSandboxPolicy::Enabled
    ) {
        policy.push_str("(allow network*)\n");
    }
    Ok(policy)
}

fn push_filesystem_policy(
    policy: &mut String,
    permission_profile: &PermissionProfile,
) -> Result<(), SandboxError> {
    match permission_profile {
        PermissionProfile::Disabled => {
            policy.push_str("(allow file-read*)\n");
            policy.push_str("(allow file-write*)\n");
        }
        PermissionProfile::External { .. } => {
            return Err(SandboxError::UnsupportedSeatbeltPolicy(
                "external filesystem policy cannot be represented as SBPL".to_string(),
            ));
        }
        PermissionProfile::Managed {
            file_system: ManagedFileSystemPermissions::Unrestricted,
            ..
        } => {
            policy.push_str("(allow file-read*)\n");
            policy.push_str("(allow file-write*)\n");
        }
        PermissionProfile::Managed {
            file_system:
                ManagedFileSystemPermissions::Restricted {
                    entries,
                    glob_scan_max_depth: _,
                },
            ..
        } => {
            for entry in entries {
                push_filesystem_entry(policy, &entry.path, entry.access)?;
            }
        }
    }
    Ok(())
}

fn push_filesystem_entry(
    policy: &mut String,
    path: &FileSystemPath,
    access: FileSystemAccessMode,
) -> Result<(), SandboxError> {
    if matches!(access, FileSystemAccessMode::Deny) {
        return Err(SandboxError::UnsupportedSeatbeltPolicy(
            "deny filesystem entries cannot be represented by this minimal SBPL lowering"
                .to_string(),
        ));
    }

    match path {
        FileSystemPath::Path { path } => {
            let path = sbpl_string(path.to_string_lossy().as_ref());
            policy.push_str(&format!("(allow file-read* (subpath \"{path}\"))\n"));
            if access.can_write() {
                policy.push_str(&format!("(allow file-write* (subpath \"{path}\"))\n"));
            }
        }
        FileSystemPath::Special {
            value: FileSystemSpecialPath::Root,
        } => {
            policy.push_str("(allow file-read*)\n");
            if access.can_write() {
                policy.push_str("(allow file-write*)\n");
            }
        }
        FileSystemPath::GlobPattern { .. } => {
            return Err(SandboxError::UnsupportedSeatbeltPolicy(
                "glob filesystem entries cannot be represented by this minimal SBPL lowering"
                    .to_string(),
            ));
        }
        FileSystemPath::Special { value } => {
            return Err(SandboxError::UnsupportedSeatbeltPolicy(format!(
                "special filesystem entry {value:?} cannot be represented by this minimal SBPL lowering"
            )));
        }
    }
    Ok(())
}

fn sbpl_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
