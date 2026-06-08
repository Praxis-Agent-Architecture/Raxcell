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
    FileSystemLoweringReport, LoweredRoot, LoweredRootAccess, LoweredRootSource, PolicyGrant,
    RunRequest,
};
use std::path::{Path, PathBuf};

use super::error::{LinuxRunError, environment_gap, sandbox_denied};
use super::filesystem::filesystem_lowering_report;
use super::shell_effects::{reject_unresolved_dynamic_redirect_paths, require_shell_effect_grants};

pub(in crate::backends) struct CodexLinuxSandboxTransform {
    pub(in crate::backends) command: TransformedSandboxCommand,
    pub(in crate::backends) filesystem_lowering: FileSystemLoweringReport,
}

pub(super) fn codex_linux_sandbox_transform(
    request: &RunRequest,
    helper_path: &Path,
    cwd: &Path,
) -> Result<CodexLinuxSandboxTransform, LinuxRunError> {
    reject_unresolved_dynamic_redirect_paths(&request.command.argv)?;
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
pub(in crate::backends) fn codex_linux_sandbox_transform_for_test(
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

fn sandbox_transform_denied(error: SandboxError) -> LinuxRunError {
    environment_gap(
        "backend-capability-gap",
        None,
        vec!["backend.codex-linux-sandbox.transform"],
        format!("failed to transform codex linux sandbox command: {error}"),
    )
}
