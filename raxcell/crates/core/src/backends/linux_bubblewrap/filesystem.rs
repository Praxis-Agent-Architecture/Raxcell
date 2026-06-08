use raxcell_protocol::{
    FileSystemLoweringReport, LoweredRoot, LoweredRootAccess, LoweredRootSource,
    PolicyDecisionRequired, RunRequest,
};
use std::path::{Path, PathBuf};

#[cfg(test)]
use std::ffi::OsString;

use super::error::{LinuxRunError, sandbox_denied};

#[cfg(test)]
pub(in crate::backends) fn build_bwrap_args(
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

pub(super) fn filesystem_lowering_report(
    request: &RunRequest,
    cwd: &Path,
) -> Result<FileSystemLoweringReport, LinuxRunError> {
    filesystem_mounts(request, cwd).map(|mounts| mounts.report)
}

struct FilesystemMounts {
    #[cfg(test)]
    read_roots: Vec<PathBuf>,
    #[cfg(test)]
    write_roots: Vec<PathBuf>,
    report: FileSystemLoweringReport,
}

fn filesystem_mounts(request: &RunRequest, cwd: &Path) -> Result<FilesystemMounts, LinuxRunError> {
    let mut read_roots = canonical_roots(request, "read")?;
    let mut write_roots = canonical_roots(request, "write")?;
    let grant_roots = apply_policy_grants(request, &mut read_roots, &mut write_roots)?;
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
        #[cfg(test)]
        read_roots,
        #[cfg(test)]
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

fn apply_policy_grants(
    request: &RunRequest,
    read_roots: &mut Vec<PathBuf>,
    write_roots: &mut Vec<PathBuf>,
) -> Result<Vec<LoweredRoot>, LinuxRunError> {
    let mut grant_roots = Vec::new();
    for grant in &request.policy_grants {
        let granted_path = std::fs::canonicalize(&grant.path).map_err(|err| {
            sandbox_denied(format!(
                "policy grant path `{}` is not available: {err}",
                grant.path
            ))
        })?;
        if grant.access.iter().any(|access| access == "write") {
            if is_covered(&granted_path, write_roots) {
                continue;
            }
            push_unique_root(write_roots, granted_path.clone());
            grant_roots.push(lowered_root(
                &granted_path,
                LoweredRootAccess::Write,
                LoweredRootSource::PolicyGrant,
            ));
            continue;
        }
        if is_covered(&granted_path, read_roots) || is_covered(&granted_path, write_roots) {
            continue;
        }
        push_unique_root(read_roots, granted_path.clone());
        grant_roots.push(lowered_root(
            &granted_path,
            LoweredRootAccess::Read,
            LoweredRootSource::PolicyGrant,
        ));
    }
    Ok(grant_roots)
}

fn push_unique_root(roots: &mut Vec<PathBuf>, root: PathBuf) {
    if !roots.iter().any(|existing| existing == &root) {
        roots.push(root);
    }
}

pub(super) fn is_covered(path: &Path, roots: &[PathBuf]) -> bool {
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

pub(super) fn runtime_roots_report(effective_roots: &[LoweredRoot]) -> Vec<LoweredRoot> {
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

#[cfg(test)]
fn bind_runtime_paths(args: &mut Vec<OsString>) {
    ro_bind_if_exists(args, "/usr");
    ro_bind_if_exists(args, "/etc");
    symlink_if_root_symlink(args, "/bin");
    symlink_if_root_symlink(args, "/lib");
    symlink_if_root_symlink(args, "/lib64");
    symlink_if_root_symlink(args, "/sbin");
}

#[cfg(test)]
fn ro_bind_if_exists(args: &mut Vec<OsString>, path: &str) {
    if Path::new(path).exists() {
        args.push(OsString::from("--ro-bind"));
        args.push(OsString::from(path));
        args.push(OsString::from(path));
    }
}

#[cfg(test)]
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

#[cfg(test)]
fn normalize_relative_root_target(target: PathBuf) -> OsString {
    if let Ok(stripped) = target.strip_prefix("/") {
        return stripped.as_os_str().to_os_string();
    }
    target.into_os_string()
}
