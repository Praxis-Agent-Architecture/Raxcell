use raxcell_protocol::{
    BackendFamily, Denial, DenialCode, FileSystemLoweringReport, LoweredRoot, LoweredRootAccess,
    LoweredRootSource, PolicyDecisionRequired, PrepareRunResponse, ProbeResponse, RunRequest,
    RunResponse,
};
use std::path::{Path, PathBuf};

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsNativeLowering {
    pub(crate) backend: BackendFamily,
    pub(crate) token_mode: WindowsTokenMode,
    pub(crate) acl_roots: Vec<WindowsAclRoot>,
    pub(crate) network_blocked: bool,
    pub(crate) filesystem_lowering: FileSystemLoweringReport,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsTokenMode {
    ReadOnlyCapability,
    WritableRootsCapability,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsAclRoot {
    pub(crate) path: String,
    pub(crate) access: LoweredRootAccess,
    pub(crate) source: LoweredRootSource,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WindowsLoweringError {
    SandboxDenied(String),
    PolicyDecisionRequired(PolicyDecisionRequired),
}

pub fn run(
    request: RunRequest,
    capability_report: ProbeResponse,
    backend: BackendFamily,
) -> RunResponse {
    let message = if cfg!(target_os = "windows") {
        "windows-native backend is declared but the runner has not been attached in Stage 2"
    } else {
        "windows-native can only run on Windows hosts"
    };
    let code = if cfg!(target_os = "windows") {
        DenialCode::BackendUnavailable
    } else {
        DenialCode::CapabilityMismatch
    };
    RunResponse {
        kind: "raxcell.runResult.v1".to_string(),
        ok: false,
        backend: Some(backend),
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

pub fn prepare_run(
    request: RunRequest,
    capability_report: ProbeResponse,
    backend: BackendFamily,
) -> PrepareRunResponse {
    let message = if cfg!(target_os = "windows") {
        "windows-native backend is declared but prepare lowering has not been attached in Stage 6"
    } else {
        "windows-native can only prepare on Windows hosts"
    };
    let code = if cfg!(target_os = "windows") {
        DenialCode::BackendUnavailable
    } else {
        DenialCode::CapabilityMismatch
    };
    PrepareRunResponse {
        kind: "raxcell.prepareRunResult.v1".to_string(),
        ok: false,
        backend: Some(backend),
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

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn lower_for_windows_native(
    request: &RunRequest,
    backend: BackendFamily,
) -> Result<WindowsNativeLowering, WindowsLoweringError> {
    let cwd = std::fs::canonicalize(&request.command.cwd).map_err(|err| {
        WindowsLoweringError::SandboxDenied(format!("failed to resolve cwd: {err}"))
    })?;
    let mut read_roots = canonical_roots(request, "read")?;
    let mut write_roots = canonical_roots(request, "write")?;
    let grant_roots = if is_covered(&cwd, &read_roots) || is_covered(&cwd, &write_roots) {
        Vec::new()
    } else {
        apply_cwd_grants(request, &cwd, &mut read_roots, &mut write_roots)?
    };
    let (read_roots, write_roots) = normalize_roots(read_roots, write_roots);
    if !is_covered(&cwd, &read_roots) && !is_covered(&cwd, &write_roots) {
        return Err(WindowsLoweringError::PolicyDecisionRequired(
            PolicyDecisionRequired {
                reason: "cwd-outside-declared-roots".to_string(),
                path: cwd.to_string_lossy().into_owned(),
                required: vec!["filesystem.read".to_string()],
                public_safe_message:
                    "command cwd is outside declared filesystem roots; upper policy decision required"
                        .to_string(),
            },
        ));
    }

    let filesystem_lowering = lowering_report(&read_roots, &write_roots, &grant_roots, request);
    let token_mode = if write_roots.is_empty() {
        WindowsTokenMode::ReadOnlyCapability
    } else {
        WindowsTokenMode::WritableRootsCapability
    };
    let acl_roots = filesystem_lowering
        .declared_roots
        .iter()
        .map(|root| WindowsAclRoot {
            path: root.path.clone(),
            access: root.access.clone(),
            source: root.source.clone(),
        })
        .collect();
    Ok(WindowsNativeLowering {
        backend,
        token_mode,
        acl_roots,
        network_blocked: request.enforcement.network.as_deref() == Some("deny"),
        filesystem_lowering,
    })
}

fn canonical_roots(request: &RunRequest, key: &str) -> Result<Vec<PathBuf>, WindowsLoweringError> {
    let Some(roots) = request.enforcement.filesystem.get(key) else {
        return Ok(Vec::new());
    };
    roots
        .iter()
        .map(|root| {
            std::fs::canonicalize(root).map_err(|err| {
                WindowsLoweringError::SandboxDenied(format!(
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
) -> Result<Vec<LoweredRoot>, WindowsLoweringError> {
    let mut grant_roots = Vec::new();
    for grant in request
        .policy_grants
        .iter()
        .filter(|grant| grant.reason == "cwd-outside-declared-roots")
    {
        let granted_path = std::fs::canonicalize(&grant.path).map_err(|err| {
            WindowsLoweringError::SandboxDenied(format!(
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

fn normalize_roots(
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
    FileSystemLoweringReport {
        declared_roots,
        runtime_roots: Vec::new(),
        policy_grants: request.policy_grants.clone(),
        warnings: Vec::new(),
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

fn lowered_root(path: &Path, access: LoweredRootAccess, source: LoweredRootSource) -> LoweredRoot {
    LoweredRoot {
        path: path.to_string_lossy().into_owned(),
        access,
        source,
    }
}
