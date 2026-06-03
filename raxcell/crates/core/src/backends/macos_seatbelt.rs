use raxcell_protocol::{
    BackendFamily, Denial, DenialCode, FileSystemLoweringReport, LoweredRoot, LoweredRootAccess,
    LoweredRootSource, PolicyDecisionRequired, PrepareRunResponse, ProbeResponse, RunRequest,
    RunResponse,
};
use std::path::{Path, PathBuf};

const MACOS_PATH_TO_SEATBELT_EXECUTABLE: &str = "/usr/bin/sandbox-exec";

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MacosSeatbeltLowering {
    pub(crate) executable: String,
    pub(crate) args: Vec<String>,
    pub(crate) profile: String,
    pub(crate) filesystem_lowering: FileSystemLoweringReport,
    pub(crate) network_denied: bool,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MacosLoweringError {
    SandboxDenied(String),
    PolicyDecisionRequired(PolicyDecisionRequired),
}

pub fn run(request: RunRequest, capability_report: ProbeResponse) -> RunResponse {
    let message = if cfg!(target_os = "macos") {
        "macos-seatbelt backend is declared but the runner has not been attached in Stage 2"
    } else {
        "macos-seatbelt can only run on macOS hosts"
    };
    let code = if cfg!(target_os = "macos") {
        DenialCode::BackendUnavailable
    } else {
        DenialCode::CapabilityMismatch
    };
    RunResponse {
        kind: "raxcell.runResult.v1".to_string(),
        ok: false,
        backend: Some(BackendFamily::MacosSeatbelt),
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

pub fn prepare_run(request: RunRequest, capability_report: ProbeResponse) -> PrepareRunResponse {
    let message = if cfg!(target_os = "macos") {
        "macos-seatbelt backend is declared but prepare lowering has not been attached in Stage 6"
    } else {
        "macos-seatbelt can only prepare on macOS hosts"
    };
    let code = if cfg!(target_os = "macos") {
        DenialCode::BackendUnavailable
    } else {
        DenialCode::CapabilityMismatch
    };
    PrepareRunResponse {
        kind: "raxcell.prepareRunResult.v1".to_string(),
        ok: false,
        backend: Some(BackendFamily::MacosSeatbelt),
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
pub(crate) fn lower_for_seatbelt(
    request: &RunRequest,
) -> Result<MacosSeatbeltLowering, MacosLoweringError> {
    let cwd = std::fs::canonicalize(&request.command.cwd).map_err(|err| {
        MacosLoweringError::SandboxDenied(format!("failed to resolve cwd: {err}"))
    })?;
    let mut read_roots = canonical_roots(request, "read")?;
    let mut write_roots = canonical_roots(request, "write")?;
    let grant_roots = if is_covered(&cwd, &read_roots) || is_covered(&cwd, &write_roots) {
        Vec::new()
    } else {
        apply_cwd_grants(request, &cwd, &mut read_roots, &mut write_roots)?
    };
    let (read_roots, write_roots) = normalize_mount_roots(read_roots, write_roots);
    if !is_covered(&cwd, &read_roots) && !is_covered(&cwd, &write_roots) {
        return Err(MacosLoweringError::PolicyDecisionRequired(
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
    let network_denied = request.enforcement.network.as_deref() == Some("deny");
    let profile = seatbelt_profile(&read_roots, &write_roots, network_denied);
    Ok(MacosSeatbeltLowering {
        executable: MACOS_PATH_TO_SEATBELT_EXECUTABLE.to_string(),
        args: vec!["-p".to_string(), profile.clone()],
        profile,
        filesystem_lowering,
        network_denied,
    })
}

fn canonical_roots(request: &RunRequest, key: &str) -> Result<Vec<PathBuf>, MacosLoweringError> {
    let Some(roots) = request.enforcement.filesystem.get(key) else {
        return Ok(Vec::new());
    };
    roots
        .iter()
        .map(|root| {
            std::fs::canonicalize(root).map_err(|err| {
                MacosLoweringError::SandboxDenied(format!(
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
) -> Result<Vec<LoweredRoot>, MacosLoweringError> {
    let mut grant_roots = Vec::new();
    for grant in request
        .policy_grants
        .iter()
        .filter(|grant| grant.reason == "cwd-outside-declared-roots")
    {
        let granted_path = std::fs::canonicalize(&grant.path).map_err(|err| {
            MacosLoweringError::SandboxDenied(format!(
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

fn seatbelt_profile(
    read_roots: &[PathBuf],
    write_roots: &[PathBuf],
    network_denied: bool,
) -> String {
    let mut sections = vec![
        "(version 1)".to_string(),
        "(deny default)".to_string(),
        "(allow process*)".to_string(),
        "(allow sysctl-read)".to_string(),
        access_policy("file-read*", read_roots),
        access_policy("file-write*", write_roots),
    ];
    sections.push(if network_denied {
        "(deny network*)".to_string()
    } else {
        "(allow network*)".to_string()
    });
    sections
        .into_iter()
        .filter(|section| !section.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn access_policy(action: &str, roots: &[PathBuf]) -> String {
    if roots.is_empty() {
        return String::new();
    }
    let paths = roots
        .iter()
        .map(|root| format!("(subpath \"{}\")", seatbelt_escape(root)))
        .collect::<Vec<_>>()
        .join(" ");
    format!("(allow {action} {paths})")
}

fn seatbelt_escape(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}
