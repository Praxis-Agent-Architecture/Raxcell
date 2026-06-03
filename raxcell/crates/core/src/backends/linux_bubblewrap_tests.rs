use super::linux_bubblewrap::{LinuxRunError, build_bwrap_args};
use raxcell_protocol::RunRequest;
use raxcell_protocol::{LoweredRootAccess, LoweredRootSource};

fn sample_run_request() -> RunRequest {
    serde_json::from_value(serde_json::json!({
        "kind": "raxcell.run.v1",
        "action": {
            "actionId": "act-1",
            "ownerRuntime": "test",
            "intentLabel": "opaque",
            "metadata": {}
        },
        "command": {
            "argv": ["/usr/bin/printf", "hello"],
            "cwd": ".",
            "env": {},
            "stdin": null
        },
        "enforcement": {
            "profile": "workspace-write-no-network",
            "filesystem": { "read": ["."], "write": ["."] },
            "network": "deny",
            "process": { "spawn": true },
            "resources": { "timeoutMs": 1000 }
        },
        "fallback": { "mode": "none" }
    }))
    .unwrap()
}

fn canonical_cwd_string() -> String {
    std::fs::canonicalize(".")
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

#[test]
fn bwrap_args_unshare_network_when_requested() {
    let cwd = std::fs::canonicalize(".").unwrap();
    let (args, _) = build_bwrap_args(&sample_run_request(), &cwd).unwrap();
    assert!(args.iter().any(|arg| arg == "--unshare-net"));
}

#[test]
fn bwrap_args_recreate_usr_merge_root_symlinks() {
    let cwd = std::fs::canonicalize(".").unwrap();
    let (args, _) = build_bwrap_args(&sample_run_request(), &cwd).unwrap();
    let string_args: Vec<String> = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    if std::fs::read_link("/bin").is_ok() {
        assert!(string_args.windows(3).any(|window| window
            == [
                "--symlink".to_string(),
                "usr/bin".to_string(),
                "/bin".to_string()
            ]));
    }
}

#[test]
fn bwrap_args_fail_closed_for_missing_declared_roots() {
    let mut request = sample_run_request();
    let missing = format!("/tmp/raxcell-missing-root-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&missing);
    request
        .enforcement
        .filesystem
        .insert("read".to_string(), vec![missing]);
    let cwd = std::fs::canonicalize(".").unwrap();
    let error = build_bwrap_args(&request, &cwd).unwrap_err();
    assert!(matches!(error, LinuxRunError::SandboxDenied(_)));
}

#[test]
fn bwrap_args_request_policy_decision_when_cwd_is_outside_declared_roots() {
    let mut request = sample_run_request();
    request
        .enforcement
        .filesystem
        .insert("read".to_string(), vec!["/tmp".to_string()]);
    request
        .enforcement
        .filesystem
        .insert("write".to_string(), vec!["/tmp".to_string()]);
    let cwd = std::fs::canonicalize(".").unwrap();
    let error = build_bwrap_args(&request, &cwd).unwrap_err();
    let LinuxRunError::PolicyDecisionRequired(decision) = error else {
        panic!("expected policy decision required");
    };
    assert_eq!(decision.reason, "cwd-outside-declared-roots");
    assert_eq!(decision.path, canonical_cwd_string());
}

#[test]
fn bwrap_args_accept_explicit_cwd_policy_grant() {
    let mut request = sample_run_request();
    request
        .enforcement
        .filesystem
        .insert("read".to_string(), vec!["/tmp".to_string()]);
    request
        .enforcement
        .filesystem
        .insert("write".to_string(), vec!["/tmp".to_string()]);
    request.policy_grants = vec![raxcell_protocol::PolicyGrant {
        reason: "cwd-outside-declared-roots".to_string(),
        path: ".".to_string(),
        access: vec!["read".to_string()],
        granted_by: Some("upper-runtime".to_string()),
    }];
    let cwd = std::fs::canonicalize(".").unwrap();
    let (args, report) = build_bwrap_args(&request, &cwd).unwrap();
    let string_args: Vec<String> = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert!(string_args.windows(3).any(|window| window
        == [
            "--ro-bind".to_string(),
            canonical_cwd_string(),
            canonical_cwd_string()
        ]));
    assert!(
        report
            .declared_roots
            .iter()
            .any(|root| root.path == canonical_cwd_string()
                && root.access == LoweredRootAccess::Read
                && root.source == LoweredRootSource::PolicyGrant)
    );
}

#[test]
fn bwrap_args_ignore_redundant_cwd_policy_grant() {
    let mut request = sample_run_request();
    request.policy_grants = vec![raxcell_protocol::PolicyGrant {
        reason: "cwd-outside-declared-roots".to_string(),
        path: ".".to_string(),
        access: vec!["read".to_string()],
        granted_by: Some("upper-runtime".to_string()),
    }];
    let cwd = std::fs::canonicalize(".").unwrap();
    let (_, report) = build_bwrap_args(&request, &cwd).unwrap();
    assert!(
        report
            .declared_roots
            .iter()
            .any(|root| root.path == canonical_cwd_string()
                && root.access == LoweredRootAccess::Write
                && root.source == LoweredRootSource::Declared)
    );
    assert!(report.warnings.is_empty());
}

#[test]
fn write_child_under_read_parent_keeps_minimal_write_mount() {
    let root = std::env::temp_dir().join(format!("raxcell-nested-{}", std::process::id()));
    let write_child = root.join("write-child");
    std::fs::create_dir_all(&write_child).unwrap();
    let mut request = sample_run_request();
    request.command.cwd = root.to_string_lossy().into_owned();
    request.enforcement.filesystem.insert(
        "read".to_string(),
        vec![root.to_string_lossy().into_owned()],
    );
    request.enforcement.filesystem.insert(
        "write".to_string(),
        vec![write_child.to_string_lossy().into_owned()],
    );
    let cwd = std::fs::canonicalize(&root).unwrap();
    let (args, report) = build_bwrap_args(&request, &cwd).unwrap();
    let string_args: Vec<String> = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let root = std::fs::canonicalize(&root)
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let write_child = std::fs::canonicalize(&write_child)
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(
        string_args
            .windows(3)
            .any(|window| window == ["--ro-bind".to_string(), root.clone(), root.clone()])
    );
    assert!(string_args.windows(3).any(|window| window
        == [
            "--bind".to_string(),
            write_child.clone(),
            write_child.clone()
        ]));
    assert!(
        report
            .declared_roots
            .iter()
            .any(|root| root.access == LoweredRootAccess::Read
                && root.source == LoweredRootSource::Declared)
    );
    assert!(
        report
            .declared_roots
            .iter()
            .any(|root| root.access == LoweredRootAccess::Write
                && root.source == LoweredRootSource::Declared)
    );
}

#[test]
fn read_child_under_write_parent_is_dropped_from_mounts() {
    let root = std::env::temp_dir().join(format!("raxcell-write-parent-{}", std::process::id()));
    let read_child = root.join("read-child");
    std::fs::create_dir_all(&read_child).unwrap();
    let mut request = sample_run_request();
    request.command.cwd = root.to_string_lossy().into_owned();
    request.enforcement.filesystem.insert(
        "read".to_string(),
        vec![read_child.to_string_lossy().into_owned()],
    );
    request.enforcement.filesystem.insert(
        "write".to_string(),
        vec![root.to_string_lossy().into_owned()],
    );
    let cwd = std::fs::canonicalize(&root).unwrap();
    let (args, report) = build_bwrap_args(&request, &cwd).unwrap();
    let string_args: Vec<String> = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let read_child = std::fs::canonicalize(&read_child)
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(!string_args.windows(3).any(|window| window
        == [
            "--ro-bind".to_string(),
            read_child.clone(),
            read_child.clone()
        ]));
    assert!(
        !report
            .declared_roots
            .iter()
            .any(|root| root.path == read_child)
    );
}

#[test]
fn lowering_report_includes_runtime_roots() {
    let cwd = std::fs::canonicalize(".").unwrap();
    let (_, report) = build_bwrap_args(&sample_run_request(), &cwd).unwrap();
    assert!(report.runtime_roots.iter().any(|root| root.path == "/usr"
        && root.access == LoweredRootAccess::Read
        && root.source == LoweredRootSource::BackendRuntime));
    assert!(report.runtime_roots.iter().any(|root| root.path == "/tmp"
        && root.access == LoweredRootAccess::Scratch
        && root.source == LoweredRootSource::BackendRuntime));
}

#[test]
fn lowering_report_drops_runtime_root_covered_by_declared_root() {
    let mut request = sample_run_request();
    request
        .enforcement
        .filesystem
        .insert("read".to_string(), vec!["/tmp".to_string()]);
    request
        .enforcement
        .filesystem
        .insert("write".to_string(), vec!["/tmp".to_string()]);
    request.policy_grants = vec![raxcell_protocol::PolicyGrant {
        reason: "cwd-outside-declared-roots".to_string(),
        path: ".".to_string(),
        access: vec!["read".to_string()],
        granted_by: Some("upper-runtime".to_string()),
    }];
    let cwd = std::fs::canonicalize(".").unwrap();
    let (_, report) = build_bwrap_args(&request, &cwd).unwrap();
    assert!(!report.runtime_roots.iter().any(|root| root.path == "/tmp"
        && root.access == LoweredRootAccess::Scratch
        && root.source == LoweredRootSource::BackendRuntime));
    assert!(report.declared_roots.iter().any(|root| root.path == "/tmp"
        && root.access == LoweredRootAccess::Write
        && root.source == LoweredRootSource::Declared));
}
