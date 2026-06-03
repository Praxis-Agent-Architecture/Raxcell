use super::windows_native::{WindowsLoweringError, WindowsTokenMode, lower_for_windows_native};
use raxcell_protocol::{BackendFamily, LoweredRootAccess, RunRequest};

fn sample_run_request(root: &std::path::Path, write_roots: Vec<String>) -> RunRequest {
    serde_json::from_value(serde_json::json!({
        "kind": "raxcell.run.v1",
        "backendPreference": ["windows-elevated"],
        "policyGrants": [],
        "action": {
            "actionId": "windows-lowering-1",
            "ownerRuntime": "test",
            "intentLabel": "opaque",
            "metadata": {}
        },
        "command": {
            "argv": ["cmd.exe", "/C", "echo hello"],
            "cwd": root.to_string_lossy(),
            "env": {},
            "stdin": null
        },
        "enforcement": {
            "profile": "workspace-write-no-network",
            "filesystem": {
                "read": [root.to_string_lossy()],
                "write": write_roots
            },
            "network": "deny",
            "process": { "spawn": true },
            "resources": { "timeoutMs": 1000 }
        },
        "fallback": { "mode": "none" }
    }))
    .unwrap()
}

#[test]
fn windows_lowering_uses_readonly_token_without_write_roots() {
    let root = std::env::temp_dir().join(format!("raxcell-windows-ro-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let request = sample_run_request(&root, Vec::new());
    let lowering = lower_for_windows_native(&request, BackendFamily::WindowsElevated).unwrap();
    assert_eq!(lowering.backend, BackendFamily::WindowsElevated);
    assert_eq!(lowering.token_mode, WindowsTokenMode::ReadOnlyCapability);
    assert!(lowering.network_blocked);
    assert!(
        lowering
            .acl_roots
            .iter()
            .any(|root| root.access == LoweredRootAccess::Read)
    );
}

#[test]
fn windows_lowering_uses_writable_token_with_write_roots() {
    let root = std::env::temp_dir().join(format!("raxcell-windows-rw-{}", std::process::id()));
    let write_root = root.join("write");
    std::fs::create_dir_all(&write_root).unwrap();
    let request = sample_run_request(&root, vec![write_root.to_string_lossy().into_owned()]);
    let lowering = lower_for_windows_native(&request, BackendFamily::WindowsElevated).unwrap();
    assert_eq!(
        lowering.token_mode,
        WindowsTokenMode::WritableRootsCapability
    );
    assert!(
        lowering
            .acl_roots
            .iter()
            .any(|root| root.access == LoweredRootAccess::Write)
    );
    assert!(
        lowering
            .filesystem_lowering
            .declared_roots
            .iter()
            .any(|root| root.access == LoweredRootAccess::Write)
    );
}

#[test]
fn windows_lowering_requests_policy_decision_for_uncovered_cwd() {
    let root = std::env::temp_dir().join(format!("raxcell-windows-policy-{}", std::process::id()));
    let declared = root.join("declared");
    let cwd = root.join("cwd");
    std::fs::create_dir_all(&declared).unwrap();
    std::fs::create_dir_all(&cwd).unwrap();
    let mut request = sample_run_request(&declared, Vec::new());
    request.command.cwd = cwd.to_string_lossy().into_owned();
    let error = lower_for_windows_native(&request, BackendFamily::WindowsElevated).unwrap_err();
    let WindowsLoweringError::PolicyDecisionRequired(decision) = error else {
        panic!("expected policy decision required");
    };
    assert_eq!(decision.reason, "cwd-outside-declared-roots");
}
