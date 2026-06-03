use super::macos_seatbelt::{MacosLoweringError, lower_for_seatbelt};
use raxcell_protocol::{LoweredRootAccess, LoweredRootSource, RunRequest};

fn sample_run_request(root: &std::path::Path) -> RunRequest {
    serde_json::from_value(serde_json::json!({
        "kind": "raxcell.run.v1",
        "backendPreference": ["macos-seatbelt"],
        "policyGrants": [],
        "action": {
            "actionId": "macos-lowering-1",
            "ownerRuntime": "test",
            "intentLabel": "opaque",
            "metadata": {}
        },
        "command": {
            "argv": ["/bin/printf", "hello"],
            "cwd": root.to_string_lossy(),
            "env": {},
            "stdin": null
        },
        "enforcement": {
            "profile": "workspace-write-no-network",
            "filesystem": {
                "read": [root.to_string_lossy()],
                "write": [root.join("write").to_string_lossy()]
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
fn seatbelt_lowering_builds_profile_and_report() {
    let root = std::env::temp_dir().join(format!("raxcell-macos-{}", std::process::id()));
    let write_root = root.join("write");
    std::fs::create_dir_all(&write_root).unwrap();
    let request = sample_run_request(&root);
    let lowering = lower_for_seatbelt(&request).unwrap();
    assert_eq!(lowering.executable, "/usr/bin/sandbox-exec");
    assert_eq!(lowering.args[0], "-p");
    assert!(lowering.profile.contains("(deny default)"));
    assert!(lowering.profile.contains("(allow file-read*"));
    assert!(lowering.profile.contains("(allow file-write*"));
    assert!(lowering.profile.contains("(deny network*)"));
    assert!(lowering.network_denied);
    assert!(
        lowering
            .filesystem_lowering
            .declared_roots
            .iter()
            .any(|root| root.access == LoweredRootAccess::Read
                && root.source == LoweredRootSource::Declared)
    );
    assert!(
        lowering
            .filesystem_lowering
            .declared_roots
            .iter()
            .any(|root| root.access == LoweredRootAccess::Write
                && root.source == LoweredRootSource::Declared)
    );
}

#[test]
fn seatbelt_lowering_requests_policy_decision_for_uncovered_cwd() {
    let root = std::env::temp_dir().join(format!("raxcell-macos-policy-{}", std::process::id()));
    let declared = root.join("declared");
    let cwd = root.join("cwd");
    std::fs::create_dir_all(&declared).unwrap();
    std::fs::create_dir_all(declared.join("write")).unwrap();
    std::fs::create_dir_all(&cwd).unwrap();
    let mut request = sample_run_request(&declared);
    request.command.cwd = cwd.to_string_lossy().into_owned();
    let error = lower_for_seatbelt(&request).unwrap_err();
    let MacosLoweringError::PolicyDecisionRequired(decision) = error else {
        panic!("expected policy decision required");
    };
    assert_eq!(decision.reason, "cwd-outside-declared-roots");
}
