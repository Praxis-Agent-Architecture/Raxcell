use super::prepare_run;
use raxcell_protocol::{BackendFamily, DenialCode, RunRequest};

fn sample_run_request() -> RunRequest {
    serde_json::from_value(serde_json::json!({
        "kind": "raxcell.run.v1",
        "backendPreference": ["linux-bubblewrap"],
        "policyGrants": [],
        "action": {
            "actionId": "prepare-1",
            "ownerRuntime": "test",
            "intentLabel": "opaque",
            "metadata": {}
        },
        "command": {
            "argv": ["/usr/bin/sh", "-c", "exit 99"],
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

#[test]
fn prepare_run_lowers_linux_request_without_executing_command() {
    if which::which("bwrap").is_err() || which::which("codex-linux-sandbox").is_err() {
        return;
    }
    let response = prepare_run(sample_run_request());
    assert_eq!(response.kind, "raxcell.prepareRunResult.v1");
    assert!(response.ok);
    assert_eq!(response.backend, Some(BackendFamily::LinuxBubblewrap));
    assert!(response.denial.is_none());
    assert!(response.policy_decision.is_none());
    assert!(response.filesystem_lowering.is_some());
    assert_eq!(
        response.backend_artifacts[0].format,
        "codex-linux-sandbox-argv"
    );
    assert!(
        response.backend_artifacts[0]
            .arguments
            .iter()
            .any(|arg| arg == "--permission-profile")
    );
}

#[test]
fn prepare_run_returns_policy_decision_when_cwd_is_outside_declared_roots() {
    if which::which("bwrap").is_err() {
        return;
    }
    let mut request = sample_run_request();
    request
        .enforcement
        .filesystem
        .insert("read".to_string(), vec!["/tmp".to_string()]);
    request
        .enforcement
        .filesystem
        .insert("write".to_string(), vec!["/tmp".to_string()]);
    let response = prepare_run(request);
    assert!(!response.ok);
    assert_eq!(
        response.denial.as_ref().map(|denial| &denial.code),
        Some(&DenialCode::PolicyDecisionRequired)
    );
    assert_eq!(
        response
            .policy_decision
            .as_ref()
            .map(|decision| decision.reason.as_str()),
        Some("cwd-outside-declared-roots")
    );
    assert!(response.filesystem_lowering.is_none());
    assert!(response.backend_artifacts.is_empty());
}
