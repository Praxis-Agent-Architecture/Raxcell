use super::run::{run, run_fail_closed};
use crate::probe::probe;
use raxcell_protocol::{BackendFamily, DenialCode, ProbeRequest, RunRequest};

fn sample_run_request() -> RunRequest {
    serde_json::from_value(serde_json::json!({
        "kind": "raxcell.run.v1",
        "action": {
            "actionId": "act-1",
            "ownerRuntime": "praxis",
            "intentLabel": "opaque",
            "metadata": { "toolId": "not-inspected-by-raxcell" }
        },
        "command": {
            "argv": ["echo", "hello"],
            "cwd": "/tmp",
            "env": {},
            "stdin": null
        },
        "enforcement": {
            "profile": "workspace-write-no-network",
            "filesystem": { "read": ["/tmp"], "write": ["/tmp"] },
            "network": "deny",
            "process": { "spawn": true },
            "resources": { "timeoutMs": 1000 }
        },
        "fallback": { "mode": "none" }
    }))
    .unwrap()
}

#[test]
fn run_fails_closed_when_backend_is_not_ready() {
    let mut request = sample_run_request();
    request.backend_preference = vec![BackendFamily::MacosSeatbelt];
    let response = run(request);
    assert!(!response.ok);
    assert_eq!(
        response.denial.unwrap().code,
        DenialCode::CapabilityMismatch
    );
}

#[test]
fn run_does_not_apply_rollback_without_an_explicit_fallback_report() {
    let mut request = sample_run_request();
    request.backend_preference = vec![BackendFamily::HostObserved];
    let response = run(request);
    assert!(response.fallback.is_none());
}

#[test]
fn legacy_fail_closed_helper_still_refuses_ready_backends() {
    let capability_report = probe(ProbeRequest {
        kind: "raxcell.probe.v1".to_string(),
        platform: Some("auto".to_string()),
        backend_preference: vec![BackendFamily::HostObserved],
        requirements: Default::default(),
    });
    let response = run_fail_closed(sample_run_request(), capability_report);
    assert!(!response.ok);
    assert_eq!(
        response.denial.unwrap().code,
        DenialCode::BackendUnavailable
    );
}
