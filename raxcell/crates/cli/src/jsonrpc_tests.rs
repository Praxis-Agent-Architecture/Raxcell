use super::jsonrpc::{handle_line, run_payload};
use raxcell_protocol::{BackendFamily, Denial, DenialCode, PolicyDecisionRequired, RunResponse};

fn fixture_path(path: &str) -> String {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .nth(2)
        .unwrap()
        .join(path)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn probe_method_returns_jsonrpc_response() {
    let line = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "1",
        "method": "probe",
        "params": {
            "kind": "raxcell.probe.v1",
            "platform": "auto",
            "backendPreference": []
        }
    })
    .to_string();
    let response = handle_line(&line).unwrap();
    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["jsonrpc"], "2.0");
    assert_eq!(value["id"], "1");
    assert_eq!(value["result"]["kind"], "raxcell.probeResult.v1");
}

#[test]
fn explain_backend_method_returns_backend_explanation() {
    let line = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "explain-1",
        "method": "explainBackend",
        "params": {
            "kind": "raxcell.explainBackend.v1",
            "platform": "auto",
            "backendPreference": ["linux-bubblewrap"]
        }
    })
    .to_string();
    let response = handle_line(&line).unwrap();
    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["result"]["kind"], "raxcell.explainBackendResult.v1");
    assert_eq!(value["result"]["selectedBackend"], "linux-bubblewrap");
    assert!(
        value["result"]["operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation["method"] == "prepareRun")
    );
}

#[test]
fn unknown_method_returns_structured_error() {
    let line = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "2",
        "method": "missing",
        "params": {}
    })
    .to_string();
    let response = handle_line(&line).unwrap();
    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["result"]["error"]["code"], "METHOD_NOT_FOUND");
}

#[test]
fn run_event_uses_unquoted_request_id() {
    let line = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "run-1",
        "method": "run",
        "params": {
            "kind": "raxcell.run.v1",
            "backendPreference": ["host-observed"],
            "action": {
                "actionId": "act-1",
                "ownerRuntime": "example",
                "intentLabel": "opaque",
                "metadata": {}
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
        }
    })
    .to_string();
    let response = handle_line(&line).unwrap();
    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["result"]["events"][0]["requestId"], "run-1");
    assert_eq!(value["result"]["result"]["ok"], false);
}

#[test]
fn prepare_run_method_returns_prepare_result() {
    let line = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "prepare-1",
        "method": "prepareRun",
        "params": {
            "kind": "raxcell.run.v1",
            "backendPreference": ["host-observed"],
            "policyGrants": [],
            "action": {
                "actionId": "act-prepare-1",
                "ownerRuntime": "example",
                "intentLabel": "opaque",
                "metadata": {}
            },
            "command": {
                "argv": ["sh", "-c", "exit 99"],
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
        }
    })
    .to_string();
    let response = handle_line(&line).unwrap();
    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["result"]["kind"], "raxcell.prepareRunResult.v1");
    assert_eq!(value["result"]["ok"], false);
    assert_eq!(value["result"]["backend"], "host-observed");
}

#[test]
fn resolve_profile_method_returns_resolved_enforcement() {
    let pack_path = fixture_path("fixtures/policy.workspace.json");
    let line = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "resolve-1",
        "method": "resolveProfile",
        "params": {
            "kind": "raxcell.resolveProfile.v1",
            "packPaths": [pack_path],
            "profile": "workspace-write-no-network",
            "variables": {
                "workspace": "/tmp/raxcell-workspace",
                "home": "/home/agent",
                "tmp": "/tmp/raxcell"
            }
        }
    })
    .to_string();
    let response = handle_line(&line).unwrap();
    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["result"]["kind"], "raxcell.resolvedProfile.v1");
    assert_eq!(
        value["result"]["enforcement"]["filesystem"]["read"][0],
        "/tmp/raxcell-workspace"
    );
}

#[test]
fn run_payload_emits_policy_decision_required_event() {
    let result = RunResponse {
        kind: "raxcell.runResult.v1".to_string(),
        ok: false,
        backend: Some(BackendFamily::LinuxBubblewrap),
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        timed_out: false,
        denial: Some(Denial {
            code: DenialCode::PolicyDecisionRequired,
            message: "upper policy decision required".to_string(),
            public_safe: true,
        }),
        policy_decision: Some(PolicyDecisionRequired {
            reason: "cwd-outside-declared-roots".to_string(),
            path: "/workspace/project".to_string(),
            required: vec!["filesystem.read".to_string()],
            public_safe_message: "upper policy decision required".to_string(),
        }),
        environment_gap: None,
        filesystem_lowering: None,
        backend_artifacts: Vec::new(),
        fallback: None,
        capability_report: None,
    };
    let value = run_payload("run-2".to_string(), result).unwrap();
    assert_eq!(value["events"][1]["event"], "policy.decisionRequired");
    let data = value["events"][1]["data"].as_str().unwrap();
    let data: serde_json::Value = serde_json::from_str(data).unwrap();
    assert_eq!(data["reason"], "cwd-outside-declared-roots");
}
