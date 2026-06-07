use super::*;
use std::collections::BTreeMap;

#[test]
fn backend_family_uses_kebab_case() {
    let value = serde_json::to_value(BackendFamily::LinuxBubblewrap).unwrap();
    assert_eq!(value, serde_json::json!("linux-bubblewrap"));
    let value = serde_json::to_value(BackendFamily::WindowsNative).unwrap();
    assert_eq!(value, serde_json::json!("windows-native"));
}

#[test]
fn action_metadata_is_opaque_and_round_trips() {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "toolId".to_string(),
        serde_json::json!("praxis.baseTool.shell.run"),
    );
    let action = OpaqueAction {
        action_id: "act-1".to_string(),
        owner_runtime: Some("praxis".to_string()),
        intent_label: Some("opaque runtime metadata".to_string()),
        metadata,
    };
    let encoded = serde_json::to_string(&action).unwrap();
    let decoded: OpaqueAction = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, action);
}

#[test]
fn denial_code_uses_stable_uppercase_wire_names() {
    let value = serde_json::to_value(DenialCode::CapabilityMismatch).unwrap();
    assert_eq!(value, serde_json::json!("CAPABILITY_MISMATCH"));
    let value = serde_json::to_value(DenialCode::PolicyDecisionRequired).unwrap();
    assert_eq!(value, serde_json::json!("POLICY_DECISION_REQUIRED"));
}

#[test]
fn policy_preset_uses_kebab_case() {
    let value = serde_json::to_value(PolicyPreset::WorkspaceReadonly).unwrap();
    assert_eq!(value, serde_json::json!("workspace-readonly"));
}

#[test]
fn resolve_profile_request_uses_stable_wire_names() {
    let request = ResolveProfileRequest {
        kind: "raxcell.resolveProfile.v1".to_string(),
        pack_paths: vec!["raxcell.policy.json".to_string()],
        profile: "workspace-write-no-network".to_string(),
        variables: BTreeMap::new(),
    };
    let value = serde_json::to_value(request).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "kind": "raxcell.resolveProfile.v1",
            "packPaths": ["raxcell.policy.json"],
            "profile": "workspace-write-no-network",
            "variables": {}
        })
    );
}

#[test]
fn policy_grants_use_stable_wire_names() {
    let grant = PolicyGrant {
        reason: "cwd-outside-declared-roots".to_string(),
        path: "/workspace/project".to_string(),
        access: vec!["read".to_string()],
        granted_by: Some("upper-runtime".to_string()),
    };
    let value = serde_json::to_value(grant).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "reason": "cwd-outside-declared-roots",
            "path": "/workspace/project",
            "access": ["read"],
            "grantedBy": "upper-runtime"
        })
    );
}

#[test]
fn filesystem_lowering_report_uses_stable_wire_names() {
    let report = FileSystemLoweringReport {
        declared_roots: vec![LoweredRoot {
            path: "/workspace".to_string(),
            access: LoweredRootAccess::Read,
            source: LoweredRootSource::Declared,
        }],
        runtime_roots: vec![LoweredRoot {
            path: "/bin".to_string(),
            access: LoweredRootAccess::RuntimeLink,
            source: LoweredRootSource::BackendRuntime,
        }],
        policy_grants: Vec::new(),
        warnings: Vec::new(),
    };
    let value = serde_json::to_value(report).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "declaredRoots": [
                { "path": "/workspace", "access": "read", "source": "declared" }
            ],
            "runtimeRoots": [
                { "path": "/bin", "access": "runtime-link", "source": "backend-runtime" }
            ],
            "policyGrants": [],
            "warnings": []
        })
    );
}

#[test]
fn prepare_run_response_uses_stable_wire_names() {
    let response = PrepareRunResponse {
        kind: "raxcell.prepareRunResult.v1".to_string(),
        ok: true,
        backend: Some(BackendFamily::LinuxBubblewrap),
        denial: None,
        policy_decision: None,
        filesystem_lowering: Some(FileSystemLoweringReport {
            declared_roots: vec![LoweredRoot {
                path: "/workspace".to_string(),
                access: LoweredRootAccess::Write,
                source: LoweredRootSource::Declared,
            }],
            runtime_roots: Vec::new(),
            policy_grants: Vec::new(),
            warnings: Vec::new(),
        }),
        backend_artifacts: vec![BackendLoweringArtifact {
            backend: BackendFamily::LinuxBubblewrap,
            format: "linux-bubblewrap-argv".to_string(),
            arguments: vec!["--die-with-parent".to_string()],
            data: BTreeMap::from([(
                "executable".to_string(),
                serde_json::json!("/usr/bin/bwrap"),
            )]),
            warnings: Vec::new(),
        }],
        capability_report: None,
    };
    let value = serde_json::to_value(response).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "kind": "raxcell.prepareRunResult.v1",
            "ok": true,
            "backend": "linux-bubblewrap",
            "denial": null,
            "policyDecision": null,
            "filesystemLowering": {
                "declaredRoots": [
                    { "path": "/workspace", "access": "write", "source": "declared" }
                ],
                "runtimeRoots": [],
                "policyGrants": [],
                "warnings": []
            },
            "backendArtifacts": [
                {
                    "backend": "linux-bubblewrap",
                    "format": "linux-bubblewrap-argv",
                    "arguments": ["--die-with-parent"],
                    "data": { "executable": "/usr/bin/bwrap" },
                    "warnings": []
                }
            ],
            "capabilityReport": null
        })
    );
}

#[test]
fn explain_backend_response_uses_stable_wire_names() {
    let response = ExplainBackendResponse {
        kind: "raxcell.explainBackendResult.v1".to_string(),
        selected_backend: Some(BackendFamily::LinuxBubblewrap),
        probe: ProbeResponse {
            kind: "raxcell.probeResult.v1".to_string(),
            ready: true,
            selected_backend: Some(BackendFamily::LinuxBubblewrap),
            supports: BTreeMap::new(),
            limits: Vec::new(),
            weaknesses: Vec::new(),
            missing: Vec::new(),
            next_actions: Vec::new(),
            public_safe_message: "ready".to_string(),
        },
        operations: vec![OperationSchema {
            method: "prepareRun".to_string(),
            input_kind: "raxcell.run.v1".to_string(),
            output_kind: "raxcell.prepareRunResult.v1".to_string(),
            side_effects: vec!["no-process-spawn".to_string()],
        }],
        explanation: BackendExplanation {
            backend: Some(BackendFamily::LinuxBubblewrap),
            host_platforms: vec!["linux".to_string()],
            isolation_primitives: vec!["bubblewrap.bind-mounts".to_string()],
            runtime_roots: Vec::new(),
            limits: Vec::new(),
            public_safe_message: "ready".to_string(),
        },
    };
    let value = serde_json::to_value(response).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "kind": "raxcell.explainBackendResult.v1",
            "selectedBackend": "linux-bubblewrap",
            "probe": {
                "kind": "raxcell.probeResult.v1",
                "ready": true,
                "selectedBackend": "linux-bubblewrap",
                "supports": {},
                "limits": [],
                "weaknesses": [],
                "missing": [],
                "nextActions": [],
                "publicSafeMessage": "ready"
            },
            "operations": [
                {
                    "method": "prepareRun",
                    "inputKind": "raxcell.run.v1",
                    "outputKind": "raxcell.prepareRunResult.v1",
                    "sideEffects": ["no-process-spawn"]
                }
            ],
            "explanation": {
                "backend": "linux-bubblewrap",
                "hostPlatforms": ["linux"],
                "isolationPrimitives": ["bubblewrap.bind-mounts"],
                "runtimeRoots": [],
                "limits": [],
                "publicSafeMessage": "ready"
            }
        })
    );
}
