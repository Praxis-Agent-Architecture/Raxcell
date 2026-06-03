use crate::backends::linux_bubblewrap;
use crate::probe::probe;
use raxcell_protocol::{
    BackendExplanation, BackendFamily, ExplainBackendRequest, ExplainBackendResponse,
    OperationSchema, ProbeRequest, ProbeResponse,
};

pub fn explain_backend(request: ExplainBackendRequest) -> ExplainBackendResponse {
    let probe = probe(ProbeRequest {
        kind: "raxcell.probe.v1".to_string(),
        platform: request.platform.clone(),
        backend_preference: request.backend_preference,
        requirements: Default::default(),
    });
    let explanation = backend_explanation(&probe);
    ExplainBackendResponse {
        kind: "raxcell.explainBackendResult.v1".to_string(),
        selected_backend: probe.selected_backend.clone(),
        probe,
        operations: operation_schemas(),
        explanation,
    }
}

fn backend_explanation(probe: &ProbeResponse) -> BackendExplanation {
    match probe.selected_backend.clone() {
        Some(BackendFamily::LinuxBubblewrap) => BackendExplanation {
            backend: Some(BackendFamily::LinuxBubblewrap),
            host_platforms: vec!["linux".to_string(), "wsl2".to_string()],
            isolation_primitives: vec![
                "bubblewrap.user-namespace".to_string(),
                "bubblewrap.bind-mounts".to_string(),
                "bubblewrap.unshare-net".to_string(),
                "bubblewrap.proc-dev-tmpfs".to_string(),
                "process.timeout".to_string(),
            ],
            runtime_roots: linux_bubblewrap::explain_runtime_roots(),
            limits: backend_limits(probe),
            public_safe_message: probe.public_safe_message.clone(),
        },
        Some(BackendFamily::MacosSeatbelt) => BackendExplanation {
            backend: Some(BackendFamily::MacosSeatbelt),
            host_platforms: vec!["macos".to_string()],
            isolation_primitives: vec![
                "apple-seatbelt.profile".to_string(),
                "seatbelt.filesystem-rules".to_string(),
                "process.timeout".to_string(),
            ],
            runtime_roots: Vec::new(),
            limits: backend_limits(probe),
            public_safe_message: probe.public_safe_message.clone(),
        },
        Some(BackendFamily::WindowsElevated) => BackendExplanation {
            backend: Some(BackendFamily::WindowsElevated),
            host_platforms: vec!["windows".to_string()],
            isolation_primitives: vec![
                "windows.restricted-token".to_string(),
                "windows-acl.workspace-rules".to_string(),
                "windows-filtering-platform.network".to_string(),
                "process.timeout".to_string(),
            ],
            runtime_roots: Vec::new(),
            limits: backend_limits(probe),
            public_safe_message: probe.public_safe_message.clone(),
        },
        Some(BackendFamily::WindowsUnelevated) => BackendExplanation {
            backend: Some(BackendFamily::WindowsUnelevated),
            host_platforms: vec!["windows".to_string()],
            isolation_primitives: vec![
                "windows.restricted-token".to_string(),
                "windows-acl.workspace-rules".to_string(),
                "process.timeout".to_string(),
            ],
            runtime_roots: Vec::new(),
            limits: backend_limits(probe),
            public_safe_message: probe.public_safe_message.clone(),
        },
        Some(BackendFamily::HostObserved) => BackendExplanation {
            backend: Some(BackendFamily::HostObserved),
            host_platforms: vec![
                "linux".to_string(),
                "macos".to_string(),
                "windows".to_string(),
            ],
            isolation_primitives: vec!["observation-only".to_string()],
            runtime_roots: Vec::new(),
            limits: backend_limits(probe),
            public_safe_message: probe.public_safe_message.clone(),
        },
        Some(BackendFamily::External) | None => BackendExplanation {
            backend: probe.selected_backend.clone(),
            host_platforms: Vec::new(),
            isolation_primitives: vec!["external-backend-contract".to_string()],
            runtime_roots: Vec::new(),
            limits: backend_limits(probe),
            public_safe_message: probe.public_safe_message.clone(),
        },
    }
}

fn backend_limits(probe: &ProbeResponse) -> Vec<String> {
    let mut limits = probe.limits.clone();
    limits.extend(probe.weaknesses.clone());
    limits.extend(probe.missing.clone());
    limits
}

fn operation_schemas() -> Vec<OperationSchema> {
    vec![
        operation_schema(
            "probe",
            "raxcell.probe.v1",
            "raxcell.probeResult.v1",
            vec!["side-effect-free"],
        ),
        operation_schema(
            "resolveProfile",
            "raxcell.resolveProfile.v1",
            "raxcell.resolvedProfile.v1",
            vec!["reads-policy-pack-files"],
        ),
        operation_schema(
            "prepareRun",
            "raxcell.run.v1",
            "raxcell.prepareRunResult.v1",
            vec!["side-effect-free", "no-process-spawn"],
        ),
        operation_schema(
            "run",
            "raxcell.run.v1",
            "raxcell.runResult.v1",
            vec!["spawns-process", "enforces-backend-boundaries"],
        ),
        operation_schema(
            "explainBackend",
            "raxcell.explainBackend.v1",
            "raxcell.explainBackendResult.v1",
            vec!["side-effect-free"],
        ),
    ]
}

fn operation_schema(
    method: &str,
    input_kind: &str,
    output_kind: &str,
    side_effects: Vec<&str>,
) -> OperationSchema {
    OperationSchema {
        method: method.to_string(),
        input_kind: input_kind.to_string(),
        output_kind: output_kind.to_string(),
        side_effects: side_effects.into_iter().map(str::to_string).collect(),
    }
}
