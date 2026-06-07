use super::explain_backend;
use raxcell_protocol::{BackendFamily, ExplainBackendRequest};

#[test]
fn explain_backend_describes_linux_operations_and_primitives() {
    let response = explain_backend(ExplainBackendRequest {
        kind: "raxcell.explainBackend.v1".to_string(),
        platform: Some("auto".to_string()),
        backend_preference: vec![BackendFamily::LinuxBubblewrap],
    });
    assert_eq!(response.kind, "raxcell.explainBackendResult.v1");
    assert_eq!(
        response.selected_backend,
        Some(BackendFamily::LinuxBubblewrap)
    );
    assert!(response.operations.iter().any(|operation| {
        operation.method == "prepareRun"
            && operation
                .side_effects
                .contains(&"no-process-spawn".to_string())
    }));
    assert!(response.operations.iter().any(|operation| {
        operation.method == "run"
            && operation
                .side_effects
                .contains(&"spawns-process".to_string())
    }));
    assert!(
        response
            .explanation
            .isolation_primitives
            .contains(&"bubblewrap.bind-mounts".to_string())
    );
}

#[test]
fn explain_backend_describes_host_observed_as_observation_only() {
    let response = explain_backend(ExplainBackendRequest {
        kind: "raxcell.explainBackend.v1".to_string(),
        platform: Some("auto".to_string()),
        backend_preference: vec![BackendFamily::HostObserved],
    });
    assert_eq!(response.selected_backend, Some(BackendFamily::HostObserved));
    assert!(
        response
            .explanation
            .isolation_primitives
            .contains(&"observation-only".to_string())
    );
}

#[test]
fn explain_backend_describes_windows_native_primitives() {
    let response = explain_backend(ExplainBackendRequest {
        kind: "raxcell.explainBackend.v1".to_string(),
        platform: Some("auto".to_string()),
        backend_preference: vec![BackendFamily::WindowsNative],
    });
    assert_eq!(
        response.selected_backend,
        Some(BackendFamily::WindowsNative)
    );
    assert!(
        response
            .explanation
            .isolation_primitives
            .contains(&"windows.restricted-token".to_string())
    );
}
