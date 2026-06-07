use crate::backends::{linux_bubblewrap, macos_seatbelt, windows_native};
use crate::probe::probe;
use raxcell_protocol::{
    BackendFamily, Denial, DenialCode, PrepareRunResponse, ProbeRequest, ProbeResponse, RunRequest,
};

pub fn prepare_run(request: RunRequest) -> PrepareRunResponse {
    let capability_report = probe(ProbeRequest {
        kind: "raxcell.probe.v1".to_string(),
        platform: Some("auto".to_string()),
        backend_preference: request.backend_preference.clone(),
        requirements: Default::default(),
    });
    match capability_report.selected_backend.clone() {
        Some(BackendFamily::LinuxBubblewrap) => {
            linux_bubblewrap::prepare_run(request, capability_report)
        }
        Some(BackendFamily::MacosSeatbelt) => {
            macos_seatbelt::prepare_run(request, capability_report)
        }
        Some(BackendFamily::WindowsNative) => {
            windows_native::prepare_run(request, capability_report, BackendFamily::WindowsNative)
        }
        Some(BackendFamily::WindowsElevated) => {
            windows_native::prepare_run(request, capability_report, BackendFamily::WindowsElevated)
        }
        Some(BackendFamily::WindowsUnelevated) => windows_native::prepare_run(
            request,
            capability_report,
            BackendFamily::WindowsUnelevated,
        ),
        Some(BackendFamily::HostObserved) => fail_closed(
            request,
            capability_report,
            DenialCode::SandboxDenied,
            "host-observed is observation only and refuses isolated preparation".to_string(),
        ),
        Some(BackendFamily::External) | None => fail_closed(
            request,
            capability_report,
            DenialCode::BackendUnavailable,
            "no built-in execution backend is available for this prepare request".to_string(),
        ),
    }
}

fn fail_closed(
    request: RunRequest,
    capability_report: ProbeResponse,
    code: DenialCode,
    message: String,
) -> PrepareRunResponse {
    PrepareRunResponse {
        kind: "raxcell.prepareRunResult.v1".to_string(),
        ok: false,
        backend: capability_report.selected_backend.clone(),
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
