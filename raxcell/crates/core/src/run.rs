use crate::backends::{linux_bubblewrap, macos_seatbelt, windows_native};
use crate::probe::probe;
use raxcell_protocol::{
    BackendFamily, Denial, DenialCode, ProbeRequest, ProbeResponse, RunRequest, RunResponse,
};

pub fn run(request: RunRequest) -> RunResponse {
    let capability_report = probe(ProbeRequest {
        kind: "raxcell.probe.v1".to_string(),
        platform: Some("auto".to_string()),
        backend_preference: request.backend_preference.clone(),
        requirements: Default::default(),
    });
    match capability_report.selected_backend.clone() {
        Some(BackendFamily::LinuxBubblewrap) => linux_bubblewrap::run(request, capability_report),
        Some(BackendFamily::MacosSeatbelt) => macos_seatbelt::run(request, capability_report),
        Some(BackendFamily::WindowsNative) => {
            windows_native::run(request, capability_report, BackendFamily::WindowsNative)
        }
        Some(BackendFamily::WindowsElevated) => {
            windows_native::run(request, capability_report, BackendFamily::WindowsElevated)
        }
        Some(BackendFamily::WindowsUnelevated) => {
            windows_native::run(request, capability_report, BackendFamily::WindowsUnelevated)
        }
        Some(BackendFamily::HostObserved) => fail_closed(
            request,
            capability_report,
            DenialCode::SandboxDenied,
            "host-observed is observation only and refuses isolated execution".to_string(),
        ),
        Some(BackendFamily::External) | None => fail_closed(
            request,
            capability_report,
            DenialCode::BackendUnavailable,
            "no built-in execution backend is available for this request".to_string(),
        ),
    }
}

#[cfg(test)]
pub fn run_fail_closed(request: RunRequest, capability_report: ProbeResponse) -> RunResponse {
    let message = if capability_report.ready {
        "Requested backend refuses execution until a real runner is attached".to_string()
    } else {
        "Requested backend is not ready; Raxcell fails closed by default".to_string()
    };
    fail_closed(
        request,
        capability_report.clone(),
        if capability_report.ready {
            DenialCode::BackendUnavailable
        } else {
            DenialCode::CapabilityMismatch
        },
        message,
    )
}

fn fail_closed(
    request: RunRequest,
    capability_report: ProbeResponse,
    code: DenialCode,
    message: String,
) -> RunResponse {
    RunResponse {
        kind: "raxcell.runResult.v1".to_string(),
        ok: false,
        backend: capability_report.selected_backend.clone(),
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        timed_out: false,
        denial: Some(Denial {
            code,
            message: format!("{message}; actionId={}", request.action.action_id),
            public_safe: true,
        }),
        policy_decision: None,
        filesystem_lowering: None,
        fallback: None,
        capability_report: Some(capability_report),
    }
}
