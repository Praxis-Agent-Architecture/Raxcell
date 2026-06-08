use raxcell_protocol::{
    BackendFamily, Denial, DenialCode, EnvironmentGap, PolicyDecisionRequired, PrepareRunResponse,
    ProbeResponse, RunRequest, RunResponse,
};

use super::error::LinuxRunError;

pub(super) fn fail(
    request: RunRequest,
    capability_report: ProbeResponse,
    code: DenialCode,
    message: String,
) -> RunResponse {
    RunResponse {
        kind: "raxcell.runResult.v1".to_string(),
        ok: false,
        backend: Some(BackendFamily::LinuxBubblewrap),
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        timed_out: false,
        denial: Some(Denial {
            code,
            message: format!("{message}; actionId={}", request.action.action_id),
            public_safe: true,
        }),
        environment_gap: None,
        policy_decision: None,
        filesystem_lowering: None,
        backend_artifacts: Vec::new(),
        fallback: None,
        capability_report: Some(capability_report),
    }
}

pub(super) fn fail_environment_gap(
    request: RunRequest,
    capability_report: ProbeResponse,
    code: DenialCode,
    gap: EnvironmentGap,
) -> RunResponse {
    RunResponse {
        kind: "raxcell.runResult.v1".to_string(),
        ok: false,
        backend: Some(BackendFamily::LinuxBubblewrap),
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        timed_out: false,
        denial: Some(Denial {
            code,
            message: format!(
                "{}; actionId={}",
                gap.public_safe_message, request.action.action_id
            ),
            public_safe: true,
        }),
        environment_gap: Some(gap),
        policy_decision: None,
        filesystem_lowering: None,
        backend_artifacts: Vec::new(),
        fallback: None,
        capability_report: Some(capability_report),
    }
}

pub(super) fn fail_policy_decision_required(
    request: RunRequest,
    capability_report: ProbeResponse,
    decision: PolicyDecisionRequired,
) -> RunResponse {
    RunResponse {
        kind: "raxcell.runResult.v1".to_string(),
        ok: false,
        backend: Some(BackendFamily::LinuxBubblewrap),
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        timed_out: false,
        denial: Some(Denial {
            code: DenialCode::PolicyDecisionRequired,
            message: format!(
                "{}; actionId={}",
                decision.public_safe_message, request.action.action_id
            ),
            public_safe: true,
        }),
        environment_gap: None,
        policy_decision: Some(decision),
        filesystem_lowering: None,
        backend_artifacts: Vec::new(),
        fallback: None,
        capability_report: Some(capability_report),
    }
}

pub(super) fn fail_prepare(
    request: RunRequest,
    capability_report: ProbeResponse,
    code: DenialCode,
    message: String,
) -> PrepareRunResponse {
    PrepareRunResponse {
        kind: "raxcell.prepareRunResult.v1".to_string(),
        ok: false,
        backend: Some(BackendFamily::LinuxBubblewrap),
        denial: Some(Denial {
            code,
            message: format!("{message}; actionId={}", request.action.action_id),
            public_safe: true,
        }),
        environment_gap: None,
        policy_decision: None,
        filesystem_lowering: None,
        backend_artifacts: Vec::new(),
        capability_report: Some(capability_report),
    }
}

pub(super) fn fail_prepare_environment_gap(
    request: RunRequest,
    capability_report: ProbeResponse,
    code: DenialCode,
    gap: EnvironmentGap,
) -> PrepareRunResponse {
    PrepareRunResponse {
        kind: "raxcell.prepareRunResult.v1".to_string(),
        ok: false,
        backend: Some(BackendFamily::LinuxBubblewrap),
        denial: Some(Denial {
            code,
            message: format!(
                "{}; actionId={}",
                gap.public_safe_message, request.action.action_id
            ),
            public_safe: true,
        }),
        environment_gap: Some(gap),
        policy_decision: None,
        filesystem_lowering: None,
        backend_artifacts: Vec::new(),
        capability_report: Some(capability_report),
    }
}

pub(super) fn fail_prepare_policy_decision_required(
    request: RunRequest,
    capability_report: ProbeResponse,
    decision: PolicyDecisionRequired,
) -> PrepareRunResponse {
    PrepareRunResponse {
        kind: "raxcell.prepareRunResult.v1".to_string(),
        ok: false,
        backend: Some(BackendFamily::LinuxBubblewrap),
        denial: Some(Denial {
            code: DenialCode::PolicyDecisionRequired,
            message: format!(
                "{}; actionId={}",
                decision.public_safe_message, request.action.action_id
            ),
            public_safe: true,
        }),
        environment_gap: None,
        policy_decision: Some(decision),
        filesystem_lowering: None,
        backend_artifacts: Vec::new(),
        capability_report: Some(capability_report),
    }
}

pub(super) fn fail_prepare_from_linux_error(
    request: RunRequest,
    capability_report: ProbeResponse,
    error: LinuxRunError,
    environment_gap_code: DenialCode,
) -> PrepareRunResponse {
    match error {
        LinuxRunError::SandboxDenied(message) => fail_prepare(
            request,
            capability_report,
            DenialCode::SandboxDenied,
            message,
        ),
        LinuxRunError::EnvironmentGap(gap) => {
            fail_prepare_environment_gap(request, capability_report, environment_gap_code, gap)
        }
        LinuxRunError::PolicyDecisionRequired(decision) => {
            fail_prepare_policy_decision_required(request, capability_report, decision)
        }
    }
}
