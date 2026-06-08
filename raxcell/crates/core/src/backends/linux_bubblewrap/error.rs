use raxcell_protocol::{EnvironmentGap, PolicyDecisionRequired};

#[derive(Debug)]
pub(in crate::backends) enum LinuxRunError {
    SandboxDenied(String),
    EnvironmentGap(EnvironmentGap),
    PolicyDecisionRequired(PolicyDecisionRequired),
}

pub(super) fn sandbox_denied(message: impl Into<String>) -> LinuxRunError {
    LinuxRunError::SandboxDenied(message.into())
}

pub(super) fn environment_gap(
    reason: impl Into<String>,
    path: Option<&str>,
    required: Vec<&str>,
    public_safe_message: impl Into<String>,
) -> LinuxRunError {
    LinuxRunError::EnvironmentGap(make_environment_gap(
        reason,
        path,
        required,
        public_safe_message,
    ))
}

pub(super) fn make_environment_gap(
    reason: impl Into<String>,
    path: Option<&str>,
    required: Vec<&str>,
    public_safe_message: impl Into<String>,
) -> EnvironmentGap {
    EnvironmentGap {
        reason: reason.into(),
        path: path.map(str::to_string),
        required: required.into_iter().map(str::to_string).collect(),
        public_safe_message: public_safe_message.into(),
    }
}
