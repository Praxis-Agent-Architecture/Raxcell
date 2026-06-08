use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendFamily {
    LinuxBubblewrap,
    MacosSeatbelt,
    WindowsNative,
    WindowsElevated,
    WindowsUnelevated,
    HostObserved,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityLevel {
    Full,
    Partial,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRequest {
    pub kind: String,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default, rename = "backendPreference")]
    pub backend_preference: Vec<BackendFamily>,
    #[serde(default)]
    pub requirements: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResponse {
    pub kind: String,
    pub ready: bool,
    #[serde(rename = "selectedBackend")]
    pub selected_backend: Option<BackendFamily>,
    pub supports: BTreeMap<String, CapabilityLevel>,
    pub limits: Vec<String>,
    pub weaknesses: Vec<String>,
    pub missing: Vec<String>,
    #[serde(rename = "nextActions")]
    pub next_actions: Vec<String>,
    #[serde(rename = "publicSafeMessage")]
    pub public_safe_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainBackendRequest {
    pub kind: String,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default, rename = "backendPreference")]
    pub backend_preference: Vec<BackendFamily>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainBackendResponse {
    pub kind: String,
    #[serde(rename = "selectedBackend")]
    pub selected_backend: Option<BackendFamily>,
    pub probe: ProbeResponse,
    pub operations: Vec<OperationSchema>,
    pub explanation: BackendExplanation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSchema {
    pub method: String,
    #[serde(rename = "inputKind")]
    pub input_kind: String,
    #[serde(rename = "outputKind")]
    pub output_kind: String,
    #[serde(rename = "sideEffects")]
    pub side_effects: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendExplanation {
    pub backend: Option<BackendFamily>,
    #[serde(rename = "hostPlatforms")]
    pub host_platforms: Vec<String>,
    #[serde(rename = "isolationPrimitives")]
    pub isolation_primitives: Vec<String>,
    #[serde(rename = "runtimeRoots")]
    pub runtime_roots: Vec<LoweredRoot>,
    pub limits: Vec<String>,
    #[serde(rename = "publicSafeMessage")]
    pub public_safe_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueAction {
    #[serde(rename = "actionId")]
    pub action_id: String,
    #[serde(rename = "ownerRuntime")]
    pub owner_runtime: Option<String>,
    #[serde(rename = "intentLabel")]
    pub intent_label: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSpec {
    pub argv: Vec<String>,
    pub cwd: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub stdin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementSpec {
    pub profile: String,
    #[serde(default)]
    pub filesystem: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub process: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub resources: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackSpec {
    pub mode: String,
}

impl Default for FallbackSpec {
    fn default() -> Self {
        Self {
            mode: "none".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRequest {
    pub kind: String,
    #[serde(default, rename = "backendPreference")]
    pub backend_preference: Vec<BackendFamily>,
    #[serde(default, rename = "policyGrants")]
    pub policy_grants: Vec<PolicyGrant>,
    pub action: OpaqueAction,
    pub command: CommandSpec,
    pub enforcement: EnforcementSpec,
    pub fallback: FallbackSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DenialCode {
    CapabilityMismatch,
    BackendUnavailable,
    SandboxDenied,
    ExecutionFailed,
    Timeout,
    FallbackApplied,
    FallbackRefused,
    PolicyDecisionRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Denial {
    pub code: DenialCode,
    pub message: String,
    #[serde(rename = "publicSafe")]
    pub public_safe: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentGap {
    pub reason: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(rename = "publicSafeMessage")]
    pub public_safe_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackReport {
    pub mode: String,
    pub protects: Vec<String>,
    #[serde(rename = "doesNotProtect")]
    pub does_not_protect: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunResponse {
    pub kind: String,
    pub ok: bool,
    pub backend: Option<BackendFamily>,
    #[serde(rename = "exitCode")]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(rename = "timedOut")]
    pub timed_out: bool,
    pub denial: Option<Denial>,
    #[serde(default, rename = "environmentGap")]
    pub environment_gap: Option<EnvironmentGap>,
    #[serde(default, rename = "policyDecision")]
    pub policy_decision: Option<PolicyDecisionRequired>,
    #[serde(default, rename = "filesystemLowering")]
    pub filesystem_lowering: Option<FileSystemLoweringReport>,
    #[serde(default, rename = "backendArtifacts")]
    pub backend_artifacts: Vec<BackendLoweringArtifact>,
    pub fallback: Option<FallbackReport>,
    #[serde(rename = "capabilityReport")]
    pub capability_report: Option<ProbeResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepareRunResponse {
    pub kind: String,
    pub ok: bool,
    pub backend: Option<BackendFamily>,
    pub denial: Option<Denial>,
    #[serde(default, rename = "environmentGap")]
    pub environment_gap: Option<EnvironmentGap>,
    #[serde(default, rename = "policyDecision")]
    pub policy_decision: Option<PolicyDecisionRequired>,
    #[serde(default, rename = "filesystemLowering")]
    pub filesystem_lowering: Option<FileSystemLoweringReport>,
    #[serde(default, rename = "backendArtifacts")]
    pub backend_artifacts: Vec<BackendLoweringArtifact>,
    #[serde(rename = "capabilityReport")]
    pub capability_report: Option<ProbeResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendLoweringArtifact {
    pub backend: BackendFamily,
    pub format: String,
    pub arguments: Vec<String>,
    pub data: BTreeMap<String, serde_json::Value>,
    pub warnings: Vec<PolicyResolutionWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaxcellEvent {
    pub kind: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub event: String,
    #[serde(default)]
    pub data: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyGrant {
    pub reason: String,
    pub path: String,
    #[serde(default)]
    pub access: Vec<String>,
    #[serde(rename = "grantedBy")]
    pub granted_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecisionRequired {
    pub reason: String,
    pub path: String,
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(rename = "publicSafeMessage")]
    pub public_safe_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSystemLoweringReport {
    #[serde(rename = "declaredRoots")]
    pub declared_roots: Vec<LoweredRoot>,
    #[serde(rename = "runtimeRoots")]
    pub runtime_roots: Vec<LoweredRoot>,
    #[serde(rename = "policyGrants")]
    pub policy_grants: Vec<PolicyGrant>,
    pub warnings: Vec<PolicyResolutionWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweredRoot {
    pub path: String,
    pub access: LoweredRootAccess,
    pub source: LoweredRootSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoweredRootAccess {
    Read,
    Write,
    Runtime,
    Scratch,
    RuntimeLink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoweredRootSource {
    Declared,
    BackendRuntime,
    PolicyGrant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyPreset {
    WorkspaceWrite,
    WorkspaceReadonly,
    NoFilesystemWrite,
    HostObserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPack {
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub extends: Vec<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, PolicyProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyProfile {
    pub preset: PolicyPreset,
    #[serde(default)]
    pub filesystem: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub process: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub resources: BTreeMap<String, serde_json::Value>,
    #[serde(default, rename = "backendPreference")]
    pub backend_preference: Vec<BackendFamily>,
    #[serde(default)]
    pub fallback: FallbackSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveProfileRequest {
    pub kind: String,
    #[serde(default, rename = "packPaths")]
    pub pack_paths: Vec<String>,
    pub profile: String,
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedProfileResponse {
    pub kind: String,
    pub profile: String,
    pub enforcement: EnforcementSpec,
    #[serde(rename = "backendPreference")]
    pub backend_preference: Vec<BackendFamily>,
    pub fallback: FallbackSpec,
    pub report: PolicyResolutionReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyResolutionReport {
    pub packs: Vec<String>,
    pub merge: Vec<String>,
    pub warnings: Vec<PolicyResolutionWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyResolutionWarning {
    pub code: String,
    pub message: String,
}
