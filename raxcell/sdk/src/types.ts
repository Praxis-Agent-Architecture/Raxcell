export type BackendFamily =
  | "linux-bubblewrap"
  | "macos-seatbelt"
  | "windows-native"
  | "windows-elevated"
  | "windows-unelevated"
  | "host-observed"
  | "external";

export type ProbeRequest = {
  kind: "raxcell.probe.v1";
  platform?: "auto" | string;
  backendPreference?: BackendFamily[];
  requirements?: Record<string, string[]>;
};

export type ProbeResponse = {
  kind: "raxcell.probeResult.v1";
  ready: boolean;
  selectedBackend: BackendFamily | null;
  supports: Record<string, "full" | "partial" | "unsupported" | "unknown">;
  limits: string[];
  weaknesses: string[];
  missing: string[];
  nextActions: string[];
  publicSafeMessage: string;
};

export type ExplainBackendRequest = {
  kind: "raxcell.explainBackend.v1";
  platform?: "auto" | string;
  backendPreference?: BackendFamily[];
};

export type OperationSchema = {
  method: string;
  inputKind: string;
  outputKind: string;
  sideEffects: string[];
};

export type BackendExplanation = {
  backend: BackendFamily | null;
  hostPlatforms: string[];
  isolationPrimitives: string[];
  runtimeRoots: LoweredRoot[];
  limits: string[];
  publicSafeMessage: string;
};

export type ExplainBackendResponse = {
  kind: "raxcell.explainBackendResult.v1";
  selectedBackend: BackendFamily | null;
  probe: ProbeResponse;
  operations: OperationSchema[];
  explanation: BackendExplanation;
};

export type PolicyPreset =
  | "workspace-write"
  | "workspace-readonly"
  | "no-filesystem-write"
  | "host-observed";

export type FallbackSpec = {
  mode: string;
};

export type EnforcementSpec = {
  profile: string;
  filesystem?: Record<string, string[]>;
  network?: string | null;
  process?: Record<string, unknown>;
  resources?: Record<string, unknown>;
};

export type PolicyGrant = {
  reason: string;
  path: string;
  access?: string[];
  grantedBy?: string | null;
};

export type PolicyDecisionRequired = {
  reason: string;
  path: string;
  required?: string[];
  publicSafeMessage: string;
};

export type EnvironmentGap = {
  reason: string;
  path?: string | null;
  required?: string[];
  publicSafeMessage: string;
};

export type LoweredRootAccess =
  | "read"
  | "write"
  | "runtime"
  | "scratch"
  | "runtime-link";

export type LoweredRootSource =
  | "declared"
  | "backend-runtime"
  | "policy-grant";

export type LoweredRoot = {
  path: string;
  access: LoweredRootAccess;
  source: LoweredRootSource;
};

export type FileSystemLoweringReport = {
  declaredRoots: LoweredRoot[];
  runtimeRoots: LoweredRoot[];
  policyGrants: PolicyGrant[];
  warnings: PolicyResolutionWarning[];
  effects?: Array<{
    path?: string;
    pattern?: string;
    rawToken: string;
    access: "read" | "write" | "readwrite";
    command: string;
    reason: string;
    confidence: "high" | "medium" | "low";
    warning?: string;
  }>;
};

export type BackendLoweringArtifact = {
  backend: BackendFamily;
  format: string;
  arguments: string[];
  data: Record<string, unknown>;
  warnings: PolicyResolutionWarning[];
};

export type RunRequest = {
  kind: "raxcell.run.v1";
  backendPreference?: BackendFamily[];
  policyGrants?: PolicyGrant[];
  action: {
    actionId: string;
    ownerRuntime?: string | null;
    intentLabel?: string | null;
    metadata?: Record<string, unknown>;
  };
  command: {
    argv: string[];
    cwd: string;
    env?: Record<string, string>;
    stdin?: string | null;
  };
  enforcement: EnforcementSpec;
  fallback: FallbackSpec;
};

export type WindowsRunnerBackend =
  | "windows-native"
  | "windows-elevated"
  | "windows-unelevated";

export type WindowsRunnerAclRoot = {
  path: string;
  access: "read" | "write";
  source: "declared" | "policy-grant";
};

export type WindowsRunnerRunRequest = {
  kind: "raxcell.windowsRunner.run.v1";
  backend: WindowsRunnerBackend;
  command: RunRequest["command"] & {
    env: Record<string, string>;
  };
  normalizedCwd: string;
  commandEnvMode: "clean";
  writeGrantMaterialization: "runner-owned";
  enforcement: EnforcementSpec;
  action: RunRequest["action"];
  filesystemLowering: FileSystemLoweringReport;
  tokenMode: "read-only-capability" | "writable-roots-capability";
  aclRoots: WindowsRunnerAclRoot[];
  networkBlocked: boolean;
};

export type RunResponse = {
  kind: "raxcell.runResult.v1";
  ok: boolean;
  backend: BackendFamily | null;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  denial: {
    code: string;
    message: string;
    publicSafe: boolean;
  } | null;
  policyDecision?: PolicyDecisionRequired | null;
  environmentGap?: EnvironmentGap | null;
  filesystemLowering?: FileSystemLoweringReport | null;
  fallback: unknown | null;
  capabilityReport: ProbeResponse | null;
};

export type PrepareRunResponse = {
  kind: "raxcell.prepareRunResult.v1";
  ok: boolean;
  backend: BackendFamily | null;
  denial: {
    code: string;
    message: string;
    publicSafe: boolean;
  } | null;
  policyDecision?: PolicyDecisionRequired | null;
  environmentGap?: EnvironmentGap | null;
  filesystemLowering?: FileSystemLoweringReport | null;
  backendArtifacts: BackendLoweringArtifact[];
  capabilityReport: ProbeResponse | null;
};

export type PolicyProfile = {
  preset: PolicyPreset;
  filesystem?: Record<string, string[]>;
  network?: string | null;
  process?: Record<string, unknown>;
  resources?: Record<string, unknown>;
  backendPreference?: BackendFamily[];
  fallback?: FallbackSpec;
};

export type PolicyPack = {
  kind: "raxcell.policyPack.v1";
  name: string;
  extends?: string[];
  profiles?: Record<string, PolicyProfile>;
};

export type ResolveProfileRequest = {
  kind: "raxcell.resolveProfile.v1";
  packPaths?: string[];
  profile: string;
  variables?: Record<string, string>;
};

export type PolicyResolutionWarning = {
  code: string;
  message: string;
};

export type PolicyResolutionReport = {
  packs: string[];
  merge: string[];
  warnings: PolicyResolutionWarning[];
};

export type ResolvedProfileResponse = {
  kind: "raxcell.resolvedProfile.v1";
  profile: string;
  enforcement: EnforcementSpec;
  backendPreference: BackendFamily[];
  fallback: FallbackSpec;
  report: PolicyResolutionReport;
};
