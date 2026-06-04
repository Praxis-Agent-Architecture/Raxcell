import type {
  BackendLoweringArtifact,
  BackendFamily,
  FileSystemLoweringReport,
  ProbeResponse,
  RunResponse,
} from "./types.js";

export type RunnerRunResponseContext = {
  backend: BackendFamily | null;
  filesystemLowering: FileSystemLoweringReport | null;
  capabilityReport: ProbeResponse | null;
  backendArtifacts: BackendLoweringArtifact[] | null;
};

export function parseRunnerRunResponse(
  stdout: string,
  context?: RunnerRunResponseContext,
): RunResponse {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch (error) {
    throw new Error(`runner stdout is not valid JSON: ${String(error)}`);
  }

  if (!isRecord(parsed) || parsed.kind !== "raxcell.runResult.v1") {
    throw new Error("runner response kind must be raxcell.runResult.v1");
  }

  const response = parsed as RunResponse;
  if (!context) {
    return response;
  }
  if (response.backend !== context.backend) {
    throw new Error(`runner response backend must match prepared backend ${context.backend}`);
  }
  return {
    ...response,
    filesystemLowering: response.filesystemLowering ?? context.filesystemLowering,
    capabilityReport: response.capabilityReport ?? context.capabilityReport,
    backendArtifacts: response.backendArtifacts ?? context.backendArtifacts,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
