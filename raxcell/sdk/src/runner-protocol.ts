import type { RunResponse } from "./types.js";

export function parseRunnerRunResponse(stdout: string): RunResponse {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch (error) {
    throw new Error(`runner stdout is not valid JSON: ${String(error)}`);
  }

  if (!isRecord(parsed) || parsed.kind !== "raxcell.runResult.v1") {
    throw new Error("runner response kind must be raxcell.runResult.v1");
  }

  return parsed as RunResponse;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
