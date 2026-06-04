import { spawn } from "node:child_process";
import type {
  ExplainBackendRequest,
  ExplainBackendResponse,
  ProbeRequest,
  ProbeResponse,
  PrepareRunResponse,
  ResolveProfileRequest,
  ResolvedProfileResponse,
  RunRequest,
  RunResponse,
} from "./types.js";

export type RaxcellClientOptions = {
  binaryPath: string;
};

export class RaxcellClient {
  readonly binaryPath: string;

  constructor(options: RaxcellClientOptions) {
    this.binaryPath = options.binaryPath;
  }

  async probe(request: ProbeRequest): Promise<ProbeResponse> {
    return runJson(
      this.binaryPath,
      ["probe"],
      request,
      "raxcell.probeResult.v1",
    );
  }

  async explainBackend(
    request: ExplainBackendRequest,
  ): Promise<ExplainBackendResponse> {
    return runJson(
      this.binaryPath,
      ["explain-backend"],
      request,
      "raxcell.explainBackendResult.v1",
    );
  }

  async resolveProfile(
    request: ResolveProfileRequest,
  ): Promise<ResolvedProfileResponse> {
    return runJson(
      this.binaryPath,
      ["resolve-profile"],
      request,
      "raxcell.resolvedProfile.v1",
    );
  }

  async run(request: RunRequest): Promise<RunResponse> {
    return runJson(
      this.binaryPath,
      ["run"],
      request,
      "raxcell.runResult.v1",
    );
  }

  async prepareRun(request: RunRequest): Promise<PrepareRunResponse> {
    return runJson(
      this.binaryPath,
      ["prepare-run"],
      request,
      "raxcell.prepareRunResult.v1",
    );
  }
}

function runJson<T extends { kind: string }>(
  binaryPath: string,
  args: string[],
  input: unknown,
  expectedKind: T["kind"],
): Promise<T> {
  return new Promise((resolve, reject) => {
    const child = spawn(binaryPath, args, { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        try {
          const response = JSON.parse(stdout.trim()) as T;
          if (response.kind !== expectedKind) {
            reject(
              new Error(
                `Unexpected raxcell response kind: ${response.kind}; expected ${expectedKind}`,
              ),
            );
            return;
          }
          resolve(response);
        } catch (error) {
          reject(error);
        }
      } else {
        reject(new Error(stderr.trim() || `raxcell exited with code ${code}`));
      }
    });
    child.stdin.end(JSON.stringify(input));
  });
}
