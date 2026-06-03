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
    const output = await runJson(this.binaryPath, ["probe", "--stdin"], request);
    return JSON.parse(output) as ProbeResponse;
  }

  async explainBackend(
    request: ExplainBackendRequest,
  ): Promise<ExplainBackendResponse> {
    const output = await runJson(
      this.binaryPath,
      ["explain-backend", "--stdin"],
      request,
    );
    return JSON.parse(output) as ExplainBackendResponse;
  }

  async resolveProfile(
    request: ResolveProfileRequest,
  ): Promise<ResolvedProfileResponse> {
    const output = await runJson(
      this.binaryPath,
      ["resolve-profile", "--stdin"],
      request,
    );
    return JSON.parse(output) as ResolvedProfileResponse;
  }

  async run(request: RunRequest): Promise<RunResponse> {
    const output = await runJson(this.binaryPath, ["run", "--stdin"], request);
    return JSON.parse(output) as RunResponse;
  }

  async prepareRun(request: RunRequest): Promise<PrepareRunResponse> {
    const output = await runJson(
      this.binaryPath,
      ["prepare-run", "--stdin"],
      request,
    );
    return JSON.parse(output) as PrepareRunResponse;
  }
}

function runJson(binaryPath: string, args: string[], input: unknown): Promise<string> {
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
        resolve(stdout.trim());
      } else {
        reject(new Error(stderr.trim() || `raxcell exited with code ${code}`));
      }
    });
    child.stdin.end(JSON.stringify(input));
  });
}
