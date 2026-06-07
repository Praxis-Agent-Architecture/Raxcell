#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { RunResponse, WindowsRunnerRunRequest } from "./types.js";

const PROFILE_NAME = "raxcell-runtime";
const VERSION = readPackageVersion();

async function main(): Promise<void> {
  const command = process.argv[2];
  if (command === "--version" || command === "-v" || command === "version") {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  if (!command || command === "--help" || command === "-h") {
    process.stdout.write(helpText());
    return;
  }
  if (command === "probe") {
    writeJson(probeCodex());
    return;
  }
  if (command === "run") {
    const request = await readRequest();
    writeJson(await runCodexSandbox(request));
    return;
  }
  throw new Error(`Unknown raxcell-windows-runner command: ${command}`);
}

function helpText(): string {
  return [
    "raxcell-windows-runner",
    "",
    "Usage:",
    "  raxcell-windows-runner probe",
    "  raxcell-windows-runner run < windows-runner-request.json",
    "",
  ].join("\n");
}

function readPackageVersion(): string {
  try {
    const thisFile = fileURLToPath(import.meta.url);
    const packageJson = JSON.parse(
      readFileSync(resolve(dirname(thisFile), "../package.json"), "utf8"),
    ) as { version?: string };
    return packageJson.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

function probeCodex(): {
  kind: "raxcell.windowsRunner.probeResult.v1";
  ready: boolean;
  codexPath: string | null;
  missing: string[];
} {
  const codexPath = codexExecutablePath();
  if (!codexPath) {
    return {
      kind: "raxcell.windowsRunner.probeResult.v1",
      ready: false,
      codexPath: null,
      missing: ["codex"],
    };
  }
  const result = spawnSync(codexPath, ["--version"], {
    encoding: "utf8",
    shell: needsWindowsCommandShell(codexPath),
  });
  return {
    kind: "raxcell.windowsRunner.probeResult.v1",
    ready: result.status === 0,
    codexPath,
    missing: result.status === 0 ? [] : ["codex"],
  };
}

function readRequest(): Promise<WindowsRunnerRunRequest> {
  return new Promise((resolvePromise, reject) => {
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      input += chunk;
    });
    process.stdin.on("end", () => {
      try {
        const parsed = JSON.parse(input) as WindowsRunnerRunRequest;
        if (parsed.kind !== "raxcell.windowsRunner.run.v1") {
          reject(new Error("request kind must be raxcell.windowsRunner.run.v1"));
          return;
        }
        resolvePromise(parsed);
      } catch (error) {
        reject(error);
      }
    });
    process.stdin.on("error", reject);
  });
}

function runCodexSandbox(request: WindowsRunnerRunRequest): Promise<RunResponse> {
  const codexPath = codexExecutablePath();
  if (!codexPath) {
    return Promise.resolve(runnerFailure(request, "BACKEND_UNAVAILABLE", "Codex CLI was not found."));
  }

  const codexHome = mkdtempSync(join(tmpdir(), "raxcell-codex-home-"));
  writeFileSync(join(codexHome, "config.toml"), codexConfig(request));

  return new Promise((resolvePromise) => {
    let finished = false;
    let timedOut = false;
    let timer: NodeJS.Timeout | null = null;
    const child = spawn(codexPath, codexSandboxArgs(request), {
      stdio: ["pipe", "pipe", "pipe"],
      shell: needsWindowsCommandShell(codexPath),
      env: {
        ...process.env,
        ...request.command.env,
        CODEX_HOME: codexHome,
      },
    });
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
    child.on("error", (error) => {
      finish(runnerFailure(request, "SPAWN_FAILED", String(error)));
    });
    child.on("close", (code) => {
      if (timedOut) {
        finish({
          kind: "raxcell.runResult.v1",
          ok: false,
          backend: request.backend,
          exitCode: null,
          stdout,
          stderr,
          timedOut: true,
          denial: {
            code: "RUNNER_TIMED_OUT",
            message: "Windows native runner timed out.",
            publicSafe: true,
          },
          policyDecision: null,
          environmentGap: null,
          filesystemLowering: request.filesystemLowering,
          backendArtifacts: null,
          fallback: null,
          capabilityReport: null,
        });
        return;
      }
      finish({
        kind: "raxcell.runResult.v1",
        ok: true,
        backend: request.backend,
        exitCode: code,
        stdout,
        stderr,
        timedOut: false,
        denial: null,
        policyDecision: null,
        environmentGap: null,
        filesystemLowering: request.filesystemLowering,
        backendArtifacts: null,
        fallback: null,
        capabilityReport: null,
      });
    });
    if (request.timeoutMs > 0) {
      timer = setTimeout(() => {
        timedOut = true;
        child.kill();
      }, request.timeoutMs);
    }
    child.stdin.end(request.command.stdin ?? "");

    function finish(response: RunResponse): void {
      if (finished) {
        return;
      }
      finished = true;
      if (timer) {
        clearTimeout(timer);
      }
      rmSync(codexHome, { recursive: true, force: true });
      resolvePromise(response);
    }
  });
}

function codexSandboxArgs(request: WindowsRunnerRunRequest): string[] {
  return [
    "sandbox",
    "--permissions-profile",
    PROFILE_NAME,
    "--include-managed-config",
    "-C",
    request.normalizedCwd,
    "--",
    ...request.command.argv,
  ];
}

function codexConfig(request: WindowsRunnerRunRequest): string {
  const lines = [
    `default_permissions = ${tomlString(PROFILE_NAME)}`,
    "",
    `[permissions.${PROFILE_NAME}.filesystem]`,
  ];
  for (const root of request.aclRoots) {
    lines.push(`${tomlString(root.path)} = ${tomlString(root.access)}`);
  }
  lines.push(
    "",
    `[permissions.${PROFILE_NAME}.network]`,
    `enabled = ${request.networkMode === "allow" ? "true" : "false"}`,
    "",
  );
  return lines.join("\n");
}

function runnerFailure(
  request: WindowsRunnerRunRequest,
  code: string,
  message: string,
): RunResponse {
  return {
    kind: "raxcell.runResult.v1",
    ok: false,
    backend: request.backend,
    exitCode: null,
    stdout: "",
    stderr: message,
    timedOut: false,
    denial: {
      code,
      message,
      publicSafe: true,
    },
    policyDecision: null,
    environmentGap: null,
    filesystemLowering: request.filesystemLowering,
    backendArtifacts: null,
    fallback: null,
    capabilityReport: null,
  };
}

function codexExecutablePath(): string | null {
  const configured = process.env.RAXCELL_CODEX_BIN;
  if (configured) {
    return existsSync(configured) ? configured : null;
  }
  return findExecutable("codex");
}

function findExecutable(name: string): string | null {
  if (isAbsolute(name) && existsSync(name)) {
    return name;
  }
  const extensions = process.platform === "win32"
    ? (process.env.PATHEXT ?? ".EXE;.CMD;.BAT;.COM").split(";")
    : [""];
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    if (!dir) {
      continue;
    }
    for (const extension of extensions) {
      const candidate = resolve(dir, extension ? `${name}${extension.toLowerCase()}` : name);
      if (existsSync(candidate)) {
        return candidate;
      }
      if (process.platform === "win32") {
        const upperCandidate = resolve(dir, `${name}${extension.toUpperCase()}`);
        if (existsSync(upperCandidate)) {
          return upperCandidate;
        }
      }
    }
  }
  return null;
}

function needsWindowsCommandShell(executable: string): boolean {
  return process.platform === "win32" && /\.(?:cmd|bat)$/i.test(executable);
}

function tomlString(value: string): string {
  return JSON.stringify(value);
}

function writeJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${String(error instanceof Error ? error.message : error)}\n`);
  process.exitCode = 1;
});
