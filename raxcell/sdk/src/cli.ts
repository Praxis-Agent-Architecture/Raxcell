#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { closeSync, existsSync, openSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeShellEffects, type ShellEffect } from "./shell-effects.js";
import type {
  BackendFamily,
  BackendExplanation,
  BackendLoweringArtifact,
  EnvironmentGap,
  ExplainBackendRequest,
  FileSystemLoweringReport,
  LoweredRoot,
  PolicyDecisionRequired,
  PolicyGrant,
  PrepareRunResponse,
  ProbeRequest,
  ProbeResponse,
  RunRequest,
  RunResponse,
} from "./types.js";

type Denial = {
  code: string;
  message: string;
  publicSafe: boolean;
};

type PreparedLinuxRun = {
  response: PrepareRunResponse;
  bwrapExecutable: string | null;
  bwrapArgs: string[];
};

type AllowedRoot = {
  path: string;
  access: "read" | "write";
  source: "declared" | "policy-grant";
};

const VERSION = readPackageVersion();
const RUNTIME_READ_ROOTS = ["/usr", "/bin", "/lib", "/lib64", "/etc"];
const PLATFORM_BACKENDS: BackendFamily[] = [
  "linux-bubblewrap",
  "macos-seatbelt",
  "windows-native",
  "windows-elevated",
  "windows-unelevated",
];

async function main(): Promise<void> {
  const args = process.argv.slice(2).filter((arg) => arg !== "--stdin");
  const command = args[0];

  if (command === "--version" || command === "-v" || command === "version") {
    process.stdout.write(`${VERSION}\n`);
    return;
  }

  if (!command || command === "--help" || command === "-h") {
    process.stdout.write(helpText());
    return;
  }

  if (command === "probe") {
    const request = await readOptionalJsonStdin() as ProbeRequest | null;
    writeJson(probeBackend(request?.backendPreference));
    return;
  }

  if (command === "explain-backend") {
    const request = await readOptionalJsonStdin() as ExplainBackendRequest | null;
    const probe = probeBackend(request?.backendPreference);
    writeJson({
      kind: "raxcell.explainBackendResult.v1",
      selectedBackend: probe.selectedBackend,
      probe,
      operations: [
        {
          method: "prepareRun",
          inputKind: "raxcell.run.v1",
          outputKind: "raxcell.prepareRunResult.v1",
          sideEffects: ["no-process-spawn"],
        },
        {
          method: "run",
          inputKind: "raxcell.run.v1",
          outputKind: "raxcell.runResult.v1",
          sideEffects: ["spawns-process"],
        },
      ],
      explanation: explainBackend(probe.selectedBackend, probe),
    });
    return;
  }

  if (command === "resolve-profile") {
    const request = await readJsonStdin() as { profile?: string };
    writeJson({
      kind: "raxcell.resolvedProfile.v1",
      profile: request.profile ?? "workspace-write-no-network",
      enforcement: {},
      backendPreference: ["linux-bubblewrap"],
      fallback: { mode: "none" },
      report: {
        packs: [],
        merge: [],
        warnings: [
          {
            code: "PROFILE_RESOLUTION_NOT_IMPLEMENTED_IN_TS_CLI",
            message: "The 0.1.x TypeScript CLI accepts fully lowered RunRequest objects.",
          },
        ],
      },
    });
    return;
  }

  if (command === "prepare-run") {
    const request = await readRunRequest();
    writeJson(prepareRun(request).response);
    return;
  }

  if (command === "run") {
    const request = await readRunRequest();
    writeJson(await runBackend(request));
    return;
  }

  throw new Error(`Unknown raxcell command: ${command}`);
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

function helpText(): string {
  return [
    "raxcell",
    "",
    "Usage:",
    "  raxcell --version",
    "  raxcell probe",
    "  raxcell explain-backend",
    "  raxcell prepare-run < request.json",
    "  raxcell run < request.json",
    "",
  ].join("\n");
}

function writeJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function readJsonStdin(): Promise<unknown> {
  return new Promise((resolvePromise, reject) => {
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      input += chunk;
    });
    process.stdin.on("error", reject);
    process.stdin.on("end", () => {
      try {
        resolvePromise(JSON.parse(input));
      } catch (error) {
        reject(new Error(`Invalid JSON request: ${String(error)}`));
      }
    });
  });
}

function readOptionalJsonStdin(): Promise<unknown | null> {
  if (process.stdin.isTTY) {
    return Promise.resolve(null);
  }
  return new Promise((resolvePromise, reject) => {
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      input += chunk;
    });
    process.stdin.on("error", reject);
    process.stdin.on("end", () => {
      if (input.trim().length === 0) {
        resolvePromise(null);
        return;
      }
      try {
        resolvePromise(JSON.parse(input));
      } catch (error) {
        reject(new Error(`Invalid JSON request: ${String(error)}`));
      }
    });
  });
}

async function readRunRequest(): Promise<RunRequest> {
  const request = await readJsonStdin();
  if (!isRunRequest(request)) {
    throw new Error("Expected request kind raxcell.run.v1");
  }
  return request;
}

function isRunRequest(value: unknown): value is RunRequest {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const request = value as RunRequest;
  return (
    request.kind === "raxcell.run.v1" &&
    Array.isArray(request.command?.argv) &&
    typeof request.command?.cwd === "string" &&
    typeof request.enforcement === "object" &&
    request.enforcement !== null
  );
}

function probeBackend(preference: BackendFamily[] = []): ProbeResponse {
  const selectedBackend = selectBackend(preference);
  if (selectedBackend === "linux-bubblewrap") {
    return probeLinux();
  }
  return probeUnattachedNativeBackend(selectedBackend);
}

function selectBackend(preference: BackendFamily[] = []): BackendFamily {
  for (const backend of preference) {
    if (PLATFORM_BACKENDS.includes(backend)) {
      return backend;
    }
  }
  if (process.platform === "darwin") {
    return "macos-seatbelt";
  }
  if (process.platform === "win32") {
    return "windows-native";
  }
  return "linux-bubblewrap";
}

function probeLinux(): ProbeResponse {
  const bwrap = findExecutable("bwrap") ?? findExecutable("bubblewrap");
  const isLinux = process.platform === "linux";
  const ready = isLinux && bwrap !== null;
  const missing: string[] = [];
  const nextActions: string[] = [];

  if (!isLinux) {
    missing.push("linux");
    nextActions.push("Use a Linux host or route to another Raxcell backend.");
  }
  if (!bwrap) {
    missing.push("bwrap");
    nextActions.push("Install bubblewrap and expose bwrap on PATH.");
  }

  return {
    kind: "raxcell.probeResult.v1",
    ready,
    selectedBackend: ready ? "linux-bubblewrap" : null,
    supports: {
      filesystem: ready ? "full" : "unsupported",
      network: ready ? "full" : "unsupported",
      process: ready ? "partial" : "unsupported",
      timeout: "partial",
    },
    limits: [
      "The 0.1.x npm CLI implements Linux bubblewrap only.",
      "Upper runtimes own policy grants and approval.",
    ],
    weaknesses: [],
    missing,
    nextActions,
    publicSafeMessage: ready
      ? "linux-bubblewrap is ready"
      : "linux-bubblewrap is not ready on this host",
  };
}

function probeUnattachedNativeBackend(backend: BackendFamily): ProbeResponse {
  const hostPlatform = hostPlatformForBackend(backend);
  const hostMatches = process.platform === hostPlatform;
  const missing = hostMatches ? [nativeRunnerDependency(backend)] : [hostPlatform];
  const nextActions = hostMatches
    ? [`Attach the ${backend} runner before executing this backend.`]
    : [`Route this request to a ${hostPlatform} host or select a backend available on this host.`];
  return {
    kind: "raxcell.probeResult.v1",
    ready: false,
    selectedBackend: backend,
    supports: {
      filesystem: "unknown",
      network: "unknown",
      process: "unknown",
      timeout: "partial",
    },
    limits: [
      `${backend} is protocol-visible but not executable in the 0.1.x npm CLI.`,
      "Raxcell reports policy gaps but does not approve them.",
    ],
    weaknesses: [],
    missing,
    nextActions,
    publicSafeMessage: hostMatches
      ? `${backend} runner is not attached`
      : `${backend} cannot run on this host`,
  };
}

function explainBackend(
  backend: BackendFamily | null,
  probe: ProbeResponse,
): BackendExplanation {
  if (backend === "linux-bubblewrap") {
    return {
      backend,
      hostPlatforms: ["linux"],
      isolationPrimitives: [
        "bubblewrap.bind-mounts",
        "bubblewrap.unshare-pid",
        "bubblewrap.unshare-net",
      ],
      runtimeRoots: runtimeLoweredRoots(),
      limits: [
        "0.1.x supports Linux bubblewrap execution only",
        "Raxcell reports policy gaps but does not approve them",
      ],
      publicSafeMessage: probe.publicSafeMessage,
    };
  }
  if (backend === "macos-seatbelt") {
    return {
      backend,
      hostPlatforms: ["darwin"],
      isolationPrimitives: [
        "apple-seatbelt.sbpl-profile",
        "sandbox-exec",
        "profile-scoped-file-read-write-rules",
      ],
      runtimeRoots: [],
      limits: [
        "macOS Seatbelt is protocol-visible but the 0.1.x npm CLI has no attached runner.",
        "Raxcell will fail closed until native execution is attached.",
      ],
      publicSafeMessage: probe.publicSafeMessage,
    };
  }
  if (
    backend === "windows-native" ||
    backend === "windows-elevated" ||
    backend === "windows-unelevated"
  ) {
    return {
      backend,
      hostPlatforms: ["win32"],
      isolationPrimitives: [
        "windows-restricted-token",
        "filesystem-acl-capability-roots",
        "job-object-process-limits",
        "wfp-network-filtering",
      ],
      runtimeRoots: [],
      limits: [
        "Windows native sandboxing is protocol-visible but the 0.1.x npm CLI has no attached runner.",
        "Raxcell will fail closed until native token/ACL/WFP execution is attached.",
      ],
      publicSafeMessage: probe.publicSafeMessage,
    };
  }
  return {
    backend,
    hostPlatforms: [],
    isolationPrimitives: [],
    runtimeRoots: [],
    limits: ["No executable backend is selected."],
    publicSafeMessage: probe.publicSafeMessage,
  };
}

function prepareRun(request: RunRequest): PreparedLinuxRun {
  const backend = selectBackend(request.backendPreference);
  if (backend === "linux-bubblewrap") {
    return prepareLinux(request);
  }
  return prepareUnattachedNative(request, backend);
}

function prepareLinux(request: RunRequest): PreparedLinuxRun {
  const capabilityReport = probeLinux();
  const bwrapExecutable = findExecutable("bwrap") ?? findExecutable("bubblewrap");
  const backend: BackendFamily | null = capabilityReport.ready ? "linux-bubblewrap" : null;
  const filesystemLowering = lowerFilesystem(request, "linux-bubblewrap");

  if (!capabilityReport.ready || !bwrapExecutable) {
    const environmentGap: EnvironmentGap = {
      reason: "missing-backend-dependency",
      path: "bwrap",
      required: ["linux", "bwrap"],
      publicSafeMessage: "Linux bubblewrap is required before Raxcell can execute this request.",
    };
    return {
      response: {
        kind: "raxcell.prepareRunResult.v1",
        ok: false,
        backend,
        denial: denial(
          "BACKEND_UNAVAILABLE",
          "linux-bubblewrap is unavailable",
        ),
        policyDecision: null,
        environmentGap,
        filesystemLowering,
        backendArtifacts: [],
        capabilityReport,
      },
      bwrapExecutable: null,
      bwrapArgs: [],
    };
  }

  const cwdDecision = cwdPolicyDecision(request, filesystemLowering.policyGrants);
  if (cwdDecision) {
    return {
      response: {
        kind: "raxcell.prepareRunResult.v1",
        ok: false,
        backend,
        denial: null,
        policyDecision: cwdDecision,
        environmentGap: null,
        filesystemLowering,
        backendArtifacts: [],
        capabilityReport,
      },
      bwrapExecutable,
      bwrapArgs: [],
    };
  }

  const environmentGap = dynamicPathEnvironmentGap(request);
  if (environmentGap) {
    return {
      response: {
        kind: "raxcell.prepareRunResult.v1",
        ok: false,
        backend,
        denial: null,
        policyDecision: null,
        environmentGap,
        filesystemLowering,
        backendArtifacts: [],
        capabilityReport,
      },
      bwrapExecutable,
      bwrapArgs: [],
    };
  }

  const pathDecision = argvPathPolicyDecision(request, filesystemLowering.policyGrants);
  if (pathDecision) {
    return {
      response: {
        kind: "raxcell.prepareRunResult.v1",
        ok: false,
        backend,
        denial: null,
        policyDecision: pathDecision,
        environmentGap: null,
        filesystemLowering,
        backendArtifacts: [],
        capabilityReport,
      },
      bwrapExecutable,
      bwrapArgs: [],
    };
  }

  const bwrapArgs = buildBwrapArgs(request, filesystemLowering);
  const backendArtifacts: BackendLoweringArtifact[] = [
    {
      backend: "linux-bubblewrap",
      format: "linux-bubblewrap-argv",
      arguments: [bwrapExecutable, ...bwrapArgs],
      data: {
        executable: bwrapExecutable,
      },
      warnings: filesystemLowering.warnings,
    },
  ];

  return {
    response: {
      kind: "raxcell.prepareRunResult.v1",
      ok: true,
      backend,
      denial: null,
      policyDecision: null,
      environmentGap: null,
      filesystemLowering,
      backendArtifacts,
      capabilityReport,
    },
    bwrapExecutable,
    bwrapArgs,
  };
}

function prepareUnattachedNative(
  request: RunRequest,
  backend: BackendFamily,
): PreparedLinuxRun {
  const capabilityReport = probeUnattachedNativeBackend(backend);
  const filesystemLowering = lowerFilesystem(request, backend);
  const gap: EnvironmentGap = nativeBackendEnvironmentGap(backend);
  return {
    response: {
      kind: "raxcell.prepareRunResult.v1",
      ok: false,
      backend,
      denial: denial("BACKEND_UNAVAILABLE", gap.publicSafeMessage),
      policyDecision: null,
      environmentGap: gap,
      filesystemLowering,
      backendArtifacts: [
        {
          backend,
          format: `${backend}-planned-lowering`,
          arguments: [],
          data: {
            attached: false,
            hostPlatform: hostPlatformForBackend(backend),
            selectedOn: process.platform,
            filesystemEffects: filesystemLowering.effects ?? [],
          },
          warnings: [
            {
              code: "NATIVE_BACKEND_RUNNER_UNATTACHED",
              message: `${backend} is protocol-visible but not executable in the 0.1.x npm CLI.`,
            },
          ],
        },
      ],
      capabilityReport,
    },
    bwrapExecutable: null,
    bwrapArgs: [],
  };
}

async function runBackend(request: RunRequest): Promise<RunResponse> {
  const prepared = prepareRun(request);

  if (!prepared.response.ok || prepared.response.policyDecision || !prepared.bwrapExecutable) {
    return {
      kind: "raxcell.runResult.v1",
      ok: false,
      backend: prepared.response.backend,
      exitCode: null,
      stdout: "",
      stderr: "",
      timedOut: false,
      denial: prepared.response.denial,
      policyDecision: prepared.response.policyDecision,
      environmentGap: prepared.response.environmentGap,
      filesystemLowering: prepared.response.filesystemLowering,
      fallback: null,
      capabilityReport: prepared.response.capabilityReport,
    };
  }

  const materializationDenial = materializeWriteGrantMounts(
    prepared.response.filesystemLowering!,
  );
  if (materializationDenial) {
    return {
      kind: "raxcell.runResult.v1",
      ok: false,
      backend: prepared.response.backend,
      exitCode: null,
      stdout: "",
      stderr: "",
      timedOut: false,
      denial: materializationDenial,
      policyDecision: null,
      environmentGap: null,
      filesystemLowering: prepared.response.filesystemLowering,
      fallback: null,
      capabilityReport: prepared.response.capabilityReport,
    };
  }

  return spawnBubblewrap(request, prepared);
}

function nativeBackendEnvironmentGap(backend: BackendFamily): EnvironmentGap {
  const requiredHost = hostPlatformForBackend(backend);
  if (process.platform !== requiredHost) {
    return {
      reason: "host-platform-mismatch",
      path: backend,
      required: [requiredHost, backend],
      publicSafeMessage: `${backend} requires a ${requiredHost} host.`,
    };
  }
  return {
    reason: "native-backend-runner-unattached",
    path: backend,
    required: [backend, nativeRunnerDependency(backend)],
    publicSafeMessage: `${backend} runner is not attached.`,
  };
}

function hostPlatformForBackend(backend: BackendFamily): NodeJS.Platform {
  if (backend === "macos-seatbelt") {
    return "darwin";
  }
  if (
    backend === "windows-native" ||
    backend === "windows-elevated" ||
    backend === "windows-unelevated"
  ) {
    return "win32";
  }
  return "linux";
}

function nativeRunnerDependency(backend: BackendFamily): string {
  if (backend === "macos-seatbelt") {
    return "/usr/bin/sandbox-exec";
  }
  return "windows-native-runner";
}

function spawnBubblewrap(
  request: RunRequest,
  prepared: PreparedLinuxRun,
): Promise<RunResponse> {
  return new Promise((resolvePromise) => {
    const child = spawn(prepared.bwrapExecutable!, prepared.bwrapArgs, {
      stdio: ["pipe", "pipe", "pipe"],
    });
    const timeoutMs = getTimeoutMs(request);
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let timer: NodeJS.Timeout | null = null;

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      resolvePromise({
        kind: "raxcell.runResult.v1",
        ok: false,
        backend: "linux-bubblewrap",
        exitCode: null,
        stdout,
        stderr: stderr || String(error),
        timedOut: false,
        denial: denial("SPAWN_FAILED", String(error)),
        policyDecision: null,
        environmentGap: null,
        filesystemLowering: prepared.response.filesystemLowering,
        fallback: null,
        capabilityReport: prepared.response.capabilityReport,
      });
    });
    child.on("close", (code) => {
      if (timer) {
        clearTimeout(timer);
      }
      resolvePromise({
        kind: "raxcell.runResult.v1",
        ok: true,
        backend: "linux-bubblewrap",
        exitCode: timedOut ? null : code,
        stdout,
        stderr,
        timedOut,
        denial: null,
        policyDecision: null,
        environmentGap: null,
        filesystemLowering: prepared.response.filesystemLowering,
        fallback: null,
        capabilityReport: prepared.response.capabilityReport,
      });
    });

    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, timeoutMs);
    }

    child.stdin.on("error", (error: NodeJS.ErrnoException) => {
      if (error.code !== "EPIPE") {
        stderr += String(error);
      }
    });
    child.stdin.end(request.command.stdin ?? "");
  });
}

function buildBwrapArgs(
  request: RunRequest,
  filesystemLowering: FileSystemLoweringReport,
): string[] {
  const env = {
    PATH: process.env.PATH ?? "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    ...(request.command.env ?? {}),
  };
  const args = [
    "--die-with-parent",
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts",
    "--new-session",
    "--clearenv",
  ];

  for (const [key, value] of Object.entries(env)) {
    args.push("--setenv", key, value);
  }

  if (request.enforcement.network === "deny") {
    args.push("--unshare-net");
  }

  args.push("--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp");

  for (const runtimeRoot of RUNTIME_READ_ROOTS) {
    if (existsSync(runtimeRoot)) {
      args.push(...parentDirArgs(runtimeRoot), "--ro-bind", runtimeRoot, runtimeRoot);
    }
  }

  for (const root of filesystemLowering.declaredRoots) {
    if (!existsSync(root.path) && !isMaterializableWriteGrant(root)) {
      continue;
    }
    args.push(...parentDirArgs(root.path));
    args.push(root.access === "write" ? "--bind" : "--ro-bind", root.path, root.path);
  }

  args.push("--chdir", request.command.cwd, "--", ...request.command.argv);
  return dedupeConsecutiveDirArgs(args);
}

function lowerFilesystem(
  request: RunRequest,
  backend: BackendFamily = "linux-bubblewrap",
): FileSystemLoweringReport {
  const filesystem = request.enforcement.filesystem ?? {};
  const declaredRoots: LoweredRoot[] = [];
  const policyGrants = normalizePolicyGrants(request.policyGrants ?? []);

  for (const path of filesystem.read ?? []) {
    declaredRoots.push({
      path: normalizeAbsolute(path),
      access: "read",
      source: "declared",
    });
  }
  for (const path of filesystem.write ?? []) {
    declaredRoots.push({
      path: normalizeAbsolute(path),
      access: "write",
      source: "declared",
    });
  }
  for (const grant of policyGrants) {
    declaredRoots.push({
      path: grant.path,
      access: grant.access?.includes("write") ? "write" : "read",
      source: "policy-grant",
    });
  }

  return {
    declaredRoots: collapseDeclaredRoots(declaredRoots),
    runtimeRoots: runtimeLoweredRootsForBackend(backend),
    policyGrants,
    warnings: [],
    effects: analyzeShellEffects(request.command.argv, normalizeAbsolute(request.command.cwd)),
  };
}

function materializeWriteGrantMounts(
  filesystemLowering: FileSystemLoweringReport,
): Denial | null {
  for (const root of filesystemLowering.declaredRoots) {
    if (!isMaterializableWriteGrant(root) || existsSync(root.path)) {
      continue;
    }
    try {
      closeSync(openSync(root.path, "a"));
    } catch (error) {
      return denial(
        "WRITE_GRANT_MATERIALIZATION_FAILED",
        `Failed to create writable policy-grant mount source ${root.path}: ${String(error)}`,
      );
    }
  }
  return null;
}

function isMaterializableWriteGrant(root: LoweredRoot): boolean {
  return root.source === "policy-grant" && root.access === "write";
}

function runtimeLoweredRoots(): LoweredRoot[] {
  return RUNTIME_READ_ROOTS.filter(existsSync).map((path) => ({
    path,
    access: "runtime",
    source: "backend-runtime",
  }));
}

function runtimeLoweredRootsForBackend(backend: BackendFamily): LoweredRoot[] {
  return backend === "linux-bubblewrap" ? runtimeLoweredRoots() : [];
}

function collapseDeclaredRoots(roots: LoweredRoot[]): LoweredRoot[] {
  const byPath = new Map<string, LoweredRoot>();
  for (const root of roots) {
    const existing = byPath.get(root.path);
    if (!existing || existing.access === "read" && root.access === "write") {
      byPath.set(root.path, root);
    }
  }
  return [...byPath.values()].sort((left, right) => left.path.localeCompare(right.path));
}

function normalizePolicyGrants(grants: PolicyGrant[]): PolicyGrant[] {
  return grants.map((grant) => ({
    ...grant,
    path: normalizeAbsolute(grant.path),
  }));
}

function cwdPolicyDecision(
  request: RunRequest,
  policyGrants: PolicyGrant[],
): PolicyDecisionRequired | null {
  const cwd = normalizeAbsolute(request.command.cwd);
  if (isAllowedPath(cwd, allowedRoots(request, policyGrants), "read")) {
    return null;
  }
  return {
    reason: "cwd-outside-declared-roots",
    path: cwd,
    required: ["read"],
    publicSafeMessage: "The command cwd is outside declared filesystem roots.",
  };
}

function argvPathPolicyDecision(
  request: RunRequest,
  policyGrants: PolicyGrant[],
): PolicyDecisionRequired | null {
  const roots = allowedRoots(request, policyGrants);
  const requirements = new Map<string, Set<"read" | "write">>();

  for (const effect of analyzeShellEffects(request.command.argv, normalizeAbsolute(request.command.cwd))) {
    if (effect.warning === "shell-dynamic-path-unresolved") {
      continue;
    }
    const path = effect.path ?? effect.pattern;
    if (!path || isRuntimePath(path)) {
      continue;
    }
    const accessSet = requirements.get(path) ?? new Set<"read" | "write">();
    for (const access of accessesForEffect(effect)) {
      accessSet.add(access);
    }
    requirements.set(path, accessSet);
  }

  for (const [path, accessSet] of requirements) {
    const missing: Array<"read" | "write"> = [];
    if (accessSet.has("read") && !isAllowedPath(path, roots, "read")) {
      missing.push("read");
    }
    if (accessSet.has("write") && !isAllowedPath(path, roots, "write")) {
      missing.push("write");
    }
    if (missing.length > 0) {
      return {
        reason: "path-outside-declared-roots",
        path,
        required: missing,
        publicSafeMessage: "The command references a path outside declared filesystem roots.",
      };
    }
  }
  return null;
}

function dynamicPathEnvironmentGap(request: RunRequest): EnvironmentGap | null {
  const effect = analyzeShellEffects(
    request.command.argv,
    normalizeAbsolute(request.command.cwd),
  ).find((candidate) => candidate.warning === "shell-dynamic-path-unresolved");
  if (!effect) {
    return null;
  }
  return {
    reason: "shell-dynamic-path-unresolved",
    path: effect.rawToken,
    required: accessListForEffect(effect),
    publicSafeMessage: "The command contains a dynamic shell path that Raxcell cannot safely normalize.",
  };
}

function accessesForEffect(effect: ShellEffect): Array<"read" | "write"> {
  return effect.access === "readwrite" ? ["read", "write"] : [effect.access];
}

function accessListForEffect(effect: ShellEffect): string[] {
  return accessesForEffect(effect);
}

function allowedRoots(
  request: RunRequest,
  policyGrants: PolicyGrant[],
): AllowedRoot[] {
  const filesystem = request.enforcement.filesystem ?? {};
  const roots: AllowedRoot[] = [];
  for (const path of filesystem.read ?? []) {
    roots.push({ path: normalizeAbsolute(path), access: "read", source: "declared" });
  }
  for (const path of filesystem.write ?? []) {
    roots.push({ path: normalizeAbsolute(path), access: "write", source: "declared" });
  }
  for (const grant of policyGrants) {
    roots.push({
      path: normalizeAbsolute(grant.path),
      access: grant.access?.includes("write") ? "write" : "read",
      source: "policy-grant",
    });
  }
  return roots;
}

function isAllowedPath(
  path: string,
  roots: AllowedRoot[],
  required: "read" | "write",
): boolean {
  return roots.some((root) => {
    if (required === "write" && root.access !== "write") {
      return false;
    }
    return path === root.path || path.startsWith(`${root.path}/`);
  });
}

function isRuntimePath(path: string): boolean {
  return RUNTIME_READ_ROOTS.some((root) => path === root || path.startsWith(`${root}/`));
}

function normalizeAbsolute(path: string): string {
  return normalize(isAbsolute(path) ? path : resolve(path));
}

function parentDirArgs(path: string): string[] {
  const parts = normalizeAbsolute(path).split("/").filter(Boolean);
  const args: string[] = [];
  let current = "";
  for (const part of parts.slice(0, -1)) {
    current += `/${part}`;
    args.push("--dir", current);
  }
  return args;
}

function dedupeConsecutiveDirArgs(args: string[]): string[] {
  const seenDirs = new Set<string>();
  const output: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--dir") {
      const dir = args[index + 1];
      if (seenDirs.has(dir)) {
        index += 1;
        continue;
      }
      seenDirs.add(dir);
    }
    output.push(args[index]);
  }
  return output;
}

function getTimeoutMs(request: RunRequest): number {
  const timeoutMs = request.enforcement.resources?.timeoutMs;
  return typeof timeoutMs === "number" && Number.isFinite(timeoutMs)
    ? timeoutMs
    : 0;
}

function findExecutable(name: string): string | null {
  if (name.includes("/") && existsSync(name)) {
    return name;
  }
  const result = spawnSync("which", [name], {
    encoding: "utf8",
  });
  if (result.status === 0) {
    return result.stdout.trim();
  }
  return null;
}

function denial(
  code: string,
  message: string,
  publicSafe = true,
): Denial {
  return {
    code,
    message,
    publicSafe,
  };
}

main().catch((error: unknown) => {
  process.stderr.write(`${String(error instanceof Error ? error.message : error)}\n`);
  process.exit(1);
});
