#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const raxcellRoot = resolve(scriptDir, "..");
const repoRoot = resolve(raxcellRoot, "..");
const rustCliPath = process.env.RAXCELL_RUST_CLI ?? resolve(raxcellRoot, "target/debug/raxcell");
const helperPath =
  process.env.RAXCELL_CODEX_LINUX_SANDBOX_BIN ??
  resolve(raxcellRoot, "target/debug/raxcell-codex-linux-sandbox");
const npmCliPath =
  process.env.RAXCELL_NPM_CLI ?? resolve(raxcellRoot, "sdk/dist/cli.js");
const backend = "linux-bubblewrap";
const outputPath = parseOutputPath(process.argv.slice(2));
const results = [];
let actionCounter = 0;

function main() {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-linux-smoke-workspace-"));
  const externalRoot = mkdtempSync(join(tmpdir(), "raxcell-linux-smoke-external-"));
  const externalReadFile = join(externalRoot, "read-only.txt");
  const externalWriteFile = join(externalRoot, "write-target.txt");
  writeFileSync(externalReadFile, "raxcell-external-read", "utf8");

  try {
    recordPreflight("rust-cli-exists", existsSync(rustCliPath), {
      surface: "rust-cli",
      path: rustCliPath,
      requiredCommand: "cargo build -p raxcell-cli -p raxcell-codex-linux-sandbox",
    });
    recordPreflight("codex-linux-helper-exists", existsSync(helperPath), {
      surface: "rust-cli",
      path: helperPath,
      requiredCommand: "cargo build -p raxcell-cli -p raxcell-codex-linux-sandbox",
    });
    recordPreflight("npm-shim-exists", existsSync(npmCliPath), {
      surface: "npm-shim",
      path: npmCliPath,
      requiredCommand: "pnpm --dir raxcell/sdk build",
    });

    if (preflightFailed()) {
      outputSummary({ workspace, externalRoot });
      return;
    }

    const probeRequest = {
      kind: "raxcell.probe.v1",
      backendPreference: [backend],
      requirements: {},
    };
    const rustProbe = runJson("rust-cli", ["probe", "--stdin"], probeRequest);
    recordCase({
      name: "probe-ready-rust-cli",
      surface: "rust-cli",
      request: summarizeRequest(probeRequest),
      run: summarizeProcessJson(rustProbe),
      pass:
        rustProbe.status === 0 &&
        rustProbe.json?.ready === true &&
        rustProbe.json?.selectedBackend === backend,
    });

    const npmProbe = runJson("npm-shim", ["probe"], probeRequest);
    recordCase({
      name: "probe-ready-npm-shim-delegates-rust",
      surface: "npm-shim",
      request: summarizeRequest(probeRequest),
      run: summarizeProcessJson(npmProbe),
      pass:
        npmProbe.status === 0 &&
        npmProbe.json?.ready === true &&
        npmProbe.json?.selectedBackend === backend,
    });

    const prepareRequest = runRequest({
      workspace,
      argv: ["/usr/bin/sh", "-lc", "printf prepare-only"],
    });
    const prepare = runJson("rust-cli", ["prepare-run", "--stdin"], prepareRequest);
    recordCase({
      name: "prepare-run-codex-artifact-rust-cli",
      surface: "rust-cli",
      request: summarizeRequest(prepareRequest),
      prepare: summarizePrepare(prepare.json),
      pass:
        prepare.status === 0 &&
        prepare.json?.ok === true &&
        hasArtifact(prepare.json, "codex-linux-sandbox-argv"),
    });

    const npmPrepare = runJson("npm-shim", ["prepare-run"], prepareRequest);
    recordCase({
      name: "prepare-run-codex-artifact-npm-shim",
      surface: "npm-shim",
      request: summarizeRequest(prepareRequest),
      prepare: summarizePrepare(npmPrepare.json),
      pass:
        npmPrepare.status === 0 &&
        npmPrepare.json?.ok === true &&
        hasArtifact(npmPrepare.json, "codex-linux-sandbox-argv"),
    });

    const workspaceFile = join(workspace, "raxcell_live_probe/hello.txt");
    mkdirSync(dirname(workspaceFile), { recursive: true });
    const workspaceRunRequest = runRequest({
      workspace,
      argv: [
        "/usr/bin/sh",
        "-lc",
        "mkdir -p raxcell_live_probe && printf raxcell-workspace > raxcell_live_probe/hello.txt && cat raxcell_live_probe/hello.txt && rm raxcell_live_probe/hello.txt && rmdir raxcell_live_probe",
      ],
    });
    const workspaceRun = runJson("rust-cli", ["run", "--stdin"], workspaceRunRequest);
    recordCase({
      name: "run-workspace-write-read-delete-rust-cli",
      surface: "rust-cli",
      request: summarizeRequest(workspaceRunRequest),
      run: summarizeRun(workspaceRun.json, {
        hostVisiblePath: workspaceFile,
        hostVisibleExists: existsSync(workspaceFile),
      }),
      pass:
        workspaceRun.status === 0 &&
        workspaceRun.json?.ok === true &&
        workspaceRun.json?.exitCode === 0 &&
        workspaceRun.json?.stdout === "raxcell-workspace" &&
        workspaceRun.json?.timedOut === false &&
        hasArtifact(workspaceRun.json, "codex-linux-sandbox-argv") &&
        !existsSync(workspaceFile),
    });

    const externalReadRequest = runRequest({
      workspace,
      argv: ["/usr/bin/sh", "-lc", `cat ${shellQuote(externalReadFile)}`],
    });
    const externalReadPrepare = runJson(
      "rust-cli",
      ["prepare-run", "--stdin"],
      externalReadRequest,
    );
    recordCase({
      name: "external-read-without-grant-policy-required",
      surface: "rust-cli",
      request: summarizeRequest(externalReadRequest),
      prepare: summarizePrepare(externalReadPrepare.json),
      pass:
        externalReadPrepare.status === 0 &&
        policyRequires(externalReadPrepare.json, "read"),
    });

    const externalWriteRequest = runRequest({
      workspace,
      argv: ["/usr/bin/sh", "-lc", `printf denied > ${shellQuote(externalWriteFile)}`],
    });
    const externalWritePrepare = runJson(
      "rust-cli",
      ["prepare-run", "--stdin"],
      externalWriteRequest,
    );
    recordCase({
      name: "external-write-without-grant-policy-required",
      surface: "rust-cli",
      request: summarizeRequest(externalWriteRequest),
      prepare: summarizePrepare(externalWritePrepare.json),
      pass:
        externalWritePrepare.status === 0 &&
        policyRequires(externalWritePrepare.json, "write"),
    });

    const readOnlyGrantWriteRequest = runRequest({
      workspace,
      argv: [
        "/usr/bin/sh",
        "-lc",
        `printf read-only-grant-denied > ${shellQuote(externalWriteFile)}`,
      ],
      policyGrants: [policyGrant(externalRoot, ["read"], "smoke-read-only")],
    });
    const readOnlyGrantWritePrepare = runJson(
      "rust-cli",
      ["prepare-run", "--stdin"],
      readOnlyGrantWriteRequest,
    );
    recordCase({
      name: "external-write-with-read-only-grant-policy-required",
      surface: "rust-cli",
      request: summarizeRequest(readOnlyGrantWriteRequest),
      prepare: summarizePrepare(readOnlyGrantWritePrepare.json),
      pass:
        readOnlyGrantWritePrepare.status === 0 &&
        policyRequires(readOnlyGrantWritePrepare.json, "write"),
    });

    const writeGrantRunRequest = runRequest({
      workspace,
      argv: [
        "/usr/bin/sh",
        "-lc",
        `printf raxcell-write-grant > ${shellQuote(externalWriteFile)}`,
      ],
      policyGrants: [policyGrant(externalRoot, ["write"], "smoke-write")],
    });
    rmSync(externalWriteFile, { force: true });
    const writeGrantRun = runJson("npm-shim", ["run"], writeGrantRunRequest);
    recordCase({
      name: "external-write-with-write-grant-host-visible-npm-shim",
      surface: "npm-shim",
      request: summarizeRequest(writeGrantRunRequest),
      run: summarizeRun(writeGrantRun.json, hostVisibleSummary(externalWriteFile)),
      pass:
        writeGrantRun.status === 0 &&
        writeGrantRun.json?.ok === true &&
        writeGrantRun.json?.exitCode === 0 &&
        hasArtifact(writeGrantRun.json, "codex-linux-sandbox-argv") &&
        existsSync(externalWriteFile) &&
        readFileSync(externalWriteFile, "utf8") === "raxcell-write-grant",
    });

    const nonzeroRequest = runRequest({
      workspace,
      argv: ["/usr/bin/sh", "-lc", "printf nonzero-path && exit 17"],
    });
    const nonzeroRun = runJson("npm-shim", ["run"], nonzeroRequest);
    recordCase({
      name: "command-nonzero-keeps-run-ok-npm-shim",
      surface: "npm-shim",
      request: summarizeRequest(nonzeroRequest),
      run: summarizeRun(nonzeroRun.json),
      pass:
        nonzeroRun.status === 0 &&
        nonzeroRun.json?.ok === true &&
        nonzeroRun.json?.exitCode === 17 &&
        nonzeroRun.json?.stdout === "nonzero-path",
    });

    const timeoutRequest = runRequest({
      workspace,
      argv: ["/usr/bin/sh", "-lc", "sleep 2; printf after-timeout"],
      timeoutMs: 100,
    });
    const timeoutRun = runJson("rust-cli", ["run", "--stdin"], timeoutRequest);
    recordCase({
      name: "timeout-documents-actual-semantics",
      surface: "rust-cli",
      request: summarizeRequest(timeoutRequest),
      run: summarizeRun(timeoutRun.json),
      pass:
        timeoutRun.status === 0 &&
        timeoutRun.json?.ok === false &&
        timeoutRun.json?.timedOut === true &&
        timeoutRun.json?.denial?.code === "TIMEOUT" &&
        !String(timeoutRun.json?.stdout ?? "").includes("after-timeout"),
    });

    const missingHelperPath = join(externalRoot, "missing-raxcell-codex-linux-sandbox");
    const missingHelperPrepare = runJson(
      "rust-cli",
      ["prepare-run", "--stdin"],
      prepareRequest,
      {
        RAXCELL_CODEX_LINUX_SANDBOX_BIN: missingHelperPath,
      },
    );
    recordCase({
      name: "missing-codex-helper-fails-closed",
      surface: "rust-cli",
      request: summarizeRequest(prepareRequest),
      prepare: summarizePrepare(missingHelperPrepare.json),
      process: summarizeProcess(missingHelperPrepare),
      pass:
        missingHelperPrepare.status === 0 &&
        missingHelperPrepare.json?.ok === false &&
        missingHelperPrepare.json?.environmentGap?.reason === "missing-backend-dependency" &&
        missingHelperPrepare.json?.environmentGap?.required?.includes(
          "dependency.binary.codex-linux-sandbox",
        ),
    });

    outputSummary({ workspace, externalRoot });
  } finally {
    rmSync(workspace, { recursive: true, force: true });
    rmSync(externalRoot, { recursive: true, force: true });
  }
}

function runRequest({ workspace, argv, policyGrants = [], timeoutMs = 3000, env = {} }) {
  actionCounter += 1;
  return {
    kind: "raxcell.run.v1",
    backendPreference: [backend],
    policyGrants,
    action: {
      actionId: `linux-live-smoke-${actionCounter}`,
      ownerRuntime: "raxcell-linux-live-smoke",
      intentLabel: "linux-codex-live-smoke",
      metadata: {},
    },
    command: {
      argv,
      cwd: workspace,
      env,
      stdin: null,
    },
    enforcement: {
      profile: "smoke-workspace-write-no-network",
      filesystem: {
        read: [workspace],
        write: [workspace],
      },
      network: "deny",
      process: { spawn: true },
      resources: { timeoutMs },
    },
    fallback: { mode: "none" },
  };
}

function policyGrant(path, access, reason) {
  return {
    reason,
    path,
    access,
    grantedBy: "raxcell-linux-live-smoke",
  };
}

function runJson(surface, args, input, envOverrides = {}) {
  const result = runCli(surface, args, input, envOverrides);
  if (result.status !== 0) {
    return { ...result, json: null };
  }
  try {
    return { ...result, json: JSON.parse(result.stdout.trim()) };
  } catch (error) {
    return { ...result, json: null, parseError: String(error) };
  }
}

function runCli(surface, args, input, envOverrides = {}) {
  const command = commandForSurface(surface, args);
  const env = {
    ...process.env,
    RAXCELL_RUST_CLI: rustCliPath,
    RAXCELL_CODEX_LINUX_SANDBOX_BIN: helperPath,
    ...envOverrides,
  };
  const result = spawnSync(command.executable, command.args, {
    encoding: "utf8",
    input: input === null || input === undefined ? undefined : JSON.stringify(input),
    env,
    timeout: 20000,
  });
  return {
    ...result,
    surface,
    command: [command.executable, ...command.args],
  };
}

function commandForSurface(surface, args) {
  if (surface === "rust-cli") {
    return { executable: rustCliPath, args };
  }
  if (surface === "npm-shim") {
    return { executable: process.execPath, args: [npmCliPath, ...args] };
  }
  throw new Error(`unknown surface ${surface}`);
}

function recordPreflight(name, pass, facts) {
  results.push({
    name,
    surface: facts.surface,
    request: null,
    prepare: null,
    run: null,
    pass,
    facts: pass
      ? facts
      : {
          ...facts,
          environmentGap: {
            reason: "missing-smoke-prerequisite",
            path: facts.path,
            required: [facts.requiredCommand],
          },
        },
  });
}

function recordCase({ name, surface, request, prepare = null, run = null, process = null, pass }) {
  results.push({
    name,
    surface,
    request,
    prepare,
    run,
    pass,
    facts: {
      artifactFormat:
        firstArtifactFormat(prepare) ?? firstArtifactFormat(run) ?? null,
      policyDecision: prepare?.policyDecision ?? run?.policyDecision ?? null,
      environmentGap: prepare?.environmentGap ?? run?.environmentGap ?? null,
      denial: prepare?.denial ?? run?.denial ?? null,
      ok: prepare?.ok ?? run?.ok ?? null,
      exitCode: run?.exitCode ?? null,
      timedOut: run?.timedOut ?? null,
      hostVisiblePath: run?.hostVisiblePath ?? null,
      hostVisibleContent: run?.hostVisibleContent ?? null,
      command: process?.command ?? null,
      status: process?.status ?? null,
    },
  });
}

function summarizeRequest(request) {
  if (request.kind === "raxcell.probe.v1") {
    return {
      kind: request.kind,
      backendPreference: request.backendPreference,
      requirements: request.requirements,
    };
  }
  return {
    kind: request.kind,
    backendPreference: request.backendPreference,
    actionId: request.action.actionId,
    argv: request.command.argv,
    cwd: request.command.cwd,
    filesystem: request.enforcement.filesystem,
    timeoutMs: request.enforcement.resources.timeoutMs,
    policyGrants: request.policyGrants.map((grant) => ({
      reason: grant.reason,
      path: grant.path,
      access: grant.access,
      grantedBy: grant.grantedBy,
    })),
  };
}

function summarizeProcessJson(result) {
  return {
    ...summarizeProcess(result),
    json: result.json,
    parseError: result.parseError,
  };
}

function summarizeProcess(result) {
  return {
    command: result.command,
    status: result.status,
    signal: result.signal,
    stderr: trim(result.stderr),
  };
}

function summarizePrepare(response) {
  return {
    ok: response?.ok,
    backend: response?.backend,
    denial: summarizeDenial(response?.denial),
    policyDecision: summarizePolicyDecision(response?.policyDecision),
    environmentGap: summarizeEnvironmentGap(response?.environmentGap),
    artifactFormats: artifactFormats(response),
    artifactFormat: artifactFormats(response)[0] ?? null,
    helperExecutable: response?.backendArtifacts?.[0]?.data?.executable ?? null,
    capabilityReady: response?.capabilityReport?.ready ?? null,
    capabilityMissing: response?.capabilityReport?.missing ?? [],
  };
}

function summarizeRun(response, extra = {}) {
  return {
    ok: response?.ok,
    backend: response?.backend,
    exitCode: response?.exitCode,
    stdout: response?.stdout,
    stderr: trim(response?.stderr),
    timedOut: response?.timedOut,
    denial: summarizeDenial(response?.denial),
    policyDecision: summarizePolicyDecision(response?.policyDecision),
    environmentGap: summarizeEnvironmentGap(response?.environmentGap),
    artifactFormats: artifactFormats(response),
    artifactFormat: artifactFormats(response)[0] ?? null,
    helperExecutable: response?.backendArtifacts?.[0]?.data?.executable ?? null,
    capabilityReady: response?.capabilityReport?.ready ?? null,
    capabilityMissing: response?.capabilityReport?.missing ?? [],
    ...extra,
  };
}

function summarizePolicyDecision(decision) {
  if (!decision) {
    return null;
  }
  return {
    reason: decision.reason,
    path: decision.path,
    required: decision.required,
  };
}

function summarizeEnvironmentGap(gap) {
  if (!gap) {
    return null;
  }
  return {
    reason: gap.reason,
    path: gap.path,
    required: gap.required,
  };
}

function summarizeDenial(denial) {
  if (!denial) {
    return null;
  }
  return {
    code: denial.code,
    message: denial.message,
  };
}

function hostVisibleSummary(path) {
  return {
    hostVisiblePath: path,
    hostVisibleExists: existsSync(path),
    hostVisibleContent: existsSync(path) ? readFileSync(path, "utf8") : null,
  };
}

function hasArtifact(response, format) {
  return artifactFormats(response).includes(format);
}

function artifactFormats(response) {
  return Array.isArray(response?.backendArtifacts)
    ? response.backendArtifacts.map((artifact) => artifact.format)
    : [];
}

function firstArtifactFormat(summary) {
  if (!summary) {
    return null;
  }
  return summary.artifactFormat ?? summary.artifactFormats?.[0] ?? null;
}

function policyRequires(response, required) {
  const requiredValues = new Set([required, `filesystem.${required}`]);
  return (
    response?.ok === false &&
    response?.policyDecision?.required?.some((value) => requiredValues.has(value)) &&
    !response.environmentGap
  );
}

function preflightFailed() {
  return results.some((result) => result.name.endsWith("-exists") && !result.pass);
}

function outputSummary({ workspace, externalRoot }) {
  const failed = results.filter((result) => !result.pass);
  const blocked = results.some(
    (result) =>
      !result.pass &&
      (result.facts?.environmentGap?.reason === "missing-smoke-prerequisite" ||
        result.run?.json?.ready === false ||
        result.run?.json?.missing?.length > 0),
  );
  const summary = {
    kind: "raxcell.linuxCodexLiveSmokeResult.v1",
    status: failed.length === 0 ? "PASS" : blocked ? "BLOCKED" : "FAIL",
    ok: failed.length === 0,
    platform: process.platform,
    backend,
    paths: {
      repoRoot,
      rustCliPath,
      helperPath,
      npmCliPath,
      workspace,
      externalRoot,
    },
    requiredEvidence: {
      rustCli: rustCliPath,
      codexLinuxSandboxHelper: helperPath,
      npmShimEnv: {
        RAXCELL_RUST_CLI: rustCliPath,
        RAXCELL_CODEX_LINUX_SANDBOX_BIN: helperPath,
      },
      forbiddenSuccessArtifact: "linux-bubblewrap-argv",
      requiredSuccessArtifact: "codex-linux-sandbox-argv",
    },
    results,
    failed: failed.map((result) => result.name),
  };
  const json = `${JSON.stringify(summary, null, 2)}\n`;
  process.stdout.write(json);
  if (outputPath) {
    mkdirSync(dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, json, "utf8");
  }
  process.exitCode = summary.ok ? 0 : 1;
}

function parseOutputPath(args) {
  const index = args.indexOf("--out");
  if (index === -1) {
    return null;
  }
  const value = args[index + 1];
  if (!value) {
    throw new Error("--out requires a path");
  }
  return resolve(value);
}

function trim(value) {
  if (typeof value !== "string") {
    return value ?? "";
  }
  return value.length > 500 ? `${value.slice(0, 500)}...` : value;
}

function shellQuote(value) {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

main();
