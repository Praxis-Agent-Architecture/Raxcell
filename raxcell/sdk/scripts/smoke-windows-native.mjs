#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(scriptDir, "..");
const cliPath = process.env.RAXCELL_BIN ?? resolve(packageRoot, "dist/cli.js");
const windowsRunnerPath = process.env.RAXCELL_WINDOWS_RUNNER ?? resolve(packageRoot, "dist/windows-runner.js");
const backend = "windows-native";
const results = [];

function main() {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-windows-smoke-workspace-"));
  const externalRoot = mkdtempSync(join(tmpdir(), "raxcell-windows-smoke-external-"));
  const externalFile = join(externalRoot, "raxcell-smoke.txt");

  try {
    const version = runCli(["--version"], null);
    const probe = runCliJson(["probe"], { kind: "raxcell.probe.v1", backendPreference: [backend] });
    const explanation = runCliJson(["explain-backend"], {
      kind: "raxcell.explainBackend.v1",
      backendPreference: [backend],
    });
    const ready = Boolean(probe.json?.ready);

    record("version", version.status === 0 && version.stdout.trim().length > 0, {
      version: version.stdout.trim(),
      stderr: version.stderr,
    });
    record("probe", probe.status === 0 && probe.json?.selectedBackend === backend, {
      ready,
      selectedBackend: probe.json?.selectedBackend,
      missing: probe.json?.missing,
      publicSafeMessage: probe.json?.publicSafeMessage,
    });
    record("explain-backend", explanation.status === 0 && explanation.json?.selectedBackend === backend, {
      primitives: explanation.json?.explanation?.isolationPrimitives,
      limits: explanation.json?.explanation?.limits,
    });

    const workspaceRequest = runRequest({
      workspace,
      argv: [
        "cmd.exe",
        "/d",
        "/s",
        "/c",
        "mkdir raxcell_live_probe && echo raxcell-ok > raxcell_live_probe\\hello.txt && type raxcell_live_probe\\hello.txt && del raxcell_live_probe\\hello.txt && rmdir raxcell_live_probe",
      ],
      policyGrants: [],
    });
    const workspacePrepare = runCliJson(["prepare-run"], workspaceRequest);
    record("prepare-workspace-write", workspacePrepare.status === 0 && readinessAwareOk(workspacePrepare.json, ready), summarizePrepare(workspacePrepare.json));

    const externalWriteRequest = runRequest({
      workspace,
      argv: ["cmd.exe", "/d", "/s", "/c", `echo raxcell-smoke > ${cmdQuote(externalFile)}`],
      policyGrants: [],
    });
    const externalWritePrepare = runCliJson(["prepare-run"], externalWriteRequest);
    record("prepare-external-write-without-grant", externalWritePrepare.status === 0 && readinessAwareDenied(externalWritePrepare.json, ready, "write"), summarizePrepare(externalWritePrepare.json));

    const readGrantWriteRequest = runRequest({
      workspace,
      argv: ["cmd.exe", "/d", "/s", "/c", `echo raxcell-smoke > ${cmdQuote(externalFile)}`],
      policyGrants: [{ reason: "smoke-read-only", path: externalFile, access: ["read"], grantedBy: "raxcell-smoke" }],
    });
    const readGrantWritePrepare = runCliJson(["prepare-run"], readGrantWriteRequest);
    record("prepare-external-write-with-read-grant", readGrantWritePrepare.status === 0 && readinessAwareDenied(readGrantWritePrepare.json, ready, "write"), summarizePrepare(readGrantWritePrepare.json));

    const dynamicRequest = runRequest({
      workspace,
      argv: ["cmd.exe", "/d", "/s", "/c", "type %USERPROFILE%\\raxcell-smoke.txt"],
      policyGrants: [],
      env: { USERPROFILE: dirname(externalFile) },
    });
    const dynamicPrepare = runCliJson(["prepare-run"], dynamicRequest);
    record("prepare-dynamic-path-gap", dynamicPrepare.status === 0 && readinessAwareEnvironmentGap(dynamicPrepare.json, ready, "shell-dynamic-path-unresolved"), summarizePrepare(dynamicPrepare.json));

    if (ready) {
      const writeGrantRunRequest = runRequest({
        workspace,
        argv: ["cmd.exe", "/d", "/s", "/c", `echo raxcell-smoke > ${cmdQuote(externalFile)} && type ${cmdQuote(externalFile)}`],
        policyGrants: [{ reason: "smoke-write", path: externalFile, access: ["write"], grantedBy: "raxcell-smoke" }],
      });
      const writeGrantRun = runCliJson(["run"], writeGrantRunRequest);
      record("run-external-write-with-write-grant", writeGrantRun.status === 0 && writeGrantRun.json?.ok === true && existsSync(externalFile) && readFileSync(externalFile, "utf8").includes("raxcell-smoke"), summarizeRun(writeGrantRun.json));
    } else {
      record("run-external-write-with-write-grant", true, {
        skipped: true,
        reason: "backend-not-ready",
      });
    }

    outputSummary({
      backend,
      cliPath,
      windowsRunnerPath,
      platform: process.platform,
      ready,
      results,
    });
  } finally {
    rmSync(workspace, { recursive: true, force: true });
    rmSync(externalRoot, { recursive: true, force: true });
  }
}

function runRequest({ workspace, argv, policyGrants, env = {} }) {
  return {
    kind: "raxcell.run.v1",
    backendPreference: [backend],
    policyGrants,
    action: {
      actionId: `smoke-${Date.now()}`,
      ownerRuntime: "raxcell-smoke",
      intentLabel: "native-backend-smoke",
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
      resources: { timeoutMs: 3000 },
    },
    fallback: { mode: "none" },
  };
}

function runCliJson(args, input) {
  const result = runCli(args, input);
  if (result.status !== 0) {
    return { ...result, json: null };
  }
  try {
    return { ...result, json: JSON.parse(result.stdout) };
  } catch (error) {
    return { ...result, json: null, parseError: String(error) };
  }
}

function runCli(args, input) {
  const isNodeScript = cliPath.endsWith(".js") || cliPath.endsWith(".mjs");
  const executable = isNodeScript ? process.execPath : cliPath;
  const executableArgs = isNodeScript ? [cliPath, ...args] : args;
  return spawnSync(executable, executableArgs, {
    encoding: "utf8",
    input: input === null ? undefined : JSON.stringify(input),
    env: {
      ...process.env,
      RAXCELL_WINDOWS_RUNNER: windowsRunnerPath,
    },
  });
}

function readinessAwareOk(response, ready) {
  return ready ? response?.ok === true : isExpectedNotReadyGap(response);
}

function readinessAwareDenied(response, ready, required) {
  if (!ready) {
    return isExpectedNotReadyGap(response);
  }
  return response?.ok === false && response?.policyDecision?.required?.includes(required);
}

function readinessAwareEnvironmentGap(response, ready, reason) {
  if (!ready) {
    return isExpectedNotReadyGap(response);
  }
  return response?.ok === false && response?.environmentGap?.reason === reason;
}

function isExpectedNotReadyGap(response) {
  return response?.ok === false &&
    ["host-platform-mismatch", "native-backend-runner-unattached"].includes(response?.environmentGap?.reason);
}

function summarizePrepare(response) {
  return {
    ok: response?.ok,
    backend: response?.backend,
    denial: response?.denial,
    policyDecision: response?.policyDecision,
    environmentGap: response?.environmentGap,
    artifactFormats: response?.backendArtifacts?.map((artifact) => artifact.format),
    aclRoots: response?.backendArtifacts?.[0]?.data?.aclRoots,
    networkMode: response?.backendArtifacts?.[0]?.data?.networkMode,
  };
}

function summarizeRun(response) {
  return {
    ok: response?.ok,
    backend: response?.backend,
    exitCode: response?.exitCode,
    stdout: response?.stdout,
    stderr: response?.stderr,
    timedOut: response?.timedOut,
    denial: response?.denial,
    policyDecision: response?.policyDecision,
    environmentGap: response?.environmentGap,
    artifactFormats: response?.backendArtifacts?.map((artifact) => artifact.format),
  };
}

function record(name, ok, details) {
  results.push({ name, ok, details });
}

function outputSummary(summary) {
  const failed = summary.results.filter((result) => !result.ok);
  process.stdout.write(`${JSON.stringify({
    kind: "raxcell.nativeSmokeResult.v1",
    ...summary,
    ok: failed.length === 0,
    failed: failed.map((result) => result.name),
  }, null, 2)}\n`);
  process.exitCode = failed.length === 0 ? 0 : 1;
}

function cmdQuote(value) {
  return `"${value.replace(/"/g, '""')}"`;
}

main();
