import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { RaxcellClient } from "./client.js";
import { writeGrantMaterializationMode } from "./backend-materialization.js";
import { parseRunnerRunResponse } from "./runner-protocol.js";
import { analyzeShellEffects, analyzeShellScript } from "./shell-effects.js";
import { DEFAULT_COMMAND_PATH, buildPreparedSpawnEnv } from "./spawn-env.js";
import type {
  ExplainBackendResponse,
  PolicyPack,
  PrepareRunResponse,
  ProbeRequest,
  ProbeResponse,
  ResolveProfileRequest,
  RunRequest,
  RunResponse,
  WindowsRunnerRunRequest,
} from "./types.js";

const testDir = dirname(fileURLToPath(import.meta.url));
const packageJsonPath = resolve(testDir, "../package.json");
const cliPath = resolve(testDir, "cli.js");
const windowsRunnerPath = resolve(testDir, "windows-runner.js");
const hasBwrap = spawnSync("which", ["bwrap"]).status === 0;

test("write grant materialization mode follows backend ownership", () => {
  assert.equal(writeGrantMaterializationMode("linux-bubblewrap"), "raxcell-precreate");
  assert.equal(writeGrantMaterializationMode("macos-seatbelt"), "raxcell-precreate");
  assert.equal(writeGrantMaterializationMode("windows-native"), "runner-owned");
  assert.equal(writeGrantMaterializationMode("windows-elevated"), "runner-owned");
  assert.equal(writeGrantMaterializationMode("windows-unelevated"), "runner-owned");
});

test("clean prepared spawn env does not inherit host environment", () => {
  const hostEnv = {
    PATH: "/host/bin",
    RAXCELL_HOST_ONLY: "should-not-leak",
  };
  const requestEnv = {
    PATH: "/request/bin",
    RAXCELL_ALLOWED: "yes",
  };

  assert.deepEqual(buildPreparedSpawnEnv(requestEnv, "clean", hostEnv), requestEnv);
  assert.deepEqual(buildPreparedSpawnEnv(undefined, "clean", hostEnv), {
    PATH: DEFAULT_COMMAND_PATH,
  });
  assert.deepEqual(buildPreparedSpawnEnv(requestEnv, "inherit", hostEnv), {
    ...hostEnv,
    ...requestEnv,
  });
  assert.equal(buildPreparedSpawnEnv(undefined, "inherit", hostEnv), undefined);
});

test("runner protocol parser accepts raxcell run result JSON", () => {
  const response: RunResponse = {
    kind: "raxcell.runResult.v1",
    ok: true,
    backend: "windows-native",
    exitCode: 7,
    stdout: "command stdout",
    stderr: "command stderr",
    timedOut: false,
    denial: null,
    policyDecision: null,
    environmentGap: null,
    filesystemLowering: null,
    fallback: null,
    capabilityReport: null,
  };

  assert.deepEqual(parseRunnerRunResponse(JSON.stringify(response)), response);
});

test("runner protocol parser overlays prepared execution facts", () => {
  const runnerResponse: RunResponse = {
    kind: "raxcell.runResult.v1",
    ok: true,
    backend: "windows-native",
    exitCode: 0,
    stdout: "runner stdout",
    stderr: "",
    timedOut: false,
    denial: null,
    policyDecision: null,
    environmentGap: null,
    fallback: null,
    capabilityReport: null,
  };
  const filesystemLowering = {
    declaredRoots: [
      { path: "C:\\workspace", access: "write" as const, source: "declared" as const },
    ],
    runtimeRoots: [],
    policyGrants: [],
    warnings: [],
  };
  const backendArtifacts = [
    {
      backend: "windows-native" as const,
      format: "windows-native-token-acl-plan",
      arguments: ["raxcell-windows-runner", "run"],
      data: {
        attached: true,
      },
      warnings: [],
    },
  ];
  const capabilityReport: ProbeResponse = {
    kind: "raxcell.probeResult.v1",
    ready: true,
    selectedBackend: "windows-native",
    supports: {},
    limits: [],
    weaknesses: [],
    missing: [],
    nextActions: [],
    publicSafeMessage: "Windows native runner is attached.",
  };

  assert.deepEqual(
    parseRunnerRunResponse(JSON.stringify(runnerResponse), {
      backend: "windows-native",
      filesystemLowering,
      capabilityReport,
      backendArtifacts,
    }),
    {
      ...runnerResponse,
      filesystemLowering,
      capabilityReport,
      backendArtifacts,
    },
  );
});

test("runner protocol parser rejects backend mismatches", () => {
  const runnerResponse: RunResponse = {
    kind: "raxcell.runResult.v1",
    ok: true,
    backend: "host-observed",
    exitCode: 0,
    stdout: "",
    stderr: "",
    timedOut: false,
    denial: null,
    policyDecision: null,
    environmentGap: null,
    filesystemLowering: null,
    fallback: null,
    capabilityReport: null,
  };

  assert.throws(
    () => parseRunnerRunResponse(JSON.stringify(runnerResponse), {
      backend: "windows-native",
      filesystemLowering: null,
      capabilityReport: null,
      backendArtifacts: null,
    }),
    /runner response backend must match prepared backend windows-native/,
  );
});

test("runner protocol parser rejects non-run-result stdout", () => {
  assert.throws(
    () => parseRunnerRunResponse("plain command stdout"),
    /runner stdout is not valid JSON/,
  );
  assert.throws(
    () => parseRunnerRunResponse(JSON.stringify({ kind: "wrong.kind" })),
    /runner response kind must be raxcell.runResult.v1/,
  );
});

test("CLI preserves Rust worker environmentGap responses on stdout only", () => {
  const fakeRustCli = createFakeRustCli({
    "prepare-run": {
      kind: "raxcell.prepareRunResult.v1",
      ok: false,
      backend: "linux-bubblewrap",
      denial: null,
      policyDecision: null,
      environmentGap: {
        reason: "missing-backend-dependency",
        path: "codex-linux-sandbox",
        required: ["codex-linux-sandbox"],
        publicSafeMessage: "Codex Linux sandbox helper is unavailable.",
      },
      filesystemLowering: null,
      backendArtifacts: [],
      capabilityReport: null,
    },
    run: {
      kind: "raxcell.runResult.v1",
      ok: false,
      backend: "linux-bubblewrap",
      exitCode: null,
      stdout: "",
      stderr: "",
      timedOut: false,
      denial: null,
      policyDecision: null,
      environmentGap: {
        reason: "backend-environment-unavailable",
        path: "codex-linux-sandbox",
        required: ["codex-linux-sandbox"],
        publicSafeMessage: "Codex Linux sandbox helper is unavailable.",
      },
      filesystemLowering: null,
      backendArtifacts: [],
      fallback: null,
      capabilityReport: null,
    },
  });

  try {
    const request = sampleRunRequest();
    const env = {
      ...process.env,
      RAXCELL_RUST_CLI: fakeRustCli.path,
    };
    const prepareResult = spawnSync(cliPath, ["prepare-run"], {
      encoding: "utf8",
      env,
      input: JSON.stringify(request),
    });
    assert.equal(prepareResult.status, 0, prepareResult.stderr);
    assert.equal(prepareResult.stderr, "");
    const prepareResponse = JSON.parse(prepareResult.stdout) as PrepareRunResponse;
    assert.equal(prepareResponse.environmentGap?.reason, "missing-backend-dependency");
    assert.equal(prepareResponse.policyDecision, null);
    assert.deepEqual(prepareResponse.backendArtifacts, []);

    const runResult = spawnSync(cliPath, ["run"], {
      encoding: "utf8",
      env,
      input: JSON.stringify(request),
    });
    assert.equal(runResult.status, 0, runResult.stderr);
    assert.equal(runResult.stderr, "");
    const runResponse = JSON.parse(runResult.stdout) as RunResponse;
    assert.equal(runResponse.environmentGap?.reason, "backend-environment-unavailable");
    assert.equal(runResponse.policyDecision, null);
    assert.deepEqual(runResponse.backendArtifacts, []);
  } finally {
    fakeRustCli.cleanup();
  }
});

test("CLI rejects Rust worker JSON with the wrong response kind", () => {
  const fakeRustCli = createFakeRustCli({
    "prepare-run": {
      kind: "raxcell.runResult.v1",
      ok: false,
      backend: "linux-bubblewrap",
      exitCode: null,
      stdout: "",
      stderr: "",
      timedOut: false,
      denial: null,
      policyDecision: null,
      environmentGap: null,
      fallback: null,
      capabilityReport: null,
    },
  });

  try {
    const result = spawnSync(cliPath, ["prepare-run"], {
      encoding: "utf8",
      env: {
        ...process.env,
        RAXCELL_RUST_CLI: fakeRustCli.path,
      },
      input: JSON.stringify(sampleRunRequest()),
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Rust worker prepare-run response kind must be raxcell\.prepareRunResult\.v1/);
    assert.equal(result.stdout, "");
  } finally {
    fakeRustCli.cleanup();
  }
});

test("shell effect analyzer classifies common filesystem commands", () => {
  const cwd = "/workspace";
  const cases: Array<{ script: string; path: string; access: string }> = [
    ["cp src /home/proview/a.txt", "/home/proview/a.txt", "write"],
    ["mv src /home/proview/a.txt", "/home/proview/a.txt", "write"],
    ["install src /home/proview/a.txt", "/home/proview/a.txt", "write"],
    ["rsync src /home/proview/dir/", "/home/proview/dir/", "write"],
    ["touch /home/proview/a.txt", "/home/proview/a.txt", "write"],
    ["mkdir -p /home/proview/dir", "/home/proview/dir", "write"],
    ["rm -rf /home/proview/dir", "/home/proview/dir", "write"],
    ["chmod 600 /home/proview/a.txt", "/home/proview/a.txt", "write"],
    ["sed -i 's/a/b/' /home/proview/a.txt", "/home/proview/a.txt", "readwrite"],
    ["perl -pi -e 's/a/b/' /home/proview/a.txt", "/home/proview/a.txt", "readwrite"],
    ["sed 's/a/b/' /home/proview/a.txt", "/home/proview/a.txt", "read"],
    ["cat /home/proview/a.txt", "/home/proview/a.txt", "read"],
    ["grep needle /home/proview/a.txt", "/home/proview/a.txt", "read"],
    ["cat > /home/proview/a.txt <<EOF", "/home/proview/a.txt", "write"],
    ["cat /home/proview/a.txt | tee /home/proview/b.txt", "/home/proview/b.txt", "write"],
  ].map(([script, path, access]) => ({ script, path, access }));

  for (const testCase of cases) {
    const effects = analyzeShellScript(testCase.script, cwd);
    assert.ok(
      effects.some((effect) => effect.path === testCase.path && effect.access === testCase.access),
      `${testCase.script} should include ${testCase.access} ${testCase.path}; got ${JSON.stringify(effects)}`,
    );
  }
});

test("shell effect analyzer classifies inline Python and Node filesystem calls", () => {
  const cwd = "/workspace";
  const cases: Array<{ script: string; access: string }> = [
    { script: `python -c "open('/home/proview/a.txt','w').write('x')"`, access: "write" },
    { script: `python -c "open('/home/proview/a.txt','a').write('x')"`, access: "write" },
    { script: `python -c "open('/home/proview/a.txt','r').read()"`, access: "read" },
    {
      script: `python -c "from pathlib import Path; Path('/home/proview/a.txt').write_text('x')"`,
      access: "write",
    },
    {
      script: `node -e "require('fs').writeFileSync('/home/proview/a.txt','x')"`,
      access: "write",
    },
    {
      script: `node -e "require('fs').appendFileSync('/home/proview/a.txt','x')"`,
      access: "write",
    },
    {
      script: `node -e "require('fs').readFileSync('/home/proview/a.txt','utf8')"`,
      access: "read",
    },
  ];

  for (const testCase of cases) {
    const effects = analyzeShellScript(testCase.script, cwd);
    assert.ok(
      effects.some((effect) => effect.path === "/home/proview/a.txt" && effect.access === testCase.access),
      `${testCase.script} should include ${testCase.access}; got ${JSON.stringify(effects)}`,
    );
  }
});

test("shell effect analyzer preserves quoted paths, globs, pipelines, and dynamic warnings", () => {
  const effects = analyzeShellScript(
    `echo x > "/home/proview/a file.txt" && cat /home/proview/*.txt | tee "$HOME/out.txt"`,
    "/workspace",
  );
  assert.ok(effects.some((effect) => effect.path === "/home/proview/a file.txt" && effect.access === "write"));
  assert.ok(effects.some((effect) => effect.pattern === "/home/proview/*.txt" && effect.warning === "shell-glob-pattern"));
  assert.ok(effects.some((effect) => effect.rawToken === "$HOME/out.txt" && effect.warning === "shell-dynamic-path-unresolved" && effect.access === "write"));
});

test("shell effect analyzer classifies Windows cmd filesystem effects", () => {
  const effects = analyzeShellScript(
    `echo hello > "C:\\Users\\proview\\a file.txt" && type C:\\Users\\proview\\a.txt && copy C:\\Users\\proview\\a.txt C:\\Users\\proview\\b.txt && del C:\\Users\\proview\\old.txt`,
    "C:\\workspace",
  );

  assert.ok(effects.some((effect) => effect.path === "C:\\Users\\proview\\a file.txt" && effect.access === "write"));
  assert.ok(effects.some((effect) => effect.path === "C:\\Users\\proview\\a.txt" && effect.access === "read"));
  assert.ok(effects.some((effect) => effect.path === "C:\\Users\\proview\\b.txt" && effect.access === "write"));
  assert.ok(effects.some((effect) => effect.path === "C:\\Users\\proview\\old.txt" && effect.access === "write"));
});

test("shell effect analyzer treats Windows cmd dynamic paths as unresolved", () => {
  const effects = analyzeShellScript(
    `type %USERPROFILE%\\a.txt && echo hello > %TARGET%\\b.txt`,
    "C:\\workspace",
  );

  assert.ok(effects.some((effect) => effect.rawToken === "%USERPROFILE%\\a.txt" && effect.warning === "shell-dynamic-path-unresolved" && effect.access === "read"));
  assert.ok(effects.some((effect) => effect.rawToken === "%TARGET%\\b.txt" && effect.warning === "shell-dynamic-path-unresolved" && effect.access === "write"));
});

test("shell effect analyzer extracts Windows cmd /c scripts from argv", () => {
  const effects = analyzeShellEffects(
    ["cmd.exe", "/d", "/s", "/c", "type C:\\Users\\proview\\a.txt"],
    "C:\\workspace",
  );

  assert.ok(effects.some((effect) => effect.path === "C:\\Users\\proview\\a.txt" && effect.access === "read"));
});

test("package exposes the raxcell executable", () => {
  const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8")) as {
    bin?: Record<string, string>;
  };
  assert.deepEqual(packageJson.bin, {
    raxcell: "./dist/cli.js",
    "raxcell-windows-runner": "./dist/windows-runner.js",
  });
});

test("package exposes colleague smoke scripts for native backends", () => {
  const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8")) as {
    scripts?: Record<string, string>;
  };
  assert.equal(packageJson.scripts?.build, "tsc -p tsconfig.json && node scripts/mark-cli-executable.mjs");
  assert.equal(packageJson.scripts?.["smoke:macos"], "node scripts/smoke-macos-seatbelt.mjs");
  assert.equal(packageJson.scripts?.["smoke:windows"], "node scripts/smoke-windows-native.mjs");
  assert.equal(existsSync(resolve(testDir, "../scripts/mark-cli-executable.mjs")), true);
  assert.equal(existsSync(windowsRunnerPath), true);
  assert.equal(existsSync(resolve(testDir, "../scripts/smoke-macos-seatbelt.mjs")), true);
  assert.equal(existsSync(resolve(testDir, "../scripts/smoke-windows-native.mjs")), true);
});

test("windows runner probes the configured Codex sandbox engine", () => {
  const tempDir = mkdtempSync(join(tmpdir(), "raxcell-windows-runner-probe-"));
  const fakeCodex = join(tempDir, "codex.js");
  writeFileSync(
    fakeCodex,
    `#!/usr/bin/env node
if (process.argv.includes("--version")) {
  console.log("codex 1.2.3");
  process.exit(0);
}
process.exit(8);
`,
  );
  chmodSync(fakeCodex, 0o755);

  try {
    const result = spawnSync(process.execPath, [windowsRunnerPath, "probe"], {
      encoding: "utf8",
      env: {
        ...process.env,
        RAXCELL_CODEX_BIN: fakeCodex,
      },
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as {
      kind: string;
      ready: boolean;
      codexPath: string | null;
      missing: string[];
    };
    assert.deepEqual(response, {
      kind: "raxcell.windowsRunner.probeResult.v1",
      ready: true,
      codexPath: fakeCodex,
      missing: [],
    });
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test("windows runner lowers Raxcell request to Codex sandbox profile", () => {
  const tempDir = mkdtempSync(join(tmpdir(), "raxcell-windows-runner-run-"));
  const fakeCodex = join(tempDir, "codex.js");
  const observedPath = join(tempDir, "observed.json");
  writeFileSync(
    fakeCodex,
    `#!/usr/bin/env node
const { readFileSync, writeFileSync } = require("node:fs");
const { join } = require("node:path");
const observed = {
  argv: process.argv.slice(2),
  codexHome: process.env.CODEX_HOME,
  config: readFileSync(join(process.env.CODEX_HOME, "config.toml"), "utf8"),
  stdin: readFileSync(0, "utf8")
};
writeFileSync(${JSON.stringify(observedPath)}, JSON.stringify(observed));
process.stdout.write(JSON.stringify(observed));
process.stderr.write("codex-stderr");
process.exit(7);
`,
  );
  chmodSync(fakeCodex, 0o755);

  const request: WindowsRunnerRunRequest = {
    kind: "raxcell.windowsRunner.run.v1",
    backend: "windows-native",
    command: {
      argv: ["cmd.exe", "/d", "/s", "/c", "type hello.txt"],
      cwd: "C:\\workspace",
      env: { RAXCELL_ALLOWED: "yes" },
      stdin: "runner-stdin",
    },
    normalizedCwd: "C:\\workspace",
    commandEnvMode: "clean",
    writeGrantMaterialization: "runner-owned",
    enforcement: {
      profile: "windows-smoke",
      filesystem: {
        read: ["C:\\workspace"],
        write: ["C:\\workspace"],
      },
      network: "deny",
      process: {},
      resources: { timeoutMs: 1000 },
    },
    action: {
      actionId: "windows-runner-test",
      ownerRuntime: "test",
      intentLabel: "windows-runner",
      metadata: {},
    },
    filesystemLowering: {
      declaredRoots: [
        { path: "C:\\workspace", access: "write", source: "declared" },
        { path: "D:\\readonly", access: "read", source: "policy-grant" },
      ],
      runtimeRoots: [],
      policyGrants: [{ reason: "test", path: "D:\\readonly", access: ["read"], grantedBy: "test" }],
      warnings: [],
    },
    tokenMode: "writable-roots-capability",
    aclRoots: [
      { path: "C:\\workspace", access: "write", source: "declared" },
      { path: "D:\\readonly", access: "read", source: "policy-grant" },
    ],
    networkBlocked: true,
    networkMode: "deny",
    timeoutMs: 1000,
  };

  try {
    const result = spawnSync(process.execPath, [windowsRunnerPath, "run"], {
      encoding: "utf8",
      input: JSON.stringify(request),
      env: {
        ...process.env,
        RAXCELL_CODEX_BIN: fakeCodex,
      },
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as RunResponse;
    const observed = JSON.parse(readFileSync(observedPath, "utf8")) as {
      argv: string[];
      codexHome: string;
      config: string;
      stdin: string;
    };

    assert.equal(response.kind, "raxcell.runResult.v1");
    assert.equal(response.ok, true);
    assert.equal(response.backend, "windows-native");
    assert.equal(response.exitCode, 7);
    assert.equal(response.stderr, "codex-stderr");
    assert.deepEqual(observed.argv, [
      "sandbox",
      "--permissions-profile",
      "raxcell-runtime",
      "--include-managed-config",
      "-C",
      "C:\\workspace",
      "--",
      "cmd.exe",
      "/d",
      "/s",
      "/c",
      "type hello.txt",
    ]);
    assert.equal(observed.stdin, "runner-stdin");
    assert.match(observed.config, /default_permissions = "raxcell-runtime"/);
    assert.match(observed.config, /\[permissions\.raxcell-runtime\.filesystem\]/);
    assert.match(observed.config, /"C:\\\\workspace" = "write"/);
    assert.match(observed.config, /"D:\\\\readonly" = "read"/);
    assert.match(observed.config, /\[permissions\.raxcell-runtime\.network\]\nenabled = false/);
    assert.ok(response.stdout.includes('"argv"'));
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test("windows runner reports backend timeout without treating it as command exit", () => {
  const tempDir = mkdtempSync(join(tmpdir(), "raxcell-windows-runner-timeout-"));
  const fakeCodex = join(tempDir, "codex.js");
  writeFileSync(
    fakeCodex,
    `#!/usr/bin/env node
setTimeout(() => {}, 10000);
`,
  );
  chmodSync(fakeCodex, 0o755);

  const request: WindowsRunnerRunRequest = {
    kind: "raxcell.windowsRunner.run.v1",
    backend: "windows-native",
    command: {
      argv: ["cmd.exe", "/d", "/s", "/c", "echo hello"],
      cwd: "C:\\workspace",
      env: {},
      stdin: null,
    },
    normalizedCwd: "C:\\workspace",
    commandEnvMode: "clean",
    writeGrantMaterialization: "runner-owned",
    enforcement: {
      profile: "windows-timeout",
      filesystem: {
        read: ["C:\\workspace"],
        write: ["C:\\workspace"],
      },
      network: "deny",
      process: {},
      resources: { timeoutMs: 50 },
    },
    action: {
      actionId: "windows-runner-timeout",
      ownerRuntime: "test",
      intentLabel: "windows-runner-timeout",
      metadata: {},
    },
    filesystemLowering: {
      declaredRoots: [{ path: "C:\\workspace", access: "write", source: "declared" }],
      runtimeRoots: [],
      policyGrants: [],
      warnings: [],
    },
    tokenMode: "writable-roots-capability",
    aclRoots: [{ path: "C:\\workspace", access: "write", source: "declared" }],
    networkBlocked: true,
    networkMode: "deny",
    timeoutMs: 50,
  };

  try {
    const result = spawnSync(process.execPath, [windowsRunnerPath, "run"], {
      encoding: "utf8",
      input: JSON.stringify(request),
      env: {
        ...process.env,
        RAXCELL_CODEX_BIN: fakeCodex,
      },
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as RunResponse;

    assert.deepEqual(response, {
      kind: "raxcell.runResult.v1",
      ok: false,
      backend: "windows-native",
      exitCode: null,
      stdout: "",
      stderr: "",
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
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test("colleague smoke scripts emit protocol JSON summaries on this host", () => {
  for (const scriptName of ["smoke-macos-seatbelt.mjs", "smoke-windows-native.mjs"]) {
    const scriptPath = resolve(testDir, "../scripts", scriptName);
    const result = spawnSync(process.execPath, [scriptPath], {
      encoding: "utf8",
      env: {
        ...process.env,
        RAXCELL_BIN: cliPath,
      },
    });

    assert.equal(result.status, 0, `${scriptName}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
    const response = JSON.parse(result.stdout) as {
      kind: string;
      ok: boolean;
      results: Array<{ name: string; ok: boolean }>;
    };
    assert.equal(response.kind, "raxcell.nativeSmokeResult.v1");
    assert.equal(response.ok, true);
    assert.ok(response.results.length >= 5);
    assert.deepEqual(response.results.filter((entry) => !entry.ok), []);
  }
});

test("cli exposes package version", () => {
  const result = spawnSync(cliPath, ["--version"], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test("probe respects backend preference for protocol-visible native backends", () => {
  const result = spawnSync(cliPath, ["probe"], {
    encoding: "utf8",
    input: JSON.stringify({
      kind: "raxcell.probe.v1",
      backendPreference: ["macos-seatbelt"],
    }),
  });
  assert.equal(result.status, 0, result.stderr);
  const response = JSON.parse(result.stdout) as ProbeResponse;
  assert.equal(response.ready, false);
  assert.equal(response.selectedBackend, "macos-seatbelt");
  assert.match(response.publicSafeMessage, /macos-seatbelt/);
});

test("explain-backend exposes native primitives without claiming execution readiness", () => {
  const result = spawnSync(cliPath, ["explain-backend"], {
    encoding: "utf8",
    input: JSON.stringify({
      kind: "raxcell.explainBackend.v1",
      backendPreference: ["windows-native"],
    }),
  });
  assert.equal(result.status, 0, result.stderr);
  const response = JSON.parse(result.stdout) as ExplainBackendResponse;
  assert.equal(response.selectedBackend, "windows-native");
  assert.equal(response.probe.ready, false);
  assert.ok(response.explanation.isolationPrimitives.includes("windows-restricted-token"));
  assert.match(response.explanation.limits.join("\n"), /Windows native sandboxing executes through/);
});

test("client dispatches prepare-run and run through stdin JSON", async () => {
  const tempDir = mkdtempSync(join(tmpdir(), "raxcell-client-"));
  const fakeCli = join(tempDir, "fake-raxcell.js");
  writeFileSync(
    fakeCli,
    `#!/usr/bin/env node
const chunks = [];
process.stdin.setEncoding("utf8");
process.stdin.on("data", chunk => chunks.push(chunk));
process.stdin.on("end", () => {
  const input = JSON.parse(chunks.join(""));
  const command = process.argv[2];
  if (process.argv.includes("--stdin")) {
    console.error("--stdin should not be passed");
    process.exit(9);
  }
  if (command === "prepare-run") {
    console.log(JSON.stringify({
      kind: "raxcell.prepareRunResult.v1",
      ok: input.kind === "raxcell.run.v1",
      backend: "linux-bubblewrap",
      denial: null,
      policyDecision: null,
      environmentGap: null,
      filesystemLowering: null,
      backendArtifacts: [],
      capabilityReport: null
    }));
    return;
  }
  if (command === "run") {
    console.log(JSON.stringify({
      kind: "raxcell.runResult.v1",
      ok: true,
      backend: "linux-bubblewrap",
      exitCode: 0,
      stdout: "ok",
      stderr: "",
      timedOut: false,
      denial: null,
      policyDecision: null,
      environmentGap: null,
      filesystemLowering: null,
      fallback: null,
      capabilityReport: null
    }));
    return;
  }
  console.error("unexpected command " + command);
  process.exit(8);
});
`,
  );
  chmodSync(fakeCli, 0o755);

  try {
    const client = new RaxcellClient({ binaryPath: fakeCli });
    const request = sampleRunRequest();
    const prepared = await client.prepareRun(request);
    const result = await client.run(request);
    assert.equal(prepared.kind, "raxcell.prepareRunResult.v1");
    assert.equal(result.stdout, "ok");
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test("client rejects responses with the wrong protocol kind", async () => {
  const tempDir = mkdtempSync(join(tmpdir(), "raxcell-client-"));
  const fakeCli = join(tempDir, "fake-raxcell.js");
  writeFileSync(
    fakeCli,
    `#!/usr/bin/env node
process.stdin.resume();
process.stdin.on("end", () => {
  console.log(JSON.stringify({ kind: "wrong.kind" }));
});
`,
  );
  chmodSync(fakeCli, 0o755);

  try {
    const client = new RaxcellClient({ binaryPath: fakeCli });
    await assert.rejects(
      () => client.prepareRun(sampleRunRequest()),
      /Unexpected raxcell response kind/,
    );
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test("cli resolves shell redirection relative paths against command cwd", () => {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-relative-path-"));
  const fakeBinDir = mkdtempSync(join(tmpdir(), "raxcell-fake-bin-"));
  const fakeBwrap = join(fakeBinDir, "bwrap");
  writeFileSync(fakeBwrap, "#!/bin/sh\nexit 0\n");
  chmodSync(fakeBwrap, 0o755);
  const request: RunRequest = {
    ...sampleRunRequest(),
    command: {
      argv: [
        "/bin/sh",
        "-lc",
        "mkdir -p raxcell_live_probe && printf 'raxcell-ok' > raxcell_live_probe/hello.txt",
      ],
      cwd: workspace,
      env: {},
      stdin: null,
    },
    enforcement: {
      ...sampleRunRequest().enforcement,
      filesystem: {
        read: [workspace],
        write: [workspace],
      },
    },
  };

  try {
    const result = spawnSync(cliPath, ["prepare-run"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH ?? ""}`,
      },
      input: JSON.stringify(request),
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as PrepareRunResponse;
    const artifact = response.backendArtifacts[0];
    assert.equal(response.ok, true);
    assert.equal(response.policyDecision, null);
    assert.equal(artifact.data.networkMode, "deny");
    assert.equal(artifact.data.commandEnvMode, "clean");
    assert.deepEqual(artifact.data.commandEnv, {
      PATH: DEFAULT_COMMAND_PATH,
    });
    assert.equal(artifact.data.writeGrantMaterialization, "raxcell-precreate");
    assert.deepEqual(artifact.data.readRoots, [workspace]);
    assert.deepEqual(artifact.data.writeRoots, [workspace]);
    assert.ok(Array.isArray(artifact.data.runtimeRoots));
    assert.ok((artifact.data.rootRules as unknown[]).some((root) => {
      return typeof root === "object" &&
        root !== null &&
        "path" in root &&
        "access" in root &&
        "source" in root &&
        root.path === workspace &&
        root.access === "write" &&
        root.source === "declared";
    }));
    assert.equal(artifact.data.timeoutMs, 1000);
    assert.deepEqual(artifact.data.processLimits, {
      spawn: true,
    });
    assert.deepEqual(artifact.data.resourceLimits, {
      timeoutMs: 1000,
    });
    assert.ok((artifact.data.filesystemEffects as unknown[]).some((effect) => {
      return typeof effect === "object" &&
        effect !== null &&
        "rawToken" in effect &&
        effect.rawToken === "raxcell_live_probe/hello.txt";
    }));
  } finally {
    rmSync(workspace, { recursive: true, force: true });
    rmSync(fakeBinDir, { recursive: true, force: true });
  }
});

test("run keeps ok true when sandbox executes a nonzero command", () => {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-nonzero-"));
  const fakeBinDir = mkdtempSync(join(tmpdir(), "raxcell-fake-bin-"));
  const fakeBwrap = join(fakeBinDir, "bwrap");
  writeFileSync(fakeBwrap, "#!/bin/sh\nprintf command-failed >&2\nexit 7\n");
  chmodSync(fakeBwrap, 0o755);
  const request: RunRequest = {
    ...sampleRunRequest(),
    command: {
      argv: ["/bin/sh", "-lc", "exit 7"],
      cwd: workspace,
      env: {},
      stdin: null,
    },
    enforcement: {
      ...sampleRunRequest().enforcement,
      filesystem: {
        read: [workspace],
        write: [workspace],
      },
    },
  };

  try {
    const result = spawnSync(cliPath, ["run"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH ?? ""}`,
      },
      input: JSON.stringify(request),
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as RunResponse;
    assert.equal(response.ok, true);
    assert.equal(response.exitCode, 7);
    assert.match(response.stderr, /command-failed/);
    assert.equal(response.denial, null);
    assert.equal(response.environmentGap, null);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
    rmSync(fakeBinDir, { recursive: true, force: true });
  }
});

test("run reports bubblewrap startup failure as backend failure", () => {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-bwrap-failure-"));
  const fakeBinDir = mkdtempSync(join(tmpdir(), "raxcell-fake-bin-"));
  const fakeBwrap = join(fakeBinDir, "bwrap");
  writeFileSync(fakeBwrap, "#!/bin/sh\nprintf 'bwrap: mount failed\\n' >&2\nexit 1\n");
  chmodSync(fakeBwrap, 0o755);
  const request: RunRequest = {
    ...sampleRunRequest(),
    command: {
      argv: ["/bin/sh", "-lc", "printf never-runs"],
      cwd: workspace,
      env: {},
      stdin: null,
    },
    enforcement: {
      ...sampleRunRequest().enforcement,
      filesystem: {
        read: [workspace],
        write: [workspace],
      },
    },
  };

  try {
    const result = spawnSync(cliPath, ["run"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH ?? ""}`,
      },
      input: JSON.stringify(request),
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as RunResponse;
    assert.equal(response.ok, false);
    assert.equal(response.exitCode, 1);
    assert.equal(response.timedOut, false);
    assert.equal(response.denial?.code, "BACKEND_EXECUTION_FAILED");
    assert.match(response.stderr, /^bwrap: mount failed/);
    assert.equal(response.policyDecision, null);
    assert.equal(response.environmentGap, null);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
    rmSync(fakeBinDir, { recursive: true, force: true });
  }
});

test("run reports parent-enforced timeout as backend failure", () => {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-timeout-"));
  const fakeBinDir = mkdtempSync(join(tmpdir(), "raxcell-fake-bin-"));
  const fakeBwrap = join(fakeBinDir, "bwrap");
  writeFileSync(fakeBwrap, "#!/bin/sh\nexec sleep 10\n");
  chmodSync(fakeBwrap, 0o755);
  const request: RunRequest = {
    ...sampleRunRequest(),
    command: {
      argv: ["/bin/sh", "-lc", "sleep 10"],
      cwd: workspace,
      env: {},
      stdin: null,
    },
    enforcement: {
      ...sampleRunRequest().enforcement,
      filesystem: {
        read: [workspace],
        write: [workspace],
      },
      resources: {
        timeoutMs: 50,
      },
    },
  };

  try {
    const result = spawnSync(cliPath, ["run"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH ?? ""}`,
      },
      input: JSON.stringify(request),
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as RunResponse;
    assert.equal(response.ok, false);
    assert.equal(response.exitCode, null);
    assert.equal(response.timedOut, true);
    assert.equal(response.denial?.code, "RUNNER_TIMED_OUT");
    assert.equal(response.policyDecision, null);
    assert.equal(response.environmentGap, null);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
    rmSync(fakeBinDir, { recursive: true, force: true });
  }
});

test("prepare-run reports policy grants as lowered policy-grant roots", () => {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-grants-workspace-"));
  const granted = mkdtempSync(join(tmpdir(), "raxcell-granted-root-"));
  const fakeBinDir = mkdtempSync(join(tmpdir(), "raxcell-fake-bin-"));
  const fakeBwrap = join(fakeBinDir, "bwrap");
  writeFileSync(fakeBwrap, "#!/bin/sh\nexit 0\n");
  chmodSync(fakeBwrap, 0o755);
  const request: RunRequest = {
    ...sampleRunRequest(),
    policyGrants: [
      {
        reason: "praxis-approved-read",
        path: granted,
        access: ["read"],
        grantedBy: "praxis-policy",
      },
    ],
    command: {
      argv: ["/bin/ls", granted],
      cwd: workspace,
      env: {},
      stdin: null,
    },
    enforcement: {
      ...sampleRunRequest().enforcement,
      filesystem: {
        read: [workspace],
        write: [workspace],
      },
    },
  };

  try {
    const result = spawnSync(cliPath, ["prepare-run"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH ?? ""}`,
      },
      input: JSON.stringify(request),
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as PrepareRunResponse;
    assert.equal(response.ok, true);
    assert.deepEqual(
      response.filesystemLowering?.declaredRoots.find((root) => root.path === granted),
      {
        path: granted,
        access: "read",
        source: "policy-grant",
      },
    );
  } finally {
    rmSync(workspace, { recursive: true, force: true });
    rmSync(granted, { recursive: true, force: true });
    rmSync(fakeBinDir, { recursive: true, force: true });
  }
});

test("prepare-run classifies external shell redirection as write gap", () => {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-write-gap-workspace-"));
  const externalRoot = mkdtempSync(join(tmpdir(), "raxcell-write-gap-external-"));
  const externalFile = join(externalRoot, "helloRax.txt");
  const fakeBinDir = mkdtempSync(join(tmpdir(), "raxcell-fake-bin-"));
  const fakeBwrap = join(fakeBinDir, "bwrap");
  writeFileSync(fakeBwrap, "#!/bin/sh\nexit 0\n");
  chmodSync(fakeBwrap, 0o755);
  const request: RunRequest = {
    ...sampleRunRequest(),
    command: {
      argv: ["/bin/sh", "-lc", `printf hello > ${externalFile}`],
      cwd: workspace,
      env: {},
      stdin: null,
    },
    enforcement: {
      ...sampleRunRequest().enforcement,
      filesystem: {
        read: [workspace],
        write: [workspace],
      },
    },
  };

  try {
    const result = spawnSync(cliPath, ["prepare-run"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH ?? ""}`,
      },
      input: JSON.stringify(request),
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as PrepareRunResponse;
    assert.equal(response.ok, false);
    assert.ok(response.policyDecision);
    assert.equal(response.policyDecision.path, externalFile);
    assert.ok(Array.isArray(response.policyDecision.required));
    assert.ok(response.policyDecision.required.includes("write"));
  } finally {
    rmSync(workspace, { recursive: true, force: true });
    rmSync(externalRoot, { recursive: true, force: true });
    rmSync(fakeBinDir, { recursive: true, force: true });
  }
});

test("prepare-run rejects external writes with only a read policy grant", () => {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-read-grant-workspace-"));
  const externalRoot = mkdtempSync(join(tmpdir(), "raxcell-read-grant-external-"));
  const externalFile = join(externalRoot, "helloRax.txt");
  const fakeBinDir = mkdtempSync(join(tmpdir(), "raxcell-fake-bin-"));
  const fakeBwrap = join(fakeBinDir, "bwrap");
  writeFileSync(fakeBwrap, "#!/bin/sh\nexit 0\n");
  chmodSync(fakeBwrap, 0o755);
  const request: RunRequest = {
    ...sampleRunRequest(),
    policyGrants: [
      {
        reason: "human-approved-read",
        path: externalFile,
        access: ["read"],
        grantedBy: "praxis-policy",
      },
    ],
    command: {
      argv: ["/bin/sh", "-lc", `printf hello > ${externalFile}`],
      cwd: workspace,
      env: {},
      stdin: null,
    },
    enforcement: {
      ...sampleRunRequest().enforcement,
      filesystem: {
        read: [workspace],
        write: [workspace],
      },
    },
  };

  try {
    const result = spawnSync(cliPath, ["prepare-run"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH ?? ""}`,
      },
      input: JSON.stringify(request),
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as PrepareRunResponse;
    assert.equal(response.ok, false);
    assert.equal(response.policyDecision?.path, externalFile);
    assert.deepEqual(response.policyDecision?.required, ["write"]);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
    rmSync(externalRoot, { recursive: true, force: true });
    rmSync(fakeBinDir, { recursive: true, force: true });
  }
});

test("prepare-run accepts external write after write policy grant", () => {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-write-grant-workspace-"));
  const externalRoot = mkdtempSync(join(tmpdir(), "raxcell-write-grant-external-"));
  const externalFile = join(externalRoot, "helloRax.txt");
  const fakeBinDir = mkdtempSync(join(tmpdir(), "raxcell-fake-bin-"));
  const fakeBwrap = join(fakeBinDir, "bwrap");
  writeFileSync(fakeBwrap, "#!/bin/sh\nexit 0\n");
  chmodSync(fakeBwrap, 0o755);
  const request: RunRequest = {
    ...sampleRunRequest(),
    policyGrants: [
      {
        reason: "human-approved-write",
        path: externalFile,
        access: ["write"],
        grantedBy: "praxis-policy",
      },
    ],
    command: {
      argv: ["/bin/sh", "-lc", `printf hello > ${externalFile}`],
      cwd: workspace,
      env: {},
      stdin: null,
    },
    enforcement: {
      ...sampleRunRequest().enforcement,
      filesystem: {
        read: [workspace],
        write: [workspace],
      },
    },
  };

  try {
    const result = spawnSync(cliPath, ["prepare-run"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH ?? ""}`,
      },
      input: JSON.stringify(request),
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as PrepareRunResponse;
    assert.equal(response.ok, true);
    assert.equal(response.policyDecision, null);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
    rmSync(externalRoot, { recursive: true, force: true });
    rmSync(fakeBinDir, { recursive: true, force: true });
  }
});

test("prepare-run accepts external read after read policy grant", () => {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-read-grant-workspace-"));
  const externalRoot = mkdtempSync(join(tmpdir(), "raxcell-read-grant-external-"));
  const externalFile = join(externalRoot, "helloRax.txt");
  writeFileSync(externalFile, "hello");
  const fakeBinDir = mkdtempSync(join(tmpdir(), "raxcell-fake-bin-"));
  const fakeBwrap = join(fakeBinDir, "bwrap");
  writeFileSync(fakeBwrap, "#!/bin/sh\nexit 0\n");
  chmodSync(fakeBwrap, 0o755);
  const request: RunRequest = {
    ...sampleRunRequest(),
    policyGrants: [
      {
        reason: "human-approved-read",
        path: externalFile,
        access: ["read"],
        grantedBy: "praxis-policy",
      },
    ],
    command: {
      argv: ["/bin/sh", "-lc", `cat ${externalFile}`],
      cwd: workspace,
      env: {},
      stdin: null,
    },
    enforcement: {
      ...sampleRunRequest().enforcement,
      filesystem: {
        read: [workspace],
        write: [workspace],
      },
    },
  };

  try {
    const result = spawnSync(cliPath, ["prepare-run"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH ?? ""}`,
      },
      input: JSON.stringify(request),
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as PrepareRunResponse;
    assert.equal(response.ok, true);
    assert.equal(response.policyDecision, null);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
    rmSync(externalRoot, { recursive: true, force: true });
    rmSync(fakeBinDir, { recursive: true, force: true });
  }
});

test("prepare-run reports dynamic shell paths as environment gap", () => {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-dynamic-gap-workspace-"));
  const fakeBinDir = mkdtempSync(join(tmpdir(), "raxcell-fake-bin-"));
  const fakeBwrap = join(fakeBinDir, "bwrap");
  writeFileSync(fakeBwrap, "#!/bin/sh\nexit 0\n");
  chmodSync(fakeBwrap, 0o755);
  const request: RunRequest = {
    ...sampleRunRequest(),
    command: {
      argv: ["/bin/sh", "-lc", "printf hello > $HOME/helloRax.txt"],
      cwd: workspace,
      env: {
        HOME: "/home/proview",
      },
      stdin: null,
    },
    enforcement: {
      ...sampleRunRequest().enforcement,
      filesystem: {
        read: [workspace],
        write: [workspace],
      },
    },
  };

  try {
    const result = spawnSync(cliPath, ["prepare-run"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH ?? ""}`,
      },
      input: JSON.stringify(request),
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as PrepareRunResponse;
    assert.equal(response.ok, false);
    assert.equal(response.policyDecision, null);
    assert.equal(response.environmentGap?.reason, "shell-dynamic-path-unresolved");
    assert.deepEqual(response.environmentGap?.required, ["write"]);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
    rmSync(fakeBinDir, { recursive: true, force: true });
  }
});

test("prepare-run only treats backend-specific runtime paths as runtime roots", () => {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-runtime-backend-workspace-"));
  const fakeBinDir = mkdtempSync(join(tmpdir(), "raxcell-fake-bin-"));
  const fakeBwrap = join(fakeBinDir, "bwrap");
  writeFileSync(fakeBwrap, "#!/bin/sh\nexit 0\n");
  chmodSync(fakeBwrap, 0o755);
  const request: RunRequest = {
    ...sampleRunRequest(),
    backendPreference: ["linux-bubblewrap"],
    command: {
      argv: ["/bin/sh", "-lc", "cat /System/raxcell.txt"],
      cwd: workspace,
      env: {},
      stdin: null,
    },
    enforcement: {
      ...sampleRunRequest().enforcement,
      filesystem: {
        read: [workspace],
      },
    },
  };

  try {
    const result = spawnSync(cliPath, ["prepare-run"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH ?? ""}`,
      },
      input: JSON.stringify(request),
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as PrepareRunResponse;
    assert.equal(response.ok, false);
    assert.equal(response.policyDecision?.reason, "path-outside-declared-roots");
    assert.equal(response.policyDecision?.path, "/System/raxcell.txt");
    assert.deepEqual(response.policyDecision?.required, ["read"]);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
    rmSync(fakeBinDir, { recursive: true, force: true });
  }
});

test(
  "run with write grant writes external absolute path to the host",
  { skip: !hasBwrap },
  () => {
    const workspace = mkdtempSync(join(tmpdir(), "raxcell-host-write-workspace-"));
    const externalRoot = mkdtempSync(join(tmpdir(), "raxcell-host-write-external-"));
    const externalFile = join(externalRoot, "helloRax.txt");
    const request: RunRequest = {
      ...sampleRunRequest(),
      policyGrants: [
        {
          reason: "human-approved-write",
          path: externalFile,
          access: ["write"],
          grantedBy: "praxis-policy",
        },
      ],
      command: {
        argv: [
          "/bin/sh",
          "-lc",
          [
            `printf '%s\\n' 'helloRax!I love raxode!' > ${externalFile}`,
            `cat ${externalFile}`,
            "python3 - <<'PY'",
            "from pathlib import Path",
            `p = Path('${externalFile}')`,
            "s = p.read_text()",
            "p.write_text(s.replace('raxode', 'praxis'))",
            "PY",
          ].join("\n"),
        ],
        cwd: workspace,
        env: {},
        stdin: null,
      },
      enforcement: {
        ...sampleRunRequest().enforcement,
        filesystem: {
          read: [workspace],
          write: [workspace],
        },
      },
    };

    try {
      const result = spawnSync(cliPath, ["run"], {
        encoding: "utf8",
        input: JSON.stringify(request),
      });
      assert.equal(result.status, 0, result.stderr);
      const response = JSON.parse(result.stdout) as RunResponse;
      assert.equal(response.ok, true);
      assert.equal(response.exitCode, 0);
      assert.match(readFileSync(externalFile, "utf8"), /praxis/);
    } finally {
      rmSync(workspace, { recursive: true, force: true });
      rmSync(externalRoot, { recursive: true, force: true });
    }
  },
);

test("prepare-run for unattached native backend returns environment facts and planned artifact", () => {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-native-prepare-workspace-"));
  const request: RunRequest = {
    ...sampleRunRequest(),
    backendPreference: ["windows-native"],
    command: {
      argv: ["/bin/sh", "-lc", "printf hello > created.txt"],
      cwd: workspace,
      env: {},
      stdin: null,
    },
    enforcement: {
      ...sampleRunRequest().enforcement,
      filesystem: {
        read: [workspace],
        write: [workspace],
      },
    },
  };

  try {
    const result = spawnSync(cliPath, ["prepare-run"], {
      encoding: "utf8",
      input: JSON.stringify(request),
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as PrepareRunResponse;
    assert.equal(response.ok, false);
    assert.equal(response.backend, "windows-native");
    assert.equal(response.policyDecision, null);
    assert.equal(response.environmentGap?.reason, "host-platform-mismatch");
    assert.deepEqual(response.filesystemLowering?.runtimeRoots, []);
    assert.ok(response.filesystemLowering?.effects?.some((effect) => effect.rawToken === "created.txt"));
    assert.equal(response.backendArtifacts[0].format, "windows-native-token-acl-plan");
    assert.equal(response.backendArtifacts[0].warnings[0].code, "NATIVE_BACKEND_HOST_PLATFORM_MISMATCH");
    assert.equal(response.backendArtifacts[0].data.attached, false);
    assert.equal(response.backendArtifacts[0].data.runnerProtocol, "raxcell.windowsRunner.run.v1");
    assert.equal(response.backendArtifacts[0].data.commandEnvMode, "clean");
    assert.equal(response.backendArtifacts[0].data.writeGrantMaterialization, "runner-owned");
    assert.deepEqual(response.backendArtifacts[0].data.commandEnv, {
      PATH: DEFAULT_COMMAND_PATH,
    });
    assert.equal(response.backendArtifacts[0].data.tokenMode, "writable-roots-capability");
    assert.equal(response.backendArtifacts[0].data.networkBlocked, true);
    assert.equal(response.backendArtifacts[0].data.networkMode, "deny");
    assert.equal(response.backendArtifacts[0].data.timeoutMs, 1000);
    assert.deepEqual(response.backendArtifacts[0].data.aclRoots, [
      {
        path: workspace,
        access: "write",
        source: "declared",
      },
    ]);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});

test("prepare-run for windows-native preserves Windows path facts on non-Windows hosts", () => {
  const request: RunRequest = {
    ...sampleRunRequest(),
    backendPreference: ["windows-native"],
    command: {
      argv: ["cmd.exe", "/c", "type C:\\workspace\\input.txt > C:\\workspace\\output.txt"],
      cwd: "C:\\workspace",
      env: {},
      stdin: null,
    },
    enforcement: {
      ...sampleRunRequest().enforcement,
      filesystem: {
        read: ["C:\\workspace"],
        write: ["C:\\workspace"],
      },
    },
  };

  const result = spawnSync(cliPath, ["prepare-run"], {
    encoding: "utf8",
    input: JSON.stringify(request),
  });
  assert.equal(result.status, 0, result.stderr);
  const response = JSON.parse(result.stdout) as PrepareRunResponse;
  const artifact = response.backendArtifacts[0];

  assert.equal(response.ok, false);
  assert.equal(response.backend, "windows-native");
  assert.equal(response.environmentGap?.reason, "host-platform-mismatch");
  assert.deepEqual(artifact.data.aclRoots, [
    {
      path: "C:\\workspace",
      access: "write",
      source: "declared",
    },
  ]);
  assert.equal(artifact.data.normalizedCwd, "C:\\workspace");
  assert.equal(artifact.data.writeGrantMaterialization, "runner-owned");
  assert.ok(response.filesystemLowering?.effects?.some((effect) => {
    return effect.path === "C:\\workspace\\input.txt" && effect.access === "read";
  }));
  assert.ok(response.filesystemLowering?.effects?.some((effect) => {
    return effect.path === "C:\\workspace\\output.txt" && effect.access === "write";
  }));
});

test("prepare-run for macos-seatbelt exposes planned SBPL profile artifact", () => {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-macos-prepare-workspace-"));
  const request: RunRequest = {
    ...sampleRunRequest(),
    backendPreference: ["macos-seatbelt"],
    command: {
      argv: ["/bin/sh", "-lc", "cat file.txt"],
      cwd: workspace,
      env: {},
      stdin: null,
    },
    enforcement: {
      ...sampleRunRequest().enforcement,
      filesystem: {
        read: [workspace],
      },
      network: "deny",
    },
  };

  try {
    const result = spawnSync(cliPath, ["prepare-run"], {
      encoding: "utf8",
      input: JSON.stringify(request),
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as PrepareRunResponse;
    const artifact = response.backendArtifacts[0];
    assert.equal(response.ok, false);
    assert.equal(response.backend, "macos-seatbelt");
    assert.equal(response.environmentGap?.reason, "host-platform-mismatch");
    assert.equal(artifact.format, "macos-seatbelt-sbpl-profile");
    assert.equal(artifact.arguments[0], "/usr/bin/sandbox-exec");
    assert.equal(artifact.data.writeGrantMaterialization, "raxcell-precreate");
    assert.match(String(artifact.data.profile), /\(deny default\)/);
    assert.match(String(artifact.data.profile), /\(deny network\*\)/);
    assert.equal(artifact.data.networkMode, "deny");
    assert.match(String(artifact.data.profile), /\(allow file-read\* \(literal "\/usr"\) \(subpath "\/usr"\)\)/);
    assert.deepEqual(artifact.data.readRoots, [workspace]);
    assert.deepEqual(artifact.data.writeRoots, []);
    assert.ok(response.filesystemLowering?.runtimeRoots.some((root) => root.path === "/usr"));
    assert.ok(response.filesystemLowering?.runtimeRoots.some((root) => root.path === "/System"));
    assert.ok(Array.isArray(artifact.data.runtimeRoots));
    assert.ok((artifact.data.runtimeRoots as unknown[]).some((root) => {
      return typeof root === "object" && root !== null && "path" in root && root.path === "/usr";
    }));
    assert.equal(artifact.data.commandEnvMode, "clean");
    assert.deepEqual(artifact.data.commandEnv, {
      PATH: DEFAULT_COMMAND_PATH,
    });
    assert.equal(artifact.data.timeoutMs, 1000);
    assert.deepEqual(artifact.data.processLimits, {
      spawn: true,
    });
    assert.deepEqual(artifact.data.resourceLimits, {
      timeoutMs: 1000,
    });
    assert.equal(artifact.warnings[0].code, "NATIVE_BACKEND_HOST_PLATFORM_MISMATCH");
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});

test("prepare-run for macos-seatbelt emits literal filters for granted file roots", () => {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-macos-file-grant-workspace-"));
  const externalRoot = mkdtempSync(join(tmpdir(), "raxcell-macos-file-grant-external-"));
  const externalFile = join(externalRoot, "helloRax.txt");
  const request: RunRequest = {
    ...sampleRunRequest(),
    backendPreference: ["macos-seatbelt"],
    policyGrants: [
      {
        reason: "human-approved-write",
        path: externalFile,
        access: ["write"],
        grantedBy: "praxis-policy",
      },
    ],
    command: {
      argv: ["/bin/sh", "-lc", `printf hello > ${externalFile}`],
      cwd: workspace,
      env: {},
      stdin: null,
    },
    enforcement: {
      ...sampleRunRequest().enforcement,
      filesystem: {
        read: [workspace],
        write: [workspace],
      },
      network: "deny",
    },
  };

  try {
    const result = spawnSync(cliPath, ["prepare-run"], {
      encoding: "utf8",
      input: JSON.stringify(request),
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as PrepareRunResponse;
    const profile = String(response.backendArtifacts[0].data.profile);
    assert.match(profile, new RegExp(`\\(allow file-read\\* \\(literal ${escapeRegExp(JSON.stringify(externalFile))}\\)`));
    assert.match(profile, new RegExp(`\\(allow file-write\\* \\(literal ${escapeRegExp(JSON.stringify(externalFile))}\\)`));
    assert.ok(response.filesystemLowering?.declaredRoots.some((root) => {
      return root.path === externalFile && root.access === "write" && root.source === "policy-grant";
    }));
    assert.ok((response.backendArtifacts[0].data.rootRules as unknown[]).some((root) => {
      return typeof root === "object" &&
        root !== null &&
        "path" in root &&
        "access" in root &&
        "source" in root &&
        root.path === workspace &&
        root.access === "write" &&
        root.source === "declared";
    }));
    assert.ok((response.backendArtifacts[0].data.rootRules as unknown[]).some((root) => {
      return typeof root === "object" &&
        root !== null &&
        "path" in root &&
        "access" in root &&
        "source" in root &&
        root.path === externalFile &&
        root.access === "write" &&
        root.source === "policy-grant";
    }));
  } finally {
    rmSync(workspace, { recursive: true, force: true });
    rmSync(externalRoot, { recursive: true, force: true });
  }
});

test("run for unattached native backend fails at provider level without child exit code", () => {
  const workspace = mkdtempSync(join(tmpdir(), "raxcell-native-run-workspace-"));
  const request: RunRequest = {
    ...sampleRunRequest(),
    backendPreference: ["macos-seatbelt"],
    command: {
      argv: ["/bin/sh", "-lc", "exit 7"],
      cwd: workspace,
      env: {},
      stdin: null,
    },
    enforcement: {
      ...sampleRunRequest().enforcement,
      filesystem: {
        read: [workspace],
        write: [workspace],
      },
    },
  };

  try {
    const result = spawnSync(cliPath, ["run"], {
      encoding: "utf8",
      input: JSON.stringify(request),
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout) as RunResponse;
    assert.equal(response.ok, false);
    assert.equal(response.backend, "macos-seatbelt");
    assert.equal(response.exitCode, null);
    assert.equal(response.environmentGap?.reason, "host-platform-mismatch");
    assert.equal(response.policyDecision, null);
    assert.equal(response.backendArtifacts?.[0].format, "macos-seatbelt-sbpl-profile");
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});

test("probe request type accepts all first-class backend families", () => {
  const request: ProbeRequest = {
    kind: "raxcell.probe.v1",
    platform: "auto",
    backendPreference: [
      "linux-bubblewrap",
      "macos-seatbelt",
      "windows-elevated",
      "windows-unelevated",
    ],
  };
  assert.equal(request.backendPreference?.length, 4);
});

function sampleRunRequest(): RunRequest {
  return {
    kind: "raxcell.run.v1",
    backendPreference: ["linux-bubblewrap"],
    policyGrants: [],
    action: {
      actionId: "act-1",
      ownerRuntime: "example",
      intentLabel: "opaque",
      metadata: {},
    },
    command: {
      argv: ["/usr/bin/printf", "hello"],
      cwd: ".",
      env: {},
      stdin: null,
    },
    enforcement: {
      profile: "workspace-write-no-network",
      filesystem: {
        read: ["/tmp"],
        write: ["/tmp"],
      },
      network: "deny",
      process: {
        spawn: true,
      },
      resources: {
        timeoutMs: 1000,
      },
    },
    fallback: {
      mode: "none",
    },
  };
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function createFakeRustCli(
  responses: Record<string, unknown>,
): { path: string; cleanup: () => void } {
  const root = mkdtempSync(join(tmpdir(), "raxcell-fake-rust-cli-"));
  const path = join(root, "raxcell-rust-cli.js");
  writeFileSync(path, [
    "#!/usr/bin/env node",
    `const responses = ${JSON.stringify(responses)};`,
    "const response = responses[process.argv[2]];",
    "process.stderr.write('rust worker debug\\n');",
    "if (!response) {",
    "  process.stderr.write(`unsupported command ${process.argv[2]}\\n`);",
    "  process.exit(2);",
    "}",
    "process.stdout.write(`${JSON.stringify(response)}\\n`);",
    "",
  ].join("\n"));
  chmodSync(path, 0o755);
  return {
    path,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

test("explain backend response type exposes operation schema", () => {
  const response: ExplainBackendResponse = {
    kind: "raxcell.explainBackendResult.v1",
    selectedBackend: "linux-bubblewrap",
    probe: {
      kind: "raxcell.probeResult.v1",
      ready: true,
      selectedBackend: "linux-bubblewrap",
      supports: {},
      limits: [],
      weaknesses: [],
      missing: [],
      nextActions: [],
      publicSafeMessage: "ready",
    },
    operations: [
      {
        method: "prepareRun",
        inputKind: "raxcell.run.v1",
        outputKind: "raxcell.prepareRunResult.v1",
        sideEffects: ["no-process-spawn"],
      },
    ],
    explanation: {
      backend: "linux-bubblewrap",
      hostPlatforms: ["linux"],
      isolationPrimitives: ["bubblewrap.bind-mounts"],
      runtimeRoots: [],
      limits: [],
      publicSafeMessage: "ready",
    },
  };
  assert.equal(response.operations[0].method, "prepareRun");
});

test("policy pack and resolve request types expose the protocol surface", () => {
  const pack: PolicyPack = {
    kind: "raxcell.policyPack.v1",
    name: "workspace",
    profiles: {
      "workspace-write-no-network": {
        preset: "workspace-write",
        filesystem: {
          read: ["$workspace"],
          write: ["$workspace"],
        },
        network: "deny",
        backendPreference: ["linux-bubblewrap"],
      },
    },
  };
  const request: ResolveProfileRequest = {
    kind: "raxcell.resolveProfile.v1",
    packPaths: ["raxcell/fixtures/policy.workspace.json"],
    profile: "workspace-write-no-network",
    variables: {
      workspace: "/workspace/project",
      home: "/home/agent",
      tmp: "/tmp/raxcell",
    },
  };
  assert.equal(pack.profiles?.["workspace-write-no-network"].preset, "workspace-write");
  assert.equal(request.variables?.workspace, "/workspace/project");
});

test("run request type exposes explicit policy grants", () => {
  const request: RunRequest = {
    kind: "raxcell.run.v1",
    backendPreference: ["linux-bubblewrap"],
    policyGrants: [
      {
        reason: "cwd-outside-declared-roots",
        path: ".",
        access: ["read"],
        grantedBy: "upper-runtime",
      },
    ],
    action: {
      actionId: "act-1",
      ownerRuntime: "example",
      intentLabel: "opaque",
      metadata: {},
    },
    command: {
      argv: ["/usr/bin/printf", "hello"],
      cwd: ".",
      env: {},
      stdin: null,
    },
    enforcement: {
      profile: "workspace-write-no-network",
      filesystem: {
        read: ["/tmp"],
        write: ["/tmp"],
      },
      network: "deny",
      process: {
        spawn: true,
      },
      resources: {
        timeoutMs: 1000,
      },
    },
    fallback: {
      mode: "none",
    },
  };
  assert.equal(request.policyGrants?.[0].reason, "cwd-outside-declared-roots");
});

test("windows runner request type exposes native runner protocol surface", () => {
  const request: WindowsRunnerRunRequest = {
    kind: "raxcell.windowsRunner.run.v1",
    backend: "windows-native",
    command: {
      argv: ["cmd.exe", "/c", "echo hello"],
      cwd: "C:\\workspace",
      env: {
        PATH: DEFAULT_COMMAND_PATH,
      },
      stdin: null,
    },
    normalizedCwd: "C:\\workspace",
    commandEnvMode: "clean",
    writeGrantMaterialization: "runner-owned",
    enforcement: {
      profile: "workspace-write",
      filesystem: {
        read: ["C:\\workspace"],
        write: ["C:\\workspace"],
      },
      network: "deny",
      process: {},
      resources: {
        timeoutMs: 1000,
      },
    },
    timeoutMs: 1000,
    action: {
      actionId: "windows-runner-type",
      ownerRuntime: "praxis",
      intentLabel: "type-test",
      metadata: {},
    },
    filesystemLowering: {
      declaredRoots: [
        {
          path: "C:\\workspace",
          access: "write",
          source: "declared",
        },
      ],
      runtimeRoots: [],
      policyGrants: [],
      warnings: [],
    },
    tokenMode: "writable-roots-capability",
    aclRoots: [
      {
        path: "C:\\workspace",
        access: "write",
        source: "declared",
      },
    ],
    networkBlocked: true,
    networkMode: "deny",
  };

  assert.equal(request.kind, "raxcell.windowsRunner.run.v1");
  assert.equal(request.commandEnvMode, "clean");
  assert.equal(request.command.env.PATH, DEFAULT_COMMAND_PATH);
  assert.equal(request.networkMode, "deny");
});

test("run response type exposes filesystem lowering report", () => {
  const response: RunResponse = {
    kind: "raxcell.runResult.v1",
    ok: true,
    backend: "linux-bubblewrap",
    exitCode: 0,
    stdout: "",
    stderr: "",
    timedOut: false,
    denial: null,
    policyDecision: null,
    filesystemLowering: {
      declaredRoots: [
        { path: "/workspace", access: "read", source: "declared" },
      ],
      runtimeRoots: [
        { path: "/usr", access: "read", source: "backend-runtime" },
      ],
      policyGrants: [],
      warnings: [],
    },
    fallback: null,
    capabilityReport: null,
    backendArtifacts: [
      {
        backend: "linux-bubblewrap",
        format: "linux-bubblewrap-argv",
        arguments: ["bwrap", "--"],
        data: {
          executable: "bwrap",
        },
        warnings: [],
      },
    ],
  };
  assert.equal(response.filesystemLowering?.runtimeRoots[0].path, "/usr");
  assert.equal(response.backendArtifacts?.[0].format, "linux-bubblewrap-argv");
});

test("prepare run response type exposes dry-run lowering result", () => {
  const response: PrepareRunResponse = {
    kind: "raxcell.prepareRunResult.v1",
    ok: true,
    backend: "linux-bubblewrap",
    denial: null,
    policyDecision: null,
    filesystemLowering: {
      declaredRoots: [
        { path: "/workspace", access: "write", source: "declared" },
      ],
      runtimeRoots: [],
      policyGrants: [],
      warnings: [],
    },
    backendArtifacts: [
      {
        backend: "linux-bubblewrap",
        format: "linux-bubblewrap-argv",
        arguments: ["--die-with-parent"],
        data: { executable: "/usr/bin/bwrap" },
        warnings: [],
      },
    ],
    capabilityReport: null,
  };
  assert.equal(response.filesystemLowering?.declaredRoots[0].access, "write");
  assert.equal(response.backendArtifacts[0].format, "linux-bubblewrap-argv");
});
