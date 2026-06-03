import assert from "node:assert/strict";
import test from "node:test";
import type {
  ExplainBackendResponse,
  PolicyPack,
  PrepareRunResponse,
  ProbeRequest,
  ResolveProfileRequest,
  RunRequest,
  RunResponse,
} from "./types.js";

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
  };
  assert.equal(response.filesystemLowering?.runtimeRoots[0].path, "/usr");
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
