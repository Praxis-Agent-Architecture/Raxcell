# Praxis TypeScript Middleware Integration For Raxcell 0.1.1

## Purpose

This document is the handoff guide for wiring Praxis to Raxcell.

Raxcell should be treated as a sandbox enforcement dependency, not as a Praxis policy engine. Praxis owns intent, tool semantics, approval, session state, and audit policy. Raxcell owns backend capability facts, platform lowering, fail-closed execution, and sandbox result reporting.

The first production target should be Linux. WSL can reuse the Linux path. macOS and native Windows should be added later with the same TypeScript port and Praxis middleware shape.

## Current Published Package

Install in Praxis:

```bash
pnpm add @praxis-ai/raxcell@0.1.1
```

Published package:

```text
@praxis-ai/raxcell@0.1.1
```

Runtime entrypoint:

```ts
import { RaxcellClient } from "@praxis-ai/raxcell";
```

`0.1.1` contains the TypeScript client, protocol types, and a `raxcell` Node CLI with a Linux bubblewrap runner. Praxis can set `RAXCELL_BIN` to the installed `raxcell` bin or to a development build artifact such as `raxcell/sdk/dist/cli.js`.

## Integration Model

Use this mental model:

```text
Praxis Agent / Harness
  -> Praxis tool execution request
  -> Praxis sandbox policy middleware
  -> Raxcell prepareRun
  -> Praxis grant / deny / rewrite / human approval
  -> Raxcell run
  -> Praxis event log and session audit
```

`prepareRun` is the main control-plane hook. It lowers a command into backend facts without spawning the command. Praxis should inspect its result before calling `run`.

## Recommended Praxis Module Boundary

Create a narrow Praxis adapter module rather than spreading Raxcell calls through tools.

Suggested location in Praxis:

```text
src/runtime/sandbox/
  sandbox-port.ts
  raxcell-sandbox-port.ts
  raxcell-policy-middleware.ts
  raxcell-request-mapper.ts
  raxcell-audit.ts
```

Suggested responsibilities:

| Module | Responsibility |
| --- | --- |
| `sandbox-port.ts` | Praxis-owned interface for sandbox execution. |
| `raxcell-sandbox-port.ts` | Thin `RaxcellClient` wrapper. |
| `raxcell-request-mapper.ts` | Convert Praxis tool/session/workspace facts to `RunRequest`. |
| `raxcell-policy-middleware.ts` | Call `prepareRun`, map decisions, call `run`. |
| `raxcell-audit.ts` | Persist normalized prepare/run/lowering events. |

Do not let individual tools instantiate `RaxcellClient`. Tools should ask the runtime for sandboxed execution.

## Praxis Sandbox Port

Define a Praxis-owned port so the runtime can swap Raxcell, mocks, or future sandboxes.

```ts
import type {
  ExplainBackendRequest,
  ExplainBackendResponse,
  PrepareRunResponse,
  ProbeRequest,
  ProbeResponse,
  ResolveProfileRequest,
  ResolvedProfileResponse,
  RunRequest,
  RunResponse,
} from "@praxis-ai/raxcell";

export type SandboxExecutionPort = {
  probe(request: ProbeRequest): Promise<ProbeResponse>;
  explainBackend(request: ExplainBackendRequest): Promise<ExplainBackendResponse>;
  resolveProfile(request: ResolveProfileRequest): Promise<ResolvedProfileResponse>;
  prepareRun(request: RunRequest): Promise<PrepareRunResponse>;
  run(request: RunRequest): Promise<RunResponse>;
};
```

Raxcell implementation:

```ts
import { RaxcellClient } from "@praxis-ai/raxcell";
import type { SandboxExecutionPort } from "./sandbox-port";

export function createRaxcellSandboxPort(input: {
  binaryPath: string;
}): SandboxExecutionPort {
  return new RaxcellClient({
    binaryPath: input.binaryPath,
  });
}
```

## CLI Binary Path Strategy

For `0.1.1`, Praxis should resolve the CLI path from runtime config.

Recommended config:

```ts
export type PraxisSandboxConfig = {
  provider: "raxcell";
  raxcell: {
    binaryPath: string;
    backendPreference: Array<"linux-bubblewrap" | "macos-seatbelt" | "windows-native">;
    defaultProfile: "workspace-write-no-network" | "read-only-no-network" | string;
  };
};
```

Recommended resolution order:

1. Explicit Praxis config field: `sandbox.raxcell.binaryPath`
2. Environment override: `RAXCELL_BIN`
3. Development fallback: local repository binary path
4. Fail closed with a clear runtime error

Do not silently fall back to unsandboxed execution if the binary is missing.

## Startup Probe

Run `probe` when Praxis starts a runtime session, or before the first sandboxed tool call.

```ts
const probe = await sandbox.probe({
  kind: "raxcell.probe.v1",
  platform: "auto",
  backendPreference: ["linux-bubblewrap"],
});

if (!probe.ready) {
  throw new Error(probe.publicSafeMessage);
}
```

Persist the probe result in session diagnostics. It is useful for explaining why a sandboxed tool is unavailable on a host.

Expected Linux goal:

```text
ready = true
selected backend = linux-bubblewrap
```

If Linux is not ready, Praxis should mark shell-like tools unavailable or degraded. It should not run them unsandboxed as a hidden fallback.

## Backend Explanation Cache

Call `explainBackend` once per runtime session and cache the result.

```ts
const explanation = await sandbox.explainBackend({
  kind: "raxcell.explainBackend.v1",
  platform: "auto",
  backendPreference: ["linux-bubblewrap"],
});
```

Use this for:

- Praxis control panel capability display;
- debugging failed policy matches;
- audit metadata;
- future platform routing;
- operator-readable sandbox diagnostics.

Important semantic difference:

| Method | Spawns command? | Intended Praxis use |
| --- | --- | --- |
| `probe` | No | Host readiness. |
| `explainBackend` | No | Capability/control-plane metadata. |
| `resolveProfile` | No | Policy pack/profile preview. |
| `prepareRun` | No | Pre-execution policy decision point. |
| `run` | Yes | Actual sandboxed command execution. |

## Mapping Praxis Tool Calls To RunRequest

Praxis should convert every execution-bearing tool call into one `RunRequest`.

Example mapper for shell-like tools:

```ts
import type { RunRequest } from "@praxis-ai/raxcell";

export type PraxisSandboxedCommand = {
  actionId: string;
  sessionId: string;
  toolId: string;
  argv: string[];
  cwd: string;
  env?: Record<string, string>;
  stdin?: string | null;
  workspaceRoot: string;
  readRoots: string[];
  writeRoots: string[];
  network: "allow" | "deny";
  timeoutMs: number;
};

export function toRaxcellRunRequest(input: PraxisSandboxedCommand): RunRequest {
  return {
    kind: "raxcell.run.v1",
    backendPreference: ["linux-bubblewrap"],
    policyGrants: [],
    action: {
      actionId: input.actionId,
      ownerRuntime: "praxis",
      intentLabel: "shell command",
      metadata: {
        sessionId: input.sessionId,
        toolId: input.toolId,
        workspaceRoot: input.workspaceRoot,
      },
    },
    command: {
      argv: input.argv,
      cwd: input.cwd,
      env: input.env ?? {},
      stdin: input.stdin ?? null,
    },
    enforcement: {
      profile: input.network === "deny"
        ? "workspace-write-no-network"
        : "workspace-write-network",
      filesystem: {
        read: input.readRoots,
        write: input.writeRoots,
      },
      network: input.network,
      process: {
        spawn: true,
      },
      resources: {
        timeoutMs: input.timeoutMs,
      },
    },
    fallback: {
      mode: "none",
    },
  };
}
```

Recommended Praxis defaults:

| Praxis situation | Raxcell mapping |
| --- | --- |
| Normal workspace command | read workspace, write workspace or scoped output dirs. |
| Read-only inspection | read workspace, write empty or temp-only. |
| Dependency install | write workspace and package caches only if Praxis policy allows. |
| Network disabled session | `network: "deny"`. |
| Network allowed session | `network: "allow"` only after Praxis policy allows it. |
| Unknown cwd | call `prepareRun` and expect possible policy decision. |

## Middleware Algorithm

The middleware should always call `prepareRun` before `run`.

```ts
import type {
  PolicyGrant,
  PrepareRunResponse,
  RunRequest,
  RunResponse,
} from "@praxis-ai/raxcell";

export type PraxisSandboxDecision =
  | { type: "allow" }
  | { type: "grant"; grants: PolicyGrant[] }
  | { type: "deny"; reason: string }
  | { type: "rewrite"; request: RunRequest; reason: string };

export async function runWithPraxisSandboxPolicy(input: {
  sandbox: SandboxExecutionPort;
  request: RunRequest;
  decide: (ctx: {
    request: RunRequest;
    prepared: PrepareRunResponse;
  }) => Promise<PraxisSandboxDecision>;
  audit: (event: unknown) => Promise<void>;
}): Promise<RunResponse> {
  let request = input.request;
  let prepared = await input.sandbox.prepareRun(request);

  await input.audit({
    type: "praxis.sandbox.prepareRun",
    actionId: request.action.actionId,
    prepared,
  });

  if (prepared.policyDecision) {
    const decision = await input.decide({ request, prepared });

    if (decision.type === "deny") {
      await input.audit({
        type: "praxis.sandbox.denied",
        actionId: request.action.actionId,
        reason: decision.reason,
        policyDecision: prepared.policyDecision,
      });
      throw new Error(decision.reason);
    }

    if (decision.type === "rewrite") {
      request = decision.request;
      prepared = await input.sandbox.prepareRun(request);
      await input.audit({
        type: "praxis.sandbox.prepareRun.afterRewrite",
        actionId: request.action.actionId,
        reason: decision.reason,
        prepared,
      });
    }

    if (decision.type === "grant") {
      request = {
        ...request,
        policyGrants: [
          ...(request.policyGrants ?? []),
          ...decision.grants,
        ],
      };
      prepared = await input.sandbox.prepareRun(request);
      await input.audit({
        type: "praxis.sandbox.prepareRun.afterGrant",
        actionId: request.action.actionId,
        grants: decision.grants,
        prepared,
      });
    }
  }

  if (!prepared.ok) {
    await input.audit({
      type: "praxis.sandbox.prepareRun.failed",
      actionId: request.action.actionId,
      denial: prepared.denial,
    });
    throw new Error(prepared.denial?.message ?? "Raxcell prepareRun failed");
  }

  const result = await input.sandbox.run(request);

  await input.audit({
    type: "praxis.sandbox.run",
    actionId: request.action.actionId,
    result,
  });

  return result;
}
```

Important rule: after a grant or rewrite, call `prepareRun` again. Praxis should never assume that a policy decision is resolved until Raxcell returns `ok: true`.

## Policy Decision Mapping

Current known policy decision reason:

```text
cwd-outside-declared-roots
```

Meaning: the command cwd is not covered by declared read/write roots. Raxcell refuses to infer that cwd should be mounted.

Recommended Praxis handling:

```ts
import type { PolicyGrant, PrepareRunResponse } from "@praxis-ai/raxcell";

export function grantCwdIfPraxisPolicyAllows(
  prepared: PrepareRunResponse,
  access: "read" | "write",
): PolicyGrant | null {
  if (prepared.policyDecision?.reason !== "cwd-outside-declared-roots") {
    return null;
  }

  return {
    reason: "cwd-outside-declared-roots",
    path: prepared.policyDecision.path,
    access: [access],
    grantedBy: "praxis-policy",
  };
}
```

Praxis should grant `write` only when its own tool/session/workspace policy permits mutation in that path. Otherwise grant `read`, rewrite cwd, or deny.

Recommended choices:

| Situation | Praxis response |
| --- | --- |
| cwd is inside trusted workspace but omitted by mapper | grant read or write, then fix mapper later. |
| cwd is a parent of workspace | usually deny or rewrite cwd to workspace. |
| cwd is `/tmp` for build tool | grant temp write if session policy allows. |
| cwd is user home | deny unless explicit human approval exists. |
| cwd is system path | deny. |

## Filesystem Lowering Report

`prepareRun` and `run` can return a filesystem lowering report. Praxis should persist it because it is the best explanation of what was actually enforced.

Expect fields representing:

- declared read roots;
- declared write roots;
- runtime roots added by Raxcell;
- roots dropped because another mount already covers them;
- warnings or backend-specific caveats.

Praxis should surface this in debug/audit views, not in normal user chat.

## Backend Artifacts

For Linux, `prepareRun` includes a backend artifact like:

```ts
{
  backend: "linux-bubblewrap",
  format: "linux-bubblewrap-argv",
  arguments: ["bwrap", "..."],
  data: {
    executable: "/usr/bin/bwrap"
  },
  warnings: []
}
```

Use cases:

- pre-execution audit;
- reproducing sandbox failures;
- comparing Praxis policy expectation with actual backend argv;
- writing Linux integration tests.

Do not show raw backend argv to the model by default. It can include local paths and operational details. Store it in bounded audit/event storage.

## Audit Event Contract

Praxis should persist three event families:

```ts
type PraxisRaxcellPrepareEvent = {
  type: "praxis.sandbox.prepareRun";
  actionId: string;
  sessionId: string;
  toolId: string;
  backendPreference: string[];
  command: {
    argv: string[];
    cwd: string;
  };
  enforcement: unknown;
  ok: boolean;
  policyDecision?: unknown;
  denial?: unknown;
  filesystemLowering?: unknown;
  backendArtifacts?: unknown;
};

type PraxisRaxcellDecisionEvent = {
  type: "praxis.sandbox.decision";
  actionId: string;
  decision: "allow" | "grant" | "deny" | "rewrite";
  reason?: string;
  grants?: unknown[];
};

type PraxisRaxcellRunEvent = {
  type: "praxis.sandbox.run";
  actionId: string;
  ok: boolean;
  exitCode?: number | null;
  timedOut?: boolean;
  denial?: unknown;
  stdoutBytes?: number;
  stderrBytes?: number;
  filesystemLowering?: unknown;
};
```

Bound all stdout/stderr stored in long-term audit logs. Raxcell results are execution data, not model-visible context.

## Error Handling

Recommended Praxis behavior:

| Failure | Likely source | Praxis behavior |
| --- | --- | --- |
| CLI binary missing | Praxis config/deployment | fail closed; mark sandbox unavailable. |
| `probe.ready = false` | host lacks backend dependency | fail closed for sandbox-required tools. |
| `prepareRun.ok = false` | invalid request or unsupported backend | do not call `run`; log denial. |
| `policyDecision` present | request needs upper-layer decision | ask Praxis policy/human; grant/rewrite/deny. |
| `run.ok = false` with denial | backend refused execution | return structured tool failure. |
| timeout | command exceeded policy | return timeout result; do not auto-retry unsandboxed. |
| nonzero exit | command-level failure | return normal tool result with exit code. |

Only nonzero exit code is a normal command failure. Sandbox denial and unavailable backend are policy/runtime failures.

## Linux E2E Acceptance Tests

Praxis should add an integration suite that runs against the Raxcell CLI on Linux.

Minimum tests:

1. `probe` returns ready for `linux-bubblewrap`.
2. `explainBackend` reports `prepareRun` as no-spawn and `run` as spawning.
3. `prepareRun` returns `ok: true` for workspace read/write roots.
4. `prepareRun` returns `filesystemLowering`.
5. `prepareRun` returns `linux-bubblewrap-argv` backend artifact.
6. `run` can read a file under an allowed read root.
7. `run` can write a file under an allowed write root.
8. `run` cannot write under a read-only root.
9. `run` cannot read an undeclared root.
10. `network: "deny"` blocks network access.
11. cwd outside declared roots returns a policy decision.
12. cwd policy grant followed by a second `prepareRun` succeeds.
13. timeout kills a long-running process.
14. Praxis audit receives prepare, decision when applicable, and run events.

Suggested test shape:

```ts
test("praxis middleware prepares, grants cwd, and runs", async () => {
  const request = toRaxcellRunRequest({
    actionId: "test-action",
    sessionId: "test-session",
    toolId: "praxis.shell",
    argv: ["/usr/bin/printf", "hello"],
    cwd: workspaceRoot,
    workspaceRoot,
    readRoots: [workspaceRoot],
    writeRoots: [workspaceRoot],
    network: "deny",
    timeoutMs: 1000,
  });

  const result = await runWithPraxisSandboxPolicy({
    sandbox,
    request,
    decide: async () => ({ type: "allow" }),
    audit: async event => events.push(event),
  });

  assert.equal(result.ok, true);
  assert.match(result.stdout ?? "", /hello/);
});
```

## First Praxis Implementation Plan

Recommended smallest useful landing sequence:

1. Add `@praxis-ai/raxcell@0.1.1` to Praxis.
2. Add `SandboxExecutionPort`.
3. Add `RaxcellClient` adapter with explicit `binaryPath`.
4. Add shell/tool-call to `RunRequest` mapper.
5. Add middleware that always calls `prepareRun` before `run`.
6. Add audit events for prepare, decision, and run.
7. Add Linux integration tests.
8. Gate existing shell-like baseTool execution through the middleware.
9. Add a Praxis config switch to require sandboxing.
10. Only after Linux is green, add WSL/macOS/Windows routing.

## Non-Goals For Praxis Side

Do not implement these in the first Praxis integration:

- bundling macOS or Windows native Raxcell binaries into the npm package;
- full macOS/Windows verification;
- model-visible sandbox transcript injection;
- broad policy DSL redesign;
- automatic unsandboxed fallback;
- per-tool bespoke sandbox clients.

Those can come later. The first goal is a reliable Linux `policy -> prepareRun -> run -> audit` loop.

## Handoff Summary

Praxis should integrate Raxcell as a runtime enforcement port:

```text
Tool request
  -> map to RunRequest
  -> prepareRun
  -> policy decision
  -> optional grant/rewrite
  -> prepareRun again
  -> run
  -> audit result
```

If this loop works on Linux, Praxis has the right abstraction. WSL, macOS, and Windows should then be backend expansion work rather than a new middleware design.
