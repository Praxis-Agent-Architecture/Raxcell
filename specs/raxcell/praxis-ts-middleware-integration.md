# Praxis TS Middleware Integration For Raxcell 0.1.0

## Conclusion

Raxcell is ready to be used by a TypeScript-based Praxis runtime as a Linux sandbox execution backend.

The integration should treat Raxcell as an enforcement port:

```text
Praxis Tool Call
  -> Praxis policy middleware
  -> Raxcell prepareRun
  -> Praxis grant/deny/rewrite decision
  -> Raxcell run
  -> Praxis event/session audit
```

Raxcell does not own Praxis policy. It owns execution enforcement and backend facts.

## What Praxis Can Use Now

### TypeScript package

Package name:

```text
@praxis-ai/raxcell@0.1.0
```

Primary class:

```ts
RaxcellClient
```

Primary types:

```ts
RunRequest
RunResponse
PrepareRunResponse
ProbeRequest
ProbeResponse
ExplainBackendRequest
ExplainBackendResponse
PolicyGrant
PolicyDecisionRequired
FileSystemLoweringReport
BackendLoweringArtifact
```

### Runtime methods

```ts
client.probe(request)
client.explainBackend(request)
client.resolveProfile(request)
client.prepareRun(request)
client.run(request)
```

The most important method for Praxis is `prepareRun`.

## Praxis-Side Port

Praxis should define a port similar to:

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

Then implement it with:

```ts
import { RaxcellClient } from "@praxis-ai/raxcell";

export function createRaxcellSandboxPort(binaryPath: string): SandboxExecutionPort {
  return new RaxcellClient({ binaryPath });
}
```

## Tool Call To RunRequest

Praxis should convert an execution-bearing tool call into a `RunRequest`.

Example:

```ts
import type { RunRequest } from "@praxis-ai/raxcell";

export function shellToolCallToRunRequest(input: {
  actionId: string;
  sessionId: string;
  argv: string[];
  cwd: string;
  readRoots: string[];
  writeRoots: string[];
  timeoutMs: number;
}): RunRequest {
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
        toolId: "praxis.shell",
      },
    },
    command: {
      argv: input.argv,
      cwd: input.cwd,
      env: {},
      stdin: null,
    },
    enforcement: {
      profile: "workspace-write-no-network",
      filesystem: {
        read: input.readRoots,
        write: input.writeRoots,
      },
      network: "deny",
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

## Policy Middleware Algorithm

```ts
import type {
  PolicyGrant,
  PrepareRunResponse,
  RunRequest,
  RunResponse,
} from "@praxis-ai/raxcell";

type PraxisSandboxDecision =
  | { type: "allow" }
  | { type: "grant"; grants: PolicyGrant[] }
  | { type: "deny"; reason: string };

export async function runWithPraxisPolicy(args: {
  sandbox: SandboxExecutionPort;
  request: RunRequest;
  decide: (prepared: PrepareRunResponse, request: RunRequest) => Promise<PraxisSandboxDecision>;
  audit: (event: unknown) => Promise<void>;
}): Promise<RunResponse> {
  let request = args.request;
  let prepared = await args.sandbox.prepareRun(request);

  await args.audit({
    type: "raxcell.prepareRun",
    actionId: request.action.actionId,
    prepared,
  });

  if (prepared.policyDecision) {
    const decision = await args.decide(prepared, request);
    if (decision.type === "deny") {
      throw new Error(decision.reason);
    }
    if (decision.type === "grant") {
      request = {
        ...request,
        policyGrants: [
          ...(request.policyGrants ?? []),
          ...decision.grants,
        ],
      };
      prepared = await args.sandbox.prepareRun(request);
      await args.audit({
        type: "raxcell.prepareRun.afterGrant",
        actionId: request.action.actionId,
        prepared,
      });
    }
  }

  if (!prepared.ok) {
    throw new Error(prepared.denial?.message ?? "Raxcell prepareRun failed");
  }

  const result = await args.sandbox.run(request);
  await args.audit({
    type: "raxcell.run",
    actionId: request.action.actionId,
    result,
  });
  return result;
}
```

## Policy Decision Mapping

Current policy decision reason:

```text
cwd-outside-declared-roots
```

Recommended Praxis policy response:

```ts
const cwdGrant: PolicyGrant = {
  reason: "cwd-outside-declared-roots",
  path: prepared.policyDecision.path,
  access: ["read"],
  grantedBy: "praxis-policy",
};
```

If the command needs to write in cwd, Praxis may grant:

```ts
{
  reason: "cwd-outside-declared-roots",
  path: prepared.policyDecision.path,
  access: ["write"],
  grantedBy: "praxis-policy"
}
```

Do not grant blindly. Praxis should decide based on its own profile/session/tool policy.

## Audit Fields

Persist at least:

```ts
{
  actionId: request.action.actionId,
  ownerRuntime: request.action.ownerRuntime,
  command: request.command,
  enforcement: request.enforcement,
  policyDecision: prepared.policyDecision,
  filesystemLowering: prepared.filesystemLowering,
  backendArtifacts: prepared.backendArtifacts,
  denial: result.denial,
  exitCode: result.exitCode,
  timedOut: result.timedOut
}
```

For Linux, `backendArtifacts` contains:

```ts
{
  backend: "linux-bubblewrap",
  format: "linux-bubblewrap-argv",
  arguments: string[],
  data: {
    executable: "/usr/bin/bwrap"
  },
  warnings: []
}
```

This is the exact backend artifact Praxis can inspect before execution.

## Recommended Linux E2E Tests

Praxis should add tests that drive the TS package against the Raxcell CLI:

1. `probe` returns ready for `linux-bubblewrap`.
2. `prepareRun` returns `filesystemLowering`.
3. `prepareRun` returns `backendArtifacts` with `linux-bubblewrap-argv`.
4. `run` can read an allowed read root.
5. `run` can write an allowed write root.
6. `run` cannot write a read-only root.
7. `run` cannot read an undeclared root.
8. `run` with network deny cannot reach the network.
9. cwd outside declared roots returns `POLICY_DECISION_REQUIRED`.
10. cwd policy grant allows the second prepare/run.
11. timeout kills a long-running process.

## What This Enables

After this integration, Praxis can treat sandboxing as a normal runtime port:

```text
BaseTool
  -> RunRequest
  -> prepareRun
  -> policy decision
  -> run
  -> audit
```

That is the first real bridge between Praxis harness semantics and Raxcell execution enforcement.
