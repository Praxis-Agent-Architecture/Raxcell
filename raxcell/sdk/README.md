# @praxis-ai/raxcell

Raxcell is an execution-enforcement sandbox SDK for agent runtimes.

This package is the TypeScript client facade. It calls a Raxcell CLI binary through JSON stdin/stdout and exposes typed protocol objects for Praxis or any other agent harness.

Version: `0.1.5`

## What This Package Is

Raxcell is the sandbox backend layer below an agent runtime.

It does:

- backend capability probing;
- backend explanation for UI/audit/control planes;
- dry-run sandbox preparation;
- policy-decision handoff;
- sandboxed command execution;
- filesystem lowering reports;
- backend-specific artifacts such as Linux bubblewrap argv.

It does not:

- make approval decisions;
- ask humans;
- decide Praxis policy;
- interpret model/tool intent;
- rewrite prompts;
- implement an agent loop.

In Praxis terms:

```text
Praxis Agent / Harness
  -> Praxis policy middleware
  -> @praxis-ai/raxcell client
  -> Raxcell CLI / worker
  -> linux-bubblewrap now
  -> macOS Seatbelt / Windows native later
```

## Current 0.1.5 Runtime Contract

The package exposes a `raxcell` executable and the client expects a CLI binary path.

```ts
import { RaxcellClient } from "@praxis-ai/raxcell";

const raxcell = new RaxcellClient({
  binaryPath: process.env.RAXCELL_BIN ?? "raxcell",
});
```

For development against this repository, Praxis can point directly at the build artifact:

```bash
RAXCELL_BIN=/home/proview/Desktop/Praxis_series/development/Raxcell/raxcell/sdk/dist/cli.js
```

The current package ships a TypeScript/Node CLI with Linux bubblewrap and macOS Seatbelt runners. Windows native execution is delegated to a native runner contract: set `RAXCELL_WINDOWS_RUNNER` or expose `raxcell-windows-runner` on `PATH`.

## Core Methods

### probe

Use `probe()` when Praxis starts, or before selecting a backend.

```ts
const probe = await raxcell.probe({
  kind: "raxcell.probe.v1",
  platform: "auto",
  backendPreference: ["linux-bubblewrap"],
});

if (!probe.ready) {
  throw new Error(probe.publicSafeMessage);
}
```

On Linux, a ready response means bubblewrap is available and Raxcell can enforce filesystem, network, process, and timeout boundaries.

### explainBackend

Use `explainBackend()` to populate a control plane, debug panel, audit log, or policy middleware cache.

```ts
const explanation = await raxcell.explainBackend({
  kind: "raxcell.explainBackend.v1",
  platform: "auto",
  backendPreference: ["linux-bubblewrap"],
});

console.log(explanation.operations);
console.log(explanation.explanation.isolationPrimitives);
```

Important operation flags:

- `prepareRun` has `no-process-spawn`;
- `run` has `spawns-process`;
- `explainBackend` and `probe` are side-effect-free.

### prepareRun

Use `prepareRun()` before executing a command. This is the main policy middleware integration point.

`prepareRun()` does not spawn the command. It asks Raxcell to lower the request into backend-specific sandbox facts.

```ts
const prepared = await raxcell.prepareRun(runRequest);

if (prepared.policyDecision) {
  // Praxis decides whether to grant, deny, ask a user, or rewrite the request.
}

if (prepared.ok) {
  console.log(prepared.filesystemLowering);
  console.log(prepared.backendArtifacts);
}
```

On Linux, `prepared.backendArtifacts[0]` is a `linux-bubblewrap-argv` artifact containing the complete bubblewrap argv Raxcell would use.

### run

Use `run()` only after Praxis policy accepts the request.

```ts
const result = await raxcell.run(runRequest);

if (!result.ok) {
  console.error(result.denial);
}
```

The result includes stdout, stderr, exit code, timeout state, denial, and `filesystemLowering`.

## RunRequest Shape

Praxis should generate one `RunRequest` per sandboxed command.

```ts
import type { RunRequest } from "@praxis-ai/raxcell";

const runRequest: RunRequest = {
  kind: "raxcell.run.v1",
  backendPreference: ["linux-bubblewrap"],
  policyGrants: [],
  action: {
    actionId: "tool-call-123",
    ownerRuntime: "praxis",
    intentLabel: "shell command",
    metadata: {
      toolId: "praxis.baseTool.shell.run",
      sessionId: "session-1",
    },
  },
  command: {
    argv: ["/usr/bin/printf", "hello"],
    cwd: "/workspace/project",
    env: {},
    stdin: null,
  },
  enforcement: {
    profile: "workspace-write-no-network",
    filesystem: {
      read: ["/workspace/project"],
      write: ["/workspace/project/tmp"],
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
```

## Praxis Policy Middleware Pattern

Recommended middleware flow:

```ts
import type {
  PolicyGrant,
  RunRequest,
  RunResponse,
} from "@praxis-ai/raxcell";

type PraxisPolicyDecision =
  | { type: "allow" }
  | { type: "grant"; grants: PolicyGrant[] }
  | { type: "deny"; reason: string };

async function executeWithRaxcellPolicy(
  raxcell: RaxcellClient,
  request: RunRequest,
  decide: (request: RunRequest) => Promise<PraxisPolicyDecision>,
): Promise<RunResponse> {
  const prepared = await raxcell.prepareRun(request);

  if (prepared.policyDecision) {
    const decision = await decide(request);
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
    }
  }

  const preparedAfterGrants = await raxcell.prepareRun(request);
  if (!preparedAfterGrants.ok) {
    throw new Error(
      preparedAfterGrants.denial?.message ??
        "Raxcell prepareRun failed",
    );
  }

  auditPreparedRun(preparedAfterGrants);
  return raxcell.run(request);
}

function auditPreparedRun(prepared: Awaited<ReturnType<RaxcellClient["prepareRun"]>>) {
  // Persist these in Praxis session/event/state storage.
  console.log(prepared.filesystemLowering);
  console.log(prepared.backendArtifacts);
}
```

## Policy Decision Handoff

If `command.cwd` is outside declared roots, Raxcell returns:

```json
{
  "ok": false,
  "denial": {
    "code": "POLICY_DECISION_REQUIRED"
  },
  "policyDecision": {
    "reason": "cwd-outside-declared-roots",
    "path": "/workspace/project",
    "required": ["filesystem.read"],
    "publicSafeMessage": "command cwd is outside declared filesystem roots; upper policy decision required"
  }
}
```

Praxis can grant:

```ts
const grant: PolicyGrant = {
  reason: "cwd-outside-declared-roots",
  path: "/workspace/project",
  access: ["read"],
  grantedBy: "praxis-policy",
};
```

Then retry `prepareRun()` or call `run()` with the updated request.

## Shell Filesystem Effects

In `0.1.5`, Linux `prepareRun()` analyzes common POSIX shell filesystem effects before lowering to bubblewrap. Raxcell reports facts; Praxis still owns policy, approval, and audit decisions.

Concrete paths outside declared roots return `policyDecision.reason = "path-outside-declared-roots"` with contextual `required` values:

- shell redirection and `tee` outputs: `write`;
- `cp`, `install`, and `rsync`: source `read`, destination `write`;
- `mv`: source `readwrite`, destination `write`;
- `touch`, `mkdir`, `rm`, `chmod`, `chown`: `write`;
- `sed -i` and `perl -pi`: `readwrite`;
- `cat`, `grep`, and non-in-place `sed`: `read`;
- Python `open(..., "w" | "a")`, `Path(...).write_text(...)`: `write`;
- Node `fs.writeFileSync(...)` and `fs.appendFileSync(...)`: `write`;
- Python/Node read calls: `read`.

Dynamic paths fail closed as environment facts, not policy grants:

```json
{
  "ok": false,
  "policyDecision": null,
  "environmentGap": {
    "reason": "shell-dynamic-path-unresolved",
    "path": "$HOME/a.txt",
    "required": ["write"],
    "publicSafeMessage": "The command contains a dynamic shell path that Raxcell cannot safely normalize."
  }
}
```

Raxcell does not expand `$HOME`, `${TARGET}`, `~`, backticks, or command substitutions from `process.env` or `request.command.env`. Praxis can surface this gap, ask the user, rewrite the command into concrete paths, or deny.

`filesystemLowering.effects` contains structured analyzer facts for UI/audit display:

```ts
type Effect = {
  path?: string;
  pattern?: string;
  rawToken: string;
  access: "read" | "write" | "readwrite";
  command: string;
  reason: string;
  confidence: "high" | "medium" | "low";
  warning?: string;
};
```

## What To Audit In Praxis

Persist these fields for every command:

- `RunRequest.action.actionId`
- `RunRequest.action.ownerRuntime`
- `PrepareRunResponse.filesystemLowering`
- `PrepareRunResponse.backendArtifacts`
- `PrepareRunResponse.policyDecision`
- `RunResponse.denial`
- `RunResponse.exitCode`
- `RunResponse.timedOut`

For Linux, `backendArtifacts` lets Praxis compare the intended policy with the actual bubblewrap argv:

```ts
const bwrap = prepared.backendArtifacts.find(
  (artifact) => artifact.format === "linux-bubblewrap-argv",
);

console.log(bwrap?.data.executable);
console.log(bwrap?.arguments);
```

## Linux Status

Linux is usable in `0.1.5`:

- `probe` detects `linux-bubblewrap`;
- `prepareRun` returns filesystem lowering and bubblewrap argv;
- `run` executes through bubblewrap;
- missing declared roots fail closed;
- cwd outside declared roots returns `POLICY_DECISION_REQUIRED`;
- explicit `policyGrants` can authorize cwd;
- network deny uses bubblewrap network unshare;
- timeout is enforced by Raxcell process management;
- common shell/Python/Node filesystem effects are reported during `prepareRun`.

## WSL Status

WSL2 should follow the Linux path conceptually because it uses Linux userspace. Treat it as Linux-bubblewrap once the host has a working `bwrap`.

## macOS And Windows Status

The protocol already exposes backend families:

- `macos-seatbelt`
- `windows-native`
- `windows-elevated`
- `windows-unelevated`

Raxcell can execute `macos-seatbelt` on macOS hosts when `/usr/bin/sandbox-exec` is available. Windows native execution requires a runner binary that enforces restricted token, ACL roots, Job Object limits, and network controls.

When selected through `backendPreference`, Windows backends return native capability facts and planned lowering artifacts. They fail closed with `environmentGap.reason = "host-platform-mismatch"` on non-Windows hosts, or `environmentGap.reason = "native-backend-runner-unattached"` on Windows hosts without a runner. They do not ask for approval, grant policy, or fall back to host execution.

Native planned artifact formats:

- `macos-seatbelt-sbpl-profile`
  - `arguments`: planned `/usr/bin/sandbox-exec -p <profile> -- <argv...>`.
  - `data.profile`: generated SBPL profile text.
  - `data.readRoots` / `data.writeRoots`: lowered roots from declarations and grants.
  - `data.runtimeRoots`: backend-runtime read roots added so Seatbelt can execute system tools and libraries; these are not upper-runtime policy grants.
  - `data.networkDenied`: backend network intent.
- `windows-native-token-acl-plan`
  - `data.runnerProtocol`: `raxcell.windowsRunner.run.v1`.
  - `data.runner`: resolved runner path, when available.
  - `data.tokenMode`: `read-only-capability` or `writable-roots-capability`.
  - `data.aclRoots`: planned filesystem ACL roots.
  - `data.networkBlocked`: WFP/network intent.
  - `data.processLimits` / `data.resourceLimits`: forwarded execution limits.

The Windows runner receives a JSON object on stdin:

```json
{
  "kind": "raxcell.windowsRunner.run.v1",
  "backend": "windows-native",
  "command": {},
  "enforcement": {},
  "filesystemLowering": {},
  "tokenMode": "writable-roots-capability",
  "aclRoots": [],
  "networkBlocked": true
}
```

It must return `raxcell.runResult.v1` JSON on stdout and keep human/debug output on stderr.

## Installation From Local Tarball

After building the tarball:

```bash
pnpm add /path/to/praxis-ai-raxcell-0.1.5.tgz
```

Then import:

```ts
import {
  RaxcellClient,
  type RunRequest,
  type PrepareRunResponse,
} from "@praxis-ai/raxcell";
```

## Version Notes

`0.1.5` is a Linux-first integration package. The API is intentionally small:

- `probe`
- `explainBackend`
- `resolveProfile`
- `prepareRun`
- `run`

The key Praxis integration point is `prepareRun`.
