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
- backend-specific artifacts such as Codex Linux helper argv.

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
  -> Codex core-backed Linux now
  -> macOS Seatbelt planned/partial
  -> Windows native runner bridge/planned
```

## Current 0.1.5 Runtime Contract

The package exposes a `raxcell` executable and the client expects a CLI binary path.

```ts
import { RaxcellClient } from "@praxis-ai/raxcell";

const raxcell = new RaxcellClient({
  binaryPath: process.env.RAXCELL_BIN ?? "raxcell",
});
```

For development against this repository, Praxis can point directly at the build artifact and enable the corrected Linux Rust worker path:

```bash
RAXCELL_BIN=/home/proview/Desktop/Praxis_series/development/Raxcell/raxcell/sdk/dist/cli.js
RAXCELL_RUST_CLI=/home/proview/Desktop/Praxis_series/development/Raxcell/raxcell/target/debug/raxcell
RAXCELL_CODEX_LINUX_SANDBOX_BIN=/home/proview/Desktop/Praxis_series/development/Raxcell/raxcell/target/debug/raxcell-codex-linux-sandbox
```

The current package ships a TypeScript/Node CLI facade. On Linux, the corrected path delegates to the Rust worker when `RAXCELL_RUST_CLI` is configured and returns Codex Linux helper artifacts; without that worker, the old direct-bwrap TypeScript path is legacy fallback. macOS Seatbelt is protocol-visible and planned/partial until Codex Seatbelt lowering is wired. Windows native execution is a runner bridge/planned path: set `RAXCELL_WINDOWS_RUNNER` or expose `raxcell-windows-runner` on `PATH`.

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

On Linux, a ready corrected response means Raxcell can lower through the Codex-derived helper path and enforce filesystem, network, process, and timeout boundaries. The public backend family may still be `linux-bubblewrap` for compatibility.

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

On Linux, the corrected Rust-worker path returns a `codex-linux-sandbox-argv` artifact. That artifact describes the Codex-derived helper invocation, not a TypeScript-built bubblewrap argv. The old direct-bwrap TypeScript path may return `linux-bubblewrap-argv`, but that format is legacy fallback only.

### run

Use `run()` only after Praxis policy accepts the request.

```ts
const result = await raxcell.run(runRequest);

if (!result.ok) {
  console.error(result.denial);
}
```

The result includes stdout, stderr, exit code, timeout state, denial, and `filesystemLowering`.

`run.ok` describes whether Raxcell launched and managed the sandbox backend. A nonzero child command exit remains `ok: true` with `exitCode != 0`; `ok: false` is reserved for backend failure, denial, timeout, policy handoff, or environment gaps.

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

Then retry `prepareRun()` and call `run()` only after the updated request prepares cleanly.

## Shell Filesystem Effects

In `0.1.5`, `prepareRun()` analyzes common shell filesystem effects before backend lowering. Linux and macOS use the POSIX shell analyzer. Windows native requests also recognize common `cmd.exe /c` filesystem effects. Raxcell reports facts; Praxis still owns policy, approval, and audit decisions.

Concrete paths outside declared roots return `policyDecision.reason = "path-outside-declared-roots"` with contextual `required` values:

- shell redirection and `tee` outputs: `write`;
- `cp`, `install`, and `rsync`: source `read`, destination `write`;
- `mv`: source `readwrite`, destination `write`;
- `touch`, `mkdir`, `rm`, `chmod`, `chown`: `write`;
- `sed -i` and `perl -pi`: `readwrite`;
- `cat`, `grep`, and non-in-place `sed`: `read`;
- Python `open(..., "w" | "a")`, `Path(...).write_text(...)`: `write`;
- Node `fs.writeFileSync(...)` and `fs.appendFileSync(...)`: `write`;
- Python/Node read calls: `read`;
- Windows `cmd.exe /c` redirection: `write`;
- Windows `type`: `read`;
- Windows `copy` / `xcopy`: source `read`, destination `write`;
- Windows `move`: source `readwrite`, destination `write`;
- Windows `del`, `erase`, `md`, and `rd`: `write`.

Dynamic paths fail closed as environment facts, not policy grants:

```json
{
  "ok": false,
  "policyDecision": null,
  "environmentGap": {
    "reason": "dynamic-shell-path-unresolved",
    "path": "$HOME/a.txt",
    "required": ["command.rewrite.static-path"],
    "publicSafeMessage": "The command contains a dynamic shell path that Raxcell cannot safely normalize."
  }
}
```

The legacy TypeScript direct-backend path may still spell this reason as `shell-dynamic-path-unresolved`; Praxis should route both spellings to rewrite/clarification, not to a grant.

Raxcell does not expand `$HOME`, `${TARGET}`, `~`, backticks, command substitutions, `%USERPROFILE%`, `%TARGET%`, or delayed `!VAR!` references from `process.env` or `request.command.env`. Praxis can surface this gap, ask the user, rewrite the command into concrete paths, or deny.

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
- `RunRequest.backendPreference`
- `RunRequest.policyGrants`
- `PrepareRunResponse.filesystemLowering`
- `PrepareRunResponse.backendArtifacts`
- `PrepareRunResponse.policyDecision`
- `PrepareRunResponse.environmentGap`
- `RunResponse.denial`
- `RunResponse.environmentGap`
- `RunResponse.exitCode`
- `RunResponse.timedOut`
- `RunResponse.backendArtifacts`

For Linux, `backendArtifacts` lets Praxis compare the intended policy with the actual Codex Linux helper argv. `prepareRun` and `run` both expose the prepared artifacts so audit and TUI rendering can use the same facts before and after execution:

```ts
const codexLinux = prepared.backendArtifacts.find(
  (artifact) => artifact.format === "codex-linux-sandbox-argv",
);

console.log(codexLinux?.data.executable);
console.log(codexLinux?.arguments);
```

## Backend Status

Linux is Codex core-backed on the corrected Rust-worker path:

- `probe` can still select the compatibility backend family `linux-bubblewrap`;
- successful corrected `prepareRun` returns `codex-linux-sandbox-argv`;
- `run` executes through the Codex-derived Linux helper;
- missing declared roots fail closed;
- cwd outside declared roots returns `POLICY_DECISION_REQUIRED`;
- explicit upper-runtime `policyGrants` can authorize cwd/path access;
- network deny uses the Codex Linux helper boundary;
- timeout is enforced by Raxcell process management;
- common shell/Python/Node filesystem effects are reported during `prepareRun`.

`linux-bubblewrap-argv` is the legacy TypeScript fallback artifact. Keep it for compatibility, but do not treat it as proof that the Codex-backed Linux path was used.

## WSL Status

WSL2 should follow the Linux path conceptually because it uses Linux userspace. Treat it as Linux-bubblewrap once the host has a working `bwrap`.

The protocol already exposes backend families:

- `macos-seatbelt`
- `windows-native`
- `windows-elevated`
- `windows-unelevated`

`macos-seatbelt` is planned/partial until Codex Seatbelt lowering is wired. A local SBPL string plus `/usr/bin/sandbox-exec` uses the same OS primitive, but it is not equivalent to Codex lowering unless the Codex lowering path produced it.

Windows native execution is bridge/planned until direct native `windows-sandbox-rs` API smoke passes. The current runner contract can delegate execution, but it is not the final native API integration.

When selected through `backendPreference`, Windows backends return native capability facts and planned lowering artifacts. They fail closed with `environmentGap.reason = "host-platform-mismatch"` on non-Windows hosts, or `environmentGap.reason = "native-backend-runner-unattached"` on Windows hosts without a runner. They do not ask for approval, grant policy, or fall back to host execution.

## Native Backend Smoke Scripts

This package includes reviewer smoke scripts for native backend validation outside Praxis:

- `pnpm smoke:macos` runs `scripts/smoke-macos-seatbelt.mjs`;
- `pnpm smoke:windows` runs `scripts/smoke-windows-native.mjs`.

They exercise the same JSON stdin/stdout CLI contract as `RaxcellClient`: `--version`, `probe`, `explain-backend`, `prepare-run`, and `run` when the backend is ready.

macOS:

```bash
cd raxcell/sdk
pnpm install --frozen-lockfile
pnpm build
pnpm smoke:macos
```

Windows PowerShell:

```powershell
cd raxcell\sdk
pnpm install --frozen-lockfile
pnpm build
pnpm smoke:windows
```

To test an installed binary or a custom build, set `RAXCELL_BIN`:

```bash
RAXCELL_BIN=/absolute/path/to/raxcell pnpm smoke:macos
```

```powershell
$env:RAXCELL_BIN = "C:\absolute\path\to\raxcell.cmd"
pnpm smoke:windows
```

Each script prints one JSON response:

```json
{
  "kind": "raxcell.nativeSmokeResult.v1",
  "backend": "macos-seatbelt",
  "ok": true,
  "ready": true,
  "results": []
}
```

`ok: true` means every expected fact matched. If the selected backend is not available on that host, the script still verifies fail-closed `environmentGap` behavior and skips the real `run` smoke. Windows native execution additionally requires `RAXCELL_WINDOWS_RUNNER` or `raxcell-windows-runner` on `PATH`; otherwise the expected fail-closed reason is `native-backend-runner-unattached`.

Native planned artifact formats:

- `codex-linux-sandbox-argv`
  - Mainline successful Linux artifact for the corrected Rust-worker path.
  - `arguments`: Codex Linux helper arguments after argv0/program.
  - `data.engine`: `codex-linux-sandbox`.
  - `data.executable`: helper executable path when the Rust worker produced the artifact.
  - Source-aware roots, runtime roots, effects, network mode, and timeout/resource facts are carried in `filesystemLowering`, `capabilityReport`, or sibling response fields. Legacy TypeScript artifacts may include extra audit data, but Praxis should not require those extras to prove the corrected Rust helper path.
- `macos-seatbelt-sbpl-profile`
  - Planned/partial until generated through Codex Seatbelt lowering.
  - `arguments`: planned `/usr/bin/sandbox-exec -p <profile> -- <argv...>`.
  - `data.profile`: generated SBPL profile text.
  - `data.commandEnvMode`: `clean`.
  - `data.writeGrantMaterialization`: `raxcell-precreate`; Raxcell precreates missing approved writable grant paths before launching Seatbelt.
  - `data.commandEnv`: effective command environment after Raxcell lowering, including the default command `PATH` unless the request overrides it.
  - `data.rootRules`: source-aware read/write roots with `source=declared|policy-grant` for audit display.
  - `data.readRoots` / `data.writeRoots`: lowered roots from declarations and grants.
  - `data.runtimeRoots`: backend-runtime read roots added so Seatbelt can execute system tools and libraries; these are not upper-runtime policy grants.
  - `data.networkDenied`: backend network intent.
  - `data.networkMode`: common audit value, `deny` or `allow`.
  - `data.timeoutMs`: parent-enforced timeout for the spawned `sandbox-exec` process.
  - `data.processLimits` / `data.resourceLimits`: forwarded execution limits.
- `windows-native-token-acl-plan`
  - Bridge/planned until direct native `windows-sandbox-rs` API smoke passes.
  - `data.runnerProtocol`: `raxcell.windowsRunner.run.v1`.
  - `data.runner`: resolved runner path, when available.
  - `data.normalizedCwd`: command cwd normalized with Windows path semantics when the request uses Windows-like paths.
  - `data.commandEnvMode`: `clean`.
  - `data.writeGrantMaterialization`: `runner-owned`; the native runner owns ACL application and any safe host precreation/copy-out needed for approved write roots.
  - `data.commandEnv`: effective command environment after Raxcell lowering, including the default command `PATH` unless the request overrides it.
  - `data.tokenMode`: `read-only-capability` or `writable-roots-capability`.
  - `data.aclRoots`: planned filesystem ACL roots; Windows-like paths such as `C:\workspace` keep Windows path shape even when a non-Windows host is only producing planned facts.
  - `data.networkBlocked`: WFP/network intent.
  - `data.networkMode`: common audit value, `deny` or `allow`.
  - `data.timeoutMs`: parent-enforced timeout that the Windows runner should mirror in its Job Object / child process management.
  - `data.processLimits` / `data.resourceLimits`: forwarded execution limits.

The Windows runner receives a JSON object on stdin:

The npm package exports this stdin shape as `WindowsRunnerRunRequest`; runner implementations should pair it with `RunResponse` for stdout.

```json
{
  "kind": "raxcell.windowsRunner.run.v1",
  "backend": "windows-native",
  "command": {},
  "normalizedCwd": "C:\\workspace",
  "commandEnvMode": "clean",
  "writeGrantMaterialization": "runner-owned",
  "enforcement": {},
  "filesystemLowering": {},
  "tokenMode": "writable-roots-capability",
  "aclRoots": [],
  "networkBlocked": true,
  "networkMode": "deny",
  "timeoutMs": 1000
}
```

It must return `raxcell.runResult.v1` JSON on stdout and keep human/debug output on stderr.
The returned `backend` must match the prepared Windows backend. Raxcell rejects mismatched runner responses as protocol errors. If the runner omits `filesystemLowering`, `backendArtifacts`, or `capabilityReport`, Raxcell overlays the prepared execution facts before returning the final `raxcell.runResult.v1` to Praxis.

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

For the consolidated Praxis boundary, see `../../docs/praxis-integration.md`.
