# Raxcell

Raxcell is an execution-enforcement sandbox SDK for agent runtimes.

It gives an agent harness a small control surface for probing sandbox capability, preparing an execution request, reporting filesystem/backend lowering facts, and running the command through a platform sandbox backend.

Raxcell is not Praxis-specific. Praxis is the first target runtime, but the contract is intended for any agent framework that needs a reusable, declarative sandbox boundary.

## Current Status

Current npm package: `@praxis-ai/raxcell@0.1.5`

Linux is usable today through the TypeScript CLI package:

- `linux-bubblewrap` executes commands through bubblewrap.
- Filesystem read/write roots are declared per request.
- Explicit `policyGrants` can add host path access after an upper runtime has approved it.
- Write grants are mounted so approved external writes land on the host, not in a sandbox shadow path.
- Network deny uses bubblewrap network isolation.
- Timeouts are enforced by Raxcell process management.
- `prepareRun` returns `filesystemLowering`, analyzer effects, and backend-specific `backendArtifacts`.
- Linux `backendArtifacts` include the complete bubblewrap argv.

macOS and Windows are protocol-visible future backend families:

- `macos-seatbelt`
- `windows-elevated`
- `windows-unelevated`
- `windows-native`

The `0.1.x` npm CLI only executes the Linux bubblewrap backend. Unsupported or unattached backends fail closed.

## Boundary

Raxcell is an execution provider, not a policy engine.

Raxcell owns:

- backend capability facts;
- backend lowering reports;
- filesystem access facts;
- sandbox process execution;
- fail-closed environment gaps and denials.

Upper runtimes own:

- policy matrices;
- approval and human gates;
- audit persistence;
- tool semantics;
- fallback decisions;
- model behavior and prompt interpretation.

In Praxis terms:

```text
Praxis / Agent Harness
  -> policy middleware
  -> RaxcellClient
  -> raxcell CLI JSON stdin/stdout
  -> linux-bubblewrap
```

## Install

```bash
pnpm add @praxis-ai/raxcell@0.1.5
```

The package exposes a `raxcell` binary:

```bash
raxcell --version
raxcell probe
raxcell explain-backend
raxcell prepare-run < request.json
raxcell run < request.json
```

For local development against this repository:

```bash
pnpm build:sdk
RAXCELL_BIN=/home/proview/Desktop/Praxis_series/development/Raxcell/raxcell/sdk/dist/cli.js
```

## SDK Usage

```ts
import { RaxcellClient, type RunRequest } from "@praxis-ai/raxcell";

const raxcell = new RaxcellClient({
  binaryPath: process.env.RAXCELL_BIN ?? "raxcell",
});

const request: RunRequest = {
  kind: "raxcell.run.v1",
  backendPreference: ["linux-bubblewrap"],
  policyGrants: [],
  action: {
    actionId: "tool-call-1",
    ownerRuntime: "praxis",
    intentLabel: "shell command",
    metadata: {},
  },
  command: {
    argv: ["/bin/sh", "-lc", "printf hello"],
    cwd: "/workspace/project",
    env: {},
    stdin: null,
  },
  enforcement: {
    profile: "workspace-write-no-network",
    filesystem: {
      read: ["/workspace/project"],
      write: ["/workspace/project"],
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

const prepared = await raxcell.prepareRun(request);

if (prepared.policyDecision) {
  // The upper runtime decides whether to deny, ask, rewrite, or grant.
}

if (prepared.environmentGap) {
  // The upper runtime decides how to handle an unresolved environment fact.
}

const result = await raxcell.run(request);
```

## Prepare-Run Semantics

`prepareRun` is the main integration point for a policy middleware. It does not spawn the command.

It can return:

- `ok: true`: the requested sandbox can be prepared with the supplied declarations and grants.
- `policyDecision.reason = "path-outside-declared-roots"`: a concrete path needs upper-runtime policy handling.
- `environmentGap.reason = "shell-dynamic-path-unresolved"`: a dynamic shell path cannot be normalized safely.
- `environmentGap.reason = "missing-backend-dependency"`: the selected backend cannot run on this host.
- `denial`: Raxcell cannot safely lower or execute the request.

Concrete external paths use `policyDecision`:

```json
{
  "reason": "path-outside-declared-roots",
  "path": "/home/proview/a.txt",
  "required": ["write"],
  "publicSafeMessage": "The command references a path outside declared filesystem roots."
}
```

Dynamic shell paths use `environmentGap` and are not expanded by Raxcell:

```json
{
  "reason": "shell-dynamic-path-unresolved",
  "path": "$HOME/a.txt",
  "required": ["write"],
  "publicSafeMessage": "The command contains a dynamic shell path that Raxcell cannot safely normalize."
}
```

Raxcell does not resolve `$HOME`, `${TARGET}`, `~`, backticks, or command substitution from host env or request env. Praxis or another upper runtime can rewrite to concrete paths, ask for clarification, or deny.

## Shell Filesystem Effect Analyzer

The Linux CLI includes a lightweight shell filesystem effect analyzer. It reports facts in `filesystemLowering.effects`.

Covered examples include:

- `cp`, `install`, `rsync`: source read, destination write.
- `mv`: source read/write, destination write.
- `touch`, `mkdir`, `rm`, `chmod`, `chown`: write.
- shell redirection and `tee`: write.
- `cat`, `grep`, non-in-place `sed`: read.
- `sed -i`, `perl -pi`: read/write.
- Python `open(..., "w" | "a")`, `Path(...).write_text(...)`: write.
- Node `fs.writeFileSync(...)`, `fs.appendFileSync(...)`: write.
- Python/Node read APIs: read.
- quoted paths, pipelines, multi-command shell, subshell, and glob patterns.

This analyzer is intentionally conservative. It reports unresolved dynamic paths as environment gaps instead of guessing.

## Run Semantics

`run.ok` describes whether the sandbox backend executed normally, not whether the child command returned zero.

If the sandbox launches correctly and the command exits nonzero:

```json
{
  "ok": true,
  "exitCode": 7,
  "denial": null,
  "environmentGap": null
}
```

Use `exitCode`, `stdout`, and `stderr` for command-level behavior. Use `ok: false`, `denial`, `policyDecision`, or `environmentGap` for sandbox/provider-level failure.

## Repository Layout

- `raxcell/sdk`: TypeScript npm package and Linux bubblewrap CLI.
- `raxcell/sdk/src/types.ts`: JSON protocol types.
- `raxcell/sdk/src/client.ts`: TypeScript client that spawns the CLI.
- `raxcell/sdk/src/cli.ts`: executable `raxcell` CLI and Linux bubblewrap runner.
- `raxcell/sdk/src/shell-effects.ts`: shell filesystem effect analyzer.
- `raxcell`: Rust workspace retained for protocol/backend research.
- `specs/raxcell`: extraction plans and integration docs.

## Verification

```bash
pnpm install --frozen-lockfile
pnpm build:sdk
pnpm test:sdk
raxcell/sdk/dist/cli.js --version
raxcell/sdk/dist/cli.js probe
raxcell/sdk/dist/cli.js explain-backend
npm --prefix raxcell/sdk pack --dry-run --json
```

## Publishing

The npm publish workflow lives at `.github/workflows/npm-publish.yml`.

It publishes `raxcell/sdk` as `@praxis-ai/raxcell` when triggered by:

- manual `workflow_dispatch`;
- a published GitHub release;
- a pushed `v*` tag.

Publishing requires the repository secret:

```text
NPM_TOKEN
```

## License

Apache-2.0. See [LICENSE](LICENSE).
