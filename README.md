# Raxcell

Raxcell is an execution-enforcement sandbox SDK for agent runtimes.

It gives an agent harness a small, typed control surface for probing sandbox capabilities, preparing a sandboxed command, auditing backend lowering, and then executing the command through a platform backend.

Raxcell is not Praxis-specific. Praxis is the first target runtime, but the contract is intended to be usable by any agent framework that needs a declarative sandbox boundary.

## Status

Current version: `0.1.4`

Linux is usable today:

- `linux-bubblewrap` can run commands through bubblewrap.
- Filesystem read/write roots are declared per request.
- Network deny is enforced with bubblewrap network isolation.
- Timeouts are enforced by Raxcell process management.
- Missing roots fail closed.
- `command.cwd` outside declared roots returns `POLICY_DECISION_REQUIRED`.
- Upper runtimes can retry with explicit `policyGrants`.
- `prepareRun` returns `filesystemLowering` and backend-specific `backendArtifacts`.
- Linux `backendArtifacts` include the complete bubblewrap argv.

macOS and Windows are protocol-visible but not enabled as executable runners in `0.1.4`:

- `macos-seatbelt` has an internal Seatbelt lowering artifact model.
- `windows-elevated` and `windows-unelevated` have internal token/ACL/WFP lowering artifact models.
- Unsupported or unattached native backends fail closed.

## Architecture

From an agent runtime's perspective:

```text
Agent / Harness
  -> Runtime policy middleware
  -> Raxcell TypeScript client
  -> raxcell CLI JSON stdin/stdout protocol
  -> linux-bubblewrap / future macOS Seatbelt / future Windows native
```

Raxcell owns:

- execution boundaries;
- backend capability facts;
- backend lowering reports;
- backend-specific artifacts;
- fail-closed execution behavior.

Upper runtimes own:

- approval;
- human gates;
- policy matrices;
- tool semantics;
- model behavior;
- prompt or intent interpretation.

## TypeScript Package

The TypeScript facade package is:

```text
@praxis-ai/raxcell@0.1.5
```

Install from npm:

```bash
pnpm add @praxis-ai/raxcell@0.1.5
```

`@praxis-ai/raxcell@0.1.5` exposes a `raxcell` bin. Praxis can either resolve it from `PATH` after package installation, or pass an explicit development build path such as `raxcell/sdk/dist/cli.js`.

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

const prepared = await raxcell.prepareRun(request);
if (!prepared.ok && prepared.policyDecision) {
  // The runtime decides whether to deny, ask a user, rewrite policy, or grant.
}

const result = await raxcell.run(request);
```

See [raxcell/sdk/README.md](raxcell/sdk/README.md) for package-level API details.

See [specs/raxcell/praxis-ts-middleware-integration.md](specs/raxcell/praxis-ts-middleware-integration.md) for the recommended Praxis middleware pattern.

## Core Protocol Methods

`probe`

Checks whether the requested backend is available and what it can enforce.

`explainBackend`

Returns backend capability facts, operation schema, isolation primitives, runtime roots, and public-safe limitations.

`resolveProfile`

Resolves a policy pack profile into explicit enforcement declarations.

`prepareRun`

Dry-runs backend selection and lowering without spawning the command. This is the main middleware hook for policy engines.

`run`

Executes the command through the selected backend.

## Repository Layout

- `raxcell/sdk/src/types.ts`: JSON protocol types.
- `raxcell/sdk/src/client.ts`: TypeScript client that spawns the CLI.
- `raxcell/sdk/src/cli.ts`: executable `raxcell` CLI and Linux bubblewrap runner.
- `raxcell/sdk/src/shell-effects.ts`: Linux shell filesystem effect analyzer.
- `specs/raxcell`: extraction plans and integration docs.

## Verification

Run the TypeScript SDK checks:

```bash
pnpm --dir raxcell/sdk install --frozen-lockfile
pnpm --dir raxcell/sdk build
pnpm --dir raxcell/sdk test
```

Run Linux smoke commands:

```bash
raxcell/sdk/dist/cli.js --version
raxcell/sdk/dist/cli.js probe
printf '%s' "$RUN_REQUEST_JSON" | raxcell/sdk/dist/cli.js prepare-run
printf '%s' "$RUN_REQUEST_JSON" | raxcell/sdk/dist/cli.js run
```

## Publishing

The npm publish workflow lives at `.github/workflows/npm-publish.yml`.

It publishes `raxcell/sdk` as `@praxis-ai/raxcell` when triggered by:

- manual `workflow_dispatch`;
- a published GitHub release;
- a pushed `v*` tag.

Configure the repository secret:

```text
NPM_TOKEN
```

The workflow runs TypeScript build, TypeScript tests, and then:

```bash
npm publish --access public --provenance
```

## License

Apache-2.0. See [LICENSE](LICENSE).
