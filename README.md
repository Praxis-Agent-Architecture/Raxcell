# Raxcell

Raxcell is an execution-enforcement sandbox SDK for agent runtimes.

It gives an agent harness a small, typed control surface for probing sandbox capabilities, preparing a sandboxed command, auditing backend lowering, and then executing the command through a platform backend.

Raxcell is not Praxis-specific. Praxis is the first target runtime, but the contract is intended to be usable by any agent framework that needs a declarative sandbox boundary.

## Status

Current version: `0.1.0`

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

macOS and Windows are protocol-visible but not enabled as executable runners in `0.1.0`:

- `macos-seatbelt` has an internal Seatbelt lowering artifact model.
- `windows-elevated` and `windows-unelevated` have internal token/ACL/WFP lowering artifact models.
- Unsupported or unattached native backends fail closed.

## Architecture

From an agent runtime's perspective:

```text
Agent / Harness
  -> Runtime policy middleware
  -> Raxcell TypeScript client or JSON-RPC worker
  -> Raxcell core
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
@praxis-ai/raxcell@0.1.0
```

Install from a local tarball:

```bash
pnpm add /path/to/praxis-ai-raxcell-0.1.0.tgz
```

Use it with a Raxcell CLI binary path:

```ts
import { RaxcellClient, type RunRequest } from "@praxis-ai/raxcell";

const raxcell = new RaxcellClient({
  binaryPath: "/absolute/path/to/raxcell",
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

- `raxcell/crates/protocol`: JSON protocol types.
- `raxcell/crates/core`: backend dispatch, policy resolution, prepare/run logic.
- `raxcell/crates/cli`: CLI and stdio JSON-RPC worker.
- `raxcell/sdk`: TypeScript client package.
- `raxcell/fixtures`: JSON smoke fixtures.
- `specs/raxcell`: extraction plans and integration docs.

## Verification

Run the Rust tests:

```bash
cargo test --manifest-path raxcell/Cargo.toml
```

Run the TypeScript SDK checks:

```bash
pnpm install
pnpm build:sdk
pnpm test:sdk
```

Run Linux smoke commands:

```bash
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- probe --stdin < raxcell/fixtures/probe.auto.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- prepare-run --stdin < raxcell/fixtures/prepare-run.linux-bubblewrap.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.linux-bubblewrap.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- explain-backend --stdin < raxcell/fixtures/explain-backend.linux-bubblewrap.json
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

The workflow runs Rust tests, TypeScript build, TypeScript tests, and then:

```bash
pnpm --dir raxcell/sdk publish --access public --no-git-checks --provenance
```

## License

Apache-2.0. See [LICENSE](LICENSE).
