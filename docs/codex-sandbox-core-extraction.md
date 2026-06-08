# Codex Sandbox Core Extraction Boundary

Date: 2026-06-06

Raxcell must converge on a Codex-derived sandbox core, not on a TypeScript
wrapper that directly shells out to per-platform primitives. The npm SDK and
CLI can remain the JSON control surface, but platform lowering and command
execution should move into Rust and reuse the same Codex sandbox components
that already encode filesystem, network, timeout, denial, and platform
capability semantics.

This document is the boundary lock for that correction.

## Evidence Anchors

Audited local Raxcell files:

- `README.md`
- `raxcell/README.md`
- `raxcell/sdk/README.md`
- `raxcell/sdk/src/cli.ts`
- `raxcell/sdk/src/client.ts`
- `raxcell/sdk/src/windows-runner.ts`
- `raxcell/crates/core/src/backends/linux_bubblewrap.rs`
- `raxcell/crates/core/src/backends/macos_seatbelt.rs`
- `raxcell/crates/core/src/backends/windows_native.rs`
- `raxcell/crates/protocol/src/types.rs`

Audited upstream Codex source from `openai/codex@main`:

- `HEAD = 87b808bb570f01f4b6fc8485c5459052fac0e320`
- `codex-rs/sandboxing/src/lib.rs`
- `codex-rs/sandboxing/src/manager.rs`
- `codex-rs/sandboxing/src/landlock.rs`
- `codex-rs/sandboxing/src/seatbelt.rs`
- `codex-rs/linux-sandbox/src/main.rs`
- `codex-rs/linux-sandbox/src/lib.rs`
- `codex-rs/linux-sandbox/src/linux_run_main.rs`
- `codex-rs/windows-sandbox-rs/src/lib.rs`
- `codex-rs/core/src/exec.rs`
- `codex-rs/execpolicy/src/lib.rs`
- `codex-rs/protocol/src/models.rs`
- `codex-rs/protocol/src/permissions.rs`

Official Codex sandbox docs:

- <https://developers.openai.com/codex/concepts/sandboxing>
- <https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md>

## Target Boundary

Raxcell is an execution/environment layer for agent runtimes.

Raxcell owns:

- receiving an already-decided execution request;
- probing backend capability;
- preparing sandbox backend facts without spawning the command;
- lowering filesystem/network/process/timeouts to backend artifacts;
- running commands inside a Codex-derived sandbox backend;
- returning `stdout`, `stderr`, `exitCode`, `timedOut`, `denial`,
  `environmentGap`, and backend facts.

Raxcell fails closed. If a backend cannot be prepared or launched, Raxcell
returns `denial` and/or `environmentGap` facts; it must not silently run on the
host.

Raxcell does not own:

- human approval;
- Praxis policy matrices;
- prompt or tool intent interpretation;
- audit persistence;
- fallback, retry, rewrite, or deny decisions;
- session, rollout, or harness state;
- Codex app, IDE, CLI, or model behavior.

The desired stack is:

```text
Agent Runtime / Harness
  -> policy / approval / audit layer
  -> Raxcell SDK / CLI protocol
  -> Raxcell Rust core
  -> Codex-derived sandbox backend
      - Linux: codex-linux-sandbox helper
      - macOS: Codex Seatbelt lowering plus sandbox-exec
      - Windows: codex-windows-sandbox native backend
```

In plain terms: keep the engine that builds and runs the sandbox; do not import
the Codex product around it.

## Current Backend Ownership Map

| Path | Current owner | Current execution path | Status |
| --- | --- | --- | --- |
| Linux npm path | `raxcell/sdk/src/cli.ts` | When `RAXCELL_RUST_CLI` is set, the TypeScript CLI delegates Linux `probe` / `explain-backend` / `prepare-run` / `run` to the Rust CLI; otherwise the old direct-bwrap path is legacy fallback | Rust-worker shim live-tested; direct bwrap is legacy |
| Linux Rust path | `raxcell/crates/core/src/backends/linux_bubblewrap.rs` | Rust lowers Raxcell requests into typed Codex permission profiles, uses `SandboxManager::transform`, and executes through `raxcell-codex-linux-sandbox` | Codex core-backed on Linux |
| macOS npm path | `raxcell/sdk/src/cli.ts` | TypeScript generates SBPL and spawns `/usr/bin/sandbox-exec` | Temporary legacy path |
| macOS Rust path | `raxcell/crates/core/src/backends/macos_seatbelt.rs` | Rust has local SBPL lowering helpers but reports runner unavailable | Temporary, not Codex lowering |
| Windows npm path | `raxcell/sdk/src/windows-runner.ts` | Runner writes temporary Codex config and invokes `codex sandbox --permissions-profile raxcell-runtime` | Temporary bridge |
| Windows Rust path | `raxcell/crates/core/src/backends/windows_native.rs` | Rust has planned ACL/token lowering concepts but no attached native execution | Planned |

The important correction is that `linux-bubblewrap` as a public backend family
can remain temporarily as a compatibility name, but successful Linux
`prepare-run` artifacts should move from `linux-bubblewrap-argv` to
`codex-linux-sandbox-argv`. That artifact means "Raxcell delegates the real
execution boundary to the Codex Linux helper", not "Raxcell hand-builds the
final bubblewrap invocation".

## Codex Sandbox Core Map

### Protocol permission model

Core files:

- `codex-rs/protocol/src/models.rs`
- `codex-rs/protocol/src/permissions.rs`

Reusable concepts:

- `PermissionProfile`
- `AdditionalPermissionProfile`
- `ManagedFileSystemPermissions`
- `FileSystemSandboxPolicy`
- `FileSystemSandboxEntry`
- `FileSystemPath`
- `FileSystemAccessMode`
- `NetworkSandboxPolicy`
- protected metadata path names such as `.git`, `.agents`, and `.codex`

Raxcell should map its `RunRequest.enforcement` and `policyGrants` into this
permission model. Upper runtimes still decide the grants; Raxcell only validates
and lowers them as facts.

### Sandbox transformation layer

Core files:

- `codex-rs/sandboxing/src/lib.rs`
- `codex-rs/sandboxing/src/manager.rs`
- `codex-rs/sandboxing/src/landlock.rs`
- `codex-rs/sandboxing/src/seatbelt.rs`
- `codex-rs/sandboxing/src/policy_transforms.rs`

Reusable concepts:

- `SandboxManager`
- `SandboxTransformRequest`
- `SandboxCommand`
- `SandboxExecRequest`
- `SandboxType`
- `SandboxablePreference`
- `SandboxTransformError`
- `create_linux_sandbox_command_args_for_permission_profile`
- `create_seatbelt_command_args`

This is the central extraction point. `SandboxManager::transform` accepts a
command plus permissions and returns the platform-specific command to execute.
Raxcell should use this transformation boundary instead of reimplementing
platform lowering in TypeScript.

### Linux helper

Core files:

- `codex-rs/linux-sandbox/src/main.rs`
- `codex-rs/linux-sandbox/src/lib.rs`
- `codex-rs/linux-sandbox/src/linux_run_main.rs`
- `codex-rs/linux-sandbox/src/bwrap.rs`
- `codex-rs/linux-sandbox/src/landlock.rs`
- `codex-rs/sandboxing/src/bwrap.rs`
- `codex-rs/sandboxing/src/landlock.rs`

Real entry:

```text
codex-linux-sandbox binary
  -> codex_linux_sandbox::run_main()
  -> linux_run_main::run_main()
```

Helper CLI shape:

```text
codex-linux-sandbox
  --sandbox-policy-cwd <path>
  --command-cwd <path>
  --permission-profile <json>
  [--use-legacy-landlock]
  [--allow-network-for-proxy]
  --
  <command argv...>
```

Codex Linux semantics to retain:

- bubblewrap is the default filesystem sandbox;
- `codex-linux-sandbox` applies `no_new_privs` and seccomp in-process;
- filesystem is read-only by default, with explicit writable roots layered in;
- protected metadata subpaths under writable roots are re-applied as read-only
  or denied;
- restricted network normally uses network namespace isolation;
- WSL1 is rejected for bubblewrap sandboxing;
- missing `bwrap` and user namespace failures are surfaced as capability
  warnings/gaps rather than hidden under generic command failure;
- legacy Landlock remains an explicit fallback path, not the main Raxcell goal.

Raxcell should not call `bwrap` directly once the Linux correction lands. It
should either invoke the Codex helper as a sibling/bundled binary or integrate
the helper crate as a Raxcell binary that preserves the Codex helper CLI shape.

### macOS Seatbelt

Core files:

- `codex-rs/sandboxing/src/seatbelt.rs`
- included SBPL templates in `codex-rs/sandboxing/src/*.sbpl`

Reusable API:

```text
create_seatbelt_command_args(CreateSeatbeltCommandArgsParams { ... })
```

Codex macOS lowering is not equivalent to "any SBPL string plus
`/usr/bin/sandbox-exec`". Raxcell's current TypeScript and Rust SBPL builders
share the OS primitive, but they do not share Codex's lowering semantics. The
macOS correction is to map Raxcell requests into Codex
`FileSystemSandboxPolicy` and `NetworkSandboxPolicy`, then call Codex Seatbelt
lowering.

Raxcell should retain the generated SBPL and `sandbox-exec` argv as backend
facts, but the generator should be Codex-derived.

### Windows native sandbox

Core files:

- `codex-rs/windows-sandbox-rs/src/lib.rs`
- `codex-rs/windows-sandbox-rs/src/resolved_permissions.rs`
- `codex-rs/windows-sandbox-rs/src/token.rs`
- `codex-rs/windows-sandbox-rs/src/acl.rs`
- `codex-rs/windows-sandbox-rs/src/workspace_acl.rs`
- `codex-rs/windows-sandbox-rs/src/wfp.rs`
- `codex-rs/windows-sandbox-rs/src/unified_exec.rs`

Reusable concepts:

- restricted token creation;
- read and write capability roots;
- deny-read and deny-write ACL planning;
- workspace ACL setup;
- Job Object and process capture;
- optional elevated backend;
- WFP network filtering where available;
- `CaptureResult` with `exit_code`, `stdout`, `stderr`, and `timed_out`.

The current `raxcell-windows-runner -> codex sandbox` route is a bridge. It
uses the Codex CLI as a product wrapper around the native backend. The target is
a Raxcell Windows runner or Rust backend that calls `codex-windows-sandbox`
APIs directly and returns `raxcell.runResult.v1`.

### Codex product execution layer

Core file:

- `codex-rs/core/src/exec.rs`

Reusable ideas:

- timeout handling;
- stdout/stderr capture;
- output caps;
- process group cleanup;
- mapping sandbox transform failures into explicit errors.

Discard from Raxcell:

- Codex `Event` / `EventMsg` emission;
- model-visible `ExecToolCallOutput` plumbing;
- session cancellation lifecycle beyond Raxcell request timeout;
- approval escalation;
- prompt, rollout, and agent loop integration.

Raxcell needs an exec runner, but it should be a Raxcell runner around
`SandboxExecRequest`, not a copy of Codex's agent exec pipeline.

### Exec policy

Core files:

- `codex-rs/execpolicy/src/lib.rs`
- child modules under `codex-rs/execpolicy/src/`

Reusable ideas:

- command prefix rule parsing;
- allow/deny decision grammar;
- network rule shape.

Discard for this correction:

- treating execpolicy as the Raxcell policy brain.

Exec policy is useful reference material for upper runtimes. In Raxcell it
should not become an approval or policy matrix layer.

## Extraction Cut Line

Retain or extract:

- `codex-protocol` permission structures needed to express runtime filesystem
  and network boundaries;
- `codex-sandboxing` transformation APIs;
- `codex-linux-sandbox` helper executable and helper logic;
- Codex Seatbelt lowering;
- `codex-windows-sandbox` native execution APIs;
- backend failure and capability probes that describe sandbox availability;
- stdout/stderr/exit/timed-out capture semantics;
- denial/environment-gap classification.

Discard or keep outside Raxcell:

- Codex agent harness;
- model providers and model adapter logic;
- approval UI and reviewer flows;
- app, IDE, TUI, CLI product surface;
- session storage, rollout persistence, compaction, and event streaming;
- prompt/tool intent interpretation;
- Praxis policy group and policy matrix;
- human approval prompts;
- npm publish and release automation.

The cut line is:

```text
Keep:     permission profile -> sandbox transform -> platform execution -> facts/results
Discard:  who decided the request is allowed, how approval was asked, and how the agent/session records it
```

## Raxcell Core API Direction

The Rust core should accept and return Raxcell protocol types. A trait is
acceptable, but an explicit dispatcher is also acceptable if it keeps call sites
clear.

Suggested shape:

```rust
pub trait SandboxBackend {
    fn probe(&self, request: ProbeRequest) -> ProbeResponse;
    fn explain(&self, request: ExplainBackendRequest) -> ExplainBackendResponse;
    fn prepare_run(&self, request: RunRequest) -> PrepareRunResponse;
    fn run(&self, request: RunRequest) -> RunResponse;
}
```

Contract invariants:

- backend input is Raxcell protocol;
- backend output is Raxcell protocol;
- upper-runtime policy grant is an input fact;
- backend never asks for approval;
- `prepare-run` never spawns the command;
- `prepare-run.ok=false` means the sandbox cannot be prepared as requested,
  usually due to environment gap, policy decision requirement, or backend
  unavailability;
- `run.ok=true` with `exitCode != 0` means the command ran in the sandbox and
  exited nonzero;
- `run.ok=false` means backend failure, sandbox construction failure, denial,
  timeout, or environment failure;
- `environmentGap` and `denial` are explicit and public-safe enough for an upper
  runtime to route or display.

Current protocol convergence:

- `RunRequest` is shared by `prepare-run` and `run`.
- `RunRequest.backendPreference` carries the upper runtime's ordered backend
  request. It does not grant policy.
- `RunRequest.policyGrants` carries upper-runtime-issued capability tickets.
  Raxcell does not invent them.
- `PrepareRunResponse` returns `denial`, `environmentGap`, `policyDecision`,
  `filesystemLowering`, `backendArtifacts`, and `capabilityReport` without
  spawning the command.
- `RunResponse` returns the same policy/environment/backend facts plus
  `stdout`, `stderr`, `exitCode`, and `timedOut`.
- TypeScript SDK types and Rust protocol structs use the same camelCase JSON
  fields for these shared objects.

Decision routing rule:

| Fact | Route |
| --- | --- |
| `policyDecision` | Concrete cwd/path capability needs Praxis policy, approval, rewrite, deny, or grant. |
| `environmentGap` | Host/backend/environment fact is unresolved; Praxis can route, ask, rewrite, install, or deny. |
| `denial` | Raxcell/backend refuses or cannot safely proceed; Praxis handles deny/retry/rewrite/fallback outside Raxcell. |
| `run.ok=true` with `exitCode!=0` | Command ran in the sandbox and failed at command level, not sandbox level. |

See `docs/praxis-integration.md` for the complete adapter table and audit
field list.

## Platform Backend Plan

### Linux first

Goal:

```text
TS SDK / CLI shim
  -> Raxcell Rust CLI or worker
  -> Codex SandboxManager
  -> codex-linux-sandbox helper
  -> command
```

First implementation slice:

1. Keep `RaxcellClient` and JSON stdin/stdout stable.
2. Make the npm-facing CLI a shim to the Rust worker for Linux.
3. Ensure Rust Linux prepare uses Codex-derived permission profile lowering and
   returns:

   ```json
   {
     "format": "codex-linux-sandbox-argv",
     "data": {
       "engine": "codex-linux-sandbox"
     }
   }
   ```

4. Stop treating `linux-bubblewrap-argv` as the primary successful artifact.
   It can remain as legacy compatibility only.
5. Probe for the Codex helper and bubblewrap/user namespace readiness, not only
   direct `bwrap`.
6. Keep nonzero command exit as `ok=true + exitCode!=0`.
7. Keep backend/helper failure as `ok=false`.

Linux verification required:

- `probe` ready on this host;
- `prepare-run` returns `codex-linux-sandbox-argv`;
- `run` can create/read/delete inside workspace;
- external read without grant returns required read;
- external write without grant returns required write;
- read grant cannot satisfy write;
- write grant writes a host-visible file;
- command nonzero returns `ok=true + exitCode!=0`;
- helper/backend construction failure returns `ok=false`.

### macOS second

Goal:

```text
Raxcell macOS backend
  -> Codex create_seatbelt_command_args
  -> /usr/bin/sandbox-exec
  -> command
```

Plan:

1. Map Raxcell filesystem and network declarations to Codex
   `FileSystemSandboxPolicy` and `NetworkSandboxPolicy`.
2. Map approved Raxcell `policyGrants` into `AdditionalPermissionProfile`.
3. Call `create_seatbelt_command_args`.
4. Return backend facts:
   - generated SBPL profile;
   - full `sandbox-exec` argv;
   - read/write/runtime roots;
   - network denial state;
   - timeout.
5. On Linux CI/host, keep macOS tests as lowering/unit coverage and smoke
   scripts that fail closed or skip real execution.

### Windows third

Goal:

```text
Raxcell Windows backend
  -> codex-windows-sandbox APIs
  -> restricted token / ACL roots / Job Object / WFP when available
  -> command
```

Plan:

1. Replace `codex sandbox` CLI bridge with direct use of
   `codex-windows-sandbox`.
2. Map Raxcell request and grants into Codex `PermissionProfile`.
3. Use native capture APIs to return stdout, stderr, exit code, and timed-out
   state.
4. Keep elevated and unelevated backend families explicit.
5. Return `raxcell.runResult.v1`; do not create Windows approval logic in the
   runner.

## Protocol And Documentation Convergence

Public method names should remain:

- `probe`
- `explain-backend`
- `prepare-run`
- `run`
- `resolve-profile` if still useful

Docs and fixtures should converge on:

- Raxcell is Codex-derived sandbox core infrastructure for agent runtimes.
- Raxcell does not include Codex agent, harness, session, UI, or approval.
- Raxcell does not decide policy.
- TypeScript SDK is the npm control surface.
- Rust core owns backend execution.
- Linux status: Codex core-backed once npm-facing path routes through Rust.
- macOS status: temporary local SBPL until Codex Seatbelt lowering is used.
- Windows status: temporary Codex CLI bridge until native Codex Windows backend
  APIs are used directly.
- `raxcell/fixtures/policy.praxis-profiles.yaml` is a parseable profile/lowering
  template, not the Raxcell policy brain.

Recommended follow-up docs:

- `docs/architecture.md`
- `docs/codex-extraction-boundary.md`
- `docs/backend-status.md`
- `docs/praxis-integration.md`

This file can be the seed for those documents, but it should remain the
canonical cut-line reference until they exist.

## Risks

- Protocol name drift: `linux-bubblewrap` currently means both the legacy TS
  backend and the desired Codex-helper Rust backend. Keep the compatibility name
  only while making artifacts and docs explicit.
- Overclaiming Codex equivalence: using the same OS primitive is not the same
  as using Codex lowering. This is especially important for macOS.
- CLI-wrapper trap: invoking `codex sandbox` proves compatibility, not core
  extraction. This is the current Windows bridge.
- Dependency size: importing Codex crates wholesale can pull product logic into
  Raxcell. Extract the minimal crates and types needed for sandboxing.
- Platform smoke coverage: Linux can be validated on this host; macOS and
  Windows need fail-closed tests here plus real smoke on native hosts.
- Policy leakage: Raxcell must not grow approval prompts, Praxis policy groups,
  or audit persistence while implementing backend facts.

## Immediate Next Step

Do not add more TypeScript backend logic.

The Linux npm-facing `prepare-run` and `run` path now has a Rust-worker shim
via `RAXCELL_RUST_CLI`; the Rust backend emits `codex-linux-sandbox-argv` and
uses Codex-derived `SandboxManager::transform` instead of locally assembling
the final helper argv.

Success criteria for that step:

- Praxis-facing `RaxcellClient` protocol remains compatible.
- Linux Rust CLI and npm-facing shim live smoke return `codex-linux-sandbox-argv`.
- TS direct-bwrap artifact is marked legacy fallback, not the primary corrected
  path.
- Raxcell continues to return environment/execution facts only.
- Raxcell still does not implement policy, approval, or audit.
