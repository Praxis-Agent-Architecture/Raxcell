# Raxcell Stage 2 Backend Copy/Rename Plan

Status: Implemented on `dev/raxcell`; ready for Stage 3 semantic planning.

## Goal

Turn the Stage 1 skeleton into a real execution backend surface:

- Keep Linux, macOS, and Windows as first-class backend families.
- Make Linux `raxcell run` execute through a real bubblewrap backend on this host.
- Keep macOS Seatbelt and Windows native sandbox as source-level first-class backends, returning explicit not-ready/mismatch on this Linux host.
- Copy/rename sandbox concepts into `raxcell/` instead of long-term depending on Codex product crates.
- Delete large non-sandbox Codex product surfaces after Raxcell owns its Stage 2 backend surface.

## User Decisions

- Backend extraction strategy: copy/rename.
- Stage 2 run scope: three-platform run abstraction; Linux must run locally, macOS/Windows remain first-class but are not locally executable on Ubuntu.
- Deletion policy: direct deletion is allowed after the stage plan explicitly names the deletion set.

## Non-Negotiable Boundaries

- Raxcell core still does not own approval, policy matrix, human gate, model behavior control, Praxis BaseTool semantics, Codex turn lifecycle, or model/tool UI behavior.
- `host-observed` must not silently execute when isolation was requested.
- `workspace-rollback` remains optional fallback, not isolation.
- macOS/Windows unsupported-on-this-host responses must be explicit and structured.
- No deleted Codex product code should be needed for `cargo test --manifest-path raxcell/Cargo.toml`.

## Files To Create Or Modify

Modify:

- `raxcell/crates/protocol/src/types.rs`
  - Add run backend status fields only if needed by the runner.
- `raxcell/crates/protocol/src/types_tests.rs`
  - Add serialization checks for run event/status if fields change.
- `raxcell/crates/core/src/lib.rs`
  - Export new real runner.
- `raxcell/crates/core/src/run.rs`
  - Replace CLI path from always fail-closed to backend-dispatched run.
- `raxcell/crates/core/src/run_tests.rs`
  - Keep fail-closed tests for unsupported/mismatch paths.
- `raxcell/crates/cli/src/main.rs`
  - Call real `run` instead of `run_fail_closed`.
- `raxcell/crates/cli/src/jsonrpc.rs`
  - Call real `run`.
- `raxcell/README.md`
  - Update Stage 2 smoke commands.

Create:

- `raxcell/crates/core/src/backends/mod.rs`
- `raxcell/crates/core/src/backends/linux_bubblewrap.rs`
- `raxcell/crates/core/src/backends/macos_seatbelt.rs`
- `raxcell/crates/core/src/backends/windows_native.rs`
- `raxcell/crates/core/src/backends/linux_bubblewrap_tests.rs`
- `raxcell/fixtures/run.linux-bubblewrap.json`

Delete after the new Raxcell Stage 2 backend passes verification:

- `codex-cli/`
- `sdk/`
- `docs/`
- `scripts/`
- `tools/`
- `third_party/`
- `.github/`
- `.devcontainer/`
- `.vscode/`
- `patches/`
- Top-level Codex product metadata files that are not needed by Raxcell:
  - `announcement_tip.toml`
  - `cliff.toml`
  - `flake.lock`
  - `flake.nix`
  - `MODULE.bazel`
  - `MODULE.bazel.lock`
  - `BUILD.bazel`
  - `defs.bzl`
  - `rbe.bzl`
  - `workspace_root_test_launcher.bat.tpl`
  - `workspace_root_test_launcher.sh.tpl`
- `codex-rs/` after the Raxcell backend no longer imports or shells out to Codex crates.

Keep:

- `.git/`
- `AGENTS.md`
- `LICENSE`
- `NOTICE`
- `README.md` until replaced by Raxcell README at repo root.
- `SECURITY.md` until replaced.
- `package.json` and `pnpm-workspace.yaml` until the Raxcell npm package/workspace replaces them.
- `raxcell/`
- `specs/`

## Execution Steps

1. Add backend modules under `raxcell/crates/core/src/backends/`.
2. Implement Linux bubblewrap command construction:
   - require `bwrap`;
   - bind the command cwd as writable;
   - bind system roots read-only where present;
   - use `--unshare-net` when `network = "deny"`;
   - capture stdout/stderr/exit status;
   - return structured denial when bwrap is missing or execution fails before spawn.
3. Add macOS and Windows backend modules that preserve first-class run abstraction but return explicit unsupported-on-current-host results on Linux.
4. Change `run` from Stage 1 fail-closed-only to backend dispatch:
   - Linux on Linux with ready bubblewrap: execute;
   - macOS on non-macOS: fail closed with `CAPABILITY_MISMATCH`;
   - Windows on non-Windows: fail closed with `CAPABILITY_MISMATCH`;
   - host-observed: fail closed unless future caller explicitly requests observation-only mode.
5. Update CLI and JSON-RPC worker to call the backend-dispatched run.
6. Add Linux fixture and smoke it.
7. Run:
   - `cargo test --manifest-path raxcell/Cargo.toml`
   - `cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.linux-bubblewrap.json`
   - `pnpm --dir raxcell/sdk build && pnpm --dir raxcell/sdk test`
   - `git diff --check -- specs/raxcell raxcell`
8. Code review:
   - check no approval/governance/model behavior logic entered `raxcell/`;
   - check macOS/Windows are not hidden behind Linux-only code;
   - check host-observed does not execute silently;
   - check run really uses bubblewrap for Linux fixture.
9. Delete the approved non-sandbox Codex product surfaces.
10. Re-run:
    - `cargo test --manifest-path raxcell/Cargo.toml`
    - `pnpm --dir raxcell/sdk build && pnpm --dir raxcell/sdk test`
    - `git status --short`

## Stage 2 Completion Criteria

- `raxcell run` can execute a simple Linux command through bubblewrap on this host.
- macOS and Windows backend families remain present in protocol and runner dispatch.
- Unsupported platform attempts return structured fail-closed responses.
- Large Codex product surfaces listed above are deleted.
- Raxcell tests pass after deletion.
- No `codex-rs/**` dependency is required for the Raxcell Stage 2 tests.

## Implementation Evidence

Completed changes:

- Added `raxcell/crates/core/src/backends/` with Linux bubblewrap, macOS Seatbelt, and Windows native backend modules.
- Added `RunRequest.backendPreference` so callers can request a backend family without Raxcell owning approval or policy decisions.
- Changed CLI and JSON-RPC `run` paths to use backend dispatch.
- Made Linux `run` execute through `bwrap`, bind the command cwd writable, bind runtime roots read-only, deny network with `--unshare-net`, clear inherited environment, capture output, and enforce `resources.timeoutMs`.
- Kept `host-observed` observation-only: it refuses isolated execution and does not silently execute on the host.
- Replaced the root npm workspace with the minimal Raxcell workspace pointing at `raxcell/sdk`.
- Deleted the Stage 2 approved Codex product surfaces, including `codex-rs/`, after backend verification.

Verification run after deletion:

```bash
cargo test --manifest-path raxcell/Cargo.toml
pnpm install && pnpm build:sdk && pnpm test:sdk
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.linux-bubblewrap.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.fail-closed.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --json '{"kind":"raxcell.run.v1","backendPreference":["linux-bubblewrap"],"action":{"actionId":"timeout-smoke","ownerRuntime":"example-runtime","intentLabel":"opaque","metadata":{}},"command":{"argv":["/usr/bin/sleep","1"],"cwd":".","env":{},"stdin":null},"enforcement":{"profile":"workspace-write-no-network","filesystem":{"read":["."],"write":["."]},"network":"deny","process":{"spawn":true},"resources":{"timeoutMs":10}},"fallback":{"mode":"none"}}'
git diff --check -- specs/raxcell raxcell package.json pnpm-workspace.yaml pnpm-lock.yaml
```

Remaining semantic boundary for Stage 3:

- Define the declarative policy pack grammar and merge model without moving approval or policy matrix decisions into Raxcell core.
- Decide how strict filesystem declarations should be lowered into each backend beyond the current Stage 2 cwd bind.
- Decide the published SDK surface split between Rust CLI binary, TypeScript facade, and future runtime adapters.
