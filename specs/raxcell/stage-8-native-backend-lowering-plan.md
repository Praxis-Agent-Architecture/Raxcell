# Raxcell Stage 8 Native Backend Lowering Plan

Status: Confirmed; native backend direction.

## Goal

Add source-level native lowering models for macOS Seatbelt and Windows native sandboxing so Raxcell can evolve beyond Linux bubblewrap while still failing closed on unsupported hosts.

This stage does not pretend macOS or Windows runners are executable on Linux. It adds deterministic lowering artifacts and tests that can later be connected to platform runners.

## Codex Source Facts

- macOS Codex sandboxing lives in `codex-rs/sandboxing/src/seatbelt.rs`.
  - It uses `/usr/bin/sandbox-exec`, not PATH lookup.
  - It builds an SBPL policy with file read/write parameters, protected metadata carveouts, network policy, Unix socket policy, and optional platform defaults.
  - Tests assert generated policy sections and `-D...` parameters.
- Windows Codex sandboxing lives primarily in `codex-rs/windows-sandbox-rs`.
  - It resolves runtime permissions into Windows-local readable/writable roots.
  - It chooses restricted token mode based on whether writable roots exist.
  - It uses ACL/capability SIDs for filesystem enforcement and WFP/firewall setup for network blocking.
  - Elevated mode sends a framed spawn request to a runner process; legacy mode can spawn directly with restricted token setup.

## Stage 8 Scope

Implement:

- macOS Seatbelt lowering artifact:
  - command path `/usr/bin/sandbox-exec`;
  - generated SBPL profile text;
  - declared read/write roots in shared `FileSystemLoweringReport`;
  - network deny marker.
- Windows native lowering artifact:
  - selected backend family;
  - token mode: `read-only-capability` or `writable-roots-capability`;
  - ACL-style planned read/write roots;
  - network block marker;
  - shared `FileSystemLoweringReport`.

Defer:

- Actual macOS process execution.
- Actual Windows ACL/token/WFP application.
- Elevated runner IPC.
- Upstream strategy middleware integration.

## Completion Criteria

- macOS and Windows backend modules contain testable lowering artifact builders.
- Builders fail closed when declared roots are missing or cwd is outside effective roots.
- Builders reuse the same `policyDecision` handoff shape for cwd coverage.
- Linux host behavior remains unchanged: macOS/Windows `run` and `prepareRun` still return mismatch/unavailable instead of executing.
- Tests cover generated native artifacts without requiring macOS or Windows.

## Implementation Evidence

Implemented:

- Added `MacosSeatbeltLowering` and `lower_for_seatbelt`.
  - Produces `/usr/bin/sandbox-exec`.
  - Produces `-p <profile>` args.
  - Produces SBPL-like profile sections for default deny, process allowance, read roots, write roots, and network deny/allow.
  - Produces shared `FileSystemLoweringReport`.
- Added `WindowsNativeLowering` and `lower_for_windows_native`.
  - Produces selected backend family.
  - Produces token mode: `ReadOnlyCapability` or `WritableRootsCapability`.
  - Produces ACL-style roots from shared declared roots.
  - Produces network block marker.
  - Produces shared `FileSystemLoweringReport`.
- Added macOS and Windows native lowering tests under `raxcell/crates/core/src/backends`.
- Kept platform execution unchanged: these builders are source-level artifacts and are not wired to make macOS/Windows runnable on this Linux host.

Verified:

- `cargo fmt --manifest-path raxcell/Cargo.toml --all`
- `cargo test --manifest-path raxcell/Cargo.toml`
  - worker: 7 passed
  - core: 30 passed
  - protocol: 9 passed
- `pnpm install && pnpm build:sdk && pnpm test:sdk`
  - TypeScript build passed
  - SDK tests: 6 passed

Debug note:

- First Rust test run exposed a bad macOS test fixture: the declared write root did not exist, so the builder correctly failed closed before cwd coverage. The test fixture now creates the declared write root before asserting `POLICY_DECISION_REQUIRED`.

Next semantic boundary:

- Decide whether native lowering artifacts should become protocol-visible `prepareRun` artifacts, or remain internal until platform runners are attached.
