# Raxcell Rust Workspace

This directory contains the Rust workspace that was extracted during the early Raxcell sandbox work.

The active npm-facing integration path for `0.1.x` is currently the TypeScript package in `raxcell/sdk`. The Rust crates remain useful as protocol and backend research material, especially for future native backend work.

## Crates

- `raxcell-protocol`: JSON protocol types.
- `raxcell-core`: backend dispatch, policy resolution, prepare/run logic.
- `raxcell-cli`: CLI and stdio JSON-RPC worker.

## Current Role

For `@praxis-ai/raxcell@0.1.5`, the npm-facing package path is:

```text
raxcell/sdk -> @praxis-ai/raxcell -> raxcell CLI facade
  -> Rust worker for Codex core-backed Linux
  -> legacy TypeScript fallback for direct bwrap / local SBPL
  -> Windows runner bridge/planned path
```

The Rust workspace is not the package facade, but it owns the corrected Linux execution path and the protocol shapes that must stay aligned with the TypeScript SDK. Treat the TypeScript package as the npm control surface and the Rust crates as the lower-level sandbox/protocol track.

## Linux Backend Notes

The Rust workspace contains Linux backend code and fixtures for:

- declared filesystem read/write roots;
- cwd coverage checks;
- explicit policy grants;
- network deny;
- timeout handling;
- filesystem lowering reports;
- backend artifacts with Codex Linux helper argv.

The corrected Linux path lowers through typed Codex-derived permission profiles, `SandboxManager::transform`, and the `raxcell-codex-linux-sandbox` helper. Successful Linux artifacts should use `codex-linux-sandbox-argv`. The old `linux-bubblewrap-argv` artifact belongs to the legacy TypeScript direct-bwrap fallback only.

## Native Backend Notes

macOS Seatbelt and Windows native backend families are protocol-visible in the broader Raxcell contract.

The Rust workspace owns the corrected Linux execution path: Linux requests lower through typed Codex-derived permission profiles, `SandboxManager::transform`, and the `raxcell-codex-linux-sandbox` helper. The npm CLI can delegate Linux protocol calls to this Rust worker with `RAXCELL_RUST_CLI`; its old direct-bwrap path is legacy fallback. macOS and Windows remain protocol-visible follow-up backends: macOS still needs Codex Seatbelt lowering wiring, and Windows execution is delegated to the `raxcell-windows-runner` contract until the native Codex sandbox core is wired directly.

Backend status should be described conservatively:

- Linux: Codex core-backed when the Rust worker path returns `codex-linux-sandbox-argv`.
- macOS: planned/partial until Codex Seatbelt lowering is wired.
- Windows: bridge/planned until direct native `windows-sandbox-rs` API smoke passes.

Raxcell owns probe, `prepare-run` facts, sandboxed run, stdout/stderr/exitCode/timedOut, denial, environment gaps, and backend artifacts. Upper runtimes such as Praxis own policy decisions, approval prompts, audit persistence, fallback, retry, rewrite, and deny behavior.

`raxcell/fixtures/policy.praxis-profiles.yaml` is a parseable Praxis-style profile template for lowering tests and examples. It is not the Raxcell policy brain; `policyGrants` are still upper-runtime-issued capability tickets that Raxcell validates and lowers.

## Verify

```bash
cargo test --manifest-path raxcell/Cargo.toml
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- probe --stdin < raxcell/fixtures/probe.auto.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- prepare-run --stdin < raxcell/fixtures/prepare-run.linux-bubblewrap.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.linux-bubblewrap.json
```
