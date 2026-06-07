# Raxcell Rust Workspace

This directory contains the Rust workspace that was extracted during the early Raxcell sandbox work.

The active npm-facing integration path for `0.1.x` is currently the TypeScript package in `raxcell/sdk`. The Rust crates remain useful as protocol and backend research material, especially for future native backend work.

## Crates

- `raxcell-protocol`: JSON protocol types.
- `raxcell-core`: backend dispatch, policy resolution, prepare/run logic.
- `raxcell-cli`: CLI and stdio JSON-RPC worker.

## Current Role

For `@praxis-ai/raxcell@0.1.5`, the executable package path is:

```text
raxcell/sdk -> @praxis-ai/raxcell -> raxcell CLI -> linux-bubblewrap / macOS Seatbelt / Windows runner bridge
```

The Rust workspace is not the published npm CLI. Treat it as a retained lower-level implementation track while the TypeScript package carries the current Praxis/Raxode integration.

## Linux Backend Notes

The Rust workspace contains Linux bubblewrap backend code and fixtures for:

- declared filesystem read/write roots;
- cwd coverage checks;
- explicit policy grants;
- network deny;
- timeout handling;
- filesystem lowering reports;
- backend artifacts with bubblewrap argv.

The npm CLI has the current production-facing Linux behavior, including shell filesystem effect analysis and host-visible writable grants. It also executes macOS Seatbelt on macOS hosts through `/usr/bin/sandbox-exec`.

## Native Backend Notes

macOS Seatbelt and Windows native backend families are protocol-visible in the broader Raxcell contract.

The Rust workspace owns the corrected Linux execution path: Linux requests lower through typed Codex-derived permission profiles, `SandboxManager::transform`, and the `raxcell-codex-linux-sandbox` helper. The npm CLI can delegate Linux protocol calls to this Rust worker with `RAXCELL_RUST_CLI`; its old direct-bwrap path is legacy fallback. macOS and Windows remain protocol-visible follow-up backends: macOS still needs Codex Seatbelt lowering wiring, and Windows execution is delegated to the `raxcell-windows-runner` contract until the native Codex sandbox core is wired directly.

## Verify

```bash
cargo test --manifest-path raxcell/Cargo.toml
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- probe --stdin < raxcell/fixtures/probe.auto.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- prepare-run --stdin < raxcell/fixtures/prepare-run.linux-bubblewrap.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.linux-bubblewrap.json
```
