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
raxcell/sdk -> @praxis-ai/raxcell -> raxcell CLI -> linux-bubblewrap
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

The npm CLI has the current production-facing Linux behavior, including shell filesystem effect analysis and host-visible writable grants.

## Native Backend Notes

macOS Seatbelt and Windows native backend families are protocol-visible in the broader Raxcell contract.

The Rust workspace includes source-level lowering concepts for native backends, but `0.1.x` npm releases do not execute macOS or Windows native runners yet.

## Verify

```bash
cargo test --manifest-path raxcell/Cargo.toml
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- probe --stdin < raxcell/fixtures/probe.auto.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- prepare-run --stdin < raxcell/fixtures/prepare-run.linux-bubblewrap.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.linux-bubblewrap.json
```
