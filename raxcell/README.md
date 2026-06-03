# Raxcell Rust Workspace

This workspace contains the Rust implementation of the Raxcell execution-enforcement sandbox SDK.

## Crates

- `raxcell-protocol`: stable JSON protocol types.
- `raxcell-core`: backend dispatch, policy resolution, prepare/run logic.
- `raxcell-cli`: CLI and stdio JSON-RPC worker.

## Linux Backend

The `linux-bubblewrap` backend is usable in `0.1.0`.

It supports:

- declared filesystem read/write roots;
- network deny;
- timeout;
- cwd coverage checks;
- explicit `policyGrants`;
- `filesystemLowering` reports;
- `backendArtifacts` with full bubblewrap argv from `prepareRun`.

## Native Backends

macOS Seatbelt and Windows native backend families are protocol-visible.

Current behavior:

- fail closed on unsupported hosts;
- source-level lowering artifact models exist for future native runner attachment;
- no macOS or Windows command execution is enabled in this Linux-first `0.1.0` stage.

## Verify

```bash
cargo test --manifest-path raxcell/Cargo.toml
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- probe --stdin < raxcell/fixtures/probe.auto.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- prepare-run --stdin < raxcell/fixtures/prepare-run.linux-bubblewrap.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.linux-bubblewrap.json
```
