# Raxcell

Raxcell is the execution enforcement sandbox SDK extracted from the Codex fork.

Stage 2 keeps the protocol, CLI/worker shape, and backend capability reporting while adding a Linux bubblewrap runner. macOS Seatbelt and Windows native backends remain first-class families and fail closed on non-matching hosts until their runners are attached.

Raxcell core owns enforcement facts and execution boundaries. Upper runtimes own governance, approval, policy matrices, human gates, and model behavior control.

## Smoke Commands

Run tests:

```bash
cargo test --manifest-path raxcell/Cargo.toml
```

Probe current host:

```bash
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- probe --stdin < raxcell/fixtures/probe.auto.json
```

Run fixture through Linux bubblewrap:

```bash
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.linux-bubblewrap.json
```

Run fixture in explicit fail-closed observation mode:

```bash
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.fail-closed.json
```
