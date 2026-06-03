# Raxcell

Raxcell is an execution enforcement sandbox SDK extracted from the Codex fork.

The goal is to provide a reusable sandbox layer for agent harnesses, runtimes, SDKs, and platforms. Raxcell core owns execution boundaries and capability facts. Upper runtimes own approval, policy matrices, human gates, tool semantics, and model behavior.

## Current Status

Stage 2 is implemented:

- Linux `run` executes through bubblewrap on this host.
- macOS Seatbelt and Windows native backend families are first-class protocol and dispatch targets, but fail closed on non-matching hosts until their runners are attached.
- `host-observed` remains observation-only and does not silently execute isolated requests on the host.
- The root npm workspace points at the Raxcell TypeScript SDK facade in `raxcell/sdk`.
- Large Codex product surfaces have been removed from this branch.

Stage 3 is implemented:

- Policy packs resolve enforcement-only profiles.
- JSON, YAML, and TOML policy pack files deserialize into the same protocol shape.
- `resolve-profile` lowers profile presets and caller-supplied common root variables into explicit enforcement declarations.

Stage 4 is implemented:

- Linux bubblewrap consumes declared read/write filesystem roots.
- Missing declared roots fail closed before execution.
- `command.cwd` outside declared roots returns `POLICY_DECISION_REQUIRED`.
- JSON-RPC worker emits `policy.decisionRequired` with typed JSON string data.
- Upper runtime decisions are passed back as explicit `policyGrants`.

Stage 5 is implemented:

- Successful Linux run responses include `filesystemLowering`.
- Nested read/write roots normalize to minimal mount authority.
- Backend runtime roots are reported explicitly and filtered when declared roots cover them.

Stage 6 backend control surface is in progress:

- `prepare-run` / `prepareRun` dry-runs backend selection, capability checks, cwd/root lowering, and policy-decision handoff without spawning the command.
- Linux prepare returns the same `filesystemLowering` report shape as successful run.
- Linux prepare returns `backendArtifacts` with the bubblewrap argv artifact for upper-runtime audit.
- macOS and Windows prepare fail closed until native lowering is attached.

Stage 7 backend explain surface is in progress:

- `explain-backend` / `explainBackend` returns selected backend capability facts, operation schemas, isolation primitives, runtime roots, and public-safe limits.
- Linux explanation includes bubblewrap primitives and backend runtime roots.
- `prepareRun` is described as no-process; `run` is described as process-spawning.

Stage 8 native backend lowering is in progress:

- macOS Seatbelt has a testable lowering artifact builder for SBPL profile text, `/usr/bin/sandbox-exec` args, network deny, and shared filesystem lowering reports.
- Windows native has a testable lowering artifact builder for token mode, ACL-style roots, network block, and shared filesystem lowering reports.
- macOS/Windows `run` and `prepareRun` still fail closed on unsupported hosts until native runners are attached.

## Repository Layout

- `raxcell/crates/protocol`: stable JSON protocol types shared by CLI, SDKs, and runtimes.
- `raxcell/crates/core`: capability probe and execution backend dispatch.
- `raxcell/crates/cli`: JSON CLI and stdio JSON-RPC worker.
- `raxcell/sdk`: TypeScript facade package.
- `raxcell/fixtures`: smoke-test JSON requests.
- `specs/raxcell`: extraction specs and stage plans.

## Verify

```bash
cargo test --manifest-path raxcell/Cargo.toml
pnpm install
pnpm build:sdk
pnpm test:sdk
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.linux-bubblewrap.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.cwd-policy-required.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.cwd-policy-granted.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- prepare-run --stdin < raxcell/fixtures/prepare-run.linux-bubblewrap.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- explain-backend --stdin < raxcell/fixtures/explain-backend.linux-bubblewrap.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- resolve-profile --stdin < raxcell/fixtures/resolve.workspace.json
```

This repository is licensed under the [Apache-2.0 License](LICENSE).
