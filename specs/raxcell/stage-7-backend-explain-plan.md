# Raxcell Stage 7 Backend Explain Plan

Status: Confirmed; backend explain/schema first.

## Goal

Expose a backend explanation surface that upper runtimes can use to inspect Raxcell's backend capabilities, operation contracts, and enforcement primitives before connecting strategy middleware.

Stage 7 does not execute commands, grant policy, ask humans, rewrite requests, or attach upstream strategy middleware.

## User Decision Captured

- Continue backend-first work with backend explain/schema.
- Use this surface later for control planes, audit UI, and upstream strategy middleware integration.

## Proposed Surface

Add `explainBackend`.

Input:

```json
{
  "kind": "raxcell.explainBackend.v1",
  "platform": "auto",
  "backendPreference": ["linux-bubblewrap"]
}
```

Output:

```json
{
  "kind": "raxcell.explainBackendResult.v1",
  "selectedBackend": "linux-bubblewrap",
  "probe": {},
  "operations": [],
  "explanation": {
    "backend": "linux-bubblewrap",
    "hostPlatforms": ["linux"],
    "isolationPrimitives": [],
    "runtimeRoots": [],
    "limits": [],
    "publicSafeMessage": ""
  }
}
```

## Semantics

- `explainBackend` is descriptive and side-effect-free.
- It reuses backend selection and capability probe so the selected backend matches `run` and `prepareRun`.
- `operations` describes Raxcell method contracts:
  - `probe`
  - `resolveProfile`
  - `prepareRun`
  - `run`
  - `explainBackend`
- `explanation` describes backend enforcement primitives and known limits.
- Linux may expose backend runtime roots using the shared `LoweredRoot` shape.
- macOS and Windows may expose declared future primitives even while native runners are not attached on this Linux host.

## Implementation Steps

1. Add protocol types:
   - `ExplainBackendRequest`
   - `ExplainBackendResponse`
   - `BackendExplanation`
   - `OperationSchema`
2. Add `raxcell_core::explain_backend`.
3. Add Linux backend explanation with bubblewrap primitives and runtime roots.
4. Add macOS, Windows, host-observed, and external backend explanations.
5. Add CLI command `explain-backend --stdin`.
6. Add JSON-RPC worker method `explainBackend`.
7. Add TypeScript SDK `explainBackend()`.
8. Add fixture `explain-backend.linux-bubblewrap.json`.
9. Add tests for protocol wire names, worker method, core selection, SDK types, and CLI smoke.

## Completion Criteria

- `explainBackend` works through protocol, core, CLI, worker, and SDK.
- Linux explanation includes bubblewrap primitives and runtime roots.
- Operation schema describes `prepareRun` as no-process and `run` as process-spawning.
- No approval, human gate, model behavior, or upstream strategy logic enters Raxcell core.

## Implementation Evidence

Implemented:

- Added protocol types:
  - `ExplainBackendRequest`
  - `ExplainBackendResponse`
  - `BackendExplanation`
  - `OperationSchema`
- Added `raxcell_core::explain_backend`.
- Added Linux backend explanation with bubblewrap primitives and runtime roots.
- Added macOS, Windows, host-observed, and external backend explanations.
- Added CLI command `explain-backend --stdin`.
- Added JSON-RPC worker method `explainBackend`.
- Added TypeScript SDK `explainBackend()` and explain response/request types.
- Added fixture `raxcell/fixtures/explain-backend.linux-bubblewrap.json`.

Verified:

- `cargo fmt --manifest-path raxcell/Cargo.toml --all`
- `cargo test --manifest-path raxcell/Cargo.toml`
  - worker: 7 passed
  - core: 25 passed
  - protocol: 9 passed
- `pnpm install && pnpm build:sdk && pnpm test:sdk`
  - TypeScript build passed
  - SDK tests: 6 passed
- `cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- explain-backend --stdin < raxcell/fixtures/explain-backend.linux-bubblewrap.json`
  - returned `raxcell.explainBackendResult.v1`
  - selected `linux-bubblewrap`
  - included `prepareRun` with `no-process-spawn`
  - included `run` with `spawns-process`
  - included Linux bubblewrap primitives and runtime roots

Next semantic boundary:

- Decide whether to start wiring `prepareRun` + `explainBackend` into the upstream strategy middleware, continue backend-first with native macOS/Windows lowering, or refine explain/schema into versioned JSON Schema artifacts.
