# Raxcell Stage 6 Backend Control Plane Plan

Status: Confirmed; backend-first implementation.

## Goal

Expose a backend-first control surface that lets an upper runtime inspect what Raxcell would enforce before executing a command.

Stage 6 focuses on backend preparation, not upstream strategy middleware. The upper runtime may later consume this surface to decide whether to grant, deny, ask a human, or rewrite policy, but Raxcell core does not make those decisions.

## User Decision Captured

- Do backend first.
  - Complete the backend control surface before connecting upstream policy middleware.
  - After the backend surface is usable, integrate it with the upstream strategy middleware and run end-to-end tests.

## Proposed Surface

Add `prepareRun` as a dry-run counterpart to `run`.

Input:

- Reuse `RunRequest`.
- The command is never spawned.
- Backend selection, capability probe, filesystem lowering, cwd coverage checks, and policy-decision handoff still run.

Output:

```json
{
  "kind": "raxcell.prepareRunResult.v1",
  "ok": true,
  "backend": "linux-bubblewrap",
  "denial": null,
  "policyDecision": null,
  "filesystemLowering": {
    "declaredRoots": [],
    "runtimeRoots": [],
    "policyGrants": [],
    "warnings": []
  },
  "capabilityReport": {}
}
```

## Semantics

- `ok: true` means the selected backend can prepare an enforceable execution surface for the request.
- `ok: false` with `denial` means the backend cannot prepare this request.
- `ok: false` with `policyDecision` means the upper runtime must decide before Raxcell can prepare or run.
- `filesystemLowering` is present when lowering completed.
- No process is spawned, and no command output is produced.

## Implementation Steps

1. Add protocol type `PrepareRunResponse`.
2. Add `raxcell_core::prepare_run`.
3. Add Linux bubblewrap prepare support by reusing existing lowering.
4. Add fail-closed prepare support for macOS, Windows, host-observed, and external backends.
5. Add CLI command `prepare-run --stdin`.
6. Add JSON-RPC worker method `prepareRun`.
7. Add TypeScript SDK `prepareRun()`.
8. Add fixture `prepare-run.linux-bubblewrap.json`.
9. Add tests for:
   - protocol wire names;
   - CLI worker method;
   - Linux prepare includes `filesystemLowering`;
   - prepare returns `POLICY_DECISION_REQUIRED` for cwd outside declared roots;
   - SDK type surface.

## Completion Criteria

- `prepareRun` works through CLI, worker, core, protocol, and TypeScript SDK.
- Successful Linux prepare includes `filesystemLowering`.
- Policy-decision-needed prepare returns the same handoff shape as run.
- No command is executed during prepare.
- No approval, human gate, model behavior, or upstream strategy logic enters Raxcell core.

## Implementation Evidence

Implemented:

- Added protocol type `PrepareRunResponse`.
- Added `raxcell_core::prepare_run`.
- Added Linux bubblewrap prepare support by reusing existing lowering without spawning the command.
- Added fail-closed prepare responses for macOS, Windows, host-observed, and external backends.
- Added CLI command `prepare-run --stdin`.
- Added JSON-RPC worker method `prepareRun`.
- Added TypeScript SDK `prepareRun()` and `PrepareRunResponse`.
- Added fixture `raxcell/fixtures/prepare-run.linux-bubblewrap.json`.

Verified:

- `cargo fmt --manifest-path raxcell/Cargo.toml --all`
- `cargo test --manifest-path raxcell/Cargo.toml`
  - worker: 6 passed
  - core: 23 passed
  - protocol: 8 passed
- `pnpm install && pnpm build:sdk && pnpm test:sdk`
  - TypeScript build passed
  - SDK tests: 5 passed
- `cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- prepare-run --stdin < raxcell/fixtures/prepare-run.linux-bubblewrap.json`
  - returned `ok: true`
  - included `filesystemLowering`
  - did not execute the fixture command, which would have exited `99` if spawned
- `cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- prepare-run --stdin < raxcell/fixtures/run.cwd-policy-required.json`
  - returned `ok: false`
  - returned `POLICY_DECISION_REQUIRED`
  - returned `policyDecision.reason: cwd-outside-declared-roots`
- Boundary scan over `raxcell/crates`, `raxcell/sdk/src`, `raxcell/fixtures`, `README.md`, and this plan found strategy/approval/human/model language only in boundary documentation, not core implementation.

Next semantic boundary:

- Decide whether the next backend-first stage should attach native macOS/Windows lowering, add backend schema/explain metadata, or start wiring this prepare surface into the upstream strategy middleware.
