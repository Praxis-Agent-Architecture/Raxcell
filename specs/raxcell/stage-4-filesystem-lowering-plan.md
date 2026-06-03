# Raxcell Stage 4 Filesystem Lowering Plan

Status: Initial implementation complete; ready for Stage 5 mount semantics and cross-platform lowering decisions.

## Goal

Make backend execution consume resolved filesystem declarations instead of using the Stage 2 Linux runner's temporary cwd-only writable bind.

Stage 4 is about backend lowering, not approval ownership. Raxcell should enforce what it can prove locally and emit structured facts when an upper policy layer must decide.

## User Decisions Captured

- Missing declared roots: fail closed.
  - If a declared `read` or `write` root does not exist on the host, Raxcell refuses execution.
  - Raxcell should not create missing roots by default.
- Undeclared path access: upstream policy controls this.
  - Raxcell should emit a policy-facing event or structured fact rather than silently widening the sandbox.
  - Raxcell core must not decide approval.
- `command.cwd` outside declared roots: upstream policy controls this.
  - Raxcell should emit a policy-facing event or structured fact rather than auto-adding cwd.
  - Raxcell core must not approve the expansion itself.
- Policy handoff shape: both denial and event.
  - One-shot CLI returns a `POLICY_DECISION_REQUIRED` denial.
  - Worker responses include a `policy.decisionRequired` event plus the fail-closed result.
- Policy handoff event data: typed JSON string.
  - Keep `RaxcellEvent.data` as `Option<String>`.
  - The string contains a stable JSON object that upper runtimes can parse.
- Future upper policy decision input: explicit grants.
  - `RunRequest` should carry `policyGrants`.
  - Grants prove the upper runtime already approved a specific cwd/root expansion.
  - Raxcell verifies grants but does not decide approval itself.

## Boundary Interpretation

Raxcell core can emit:

- facts;
- denials;
- decision-required events;
- capability reports;
- precise missing/unsupported path reports.

Raxcell core must not emit:

- approval prompts;
- human gate UI state;
- command allow/deny policy decisions;
- model behavior instructions;
- Praxis-specific policy matrix decisions.

In plain terms: Raxcell can say "this run needs an upper policy decision because cwd is outside declared roots." It must not say "approved" or "denied by policy" unless the denial is a local enforcement fact such as a missing root or unavailable backend.

## Proposed Filesystem Lowering Semantics

Linux bubblewrap lowering:

- Mount declared `write` roots read-write.
- Mount declared `read` roots read-only unless the same root is already writable.
- Mount required runtime roots read-only.
- Mount `/proc`, `/dev`, and temporary runtime scratch paths only as needed by the backend.
- Do not bind the command cwd separately unless it is covered by a declared read/write root or an upper policy decision is supplied in a future request.
- Reject missing declared roots before spawning `bwrap`.
- Preserve `--unshare-net` when network is `deny`.

macOS Seatbelt lowering:

- Keep the same resolved read/write root model.
- Compile roots into Seatbelt file read/write permissions when the runner is attached.
- On non-macOS hosts, continue structured fail-closed mismatch.

Windows native lowering:

- Keep the same resolved read/write root model.
- Lower roots into Windows native sandbox ACL/token/firewall behavior when the runner is attached.
- On non-Windows hosts, continue structured fail-closed mismatch.

## Event/Protocol Work Needed

Stage 4 needs a protocol shape for upper-policy handoff.

Candidate event:

```json
{
  "kind": "raxcell.event.v1",
  "requestId": "run-1",
  "event": "policy.decisionRequired",
  "data": "{\"reason\":\"cwd-outside-declared-roots\",\"path\":\"/workspace/project\"}"
}
```

Candidate denial:

```json
{
  "code": "POLICY_DECISION_REQUIRED",
  "message": "command cwd is outside declared filesystem roots; upper policy decision required",
  "publicSafe": true
}
```

Confirmed naming:

- Add `DenialCode::PolicyDecisionRequired`, serialized as `POLICY_DECISION_REQUIRED`.
- Add worker event name `policy.decisionRequired`.
- Keep event `data` as a typed JSON string.
- Add `RunRequest.policyGrants` for future upper-policy grants.

## Implementation Steps

1. Add policy handoff code/event shape to protocol.
2. Add filesystem coverage checks:
   - declared root exists;
   - cwd is covered by read or write roots;
   - write roots are not silently inferred from cwd.
3. Change Linux bubblewrap args to bind declared roots instead of always binding cwd writable.
4. Add fixtures:
   - successful declared read/write root run;
   - missing root fail-closed;
   - cwd outside roots policy handoff;
   - host-observed still refuses isolated execution.
5. Add tests around path coverage, missing roots, and bwrap argument construction.
6. Verify Linux smoke and no-governance boundary scan.

## Completion Criteria

- Linux runner consumes resolved filesystem declarations.
- Missing declared roots fail closed before execution.
- Cwd/root conflicts produce upper-policy handoff facts rather than silent auto-expansion.
- No approval, human gate, policy matrix, or runtime-specific decision logic enters Raxcell core.

## Implementation Evidence

Completed changes:

- Added `DenialCode::PolicyDecisionRequired`, serialized as `POLICY_DECISION_REQUIRED`.
- Added `PolicyGrant` and `RunRequest.policyGrants`.
- Added `PolicyDecisionRequired` and optional `RunResponse.policyDecision`.
- Changed Linux bubblewrap lowering to:
  - canonicalize declared `read` and `write` roots;
  - fail closed when declared roots are missing;
  - bind declared `write` roots read-write;
  - bind declared `read` roots read-only unless the same root is already writable;
  - require `command.cwd` to be covered by declared roots or explicit `policyGrants`;
  - return `POLICY_DECISION_REQUIRED` when cwd needs an upper policy decision.
- Changed JSON-RPC worker `run` payloads to emit `policy.decisionRequired` events with typed JSON string `data`.
- Added TypeScript SDK `RunRequest`, `RunResponse`, `PolicyGrant`, and `PolicyDecisionRequired` types plus `RaxcellClient.run()`.
- Added fixtures:
  - `raxcell/fixtures/run.missing-root.json`
  - `raxcell/fixtures/run.cwd-policy-required.json`
  - `raxcell/fixtures/run.cwd-policy-granted.json`

Verification run:

```bash
cargo test --manifest-path raxcell/Cargo.toml
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.linux-bubblewrap.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.missing-root.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.cwd-policy-required.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.cwd-policy-granted.json
pnpm install && pnpm build:sdk && pnpm test:sdk
```

Worker smoke:

```bash
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- worker < /tmp/raxcell-worker-policy-smoke.jsonl
```

Code review result:

- No approval, human gate, policy matrix, command allow/deny, or runtime-specific decision logic entered Raxcell core.
- The only `approval`/`policy matrix` wording in source scan is README boundary text.

Next semantic boundary:

- Decide whether nested read/write roots should be normalized before binding, for example read `/workspace` plus write `/workspace/tmp`.
- Decide whether backend runtime roots such as `/usr`, `/etc`, `/proc`, `/dev`, and scratch `/tmp` should become explicit capability report entries.
- Decide how macOS Seatbelt and Windows native lowering should represent the same declared roots once their runners are attached.
