# Praxis Integration Semantics

Raxcell is the execution/environment layer below Praxis. Praxis owns the
policy decision and durable control plane; Raxcell owns sandbox facts and
sandboxed execution.

## Ownership Boundary

Praxis owns:

- policy matrices and per-session policy selection;
- approval and human prompts;
- audit persistence;
- fallback, retry, rewrite, and deny decisions;
- interpreting tool intent, model behavior, and prompt context.

Raxcell owns:

- backend probe and capability facts;
- `prepare-run` lowering facts without spawning the command;
- sandboxed `run`;
- stdout, stderr, exit code, timeout, denial, environment gap, and backend
  artifacts.

Raxcell fails closed. It must not auto-fallback to host execution when a
sandbox backend cannot be prepared or launched. `fallback.mode` can travel in
the protocol as an upper-runtime instruction, but Praxis decides whether any
fallback, retry, rewrite, or deny path is acceptable.

`policyGrants` are capability tickets issued by an upper runtime after its own
policy and approval checks. Raxcell validates and lowers them into backend
facts; it does not invent grants, prompt for grants, persist grants, or treat
runtime roots as grants.

## Protocol Shape

`RunRequest` is the shared input for `prepare-run` and `run`.

Important integration fields:

- `backendPreference`: ordered backend families requested by Praxis.
- `policyGrants`: upper-runtime-issued filesystem capability tickets.
- `action`: opaque Praxis action metadata for correlation and audit.
- `command`: argv, cwd, env, and stdin facts to execute.
- `enforcement`: requested filesystem, network, process, and resource boundary.
- `fallback`: upper-runtime fallback mode. Raxcell carries this fact but Praxis
  owns the decision to fallback, retry, rewrite, or deny.

`PrepareRunResponse` returns sandbox-preparation facts and never spawns the
command.

Important integration fields:

- `ok`: whether the selected backend can prepare the sandbox with the supplied
  declarations and grants.
- `backend`: selected backend family, when one was selected.
- `denial`: Raxcell-level refusal or backend construction failure.
- `environmentGap`: unresolved environment/backend fact that Praxis may route.
- `policyDecision`: concrete missing capability that requires Praxis policy.
- `filesystemLowering`: declared roots, runtime roots, grant roots, warnings,
  and analyzed command filesystem effects.
- `backendArtifacts`: backend-specific planned invocation facts.
- `capabilityReport`: probe facts used for this preparation.

`RunResponse` returns sandbox execution results.

Important integration fields:

- `ok`: whether Raxcell launched and managed the sandbox backend successfully.
- `exitCode`: child command exit code; nonzero command exits still use
  `ok: true` when the sandbox ran normally.
- `stdout` / `stderr`: captured child output.
- `timedOut`: whether Raxcell timed out the child/backend.
- `denial`: Raxcell-level refusal, timeout, or backend failure.
- `environmentGap`: unresolved environment/backend fact.
- `policyDecision`: policy handoff if `run` reuses prepare validation and the
  request still needs a grant.
- `filesystemLowering` and `backendArtifacts`: execution facts matching the
  prepared sandbox.
- `capabilityReport`: probe facts used for the run.

The TypeScript SDK and Rust protocol use the same camelCase JSON fields for
these objects. The Rust structs serialize fields such as `backendPreference`,
`policyGrants`, `environmentGap`, `policyDecision`, `filesystemLowering`,
`backendArtifacts`, `exitCode`, `timedOut`, and `capabilityReport`; the
TypeScript types expose the same wire names. The older TypeScript direct
backend path may keep legacy artifact formats for compatibility, but the
protocol meaning is shared.

## Decision Routing Table

| Response fact | Meaning | Praxis action | Raxcell behavior |
| --- | --- | --- | --- |
| `PrepareRunResponse.ok=true` and no `policyDecision` / `environmentGap` / `denial` | Sandbox can be prepared with supplied declarations and grants | Audit the lowering facts, then call `run` if policy allows | Does not spawn during prepare |
| `RunResponse.ok=true` with `exitCode=0` | Command ran in sandbox and succeeded | Treat as command success; persist output and artifacts | Returns stdout/stderr/facts |
| `RunResponse.ok=true` with `exitCode!=0` | Command ran in sandbox and failed at command level | Handle as tool/command failure, not sandbox failure | Returns stdout/stderr/exit code |
| `policyDecision.reason=cwd-outside-declared-roots` | Concrete cwd needs a read capability | Decide deny, ask, rewrite cwd, or issue a read grant | Reports required capability |
| `policyDecision.reason=path-outside-declared-roots` | Concrete command path needs read/write/readwrite capability | Decide deny, ask, rewrite command, or issue grant | Reports path and required capability |
| `environmentGap.reason=dynamic-shell-path-unresolved` | Shell path cannot be normalized safely in the corrected Rust path | Ask or rewrite to concrete path; do not grant blindly | Does not expand host/request env |
| `environmentGap.reason=shell-dynamic-path-unresolved` | Legacy TypeScript direct-backend spelling for the same dynamic shell-path gap | Treat as the same route during compatibility windows | Does not expand host/request env |
| `environmentGap.reason=missing-backend-dependency` | Selected backend dependency is unavailable | Install/route/deny according to Praxis policy | Fails closed |
| `environmentGap.reason=host-platform-mismatch` | Requested backend belongs to another OS | Route to another backend or deny | Fails closed |
| `environmentGap.reason=native-backend-runner-unattached` | Native runner contract is not attached | Attach runner, route, or deny | Fails closed |
| `denial.code=POLICY_DECISION_REQUIRED` | Request needs upper policy before lowering/execution | Treat as policy handoff, not an auto-deny | Does not grant or prompt |
| Other `denial` | Raxcell or backend cannot safely proceed | Deny, surface, or retry with a changed request/backend | Does not fall back to host |
| `timedOut=true` | Raxcell timed out the backend/child | Handle as timeout, maybe retry with new policy | Marks timeout and returns facts |

`policyDecision` is for concrete, decidable capability gaps. `environmentGap`
is for unresolved host/backend facts. `denial` is for Raxcell refusing or
failing to safely prepare/run the backend.

## Backend Artifacts

`backendArtifacts` are audit/debug facts, not policy grants. Praxis can store
and display them to show what Raxcell prepared or executed.

Linux mainline success artifact:

- `format: "codex-linux-sandbox-argv"`
- `arguments`: Codex Linux helper arguments after argv0/program.
- `data.engine`: `codex-linux-sandbox`.
- `data.executable`: helper executable path when the Rust worker produced the
  artifact.

Source-aware roots, runtime roots, effects, network mode, and timeout/resource
facts are carried in `filesystemLowering`, `capabilityReport`, or sibling
response fields. Legacy TypeScript artifacts may include extra audit data, but
Praxis should not require those extras to prove the corrected Rust helper path.

Legacy Linux TypeScript fallback artifact:

- `format: "linux-bubblewrap-argv"`
- Only means the old direct TypeScript fallback assembled a bubblewrap command.
- Do not treat it as the corrected Codex-core-backed Linux path.

Other planned/native artifacts:

- `macos-seatbelt-sbpl-profile`: generated SBPL plus `sandbox-exec` argv and
  lowering facts. It is planned/partial until Codex Seatbelt lowering is wired.
- `windows-native-token-acl-plan`: runner protocol, token/ACL plan, network
  intent, and execution limits. It is a bridge/planned artifact until the
  native `windows-sandbox-rs` API path has real smoke coverage.

## Backend Status

| Backend family | Current status | Integration note |
| --- | --- | --- |
| `linux-bubblewrap` with `codex-linux-sandbox-argv` | Codex core-backed Linux path | Public backend family can remain a compatibility name while the artifact proves the Codex helper path |
| `linux-bubblewrap` with `linux-bubblewrap-argv` | Legacy TypeScript fallback | Compatibility only; do not present as the corrected mainline |
| `macos-seatbelt` | Planned/partial | Uses the same OS primitive only when actually running on macOS; do not claim Codex equivalence until Codex Seatbelt lowering is wired |
| `windows-native` / `windows-elevated` / `windows-unelevated` | Bridge/planned | Runner contract exists; do not claim native completion until direct `windows-sandbox-rs` API smoke passes |
| `host-observed` | Observation-only | Diagnostics only; not an enforcement fallback for failed sandbox runs |

## Praxis Adapter Notes

The Praxis adapter should:

- map one execution-bearing tool call to one `RunRequest`;
- pass `backendPreference` explicitly when routing matters;
- keep `fallback.mode` conservative, usually `none`;
- persist `action.actionId`, `ownerRuntime`, `filesystemLowering`,
  `backendArtifacts`, `policyDecision`, `environmentGap`, `denial`,
  `exitCode`, and `timedOut`;
- convert approved Praxis policy decisions into `policyGrants`;
- retry `prepare-run` after adding grants before calling `run`;
- treat runtime roots with `source: backend-runtime` as backend facts, not
  permissions granted by Praxis;
- surface `environmentGap` as an environment/backend routing issue, not an
  approval prompt.

The Praxis adapter must not:

- bypass `prepare-run` for commands that need policy inspection;
- turn Raxcell into a policy matrix, approval UI, audit store, fallback engine,
  retry engine, rewrite engine, or deny engine;
- add implicit host execution when Raxcell fails closed;
- convert dynamic paths into grants without a concrete rewritten path;
- treat `linux-bubblewrap-argv` as proof of the Codex-backed Linux path;
- call macOS or Windows "complete" before the Codex lowering/native API paths
  are actually wired and smoke-tested.

## Profile Fixture

`raxcell/fixtures/policy.praxis-profiles.yaml` is a parseable template for
Praxis-style profiles and Raxcell lowering. It is not the Raxcell policy brain.
It demonstrates how upper-runtime profile choices can become concrete
`RunRequest.enforcement`, `backendPreference`, and `fallback` facts. Production
Praxis policy still decides which profile to use and when to issue
`policyGrants`.
