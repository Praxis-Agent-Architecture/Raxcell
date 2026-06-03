# Raxcell Sandbox Extract Spec

Status: Approved for Stage 1 planning
Branch: `dev/raxcell`
Repository: `/home/proview/Desktop/Praxis_series/development/Raxcell`

## 1. Purpose

Raxcell will extract the reusable sandbox enforcement parts of the Codex fork into a general-purpose execution enforcement sandbox SDK.

The product target is not "Codex with a new name" and not a Praxis-only runtime component. Raxcell must become a standalone enforcement layer that any upper runtime, harness, agent framework, SDK, or platform can mount.

In plain terms: upper systems decide what an action means and whether it should be allowed; Raxcell makes the actual process execution obey the declared filesystem, network, process, environment, resource, backend, and fallback boundaries.

## 2. Boundary

Raxcell core owns:

- Compiling local enforcement profiles into runtime execution permissions.
- Probing platform backends and reporting real enforcement capability.
- Preparing sandbox backends before execution.
- Running commands or process actions inside the selected sandbox backend.
- Returning structured execution results, denials, capability mismatches, and optional fallback results.
- Providing a language-neutral JSON/CLI protocol and an npm TypeScript facade.
- Providing optional fallback modules, including workspace rollback, only when explicitly enabled by the caller.

Raxcell core does not own:

- Agent turn lifecycle.
- Model behavior control.
- Business risk classification.
- Policy matrix ownership.
- Human approval UI.
- Auto-review, guardian review, or side-agent review.
- Tool semantics such as Praxis BaseTool, OpenAI Agents SDK tools, MCP tools, or product-specific tool ids.
- Codex UI, TUI, app-server, model provider, memory, skills, cloud task, connector, or conversation-state behavior.

Approval and governance belong to the upper runtime. Raxcell may emit typed facts that a runtime can use to ask for approval, but Raxcell core must not decide who approves or how a policy matrix is evaluated.

## 3. Decisions Already Aligned

The current design lock is:

- Default mismatch behavior: fail closed.
- Core scope: execution enforcement only.
- Approval ownership: upper runtime owns approvals; Raxcell returns facts and denials.
- Registry: local file-backed policy packs.
- Registry merge model: stricter result wins by default.
- ABI: JSON/CLI protocol first; npm SDK wraps the protocol and native binaries.
- Protocol entrypoints: provide both one-shot CLI JSON wrappers and a stdio JSON-RPC worker with streaming lifecycle/output events.
- Action layer: opaque metadata only, used for correlation and intent labels.
- Command/process layer: real enforcement target.
- Backend reporting: probe and prepare must return actual supports, limits, weaknesses, and missing dependencies before execution.
- Workspace rollback: optional built-in fallback module, never default isolation.
- Praxis integration: future Praxis adapter should mount Raxcell as a sandbox provider, not replace Praxis governance, approval, or BaseTool executor semantics.
- First implementation layout: create a new top-level `raxcell/` tree and adapt Codex sandbox crates into it gradually.
- First platform strategy: keep Linux, macOS, and Windows as first-class backend families from Stage 1; local verification starts on Linux, while macOS/Windows remain conditionally compiled and prepared for CI or remote verification.

## 4. Evidence From Codex

Codex provides a strong implementation basis for enforcement, but its product surface is broader than Raxcell core should be.

Reusable enforcement pieces:

- `codex-rs/sandboxing/src/manager.rs` defines the platform backend enum: `None`, `MacosSeatbelt`, `LinuxSeccomp`, and `WindowsRestrictedToken`.
- The same file selects a platform sandbox from the OS and Windows sandbox flag, then transforms a command plus permission profile into a platform-specific sandbox execution request.
- `SandboxCommand`, `SandboxExecRequest`, and `SandboxTransformRequest` are close to the kind of command/process request model Raxcell needs.
- `codex-rs/protocol/src/models.rs` already separates compiled runtime permissions with `PermissionProfile::Managed`, `Disabled`, and `External`.
- `codex-rs/config/src/permissions_toml.rs` already resolves named permission profiles with `extends`, cycle detection, and parent-before-child merging. Raxcell should adapt this into local policy packs with stricter merge semantics.
- `codex-rs/linux-sandbox/src/lib.rs` states the Linux helper applies `no_new_privs`, seccomp, and bubblewrap filesystem isolation.
- `codex-rs/windows-sandbox-rs` contains real native Windows sandbox work, including restricted token behavior, elevated helper paths, ACL handling, firewall setup, private desktop, and unified exec paths.

Codex pieces to keep out of Raxcell core:

- `codex-rs/core/src/exec_policy.rs` parses commands and decides `Forbidden`, `Prompt`, or `Allow`, including whether to bypass sandbox after explicit allow rules. That is governance and policy-matrix territory for Raxcell's upper runtime, not core enforcement.
- `codex-rs/protocol/src/protocol.rs` approval policy variants such as `OnRequest`, `Never`, and granular approval are Codex turn-level behavior.
- `codex-rs/protocol/src/approvals.rs` and `request_permissions.rs` contain useful event shapes, but the decision lifecycle belongs outside Raxcell core.
- Anything tied to Codex conversation turns, model context, connectors, app tools, MCP approval surfaces, guardian/auto-review, or UI routing must remain reference material or adapter material.

Official Codex documentation supports this split:

- Codex describes sandboxing as the technical boundary for local commands and approvals as the policy deciding when Codex must stop before crossing that boundary: https://developers.openai.com/codex/concepts/sandboxing
- Codex states sandboxing applies to spawned commands such as git, package managers, and test runners, not just built-in file operations: https://developers.openai.com/codex/concepts/sandboxing
- Codex documents platform-native enforcement across macOS, Linux, WSL2, and native Windows: https://developers.openai.com/codex/concepts/sandboxing
- Windows documentation separates native elevated sandbox, native unelevated fallback, and WSL2 using the Linux sandbox implementation: https://developers.openai.com/codex/windows

## 5. Evidence From Praxis

Praxis already has the right upper-runtime ownership model. Raxcell should integrate with it without absorbing it.

Important Praxis facts:

- `src/basetool/factMatrix.ts` says runtime mounts executor ports, evaluates sandbox and policy, and owns approvals and live resources; sandbox consumes sandbox hints and runtime policy.
- `src/runtimeImplementation/runtime.sandboxPlane/sandboxRuntimeProvider.ts` models `probe`, `prepare`, `runSmoke`, and `explainUnavailable`. Raxcell should provide the same kind of readiness and explanation surface at the enforcement layer.
- `src/runtimeImplementation/runtime.sandboxPlane/baseToolSandboxPlanner.ts` currently models `none`, `workspace-rollback`, and `isolated`, and records `requestedMode`, `effectiveMode`, `degradeReason`, `protects`, and `doesNotProtect`.
- The same planner degrades strong sandbox requests to workspace rollback when the strong provider is not ready.
- `src/runtimeImplementation/runtime.sandboxPlane/workspaceRollbackSandbox.ts` explicitly states rollback only protects workspace files and does not protect home directories, system paths, global package caches, or external services.

Raxcell should learn from Praxis by making fallback disclosure explicit, but Raxcell must not adopt Praxis's default degradation in core. Core remains fail closed. Praxis can opt into workspace rollback through its adapter.

## 6. Target Architecture

Raxcell should be split into five long-term layers:

1. `raxcell-core`
   - Rust implementation of enforcement profiles, backend selection, backend probing, command execution, denial mapping, capability mismatch handling, and optional fallback hooks.

2. `raxcell-protocol`
   - Language-neutral JSON schema for requests, responses, denials, capability reports, fallback reports, and version negotiation.
   - This is the stable contract for non-JS users.

3. `raxcell-cli`
   - Binary entrypoint for `probe`, `prepare`, `run`, `explain`, and `schema`.
   - Supports one-shot JSON request/response wrappers for manual use.
   - Supports a stdio JSON-RPC worker for SDKs and other runtimes.
   - Streams lifecycle and output events for long-running executions.

4. `@raxcell/sdk`
   - npm TypeScript facade.
   - Resolves bundled/native binaries.
   - Provides ergonomic TS types, validation, and process lifecycle helpers.
   - Does not become the only supported integration path.

5. `raxcell-adapters`
   - Optional packages or modules for Praxis and other runtimes.
   - Adapters translate runtime policy decisions into Raxcell enforcement profiles and translate Raxcell results back into runtime events.

## 7. Core Protocol Shape

First-stage JSON requests should be small and explicit.

`ProbeRequest`:

```json
{
  "kind": "raxcell.probe.v1",
  "platform": "auto",
  "backendPreference": ["linux-bubblewrap", "macos-seatbelt", "windows-elevated", "windows-unelevated"],
  "requirements": {
    "filesystem": ["read-restrict", "write-restrict"],
    "network": ["deny"],
    "process": ["spawn"],
    "resource": ["timeout"]
  }
}
```

`ProbeResponse`:

```json
{
  "kind": "raxcell.probeResult.v1",
  "ready": true,
  "selectedBackend": "linux-bubblewrap",
  "supports": {
    "filesystem.readRestrict": "full",
    "filesystem.writeRestrict": "full",
    "network.deny": "full",
    "process.spawn": "full",
    "resource.timeout": "full"
  },
  "limits": [],
  "weaknesses": [],
  "missing": [],
  "nextActions": []
}
```

`RunRequest`:

```json
{
  "kind": "raxcell.run.v1",
  "action": {
    "actionId": "runtime-generated-id",
    "ownerRuntime": "praxis",
    "intentLabel": "shell command from base tool",
    "metadata": {}
  },
  "command": {
    "argv": ["npm", "test"],
    "cwd": "/workspace/project",
    "env": {},
    "stdin": null
  },
  "enforcement": {
    "profile": "workspace-write-no-network",
    "filesystem": {
      "read": ["/workspace/project"],
      "write": ["/workspace/project"],
      "denyRead": [],
      "denyWrite": []
    },
    "network": "deny",
    "process": {
      "spawn": true
    },
    "resources": {
      "timeoutMs": 600000,
      "maxOutputBytes": 2000000
    }
  },
  "fallback": {
    "mode": "none"
  }
}
```

`RunResponse`:

```json
{
  "kind": "raxcell.runResult.v1",
  "ok": true,
  "backend": "linux-bubblewrap",
  "exitCode": 0,
  "stdout": "...",
  "stderr": "",
  "timedOut": false,
  "denial": null,
  "fallback": null,
  "capabilityReport": {
    "ready": true,
    "selectedBackend": "linux-bubblewrap"
  }
}
```

The action object remains opaque. Raxcell may echo it for correlation but must not inspect it for governance.

`RunEvent` stream:

```json
{
  "kind": "raxcell.event.v1",
  "requestId": "runtime-request-id",
  "event": "stdout",
  "data": "chunk text"
}
```

First-stage event names:

- `probe.started`
- `probe.finished`
- `prepare.started`
- `prepare.finished`
- `run.started`
- `stdout`
- `stderr`
- `denial`
- `fallback.started`
- `fallback.finished`
- `run.finished`

## 8. Denial And Mismatch Semantics

Raxcell should distinguish:

- `CAPABILITY_MISMATCH`: requested enforcement cannot be provided by the selected platform backend.
- `BACKEND_UNAVAILABLE`: backend dependency or OS feature is missing.
- `SANDBOX_DENIED`: the backend enforced a boundary and denied the action.
- `EXECUTION_FAILED`: command ran inside the sandbox but failed normally.
- `TIMEOUT`: command exceeded configured resource limits.
- `FALLBACK_APPLIED`: optional fallback ran because the upper runtime explicitly requested it.
- `FALLBACK_REFUSED`: fallback was requested but cannot honestly cover the requested enforcement.

Default behavior:

- Capability mismatch fails closed.
- Backend unavailable fails closed.
- Sandbox denial returns structured denial facts.
- Fallback is not automatic.
- Rollback fallback must disclose `protects` and `doesNotProtect`.

## 9. Local Policy Registry

First-stage registry is local and file-backed.

Candidate lookup layers:

- Built-in defaults.
- Global policy packs.
- User policy packs.
- Repository policy packs.
- Per-run explicit profile or enforcement overlay.

Merge semantics:

- Stricter result wins by default.
- `deny` wins over `allow`.
- `read-only` wins over write if conflict is not explicitly granted.
- Narrower path roots win over broader path roots.
- Network deny wins over network allow unless the upper runtime passes an explicit grant.
- Unknown fields fail validation.
- Profile inheritance must detect cycles.
- Built-in profiles must be stable names.

This is intentionally different from ordinary config overriding. Sandboxing configuration must not become an accidental privilege-escalation channel.

## 10. Backend Model

Backends should report capability rather than pretend all platforms are identical.

Initial backend families:

- `linux-bubblewrap`
- `macos-seatbelt`
- `windows-elevated`
- `windows-unelevated`
- `host-observed`
- `external`
- `workspace-rollback` as fallback module, not isolation backend

WSL2 should map to the Linux path. WSL1 should be unsupported for the bubblewrap path.

Each backend reports:

- `ready`
- `dependencies`
- `supports`
- `limits`
- `weaknesses`
- `missing`
- `nextActions`
- `publicSafeMessage`

Windows must preserve the distinction between elevated and unelevated support. Unelevated is useful but weaker; Raxcell should not hide that weakness from upper runtimes.

Stage 1 must not become Linux-only. Linux can be the first locally smoke-tested backend because the current development host is Ubuntu, but the public protocol and source layout must treat macOS Seatbelt and native Windows elevated/unelevated backends as first-class from the start.

## 11. Workspace Rollback Module

Workspace rollback is a compensating fallback, not a sandbox.

It may:

- Snapshot workspace files before execution.
- Detect created, modified, and deleted workspace files.
- Restore workspace changes on failure or explicit runtime request.
- Return public-safe diff metadata.

It must disclose:

- It protects workspace files only.
- It does not protect home directories.
- It does not protect system paths.
- It does not protect global package caches.
- It does not protect external services.
- It does not undo network side effects.

Core default remains `fallback.mode = "none"`. Praxis or another runtime may explicitly request rollback when that runtime decides the reduced protection is acceptable.

## 12. Extraction Map

Keep or adapt into Raxcell core:

- `codex-rs/sandboxing`
- `codex-rs/linux-sandbox`
- `codex-rs/windows-sandbox-rs`
- Platform-specific Seatbelt argument generation from the existing macOS sandbox path.
- Permission profile structures from `codex-rs/protocol/src/models.rs`, renamed away from Codex turn terminology.
- Permission TOML profile resolution from `codex-rs/config/src/permissions_toml.rs`, modified for local policy packs and stricter merge.
- Execution result and timeout/cancellation plumbing from the exec path where it is not Codex-turn-specific.

Keep as reference or adapter, not core:

- `codex-rs/core/src/exec_policy.rs`
- `codex-rs/protocol/src/approvals.rs`
- `codex-rs/protocol/src/request_permissions.rs`
- Codex shell tool schema and model-facing `request_permissions` tool.
- Codex auto-review, guardian, app tool approval, MCP approval, and turn context.
- Codex TUI, app-server, ChatGPT connector, model provider, memory, skill, cloud-task, and telemetry surfaces.

Likely delete or move out after spec approval:

- Product UI crates and packages that only serve Codex app/CLI/TUI.
- Model-provider integration that is unrelated to process execution enforcement.
- Conversation, rollout, message history, memories, skills, plugins, MCP, cloud task, ChatGPT, and connector code.
- Codex-specific docs that do not apply to Raxcell after extraction.

No large deletion should happen until the user approves this spec and the implementation plan lists the exact deletion set.

## 13. First Implementation Stage

Stage 1 should avoid broad deletion. It should create the Raxcell target shape while keeping the Codex source available for reference.

Recommended first stage:

1. Add the Raxcell extraction spec.
2. Add a top-level `raxcell/` target layout proposal in the implementation plan.
3. Introduce a small protocol schema package with request/response types, without moving platform backends yet.
4. Add an adapter layer around existing `codex-rs/sandboxing` transform logic.
5. Add probe output shape for Linux, macOS, and Windows backend families, with local Linux smoke coverage first.
6. Add minimal CLI skeleton for one-shot JSON and stdio JSON-RPC worker mode once the plan is approved.
7. Add tests for profile merge strictness, capability mismatch fail-closed behavior, and action metadata opacity.

Non-goals for Stage 1:

- No npm publish yet.
- No remote registry.
- No daemon.
- No full repository pruning.
- No Praxis adapter implementation yet.
- No replacement of Codex exec pipeline yet.

## 14. Review Gates

Each coherent stage must pass:

- Format checks for touched Rust or TS files.
- Focused tests for touched crates/packages.
- A code-review pass that looks for boundary drift, policy leakage, unsafe fallback behavior, and Codex product coupling.
- A deletion review before removing any large Codex subsystem.

Review questions for every implementation PR:

- Did Raxcell core start making governance decisions?
- Did any fallback silently reduce isolation?
- Did any platform weakness get hidden behind a generic success?
- Did action metadata become business/tool semantics?
- Did npm SDK become the only usable ABI?
- Did Praxis-specific terms enter core protocol?

## 15. Approved Stage 1 Decisions

The following decisions are approved for the implementation plan:

1. Package layout name:
   - use a new top-level `raxcell/` tree.

2. Spec file permanence:
   - keep this spec and future engineering specs under `specs/raxcell/`
   - move user-facing documentation elsewhere only after Raxcell has a public docs plan

3. First protocol style:
   - support one-shot JSON CLI wrappers.
   - support stdio JSON-RPC worker mode.
   - stream status and output events.

4. First host target:
   - keep Linux, macOS, and Windows backends first-class from Stage 1.
   - use local Linux verification first because the current development host is Ubuntu.
   - prepare macOS/Windows validation through conditional compilation, existing Codex source preservation, and future CI or remote checks.

Implementation planning may begin from this approved decision set.
