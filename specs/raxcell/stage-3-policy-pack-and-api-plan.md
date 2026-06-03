# Raxcell Stage 3 Policy Pack And API Plan

Status: Initial implementation complete; ready for Stage 4 filesystem backend lowering decisions.

## Goal

Turn the Stage 2 execution backend surface into a declarative, cross-language integration surface:

- Define the first policy pack grammar.
- Keep policy packs limited to execution enforcement facts.
- Add profile presets as the first filesystem lowering layer.
- Make JSON protocol the language-neutral ABI.
- Keep CLI/worker as the stable cross-language runtime carrier.
- Keep TypeScript SDK as the first official facade, not the only integration path.

## Confirmed User Decisions

- Policy pack boundary: enforcement only.
  - Raxcell packs describe filesystem, network, process, environment, backend, resources, and fallback enforcement facts.
  - Raxcell packs do not decide approval, human gate, business risk, policy matrix, command allow/deny, tool meaning, or model behavior.
- Filesystem lowering direction: profile presets.
  - Stage 3 starts with named presets such as workspace write, workspace read-only, no network, and host observed refusal.
  - Explicit roots remain available as overrides, but preset semantics are the user-facing shorthand.
- Public API source of truth: JSON Protocol First + CLI/Worker Stable + TypeScript Facade.
  - JSON request/response schemas are the cross-language ABI.
  - The `raxcell` binary is the universal runtime carrier that any language can spawn.
  - The npm SDK is a convenience layer that manages the binary, worker lifecycle, and typed helpers for TypeScript users.
- Policy pack formats: JSON, YAML, and TOML.
  - All three formats must deserialize into the same policy pack protocol shape.
  - JSON remains the canonical fixture and wire representation.
- Profile variables: common roots.
  - Stage 3 recognizes `$workspace`, `$home`, `$tmp`, and future named runtime roots.
  - Variable values are supplied by the caller during profile resolution; Raxcell should not silently guess sensitive roots.

## Non-Negotiable Boundaries

- Raxcell core remains execution enforcement only.
- Policy packs must not contain command approval rules such as `command.allow`, `command.deny`, `prompt`, `askUser`, or `review`.
- Policy packs may contain named enforcement profiles and backend requirements.
- If a pack requests enforcement that the selected backend cannot provide, Raxcell fails closed with a structured denial.
- `host-observed` does not become a fallback execution mode for isolated requests.
- Workspace rollback remains optional fallback and must disclose what it does and does not protect.
- Praxis-specific concepts must stay in future adapters, not core protocol.

## Proposed Pack Grammar

Initial local file format shown as canonical JSON:

```json
{
  "kind": "raxcell.policyPack.v1",
  "name": "workspace-write-no-network",
  "extends": [],
  "profiles": {
    "workspace-write-no-network": {
      "preset": "workspace-write",
      "filesystem": {
        "read": ["$workspace"],
        "write": ["$workspace"],
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
      },
      "backendPreference": [
        "linux-bubblewrap",
        "macos-seatbelt",
        "windows-elevated",
        "windows-unelevated"
      ],
      "fallback": {
        "mode": "none"
      }
    }
  }
}
```

## Proposed Profile Presets

Stage 3 presets:

- `workspace-write`
  - Workspace is readable and writable.
  - Runtime roots required to execute the command may be mounted read-only.
  - Network is separately controlled by the profile's network field.
- `workspace-readonly`
  - Workspace is readable but not writable.
  - Runtime roots required to execute the command may be mounted read-only.
- `no-filesystem-write`
  - No caller-declared write roots are allowed.
  - Runtime scratch paths may be created only when the backend needs them and reports them.
- `host-observed`
  - Observation-only capability reporting.
  - It refuses isolated execution requests.

Stage 3 should not add `danger-full-access` as a preset in core. A higher runtime may choose to bypass Raxcell or request `host-observed`, but core should avoid normalizing unsafe execution as an enforcement profile.

## Merge Model

Policy pack resolution:

1. Load local packs.
2. Resolve `extends` parent-before-child.
3. Reject cycles.
4. Merge fields with stricter result winning by default.
5. Return the resolved enforcement profile plus a merge report.

Strictness ordering:

- Network: `deny` is stricter than `allow` because this is network reachability, not command approval.
- Filesystem write: fewer writable roots are stricter than more writable roots.
- Filesystem read: fewer readable roots are stricter than more readable roots.
- Backend: a backend with stronger reported isolation is stricter than `host-observed`.
- Fallback: `none` is stricter than `workspace-rollback`.
- Timeout: lower non-zero timeout is stricter than higher timeout; missing timeout is weaker.
- Max output: lower non-zero max output is stricter than higher max output; missing cap is weaker.

If strictness cannot be compared safely, resolution fails closed and asks the caller to make the override explicit.

## Protocol Additions

Add protocol types:

- `PolicyPack`
- `PolicyProfile`
- `PolicyPreset`
- `ResolvedPolicyProfile`
- `PolicyResolutionReport`
- `PolicyResolutionWarning`

Add CLI entrypoint:

```bash
raxcell resolve-profile --stdin
```

Input:

```json
{
  "kind": "raxcell.resolveProfile.v1",
  "packPaths": ["./raxcell.policy.json"],
  "profile": "workspace-write-no-network",
  "variables": {
    "workspace": "/workspace/project"
  }
}
```

Output:

```json
{
  "kind": "raxcell.resolvedProfile.v1",
  "profile": "workspace-write-no-network",
  "enforcement": {},
  "backendPreference": [],
  "fallback": {
    "mode": "none"
  },
  "report": {
    "packs": [],
    "merge": [],
    "warnings": []
  }
}
```

The resolved output should be directly usable to build a `RunRequest`.

## Implementation Steps

1. Add protocol structs and serialization tests.
2. Add a new core module for policy pack loading and resolution.
3. Implement preset-to-enforcement lowering without touching approval or command allow/deny logic.
4. Add `resolve-profile` to the CLI and JSON-RPC worker.
5. Add fixtures for pack resolution and a resolved profile run.
6. Update TypeScript SDK types and helpers around the JSON protocol.
7. Verify with Rust tests, SDK build/test, fixture smoke, and boundary scans.
8. Code review for:
   - no approval/governance logic in core;
   - strict merge behavior;
   - host-observed refusal;
   - preset lowering consistency;
   - JSON protocol compatibility.

## Completion Criteria

- A local policy pack can resolve into a concrete `RunRequest` enforcement shape.
- Profile presets lower into explicit filesystem/network/process/resource declarations.
- Conflicting pack inheritance either resolves by strictness or fails closed.
- Raxcell tests cover pack loading, cycle rejection, strict merge, and preset lowering.
- The TypeScript SDK can call profile resolution through the same JSON protocol.
- No Raxcell core code owns approval, human gate, policy matrix, command risk, or tool semantics.

## Implementation Evidence

Completed changes:

- Added protocol types for policy packs, profile presets, resolve-profile requests, resolved profiles, and resolution reports.
- Added `raxcell-core` policy pack loading and resolution.
- Added JSON, YAML, and TOML policy pack parsing into the same `PolicyPack` protocol shape.
- Added pack kind validation, duplicate pack detection, missing parent errors, inheritance cycle detection, stricter merge behavior, and common-root variable expansion.
- Added profile preset lowering for `workspace-write`, `workspace-readonly`, `no-filesystem-write`, and `host-observed`.
- Added `raxcell resolve-profile --stdin/--json`.
- Added JSON-RPC worker method `resolveProfile`.
- Added TypeScript SDK types and `RaxcellClient.resolveProfile()`.
- Added fixtures:
  - `raxcell/fixtures/policy.workspace.json`
  - `raxcell/fixtures/policy.workspace.yaml`
  - `raxcell/fixtures/policy.workspace.toml`
  - `raxcell/fixtures/resolve.workspace.json`

Verification run:

```bash
cargo test --manifest-path raxcell/Cargo.toml -p raxcell-cli
cargo test --manifest-path raxcell/Cargo.toml -p raxcell-core
cargo test --manifest-path raxcell/Cargo.toml
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- resolve-profile --stdin < raxcell/fixtures/resolve.workspace.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- resolve-profile --json '{"kind":"raxcell.resolveProfile.v1","packPaths":["raxcell/fixtures/policy.workspace.yaml"],"profile":"workspace-write-no-network","variables":{"workspace":"/tmp/raxcell-workspace","home":"/home/agent","tmp":"/tmp/raxcell"}}'
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- resolve-profile --json '{"kind":"raxcell.resolveProfile.v1","packPaths":["raxcell/fixtures/policy.workspace.toml"],"profile":"workspace-write-no-network","variables":{"workspace":"/tmp/raxcell-workspace","home":"/home/agent","tmp":"/tmp/raxcell"}}'
pnpm install && pnpm build:sdk && pnpm test:sdk
git diff --check -- README.md specs/raxcell raxcell package.json pnpm-workspace.yaml pnpm-lock.yaml
```

Code review findings fixed:

- Replaced deprecated `serde_yaml` with `yaml_serde`.
- Fixed JSON-RPC test fixture paths so tests do not depend on process cwd.
- Fixed merge normalization so `no-filesystem-write` can tighten parent writable roots instead of inheriting them.
- Added regression coverage for no-write preset inheritance.

Next semantic boundary:

- Stage 3 resolves filesystem declarations, but Stage 2 Linux runner still binds the command cwd writable and does not yet consume resolved `read`/`write`/`denyRead`/`denyWrite` roots.
- Stage 4 should define how backend-specific filesystem lowering handles undeclared paths, missing roots, runtime roots, and cwd/root conflicts before changing backend execution behavior.

## Questions Before Implementation

1. Should the public API source of truth be JSON Protocol First + CLI/Worker Stable + TypeScript Facade?
2. Should the pack file format start as JSON only, or should Stage 3 also accept TOML/YAML?
3. Should profile variables initially support only `$workspace`, or should Stage 3 include `$home`, `$tmp`, and named runtime roots?

Resolved answers:

1. JSON Protocol First + CLI/Worker Stable + TypeScript Facade.
2. JSON, YAML, and TOML.
3. Common roots: `$workspace`, `$home`, `$tmp`, and future named runtime roots supplied by the caller.
