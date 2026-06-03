# Raxcell Stage 5 Lowering Report Plan

Status: Confirmed; ready to implement.

## Goal

Make filesystem lowering auditable and cross-platform:

- Normalize nested read/write roots with minimal write authority.
- Report backend runtime roots explicitly.
- Introduce a shared lowering report model that Linux, macOS, and Windows can all use.

Stage 5 does not add approval, policy matrix decisions, human gates, model behavior control, or runtime-specific command allow/deny logic.

## User Decisions Captured

- Nested read/write roots: write overrides.
  - Example: read `/workspace` plus write `/workspace/tmp` means `/workspace` remains read-only except `/workspace/tmp` is writable.
  - Raxcell should support this default while leaving room for upper harness policy to choose stricter behavior later.
- Backend runtime roots: report explicitly.
  - Backends may automatically add roots required for execution, such as `/usr`, `/etc`, `/proc`, `/dev`, and scratch `/tmp`.
  - These roots must be reported so upper runtimes can audit the true sandbox surface.
- Cross-platform lowering: shared model.
  - Define a common `FileSystemLoweringReport`.
  - Linux maps it to bubblewrap mounts.
  - macOS will map it to Seatbelt file rules when attached.
  - Windows will map it to native ACL/token/firewall behavior when attached.

## Proposed Shared Report Shape

```json
{
  "filesystemLowering": {
    "declaredRoots": [
      { "path": "/workspace", "access": "read", "source": "declared" },
      { "path": "/workspace/tmp", "access": "write", "source": "declared" }
    ],
    "runtimeRoots": [
      { "path": "/usr", "access": "read", "source": "backend-runtime" },
      { "path": "/etc", "access": "read", "source": "backend-runtime" },
      { "path": "/proc", "access": "runtime", "source": "backend-runtime" },
      { "path": "/dev", "access": "runtime", "source": "backend-runtime" },
      { "path": "/tmp", "access": "scratch", "source": "backend-runtime" }
    ],
    "policyGrants": [],
    "warnings": []
  }
}
```

## Linux Semantics

- Canonicalize declared roots.
- Missing declared roots fail closed.
- Deduplicate roots.
- If a declared write root is nested under a declared read root, keep both:
  - parent read root is mounted read-only;
  - nested write root is mounted read-write later in the bubblewrap command.
- If a declared read root is nested under a declared write root, drop the read root from mounts because the write parent already grants stronger access.
- Backend runtime roots are mounted as needed and reported:
  - `/usr`: read
  - `/etc`: read
  - `/proc`: runtime
  - `/dev`: runtime
  - `/tmp`: scratch
  - root symlinks such as `/bin`, `/lib`, and `/lib64`: runtime-link when present.

## macOS And Windows Semantics

- macOS and Windows should produce the same shared report shape before lowering into platform-native rules.
- On this Linux host, they remain non-executable and return structured mismatch/unavailable results.
- Source-level backend modules should keep the shared model visible, even if native runners are attached later.

## Implementation Steps

1. Add protocol structs:
   - `FileSystemLoweringReport`
   - `LoweredRoot`
   - `LoweredRootAccess`
   - `LoweredRootSource`
2. Add optional `filesystemLowering` to `RunResponse`.
3. Refactor Linux filesystem lowering to produce `FileSystemLoweringReport`.
4. Change bwrap arg construction to use normalized read/write mounts.
5. Add tests for:
   - write child under read parent;
   - read child under write parent;
   - runtime roots reported;
   - policy grant roots reported.
6. Update TypeScript SDK types.
7. Add fixture smoke or test assertions for report presence.
8. Verify Rust tests, SDK build/test, Linux smoke, and no-governance boundary scan.

## Completion Criteria

- Linux successful run responses include `filesystemLowering`.
- Runtime roots are visible in the report.
- Nested read/write roots preserve minimal write authority.
- Shared report shape is platform-neutral.
- No approval, policy matrix, human gate, model behavior, or runtime-specific command decision logic enters Raxcell core.

## Implementation Evidence

Implemented:

- Added the shared `FileSystemLoweringReport` protocol shape and exposed it on successful run responses.
- Added TypeScript SDK types for the shared report shape.
- Linux bubblewrap lowering now reports the final sandbox filesystem surface:
  - declared read/write roots;
  - policy-grant roots when an upper runtime explicitly grants cwd access;
  - backend runtime roots required for execution.
- Nested filesystem roots normalize to minimal mount authority:
  - write child under read parent keeps both mounts;
  - read child under write parent is dropped from mounts.
- Backend runtime roots are filtered when an explicit effective root already covers them, so declared `/tmp` write is not also reported as backend scratch `/tmp`.
- Redundant cwd policy grants are ignored when declared roots already cover cwd, so they do not pollute source attribution or warnings.

Verified:

- `cargo fmt --manifest-path raxcell/Cargo.toml --all`
- `cargo test --manifest-path raxcell/Cargo.toml`
  - worker: 5 passed
  - core: 21 passed
  - protocol: 7 passed
- `pnpm build:sdk && pnpm test:sdk`
  - TypeScript build passed
  - SDK tests: 4 passed
- `cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.linux-bubblewrap.json`
  - returned `ok: true`
  - included `filesystemLowering`
  - reported `/tmp` as backend scratch root
- `cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.cwd-policy-granted.json`
  - returned `ok: true`
  - included `filesystemLowering`
  - reported cwd as `policy-grant`
  - did not report `/tmp` as backend scratch because `/tmp` was explicitly declared as write
- Boundary scan over `raxcell/crates`, `raxcell/sdk/src`, `raxcell/fixtures`, and `README.md` found only the README boundary statement about upper runtimes owning approval, policy matrices, human gates, tool semantics, and model behavior.

Next semantic boundary:

- Decide whether Stage 6 should expose a backend `prepare/explain/schema` control surface, add upper-configurable root-overlap policy modes, or attach native macOS/Windows runner semantics.
