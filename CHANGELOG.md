# Changelog

## 0.1.5

- Added a structured Linux shell filesystem effect analyzer for common shell, Python, and Node read/write patterns.
- Reported concrete external path requirements as `policyDecision.reason = "path-outside-declared-roots"` with contextual `required` values.
- Reported dynamic shell paths such as `$HOME/a.txt`, `${TARGET}/x`, `~/x`, and command-substitution paths as `environmentGap.reason = "shell-dynamic-path-unresolved"`.
- Added analyzer effects to `filesystemLowering.effects` for Praxis audit/TUI display without making Raxcell a policy engine.
- Exported `analyzeShellEffects` and `analyzeShellScript` from the TypeScript SDK.

## 0.1.4

- Classified shell redirection and Python `write_text(...)` absolute path references as write requirements during `prepare-run`.
- Kept read-only policy grants from lowering into writable sandbox shadow paths for external absolute writes.
- Materialized missing host files for writable policy-grant mounts before running bubblewrap, so approved writes land on the host path.

## 0.1.3

- Clarified `run.ok` semantics: a successfully launched sandbox returns `ok: true` even when the command exits nonzero.
- Preserved command nonzero status in `exitCode`, `stdout`, and `stderr` without converting it into a sandbox denial.
- Added `source: "policy-grant"` lowered roots for policy-granted paths in `filesystemLowering.declaredRoots`.

## 0.1.2

- Fixed shell path extraction so relative paths such as `raxcell_live_probe/hello.txt` resolve against `command.cwd`.
- Fixed shell redirection preflight to avoid misreading relative paths with slashes as absolute paths such as `/hello.txt`.

## 0.1.1

- Added the `raxcell` npm bin at `dist/cli.js`.
- Added a TypeScript/Node Linux bubblewrap CLI for `probe`, `explain-backend`, `prepare-run`, and `run`.
- Updated `RaxcellClient` to call CLI subcommands without `--stdin` and validate response `kind`.
- Added `environmentGap` protocol fields for prepare/run results.
- Added package, client, CLI, and npm pack tests for the executable contract.
- Updated Praxis integration docs for `RAXCELL_BIN` and the Linux-first executable path.
- Removed stale Rust steps from the npm publish workflow.

## 0.1.0

- Introduced the Raxcell Rust workspace:
  - `raxcell-protocol`
  - `raxcell-core`
  - `raxcell-cli`
- Added Linux bubblewrap execution.
- Added `probe`, `resolveProfile`, `prepareRun`, `explainBackend`, and `run`.
- Added `filesystemLowering` reports.
- Added `backendArtifacts` for Linux bubblewrap argv auditing.
- Added TypeScript package `@praxis-ai/raxcell`.
- Added Praxis TypeScript middleware integration documentation.
- Added npm publish workflow.
