# Changelog

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
