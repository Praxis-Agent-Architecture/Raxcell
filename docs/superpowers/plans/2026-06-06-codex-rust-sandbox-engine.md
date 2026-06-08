# Codex Rust Sandbox Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Raxcell's hand-built Linux sandbox runner with a Codex v0.137.0 based Rust sandbox engine while preserving the Raxcell prepare-run/run/probe/explain protocol used by Praxis and other runtimes.

**Architecture:** Praxis and other runtimes remain the policy, approval, audit, and fallback owners. Raxcell accepts already-decided filesystem/network grants, reports environment gaps during prepare-run, and executes through Codex-derived sandbox primitives. The first landing slice wires Linux to Codex `SandboxManager` plus `codex-linux-sandbox`; macOS Seatbelt and Windows restricted-token engines follow the same crate boundary later.

**Tech Stack:** Rust 2024, Raxcell Rust workspace, Codex v0.137.0 sandboxing sources, JSON stdin/stdout CLI protocol, existing TypeScript SDK client surface.

---

### Task 1: Lock the Raxcell/Praxis boundary

**Files:**
- Modify: `raxcell/crates/core/src/backends/linux_bubblewrap_tests.rs`
- Modify: `raxcell/crates/core/src/backends/linux_bubblewrap.rs`

- [ ] Add tests that assert command nonzero exit keeps `run.ok = true` when the sandbox backend executed normally.
- [ ] Add tests that assert missing sandbox helper or backend construction failure keeps `run.ok = false`.
- [ ] Add tests that assert policy-granted roots appear in `filesystemLowering.policyGrants` with source `policy-grant`.
- [ ] Keep Praxis semantics unchanged: Raxcell does not approve, audit, fallback, or rollback.

### Task 2: Introduce Codex-derived sandbox protocol types

**Files:**
- Create: `raxcell/crates/codex-protocol/Cargo.toml`
- Create: `raxcell/crates/codex-protocol/src/lib.rs`
- Modify: `raxcell/Cargo.toml`

- [ ] Extract the minimal Codex v0.137.0 permission model required by sandboxing: `PermissionProfile`, `ManagedFileSystemPermissions`, `AdditionalPermissionProfile`, `FileSystemSandboxPolicy`, `FileSystemSandboxEntry`, `FileSystemPath`, `FileSystemAccessMode`, and `NetworkSandboxPolicy`.
- [ ] Preserve Codex filesystem semantics for read/write/deny roots and protected metadata names.
- [ ] Avoid importing Codex approval, rollout, model, or UI protocol.

### Task 3: Introduce Codex-derived sandbox construction

**Files:**
- Create: `raxcell/crates/codex-sandboxing/Cargo.toml`
- Create: `raxcell/crates/codex-sandboxing/src/lib.rs`
- Create: `raxcell/crates/codex-sandboxing/src/manager.rs`
- Create: `raxcell/crates/codex-sandboxing/src/landlock.rs`
- Create: `raxcell/crates/codex-sandboxing/src/seatbelt.rs`
- Modify: `raxcell/Cargo.toml`

- [ ] Extract `SandboxManager`, `SandboxType`, `SandboxCommand`, and `SandboxTransformRequest`.
- [ ] Keep macOS Seatbelt lowering available behind platform cfg.
- [ ] Keep Windows transform boundary available, but defer actual Windows capture wiring to a later slice.
- [ ] Do not import Codex core execution/session logic.

### Task 4: Introduce Codex Linux sandbox helper

**Files:**
- Create: `raxcell/crates/codex-linux-sandbox/Cargo.toml`
- Create: `raxcell/crates/codex-linux-sandbox/src/lib.rs`
- Create: `raxcell/crates/codex-linux-sandbox/src/main.rs`
- Modify: `raxcell/Cargo.toml`

- [ ] Extract the Codex v0.137.0 Linux helper path that composes bubblewrap with seccomp/no_new_privs.
- [ ] Preserve the helper CLI shape used by `SandboxManager`.
- [ ] Ensure Raxcell probe reports `dependency.binary.raxcell-codex-linux-sandbox` or bundled helper readiness, not only host `bwrap`.

### Task 5: Wire Raxcell Linux prepare-run/run to Codex engine

**Files:**
- Modify: `raxcell/crates/core/src/backends/linux_bubblewrap.rs`
- Modify: `raxcell/crates/core/src/probe.rs`
- Modify: `raxcell/crates/cli/src/main.rs`

- [ ] Translate Raxcell `RunRequest.enforcement` and `policyGrants` into Codex `PermissionProfile` plus `AdditionalPermissionProfile`.
- [ ] `prepare_run` uses `SandboxManager.transform` and returns backend artifacts showing the Codex helper argv.
- [ ] `run` executes the transformed argv and returns `ok = true` for normal sandbox execution even when `exitCode != 0`.
- [ ] `run` returns `ok = false` only for sandbox/backend denial, environment failure, timeout, or construction errors.

### Task 6: Verify and hand off

**Files:**
- Modify as needed in Rust tests.

- [ ] Run `cargo test -p raxcell-core` from `raxcell/`.
- [ ] Run `cargo test -p raxcell-cli` from `raxcell/`.
- [ ] Run a Linux smoke that writes inside the workspace, blocks external write without grant, and writes host-visible external files with a write grant.
- [ ] Summarize macOS and Windows follow-up engine wiring for the forked test thread.
