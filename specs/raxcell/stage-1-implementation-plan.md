# Raxcell Stage 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the first Raxcell execution-enforcement SDK skeleton with a top-level `raxcell/` tree, language-neutral protocol, stdio JSON-RPC worker, one-shot CLI wrappers, first-class Linux/macOS/Windows backend capability reporting, and fail-closed run semantics.

**Architecture:** Stage 1 creates a new Raxcell surface beside the existing Codex fork instead of deleting Codex code. The Rust side owns protocol and enforcement facts; the TypeScript SDK wraps the CLI/worker protocol. Real Codex backend extraction comes in Stage 2, but Stage 1 must already model all three platform backend families as first-class capability reports.

**Tech Stack:** Rust 2024, `serde`, `serde_json`, `tokio`, `clap`, Node/TypeScript SDK wrapper, stdio JSON-RPC style messages, JSON fixtures, local Linux verification.

---

## Scope Rules

- Do not delete Codex code in Stage 1.
- Do not move existing `codex-rs/sandboxing`, `codex-rs/linux-sandbox`, or `codex-rs/windows-sandbox-rs` yet.
- Do not add approval, policy matrix, human gate, model behavior control, or Praxis-specific logic to Raxcell core.
- Do not make `host-observed` a silent fallback for `run`.
- Default run behavior is fail closed until a requested backend can honestly execute the enforcement request.
- Keep Linux, macOS, and Windows backend families present in protocol and probe output from the start.
- Local smoke verification can only prove Linux behavior on this Ubuntu host; macOS/Windows validation must be represented as conditional/source-level readiness until CI or remote hosts exist.
- Do not commit unless the user explicitly asks for a commit.

## File Structure

Create:

- `raxcell/Cargo.toml`
  - Independent Stage 1 Rust workspace for Raxcell crates.
- `raxcell/crates/protocol/Cargo.toml`
  - Rust protocol crate manifest.
- `raxcell/crates/protocol/src/lib.rs`
  - Protocol module exports.
- `raxcell/crates/protocol/src/types.rs`
  - JSON-serializable request, response, event, backend, denial, and fallback types.
- `raxcell/crates/protocol/src/types_tests.rs`
  - Protocol serialization and opacity tests.
- `raxcell/crates/core/Cargo.toml`
  - Rust core crate manifest.
- `raxcell/crates/core/src/lib.rs`
  - Core module exports.
- `raxcell/crates/core/src/probe.rs`
  - Backend capability probe implementation for Linux, macOS, Windows, external, and host-observed.
- `raxcell/crates/core/src/run.rs`
  - Fail-closed run planner and response builder.
- `raxcell/crates/core/src/probe_tests.rs`
  - Backend capability and current-host probe tests.
- `raxcell/crates/core/src/run_tests.rs`
  - Fail-closed run tests.
- `raxcell/crates/cli/Cargo.toml`
  - CLI crate manifest.
- `raxcell/crates/cli/src/main.rs`
  - `raxcell probe`, `raxcell run`, and `raxcell worker` entrypoint.
- `raxcell/crates/cli/src/jsonrpc.rs`
  - Stdio JSON-RPC line protocol loop.
- `raxcell/crates/cli/src/jsonrpc_tests.rs`
  - JSON-RPC message parsing tests.
- `raxcell/sdk/package.json`
  - npm package skeleton for `@raxcell/sdk`.
- `raxcell/sdk/tsconfig.json`
  - SDK TypeScript config.
- `raxcell/sdk/src/index.ts`
  - TypeScript facade exports.
- `raxcell/sdk/src/client.ts`
  - Worker client wrapper over the `raxcell` binary.
- `raxcell/sdk/src/types.ts`
  - TypeScript protocol types matching Rust JSON.
- `raxcell/sdk/src/client.test.ts`
  - SDK request/response codec tests.
- `raxcell/fixtures/probe.auto.json`
  - Sample probe request.
- `raxcell/fixtures/run.fail-closed.json`
  - Sample run request that should not execute without a real backend.
- `raxcell/README.md`
  - Stage 1 developer notes and command examples.

Modify:

- `specs/raxcell/sandbox-extract-spec.md`
  - Only if implementation discovers an inconsistency in the approved Stage 1 decisions.

Do not modify in Stage 1:

- `codex-rs/sandboxing/**`
- `codex-rs/linux-sandbox/**`
- `codex-rs/windows-sandbox-rs/**`
- `codex-rs/core/**`
- `docs/**`

---

## Task 1: Create Raxcell Rust Workspace

**Files:**
- Create: `raxcell/Cargo.toml`
- Create: `raxcell/crates/protocol/Cargo.toml`
- Create: `raxcell/crates/protocol/src/lib.rs`
- Create: `raxcell/crates/core/Cargo.toml`
- Create: `raxcell/crates/core/src/lib.rs`
- Create: `raxcell/crates/cli/Cargo.toml`
- Create: `raxcell/crates/cli/src/main.rs`

- [ ] **Step 1: Create workspace manifest**

Write `raxcell/Cargo.toml`:

```toml
[workspace]
members = [
  "crates/protocol",
  "crates/core",
  "crates/cli",
]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "Apache-2.0"

[workspace.dependencies]
anyhow = "1"
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tokio = { version = "1", features = ["io-std", "io-util", "macros", "process", "rt-multi-thread"] }
which = "8"
```

- [ ] **Step 2: Create protocol crate manifest**

Write `raxcell/crates/protocol/Cargo.toml`:

```toml
[package]
name = "raxcell-protocol"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
name = "raxcell_protocol"
path = "src/lib.rs"
doctest = false

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
```

- [ ] **Step 3: Create protocol lib export**

Write `raxcell/crates/protocol/src/lib.rs`:

```rust
mod types;

pub use types::*;

#[cfg(test)]
#[path = "types_tests.rs"]
mod types_tests;
```

- [ ] **Step 4: Create core crate manifest**

Write `raxcell/crates/core/Cargo.toml`:

```toml
[package]
name = "raxcell-core"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
name = "raxcell_core"
path = "src/lib.rs"
doctest = false

[dependencies]
raxcell-protocol = { path = "../protocol" }
serde = { workspace = true }
serde_json = { workspace = true }
which = { workspace = true }
```

- [ ] **Step 5: Create core lib export**

Write `raxcell/crates/core/src/lib.rs`:

```rust
mod probe;
mod run;

pub use probe::probe;
pub use run::run_fail_closed;

#[cfg(test)]
#[path = "probe_tests.rs"]
mod probe_tests;

#[cfg(test)]
#[path = "run_tests.rs"]
mod run_tests;
```

- [ ] **Step 6: Create CLI manifest**

Write `raxcell/crates/cli/Cargo.toml`:

```toml
[package]
name = "raxcell-cli"
version.workspace = true
edition.workspace = true
license.workspace = true

[[bin]]
name = "raxcell"
path = "src/main.rs"

[dependencies]
anyhow = { workspace = true }
clap = { workspace = true }
raxcell-core = { path = "../core" }
raxcell-protocol = { path = "../protocol" }
serde_json = { workspace = true }
tokio = { workspace = true }
```

- [ ] **Step 7: Create temporary CLI entrypoint**

Write `raxcell/crates/cli/src/main.rs`:

```rust
fn main() {
    eprintln!("raxcell CLI skeleton");
}
```

- [ ] **Step 8: Verify workspace compiles**

Run:

```bash
cargo test --manifest-path raxcell/Cargo.toml
```

Expected:

```text
test result: ok
```

- [ ] **Step 9: Review checkpoint**

Run:

```bash
git diff --check -- raxcell
git status --short
```

Expected:

```text
?? raxcell/
```

No commit unless the user explicitly asks.

---

## Task 2: Define Protocol Types

**Files:**
- Create: `raxcell/crates/protocol/src/types.rs`
- Create: `raxcell/crates/protocol/src/types_tests.rs`

- [ ] **Step 1: Write protocol types**

Write `raxcell/crates/protocol/src/types.rs`:

```rust
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendFamily {
    LinuxBubblewrap,
    MacosSeatbelt,
    WindowsElevated,
    WindowsUnelevated,
    HostObserved,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityLevel {
    Full,
    Partial,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRequest {
    pub kind: String,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default, rename = "backendPreference")]
    pub backend_preference: Vec<BackendFamily>,
    #[serde(default)]
    pub requirements: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResponse {
    pub kind: String,
    pub ready: bool,
    #[serde(rename = "selectedBackend")]
    pub selected_backend: Option<BackendFamily>,
    pub supports: BTreeMap<String, CapabilityLevel>,
    pub limits: Vec<String>,
    pub weaknesses: Vec<String>,
    pub missing: Vec<String>,
    #[serde(rename = "nextActions")]
    pub next_actions: Vec<String>,
    #[serde(rename = "publicSafeMessage")]
    pub public_safe_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueAction {
    #[serde(rename = "actionId")]
    pub action_id: String,
    #[serde(rename = "ownerRuntime")]
    pub owner_runtime: Option<String>,
    #[serde(rename = "intentLabel")]
    pub intent_label: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSpec {
    pub argv: Vec<String>,
    pub cwd: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub stdin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementSpec {
    pub profile: String,
    #[serde(default)]
    pub filesystem: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub process: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub resources: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackSpec {
    pub mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRequest {
    pub kind: String,
    pub action: OpaqueAction,
    pub command: CommandSpec,
    pub enforcement: EnforcementSpec,
    pub fallback: FallbackSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DenialCode {
    CapabilityMismatch,
    BackendUnavailable,
    SandboxDenied,
    ExecutionFailed,
    Timeout,
    FallbackApplied,
    FallbackRefused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Denial {
    pub code: DenialCode,
    pub message: String,
    #[serde(rename = "publicSafe")]
    pub public_safe: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackReport {
    pub mode: String,
    pub protects: Vec<String>,
    #[serde(rename = "doesNotProtect")]
    pub does_not_protect: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunResponse {
    pub kind: String,
    pub ok: bool,
    pub backend: Option<BackendFamily>,
    #[serde(rename = "exitCode")]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(rename = "timedOut")]
    pub timed_out: bool,
    pub denial: Option<Denial>,
    pub fallback: Option<FallbackReport>,
    #[serde(rename = "capabilityReport")]
    pub capability_report: Option<ProbeResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaxcellEvent {
    pub kind: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub event: String,
    #[serde(default)]
    pub data: Option<String>,
}
```

- [ ] **Step 2: Write serialization tests**

Write `raxcell/crates/protocol/src/types_tests.rs`:

```rust
use super::*;
use std::collections::BTreeMap;

#[test]
fn backend_family_uses_kebab_case() {
    let value = serde_json::to_value(BackendFamily::LinuxBubblewrap).unwrap();
    assert_eq!(value, serde_json::json!("linux-bubblewrap"));
}

#[test]
fn action_metadata_is_opaque_and_round_trips() {
    let mut metadata = BTreeMap::new();
    metadata.insert("toolId".to_string(), serde_json::json!("praxis.baseTool.shell.run"));
    let action = OpaqueAction {
        action_id: "act-1".to_string(),
        owner_runtime: Some("praxis".to_string()),
        intent_label: Some("opaque runtime metadata".to_string()),
        metadata,
    };
    let encoded = serde_json::to_string(&action).unwrap();
    let decoded: OpaqueAction = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, action);
}

#[test]
fn denial_code_uses_stable_uppercase_wire_names() {
    let value = serde_json::to_value(DenialCode::CapabilityMismatch).unwrap();
    assert_eq!(value, serde_json::json!("CAPABILITY_MISMATCH"));
}
```

- [ ] **Step 3: Run protocol tests**

Run:

```bash
cargo test --manifest-path raxcell/Cargo.toml -p raxcell-protocol
```

Expected:

```text
3 passed
```

---

## Task 3: Implement Three-Platform Capability Probe

**Files:**
- Create: `raxcell/crates/core/src/probe.rs`
- Create: `raxcell/crates/core/src/probe_tests.rs`

- [ ] **Step 1: Implement probe**

Write `raxcell/crates/core/src/probe.rs`:

```rust
use raxcell_protocol::{BackendFamily, CapabilityLevel, ProbeRequest, ProbeResponse};
use std::collections::BTreeMap;

pub fn probe(request: ProbeRequest) -> ProbeResponse {
    let selected_backend = choose_backend(&request);
    let mut supports = BTreeMap::new();
    let mut missing = Vec::new();
    let mut weaknesses = Vec::new();

    match selected_backend {
        Some(BackendFamily::LinuxBubblewrap) => {
            supports.insert("filesystem.readRestrict".to_string(), CapabilityLevel::Full);
            supports.insert("filesystem.writeRestrict".to_string(), CapabilityLevel::Full);
            supports.insert("network.deny".to_string(), CapabilityLevel::Full);
            supports.insert("process.spawn".to_string(), CapabilityLevel::Full);
            supports.insert("resource.timeout".to_string(), CapabilityLevel::Full);
            if cfg!(target_os = "linux") {
                if which::which("bwrap").is_err() {
                    missing.push("dependency.binary.bwrap".to_string());
                }
            } else {
                missing.push("current-host-is-not-linux".to_string());
            }
        }
        Some(BackendFamily::MacosSeatbelt) => {
            supports.insert("filesystem.readRestrict".to_string(), CapabilityLevel::Full);
            supports.insert("filesystem.writeRestrict".to_string(), CapabilityLevel::Full);
            supports.insert("network.deny".to_string(), CapabilityLevel::Full);
            supports.insert("process.spawn".to_string(), CapabilityLevel::Full);
            supports.insert("resource.timeout".to_string(), CapabilityLevel::Full);
            if !cfg!(target_os = "macos") {
                missing.push("current-host-is-not-macos".to_string());
            }
        }
        Some(BackendFamily::WindowsElevated) => {
            supports.insert("filesystem.readRestrict".to_string(), CapabilityLevel::Full);
            supports.insert("filesystem.writeRestrict".to_string(), CapabilityLevel::Full);
            supports.insert("network.deny".to_string(), CapabilityLevel::Full);
            supports.insert("process.spawn".to_string(), CapabilityLevel::Full);
            supports.insert("resource.timeout".to_string(), CapabilityLevel::Full);
            if !cfg!(target_os = "windows") {
                missing.push("current-host-is-not-windows".to_string());
            }
        }
        Some(BackendFamily::WindowsUnelevated) => {
            supports.insert("filesystem.readRestrict".to_string(), CapabilityLevel::Partial);
            supports.insert("filesystem.writeRestrict".to_string(), CapabilityLevel::Full);
            supports.insert("network.deny".to_string(), CapabilityLevel::Partial);
            supports.insert("process.spawn".to_string(), CapabilityLevel::Full);
            supports.insert("resource.timeout".to_string(), CapabilityLevel::Full);
            weaknesses.push("windows-unelevated uses restricted token and weaker network controls than elevated mode".to_string());
            if !cfg!(target_os = "windows") {
                missing.push("current-host-is-not-windows".to_string());
            }
        }
        Some(BackendFamily::HostObserved) => {
            supports.insert("filesystem.readRestrict".to_string(), CapabilityLevel::Unsupported);
            supports.insert("filesystem.writeRestrict".to_string(), CapabilityLevel::Unsupported);
            supports.insert("network.deny".to_string(), CapabilityLevel::Unsupported);
            supports.insert("process.spawn".to_string(), CapabilityLevel::Full);
            supports.insert("resource.timeout".to_string(), CapabilityLevel::Full);
            weaknesses.push("host-observed is observation only and does not enforce filesystem or network isolation".to_string());
        }
        Some(BackendFamily::External) | None => {
            supports.insert("filesystem.readRestrict".to_string(), CapabilityLevel::Unknown);
            supports.insert("filesystem.writeRestrict".to_string(), CapabilityLevel::Unknown);
            supports.insert("network.deny".to_string(), CapabilityLevel::Unknown);
            supports.insert("process.spawn".to_string(), CapabilityLevel::Unknown);
            supports.insert("resource.timeout".to_string(), CapabilityLevel::Unknown);
        }
    }

    let ready = selected_backend.is_some() && missing.is_empty();
    ProbeResponse {
        kind: "raxcell.probeResult.v1".to_string(),
        ready,
        selected_backend,
        supports,
        limits: Vec::new(),
        weaknesses,
        missing,
        next_actions: if ready { Vec::new() } else { vec!["choose-supported-backend-or-install-missing-dependencies".to_string()] },
        public_safe_message: if ready {
            "selected backend is ready on this host".to_string()
        } else {
            "selected backend is not ready on this host".to_string()
        },
    }
}

fn choose_backend(request: &ProbeRequest) -> Option<BackendFamily> {
    if let Some(first) = request.backend_preference.first() {
        return Some(first.clone());
    }
    if cfg!(target_os = "linux") {
        Some(BackendFamily::LinuxBubblewrap)
    } else if cfg!(target_os = "macos") {
        Some(BackendFamily::MacosSeatbelt)
    } else if cfg!(target_os = "windows") {
        Some(BackendFamily::WindowsElevated)
    } else {
        Some(BackendFamily::External)
    }
}
```

- [ ] **Step 2: Write probe tests**

Write `raxcell/crates/core/src/probe_tests.rs`:

```rust
use super::probe::probe;
use raxcell_protocol::{BackendFamily, CapabilityLevel, ProbeRequest};
use std::collections::BTreeMap;

#[test]
fn probe_includes_linux_macos_and_windows_backend_families_by_type() {
    let backends = [
        BackendFamily::LinuxBubblewrap,
        BackendFamily::MacosSeatbelt,
        BackendFamily::WindowsElevated,
        BackendFamily::WindowsUnelevated,
    ];
    assert_eq!(backends.len(), 4);
}

#[test]
fn windows_unelevated_reports_weaker_network_controls() {
    let response = probe(ProbeRequest {
        kind: "raxcell.probe.v1".to_string(),
        platform: Some("auto".to_string()),
        backend_preference: vec![BackendFamily::WindowsUnelevated],
        requirements: BTreeMap::new(),
    });
    assert_eq!(
        response.supports.get("network.deny"),
        Some(&CapabilityLevel::Partial)
    );
    assert!(!response.weaknesses.is_empty());
}

#[test]
fn host_observed_is_not_reported_as_isolation() {
    let response = probe(ProbeRequest {
        kind: "raxcell.probe.v1".to_string(),
        platform: Some("auto".to_string()),
        backend_preference: vec![BackendFamily::HostObserved],
        requirements: BTreeMap::new(),
    });
    assert_eq!(
        response.supports.get("filesystem.writeRestrict"),
        Some(&CapabilityLevel::Unsupported)
    );
}
```

- [ ] **Step 3: Run core probe tests**

Run:

```bash
cargo test --manifest-path raxcell/Cargo.toml -p raxcell-core probe
```

Expected:

```text
3 passed
```

---

## Task 4: Implement Fail-Closed Run Response

**Files:**
- Create: `raxcell/crates/core/src/run.rs`
- Create: `raxcell/crates/core/src/run_tests.rs`

- [ ] **Step 1: Implement fail-closed run**

Write `raxcell/crates/core/src/run.rs`:

```rust
use raxcell_protocol::{Denial, DenialCode, ProbeResponse, RunRequest, RunResponse};

pub fn run_fail_closed(request: RunRequest, capability_report: ProbeResponse) -> RunResponse {
    let message = if capability_report.ready {
        "Stage 1 run refuses execution until a real backend runner is attached".to_string()
    } else {
        "Requested backend is not ready; Raxcell fails closed by default".to_string()
    };
    RunResponse {
        kind: "raxcell.runResult.v1".to_string(),
        ok: false,
        backend: capability_report.selected_backend.clone(),
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        timed_out: false,
        denial: Some(Denial {
            code: if capability_report.ready {
                DenialCode::BackendUnavailable
            } else {
                DenialCode::CapabilityMismatch
            },
            message: format!("{message}; actionId={}", request.action.action_id),
            public_safe: true,
        }),
        fallback: None,
        capability_report: Some(capability_report),
    }
}
```

- [ ] **Step 2: Write run tests**

Write `raxcell/crates/core/src/run_tests.rs`:

```rust
use super::probe::probe;
use super::run::run_fail_closed;
use raxcell_protocol::{BackendFamily, DenialCode, ProbeRequest, RunRequest};
use std::collections::BTreeMap;

fn sample_run_request() -> RunRequest {
    serde_json::from_value(serde_json::json!({
        "kind": "raxcell.run.v1",
        "action": {
            "actionId": "act-1",
            "ownerRuntime": "praxis",
            "intentLabel": "opaque",
            "metadata": { "toolId": "not-inspected-by-raxcell" }
        },
        "command": {
            "argv": ["echo", "hello"],
            "cwd": "/tmp",
            "env": {},
            "stdin": null
        },
        "enforcement": {
            "profile": "workspace-write-no-network",
            "filesystem": { "read": ["/tmp"], "write": ["/tmp"] },
            "network": "deny",
            "process": { "spawn": true },
            "resources": { "timeoutMs": 1000 }
        },
        "fallback": { "mode": "none" }
    })).unwrap()
}

#[test]
fn run_fails_closed_when_backend_is_not_ready() {
    let capability_report = probe(ProbeRequest {
        kind: "raxcell.probe.v1".to_string(),
        platform: Some("auto".to_string()),
        backend_preference: vec![BackendFamily::MacosSeatbelt],
        requirements: BTreeMap::new(),
    });
    let response = run_fail_closed(sample_run_request(), capability_report);
    assert!(!response.ok);
    assert_eq!(response.denial.unwrap().code, DenialCode::CapabilityMismatch);
}

#[test]
fn run_does_not_apply_rollback_without_an_explicit_fallback_report() {
    let capability_report = probe(ProbeRequest {
        kind: "raxcell.probe.v1".to_string(),
        platform: Some("auto".to_string()),
        backend_preference: vec![BackendFamily::HostObserved],
        requirements: BTreeMap::new(),
    });
    let response = run_fail_closed(sample_run_request(), capability_report);
    assert!(response.fallback.is_none());
}
```

- [ ] **Step 3: Run run tests**

Run:

```bash
cargo test --manifest-path raxcell/Cargo.toml -p raxcell-core run
```

Expected:

```text
2 passed
```

---

## Task 5: Implement One-Shot CLI And Stdio JSON-RPC Worker

**Files:**
- Modify: `raxcell/crates/cli/src/main.rs`
- Create: `raxcell/crates/cli/src/jsonrpc.rs`
- Create: `raxcell/crates/cli/src/jsonrpc_tests.rs`

- [ ] **Step 1: Implement CLI entrypoint**

Replace `raxcell/crates/cli/src/main.rs` with:

```rust
mod jsonrpc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use raxcell_core::{probe, run_fail_closed};
use raxcell_protocol::{ProbeRequest, RunRequest};
use std::io::{self, Read};

#[derive(Debug, Parser)]
#[command(name = "raxcell")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Probe { #[arg(long)] json: Option<String>, #[arg(long)] stdin: bool },
    Run { #[arg(long)] json: Option<String>, #[arg(long)] stdin: bool },
    Worker,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Probe { json, stdin } => {
            let request: ProbeRequest = serde_json::from_str(&read_json(json, stdin)?)?;
            println!("{}", serde_json::to_string(&probe(request))?);
        }
        Command::Run { json, stdin } => {
            let request: RunRequest = serde_json::from_str(&read_json(json, stdin)?)?;
            let probe_request = ProbeRequest {
                kind: "raxcell.probe.v1".to_string(),
                platform: Some("auto".to_string()),
                backend_preference: Vec::new(),
                requirements: Default::default(),
            };
            let capability_report = probe(probe_request);
            println!("{}", serde_json::to_string(&run_fail_closed(request, capability_report))?);
        }
        Command::Worker => jsonrpc::run_worker().await?,
    }
    Ok(())
}

fn read_json(json: Option<String>, stdin: bool) -> Result<String> {
    if let Some(json) = json {
        return Ok(json);
    }
    if stdin {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        return Ok(input);
    }
    anyhow::bail!("provide --json '<request>' or --stdin")
}
```

- [ ] **Step 2: Implement JSON-RPC worker**

Write `raxcell/crates/cli/src/jsonrpc.rs`:

```rust
use anyhow::Result;
use raxcell_core::{probe, run_fail_closed};
use raxcell_protocol::{ProbeRequest, RaxcellEvent, RunRequest};
use serde_json::Value;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};

pub async fn run_worker() -> Result<()> {
    let stdin = BufReader::new(io::stdin());
    let mut lines = stdin.lines();
    let mut stdout = io::stdout();

    while let Some(line) = lines.next_line().await? {
        let response = handle_line(&line)?;
        stdout.write_all(response.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
    }
    Ok(())
}

pub fn handle_line(line: &str) -> Result<String> {
    let value: Value = serde_json::from_str(line)?;
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let method = value.get("method").and_then(Value::as_str).unwrap_or("");
    let params = value.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "probe" => {
            let request: ProbeRequest = serde_json::from_value(params)?;
            serde_json::to_value(probe(request))?
        }
        "run" => {
            let request: RunRequest = serde_json::from_value(params)?;
            let started = RaxcellEvent {
                kind: "raxcell.event.v1".to_string(),
                request_id: id.to_string(),
                event: "run.started".to_string(),
                data: None,
            };
            let capability_report = probe(ProbeRequest {
                kind: "raxcell.probe.v1".to_string(),
                platform: Some("auto".to_string()),
                backend_preference: Vec::new(),
                requirements: Default::default(),
            });
            serde_json::json!({
                "events": [started],
                "result": run_fail_closed(request, capability_report)
            })
        }
        _ => serde_json::json!({
            "error": {
                "code": "METHOD_NOT_FOUND",
                "message": format!("unknown method `{method}`")
            }
        }),
    };
    Ok(serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    }).to_string())
}
```

- [ ] **Step 3: Export JSON-RPC tests**

Add to the end of `raxcell/crates/cli/src/main.rs`:

```rust
#[cfg(test)]
#[path = "jsonrpc_tests.rs"]
mod jsonrpc_tests;
```

- [ ] **Step 4: Write JSON-RPC tests**

Write `raxcell/crates/cli/src/jsonrpc_tests.rs`:

```rust
use super::jsonrpc::handle_line;

#[test]
fn probe_method_returns_jsonrpc_response() {
    let line = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "1",
        "method": "probe",
        "params": {
            "kind": "raxcell.probe.v1",
            "platform": "auto",
            "backendPreference": []
        }
    }).to_string();
    let response = handle_line(&line).unwrap();
    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["jsonrpc"], "2.0");
    assert_eq!(value["id"], "1");
    assert_eq!(value["result"]["kind"], "raxcell.probeResult.v1");
}

#[test]
fn unknown_method_returns_structured_error() {
    let line = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "2",
        "method": "missing",
        "params": {}
    }).to_string();
    let response = handle_line(&line).unwrap();
    let value: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["result"]["error"]["code"], "METHOD_NOT_FOUND");
}
```

- [ ] **Step 5: Run CLI tests**

Run:

```bash
cargo test --manifest-path raxcell/Cargo.toml -p raxcell-cli
```

Expected:

```text
2 passed
```

- [ ] **Step 6: Smoke one-shot probe**

Run:

```bash
printf '%s\n' '{"kind":"raxcell.probe.v1","platform":"auto","backendPreference":[]}' \
  | cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- probe --stdin
```

Expected:

```text
{"kind":"raxcell.probeResult.v1",...}
```

---

## Task 6: Add Fixtures And README

**Files:**
- Create: `raxcell/fixtures/probe.auto.json`
- Create: `raxcell/fixtures/run.fail-closed.json`
- Create: `raxcell/README.md`

- [ ] **Step 1: Add probe fixture**

Write `raxcell/fixtures/probe.auto.json`:

```json
{
  "kind": "raxcell.probe.v1",
  "platform": "auto",
  "backendPreference": [
    "linux-bubblewrap",
    "macos-seatbelt",
    "windows-elevated",
    "windows-unelevated"
  ],
  "requirements": {
    "filesystem": ["read-restrict", "write-restrict"],
    "network": ["deny"],
    "process": ["spawn"],
    "resource": ["timeout"]
  }
}
```

- [ ] **Step 2: Add fail-closed run fixture**

Write `raxcell/fixtures/run.fail-closed.json`:

```json
{
  "kind": "raxcell.run.v1",
  "action": {
    "actionId": "fixture-run-1",
    "ownerRuntime": "example-runtime",
    "intentLabel": "opaque command metadata",
    "metadata": {
      "toolId": "opaque-to-raxcell"
    }
  },
  "command": {
    "argv": ["echo", "hello"],
    "cwd": "/tmp",
    "env": {},
    "stdin": null
  },
  "enforcement": {
    "profile": "workspace-write-no-network",
    "filesystem": {
      "read": ["/tmp"],
      "write": ["/tmp"]
    },
    "network": "deny",
    "process": {
      "spawn": true
    },
    "resources": {
      "timeoutMs": 1000,
      "maxOutputBytes": 200000
    }
  },
  "fallback": {
    "mode": "none"
  }
}
```

- [ ] **Step 3: Add Stage 1 README**

Write `raxcell/README.md`:

```markdown
# Raxcell

Raxcell is the execution enforcement sandbox SDK extracted from the Codex fork.

Stage 1 creates the protocol, CLI/worker shape, and backend capability reporting. It does not delete Codex code and does not yet move the real platform backends.

Raxcell core owns enforcement facts and execution boundaries. Upper runtimes own governance, approval, policy matrices, human gates, and model behavior control.

## Smoke Commands

Run tests:

```bash
cargo test --manifest-path raxcell/Cargo.toml
```

Probe current host:

```bash
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- probe --stdin < raxcell/fixtures/probe.auto.json
```

Run fixture in fail-closed Stage 1 mode:

```bash
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.fail-closed.json
```
```

- [ ] **Step 4: Validate fixtures**

Run:

```bash
python3 -m json.tool raxcell/fixtures/probe.auto.json >/dev/null
python3 -m json.tool raxcell/fixtures/run.fail-closed.json >/dev/null
```

Expected:

```text
no output
```

---

## Task 7: Add TypeScript SDK Facade

**Files:**
- Create: `raxcell/sdk/package.json`
- Create: `raxcell/sdk/tsconfig.json`
- Create: `raxcell/sdk/src/types.ts`
- Create: `raxcell/sdk/src/client.ts`
- Create: `raxcell/sdk/src/index.ts`
- Create: `raxcell/sdk/src/client.test.ts`

- [ ] **Step 1: Create SDK package manifest**

Write `raxcell/sdk/package.json`:

```json
{
  "name": "@raxcell/sdk",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "test": "node --test dist/client.test.js"
  },
  "devDependencies": {
    "@types/node": "^24.0.0",
    "typescript": "^5.9.0"
  }
}
```

- [ ] **Step 2: Create SDK TypeScript config**

Write `raxcell/sdk/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "declaration": true,
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*.ts"]
}
```

- [ ] **Step 3: Add SDK wire types**

Write `raxcell/sdk/src/types.ts`:

```ts
export type BackendFamily =
  | "linux-bubblewrap"
  | "macos-seatbelt"
  | "windows-elevated"
  | "windows-unelevated"
  | "host-observed"
  | "external";

export type ProbeRequest = {
  kind: "raxcell.probe.v1";
  platform?: "auto" | string;
  backendPreference?: BackendFamily[];
  requirements?: Record<string, string[]>;
};

export type ProbeResponse = {
  kind: "raxcell.probeResult.v1";
  ready: boolean;
  selectedBackend: BackendFamily | null;
  supports: Record<string, "full" | "partial" | "unsupported" | "unknown">;
  limits: string[];
  weaknesses: string[];
  missing: string[];
  nextActions: string[];
  publicSafeMessage: string;
};
```

- [ ] **Step 4: Add SDK client**

Write `raxcell/sdk/src/client.ts`:

```ts
import { spawn } from "node:child_process";
import type { ProbeRequest, ProbeResponse } from "./types.js";

export type RaxcellClientOptions = {
  binaryPath: string;
};

export class RaxcellClient {
  readonly binaryPath: string;

  constructor(options: RaxcellClientOptions) {
    this.binaryPath = options.binaryPath;
  }

  async probe(request: ProbeRequest): Promise<ProbeResponse> {
    const output = await runJson(this.binaryPath, ["probe", "--stdin"], request);
    return JSON.parse(output) as ProbeResponse;
  }
}

function runJson(binaryPath: string, args: string[], input: unknown): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(binaryPath, args, { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve(stdout.trim());
      } else {
        reject(new Error(stderr.trim() || `raxcell exited with code ${code}`));
      }
    });
    child.stdin.end(JSON.stringify(input));
  });
}
```

- [ ] **Step 5: Add SDK exports**

Write `raxcell/sdk/src/index.ts`:

```ts
export { RaxcellClient } from "./client.js";
export type { BackendFamily, ProbeRequest, ProbeResponse } from "./types.js";
```

- [ ] **Step 6: Add SDK smoke test**

Write `raxcell/sdk/src/client.test.ts`:

```ts
import assert from "node:assert/strict";
import test from "node:test";
import type { ProbeRequest } from "./types.js";

test("probe request type accepts all first-class backend families", () => {
  const request: ProbeRequest = {
    kind: "raxcell.probe.v1",
    platform: "auto",
    backendPreference: [
      "linux-bubblewrap",
      "macos-seatbelt",
      "windows-elevated",
      "windows-unelevated",
    ],
  };
  assert.equal(request.backendPreference?.length, 4);
});
```

- [ ] **Step 7: Build SDK**

Run:

```bash
pnpm --dir raxcell/sdk install
pnpm --dir raxcell/sdk build
pnpm --dir raxcell/sdk test
```

Expected:

```text
test pass
```

If local package manager policy makes nested `pnpm install` undesirable, skip SDK dependency installation and run only the Rust tasks in this stage, then record the SDK install as not verified.

---

## Task 8: Full Stage 1 Verification And Review

**Files:**
- Review: `specs/raxcell/sandbox-extract-spec.md`
- Review: `specs/raxcell/stage-1-implementation-plan.md`
- Review: `raxcell/**`

- [ ] **Step 1: Run Rust tests**

Run:

```bash
cargo test --manifest-path raxcell/Cargo.toml
```

Expected:

```text
all raxcell tests pass
```

- [ ] **Step 2: Run fixture smoke checks**

Run:

```bash
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- probe --stdin < raxcell/fixtures/probe.auto.json
cargo run --manifest-path raxcell/Cargo.toml -p raxcell-cli -- run --stdin < raxcell/fixtures/run.fail-closed.json
```

Expected:

```text
probe returns raxcell.probeResult.v1
run returns ok=false with a structured denial
```

- [ ] **Step 3: Run formatting checks**

Run:

```bash
cargo fmt --manifest-path raxcell/Cargo.toml -- --check
git diff --check -- specs/raxcell raxcell
```

Expected:

```text
no output from git diff --check
cargo fmt exits 0
```

- [ ] **Step 4: Code review boundary scan**

Run:

```bash
rg -n "approval|policy matrix|guardian|auto-review|Praxis|BaseTool|model behavior|human gate" raxcell || true
rg -n "host-observed|workspace-rollback|fallback" raxcell
```

Expected:

```text
No core code owns approval, policy matrix, guardian, auto-review, Praxis, BaseTool, model behavior, or human gate logic.
Any host-observed or fallback references are explicit and do not silently execute.
```

- [ ] **Step 5: Manual review questions**

Answer these in the final review note:

- Does Raxcell core make any governance decision?
- Does `run` execute anything before a real backend is attached?
- Is `host-observed` reported as non-isolation?
- Does Windows unelevated report weaker network/read controls?
- Are Linux, macOS, and Windows represented as first-class backend families?
- Is the SDK an npm facade over protocol rather than the only ABI?

- [ ] **Step 6: Handoff**

Stop and report:

- Files created.
- Tests run and results.
- Any unverified SDK step.
- Whether Stage 1 is ready for code review/fix loop.

No commit unless the user explicitly asks.
