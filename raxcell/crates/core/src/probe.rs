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
            supports.insert(
                "filesystem.writeRestrict".to_string(),
                CapabilityLevel::Full,
            );
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
            supports.insert(
                "filesystem.writeRestrict".to_string(),
                CapabilityLevel::Full,
            );
            supports.insert("network.deny".to_string(), CapabilityLevel::Full);
            supports.insert("process.spawn".to_string(), CapabilityLevel::Full);
            supports.insert("resource.timeout".to_string(), CapabilityLevel::Full);
            if !cfg!(target_os = "macos") {
                missing.push("current-host-is-not-macos".to_string());
            }
        }
        Some(BackendFamily::WindowsElevated) => {
            supports.insert("filesystem.readRestrict".to_string(), CapabilityLevel::Full);
            supports.insert(
                "filesystem.writeRestrict".to_string(),
                CapabilityLevel::Full,
            );
            supports.insert("network.deny".to_string(), CapabilityLevel::Full);
            supports.insert("process.spawn".to_string(), CapabilityLevel::Full);
            supports.insert("resource.timeout".to_string(), CapabilityLevel::Full);
            if !cfg!(target_os = "windows") {
                missing.push("current-host-is-not-windows".to_string());
            }
        }
        Some(BackendFamily::WindowsUnelevated) => {
            supports.insert(
                "filesystem.readRestrict".to_string(),
                CapabilityLevel::Partial,
            );
            supports.insert(
                "filesystem.writeRestrict".to_string(),
                CapabilityLevel::Full,
            );
            supports.insert("network.deny".to_string(), CapabilityLevel::Partial);
            supports.insert("process.spawn".to_string(), CapabilityLevel::Full);
            supports.insert("resource.timeout".to_string(), CapabilityLevel::Full);
            weaknesses.push(
                "windows-unelevated uses restricted token and weaker network controls than elevated mode"
                    .to_string(),
            );
            if !cfg!(target_os = "windows") {
                missing.push("current-host-is-not-windows".to_string());
            }
        }
        Some(BackendFamily::HostObserved) => {
            supports.insert(
                "filesystem.readRestrict".to_string(),
                CapabilityLevel::Unsupported,
            );
            supports.insert(
                "filesystem.writeRestrict".to_string(),
                CapabilityLevel::Unsupported,
            );
            supports.insert("network.deny".to_string(), CapabilityLevel::Unsupported);
            supports.insert("process.spawn".to_string(), CapabilityLevel::Full);
            supports.insert("resource.timeout".to_string(), CapabilityLevel::Full);
            weaknesses.push(
                "host-observed is observation only and does not enforce filesystem or network isolation"
                    .to_string(),
            );
        }
        Some(BackendFamily::External) | None => {
            supports.insert(
                "filesystem.readRestrict".to_string(),
                CapabilityLevel::Unknown,
            );
            supports.insert(
                "filesystem.writeRestrict".to_string(),
                CapabilityLevel::Unknown,
            );
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
        next_actions: if ready {
            Vec::new()
        } else {
            vec!["choose-supported-backend-or-install-missing-dependencies".to_string()]
        },
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
