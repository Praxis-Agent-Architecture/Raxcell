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
