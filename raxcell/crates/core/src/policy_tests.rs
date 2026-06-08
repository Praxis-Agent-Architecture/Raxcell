use super::policy::{PolicyResolutionError, resolve_profile};
use raxcell_protocol::{BackendFamily, ResolveProfileRequest};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn temp_policy_path(name: &str, extension: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "raxcell-{name}-{}.{}",
        std::process::id(),
        extension
    ))
}

fn write_temp_policy(name: &str, extension: &str, content: &str) -> String {
    let path = temp_policy_path(name, extension);
    std::fs::write(&path, content).unwrap();
    path.to_string_lossy().into_owned()
}

fn request(path: String) -> ResolveProfileRequest {
    ResolveProfileRequest {
        kind: "raxcell.resolveProfile.v1".to_string(),
        pack_paths: vec![path],
        profile: "workspace-write-no-network".to_string(),
        variables: BTreeMap::from([
            ("workspace".to_string(), "/workspace/project".to_string()),
            ("home".to_string(), "/home/agent".to_string()),
            ("tmp".to_string(), "/tmp/raxcell".to_string()),
        ]),
    }
}

fn praxis_profiles_fixture_request(profile: &str) -> ResolveProfileRequest {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/policy.praxis-profiles.yaml");
    ResolveProfileRequest {
        kind: "raxcell.resolveProfile.v1".to_string(),
        pack_paths: vec![fixture.to_string_lossy().into_owned()],
        profile: profile.to_string(),
        variables: BTreeMap::from([
            ("workspace".to_string(), "/workspace/project".to_string()),
            ("home".to_string(), "/home/agent".to_string()),
            ("tmp".to_string(), "/tmp/raxcell".to_string()),
            (
                "approvedExternalRead".to_string(),
                "/mnt/approved-read".to_string(),
            ),
            (
                "approvedExternalWrite".to_string(),
                "/mnt/approved-write".to_string(),
            ),
        ]),
    }
}

#[test]
fn resolves_json_policy_pack_with_common_root_variables() {
    let path = write_temp_policy(
        "json-policy",
        "json",
        r#"{
          "kind": "raxcell.policyPack.v1",
          "name": "base",
          "profiles": {
            "workspace-write-no-network": {
              "preset": "workspace-write",
              "filesystem": {
                "read": ["$workspace", "$home/.cache"],
                "write": ["$workspace", "$tmp/build"]
              },
              "network": "deny",
              "process": { "spawn": true },
              "resources": { "timeoutMs": 1000 },
              "backendPreference": ["linux-bubblewrap"],
              "fallback": { "mode": "none" }
            }
          }
        }"#,
    );
    let resolved = resolve_profile(request(path)).unwrap();
    assert_eq!(
        resolved.enforcement.filesystem["read"],
        vec![
            "/workspace/project".to_string(),
            "/home/agent/.cache".to_string()
        ]
    );
    assert_eq!(
        resolved.enforcement.filesystem["write"],
        vec![
            "/workspace/project".to_string(),
            "/tmp/raxcell/build".to_string()
        ]
    );
    assert_eq!(resolved.enforcement.network, Some("deny".to_string()));
    assert_eq!(resolved.backend_preference.len(), 1);
}

#[test]
fn resolves_yaml_and_toml_policy_packs() {
    let yaml_path = write_temp_policy(
        "yaml-policy",
        "yaml",
        r#"
kind: raxcell.policyPack.v1
name: yaml-pack
profiles:
  workspace-write-no-network:
    preset: workspace-readonly
    network: deny
"#,
    );
    let yaml_resolved = resolve_profile(request(yaml_path)).unwrap();
    assert_eq!(
        yaml_resolved.enforcement.filesystem["read"],
        vec!["/workspace/project".to_string()]
    );
    assert!(yaml_resolved.enforcement.filesystem["write"].is_empty());

    let toml_path = write_temp_policy(
        "toml-policy",
        "toml",
        r#"
kind = "raxcell.policyPack.v1"
name = "toml-pack"

[profiles.workspace-write-no-network]
preset = "workspace-readonly"
network = "deny"
"#,
    );
    let toml_resolved = resolve_profile(request(toml_path)).unwrap();
    assert_eq!(
        toml_resolved.enforcement.filesystem["read"],
        vec!["/workspace/project".to_string()]
    );
    assert!(toml_resolved.enforcement.filesystem["write"].is_empty());
}

#[test]
fn rejects_policy_pack_cycles() {
    let parent = write_temp_policy(
        "cycle-a",
        "json",
        r#"{
          "kind": "raxcell.policyPack.v1",
          "name": "a",
          "extends": ["b"],
          "profiles": {
            "workspace-write-no-network": { "preset": "workspace-write" }
          }
        }"#,
    );
    let child = write_temp_policy(
        "cycle-b",
        "json",
        r#"{
          "kind": "raxcell.policyPack.v1",
          "name": "b",
          "extends": ["a"],
          "profiles": {
            "workspace-write-no-network": { "preset": "workspace-write" }
          }
        }"#,
    );
    let mut resolve_request = request(child);
    resolve_request.pack_paths.insert(0, parent);
    let error = resolve_profile(resolve_request).unwrap_err();
    assert!(matches!(error, PolicyResolutionError::Cycle { .. }));
}

#[test]
fn stricter_merge_wins_for_network_fallback_and_timeout() {
    let parent = write_temp_policy(
        "merge-parent",
        "json",
        r#"{
          "kind": "raxcell.policyPack.v1",
          "name": "parent",
          "profiles": {
            "workspace-write-no-network": {
              "preset": "workspace-write",
              "network": "allow",
              "resources": { "timeoutMs": 5000 },
              "fallback": { "mode": "workspace-rollback" }
            }
          }
        }"#,
    );
    let child = write_temp_policy(
        "merge-child",
        "json",
        r#"{
          "kind": "raxcell.policyPack.v1",
          "name": "child",
          "extends": ["parent"],
          "profiles": {
            "workspace-write-no-network": {
              "preset": "workspace-write",
              "network": "deny",
              "resources": { "timeoutMs": 1000 },
              "fallback": { "mode": "none" }
            }
          }
        }"#,
    );
    let mut resolve_request = request(child);
    resolve_request.pack_paths.insert(0, parent);
    let resolved = resolve_profile(resolve_request).unwrap();
    assert_eq!(resolved.enforcement.network, Some("deny".to_string()));
    assert_eq!(
        resolved.enforcement.resources["timeoutMs"],
        serde_json::json!(1000)
    );
    assert_eq!(resolved.fallback.mode, "none");
}

#[test]
fn no_filesystem_write_preset_tightens_parent_write_roots() {
    let parent = write_temp_policy(
        "no-write-parent",
        "json",
        r#"{
          "kind": "raxcell.policyPack.v1",
          "name": "parent-no-write",
          "profiles": {
            "workspace-write-no-network": {
              "preset": "workspace-write",
              "filesystem": { "write": ["$workspace"] }
            }
          }
        }"#,
    );
    let child = write_temp_policy(
        "no-write-child",
        "json",
        r#"{
          "kind": "raxcell.policyPack.v1",
          "name": "child-no-write",
          "extends": ["parent-no-write"],
          "profiles": {
            "workspace-write-no-network": {
              "preset": "no-filesystem-write"
            }
          }
        }"#,
    );
    let mut resolve_request = request(child);
    resolve_request.pack_paths.insert(0, parent);
    let resolved = resolve_profile(resolve_request).unwrap();
    assert!(resolved.enforcement.filesystem["write"].is_empty());
}

#[test]
fn resolves_praxis_profile_examples_fixture() {
    let expected = [
        (
            "host-observed",
            "allow",
            vec![],
            vec![],
            vec![BackendFamily::HostObserved],
        ),
        (
            "workspace-readonly-no-network",
            "deny",
            vec!["/workspace/project"],
            vec![],
            vec![BackendFamily::LinuxBubblewrap],
        ),
        (
            "workspace-write-no-network",
            "deny",
            vec!["/workspace/project", "/home/agent/.cache"],
            vec!["/workspace/project", "/tmp/raxcell/build"],
            vec![BackendFamily::LinuxBubblewrap],
        ),
        (
            "workspace-write-network",
            "allow",
            vec!["/workspace/project", "/home/agent/.cache"],
            vec!["/workspace/project", "/tmp/raxcell/build"],
            vec![BackendFamily::LinuxBubblewrap],
        ),
        (
            "external-read-approved",
            "deny",
            vec!["/workspace/project", "/mnt/approved-read"],
            vec![],
            vec![BackendFamily::LinuxBubblewrap],
        ),
        (
            "external-write-approved",
            "deny",
            vec!["/workspace/project", "/mnt/approved-write"],
            vec!["/workspace/project", "/mnt/approved-write"],
            vec![BackendFamily::LinuxBubblewrap],
        ),
        (
            "strict-fail-closed",
            "deny",
            vec!["/workspace/project"],
            vec![],
            vec![BackendFamily::LinuxBubblewrap],
        ),
        (
            "debug-artifact-rich",
            "deny",
            vec![
                "/workspace/project",
                "/home/agent/.cache",
                "/tmp/raxcell/debug",
            ],
            vec![
                "/workspace/project",
                "/tmp/raxcell/build",
                "/tmp/raxcell/debug",
            ],
            vec![BackendFamily::LinuxBubblewrap],
        ),
    ];

    for (profile, network, read_roots, write_roots, backend_preference) in expected {
        let resolved = resolve_profile(praxis_profiles_fixture_request(profile)).unwrap();
        assert_eq!(resolved.profile, profile);
        assert_eq!(resolved.enforcement.profile, profile);
        assert_eq!(resolved.enforcement.network, Some(network.to_string()));
        assert_eq!(
            resolved.enforcement.filesystem["read"],
            read_roots
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            resolved.enforcement.filesystem["write"],
            write_roots
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        );
        assert_eq!(resolved.backend_preference, backend_preference);
        assert_eq!(resolved.fallback.mode, "none");
        assert_eq!(
            resolved.enforcement.process["spawn"],
            serde_json::json!(true)
        );
        assert!(resolved.enforcement.resources.contains_key("timeoutMs"));
        assert!(
            resolved
                .enforcement
                .resources
                .contains_key("maxOutputBytes")
        );
    }
}
