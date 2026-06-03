use super::policy::{PolicyResolutionError, resolve_profile};
use raxcell_protocol::ResolveProfileRequest;
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
