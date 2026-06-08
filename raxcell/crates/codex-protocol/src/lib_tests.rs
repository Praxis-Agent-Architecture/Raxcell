use super::*;
use serde_json::json;
use std::num::NonZeroUsize;
use std::path::PathBuf;

#[test]
fn serializes_tagged_managed_permission_profile() {
    let profile = PermissionProfile::Managed {
        file_system: ManagedFileSystemPermissions::Restricted {
            entries: vec![FileSystemSandboxEntry {
                path: FileSystemPath::Path {
                    path: PathBuf::from("/workspace"),
                },
                access: FileSystemAccessMode::Read,
            }],
            glob_scan_max_depth: NonZeroUsize::new(3),
        },
        network: NetworkSandboxPolicy::Restricted,
    };

    let value = serde_json::to_value(profile).expect("profile should serialize");

    assert_eq!(
        value,
        json!({
            "type": "managed",
            "file_system": {
                "type": "restricted",
                "entries": [
                    {
                        "path": {
                            "type": "path",
                            "path": "/workspace"
                        },
                        "access": "read"
                    }
                ],
                "glob_scan_max_depth": 3
            },
            "network": "restricted"
        })
    );
}

#[test]
fn accepts_access_mode_none_alias_as_deny() {
    let access: FileSystemAccessMode =
        serde_json::from_value(json!("none")).expect("none should alias deny");

    assert_eq!(access, FileSystemAccessMode::Deny);
    assert!(!access.can_read());
    assert!(!access.can_write());
}

#[test]
fn network_policy_uses_kebab_case_and_reports_enabled_state() {
    let enabled = NetworkSandboxPolicy::Enabled;
    let restricted = NetworkSandboxPolicy::Restricted;

    assert_eq!(
        serde_json::to_value(enabled).expect("network policy should serialize"),
        json!("enabled")
    );
    assert!(enabled.is_enabled());
    assert!(!restricted.is_enabled());
}

#[test]
fn filesystem_policy_constructors_preserve_kind_and_entries() {
    let entries = vec![
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: PathBuf::from("/readable"),
            },
            access: FileSystemAccessMode::Read,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::GlobPattern {
                pattern: "/tmp/**".to_string(),
            },
            access: FileSystemAccessMode::Deny,
        },
    ];

    assert_eq!(
        FileSystemSandboxPolicy::restricted(entries.clone()),
        FileSystemSandboxPolicy {
            kind: FileSystemSandboxKind::Restricted,
            glob_scan_max_depth: None,
            entries
        }
    );
    assert_eq!(
        FileSystemSandboxPolicy::read_only(),
        FileSystemSandboxPolicy::restricted(vec![FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            access: FileSystemAccessMode::Read,
        }])
    );
    assert_eq!(
        FileSystemSandboxPolicy::unrestricted().kind,
        FileSystemSandboxKind::Unrestricted
    );
    assert_eq!(
        FileSystemSandboxPolicy::external_sandbox().kind,
        FileSystemSandboxKind::ExternalSandbox
    );
}

#[test]
fn protected_metadata_helpers_match_codex_names() {
    assert_eq!(PROTECTED_METADATA_PATH_NAMES, [".git", ".agents", ".codex"]);

    assert!(is_protected_metadata_name(".git"));
    assert!(is_protected_metadata_name(".agents"));
    assert!(is_protected_metadata_name(".codex"));
    assert!(!is_protected_metadata_name(".raxcell"));

    assert!(!is_protected_metadata_directory_name(".git"));
    assert!(is_protected_metadata_directory_name(".agents"));
    assert!(is_protected_metadata_directory_name(".codex"));
}

#[test]
fn unrestricted_and_external_policies_have_full_disk_access() {
    for policy in [
        FileSystemSandboxPolicy::unrestricted(),
        FileSystemSandboxPolicy::external_sandbox(),
    ] {
        assert!(policy.has_full_disk_read_access());
        assert!(policy.has_full_disk_write_access());
        assert!(policy.can_read_path("/workspace/.git/config"));
        assert!(policy.can_write_path("/workspace/.git/config"));
    }
}

#[test]
fn writable_roots_do_not_allow_metadata_writes_without_explicit_rule() {
    let policy = FileSystemSandboxPolicy::restricted(vec![FileSystemSandboxEntry {
        path: FileSystemPath::Path {
            path: PathBuf::from("/workspace"),
        },
        access: FileSystemAccessMode::Write,
    }]);

    assert!(policy.can_read_path("/workspace/src/main.rs"));
    assert!(policy.can_write_path("/workspace/src/main.rs"));
    assert!(!policy.can_write_path("/workspace/.git/config"));
    assert!(!policy.can_write_path("/workspace/.agents/skills/example/SKILL.md"));
    assert!(!policy.can_write_path("/workspace/.codex/config.toml"));

    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: PathBuf::from("/workspace"),
            },
            access: FileSystemAccessMode::Write,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: PathBuf::from("/workspace/.codex"),
            },
            access: FileSystemAccessMode::Write,
        },
    ]);

    assert!(policy.can_write_path("/workspace/.codex/config.toml"));
    assert!(!policy.can_write_path("/workspace/.git/config"));
}

#[test]
fn root_write_with_additional_write_path_remains_full_disk_write() {
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            access: FileSystemAccessMode::Write,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: PathBuf::from("/workspace"),
            },
            access: FileSystemAccessMode::Write,
        },
    ]);

    assert!(policy.has_full_disk_read_access());
    assert!(policy.has_full_disk_write_access());
    assert!(policy.can_write_path("/workspace/src/main.rs"));
    assert!(policy.can_write_path("/workspace/.git/config"));
}

#[test]
fn root_write_with_same_path_read_and_write_remains_full_disk_write() {
    let shared_path = PathBuf::from("/workspace");
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            access: FileSystemAccessMode::Write,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: shared_path.clone(),
            },
            access: FileSystemAccessMode::Read,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path { path: shared_path },
            access: FileSystemAccessMode::Write,
        },
    ]);

    assert!(policy.has_full_disk_write_access());
    assert!(policy.can_write_path("/workspace/src/main.rs"));
}

#[test]
fn root_read_with_deny_entry_is_not_full_disk_read() {
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            access: FileSystemAccessMode::Read,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: PathBuf::from("/private"),
            },
            access: FileSystemAccessMode::Deny,
        },
    ]);

    assert!(!policy.has_full_disk_read_access());
    assert!(!policy.can_read_path("/private/secret.txt"));
}

#[test]
fn root_write_with_read_only_carveout_is_not_full_disk_write() {
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            access: FileSystemAccessMode::Write,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: PathBuf::from("/private"),
            },
            access: FileSystemAccessMode::Read,
        },
    ]);

    assert!(!policy.has_full_disk_write_access());
    assert!(!policy.can_write_path("/private/secret.txt"));
}

#[test]
fn root_write_with_same_path_deny_and_write_is_not_full_disk_write() {
    let shared_path = PathBuf::from("/private");
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            access: FileSystemAccessMode::Write,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: shared_path.clone(),
            },
            access: FileSystemAccessMode::Deny,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path { path: shared_path },
            access: FileSystemAccessMode::Write,
        },
    ]);

    assert!(!policy.has_full_disk_write_access());
    assert!(!policy.can_write_path("/private/secret.txt"));
}

#[test]
fn unsupported_deny_globs_make_access_helpers_fail_closed() {
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            access: FileSystemAccessMode::Read,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::GlobPattern {
                pattern: "/private/**".to_string(),
            },
            access: FileSystemAccessMode::Deny,
        },
    ]);

    assert!(!policy.has_full_disk_read_access());
    assert!(!policy.can_read_path("/workspace/src/main.rs"));
    assert!(!policy.can_write_path("/workspace/src/main.rs"));
}
