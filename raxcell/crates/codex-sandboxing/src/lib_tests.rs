use crate::{
    CODEX_LINUX_SANDBOX_ARG0, SandboxCommand, SandboxError, SandboxManager,
    SandboxTransformRequest, SandboxType,
};
use raxcell_codex_protocol::{
    AdditionalPermissionProfile, FileSystemAccessMode, FileSystemPath, FileSystemPermissions,
    FileSystemSandboxEntry, FileSystemSpecialPath, ManagedFileSystemPermissions,
    NetworkPermissions, NetworkSandboxPolicy, PermissionProfile,
};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;

fn command() -> SandboxCommand {
    SandboxCommand {
        program: PathBuf::from("/bin/echo"),
        args: vec!["hello".to_string()],
        cwd: PathBuf::from("/workspace"),
        env: BTreeMap::from([("A".to_string(), "B".to_string())]),
        additional_permissions: Vec::new(),
    }
}

fn linux_request(helper: Option<PathBuf>) -> SandboxTransformRequest {
    SandboxTransformRequest {
        command: command(),
        permission_profile: PermissionProfile::External {
            network: NetworkSandboxPolicy::Restricted,
        },
        sandbox_type: SandboxType::LinuxSeccomp,
        sandbox_policy_cwd: PathBuf::from("/workspace"),
        codex_linux_sandbox_exe: helper,
        use_legacy_landlock: true,
        allow_network_for_proxy: false,
    }
}

#[test]
fn linux_transform_wraps_command_with_helper_args_and_arg0_override() {
    let manager = SandboxManager::new();

    let transformed = manager
        .transform(linux_request(Some(PathBuf::from("/opt/bin/helper"))))
        .expect("linux helper path should transform");

    assert_eq!(transformed.program, PathBuf::from("/opt/bin/helper"));
    assert_eq!(
        transformed.arg0_override.as_deref(),
        Some(CODEX_LINUX_SANDBOX_ARG0)
    );
    assert_eq!(
        transformed.args,
        vec![
            "--sandbox-policy-cwd",
            "/workspace",
            "--command-cwd",
            "/workspace",
            "--permission-profile",
            "{\"type\":\"external\",\"network\":\"restricted\"}",
            "--use-legacy-landlock",
            "--",
            "/bin/echo",
            "hello",
        ]
    );
}

#[test]
fn linux_transform_uses_helper_path_as_arg0_when_helper_is_named_codex_linux_sandbox() {
    let manager = SandboxManager::new();

    let transformed = manager
        .transform(linux_request(Some(PathBuf::from(
            "/opt/bin/codex-linux-sandbox",
        ))))
        .expect("named helper path should transform");

    assert_eq!(
        transformed.arg0_override.as_deref(),
        Some("/opt/bin/codex-linux-sandbox")
    );
    assert_eq!(
        transformed.args.first().map(String::as_str),
        Some("--sandbox-policy-cwd")
    );
}

#[test]
fn linux_transform_argv_uses_arg0_override() {
    let manager = SandboxManager::new();

    let transformed = manager
        .transform(linux_request(Some(PathBuf::from("/opt/bin/helper"))))
        .expect("linux helper path should transform");

    assert_eq!(transformed.program, PathBuf::from("/opt/bin/helper"));
    assert_eq!(
        transformed.arg0_override.as_deref(),
        Some(CODEX_LINUX_SANDBOX_ARG0)
    );
    assert_eq!(
        transformed.argv().first().map(String::as_str),
        Some(CODEX_LINUX_SANDBOX_ARG0)
    );
}

#[test]
fn seatbelt_lowering_includes_filesystem_and_network_grants() {
    let args = crate::seatbelt::create_seatbelt_command_args(
        vec!["/bin/echo".to_string(), "hello".to_string()],
        &PermissionProfile::Managed {
            file_system: ManagedFileSystemPermissions::Restricted {
                entries: vec![
                    FileSystemSandboxEntry {
                        path: FileSystemPath::Special {
                            value: FileSystemSpecialPath::Root,
                        },
                        access: FileSystemAccessMode::Read,
                    },
                    FileSystemSandboxEntry {
                        path: FileSystemPath::Path {
                            path: PathBuf::from("/tmp/out"),
                        },
                        access: FileSystemAccessMode::Write,
                    },
                ],
                glob_scan_max_depth: None,
            },
            network: NetworkSandboxPolicy::Enabled,
        },
    )
    .expect("supported filesystem entries should lower to seatbelt args");

    assert_eq!(args.first().map(String::as_str), Some("-p"));
    let policy = &args[1];
    assert!(policy.contains("(allow file-read*)"));
    assert!(policy.contains("(allow file-write* (subpath \"/tmp/out\"))"));
    assert!(policy.contains("(allow network*)"));
    assert_eq!(args[2..], ["/bin/echo", "hello"]);
}

#[test]
fn seatbelt_lowering_rejects_unsupported_glob_and_special_entries() {
    let glob_error = crate::seatbelt::create_seatbelt_command_args(
        vec!["/bin/echo".to_string()],
        &PermissionProfile::Managed {
            file_system: ManagedFileSystemPermissions::Restricted {
                entries: vec![FileSystemSandboxEntry {
                    path: FileSystemPath::GlobPattern {
                        pattern: "/tmp/**".to_string(),
                    },
                    access: FileSystemAccessMode::Read,
                }],
                glob_scan_max_depth: None,
            },
            network: NetworkSandboxPolicy::Restricted,
        },
    )
    .expect_err("glob entries are not supported by minimal seatbelt lowering");
    assert!(matches!(
        glob_error,
        SandboxError::UnsupportedSeatbeltPolicy(_)
    ));

    let special_error = crate::seatbelt::create_seatbelt_command_args(
        vec!["/bin/echo".to_string()],
        &PermissionProfile::Managed {
            file_system: ManagedFileSystemPermissions::Restricted {
                entries: vec![FileSystemSandboxEntry {
                    path: FileSystemPath::Special {
                        value: FileSystemSpecialPath::Tmpdir,
                    },
                    access: FileSystemAccessMode::Read,
                }],
                glob_scan_max_depth: None,
            },
            network: NetworkSandboxPolicy::Restricted,
        },
    )
    .expect_err("non-root special entries are not supported by minimal seatbelt lowering");
    assert!(matches!(
        special_error,
        SandboxError::UnsupportedSeatbeltPolicy(_)
    ));
}

#[test]
fn linux_transform_applies_additional_filesystem_permissions() {
    let manager = SandboxManager::new();
    let mut command = command();
    command.additional_permissions = vec![AdditionalPermissionProfile {
        network: Some(NetworkPermissions {
            enabled: Some(true),
        }),
        file_system: Some(FileSystemPermissions {
            entries: vec![FileSystemSandboxEntry {
                path: FileSystemPath::Path {
                    path: PathBuf::from("/tmp/out"),
                },
                access: FileSystemAccessMode::Write,
            }],
            glob_scan_max_depth: NonZeroUsize::new(4),
        }),
    }];

    let transformed = manager
        .transform(SandboxTransformRequest {
            command,
            permission_profile: PermissionProfile::Managed {
                file_system: ManagedFileSystemPermissions::Restricted {
                    entries: vec![FileSystemSandboxEntry {
                        path: FileSystemPath::Path {
                            path: PathBuf::from("/workspace"),
                        },
                        access: FileSystemAccessMode::Read,
                    }],
                    glob_scan_max_depth: None,
                },
                network: NetworkSandboxPolicy::Restricted,
            },
            sandbox_type: SandboxType::LinuxSeccomp,
            sandbox_policy_cwd: PathBuf::from("/workspace"),
            codex_linux_sandbox_exe: Some(PathBuf::from("/opt/bin/helper")),
            use_legacy_landlock: false,
            allow_network_for_proxy: false,
        })
        .expect("additional permissions should lower into the helper profile");

    assert_eq!(
        transformed.permission_profile,
        PermissionProfile::Managed {
            file_system: ManagedFileSystemPermissions::Restricted {
                entries: vec![
                    FileSystemSandboxEntry {
                        path: FileSystemPath::Path {
                            path: PathBuf::from("/workspace"),
                        },
                        access: FileSystemAccessMode::Read,
                    },
                    FileSystemSandboxEntry {
                        path: FileSystemPath::Path {
                            path: PathBuf::from("/tmp/out"),
                        },
                        access: FileSystemAccessMode::Write,
                    },
                ],
                glob_scan_max_depth: NonZeroUsize::new(4),
            },
            network: NetworkSandboxPolicy::Enabled,
        }
    );

    let permission_profile = transformed
        .args
        .windows(2)
        .find(|pair| pair[0] == "--permission-profile")
        .map(|pair| pair[1].as_str())
        .expect("linux helper args should include permission profile JSON");
    assert!(permission_profile.contains("\"path\":\"/tmp/out\""));
    assert!(permission_profile.contains("\"network\":\"enabled\""));
}

#[test]
fn additional_filesystem_permissions_do_not_narrow_unrestricted_profile() {
    let manager = SandboxManager::new();
    let mut command = command();
    command.additional_permissions = vec![AdditionalPermissionProfile {
        network: Some(NetworkPermissions {
            enabled: Some(true),
        }),
        file_system: Some(FileSystemPermissions {
            entries: vec![FileSystemSandboxEntry {
                path: FileSystemPath::Path {
                    path: PathBuf::from("/tmp/out"),
                },
                access: FileSystemAccessMode::Write,
            }],
            glob_scan_max_depth: NonZeroUsize::new(4),
        }),
    }];

    let transformed = manager
        .transform(SandboxTransformRequest {
            command,
            permission_profile: PermissionProfile::Managed {
                file_system: ManagedFileSystemPermissions::Unrestricted,
                network: NetworkSandboxPolicy::Restricted,
            },
            sandbox_type: SandboxType::None,
            sandbox_policy_cwd: PathBuf::from("/workspace"),
            codex_linux_sandbox_exe: None,
            use_legacy_landlock: false,
            allow_network_for_proxy: false,
        })
        .expect("unrestricted profile should remain valid");

    assert_eq!(
        transformed.permission_profile,
        PermissionProfile::Managed {
            file_system: ManagedFileSystemPermissions::Unrestricted,
            network: NetworkSandboxPolicy::Enabled,
        }
    );
}

#[test]
fn missing_linux_helper_reports_specific_error() {
    let manager = SandboxManager::new();

    let error = manager
        .transform(linux_request(None))
        .expect_err("missing helper should fail");

    assert_eq!(error, SandboxError::MissingLinuxSandboxExecutable);
}

#[test]
fn no_sandbox_keeps_original_command() {
    let manager = SandboxManager::new();
    let command = command();

    let transformed = manager
        .transform(SandboxTransformRequest {
            command: command.clone(),
            permission_profile: PermissionProfile::read_only(),
            sandbox_type: SandboxType::None,
            sandbox_policy_cwd: PathBuf::from("/workspace"),
            codex_linux_sandbox_exe: None,
            use_legacy_landlock: false,
            allow_network_for_proxy: false,
        })
        .expect("no sandbox should not transform");

    assert_eq!(transformed.program, command.program);
    assert_eq!(transformed.args, command.args);
    assert_eq!(transformed.cwd, command.cwd);
    assert_eq!(transformed.env, command.env);
    assert_eq!(transformed.arg0_override, None);
}

#[test]
fn windows_boundary_keeps_original_command_for_later_native_runner() {
    let manager = SandboxManager::new();
    let command = command();

    let transformed = manager
        .transform(SandboxTransformRequest {
            command: command.clone(),
            permission_profile: PermissionProfile::read_only(),
            sandbox_type: SandboxType::WindowsRestrictedToken,
            sandbox_policy_cwd: PathBuf::from("/workspace"),
            codex_linux_sandbox_exe: None,
            use_legacy_landlock: false,
            allow_network_for_proxy: false,
        })
        .expect("windows boundary should remain a command boundary");

    assert_eq!(transformed.program, command.program);
    assert_eq!(transformed.args, command.args);
    assert_eq!(transformed.arg0_override, None);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_seatbelt_reports_unavailable_on_non_macos() {
    let manager = SandboxManager::new();

    let error = manager
        .transform(SandboxTransformRequest {
            command: command(),
            permission_profile: PermissionProfile::read_only(),
            sandbox_type: SandboxType::MacosSeatbelt,
            sandbox_policy_cwd: PathBuf::from("/workspace"),
            codex_linux_sandbox_exe: None,
            use_legacy_landlock: false,
            allow_network_for_proxy: false,
        })
        .expect_err("seatbelt is not available on non-macos targets");

    assert_eq!(error, SandboxError::SeatbeltUnavailable);
}
