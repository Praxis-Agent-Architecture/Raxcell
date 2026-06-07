use super::linux_bubblewrap::{
    LinuxRunError, build_bwrap_args, codex_linux_sandbox_path,
    codex_linux_sandbox_transform_for_test, prepare_run, prepare_run_with_helper_path_for_test,
    run, run_with_helper_path_for_test,
};
use raxcell_codex_protocol::{
    FileSystemAccessMode, FileSystemPath, ManagedFileSystemPermissions, PermissionProfile,
};
use raxcell_codex_sandboxing::CODEX_LINUX_SANDBOX_ARG0;
use raxcell_protocol::{BackendFamily, CapabilityLevel, ProbeResponse, RunRequest};
use raxcell_protocol::{LoweredRootAccess, LoweredRootSource};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn sample_run_request() -> RunRequest {
    serde_json::from_value(serde_json::json!({
        "kind": "raxcell.run.v1",
        "action": {
            "actionId": "act-1",
            "ownerRuntime": "test",
            "intentLabel": "opaque",
            "metadata": {}
        },
        "command": {
            "argv": ["/usr/bin/printf", "hello"],
            "cwd": ".",
            "env": {},
            "stdin": null
        },
        "enforcement": {
            "profile": "workspace-write-no-network",
            "filesystem": { "read": ["."], "write": ["."] },
            "network": "deny",
            "process": { "spawn": true },
            "resources": { "timeoutMs": 1000 }
        },
        "fallback": { "mode": "none" }
    }))
    .unwrap()
}

fn canonical_cwd_string() -> String {
    std::fs::canonicalize(".")
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

fn ready_capability_report() -> ProbeResponse {
    ProbeResponse {
        kind: "raxcell.probeResult.v1".to_string(),
        ready: true,
        selected_backend: Some(BackendFamily::LinuxBubblewrap),
        supports: BTreeMap::from([
            ("filesystem.readRestrict".to_string(), CapabilityLevel::Full),
            (
                "filesystem.writeRestrict".to_string(),
                CapabilityLevel::Full,
            ),
            ("network.deny".to_string(), CapabilityLevel::Full),
            ("process.spawn".to_string(), CapabilityLevel::Full),
            ("resource.timeout".to_string(), CapabilityLevel::Full),
        ]),
        limits: Vec::new(),
        weaknesses: Vec::new(),
        missing: Vec::new(),
        next_actions: Vec::new(),
        public_safe_message: "selected backend is ready on this host".to_string(),
    }
}

fn live_codex_linux_sandbox_available() -> bool {
    cfg!(target_os = "linux") && which::which("bwrap").is_ok() && codex_linux_sandbox_path().is_ok()
}

fn temp_effect_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("raxcell-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[cfg(unix)]
fn fake_codex_linux_sandbox_helper() -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let helper =
        std::env::temp_dir().join(format!("raxcell-fake-codex-helper-{}", std::process::id()));
    std::fs::write(
        &helper,
        "#!/bin/sh\nif [ \"$1\" = \"--help\" ]; then echo 'codex-linux-sandbox --sandbox-policy-cwd'; exit 0; fi\necho 'invalid permission profile JSON for --permission-profile' >&2\nexit 1\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&helper).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&helper, permissions).unwrap();
    helper
}

fn add_policy_grant(request: &mut RunRequest, root: &Path, access: &str) {
    request.policy_grants = vec![raxcell_protocol::PolicyGrant {
        reason: "shell-effect-outside-declared-roots".to_string(),
        path: root.to_string_lossy().into_owned(),
        access: vec![access.to_string()],
        granted_by: Some("upper-runtime".to_string()),
    }];
}

#[test]
fn run_reports_backend_success_when_command_exits_nonzero() {
    if !live_codex_linux_sandbox_available() {
        return;
    }

    let mut request = sample_run_request();
    request.command.argv = vec![
        "/bin/sh".to_string(),
        "-lc".to_string(),
        "exit 7".to_string(),
    ];
    request.enforcement.network = Some("allow".to_string());

    let response = run(request, ready_capability_report());

    assert!(response.ok);
    assert_eq!(response.exit_code, Some(7));
    assert_eq!(response.denial, None);
    assert_eq!(response.policy_decision, None);
}

#[test]
fn run_reports_backend_success_when_command_exits_nonzero_with_backend_like_stderr() {
    if !live_codex_linux_sandbox_available() {
        return;
    }

    let mut request = sample_run_request();
    request.command.argv = vec![
        "/bin/sh".to_string(),
        "-lc".to_string(),
        "echo 'bwrap: user command stderr' >&2; exit 9".to_string(),
    ];
    request.enforcement.network = Some("allow".to_string());

    let response = run(request, ready_capability_report());

    assert!(response.ok);
    assert_eq!(response.exit_code, Some(9));
    assert!(response.stderr.contains("bwrap: user command stderr"));
    assert_eq!(response.denial, None);
    assert_eq!(response.policy_decision, None);
}

#[test]
fn prepare_artifact_uses_codex_linux_sandbox_helper_shape() {
    if !live_codex_linux_sandbox_available() {
        return;
    }

    let response = prepare_run(sample_run_request(), ready_capability_report());

    assert!(response.ok);
    assert_eq!(response.backend_artifacts.len(), 1);
    assert_eq!(
        response.backend_artifacts[0].format,
        "codex-linux-sandbox-argv"
    );
    assert!(
        response.backend_artifacts[0]
            .arguments
            .iter()
            .any(|argument| argument == "--permission-profile")
    );
}

#[test]
fn codex_linux_transform_uses_sandbox_manager_shape_without_live_helper() {
    let request = sample_run_request();
    let cwd = std::fs::canonicalize(".").unwrap();

    let transformed =
        codex_linux_sandbox_transform_for_test(&request, "/opt/raxcell/helper".as_ref(), &cwd)
            .unwrap();

    assert_eq!(
        transformed.command.program,
        std::path::PathBuf::from("/opt/raxcell/helper")
    );
    assert_eq!(
        transformed.command.arg0_override.as_deref(),
        Some(CODEX_LINUX_SANDBOX_ARG0)
    );
    assert_eq!(
        transformed.command.args.first().map(String::as_str),
        Some("--sandbox-policy-cwd")
    );
    assert_eq!(
        transformed
            .command
            .args
            .iter()
            .filter(|arg| *arg == "--")
            .count(),
        1
    );
    assert!(
        transformed
            .command
            .args
            .ends_with(&["/usr/bin/printf".to_string(), "hello".to_string()])
    );
}

#[test]
fn codex_linux_transform_lowers_policy_grant_as_additional_permission() {
    let mut request = sample_run_request();
    request
        .enforcement
        .filesystem
        .insert("read".to_string(), vec!["/tmp".to_string()]);
    request
        .enforcement
        .filesystem
        .insert("write".to_string(), vec!["/tmp".to_string()]);
    request.policy_grants = vec![raxcell_protocol::PolicyGrant {
        reason: "cwd-outside-declared-roots".to_string(),
        path: ".".to_string(),
        access: vec!["write".to_string()],
        granted_by: Some("upper-runtime".to_string()),
    }];
    let cwd = std::fs::canonicalize(".").unwrap();

    let transformed =
        codex_linux_sandbox_transform_for_test(&request, "/opt/raxcell/helper".as_ref(), &cwd)
            .unwrap();

    let PermissionProfile::Managed {
        file_system: ManagedFileSystemPermissions::Restricted { entries, .. },
        ..
    } = transformed.command.permission_profile
    else {
        panic!("linux transform should produce a managed permission profile");
    };
    assert!(entries.iter().any(|entry| {
        entry.access == FileSystemAccessMode::Write
            && matches!(
                &entry.path,
                FileSystemPath::Path { path } if path == &cwd
            )
    }));
    assert!(
        transformed
            .filesystem_lowering
            .declared_roots
            .iter()
            .any(|root| root.path == canonical_cwd_string()
                && root.access == LoweredRootAccess::Write
                && root.source == LoweredRootSource::PolicyGrant)
    );
}

#[test]
fn codex_linux_transform_lowers_non_cwd_policy_grant_as_additional_permission() {
    let grant_root = std::env::temp_dir().join(format!(
        "raxcell-transform-policy-grant-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&grant_root).unwrap();
    let canonical_grant_root = std::fs::canonicalize(&grant_root).unwrap();

    let mut request = sample_run_request();
    request.policy_grants = vec![raxcell_protocol::PolicyGrant {
        reason: "user-approved-extra-root".to_string(),
        path: grant_root.to_string_lossy().into_owned(),
        access: vec!["read".to_string()],
        granted_by: Some("upper-runtime".to_string()),
    }];
    let cwd = std::fs::canonicalize(".").unwrap();

    let transformed =
        codex_linux_sandbox_transform_for_test(&request, "/opt/raxcell/helper".as_ref(), &cwd)
            .unwrap();

    let _ = std::fs::remove_dir_all(&grant_root);

    let PermissionProfile::Managed {
        file_system: ManagedFileSystemPermissions::Restricted { entries, .. },
        ..
    } = transformed.command.permission_profile
    else {
        panic!("linux transform should produce a managed permission profile");
    };
    assert!(entries.iter().any(|entry| {
        entry.access == FileSystemAccessMode::Read
            && matches!(
                &entry.path,
                FileSystemPath::Path { path } if path == &canonical_grant_root
            )
    }));
}

#[test]
fn codex_linux_transform_fails_closed_for_missing_policy_grant_path() {
    let missing_grant_root = std::env::temp_dir().join(format!(
        "raxcell-missing-policy-grant-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&missing_grant_root);

    let mut request = sample_run_request();
    request.policy_grants = vec![raxcell_protocol::PolicyGrant {
        reason: "user-approved-extra-root".to_string(),
        path: missing_grant_root.to_string_lossy().into_owned(),
        access: vec!["read".to_string()],
        granted_by: Some("upper-runtime".to_string()),
    }];
    let cwd = std::fs::canonicalize(".").unwrap();

    let Err(LinuxRunError::SandboxDenied(message)) =
        codex_linux_sandbox_transform_for_test(&request, "/opt/raxcell/helper".as_ref(), &cwd)
    else {
        panic!("expected missing policy grant path to fail closed");
    };
    assert!(message.contains("policy grant path"));
    assert!(message.contains("is not available"));
}

#[test]
fn codex_linux_transform_requires_policy_decision_for_shell_external_redirection_without_grant() {
    let effect_root = temp_effect_root("external-redirection");
    let target = effect_root.join("out.txt");
    let mut request = sample_run_request();
    request.command.argv = vec![
        "/bin/sh".to_string(),
        "-lc".to_string(),
        format!("printf hello > {}", target.to_string_lossy()),
    ];
    let cwd = std::fs::canonicalize(".").unwrap();

    let Err(error) =
        codex_linux_sandbox_transform_for_test(&request, "/opt/raxcell/helper".as_ref(), &cwd)
    else {
        panic!("expected shell external write to require a policy decision");
    };
    let _ = std::fs::remove_dir_all(&effect_root);

    let LinuxRunError::PolicyDecisionRequired(decision) = error else {
        panic!("expected policy decision required");
    };
    assert_eq!(decision.reason, "shell-effect-outside-declared-roots");
    assert_eq!(decision.path, target.to_string_lossy());
    assert_eq!(decision.required, vec!["filesystem.write".to_string()]);
}

#[test]
fn codex_linux_transform_rejects_read_grant_for_shell_external_write() {
    let effect_root = temp_effect_root("read-grant-write");
    let target = effect_root.join("out.txt");
    let mut request = sample_run_request();
    request.command.argv = vec![
        "sh".to_string(),
        "-c".to_string(),
        format!("printf hello >> {}", target.to_string_lossy()),
    ];
    add_policy_grant(&mut request, &effect_root, "read");
    let cwd = std::fs::canonicalize(".").unwrap();

    let Err(error) =
        codex_linux_sandbox_transform_for_test(&request, "/opt/raxcell/helper".as_ref(), &cwd)
    else {
        panic!("expected read grant to be insufficient for shell external write");
    };
    let _ = std::fs::remove_dir_all(&effect_root);

    let LinuxRunError::PolicyDecisionRequired(decision) = error else {
        panic!("expected policy decision required");
    };
    assert_eq!(decision.reason, "shell-effect-outside-declared-roots");
    assert_eq!(decision.required, vec!["filesystem.write".to_string()]);
}

#[cfg(unix)]
#[test]
fn prepare_run_accepts_write_grant_for_shell_external_write_and_keeps_codex_artifact() {
    let effect_root = temp_effect_root("write-grant-write");
    let target = effect_root.join("out.txt");
    let helper = fake_codex_linux_sandbox_helper();
    let mut request = sample_run_request();
    request.command.argv = vec![
        "bash".to_string(),
        "-lc".to_string(),
        format!("printf hello 1> {}", target.to_string_lossy()),
    ];
    add_policy_grant(&mut request, &effect_root, "write");

    let response =
        prepare_run_with_helper_path_for_test(request, ready_capability_report(), &helper);

    let _ = std::fs::remove_dir_all(&effect_root);
    let _ = std::fs::remove_file(&helper);

    assert!(response.ok);
    assert_eq!(response.denial, None);
    assert_eq!(response.policy_decision, None);
    assert_eq!(response.backend_artifacts.len(), 1);
    assert_eq!(
        response.backend_artifacts[0].format,
        "codex-linux-sandbox-argv"
    );
}

#[test]
fn codex_linux_transform_accepts_read_grant_for_shell_external_cat_read() {
    let effect_root = temp_effect_root("read-grant-cat");
    let target = effect_root.join("input.txt");
    std::fs::write(&target, "hello").unwrap();
    let mut request = sample_run_request();
    request.command.argv = vec![
        "/bin/dash".to_string(),
        "-c".to_string(),
        format!("cat {}", target.to_string_lossy()),
    ];
    add_policy_grant(&mut request, &effect_root, "read");
    let cwd = std::fs::canonicalize(".").unwrap();

    let transformed =
        codex_linux_sandbox_transform_for_test(&request, "/opt/raxcell/helper".as_ref(), &cwd)
            .unwrap();
    let _ = std::fs::remove_dir_all(&effect_root);

    assert!(
        transformed
            .filesystem_lowering
            .policy_grants
            .iter()
            .any(|grant| grant.access == ["read".to_string()])
    );
}

#[test]
fn run_reports_backend_failure_when_helper_cannot_be_resolved() {
    let missing_helper = std::env::temp_dir().join(format!(
        "raxcell-missing-codex-linux-sandbox-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&missing_helper);

    let response = run_with_helper_path_for_test(
        sample_run_request(),
        ready_capability_report(),
        &missing_helper,
    );

    assert!(!response.ok);
    assert_eq!(response.exit_code, None);
    assert_eq!(
        response.denial.unwrap().code,
        raxcell_protocol::DenialCode::SandboxDenied
    );
    assert_eq!(response.filesystem_lowering, None);
    assert_eq!(response.fallback, None);
}

#[cfg(unix)]
#[test]
fn run_reports_backend_failure_when_spawned_helper_preflight_fails() {
    use std::os::unix::fs::PermissionsExt;

    let fake_helper = std::env::temp_dir().join(format!(
        "raxcell-fake-codex-linux-sandbox-{}",
        std::process::id()
    ));
    std::fs::write(
        &fake_helper,
        "#!/bin/sh\necho unexpected helper failure >&2\nexit 42\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&fake_helper).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&fake_helper, permissions).unwrap();

    let response = run_with_helper_path_for_test(
        sample_run_request(),
        ready_capability_report(),
        &fake_helper,
    );

    let _ = std::fs::remove_file(&fake_helper);

    assert!(!response.ok);
    assert_eq!(response.exit_code, None);
    let denial = response.denial.unwrap();
    assert_eq!(denial.code, raxcell_protocol::DenialCode::SandboxDenied);
    assert!(denial.message.contains("helper preflight failed"));
    assert_eq!(response.filesystem_lowering, None);
    assert_eq!(response.fallback, None);
}

#[cfg(unix)]
#[test]
fn run_reports_backend_failure_when_helper_help_text_is_not_codex_sandbox() {
    use std::os::unix::fs::PermissionsExt;

    let fake_helper =
        std::env::temp_dir().join(format!("raxcell-fake-helper-help-{}", std::process::id()));
    std::fs::write(
        &fake_helper,
        "#!/bin/sh\nif [ \"$1\" = \"--help\" ]; then echo 'not the sandbox helper'; exit 0; fi\necho unexpected helper failure >&2\nexit 42\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&fake_helper).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&fake_helper, permissions).unwrap();

    let response = run_with_helper_path_for_test(
        sample_run_request(),
        ready_capability_report(),
        &fake_helper,
    );

    let _ = std::fs::remove_file(&fake_helper);

    assert!(!response.ok);
    assert_eq!(response.exit_code, None);
    let denial = response.denial.unwrap();
    assert_eq!(denial.code, raxcell_protocol::DenialCode::SandboxDenied);
    assert!(denial.message.contains("helper preflight"));
    assert_eq!(response.filesystem_lowering, None);
    assert_eq!(response.fallback, None);
}

#[test]
fn bwrap_args_unshare_network_when_requested() {
    let cwd = std::fs::canonicalize(".").unwrap();
    let (args, _) = build_bwrap_args(&sample_run_request(), &cwd).unwrap();
    assert!(args.iter().any(|arg| arg == "--unshare-net"));
}

#[test]
fn bwrap_args_recreate_usr_merge_root_symlinks() {
    let cwd = std::fs::canonicalize(".").unwrap();
    let (args, _) = build_bwrap_args(&sample_run_request(), &cwd).unwrap();
    let string_args: Vec<String> = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    if std::fs::read_link("/bin").is_ok() {
        assert!(string_args.windows(3).any(|window| window
            == [
                "--symlink".to_string(),
                "usr/bin".to_string(),
                "/bin".to_string()
            ]));
    }
}

#[test]
fn bwrap_args_fail_closed_for_missing_declared_roots() {
    let mut request = sample_run_request();
    let missing = format!("/tmp/raxcell-missing-root-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&missing);
    request
        .enforcement
        .filesystem
        .insert("read".to_string(), vec![missing]);
    let cwd = std::fs::canonicalize(".").unwrap();
    let error = build_bwrap_args(&request, &cwd).unwrap_err();
    assert!(matches!(error, LinuxRunError::SandboxDenied(_)));
}

#[test]
fn bwrap_args_request_policy_decision_when_cwd_is_outside_declared_roots() {
    let mut request = sample_run_request();
    request
        .enforcement
        .filesystem
        .insert("read".to_string(), vec!["/tmp".to_string()]);
    request
        .enforcement
        .filesystem
        .insert("write".to_string(), vec!["/tmp".to_string()]);
    let cwd = std::fs::canonicalize(".").unwrap();
    let error = build_bwrap_args(&request, &cwd).unwrap_err();
    let LinuxRunError::PolicyDecisionRequired(decision) = error else {
        panic!("expected policy decision required");
    };
    assert_eq!(decision.reason, "cwd-outside-declared-roots");
    assert_eq!(decision.path, canonical_cwd_string());
}

#[test]
fn bwrap_args_accept_explicit_cwd_policy_grant() {
    let mut request = sample_run_request();
    request
        .enforcement
        .filesystem
        .insert("read".to_string(), vec!["/tmp".to_string()]);
    request
        .enforcement
        .filesystem
        .insert("write".to_string(), vec!["/tmp".to_string()]);
    request.policy_grants = vec![raxcell_protocol::PolicyGrant {
        reason: "cwd-outside-declared-roots".to_string(),
        path: ".".to_string(),
        access: vec!["read".to_string()],
        granted_by: Some("upper-runtime".to_string()),
    }];
    let cwd = std::fs::canonicalize(".").unwrap();
    let (args, report) = build_bwrap_args(&request, &cwd).unwrap();
    let string_args: Vec<String> = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert!(string_args.windows(3).any(|window| window
        == [
            "--ro-bind".to_string(),
            canonical_cwd_string(),
            canonical_cwd_string()
        ]));
    assert!(
        report
            .declared_roots
            .iter()
            .any(|root| root.path == canonical_cwd_string()
                && root.access == LoweredRootAccess::Read
                && root.source == LoweredRootSource::PolicyGrant)
    );
    assert_eq!(report.policy_grants, request.policy_grants);
}

#[test]
fn bwrap_args_ignore_redundant_cwd_policy_grant() {
    let mut request = sample_run_request();
    request.policy_grants = vec![raxcell_protocol::PolicyGrant {
        reason: "cwd-outside-declared-roots".to_string(),
        path: ".".to_string(),
        access: vec!["read".to_string()],
        granted_by: Some("upper-runtime".to_string()),
    }];
    let cwd = std::fs::canonicalize(".").unwrap();
    let (_, report) = build_bwrap_args(&request, &cwd).unwrap();
    assert!(
        report
            .declared_roots
            .iter()
            .any(|root| root.path == canonical_cwd_string()
                && root.access == LoweredRootAccess::Write
                && root.source == LoweredRootSource::Declared)
    );
    assert!(report.warnings.is_empty());
}

#[test]
fn write_child_under_read_parent_keeps_minimal_write_mount() {
    let root = std::env::temp_dir().join(format!("raxcell-nested-{}", std::process::id()));
    let write_child = root.join("write-child");
    std::fs::create_dir_all(&write_child).unwrap();
    let mut request = sample_run_request();
    request.command.cwd = root.to_string_lossy().into_owned();
    request.enforcement.filesystem.insert(
        "read".to_string(),
        vec![root.to_string_lossy().into_owned()],
    );
    request.enforcement.filesystem.insert(
        "write".to_string(),
        vec![write_child.to_string_lossy().into_owned()],
    );
    let cwd = std::fs::canonicalize(&root).unwrap();
    let (args, report) = build_bwrap_args(&request, &cwd).unwrap();
    let string_args: Vec<String> = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let root = std::fs::canonicalize(&root)
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let write_child = std::fs::canonicalize(&write_child)
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(
        string_args
            .windows(3)
            .any(|window| window == ["--ro-bind".to_string(), root.clone(), root.clone()])
    );
    assert!(string_args.windows(3).any(|window| window
        == [
            "--bind".to_string(),
            write_child.clone(),
            write_child.clone()
        ]));
    assert!(
        report
            .declared_roots
            .iter()
            .any(|root| root.access == LoweredRootAccess::Read
                && root.source == LoweredRootSource::Declared)
    );
    assert!(
        report
            .declared_roots
            .iter()
            .any(|root| root.access == LoweredRootAccess::Write
                && root.source == LoweredRootSource::Declared)
    );
}

#[test]
fn read_child_under_write_parent_is_dropped_from_mounts() {
    let root = std::env::temp_dir().join(format!("raxcell-write-parent-{}", std::process::id()));
    let read_child = root.join("read-child");
    std::fs::create_dir_all(&read_child).unwrap();
    let mut request = sample_run_request();
    request.command.cwd = root.to_string_lossy().into_owned();
    request.enforcement.filesystem.insert(
        "read".to_string(),
        vec![read_child.to_string_lossy().into_owned()],
    );
    request.enforcement.filesystem.insert(
        "write".to_string(),
        vec![root.to_string_lossy().into_owned()],
    );
    let cwd = std::fs::canonicalize(&root).unwrap();
    let (args, report) = build_bwrap_args(&request, &cwd).unwrap();
    let string_args: Vec<String> = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let read_child = std::fs::canonicalize(&read_child)
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(!string_args.windows(3).any(|window| window
        == [
            "--ro-bind".to_string(),
            read_child.clone(),
            read_child.clone()
        ]));
    assert!(
        !report
            .declared_roots
            .iter()
            .any(|root| root.path == read_child)
    );
}

#[test]
fn lowering_report_includes_runtime_roots() {
    let cwd = std::fs::canonicalize(".").unwrap();
    let (_, report) = build_bwrap_args(&sample_run_request(), &cwd).unwrap();
    assert!(report.runtime_roots.iter().any(|root| root.path == "/usr"
        && root.access == LoweredRootAccess::Read
        && root.source == LoweredRootSource::BackendRuntime));
    assert!(report.runtime_roots.iter().any(|root| root.path == "/tmp"
        && root.access == LoweredRootAccess::Scratch
        && root.source == LoweredRootSource::BackendRuntime));
}

#[test]
fn lowering_report_drops_runtime_root_covered_by_declared_root() {
    let mut request = sample_run_request();
    request
        .enforcement
        .filesystem
        .insert("read".to_string(), vec!["/tmp".to_string()]);
    request
        .enforcement
        .filesystem
        .insert("write".to_string(), vec!["/tmp".to_string()]);
    request.policy_grants = vec![raxcell_protocol::PolicyGrant {
        reason: "cwd-outside-declared-roots".to_string(),
        path: ".".to_string(),
        access: vec!["read".to_string()],
        granted_by: Some("upper-runtime".to_string()),
    }];
    let cwd = std::fs::canonicalize(".").unwrap();
    let (_, report) = build_bwrap_args(&request, &cwd).unwrap();
    assert!(!report.runtime_roots.iter().any(|root| root.path == "/tmp"
        && root.access == LoweredRootAccess::Scratch
        && root.source == LoweredRootSource::BackendRuntime));
    assert!(report.declared_roots.iter().any(|root| root.path == "/tmp"
        && root.access == LoweredRootAccess::Write
        && root.source == LoweredRootSource::Declared));
}
