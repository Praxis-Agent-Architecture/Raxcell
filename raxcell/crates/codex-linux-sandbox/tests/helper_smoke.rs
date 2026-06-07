use std::process::Command;

#[test]
fn helper_runs_simple_command_when_bwrap_is_available() {
    if !cfg!(target_os = "linux")
        || std::process::Command::new("bwrap")
            .arg("--help")
            .output()
            .is_err()
    {
        return;
    }

    let helper = env!("CARGO_BIN_EXE_raxcell-codex-linux-sandbox");
    let profile = serde_json::json!({
        "type": "managed",
        "file_system": {
            "type": "restricted",
            "entries": [
                {
                    "path": {
                        "type": "special",
                        "value": { "kind": "root" }
                    },
                    "access": "read"
                }
            ]
        },
        "network": "restricted"
    })
    .to_string();

    let output = Command::new(helper)
        .args([
            "--sandbox-policy-cwd",
            ".",
            "--command-cwd",
            ".",
            "--permission-profile",
            &profile,
            "--",
            "/bin/true",
        ])
        .output()
        .expect("helper should start");

    if !output.status.success() && is_environment_bwrap_failure(&output.stderr) {
        return;
    }

    assert!(
        output.status.success(),
        "helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn is_environment_bwrap_failure(stderr: &[u8]) -> bool {
    let stderr = String::from_utf8_lossy(stderr);
    [
        "bwrap: Creating new namespace failed",
        "bwrap: No permissions to create new namespace",
        "bwrap: Operation not permitted",
        "bwrap: setting up uid map",
        "bwrap: Can't mount proc",
    ]
    .iter()
    .any(|message| stderr.contains(message))
}

#[test]
fn helper_seccomp_operation_not_permitted_is_not_treated_as_environment_failure() {
    assert!(!is_environment_bwrap_failure(
        b"failed to apply Linux seccomp hardening: Operation not permitted"
    ));
}
