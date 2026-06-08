use clap::CommandFactory;
use clap::Parser;
use raxcell_codex_protocol::{
    FileSystemAccessMode, FileSystemPath, FileSystemSandboxKind, FileSystemSandboxPolicy,
    FileSystemSpecialPath, NetworkSandboxPolicy, PermissionProfile,
};
#[cfg(target_os = "linux")]
use std::mem;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::ExitCode;
use thiserror::Error;

const CODEX_LINUX_SANDBOX_ARG0: &str = "codex-linux-sandbox";

#[derive(Debug, Parser)]
#[command(name = CODEX_LINUX_SANDBOX_ARG0, bin_name = CODEX_LINUX_SANDBOX_ARG0)]
/// CLI surface for the Linux sandbox helper.
pub struct LinuxSandboxCommand {
    /// It is possible that the cwd used in the context of the sandbox policy
    /// is different from the cwd of the process to spawn.
    #[arg(long = "sandbox-policy-cwd")]
    sandbox_policy_cwd: PathBuf,

    /// The logical working directory for the command being sandboxed.
    #[arg(long = "command-cwd", hide = true)]
    command_cwd: Option<PathBuf>,

    /// Canonical runtime permissions for the command.
    #[arg(
        long = "permission-profile",
        hide = true,
        value_parser = parse_permission_profile
    )]
    permission_profile: Option<PermissionProfile>,

    /// Opt-in: use the legacy Landlock Linux sandbox fallback.
    #[arg(long = "use-legacy-landlock", hide = true, default_value_t = false)]
    use_legacy_landlock: bool,

    /// Internal: apply hardening in the already-sandboxed process, then exec.
    #[arg(long = "apply-seccomp-then-exec", hide = true, default_value_t = false)]
    apply_seccomp_then_exec: bool,

    /// Internal compatibility flag for proxy-routed networking.
    #[arg(long = "allow-network-for-proxy", hide = true, default_value_t = false)]
    allow_network_for_proxy: bool,

    /// Full command args to run under the Linux sandbox helper.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[derive(Debug, Error)]
pub enum SandboxHelperError {
    #[error("missing permission profile configuration")]
    MissingPermissionProfile,
    #[error("No command specified to execute.")]
    MissingCommand,
    #[error("--apply-seccomp-then-exec is incompatible with --use-legacy-landlock")]
    InvalidInnerStageMode,
    #[error(
        "--use-legacy-landlock is recognized for CLI compatibility but is not implemented by the Raxcell helper yet"
    )]
    LegacyLandlockUnsupported,
    #[error(
        "--allow-network-for-proxy is recognized for CLI compatibility but is not implemented by the Raxcell helper yet"
    )]
    ProxyNetworkUnsupported,
    #[error("unsupported filesystem path in permission profile: {0}")]
    UnsupportedFileSystemPath(String),
    #[error("failed to resolve current helper executable: {0}")]
    CurrentExe(std::io::Error),
    #[error("failed to apply Linux no_new_privs hardening: {0}")]
    NoNewPrivs(std::io::Error),
    #[error("failed to apply Linux seccomp hardening: {0}")]
    Seccomp(std::io::Error),
    #[error("failed to spawn bubblewrap: {0}")]
    SpawnBwrap(std::io::Error),
    #[error("failed to wait for bubblewrap: {0}")]
    WaitBwrap(std::io::Error),
    #[error("bubblewrap process was terminated by signal")]
    BwrapTerminatedBySignal,
    #[error("failed to exec sandboxed command: {0}")]
    ExecCommand(std::io::Error),
}

pub fn run_main() -> ExitCode {
    match run_from(std::env::args_os()) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn run_from<I, T>(args: I) -> Result<u8, SandboxHelperError>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let command = LinuxSandboxCommand::parse_from(args);
    run(command)
}

fn run(command: LinuxSandboxCommand) -> Result<u8, SandboxHelperError> {
    if command.command.is_empty() {
        return Err(SandboxHelperError::MissingCommand);
    }
    if command.apply_seccomp_then_exec && command.use_legacy_landlock {
        return Err(SandboxHelperError::InvalidInnerStageMode);
    }
    if command.use_legacy_landlock {
        return Err(SandboxHelperError::LegacyLandlockUnsupported);
    }
    if command.allow_network_for_proxy {
        return Err(SandboxHelperError::ProxyNetworkUnsupported);
    }
    let permission_profile = command
        .permission_profile
        .clone()
        .ok_or(SandboxHelperError::MissingPermissionProfile)?;
    if command.apply_seccomp_then_exec {
        apply_inner_process_hardening()?;
        exec_command(command.command);
    }
    let bwrap_args = build_bwrap_args(&command, &permission_profile)?;
    let status = Command::new("bwrap")
        .args(bwrap_args)
        .status()
        .map_err(SandboxHelperError::SpawnBwrap)?;
    status_code(status)
}

fn status_code(status: std::process::ExitStatus) -> Result<u8, SandboxHelperError> {
    match status.code() {
        Some(code) => Ok(code.try_into().unwrap_or(1)),
        None => Err(SandboxHelperError::BwrapTerminatedBySignal),
    }
}

fn build_bwrap_args(
    command: &LinuxSandboxCommand,
    permission_profile: &PermissionProfile,
) -> Result<Vec<String>, SandboxHelperError> {
    let (file_system, network) = permission_profile.to_runtime_permissions();
    let command_cwd = command
        .command_cwd
        .as_deref()
        .unwrap_or(&command.sandbox_policy_cwd);
    let inner = inner_seccomp_command(command)?;

    let mut args = vec!["--die-with-parent".to_string()];
    if network != NetworkSandboxPolicy::Enabled {
        args.push("--unshare-net".to_string());
    }
    args.push("--dev".to_string());
    args.push("/dev".to_string());
    args.push("--proc".to_string());
    args.push("/proc".to_string());
    args.push("--tmpfs".to_string());
    args.push("/tmp".to_string());
    push_filesystem_args(&mut args, &file_system)?;
    args.push("--chdir".to_string());
    args.push(command_cwd.to_string_lossy().into_owned());
    args.push("--".to_string());
    args.extend(inner);
    Ok(args)
}

fn inner_seccomp_command(command: &LinuxSandboxCommand) -> Result<Vec<String>, SandboxHelperError> {
    let permission_profile_json = serde_json::to_string(
        &command
            .permission_profile
            .as_ref()
            .ok_or(SandboxHelperError::MissingPermissionProfile)?,
    )
    .expect("permission profile should serialize after parsing");
    let mut inner = vec![
        std::env::current_exe()
            .map_err(SandboxHelperError::CurrentExe)?
            .to_string_lossy()
            .into_owned(),
        "--sandbox-policy-cwd".to_string(),
        command.sandbox_policy_cwd.to_string_lossy().into_owned(),
    ];
    if let Some(command_cwd) = &command.command_cwd {
        inner.push("--command-cwd".to_string());
        inner.push(command_cwd.to_string_lossy().into_owned());
    }
    inner.push("--permission-profile".to_string());
    inner.push(permission_profile_json);
    inner.push("--apply-seccomp-then-exec".to_string());
    inner.push("--".to_string());
    inner.extend(command.command.clone());
    Ok(inner)
}

fn push_filesystem_args(
    args: &mut Vec<String>,
    file_system: &FileSystemSandboxPolicy,
) -> Result<(), SandboxHelperError> {
    match file_system.kind {
        FileSystemSandboxKind::Unrestricted | FileSystemSandboxKind::ExternalSandbox => {
            args.extend(["--bind".to_string(), "/".to_string(), "/".to_string()]);
            return Ok(());
        }
        FileSystemSandboxKind::Restricted => {}
    }

    for entry in &file_system.entries {
        match &entry.path {
            FileSystemPath::Path { path } => push_path_entry(args, path, entry.access),
            FileSystemPath::Special { value } => push_special_entry(args, value, entry.access),
            FileSystemPath::GlobPattern { pattern } => {
                return Err(SandboxHelperError::UnsupportedFileSystemPath(format!(
                    "glob pattern `{pattern}`"
                )));
            }
        }
    }
    Ok(())
}

fn push_path_entry(args: &mut Vec<String>, path: &Path, access: FileSystemAccessMode) {
    match access {
        FileSystemAccessMode::Read => push_mount(args, "--ro-bind", path),
        FileSystemAccessMode::Write => push_mount(args, "--bind", path),
        FileSystemAccessMode::Deny => {}
    }
}

fn push_special_entry(
    args: &mut Vec<String>,
    value: &FileSystemSpecialPath,
    access: FileSystemAccessMode,
) {
    if matches!(access, FileSystemAccessMode::Deny) {
        return;
    }
    match value {
        FileSystemSpecialPath::Root => {
            let flag = if access == FileSystemAccessMode::Write {
                "--bind"
            } else {
                "--ro-bind"
            };
            push_mount(args, flag, Path::new("/"));
        }
        FileSystemSpecialPath::Minimal => {
            for path in ["/bin", "/sbin", "/usr", "/etc", "/lib", "/lib64"] {
                let path = Path::new(path);
                if path.exists() {
                    push_mount(args, "--ro-bind", path);
                }
            }
        }
        FileSystemSpecialPath::Tmpdir | FileSystemSpecialPath::SlashTmp => {
            let flag = if access == FileSystemAccessMode::Write {
                "--bind"
            } else {
                "--ro-bind"
            };
            push_mount(args, flag, Path::new("/tmp"));
        }
        FileSystemSpecialPath::ProjectRoots { subpath }
        | FileSystemSpecialPath::Unknown { subpath, .. } => {
            if let Some(subpath) = subpath {
                let flag = if access == FileSystemAccessMode::Write {
                    "--bind"
                } else {
                    "--ro-bind"
                };
                push_mount(args, flag, subpath);
            }
        }
    }
}

fn push_mount(args: &mut Vec<String>, flag: &str, path: &Path) {
    let path = path.to_string_lossy().into_owned();
    args.push(flag.to_string());
    args.push(path.clone());
    args.push(path);
}

fn parse_permission_profile(value: &str) -> Result<PermissionProfile, String> {
    serde_json::from_str(value).map_err(|err| format!("invalid permission profile JSON: {err}"))
}

#[cfg(target_os = "linux")]
fn apply_inner_process_hardening() -> Result<(), SandboxHelperError> {
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result != 0 {
        return Err(SandboxHelperError::NoNewPrivs(
            std::io::Error::last_os_error(),
        ));
    }
    apply_seccomp_filter()
}

#[cfg(target_os = "linux")]
fn apply_seccomp_filter() -> Result<(), SandboxHelperError> {
    let filter = build_seccomp_filter();
    let mut program = libc::sock_fprog {
        len: filter
            .len()
            .try_into()
            .expect("seccomp filter length should fit sock_fprog len"),
        filter: filter.as_ptr().cast_mut(),
    };
    let result = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &mut program as *mut libc::sock_fprog,
        )
    };
    if result != 0 {
        return Err(SandboxHelperError::Seccomp(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_inner_process_hardening() -> Result<(), SandboxHelperError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn denied_seccomp_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_clone3,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
    ]
}

#[cfg(target_os = "linux")]
fn build_seccomp_filter() -> Vec<libc::sock_filter> {
    let mut filter = Vec::new();
    filter.push(bpf_stmt(
        bpf_code(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS),
        mem::offset_of!(libc::seccomp_data, arch)
            .try_into()
            .expect("seccomp_data.arch offset should fit BPF immediate"),
    ));
    filter.push(bpf_jump(
        bpf_code(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K),
        expected_audit_arch(),
        1,
        0,
    ));
    filter.push(bpf_stmt(
        bpf_code(libc::BPF_RET | libc::BPF_K),
        libc::SECCOMP_RET_KILL_PROCESS,
    ));
    filter.push(bpf_stmt(
        bpf_code(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS),
        mem::offset_of!(libc::seccomp_data, nr)
            .try_into()
            .expect("seccomp_data.nr offset should fit BPF immediate"),
    ));
    push_x32_syscall_guard(&mut filter);
    for syscall in denied_seccomp_syscalls() {
        filter.push(bpf_jump(
            bpf_code(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K),
            syscall
                .try_into()
                .expect("syscall number should fit BPF immediate"),
            0,
            1,
        ));
        filter.push(bpf_stmt(
            bpf_code(libc::BPF_RET | libc::BPF_K),
            libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        ));
    }
    filter.push(bpf_stmt(
        bpf_code(libc::BPF_RET | libc::BPF_K),
        libc::SECCOMP_RET_ALLOW,
    ));
    filter
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn push_x32_syscall_guard(filter: &mut Vec<libc::sock_filter>) {
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;

    filter.push(bpf_jump(
        bpf_code(libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K),
        X32_SYSCALL_BIT,
        0,
        1,
    ));
    filter.push(bpf_stmt(
        bpf_code(libc::BPF_RET | libc::BPF_K),
        libc::SECCOMP_RET_KILL_PROCESS,
    ));
}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
fn push_x32_syscall_guard(_filter: &mut Vec<libc::sock_filter>) {}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn expected_audit_arch() -> u32 {
    0xC000_003E
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn expected_audit_arch() -> u32 {
    0xC000_00B7
}

#[cfg(all(target_os = "linux", target_arch = "x86"))]
fn expected_audit_arch() -> u32 {
    0x4000_0003
}

#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
fn expected_audit_arch() -> u32 {
    0xC000_00F3
}

#[cfg(target_os = "linux")]
fn bpf_code(code: u32) -> u16 {
    code.try_into()
        .expect("classic BPF opcode should fit sock_filter.code")
}

#[cfg(target_os = "linux")]
fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[cfg(target_os = "linux")]
fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[cfg(unix)]
fn exec_command(command: Vec<String>) -> ! {
    use std::os::unix::process::CommandExt;

    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);
    let err = child.exec();
    panic!("{}", SandboxHelperError::ExecCommand(err));
}

#[cfg(not(unix))]
fn exec_command(command: Vec<String>) -> ! {
    let status = Command::new(&command[0])
        .args(&command[1..])
        .status()
        .unwrap_or_else(|err| panic!("{}", SandboxHelperError::ExecCommand(err)));
    std::process::exit(status.code().unwrap_or(1));
}

pub fn help_text_for_test() -> String {
    let mut command = LinuxSandboxCommand::command();
    command.render_long_help().to_string()
}

pub fn parse_args_for_test(args: &[&str]) -> Result<(), String> {
    LinuxSandboxCommand::try_parse_from(args)
        .map(|_| ())
        .map_err(|err| err.to_string())
}

pub fn bwrap_args_for_test(args: &[&str]) -> Result<Vec<String>, String> {
    let command = LinuxSandboxCommand::try_parse_from(args).map_err(|err| err.to_string())?;
    let permission_profile = command
        .permission_profile
        .clone()
        .ok_or_else(|| "missing permission profile configuration".to_string())?;
    build_bwrap_args(&command, &permission_profile).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_text_preserves_codex_linux_sandbox_shape() {
        let help = help_text_for_test();

        assert!(help.contains("codex-linux-sandbox"));
        assert!(help.contains("--sandbox-policy-cwd"));
    }

    #[test]
    fn invalid_permission_profile_reports_codex_parser_error() {
        let error = parse_args_for_test(&[
            "codex-linux-sandbox",
            "--sandbox-policy-cwd",
            ".",
            "--command-cwd",
            ".",
            "--permission-profile",
            "{not-json",
            "--",
            "/bin/true",
        ])
        .expect_err("invalid profile should fail");

        assert!(error.contains("--permission-profile"));
        assert!(error.contains("invalid permission profile JSON"));
    }

    #[test]
    fn managed_profile_lowers_to_bubblewrap_argv() {
        let profile = serde_json::json!({
            "type": "managed",
            "file_system": {
                "type": "restricted",
                "entries": [
                    {
                        "path": { "type": "path", "path": "/usr" },
                        "access": "read"
                    },
                    {
                        "path": { "type": "path", "path": "/tmp" },
                        "access": "write"
                    }
                ]
            },
            "network": "restricted"
        })
        .to_string();
        let args = bwrap_args_for_test(&[
            "codex-linux-sandbox",
            "--sandbox-policy-cwd",
            ".",
            "--command-cwd",
            "/tmp",
            "--permission-profile",
            &profile,
            "--",
            "/bin/echo",
            "hello",
        ])
        .expect("managed profile should lower");

        assert!(args.iter().any(|arg| arg == "--unshare-net"));
        assert!(
            args.windows(3)
                .any(|window| window == ["--ro-bind", "/usr", "/usr"])
        );
        assert!(
            args.windows(3)
                .any(|window| window == ["--bind", "/tmp", "/tmp"])
        );
        let tmpfs_index = args
            .windows(2)
            .position(|window| window == ["--tmpfs", "/tmp"])
            .expect("helper should create /tmp scratch");
        let tmp_bind_index = args
            .windows(3)
            .position(|window| window == ["--bind", "/tmp", "/tmp"])
            .expect("helper should bind granted /tmp after scratch setup");
        assert!(tmpfs_index < tmp_bind_index);
        assert!(args.windows(2).any(|window| window == ["--chdir", "/tmp"]));
        assert!(
            args.windows(3)
                .any(|window| window == ["--", "/bin/echo", "hello"])
        );
    }

    #[test]
    fn seccomp_filter_denies_namespace_and_kernel_mutation_syscalls() {
        let denied = denied_seccomp_syscalls();

        assert!(denied.contains(&(libc::SYS_mount as i64)));
        assert!(denied.contains(&(libc::SYS_umount2 as i64)));
        assert!(denied.contains(&(libc::SYS_unshare as i64)));
        assert!(denied.contains(&(libc::SYS_setns as i64)));
        assert!(denied.contains(&(libc::SYS_ptrace as i64)));
        assert!(denied.contains(&(libc::SYS_bpf as i64)));
        assert!(denied.contains(&(libc::SYS_init_module as i64)));
        assert!(denied.contains(&(libc::SYS_finit_module as i64)));
        assert!(denied.contains(&(libc::SYS_delete_module as i64)));
        assert!(denied.contains(&(libc::SYS_kexec_load as i64)));
    }

    #[test]
    fn seccomp_filter_returns_eperm_for_denied_syscalls_and_allows_others() {
        let filter = build_seccomp_filter();
        let deny_action = libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32);
        let allow_action = libc::SECCOMP_RET_ALLOW;

        assert!(
            filter
                .iter()
                .any(|instruction| instruction.k == deny_action)
        );
        assert_eq!(
            filter.last().map(|instruction| instruction.k),
            Some(allow_action)
        );
    }

    #[test]
    fn seccomp_filter_checks_arch_before_syscall_number() {
        let filter = build_seccomp_filter();
        let load_word_abs = bpf_code(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS);
        let jump_equal = bpf_code(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K);
        let return_constant = bpf_code(libc::BPF_RET | libc::BPF_K);

        assert_eq!(filter[0].code, load_word_abs);
        assert_eq!(
            filter[0].k,
            mem::offset_of!(libc::seccomp_data, arch) as u32
        );
        assert_eq!(filter[1].code, jump_equal);
        assert_eq!(filter[1].k, expected_audit_arch());
        assert_eq!(filter[1].jt, 1);
        assert_eq!(filter[1].jf, 0);
        assert_eq!(filter[2].code, return_constant);
        assert_eq!(filter[2].k, libc::SECCOMP_RET_KILL_PROCESS);
        assert_eq!(filter[3].code, load_word_abs);
        assert_eq!(filter[3].k, mem::offset_of!(libc::seccomp_data, nr) as u32);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn expected_audit_arch_matches_x86_64() {
        assert_eq!(expected_audit_arch(), 0xC000_003E);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn seccomp_filter_rejects_x32_syscall_numbers_before_deny_list() {
        let filter = build_seccomp_filter();
        let jump_mask = bpf_code(libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K);
        let return_constant = bpf_code(libc::BPF_RET | libc::BPF_K);

        assert_eq!(filter[4].code, jump_mask);
        assert_eq!(filter[4].k, 0x4000_0000);
        assert_eq!(filter[4].jt, 0);
        assert_eq!(filter[4].jf, 1);
        assert_eq!(filter[5].code, return_constant);
        assert_eq!(filter[5].k, libc::SECCOMP_RET_KILL_PROCESS);
        assert_eq!(
            filter[6].code,
            bpf_code(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K)
        );
        assert_eq!(filter[6].k, libc::SYS_mount as u32);
    }
}
