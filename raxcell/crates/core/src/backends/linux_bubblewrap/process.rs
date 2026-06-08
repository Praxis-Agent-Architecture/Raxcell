use raxcell_protocol::RunRequest;
use std::process::Command;
use std::time::Duration;

use super::error::{LinuxRunError, sandbox_denied};

#[cfg(unix)]
pub(super) fn put_child_in_new_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
pub(super) fn put_child_in_new_process_group(_command: &mut Command) {}

#[cfg(unix)]
pub(super) fn kill_child_process_group(child: &mut std::process::Child) -> std::io::Result<()> {
    let pgid = child.id() as libc::pid_t;
    if unsafe { libc::kill(-pgid, libc::SIGKILL) } == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn kill_child_process_group(child: &mut std::process::Child) -> std::io::Result<()> {
    child.kill()
}

pub(super) fn timeout_duration(request: &RunRequest) -> Result<Option<Duration>, LinuxRunError> {
    let Some(value) = request.enforcement.resources.get("timeoutMs") else {
        return Ok(None);
    };
    let Some(timeout_ms) = value.as_u64() else {
        return Err(sandbox_denied(
            "resources.timeoutMs must be an unsigned integer",
        ));
    };
    if timeout_ms == 0 {
        return Ok(None);
    }
    Ok(Some(Duration::from_millis(timeout_ms)))
}
