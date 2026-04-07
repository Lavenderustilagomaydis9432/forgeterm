use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

/// Check if another forgeterm-agent is already running via PID file.
pub fn check_running(pid_file: &Path) -> Result<bool> {
    let pid_str = match fs::read_to_string(pid_file) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).context("reading PID file"),
    };

    let pid: u32 = pid_str.trim().parse().context("invalid PID in PID file")?;

    if is_forgeterm_running(pid) {
        return Ok(true);
    }

    // Stale PID file
    let _ = fs::remove_file(pid_file);
    Ok(false)
}

/// Check if a PID is a running forgeterm-agent process.
#[cfg(target_os = "linux")]
fn is_forgeterm_running(pid: u32) -> bool {
    let proc_path = format!("/proc/{pid}");
    if Path::new(&proc_path).exists() {
        let cmdline_path = format!("/proc/{pid}/cmdline");
        if let Ok(bytes) = fs::read(&cmdline_path) {
            let cmdline = String::from_utf8_lossy(&bytes);
            if cmdline.contains("forgeterm-agent") {
                return true;
            }
        }
    }
    false
}

/// Check if a PID is a running forgeterm-agent process (macOS).
/// Uses kill(pid, 0) to check existence, then libproc to verify the process name.
#[cfg(target_os = "macos")]
fn is_forgeterm_running(pid: u32) -> bool {
    use nix::errno::Errno;
    use nix::sys::signal;
    use nix::unistd::Pid;

    // Check if process exists (EPERM = exists but owned by another user)
    let nix_pid = Pid::from_raw(pid as i32);
    match signal::kill(nix_pid, None) {
        Ok(()) => {}
        Err(Errno::EPERM) => {}
        Err(_) => return false,
    }

    // Verify it's actually forgeterm-agent by checking the process path
    if let Ok(path) = libproc::libproc::proc_pid::pidpath(pid as i32) {
        return path.contains("forgeterm-agent");
    }

    false
}

/// Write current process PID to file.
pub fn write_pid_file(pid_file: &Path) -> Result<()> {
    if let Some(parent) = pid_file.parent() {
        fs::create_dir_all(parent).context("creating PID file directory")?;
    }
    let mut f = fs::File::create(pid_file).context("creating PID file")?;
    write!(f, "{}", std::process::id())?;
    Ok(())
}

/// Remove PID file on shutdown.
pub fn remove_pid_file(pid_file: &Path) {
    let _ = fs::remove_file(pid_file);
}

/// Fork into background daemon. Call before starting tokio runtime.
pub fn daemonize() -> Result<()> {
    match unsafe { nix::unistd::fork() }.context("fork failed")? {
        nix::unistd::ForkResult::Parent { .. } => {
            std::process::exit(0);
        }
        nix::unistd::ForkResult::Child => {}
    }

    nix::unistd::setsid().context("setsid failed")?;

    // Redirect stdio to /dev/null so writes don't fail after terminal closes
    let devnull = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&devnull);
    unsafe {
        libc::dup2(fd, libc::STDIN_FILENO);
        libc::dup2(fd, libc::STDOUT_FILENO);
        libc::dup2(fd, libc::STDERR_FILENO);
    }

    Ok(())
}

/// Wait for SIGTERM or SIGINT.
pub async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
}
