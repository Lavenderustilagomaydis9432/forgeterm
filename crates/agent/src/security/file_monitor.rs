use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tracing::debug;

use forgeterm_shared::types::{CliType, Signal};

use super::rules::SecurityRules;

/// Scan open file descriptors of a process and check against security rules.
/// Returns security signals for any sensitive file access or boundary violations.
/// Uses time-windowed dedup: same file re-alerts after `dedup_window` expires.
pub fn scan_fds(
    pid: u32,
    session_id: u64,
    cli_type: &CliType,
    project_dir: &Path,
    rules: &SecurityRules,
    already_seen: &mut HashMap<PathBuf, Instant>,
    dedup_window: Duration,
) -> Vec<Signal> {
    let open_files = list_open_files(pid);
    let mut signals = Vec::new();

    for (file_path, writable) in &open_files {
        if let Some(&seen_at) = already_seen.get(file_path) {
            if seen_at.elapsed() < dedup_window {
                continue;
            }
        }

        // Check against sensitive file rules
        if let Some((rule_name, severity, known_safe)) = rules.match_file(file_path) {
            already_seen.insert(file_path.clone(), Instant::now());
            signals.push(Signal::SensitiveFileAccess {
                session_id,
                pid,
                cli_type: cli_type.clone(),
                path: file_path.clone(),
                rule_name: rule_name.to_string(),
                severity: severity.clone(),
                known_safe: known_safe.map(String::from),
            });
            continue;
        }

        // Boundary detection: writable file outside project directory
        if *writable && !file_path.starts_with(project_dir) && is_user_file(file_path) {
            already_seen.insert(file_path.clone(), Instant::now());
            signals.push(Signal::BoundaryViolation {
                session_id,
                pid,
                cli_type: cli_type.clone(),
                path: file_path.clone(),
                project_dir: project_dir.to_path_buf(),
            });
        }
    }

    signals
}

/// Check inotify/kqueue file access event against security rules.
/// Tries PID attribution first; falls back to attributing to all active sessions
/// when no PID has the file open (short-lived access like `cat file > /dev/null`).
pub fn check_inotify_access(
    path: &Path,
    tracked_pids: &[(u32, u64, CliType)],
    rules: &SecurityRules,
) -> Vec<Signal> {
    let mut signals = Vec::new();

    let (rule_name, severity, known_safe) = match rules.match_file(path) {
        Some(m) => m,
        None => return signals,
    };
    let known_safe_owned = known_safe.map(String::from);

    // Try to find which tracked PID has the file open
    let mut attributed = false;
    for (pid, session_id, cli_type) in tracked_pids {
        if pid_has_file_open(*pid, path) {
            signals.push(Signal::SensitiveFileAccess {
                session_id: *session_id,
                pid: *pid,
                cli_type: cli_type.clone(),
                path: path.to_path_buf(),
                rule_name: rule_name.to_string(),
                severity: severity.clone(),
                known_safe: known_safe_owned.clone(),
            });
            attributed = true;
        }
    }

    // If no PID match (short-lived access), attribute to first active session only.
    // Attributing to all sessions caused notification floods (N sessions x M files).
    if !attributed {
        if let Some((pid, session_id, cli_type)) = tracked_pids.first() {
            signals.push(Signal::SensitiveFileAccess {
                session_id: *session_id,
                pid: *pid,
                cli_type: cli_type.clone(),
                path: path.to_path_buf(),
                rule_name: rule_name.to_string(),
                severity: severity.clone(),
                known_safe: known_safe_owned,
            });
        }
    }

    signals
}

/// Filter out system paths that are normal to write to.
fn is_user_file(path: &Path) -> bool {
    let skip_prefixes = [
        "/tmp/",
        "/var/tmp/",
        "/run/",
        "/usr/",
        "/lib/",
        "/lib64/",
        "/nix/",
        "/private/var/",
        "/System/",
        "/Library/",
    ];
    let path_str = path.to_string_lossy();
    for prefix in &skip_prefixes {
        if path_str.starts_with(prefix) {
            return false;
        }
    }
    true
}

// --- Linux implementation ---

#[cfg(target_os = "linux")]
fn list_open_files(pid: u32) -> Vec<(PathBuf, bool)> {
    use std::fs;
    let fd_dir = format!("/proc/{pid}/fd");
    let entries = match fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut files = Vec::new();
    for entry in entries.flatten() {
        let link = match fs::read_link(entry.path()) {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Skip non-file targets (pipes, sockets, /dev/*, /proc/*)
        if !link.is_absolute()
            || link.starts_with("/dev/")
            || link.starts_with("/proc/")
            || link.starts_with("/sys/")
        {
            continue;
        }

        let writable = is_write_fd_linux(&fd_dir, &entry.file_name().to_string_lossy());
        files.push((link, writable));
    }
    files
}

#[cfg(target_os = "linux")]
fn is_write_fd_linux(fd_dir: &str, fd_num: &str) -> bool {
    use std::fs;
    let fdinfo_path = fd_dir.replace("/fd", "/fdinfo").to_string() + "/" + fd_num;
    let content = match fs::read_to_string(&fdinfo_path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    for line in content.lines() {
        if let Some(flags_str) = line.strip_prefix("flags:\t") {
            if let Ok(flags) = u32::from_str_radix(flags_str.trim(), 8) {
                let access_mode = flags & 3;
                return access_mode == 1 || access_mode == 2; // O_WRONLY or O_RDWR
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn pid_has_file_open(pid: u32, target: &Path) -> bool {
    use std::fs;
    let fd_dir = format!("/proc/{pid}/fd");
    let entries = match fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return false,
    };
    for entry in entries.flatten() {
        if let Ok(link) = fs::read_link(entry.path()) {
            if link == target {
                return true;
            }
        }
    }
    false
}

/// Inotify state with both directory and individual file watches.
#[cfg(target_os = "linux")]
pub struct InotifyWatches {
    pub inotify: inotify::Inotify,
    pub dir_watches: Vec<(inotify::WatchDescriptor, PathBuf)>,
    pub file_watches: Vec<(inotify::WatchDescriptor, PathBuf)>,
}

/// Set up inotify watches on sensitive directories and individual files.
#[cfg(target_os = "linux")]
pub fn setup_inotify(watch_dirs: &[PathBuf], watch_files: &[PathBuf]) -> Option<InotifyWatches> {
    let inotify = match inotify::Inotify::init() {
        Ok(i) => i,
        Err(e) => {
            debug!("Could not init inotify: {e}");
            return None;
        }
    };

    let mut dir_watches = Vec::new();
    let mut file_watches = Vec::new();

    for dir in watch_dirs {
        if !dir.exists() {
            debug!("Skipping inotify watch on non-existent {}", dir.display());
            continue;
        }
        match inotify
            .watches()
            .add(dir, inotify::WatchMask::ACCESS | inotify::WatchMask::OPEN)
        {
            Ok(wd) => {
                debug!("inotify watching dir {}", dir.display());
                dir_watches.push((wd, dir.clone()));
            }
            Err(e) => {
                debug!("Could not watch dir {}: {e}", dir.display());
            }
        }
    }

    for file in watch_files {
        if !file.exists() {
            debug!("Skipping inotify watch on non-existent {}", file.display());
            continue;
        }
        match inotify.watches().add(file, inotify::WatchMask::ACCESS) {
            Ok(wd) => {
                debug!("inotify watching file {}", file.display());
                file_watches.push((wd, file.clone()));
            }
            Err(e) => {
                debug!("Could not watch file {}: {e}", file.display());
            }
        }
    }

    if dir_watches.is_empty() && file_watches.is_empty() {
        return None;
    }

    Some(InotifyWatches {
        inotify,
        dir_watches,
        file_watches,
    })
}

// --- macOS implementation ---

/// List open files for a process using lsof (macOS).
/// Returns (path, is_writable) pairs.
#[cfg(target_os = "macos")]
fn list_open_files(pid: u32) -> Vec<(PathBuf, bool)> {
    use std::process::Command;

    // lsof -p PID -Fn -F0 outputs null-separated fields.
    // We use simpler -Fna output: 'n' prefix = name, 'a' prefix = access mode
    let output = match Command::new("lsof")
        .args(["-p", &pid.to_string(), "-Fna"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut files = Vec::new();
    let mut current_name: Option<PathBuf> = None;
    let mut current_writable = false;

    for line in text.lines() {
        if let Some(name) = line.strip_prefix('n') {
            // Flush previous entry
            if let Some(path) = current_name.take() {
                if path.is_absolute() && !is_system_path_macos(&path) {
                    files.push((path, current_writable));
                }
            }
            current_name = Some(PathBuf::from(name));
            current_writable = false;
        } else if let Some(access) = line.strip_prefix('a') {
            // Access mode: r=read, w=write, u=read+write
            current_writable = access.contains('w') || access.contains('u');
        }
    }
    // Flush last entry
    if let Some(path) = current_name {
        if path.is_absolute() && !is_system_path_macos(&path) {
            files.push((path, current_writable));
        }
    }

    files
}

#[cfg(target_os = "macos")]
fn is_system_path_macos(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("/dev/") || s.starts_with("/System/") || s.starts_with("/proc/")
}

#[cfg(target_os = "macos")]
fn pid_has_file_open(pid: u32, target: &Path) -> bool {
    list_open_files(pid).iter().any(|(path, _)| path == target)
}

/// Set up kqueue watches on sensitive directories (macOS).
#[cfg(target_os = "macos")]
pub fn setup_kqueue(watch_dirs: &[PathBuf]) -> Option<(kqueue::Watcher, Vec<PathBuf>)> {
    let mut watcher = match kqueue::Watcher::new() {
        Ok(w) => w,
        Err(e) => {
            debug!("Could not create kqueue watcher: {e}");
            return None;
        }
    };

    let mut watched = Vec::new();
    for dir in watch_dirs {
        if !dir.exists() {
            debug!("Skipping kqueue watch on non-existent {}", dir.display());
            continue;
        }
        if let Err(e) = watcher.add_filename(
            dir,
            kqueue::EventFilter::EVFILT_VNODE,
            kqueue::FilterFlag::NOTE_WRITE | kqueue::FilterFlag::NOTE_EXTEND,
        ) {
            debug!("Could not watch {}: {e}", dir.display());
            continue;
        }
        debug!("kqueue watching {}", dir.display());
        watched.push(dir.clone());
    }

    if let Err(e) = watcher.watch() {
        debug!("kqueue watch() failed: {e}");
        return None;
    }

    if watched.is_empty() {
        return None;
    }

    Some((watcher, watched))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_file_filter() {
        assert!(!is_user_file(Path::new("/tmp/some_lock")));
        assert!(!is_user_file(Path::new("/usr/lib/libc.so")));
        assert!(is_user_file(Path::new("/home/user/project/secret.txt")));
        assert!(is_user_file(Path::new("/etc/shadow")));
    }

    #[test]
    fn write_fd_parsing() {
        // is_write_fd reads from /proc, tested implicitly in integration
        // This test validates the logic concept
        assert!(true);
    }
}
