# Contributing to Forgeterm

## Build from Source

```bash
git clone https://github.com/diemoeve/forgeterm.git
cd forgeterm
cargo build --release
```

Binaries are at `target/release/forgeterm-agent` (daemon) and `target/release/forgeterm` (TUI).

## Run Tests

```bash
cargo test --workspace
```

All tests must pass. No `#[ignore]` without a comment explaining why.

## Code Style

- `cargo fmt` before every commit
- `cargo clippy -- -D warnings` must pass
- No `unwrap()` in production code. Use `anyhow` for error handling.
- `#[cfg(target_os)]` for platform-specific code

## Adding a Detection Rule

Detection rules live in `config/security-rules.toml`. Three types:

**File access rule:**
```toml
[[file_access]]
name = "Terraform state"
paths = ["*.tfstate", "*.tfstate.backup"]
severity = "Critical"
```

**Network allowlist entry:**
```toml
[[network_allow]]
name = "My API"
hosts = ["api.example.com"]
```

**Command pattern (regex):**
```toml
[[command_pattern]]
name = "Suspicious download"
pattern = "wget.*-O\\s+/tmp/"
severity = "Warning"
```

No code changes needed for new rules. The engine loads them from config at startup.

## Adding a New AI CLI Tool

1. Add a variant to `CliType` in `crates/shared/src/types.rs`
2. Add the match arm in `CliType::from_config_str()`
3. Add the display name in the `Display` impl
4. Add detection patterns to `config/agent.toml` under `[discovery.patterns]`
5. (Optional) Add per-CLI governor defaults to `config/agent.toml`

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run `cargo fmt` and `cargo clippy -- -D warnings`
4. Run `cargo test --workspace`
5. Open a PR against `main`
6. CI must pass on both Linux and macOS

Keep PRs focused. One feature or fix per PR.

## Reporting Bugs

Open a GitHub issue. Include:
- OS and architecture
- Forgeterm version (`forgeterm-agent --version`)
- Steps to reproduce
- Relevant log output from `journalctl --user -u forgeterm-agent`
