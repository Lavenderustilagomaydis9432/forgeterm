# Security Policy

Forgeterm is a security monitoring tool. Vulnerabilities in Forgeterm itself are taken seriously.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Use [GitHub Security Advisories](https://github.com/diemoeve/forgeterm/security/advisories/new) to report vulnerabilities privately.

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

You will receive a response within 72 hours.

## Scope

The following are in scope:

- Privilege escalation via the daemon or TUI
- Bypassing security detection rules
- Audit log tampering or injection
- IPC protocol vulnerabilities (Unix socket)
- Information disclosure through audit logs or IPC
- Denial of service against the monitoring daemon

The following are out of scope:

- Vulnerabilities in monitored AI tools themselves (Claude Code, Codex, etc.)
- Issues requiring physical access to the machine
- Issues in dependencies without a demonstrated exploit path in Forgeterm

## Supported Versions

Only the latest release is supported with security updates.
