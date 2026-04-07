#!/usr/bin/env bash
set -euo pipefail

REPO="diemoeve/forgeterm"
BIN_DIR="${HOME}/.local/bin"
CONFIG_DIR="${HOME}/.config/forgeterm"
DATA_DIR="${HOME}/.local/share/forgeterm"

info()  { printf '\033[1;34m::\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33mwarn:\033[0m %s\n' "$*"; }
error() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Linux)  OS_TAG="linux" ;;
    Darwin) OS_TAG="darwin" ;;
    *) error "Unsupported OS: $OS. Forgeterm supports Linux and macOS." ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) error "Unsupported architecture: $ARCH" ;;
esac

info "Installing forgeterm for ${OS_TAG}-${ARCH}"

# Get latest release tag (portable: follows GitHub redirect)
LATEST=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
    "https://github.com/${REPO}/releases/latest" | sed 's|.*/||')

if [ -z "$LATEST" ] || [ "$LATEST" = "releases" ]; then
    error "No releases found. Check https://github.com/${REPO}/releases"
fi

info "Latest release: ${LATEST}"

ASSET="forgeterm-${OS_TAG}-${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET}"

# Download and extract
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

info "Downloading ${ASSET}..."
if ! curl -fsSL -o "${TMPDIR}/${ASSET}" "$DOWNLOAD_URL"; then
    error "Download failed. Check that a release exists for ${OS_TAG}-${ARCH}."
fi

tar xzf "${TMPDIR}/${ASSET}" -C "$TMPDIR"

# Install binaries
mkdir -p "$BIN_DIR"
install -m 755 "${TMPDIR}/forgeterm-agent" "${BIN_DIR}/forgeterm-agent"
info "Installed ${BIN_DIR}/forgeterm-agent"

if [ -f "${TMPDIR}/forgeterm" ]; then
    install -m 755 "${TMPDIR}/forgeterm" "${BIN_DIR}/forgeterm"
    info "Installed ${BIN_DIR}/forgeterm"
fi

# Install default configs (skip if user has customized)
mkdir -p "$CONFIG_DIR"
if [ ! -f "${CONFIG_DIR}/agent.toml" ]; then
    if [ -f "${TMPDIR}/agent.toml" ]; then
        install -m 644 "${TMPDIR}/agent.toml" "${CONFIG_DIR}/agent.toml"
        info "Installed default config: ${CONFIG_DIR}/agent.toml"
    fi
else
    info "Keeping existing config: ${CONFIG_DIR}/agent.toml"
fi

if [ ! -f "${CONFIG_DIR}/security-rules.toml" ]; then
    if [ -f "${TMPDIR}/security-rules.toml" ]; then
        install -m 644 "${TMPDIR}/security-rules.toml" "${CONFIG_DIR}/security-rules.toml"
        info "Installed default rules: ${CONFIG_DIR}/security-rules.toml"
    fi
else
    info "Keeping existing rules: ${CONFIG_DIR}/security-rules.toml"
fi

# Create data directory
mkdir -p "${DATA_DIR}/audit"

# Platform-specific service setup
if [ "$OS_TAG" = "linux" ]; then
    SYSTEMD_DIR="${HOME}/.config/systemd/user"
    if command -v systemctl >/dev/null 2>&1; then
        mkdir -p "$SYSTEMD_DIR"
        cat > "${SYSTEMD_DIR}/forgeterm-agent.service" <<UNIT
[Unit]
Description=Forgeterm Guardian Agent - AI CLI monitor daemon
After=default.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/forgeterm-agent
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=forgeterm-agent
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${DATA_DIR} ${CONFIG_DIR}
PrivateTmp=true

[Install]
WantedBy=default.target
UNIT

        systemctl --user daemon-reload
        systemctl --user enable forgeterm-agent.service
        systemctl --user start forgeterm-agent.service
        info "systemd service enabled and started"
    else
        info "systemd not found. Run manually: forgeterm-agent"
    fi

elif [ "$OS_TAG" = "darwin" ]; then
    LAUNCHD_DIR="${HOME}/Library/LaunchAgents"
    PLIST="${LAUNCHD_DIR}/com.forgeterm.agent.plist"
    mkdir -p "$LAUNCHD_DIR"

    cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.forgeterm.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN_DIR}/forgeterm-agent</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/forgeterm-agent.err</string>
    <key>StandardOutPath</key>
    <string>/tmp/forgeterm-agent.out</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
PLIST

    launchctl load "$PLIST" 2>/dev/null || true
    info "launchd agent loaded"
fi

# PATH check
case ":$PATH:" in
    *":${BIN_DIR}:"*) ;;
    *)
        warn "${BIN_DIR} is not in your PATH."
        warn "Add to your shell profile:"
        warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
        ;;
esac

info "Done. Run 'forgeterm' to open the dashboard."
