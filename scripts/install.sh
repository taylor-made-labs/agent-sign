#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Agent-Sign Installer
# Builds, installs, configures, and verifies the complete agent-sign toolchain.
# Supports macOS (launchd) and Linux (systemd --user).
# =============================================================================

INSTALL_DIR="$HOME/.agent-sign/bin"
KEYS_DIR="$HOME/.agent-sign/keys"
CONFIG_DIR="$HOME/.agent-sign"
CONFIG_FILE="$CONFIG_DIR/config.toml"
PUB_KEY_FILE="$KEYS_DIR/agent_ed25519.pub"

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()  { echo -e "${BOLD}==> ${NC}$1"; }
ok()    { echo -e "${GREEN}  ✓${NC} $1"; }
warn()  { echo -e "${YELLOW}  ⚠${NC} $1"; }
err()   { echo -e "${RED}  ✗${NC} $1"; }
step()  { echo -e "\n${CYAN}${BOLD}── $1 ──${NC}"; }

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         Agent-Sign Toolchain Installer           ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ─── Step 0: Prerequisites & Binary Resolution ──────────────────────────────
step "Resolving binaries"

mkdir -p "$INSTALL_DIR"
mkdir -p "$KEYS_DIR"
chmod 700 "$CONFIG_DIR"
chmod 700 "$KEYS_DIR"

VERSION="v0.1.0"
REPO="taylor-made-labs/agent-sign"
INSTALLED_FROM_RELEASE=false

# Check if we are running in the source repo with target/release already built
if [ -f "target/release/agent-signd" ] && [ -f "target/release/agent-sign" ] && [ -f "target/release/agent-git" ]; then
    info "Using existing local release binaries from target/release/"
    cp target/release/agent-signd "$INSTALL_DIR/agent-signd"
    cp target/release/agent-sign  "$INSTALL_DIR/agent-sign"
    cp target/release/agent-git   "$INSTALL_DIR/agent-git"
    cp target/release/agent-git   "$INSTALL_DIR/git"
    INSTALLED_FROM_RELEASE=true
fi

# If not already installed and no cargo, or if running via curl/standalone, attempt GitHub Release download
if [ "$INSTALLED_FROM_RELEASE" = false ]; then
    OS="$(uname -s)"
    ARCH="$(uname -m)"
    TARGET_TRIPLE=""

    if [ "$OS" = "Darwin" ]; then
        if [ "$ARCH" = "arm64" ]; then
            TARGET_TRIPLE="aarch64-apple-darwin"
        else
            TARGET_TRIPLE="x86_64-apple-darwin"
        fi
    elif [ "$OS" = "Linux" ]; then
        if [ "$ARCH" = "x86_64" ]; then
            TARGET_TRIPLE="x86_64-unknown-linux-gnu"
        fi
    fi

    if [ -n "$TARGET_TRIPLE" ] && command -v curl &>/dev/null; then
        TARBALL="agent-sign-${TARGET_TRIPLE}.tar.gz"
        URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"
        info "Attempting to download pre-compiled release: ${TARBALL}..."

        TMP_DIR=$(mktemp -d)
        if curl -fsSL "$URL" -o "$TMP_DIR/$TARBALL" 2>/dev/null; then
            tar -xzf "$TMP_DIR/$TARBALL" -C "$TMP_DIR"
            EXTRACTED_DIR="$TMP_DIR/agent-sign-${TARGET_TRIPLE}"
            if [ -d "$EXTRACTED_DIR/bin" ]; then
                cp "$EXTRACTED_DIR/bin/"* "$INSTALL_DIR/"
                ok "Downloaded and installed pre-compiled binaries for ${TARGET_TRIPLE}"
                INSTALLED_FROM_RELEASE=true
            fi
            rm -rf "$TMP_DIR"
        else
            rm -rf "$TMP_DIR"
            info "Release download not available or failed — checking for local Cargo build..."
        fi
    fi
fi

# Fallback to local Cargo build if needed
if [ "$INSTALLED_FROM_RELEASE" = false ]; then
    if ! command -v cargo &>/dev/null; then
        err "Rust/Cargo not found and pre-compiled binary could not be downloaded."
        err "Please install Rust from https://rustup.rs or download a release from:"
        err "https://github.com/${REPO}/releases"
        exit 1
    fi
    info "Building from source with Cargo..."
    cargo build --release --quiet 2>&1 | tail -5
    cp target/release/agent-signd "$INSTALL_DIR/agent-signd"
    cp target/release/agent-sign  "$INSTALL_DIR/agent-sign"
    cp target/release/agent-git   "$INSTALL_DIR/agent-git"
    cp target/release/agent-git   "$INSTALL_DIR/git"
    ok "Build and installation from source complete"
fi

chmod +x "$INSTALL_DIR/agent-signd"
chmod +x "$INSTALL_DIR/agent-sign"
chmod +x "$INSTALL_DIR/agent-git"
chmod +x "$INSTALL_DIR/git"

ok "Binaries ready in $INSTALL_DIR"

# ─── Step 3: Generate agent keypair ─────────────────────────────────────────
step "Agent signing keypair"

"$INSTALL_DIR/agent-signd" setup 2>&1 | grep -v "^=\|^$" || true

if [ -f "$PUB_KEY_FILE" ]; then
    AGENT_PUB_KEY=$(cat "$PUB_KEY_FILE")
    ok "Agent public key: $AGENT_PUB_KEY"
else
    err "Keypair generation failed — $PUB_KEY_FILE not found"
    exit 1
fi

# ─── Step 4: Auto-detect fallback signing program ───────────────────────────
step "Detecting your existing signing setup"

FALLBACK_PROGRAM=""
DETECTED_SOURCE=""

# Check git config first
GIT_SSH_PROGRAM=$(git config --global gpg.ssh.program 2>/dev/null || echo "")
GIT_GPG_FORMAT=$(git config --global gpg.format 2>/dev/null || echo "")

if [ "$GIT_GPG_FORMAT" = "ssh" ] && [ -n "$GIT_SSH_PROGRAM" ]; then
    if [ -x "$GIT_SSH_PROGRAM" ] || [ -f "$GIT_SSH_PROGRAM" ]; then
        FALLBACK_PROGRAM="$GIT_SSH_PROGRAM"
        DETECTED_SOURCE="git config (gpg.ssh.program)"
    fi
fi

# If not found via git config, try common locations
if [ -z "$FALLBACK_PROGRAM" ]; then
    # 1Password (macOS)
    if [ -x "/Applications/1Password.app/Contents/MacOS/op-ssh-sign" ]; then
        FALLBACK_PROGRAM="/Applications/1Password.app/Contents/MacOS/op-ssh-sign"
        DETECTED_SOURCE="1Password (macOS)"
    # 1Password (Linux snap)
    elif [ -x "/snap/1password/current/op-ssh-sign" ]; then
        FALLBACK_PROGRAM="/snap/1password/current/op-ssh-sign"
        DETECTED_SOURCE="1Password (Linux snap)"
    # 1Password (Linux flatpak)
    elif command -v op-ssh-sign &>/dev/null; then
        FALLBACK_PROGRAM="$(command -v op-ssh-sign)"
        DETECTED_SOURCE="1Password (PATH)"
    # Standard ssh-keygen
    elif [ -x "/usr/bin/ssh-keygen" ]; then
        FALLBACK_PROGRAM="/usr/bin/ssh-keygen"
        DETECTED_SOURCE="OpenSSH ssh-keygen"
    fi
fi

if [ -n "$FALLBACK_PROGRAM" ]; then
    ok "Detected fallback signing program: $FALLBACK_PROGRAM ($DETECTED_SOURCE)"
else
    warn "No existing signing program detected — defaulting to /usr/bin/ssh-keygen"
    FALLBACK_PROGRAM="/usr/bin/ssh-keygen"
fi

# ─── Step 5: Generate config ────────────────────────────────────────────────
step "Generating configuration"

# Detect human identity from git config
HUMAN_NAME=$(git config --global user.name 2>/dev/null || echo "")
HUMAN_EMAIL=$(git config --global user.email 2>/dev/null || echo "")

if [ ! -f "$CONFIG_FILE" ]; then
    cat > "$CONFIG_FILE" <<EOF
# Agent-Sign Configuration
# Documentation: https://github.com/taylor-made-labs/agent-sign

[security]
# Session lease duration before re-approval is needed
default_lease_duration = "2h"

# Protect production branches (agent commits blocked unless overridden)
allow_main_branch = false
block_branches = ["main", "master"]

# Guard against runaway commit loops
max_commits_per_minute = 10

# Set to true for CI/headless environments (no interactive prompt)
auto_approve = false

[attribution]
# "split"    -> Author: Agent, Committer: You (recommended for OSS)
# "trailers" -> Author: You + Co-Authored-By trailers (enterprise LDAP compliant)
# "alias"    -> Author & Committer: You (Agent) <you+agent@domain.com>
mode = "split"

[agent]
name = "Agent"
email = "agent@local.internal"

[human]
# Auto-detected from your git config. Override here if needed.
# name = "$HUMAN_NAME"
# email = "$HUMAN_EMAIL"

[ssh]
# Your existing signing program — human commits are forwarded here.
# Agent-sign delegates to this when no agent event token is present.
fallback_program = "$FALLBACK_PROGRAM"
EOF
    ok "Config written to $CONFIG_FILE"
else
    # Update fallback_program in existing config if it's still the default
    if grep -q 'fallback_program = "/usr/bin/ssh-keygen"' "$CONFIG_FILE" && [ "$FALLBACK_PROGRAM" != "/usr/bin/ssh-keygen" ]; then
        sed -i.bak "s|fallback_program = \"/usr/bin/ssh-keygen\"|fallback_program = \"$FALLBACK_PROGRAM\"|" "$CONFIG_FILE"
        rm -f "$CONFIG_FILE.bak"
        ok "Updated fallback_program in existing config to $FALLBACK_PROGRAM"
    else
        ok "Existing config preserved at $CONFIG_FILE"
    fi
fi

# ─── Step 6: Register agent key in allowed_signers ──────────────────────────
step "Registering agent key for local verification"

ALLOWED_SIGNERS_FILE=$(git config --global gpg.ssh.allowedSignersFile 2>/dev/null || echo "")

if [ -z "$ALLOWED_SIGNERS_FILE" ]; then
    ALLOWED_SIGNERS_FILE="$HOME/.config/git/allowed_signers"
    mkdir -p "$(dirname "$ALLOWED_SIGNERS_FILE")"
    git config --global gpg.ssh.allowedSignersFile "$ALLOWED_SIGNERS_FILE"
    ok "Set gpg.ssh.allowedSignersFile to $ALLOWED_SIGNERS_FILE"
fi

# Expand ~ in path
ALLOWED_SIGNERS_FILE="${ALLOWED_SIGNERS_FILE/#\~/$HOME}"

# Extract key type and key data from agent public key
AGENT_KEY_DATA=$(awk '{print $2}' "$PUB_KEY_FILE")
AGENT_SIGNER_EMAIL=$(git config --global user.email 2>/dev/null || echo "agent@local.internal")
AGENT_SIGNER_LINE="$AGENT_SIGNER_EMAIL $AGENT_PUB_KEY"

if [ -f "$ALLOWED_SIGNERS_FILE" ] && grep -qF "$AGENT_KEY_DATA" "$ALLOWED_SIGNERS_FILE"; then
    ok "Agent key already registered in $ALLOWED_SIGNERS_FILE"
else
    mkdir -p "$(dirname "$ALLOWED_SIGNERS_FILE")"
    echo "$AGENT_SIGNER_LINE" >> "$ALLOWED_SIGNERS_FILE"
    ok "Agent key added to $ALLOWED_SIGNERS_FILE"
fi

# ─── Step 7: Stop any existing daemon ───────────────────────────────────────
step "Managing daemon"

# Stop any running agent-signd
if pgrep -f "agent-signd" &>/dev/null; then
    info "Stopping existing agent-signd process(es)..."
    pkill -f "agent-signd" 2>/dev/null || true
    sleep 1
    ok "Existing daemon stopped"
fi

# Remove stale socket
if [ -S "$CONFIG_DIR/daemon.sock" ]; then
    rm -f "$CONFIG_DIR/daemon.sock"
    ok "Removed stale socket"
fi

# ─── Step 8: Install and start daemon service ───────────────────────────────
OS="$(uname -s)"

if [ "$OS" = "Darwin" ]; then
    # macOS: install launchd service
    PLIST_SRC="scripts/agent-signd.plist"
    PLIST_DST="$HOME/Library/LaunchAgents/com.agentsign.agent-signd.plist"

    if [ -f "$PLIST_SRC" ]; then
        # Unload if already loaded
        launchctl bootout "gui/$(id -u)/com.agentsign.agent-signd" 2>/dev/null || true

        cp "$PLIST_SRC" "$PLIST_DST"
        launchctl bootstrap "gui/$(id -u)" "$PLIST_DST"
        ok "Daemon installed and started via launchd (auto-starts on login)"
    else
        warn "LaunchAgent plist not found at $PLIST_SRC — starting daemon manually"
        "$INSTALL_DIR/agent-signd" &
        disown
        ok "Daemon started in background (PID: $!)"
    fi
elif [ "$OS" = "Linux" ]; then
    # Linux: install systemd user service
    SERVICE_SRC="scripts/agent-signd.service"
    SERVICE_DST="$HOME/.config/systemd/user/agent-signd.service"

    if [ -f "$SERVICE_SRC" ] && command -v systemctl &>/dev/null; then
        mkdir -p "$HOME/.config/systemd/user"
        cp "$SERVICE_SRC" "$SERVICE_DST"
        systemctl --user daemon-reload
        systemctl --user enable --now agent-signd
        ok "Daemon installed and started via systemd (auto-starts on login)"
    else
        "$INSTALL_DIR/agent-signd" &
        disown
        ok "Daemon started in background (PID: $!)"
    fi
else
    "$INSTALL_DIR/agent-signd" &
    disown
    ok "Daemon started in background (PID: $!)"
fi

# Give daemon a moment to start
sleep 1

# ─── Step 9: Configure agent environments & shell PATH ──────────────────────
step "Configuring environment & agent integrations"

# 1. Shell profiles (global PATH injection)
add_to_shell_profile() {
    local file="$1"
    if [ -f "$file" ]; then
        if grep -q "# >>> agent-sign >>>" "$file"; then
            ok "Shell PATH already configured in $file"
        else
            cat >> "$file" << 'EOF'

# >>> agent-sign >>>
# Added automatically by agent-sign installer
export PATH="$HOME/.agent-sign/bin:$PATH"
# <<< agent-sign <<<
EOF
            ok "Added agent-sign to PATH in $file"
        fi
    fi
}

add_to_shell_profile "$HOME/.zshrc"
add_to_shell_profile "$HOME/.zprofile"
add_to_shell_profile "$HOME/.bashrc"
add_to_shell_profile "$HOME/.bash_profile"

# 2. IDE environment configuration (Cursor, VS Code, Windsurf)
python3 - << 'PYEOF'
import os, re

ide_configs = [
    os.path.expanduser("~/Library/Application Support/Cursor/User/settings.json"),
    os.path.expanduser("~/.config/Cursor/User/settings.json"),
    os.path.expanduser("~/Library/Application Support/Code/User/settings.json"),
    os.path.expanduser("~/.config/Code/User/settings.json"),
    os.path.expanduser("~/Library/Application Support/Windsurf/User/settings.json"),
    os.path.expanduser("~/.config/Windsurf/User/settings.json"),
]

for config_path in ide_configs:
    if not os.path.exists(config_path):
        continue
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()

        if ".agent-sign/bin" in content:
            print(f"  \033[0;32m✓\033[0m IDE config already includes agent-sign: {config_path}")
            continue

        last_brace = content.rfind("}")
        if last_brace == -1:
            continue

        prefix = content[:last_brace].rstrip()
        clean_prefix = re.sub(r"//.*", "", prefix).rstrip()
        comma = "" if clean_prefix.endswith(",") else ","

        snippet = f"""{comma}
    // Added automatically by agent-sign installer
    "terminal.integrated.env.osx": {{
        "PATH": "${{env:HOME}}/.agent-sign/bin:${{env:PATH}}"
    }},
    "terminal.integrated.env.linux": {{
        "PATH": "${{env:HOME}}/.agent-sign/bin:${{env:PATH}}"
    }}
"""
        new_content = prefix + snippet + content[last_brace:]
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        print(f"  \033[0;32m✓\033[0m Configured terminal env in {config_path}")
    except Exception as e:
        print(f"  \033[0;33m⚠\033[0m Could not update {config_path}: {e}")
PYEOF

# 3. Antigravity / Gemini configuration
if [ -d "$HOME/.gemini/config" ]; then
    mkdir -p "$HOME/.gemini/config/rules"
    cat > "$HOME/.gemini/config/rules/agent-sign.md" << 'EOF'
# Agent-Sign Integration
Git commits in this environment are automatically intercepted, authorized, and signed via `agent-sign` (`~/.agent-sign/bin/git`).
Run `git commit` normally when committing changes. Never bypass signing or pass `--no-gpg-sign`.
EOF
    ok "Configured Antigravity rule in ~/.gemini/config/rules/agent-sign.md"
fi

# ─── Step 10: Verify ────────────────────────────────────────────────────────
step "Verifying installation"

PASS=0
FAIL=0

verify() {
    if eval "$2" &>/dev/null; then
        ok "$1"
        PASS=$((PASS + 1))
    else
        err "$1"
        FAIL=$((FAIL + 1))
    fi
}

verify "agent-signd binary exists"  "[ -x '$INSTALL_DIR/agent-signd' ]"
verify "agent-sign binary exists"   "[ -x '$INSTALL_DIR/agent-sign' ]"
verify "agent-git binary exists"    "[ -x '$INSTALL_DIR/agent-git' ]"
verify "git shim exists"            "[ -x '$INSTALL_DIR/git' ]"
verify "Private key exists"         "[ -f '$KEYS_DIR/agent_ed25519' ]"
verify "Public key exists"          "[ -f '$PUB_KEY_FILE' ]"
verify "Config file exists"         "[ -f '$CONFIG_FILE' ]"
verify "Key permissions (0600)"     "[ \"\$(stat -f '%Lp' '$KEYS_DIR/agent_ed25519' 2>/dev/null || stat -c '%a' '$KEYS_DIR/agent_ed25519' 2>/dev/null)\" = '600' ]"
verify "Daemon socket exists"       "[ -S '$CONFIG_DIR/daemon.sock' ]"
verify "Daemon responds to ping"    "'$INSTALL_DIR/agent-signd' status 2>&1 | grep -q 'active'"
verify "Shell PATH configured"      "grep -q '# >>> agent-sign >>>' ~/.zshrc 2>/dev/null || grep -q '# >>> agent-sign >>>' ~/.bashrc 2>/dev/null || grep -q '# >>> agent-sign >>>' ~/.zprofile 2>/dev/null"

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}All $PASS checks passed!${NC}"
else
    echo -e "${YELLOW}${BOLD}$PASS passed, $FAIL failed${NC}"
fi

# ─── Step 11: Register Signing Key on GitHub / GitLab ───────────────────────
step "GitHub / GitLab Signing Key Setup"

REGISTERED_VIA_GH=false

if command -v gh &>/dev/null; then
    if gh auth status &>/dev/null; then
        info "Found authenticated GitHub CLI (gh). Attempting automated key registration..."
        # Check if already registered
        if gh ssh-key list 2>/dev/null | grep -qF "$AGENT_KEY_DATA"; then
            ok "Agent signing key is already registered on GitHub!"
            REGISTERED_VIA_GH=true
        else
            if gh ssh-key add "$PUB_KEY_FILE" --type signing --title "Agent-Sign Sub-Key ($(hostname -s))" 2>/dev/null; then
                ok "Successfully added Agent Signing Key to your GitHub account via gh CLI!"
                REGISTERED_VIA_GH=true
            else
                warn "gh ssh-key add requires additional scope or encountered an issue. Falling back to quick-link."
            fi
        fi
    fi
fi

if [ "$REGISTERED_VIA_GH" = false ]; then
    # Copy to clipboard if utility available
    COPIED_CLIPBOARD=false
    if command -v pbcopy &>/dev/null; then
        pbcopy < "$PUB_KEY_FILE"
        COPIED_CLIPBOARD=true
    elif command -v wl-copy &>/dev/null; then
        wl-copy < "$PUB_KEY_FILE"
        COPIED_CLIPBOARD=true
    elif command -v xclip &>/dev/null; then
        xclip -selection clipboard < "$PUB_KEY_FILE"
        COPIED_CLIPBOARD=true
    fi

    echo ""
    echo -e "${BOLD}Add your Agent SSH Signing Key to GitHub:${NC}"
    echo -e "   1. Browser URL: ${CYAN}https://github.com/settings/ssh/new${NC}"
    echo -e "   2. Key type:    ${BOLD}Signing Key${NC}  (NOT Authentication Key)"
    echo -e "   3. Key content:"
    echo ""
    echo -e "   ${GREEN}$AGENT_PUB_KEY${NC}"
    echo ""

    if [ "$COPIED_CLIPBOARD" = true ]; then
        ok "Public key automatically copied to your clipboard!"
    fi

    # Try to open the URL directly if in an interactive desktop session
    if [ -t 0 ] || [ -n "${DISPLAY:-}" ] || [ "$(uname -s)" = "Darwin" ]; then
        if [ "$OS" = "Darwin" ] && command -v open &>/dev/null; then
            open "https://github.com/settings/ssh/new" 2>/dev/null || true
            ok "Opened GitHub SSH settings in your browser."
        elif command -v xdg-open &>/dev/null; then
            xdg-open "https://github.com/settings/ssh/new" 2>/dev/null || true
            ok "Opened GitHub SSH settings in your browser."
        fi
    fi
fi

# ─── Step 12: Print results & next steps ───────────────────────────────────
step "Setup Complete"

echo ""
echo -e "${BOLD}1. Agent tools are ready — zero aliases required!${NC}"
echo -e "   The installer automatically configured:"
echo -e "     ${GREEN}✓${NC} Shell PATH in your shell profiles (~/.zshrc / ~/.zprofile)"
echo -e "     ${GREEN}✓${NC} IDE terminal environments (Cursor / VS Code / Windsurf)"
echo -e "     ${GREEN}✓${NC} Claude Code, Antigravity, Aider, and any CLI tools inherit PATH automatically"
echo ""
echo -e "   To activate in your current terminal session:"
echo -e "     ${GREEN}source ~/.zshrc${NC}  (or open a new terminal window)"
echo ""
echo -e "${BOLD}2. Verify daemon status anytime:${NC}"
echo -e "     ${GREEN}$INSTALL_DIR/agent-signd status${NC}"
echo ""
echo -e "   Your human commits (terminal, IDE buttons) continue to use"
echo -e "   your personal signing key ($DETECTED_SOURCE) as normal."
echo ""
echo -e "${BOLD}3. Zero blast-radius reassurance:${NC}"
echo -e "   The agent key is strictly a Git SSH signing key. It cannot access SSH"
echo -e "   servers, clone private repos, or push to remotes."
echo -e "   To cleanly uninstall at any time: ${CYAN}./scripts/uninstall.sh${NC}"
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║              Installation Complete ✓             ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""
