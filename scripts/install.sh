#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# agent-sign Installer
# Builds, installs, configures, and verifies the complete toolchain.
# Supports macOS (launchd) and Linux (systemd --user).
#
# Programs: agent-signd (service), agent-sign (CLI), agent-ssh-sign (git's
# signing program), agent-git (the wrapper, also installed as `git`).
#
# Everything lives in ~/.agent-sign: the programs (bin/), the agent key
# (keys/), config.toml, leases.json and the service's socket. The service runs
# as the LaunchAgent com.agentsign.agent-signd (macOS) or the systemd
# user unit agent-signd (Linux).
#
# Installing over an existing install keeps its key, leases and config. If
# ~/.agent-sign is a link to a directory kept elsewhere, it's used in place.
#
# Usage:
#   ./scripts/install.sh                         from a source checkout or a release archive
#   install.sh --from-homebrew <prefix>          after `brew install agent-sign`
#   --yes                                        don't stop to ask before changing things
# =============================================================================

STATE_DIR="$HOME/.agent-sign"
INSTALL_DIR="$STATE_DIR/bin"
KEYS_DIR="$STATE_DIR/keys"
CONFIG_DIR="$STATE_DIR"
CONFIG_FILE="$CONFIG_DIR/config.toml"
PUB_KEY_FILE="$KEYS_DIR/agent_ed25519.pub"
SERVICE_LABEL="com.agentsign.agent-signd"

# The directory holding this script (and the service files beside it), and
# the checkout or archive it came in, so it works from any directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="$(dirname "$SCRIPT_DIR")"

HOMEBREW_PREFIX_ARG=""
ASSUME_YES=false
while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y)
            ASSUME_YES=true
            shift
            ;;
        --from-homebrew)
            HOMEBREW_PREFIX_ARG="${2:-}"
            [ -n "$HOMEBREW_PREFIX_ARG" ] || { echo "--from-homebrew needs the formula's prefix" >&2; exit 2; }
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 2
            ;;
    esac
done

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
echo -e "${BOLD}║            agent-sign Installer (pre-release)          ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ─── Before anything: say what will change, and ask ────────────────────────
# Someone at a terminal sees every change before it's made (docs/INSTALL.md
# has the details) and can stop here. Without a terminal, or with --yes, it
# goes ahead.
if [ -t 0 ] && [ "$ASSUME_YES" = false ]; then
    echo "This will:"
    echo "  • put agent-sign's programs, a new agent signing key, and its config in ~/.agent-sign"
    echo "  • add the agent key to git's allowed_signers file, under your git email"
    echo "  • install a user service that keeps agent-signd running ($( [ "$(uname -s)" = Darwin ] && echo launchd || echo systemd))"
    echo "  • put ~/.agent-sign/bin first on PATH in the shell profiles you have"
    echo "    (.zshrc, .zprofile, .bashrc, .bash_profile), so agents started from them use its git"
    echo "  • do the same for the terminals of Cursor, VS Code and Windsurf, if installed,"
    echo "    and add a rule for Google Antigravity, if installed"
    [ -d "$HOME/.agent-sign" ] && echo "  • move your agent-sign install to ~/.agent-sign, keeping its key and leases"
    echo "It asks separately before adding anything to your GitHub account."
    echo "./scripts/uninstall.sh undoes all of it."
    read -r -p "Continue? [Y/n] " REPLY_GO || REPLY_GO=""
    case "$REPLY_GO" in [nN]|[nN][oO]) echo "Nothing was changed."; exit 0 ;; esac
fi

# ─── Step 0: Prerequisites & Binary Resolution ──────────────────────────────
step "Resolving binaries"

# Stops a service by its service manager name, if it's running.
stop_service() {
    local label="$1" unit="$2"
    if [ "$(uname -s)" = "Darwin" ]; then
        launchctl bootout "gui/$(id -u)/$label" 2>/dev/null && ok "Stopped $label" || true
    elif command -v systemctl &>/dev/null; then
        systemctl --user stop "$unit" 2>/dev/null && ok "Stopped $unit" || true
    fi
}

mkdir -p "$INSTALL_DIR"
mkdir -p "$KEYS_DIR"
chmod 700 "$CONFIG_DIR"
chmod 700 "$KEYS_DIR"

VERSION="v0.1.0"
REPO="taylor-made-labs/agent-sign"
INSTALLED_FROM_RELEASE=false

# Installs the built programs into $INSTALL_DIR, with `git` as a copy of the
# wrapper. Each file is copied to a temporary name and renamed into place, so a
# running binary is never overwritten in place.
install_binaries() {
    local src="$1"
    local name
    for name in agent-signd agent-sign agent-ssh-sign agent-git; do
        cp "$src/$name" "$INSTALL_DIR/.$name.new"
        mv -f "$INSTALL_DIR/.$name.new" "$INSTALL_DIR/$name"
    done
    cp "$src/agent-git" "$INSTALL_DIR/.git.new"
    mv -f "$INSTALL_DIR/.git.new" "$INSTALL_DIR/git"
}

# Installs from a Homebrew prefix: links to the formula's programs through its
# stable `opt` prefix, so `brew upgrade` updates what's installed here.
install_from_homebrew() {
    local prefix="$1"
    local name
    for name in agent-signd agent-sign agent-ssh-sign; do
        ln -sfn "$prefix/bin/$name" "$INSTALL_DIR/$name"
    done
    ln -sfn "$prefix/libexec/agent-git" "$INSTALL_DIR/agent-git"
    ln -sfn "$prefix/libexec/agent-git" "$INSTALL_DIR/git"
}

if [ -n "$HOMEBREW_PREFIX_ARG" ]; then
    info "Using the programs Homebrew installed in $HOMEBREW_PREFIX_ARG"
    install_from_homebrew "$HOMEBREW_PREFIX_ARG"
    INSTALLED_FROM_RELEASE=true
# Programs next to this script: a release archive (bin/) or a built checkout
# (target/release/).
elif [ -x "$SOURCE_ROOT/bin/agent-signd" ] && [ -x "$SOURCE_ROOT/bin/agent-git" ]; then
    info "Using the programs in this release archive"
    install_binaries "$SOURCE_ROOT/bin"
    INSTALLED_FROM_RELEASE=true
elif [ -f "$SOURCE_ROOT/target/release/agent-signd" ] && [ -f "$SOURCE_ROOT/target/release/agent-sign" ] && [ -f "$SOURCE_ROOT/target/release/agent-ssh-sign" ] && [ -f "$SOURCE_ROOT/target/release/agent-git" ]; then
    info "Using existing local release binaries from target/release/"
    install_binaries "$SOURCE_ROOT/target/release"
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
        elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
            TARGET_TRIPLE="aarch64-unknown-linux-gnu"
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
            if [ -x "$EXTRACTED_DIR/bin/agent-signd" ]; then
                install_binaries "$EXTRACTED_DIR/bin"
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
    (cd "$SOURCE_ROOT" && cargo build --release --locked --quiet 2>&1 | tail -5)
    install_binaries "$SOURCE_ROOT/target/release"
    ok "Build and installation from source complete"
fi

chmod +x "$INSTALL_DIR/agent-signd"
chmod +x "$INSTALL_DIR/agent-sign"
chmod +x "$INSTALL_DIR/agent-ssh-sign"
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
# agent-sign configuration
# Documentation: https://github.com/taylor-made-labs/agent-sign (README.md, SPEC.md)
# agent-signd reads this file when it starts: restart the service after changing it.

[security]
# A lease is your approval, given once, for agents to sign commits in one
# repository. Its terms are fixed when you approve and never grow; changing
# these settings later can only narrow leases already granted.
#
# Lease mode: "identity" (default: until you revoke it, or max_lease_ceiling),
# "timed" (default_lease_duration after approval), or "process" (not tied to a
# process yet; works as "timed")
lease_mode = "identity"

# Lease scope: "branch" (default) or "repo". With branch scope and
# allow_branch_switching (default true), a lease covers every unprotected
# branch of the repository, and the approval says so.
lease_scope = "branch"

# How long a "timed" lease lasts
default_lease_duration = "2h"

# Optional longest life for "identity" leases (e.g. "24h", "7d", or "none")
# max_lease_ceiling = "7d"

# Protect production branches (agent commits blocked unless overridden)
allow_main_branch = false
block_branches = ["main", "master"]

# Guard against runaway commit loops
max_commits_per_minute = 10

# true grants every lease without asking. Only for a machine with no screen
# (where agent-signd can't ask you), and only if every process that can reach the
# service is trusted. See docs/INSTALL.md, "Headless machines".
auto_approve = false

[attribution]
# "split"    -> Author: the agent, Committer: you
# "trailers" -> Author and Committer: you, plus Co-Authored-By and X-Agent-*
#               trailers (only when the message is given with -m or --message)
# "alias"    -> Author and Committer: "<your name> (Agent)" <the [agent] email>
mode = "split"

[agent]
name = "Agent"
email = "agent@local.internal"

[human]
# Auto-detected from your git config. Override here if needed.
# name = "$HUMAN_NAME"
# email = "$HUMAN_EMAIL"

[ssh]
# Your existing signing program. A signing request without an agent token
# (your own commits, when git calls agent-sign's signing program) is passed to it.
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

# Stop a service installed earlier through its service manager, then any
# service started by hand. Match the process name exactly, and only your own
# processes: matching command lines (as `pkill -f` does) would also stop any
# shell or SSH session whose command happens to contain the name.
stop_service "$SERVICE_LABEL" agent-signd
for name in agent-signd agent-signd; do
    if pgrep -u "$(id -u)" -x "$name" &>/dev/null; then
        info "Stopping a running $name started by hand..."
        pkill -u "$(id -u)" -x "$name" 2>/dev/null || true
        sleep 1
        ok "Stopped"
    fi
done

# Remove stale socket
if [ -S "$CONFIG_DIR/daemon.sock" ]; then
    rm -f "$CONFIG_DIR/daemon.sock"
    ok "Removed stale socket"
fi

# ─── Step 8: Install and start daemon service ───────────────────────────────
OS="$(uname -s)"

start_by_hand() {
    nohup "$INSTALL_DIR/agent-signd" >/dev/null 2>&1 &
    disown
    ok "Service started in the background (PID: $!)"
}

if [ "$OS" = "Darwin" ]; then
    # macOS: the LaunchAgent.
    PLIST_SRC="$SCRIPT_DIR/agent-signd.plist"
    PLIST_DST="$HOME/Library/LaunchAgents/$SERVICE_LABEL.plist"
    if [ -f "$PLIST_SRC" ]; then
        mkdir -p "$HOME/Library/LaunchAgents"
        cp "$PLIST_SRC" "$PLIST_DST"
        launchctl bootstrap "gui/$(id -u)" "$PLIST_DST"
        ok "Service installed and started: LaunchAgent $SERVICE_LABEL (starts at login)"
    else
        warn "LaunchAgent file not found at $PLIST_SRC"
        start_by_hand
    fi
elif [ "$OS" = "Linux" ]; then
    # Linux: the systemd user unit.
    SERVICE_SRC="$SCRIPT_DIR/agent-signd.service"
    SERVICE_DST="$HOME/.config/systemd/user/agent-signd.service"
    if [ -f "$SERVICE_SRC" ] && command -v systemctl &>/dev/null; then
        mkdir -p "$HOME/.config/systemd/user"
        cp "$SERVICE_SRC" "$SERVICE_DST"
        systemctl --user daemon-reload
        systemctl --user enable --now agent-signd
        ok "Service installed and started: systemd user service agent-signd"
        info "It runs while you're logged in. On a machine you log out of (a server),"
        info "keep it running with: loginctl enable-linger \"\$USER\""
    else
        start_by_hand
    fi
else
    start_by_hand
fi

# Give daemon a moment to start
sleep 1

# ─── Step 9: Configure agent environments & shell PATH ──────────────────────
step "Configuring environment & agent integrations"

# 1. Shell profiles (global PATH injection)
# Puts ~/.agent-sign/bin first on PATH in a marked block, once.
add_to_shell_profile() {
    local file="$1"
    if [ -f "$file" ]; then
        if grep -q "# >>> agent-sign >>>" "$file"; then
            ok "Shell PATH already configured in $file"
        else
            cat >> "$file" << 'EOF'

# >>> agent-sign >>>
# Added by the agent-sign installer; ./scripts/uninstall.sh removes it.
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
    // Added by the agent-sign installer
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
# agent-sign
Git commits here go through agent-sign (`~/.agent-sign/bin/git`), which signs them with the agent's own key once the person has approved.
Run `git commit` normally. Never pass `--no-gpg-sign` or call another git to get around it.
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

verify "agent-signd binary exists"        "[ -x '$INSTALL_DIR/agent-signd' ]"
verify "agent-sign binary exists"         "[ -x '$INSTALL_DIR/agent-sign' ]"
verify "agent-ssh-sign binary exists" "[ -x '$INSTALL_DIR/agent-ssh-sign' ]"
verify "agent-git binary exists"     "[ -x '$INSTALL_DIR/agent-git' ]"
verify "git shim exists"            "[ -x '$INSTALL_DIR/git' ]"
verify "Private key exists"         "[ -f '$KEYS_DIR/agent_ed25519' ]"
verify "Public key exists"          "[ -f '$PUB_KEY_FILE' ]"
verify "Config file exists"         "[ -f '$CONFIG_FILE' ]"
# GNU stat first: on Linux, `stat -f` means "file system status" and prints
# something else, so trying the BSD form first failed this check on Linux.
verify "Key permissions (0600)"     "[ \"\$(stat -c '%a' '$KEYS_DIR/agent_ed25519' 2>/dev/null || stat -f '%Lp' '$KEYS_DIR/agent_ed25519' 2>/dev/null)\" = '600' ]"
verify "Daemon socket exists"       "[ -S '$CONFIG_DIR/daemon.sock' ]"
# grep without -q reads all of the output: with -q it stops at the first match,
# agent-signd's next line then hits a closed pipe, and under pipefail the check
# failed at random.
verify "Daemon responds to ping"    "'$INSTALL_DIR/agent-signd' status 2>&1 | grep 'active' >/dev/null"
verify "Shell PATH configured"      "grep -q '# >>> agent-sign >>>' ~/.zshrc 2>/dev/null || grep -q '# >>> agent-sign >>>' ~/.bashrc 2>/dev/null || grep -q '# >>> agent-sign >>>' ~/.zprofile 2>/dev/null || grep -q '# >>> agent-sign >>>' ~/.bash_profile 2>/dev/null"

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}All $PASS checks passed!${NC}"
else
    echo -e "${YELLOW}${BOLD}$PASS passed, $FAIL failed${NC}"
fi

# ─── Step 11: Register Signing Key on GitHub / GitLab ───────────────────────
step "GitHub / GitLab Signing Key Setup"

REGISTERED_VIA_GH=false

# Adding a key to someone's GitHub account is theirs to agree to: ask, and
# only when there's a person at the terminal to answer.
ADD_WITH_GH=false
if command -v gh &>/dev/null && gh auth status &>/dev/null && [ -t 0 ]; then
    echo ""
    echo "The GitHub CLI (gh) is signed in. agent-sign can add the agent's public"
    echo "key to your GitHub account as a signing key (it can sign, not log in or push),"
    echo "so agent commits show as Verified."
    read -r -p "Add it now with gh? [y/N] " REPLY_GH || REPLY_GH=""
    case "$REPLY_GH" in [yY]|[yY][eE][sS]) ADD_WITH_GH=true ;; esac
fi
if [ "$ADD_WITH_GH" = true ]; then
    if gh ssh-key list 2>/dev/null | grep -F "$AGENT_KEY_DATA" >/dev/null; then
        ok "The agent's signing key is already on your GitHub account"
        REGISTERED_VIA_GH=true
    elif gh ssh-key add "$PUB_KEY_FILE" --type signing --title "agent-sign agent signing key ($(hostname -s))" 2>/dev/null; then
        ok "Added the agent's signing key to your GitHub account"
        REGISTERED_VIA_GH=true
    else
        warn "gh couldn't add the key (it may need the admin:ssh_signing_key scope); the steps to add it by hand follow"
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
echo -e "${BOLD}1. Open a new terminal${NC} (or run ${GREEN}source ~/.bashrc${NC} / ${GREEN}source ~/.zshrc${NC})."
echo -e "   The installer put $INSTALL_DIR first on PATH in the shell profiles"
echo -e "   it found, so agents started from a new terminal run the wrapper as git."
echo -e "   Then check the setup with: ${GREEN}agent-sign doctor${NC}"
echo ""
echo -e "${BOLD}2. Your own commits${NC} from an interactive terminal skip agent-sign and use"
echo -e "   your own signing (${DETECTED_SOURCE:-none detected}). An editor's commit button whose"
echo -e "   git is the wrapper looks like an agent to agent-sign, and asks for a lease."
echo ""
echo -e "${BOLD}3. What the agent key can do:${NC} it's registered as a signing key only, so"
echo -e "   it can't log in or push. But it's stored unencrypted, readable by your"
echo -e "   user, and signatures made with it show as Verified for you; see the"
echo -e "   README's \"What it protects against, and what it doesn't\"."
echo ""
echo -e "   To uninstall: ${CYAN}./scripts/uninstall.sh${NC}"
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║              Installation Complete ✓             ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""
