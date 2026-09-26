#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Agent-Sign Uninstaller
# Cleanly removes all agent-sign state, binaries, keys, config, and services.
# Run this before re-installing, or to fully remove agent-sign from your system.
# =============================================================================

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓${NC} $1"; }
warn() { echo -e "${YELLOW}  ⚠${NC} $1"; }
info() { echo -e "${BOLD}==> ${NC}$1"; }

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         Agent-Sign Uninstaller                   ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ─── Step 1: Stop daemon ────────────────────────────────────────────────────
info "Stopping agent-signd daemon..."

OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
    launchctl bootout "gui/$(id -u)/com.agentsign.agent-signd" 2>/dev/null && ok "LaunchAgent unloaded" || true
    rm -f "$HOME/Library/LaunchAgents/com.agentsign.agent-signd.plist" && ok "LaunchAgent plist removed" || true
elif [ "$OS" = "Linux" ] && command -v systemctl &>/dev/null; then
    systemctl --user stop agent-signd 2>/dev/null && ok "Systemd service stopped" || true
    systemctl --user disable agent-signd 2>/dev/null && ok "Systemd service disabled" || true
    rm -f "$HOME/.config/systemd/user/agent-signd.service" && ok "Systemd service file removed" || true
    systemctl --user daemon-reload 2>/dev/null || true
fi

if pgrep -f "agent-signd" &>/dev/null; then
    pkill -f "agent-signd" 2>/dev/null && ok "Running daemon processes killed" || true
    sleep 1
fi

# ─── Step 2: Remove agent key from allowed_signers ──────────────────────────
info "Cleaning up allowed_signers..."

PUB_KEY_FILE="$HOME/.agent-sign/keys/agent_ed25519.pub"
ALLOWED_SIGNERS_FILE=$(git config --global gpg.ssh.allowedSignersFile 2>/dev/null || echo "")
ALLOWED_SIGNERS_FILE="${ALLOWED_SIGNERS_FILE/#\~/$HOME}"

if [ -n "$ALLOWED_SIGNERS_FILE" ] && [ -f "$ALLOWED_SIGNERS_FILE" ] && [ -f "$PUB_KEY_FILE" ]; then
    AGENT_KEY_DATA=$(awk '{print $2}' "$PUB_KEY_FILE" 2>/dev/null || echo "")
    if [ -n "$AGENT_KEY_DATA" ] && grep -qF "$AGENT_KEY_DATA" "$ALLOWED_SIGNERS_FILE"; then
        grep -vF "$AGENT_KEY_DATA" "$ALLOWED_SIGNERS_FILE" > "${ALLOWED_SIGNERS_FILE}.tmp"
        mv "${ALLOWED_SIGNERS_FILE}.tmp" "$ALLOWED_SIGNERS_FILE"
        ok "Agent key removed from $ALLOWED_SIGNERS_FILE"
    else
        ok "Agent key was not in allowed_signers (nothing to remove)"
    fi
else
    ok "No allowed_signers cleanup needed"
fi

# ─── Step 3: Remove shell profile PATH entries ─────────────────────────────
info "Cleaning up shell profile PATH entries..."

cleanup_shell_profile() {
    local file="$1"
    if [ -f "$file" ] && grep -q "# >>> agent-sign >>>" "$file"; then
        sed -i.bak '/# >>> agent-sign >>>/,/# <<< agent-sign <<</d' "$file"
        rm -f "${file}.bak"
        ok "Removed agent-sign from $file"
    fi
}

cleanup_shell_profile "$HOME/.zshrc"
cleanup_shell_profile "$HOME/.zprofile"
cleanup_shell_profile "$HOME/.bashrc"
cleanup_shell_profile "$HOME/.bash_profile"

# ─── Step 4: Revert IDE environment configuration ───────────────────────────
info "Reverting IDE configuration (Cursor, VS Code, Windsurf)..."

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

pattern = r',?\s*// Added automatically by agent-sign installer\s*"terminal\.integrated\.env\.osx":\s*\{\s*"PATH":\s*"[^\"]*agent-sign[^\"]*"\s*\},\s*"terminal\.integrated\.env\.linux":\s*\{\s*"PATH":\s*"[^\"]*agent-sign[^\"]*"\s*\}'

for config_path in ide_configs:
    if not os.path.exists(config_path):
        continue
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
        if ".agent-sign/bin" not in content:
            continue
        new_content = re.sub(pattern, "", content)
        if new_content != content:
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(new_content)
            print(f"  \033[0;32m✓\033[0m Reverted agent-sign config in {config_path}")
    except Exception as e:
        print(f"  \033[0;33m⚠\033[0m Could not revert {config_path}: {e}")
PYEOF

# ─── Step 5: Remove Antigravity rule ─────────────────────────────────────────
if [ -f "$HOME/.gemini/config/rules/agent-sign.md" ]; then
    rm -f "$HOME/.gemini/config/rules/agent-sign.md"
    ok "Removed Antigravity rule"
fi

# ─── Step 6: Remove installed directory ─────────────────────────────────────
info "Removing ~/.agent-sign directory..."

if [ -d "$HOME/.agent-sign" ]; then
    rm -rf "$HOME/.agent-sign"
    ok "Removed $HOME/.agent-sign (binaries, keys, config, socket)"
else
    ok "~/.agent-sign does not exist (already clean)"
fi

# ─── Step 7: Summary ────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}Uninstall complete.${NC}"
echo ""
echo "What was removed:"
echo "  • Daemon process and service (launchd/systemd)"
echo "  • ~/.agent-sign/ (binaries, keypair, config, socket)"
echo "  • Agent key entry from allowed_signers"
echo "  • Shell PATH entries from shell profiles"
echo "  • IDE terminal environment settings (Cursor / VS Code / Windsurf)"
echo "  • Antigravity agent rule"
echo ""
echo "What was NOT modified:"
echo "  • Your ~/.gitconfig (personal signing key, gpg.format, etc.)"
echo "  • Your GitHub/GitLab SSH keys (remove the agent signing key manually if desired)"
echo ""
echo "To reinstall fresh: ./scripts/install.sh"
echo ""
