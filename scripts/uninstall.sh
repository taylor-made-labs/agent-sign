#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# agent-commits (formerly agent-sign) uninstaller
# Removes agent-commits' service, programs, keys, leases and config, and undoes the
# installer's PATH, editor and allowed_signers changes. It leaves your own git
# settings alone, including gpg.ssh.allowedSignersFile if the installer set it.
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
echo -e "${BOLD}║                agent-commits Uninstaller                  ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ─── Step 1: Stop daemon ────────────────────────────────────────────────────
info "Stopping the agent-commits service (agent-commitsd, installed as agent-signd)..."

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

# A service started by hand rather than by launchd or systemd. Match the
# process name exactly, and only your own processes: matching command lines
# (as `pkill -f` does) would also stop any shell or SSH session whose command
# happens to contain the name.
for name in agent-signd agent-commitsd; do
    if pgrep -u "$(id -u)" -x "$name" &>/dev/null; then
        pkill -u "$(id -u)" -x "$name" 2>/dev/null && ok "Stopped a running $name" || true
        sleep 1
    fi
done

# ─── Step 2: Remove agent key from allowed_signers ──────────────────────────
info "Cleaning up allowed_signers..."

# ~/.agent-commits after agent-commitsd has migrated; ~/.agent-sign is then a link to it.
if [ -d "$HOME/.agent-commits" ]; then
    PUB_KEY_FILE="$HOME/.agent-commits/keys/agent_ed25519.pub"
else
    PUB_KEY_FILE="$HOME/.agent-sign/keys/agent_ed25519.pub"
fi
ALLOWED_SIGNERS_FILE=$(git config --global gpg.ssh.allowedSignersFile 2>/dev/null || echo "")
ALLOWED_SIGNERS_FILE="${ALLOWED_SIGNERS_FILE/#\~/$HOME}"

if [ -n "$ALLOWED_SIGNERS_FILE" ] && [ -f "$ALLOWED_SIGNERS_FILE" ] && [ -f "$PUB_KEY_FILE" ]; then
    AGENT_KEY_DATA=$(awk '{print $2}' "$PUB_KEY_FILE" 2>/dev/null || echo "")
    if [ -n "$AGENT_KEY_DATA" ] && grep -qF "$AGENT_KEY_DATA" "$ALLOWED_SIGNERS_FILE"; then
        # grep exits 1 when no line is left (the agent's was the only one, as on
        # a machine where the installer created the file). That's success here;
        # under `set -e` it used to stop the uninstaller halfway.
        { grep -vF "$AGENT_KEY_DATA" "$ALLOWED_SIGNERS_FILE" || [ $? -eq 1 ]; } > "${ALLOWED_SIGNERS_FILE}.tmp"
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

if [ -L "$HOME/.agent-sign" ]; then
    rm -f "$HOME/.agent-sign"
    ok "Removed the $HOME/.agent-sign link"
elif [ -d "$HOME/.agent-sign" ]; then
    rm -rf "$HOME/.agent-sign"
    ok "Removed $HOME/.agent-sign (binaries, keys, config, socket)"
else
    ok "~/.agent-sign does not exist (already clean)"
fi

if [ -d "$HOME/.agent-commits" ]; then
    rm -rf "$HOME/.agent-commits"
    ok "Removed $HOME/.agent-commits (binaries, keys, config, socket)"
fi

# ─── Step 7: Summary ────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}Uninstall complete.${NC}"
echo ""
echo "What was removed:"
echo "  • Daemon process and service (launchd/systemd)"
echo "  • ~/.agent-commits/ and ~/.agent-sign/ (binaries, keypair, config, socket)"
echo "  • Agent key entry from allowed_signers"
echo "  • Shell PATH entries from shell profiles"
echo "  • IDE terminal environment settings (Cursor / VS Code / Windsurf)"
echo "  • Antigravity agent rule"
echo ""
echo "What was NOT modified:"
echo "  • Your git config (your signing key, gpg.format, and gpg.ssh.allowedSignersFile,"
echo "    which the installer sets if it wasn't set; unset it with"
echo "    git config --global --unset gpg.ssh.allowedSignersFile if you don't use it)"
echo "  • Your GitHub/GitLab account: remove the agent's signing key there yourself"
echo ""
echo "To reinstall fresh: ./scripts/install.sh"
echo ""
