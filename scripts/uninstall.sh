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
info "Stopping the agent-commits service (and agent-sign's, if it's still installed)..."

# agent-commits' service, and agent-sign's from an install made before the rename.
OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
    for label in com.agentcommits.agent-commitsd com.agentsign.agent-signd; do
        launchctl bootout "gui/$(id -u)/$label" 2>/dev/null && ok "Stopped LaunchAgent $label" || true
        if [ -f "$HOME/Library/LaunchAgents/$label.plist" ]; then
            rm -f "$HOME/Library/LaunchAgents/$label.plist"
            ok "Removed LaunchAgent $label"
        fi
    done
elif [ "$OS" = "Linux" ] && command -v systemctl &>/dev/null; then
    for unit in agent-commitsd agent-signd; do
        systemctl --user stop "$unit" 2>/dev/null && ok "Stopped systemd unit $unit" || true
        systemctl --user disable "$unit" 2>/dev/null || true
        if [ -f "$HOME/.config/systemd/user/$unit.service" ]; then
            rm -f "$HOME/.config/systemd/user/$unit.service"
            ok "Removed systemd unit $unit"
        fi
    done
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

# Removes the installer's marked PATH block (and agent-sign's, from an
# older install).
cleanup_shell_profile() {
    local file="$1" name
    for name in agent-commits agent-sign; do
        if [ -f "$file" ] && grep -q "# >>> $name >>>" "$file"; then
            sed -i.bak "/# >>> $name >>>/,/# <<< $name <<</d" "$file"
            rm -f "${file}.bak"
            ok "Removed $name's PATH block from $file"
        fi
    done
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

# The snippet the installer adds, under either installer's comment, pointing
# at either directory.
pattern = r',?\s*// Added (?:automatically by agent-sign installer|by the agent-commits installer)\s*"terminal\.integrated\.env\.osx":\s*\{\s*"PATH":\s*"[^\"]*\.agent-(?:sign|commits)/bin[^\"]*"\s*\},\s*"terminal\.integrated\.env\.linux":\s*\{\s*"PATH":\s*"[^\"]*\.agent-(?:sign|commits)/bin[^\"]*"\s*\}'

for config_path in ide_configs:
    if not os.path.exists(config_path):
        continue
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
        if ".agent-sign/bin" not in content and ".agent-commits/bin" not in content:
            continue
        new_content = re.sub(pattern, "", content)
        if new_content != content:
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(new_content)
            print(f"  \033[0;32m✓\033[0m Removed agent-commits' terminal PATH from {config_path}")
    except Exception as e:
        print(f"  \033[0;33m⚠\033[0m Could not revert {config_path}: {e}")
PYEOF

# ─── Step 5: Remove Antigravity rule ─────────────────────────────────────────
for rule in agent-commits agent-sign; do
    if [ -f "$HOME/.gemini/config/rules/$rule.md" ]; then
        rm -f "$HOME/.gemini/config/rules/$rule.md"
        ok "Removed Antigravity rule $rule.md"
    fi
done

# ─── Step 6: Remove installed directory ─────────────────────────────────────
info "Removing ~/.agent-commits (and ~/.agent-sign)..."

# A link is removed, never followed: if either name links to a directory you
# keep somewhere else, that directory (and the key in it) is left for you.
for dir in "$HOME/.agent-commits" "$HOME/.agent-sign"; do
    if [ -L "$dir" ]; then
        TARGET="$(cd "$dir" 2>/dev/null && pwd -P || true)"
        rm -f "$dir"
        ok "Removed the link $dir"
        if [ -n "$TARGET" ] && [ -d "$TARGET" ] && [ "$TARGET" != "$HOME/.agent-commits" ] && [ "$TARGET" != "$HOME/.agent-sign" ]; then
            warn "Left $TARGET, which it pointed to: delete it yourself if you no longer need the agent key in it"
        fi
    elif [ -d "$dir" ]; then
        rm -rf "$dir"
        ok "Removed $dir (programs, key, config, leases, socket)"
    fi
done

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
