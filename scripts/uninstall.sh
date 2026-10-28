#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# agent-sign uninstaller
# Removes agent-sign's service, programs, keys, leases and config, and undoes the
# installer's PATH, editor and allowed_signers changes. It puts your own
# signing program back as git's gpg.ssh.program (from fallback_program in
# config.toml), and otherwise leaves your git settings alone, including
# gpg.ssh.allowedSignersFile if the installer set it.
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
echo -e "${BOLD}║                agent-sign Uninstaller                  ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ─── Step 1: Stop daemon ────────────────────────────────────────────────────
info "Stopping the agent-sign service..."

OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
    for label in com.agentsign.agent-signd; do
        launchctl bootout "gui/$(id -u)/$label" 2>/dev/null && ok "Stopped LaunchAgent $label" || true
        if [ -f "$HOME/Library/LaunchAgents/$label.plist" ]; then
            rm -f "$HOME/Library/LaunchAgents/$label.plist"
            ok "Removed LaunchAgent $label"
        fi
    done
elif [ "$OS" = "Linux" ] && command -v systemctl &>/dev/null; then
    for unit in agent-signd; do
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
for name in agent-signd agent-signd; do
    if pgrep -u "$(id -u)" -x "$name" &>/dev/null; then
        pkill -u "$(id -u)" -x "$name" 2>/dev/null && ok "Stopped a running $name" || true
        sleep 1
    fi
done

# ─── Step 2: Put your own signing program back ─────────────────────────────
# The installer set git's gpg.ssh.program to agent-ssh-sign and kept what it
# was as fallback_program. Put back only if it's still agent-ssh-sign (if
# you changed it since, it's yours). "ssh-keygen" is git's own default, what
# the installer records when nothing was set, so then the setting is unset.
info "Putting your own signing program back..."
CURRENT_SSH_PROGRAM=$(git config --global --includes --get gpg.ssh.program 2>/dev/null || echo "")
if [ -n "$CURRENT_SSH_PROGRAM" ] && [ "$(basename -- "$CURRENT_SSH_PROGRAM")" = "agent-ssh-sign" ]; then
    FALLBACK_PROGRAM=""
    if [ -f "$HOME/.agent-sign/config.toml" ]; then
        FALLBACK_PROGRAM=$(sed -n 's/^[[:space:]]*fallback_program[[:space:]]*=[[:space:]]*"\(.*\)"[[:space:]]*$/\1/p' "$HOME/.agent-sign/config.toml" | head -1 | sed -e 's/\\"/"/g' -e 's/\\\\/\\/g')
    fi
    if [ -z "$FALLBACK_PROGRAM" ] || [ "$FALLBACK_PROGRAM" = "ssh-keygen" ]; then
        git config --global --unset gpg.ssh.program || true
        ok "gpg.ssh.program unset: git signs with ssh-keygen, its default"
    else
        git config --global gpg.ssh.program "$FALLBACK_PROGRAM"
        ok "gpg.ssh.program is your own signer again: $FALLBACK_PROGRAM"
    fi
else
    ok "gpg.ssh.program isn't agent-sign's (${CURRENT_SSH_PROGRAM:-not set}): left as it is"
fi

# ─── Step 3: Remove agent-sign's lines from allowed_signers ─────────────────
# agent-sign's managed block (the agents' certificate authorities), a bare
# trust line an earlier version added, and the shared agent key line of
# earlier versions.
info "Cleaning up allowed_signers..."

ALLOWED_SIGNERS_FILE=$(git config --global gpg.ssh.allowedSignersFile 2>/dev/null || echo "")
ALLOWED_SIGNERS_FILE="${ALLOWED_SIGNERS_FILE/#\~/$HOME}"
TRUST_BLOCK_BEGIN="# agent-sign: agents' certificate authorities, managed; do not edit"
TRUST_BLOCK_END="# agent-sign: end of agents' certificate authorities"

REMOVED_ANY=false
if [ -n "$ALLOWED_SIGNERS_FILE" ] && [ -f "$ALLOWED_SIGNERS_FILE" ]; then
    if grep -qxF "$TRUST_BLOCK_BEGIN" "$ALLOWED_SIGNERS_FILE"; then
        BEGIN="$TRUST_BLOCK_BEGIN" END="$TRUST_BLOCK_END" awk '
            $0 == ENVIRON["BEGIN"] { inside = 1; next }
            inside && $0 == ENVIRON["END"] { inside = 0; next }
            !inside { print }
        ' "$ALLOWED_SIGNERS_FILE" > "${ALLOWED_SIGNERS_FILE}.tmp"
        cat "${ALLOWED_SIGNERS_FILE}.tmp" > "$ALLOWED_SIGNERS_FILE"
        rm -f "${ALLOWED_SIGNERS_FILE}.tmp"
        ok "Removed agent-sign's block from $ALLOWED_SIGNERS_FILE"
        REMOVED_ANY=true
    fi
    # Each authority's key (and the old shared key), wherever its line is.
    KEY_DATA_LIST=$(cat "$HOME/.agent-sign/keys/agents_cas.pub" "$HOME/.agent-sign/keys/agents_ca_ed25519.pub" "$HOME/.agent-sign/keys/agent_ed25519.pub" 2>/dev/null | awk 'NF >= 2 {print $2}' || true)
    for AGENT_KEY_DATA in $KEY_DATA_LIST; do
        if [ -n "$AGENT_KEY_DATA" ] && grep -qF "$AGENT_KEY_DATA" "$ALLOWED_SIGNERS_FILE"; then
            # grep exits 1 when no line is left (agent-sign's was the only one,
            # as on a machine where the installer created the file). That's
            # success here; under `set -e` it used to stop the uninstaller
            # halfway.
            { grep -vF "$AGENT_KEY_DATA" "$ALLOWED_SIGNERS_FILE" || [ $? -eq 1 ]; } > "${ALLOWED_SIGNERS_FILE}.tmp"
            mv "${ALLOWED_SIGNERS_FILE}.tmp" "$ALLOWED_SIGNERS_FILE"
            ok "Removed an agent key's line (${AGENT_KEY_DATA:0:24}...) from $ALLOWED_SIGNERS_FILE"
            REMOVED_ANY=true
        fi
    done
fi
if [ "$REMOVED_ANY" = false ]; then
    ok "No allowed_signers cleanup needed"
fi

# ─── Step 4: Remove shell profile PATH entries ─────────────────────────────
info "Cleaning up shell profile PATH entries..."

# Removes the installer's marked PATH block.
cleanup_shell_profile() {
    local file="$1"
    if [ -f "$file" ] && grep -q "# >>> agent-sign >>>" "$file"; then
        sed -i.bak "/# >>> agent-sign >>>/,/# <<< agent-sign <<</d" "$file"
        rm -f "${file}.bak"
        ok "Removed agent-sign's PATH block from $file"
    fi
}

cleanup_shell_profile "$HOME/.zshrc"
cleanup_shell_profile "$HOME/.zprofile"
cleanup_shell_profile "$HOME/.bashrc"
cleanup_shell_profile "$HOME/.bash_profile"

# ─── Step 5: Revert IDE environment configuration ───────────────────────────
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

# The snippet the installer adds, under the comment this installer writes or
# the one earlier versions wrote.
pattern = r',?\s*// Added (?:automatically by agent-sign installer|by the agent-sign installer)\s*"terminal\.integrated\.env\.osx":\s*\{\s*"PATH":\s*"[^\"]*\.agent-sign/bin[^\"]*"\s*\},\s*"terminal\.integrated\.env\.linux":\s*\{\s*"PATH":\s*"[^\"]*\.agent-sign/bin[^\"]*"\s*\}'

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
            print(f"  \033[0;32m✓\033[0m Removed agent-sign's terminal PATH from {config_path}")
    except Exception as e:
        print(f"  \033[0;33m⚠\033[0m Could not revert {config_path}: {e}")
PYEOF

# ─── Step 6: Remove Antigravity rule ─────────────────────────────────────────
if [ -f "$HOME/.gemini/config/rules/agent-sign.md" ]; then
    rm -f "$HOME/.gemini/config/rules/agent-sign.md"
    ok "Removed Antigravity rule agent-sign.md"
fi

# ─── Step 7: Remove installed directory ─────────────────────────────────────
info "Removing ~/.agent-sign..."

# A link is removed, never followed: if ~/.agent-sign links to a directory
# you keep somewhere else, that directory (and the key in it) is left for you.
DIR="$HOME/.agent-sign"
if [ -L "$DIR" ]; then
    TARGET="$(cd "$DIR" 2>/dev/null && pwd -P || true)"
    rm -f "$DIR"
    ok "Removed the link $DIR"
    if [ -n "$TARGET" ] && [ -d "$TARGET" ]; then
        warn "Left $TARGET, which it pointed to: delete it yourself if you no longer need the agent key in it"
    fi
elif [ -d "$DIR" ]; then
    rm -rf "$DIR"
    ok "Removed $DIR (programs, key, config, leases, socket)"
fi

# ─── Step 8: Summary ────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}Uninstall complete.${NC}"
echo ""
echo "What was removed:"
echo "  • Daemon process and service (launchd/systemd)"
echo "  • ~/.agent-sign/ (binaries, keys, config, socket)"
echo "  • agent-sign's lines in allowed_signers (its block for the agents' authorities, an old agent key)"
echo "  • agent-sign as your gpg.ssh.program: your own signer is back"
echo "  • Shell PATH entries from shell profiles"
echo "  • IDE terminal environment settings (Cursor / VS Code / Windsurf)"
echo "  • Antigravity agent rule"
echo ""
echo "What was NOT modified:"
echo "  • The rest of your git config (your signing key, gpg.format, and gpg.ssh.allowedSignersFile,"
echo "    which the installer sets if it wasn't set; unset it with"
echo "    git config --global --unset gpg.ssh.allowedSignersFile if you don't use it)"
echo "  • Your GitHub/GitLab account: remove the agent's signing key there yourself"
echo ""
echo "To reinstall fresh: ./scripts/install.sh"
echo ""
