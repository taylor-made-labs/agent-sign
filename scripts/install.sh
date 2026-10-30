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
# Everything lives in ~/.agent-sign: the programs (bin/), the agents'
# certificate authorities' public keys (keys/), config.toml, leases.json and
# the service's socket. No private key is ever stored there: the agents'
# certificate authority is made in the service's memory at each start, and
# private keys earlier versions left in plain files are deleted (after the
# question below). The installer also routes your own SSH signing through
# agent-sign (git's gpg.ssh.program), keeping your signer as its
# fallback_program, and keeps a marked block in your allowed_signers file
# that trusts agents' signatures. The service runs
# as the LaunchAgent com.agentsign.agent-signd (macOS) or the systemd
# user unit agent-signd (Linux). On macOS it runs from a copy inside a small
# app bundle, ~/.agent-sign/agent-sign.app, so that the system's Touch ID
# prompt says "agent-sign" instead of "agent-signd".
#
# Installing over an existing install keeps its keys, leases and config. If
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
# An agents' certificate authority private key that earlier development
# builds stored unprotected: deleted, and the service won't start while it's
# there. The current authority's public key, and every one the service has
# started with (one per line, with its date), are kept beside it.
CA_KEY_FILE="$KEYS_DIR/agents_ca_ed25519"
CA_PUB_FILE="$KEYS_DIR/agents_ca_ed25519.pub"
CAS_HISTORY_FILE="$KEYS_DIR/agents_cas.pub"
# The shared agent key of versions before per-agent identities: no longer
# made or used. Its private half was stored unprotected, so it counts as
# exposed and is deleted; its public half stays, so commits it signed can
# still be checked.
LEGACY_KEY_FILE="$KEYS_DIR/agent_ed25519"
LEGACY_PUB_KEY_FILE="$KEYS_DIR/agent_ed25519.pub"
# Where an earlier build of this change moved that private half: deleted too.
RETIRED_DIR="$KEYS_DIR/retired"
# The managed block in your allowed_signers file: the service rewrites the
# lines between these two at each start, and nothing outside them.
TRUST_BLOCK_BEGIN="# agent-sign: agents' certificate authorities, managed; do not edit"
TRUST_BLOCK_END="# agent-sign: end of agents' certificate authorities"
TRUST_PREFIX='*@agents.local cert-authority,namespaces="git" '
# git's signing program for your own SSH signatures, once routed.
AGENT_SSH_SIGN="$INSTALL_DIR/agent-ssh-sign"
SERVICE_LABEL="com.agentsign.agent-signd"
# macOS: the app bundle the service runs from (see make_service_bundle).
APP_DIR="$STATE_DIR/agent-sign.app"
APP_PROGRAM="$APP_DIR/Contents/MacOS/agent-signd"

# The directory holding this script (and the service files beside it), and
# the checkout or archive it came in, so it works from any directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="$(dirname "$SCRIPT_DIR")"

HOMEBREW_PREFIX_ARG=""
RELEASE_ARCHIVE=""
EXPECTED_SHA256=""
ASSUME_YES=false
while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y)
            ASSUME_YES=true
            shift
            ;;
        --archive)
            RELEASE_ARCHIVE="${2:-}"
            [ -n "$RELEASE_ARCHIVE" ] || { echo "--archive needs a file" >&2; exit 2; }
            shift 2
            ;;
        --sha256)
            EXPECTED_SHA256="${2:-}"
            [ -n "$EXPECTED_SHA256" ] || { echo "--sha256 needs the independently trusted archive digest" >&2; exit 2; }
            shift 2
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

# Resolve trust before extracting or installing any release bytes. The expected
# digest comes from the caller's independent review, never from the same mutable
# download as the archive. Extracted release binaries alone are not admitted.
if [ -n "$RELEASE_ARCHIVE" ] || [ -n "$EXPECTED_SHA256" ]; then
    [ -n "$RELEASE_ARCHIVE" ] && [[ "$EXPECTED_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] \
        || { echo "Release installation requires --archive FILE --sha256 TRUSTED-DIGEST" >&2; exit 2; }
    [ -z "$HOMEBREW_PREFIX_ARG" ] || { echo "Choose either a release archive or Homebrew" >&2; exit 2; }
    [ -f "$RELEASE_ARCHIVE" ] || { echo "Release archive is not a file" >&2; exit 2; }
    RELEASE_TMP=$(mktemp -d)
    trap 'rm -rf "$RELEASE_TMP"' EXIT
    # Verify and extract the same private copy, not a caller path that can
    # change while the installation question is open.
    cp "$RELEASE_ARCHIVE" "$RELEASE_TMP/input.tar.gz"
    RELEASE_ARCHIVE="$RELEASE_TMP/input.tar.gz"
    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL_SHA256=$(sha256sum "$RELEASE_ARCHIVE" | awk '{print $1}')
    else
        ACTUAL_SHA256=$(shasum -a 256 "$RELEASE_ARCHIVE" | awk '{print $1}')
    fi
    [ "$(printf '%s' "$ACTUAL_SHA256" | tr 'A-F' 'a-f')" = "$(printf '%s' "$EXPECTED_SHA256" | tr 'A-F' 'a-f')" ] \
        || { echo "Release archive digest differs; nothing extracted or installed" >&2; exit 1; }
fi

# ─── What there is now ───────────────────────────────────────────────────────
# Your own SSH signing: git's gpg.ssh.program, which becomes agent-ssh-sign.
# What it was (or ssh-keygen, git's default, if it wasn't set) becomes
# agent-sign's fallback_program, where your own signatures go on to, and
# where uninstall.sh finds it to put it back. If it already is agent-ssh-sign
# (installing again), the fallback_program in config.toml is kept.
# --includes: the value may come from a file the global config includes,
# which `git config --global` alone doesn't read.
PREVIOUS_SSH_PROGRAM=$(git config --global --includes --get gpg.ssh.program 2>/dev/null || echo "")
ALREADY_ROUTED=false
if [ -n "$PREVIOUS_SSH_PROGRAM" ] && [ "$(basename -- "$PREVIOUS_SSH_PROGRAM")" = "agent-ssh-sign" ]; then
    ALREADY_ROUTED=true
    FALLBACK_PROGRAM=""
elif [ -n "$PREVIOUS_SSH_PROGRAM" ]; then
    FALLBACK_PROGRAM="$PREVIOUS_SSH_PROGRAM"
else
    FALLBACK_PROGRAM="ssh-keygen"
fi

# Private keys earlier versions stored unprotected, one per line: deleted
# below, after the question. (Taylor, 28 Oct 2026: keys are never stored
# unprotected; one that was counts as exposed.)
UNPROTECTED_KEYS=""
for key in "$CA_KEY_FILE" "$LEGACY_KEY_FILE" "$RETIRED_DIR"/agent_ed25519.*; do
    if [ -e "$key" ] || [ -L "$key" ]; then
        UNPROTECTED_KEYS="$UNPROTECTED_KEYS$key
"
    fi
done

# ─── Before anything: say what will change, and ask ────────────────────────
# Someone at a terminal sees every change before it's made (docs/INSTALL.md
# has the details) and can stop here. Without a terminal, or with --yes, it
# goes ahead.
if [ -t 0 ] && [ "$ASSUME_YES" = false ]; then
    echo "This will:"
    echo "  • put agent-sign's programs and its config in ~/.agent-sign (the agents' certificate"
    echo "    authority lives only in the service's memory; no private key is stored)"
    echo "  • keep a marked block in git's allowed_signers file that trusts agents' signatures"
    echo "    for *@agents.local only (the service updates it each time it starts)"
    if [ "$ALREADY_ROUTED" = true ]; then
        echo "  • keep your own SSH signing going through agent-sign (git's gpg.ssh.program is"
        echo "    already agent-ssh-sign)"
    else
        echo "  • route your own SSH signing through agent-sign: git's gpg.ssh.program becomes"
        echo "    ~/.agent-sign/bin/agent-ssh-sign, which refuses requests from agents and passes"
        echo "    yours on to your signer, $FALLBACK_PROGRAM (uninstall.sh puts it back)"
    fi
    printf '%s' "$UNPROTECTED_KEYS" | while IFS= read -r key; do
        [ -n "$key" ] || continue
        echo "  • delete $key: a private key an earlier version stored"
        echo "    unprotected (its public half stays, so commits it signed still verify)"
    done
    echo "  • install a user service that keeps agent-signd running ($( [ "$(uname -s)" = Darwin ] && echo launchd || echo systemd))"
    echo "  • put ~/.agent-sign/bin first on PATH in the shell profiles you have"
    echo "    (.zshrc, .zprofile, .bashrc, .bash_profile), so agents started from them use its git"
    echo "  • do the same for the terminals of Cursor, VS Code and Windsurf, if installed,"
    echo "    and add a rule for Google Antigravity, if installed"
    [ -d "$HOME/.agent-sign" ] && echo "  • move your agent-sign install to ~/.agent-sign, keeping its keys and leases"
    echo "./scripts/uninstall.sh undoes all of it."
    # The end of input (Ctrl-D, or a closed terminal) is no answer, so it
    # counts as no: what follows deletes keys and reroutes signing.
    read -r -p "Continue? [Y/n] " REPLY_GO || REPLY_GO="n"
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
    # Never install a test build: it stands in for the device owner.
    sh "$SCRIPT_DIR/check-binary-clean.sh" "$src" || exit 1
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
    sh "$SCRIPT_DIR/check-binary-clean.sh" "$prefix/bin" || exit 1
    for name in agent-signd agent-sign agent-ssh-sign; do
        ln -sfn "$prefix/bin/$name" "$INSTALL_DIR/$name"
    done
    ln -sfn "$prefix/libexec/agent-git" "$INSTALL_DIR/agent-git"
    ln -sfn "$prefix/libexec/agent-git" "$INSTALL_DIR/git"
}

if [ -n "$HOMEBREW_PREFIX_ARG" ]; then
    info "Using the explicitly selected Homebrew installation in $HOMEBREW_PREFIX_ARG"
    install_from_homebrew "$HOMEBREW_PREFIX_ARG"
elif [ -n "$RELEASE_ARCHIVE" ]; then
    mkdir -p "$RELEASE_TMP/unpacked"
    tar -xzf "$RELEASE_ARCHIVE" -C "$RELEASE_TMP/unpacked"
    # Standard release archives contain exactly one top-level product folder.
    RELEASE_ROOTS=("$RELEASE_TMP/unpacked"/agent-sign-*)
    [ "${#RELEASE_ROOTS[@]}" -eq 1 ] && [ -d "${RELEASE_ROOTS[0]}/bin" ] \
        || { err "Unexpected release layout"; exit 1; }
    install_binaries "${RELEASE_ROOTS[0]}/bin"
elif [ -f "$SOURCE_ROOT/Cargo.toml" ]; then
    command -v cargo >/dev/null 2>&1 || { err "Building this selected source requires Rust/Cargo. No release download was attempted."; exit 1; }
    info "Building the selected source (existing target/release binaries are not used without rebuilding)"
    (cd "$SOURCE_ROOT" && cargo build --release --locked)
    install_binaries "$SOURCE_ROOT/target/release"
else
    err "No selected source or trusted release archive. Use this reviewed installer with --archive FILE --sha256 TRUSTED-DIGEST, or explicitly select --from-homebrew PREFIX."
    exit 1
fi

chmod +x "$INSTALL_DIR/agent-signd"
chmod +x "$INSTALL_DIR/agent-sign"
chmod +x "$INSTALL_DIR/agent-ssh-sign"
chmod +x "$INSTALL_DIR/agent-git"
chmod +x "$INSTALL_DIR/git"

ok "Binaries ready in $INSTALL_DIR"

# ─── Step 3: The agents' certificate authority ──────────────────────────────
step "Agents' certificate authority"

# Each agent session signs with its own key, held only in the service's
# memory, under a certificate for the agent's principal
# (claude-code.1a2b3c4d@agents.local) from an authority the service makes in
# its memory at each start and never writes anywhere. `setup` only makes the
# folders.
"$INSTALL_DIR/agent-signd" setup >/dev/null 2>&1 || true
ok "The agents' certificate authority is made in the service's memory at each start; no private key is stored"

# Private keys earlier versions stored unprotected (listed in the question
# above): deleted, not moved aside, since a stored copy is as exposed as the
# original. Public halves stay, so what they signed can still be checked.
printf '%s' "$UNPROTECTED_KEYS" | while IFS= read -r key; do
    [ -n "$key" ] || continue
    rm -f "$key"
    ok "Deleted $key (a private key stored unprotected by an earlier version)"
done
rmdir "$RETIRED_DIR" 2>/dev/null || true

# ─── Step 4: Your own signing program ───────────────────────────────────────
step "Your own signing"

# See "What there is now" at the top: FALLBACK_PROGRAM is what git's
# gpg.ssh.program was, or ssh-keygen (git's default) if it wasn't set.
DETECTED_SOURCE="git's gpg.ssh.program"
if [ "$ALREADY_ROUTED" = true ]; then
    ok "Your own signing already goes through agent-sign ($PREVIOUS_SSH_PROGRAM)"
elif [ -n "$PREVIOUS_SSH_PROGRAM" ]; then
    ok "Your own signer: $FALLBACK_PROGRAM (git's gpg.ssh.program)"
else
    DETECTED_SOURCE="ssh-keygen, git's default"
    ok "Your own signer: ssh-keygen (git's default; gpg.ssh.program wasn't set)"
fi

# A value for a TOML basic string ("..."): backslashes and quotes escaped.
toml_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# Sets [ssh] fallback_program in config.toml to $1, replacing the line if
# there is one, adding it under [ssh] if not, or adding [ssh] at the end.
set_fallback_program() {
    local value
    value="$(toml_escape "$1")"
    FALLBACK_LINE="fallback_program = \"$value\"" awk '
        BEGIN { line = ENVIRON["FALLBACK_LINE"]; done = 0 }
        /^[[:space:]]*fallback_program[[:space:]]*=/ { if (!done) print line; done = 1; next }
        { print }
        /^[[:space:]]*\[ssh\][[:space:]]*$/ && !done { print line; done = 1 }
        END { if (!done) { print ""; print "[ssh]"; print line } }
    ' "$CONFIG_FILE" > "$CONFIG_FILE.new"
    cat "$CONFIG_FILE.new" > "$CONFIG_FILE"
    rm -f "$CONFIG_FILE.new"
}

# ─── Step 5: Generate config ────────────────────────────────────────────────
step "Generating configuration"

# Detect human identity from git config
HUMAN_NAME=$(git config --global user.name 2>/dev/null || echo "")
HUMAN_EMAIL=$(git config --global user.email 2>/dev/null || echo "")

# Routed already, but no config to say where your signatures go on to:
# git's default, said plainly so you can change it.
if [ "$ALREADY_ROUTED" = true ] && [ ! -f "$CONFIG_FILE" ]; then
    FALLBACK_PROGRAM="ssh-keygen"
    warn "gpg.ssh.program was already agent-ssh-sign, but there was no config: your own signatures go on to ssh-keygen. If you sign with another program, set fallback_program in $CONFIG_FILE"
fi

if [ ! -f "$CONFIG_FILE" ]; then
    cat > "$CONFIG_FILE" <<EOF
# agent-sign configuration
# Documentation: https://github.com/taylor-made-labs/agent-sign (README.md, SPEC.md)
# agent-signd reads this file when it starts: restart the service after changing it.

[security]
# Whether agent commits need your approval: "none" (the default: agents sign
# as themselves, never as you, and the service's log records which agent
# committed where) or "device-owner" (you approve each lease once, with
# Touch ID or your login password on macOS; Linux can't approve yet).
approval = "none"

# A lease is the permission, for one repository, under which agents sign
# commits. Its terms are fixed when it's granted and never grow; changing
# these settings later can only narrow leases already granted.
#
# Lease mode: "identity" (default: until its work is finished, see below, or max_lease_ceiling),
# "timed" (default_lease_duration after approval), or "process" (not tied to a
# process yet; works as "timed")
lease_mode = "identity"

# Lease scope: "branch" (default) or "repo". With branch scope, a lease covers
# only the branch you approved, in that repository (allow_branch_switching =
# false, the default and the narrowest). Set it to true, or lease_scope to
# "repo", to cover every unprotected branch of the repository; the approval
# prompt then says "any unprotected branch".
lease_scope = "branch"
allow_branch_switching = false

# How long a "timed" lease lasts
default_lease_duration = "2h"

# Optional longest life for "identity" leases (e.g. "24h", "7d", or "none")
# max_lease_ceiling = "7d"

# Every lease ends when the branch it was approved for is merged or deleted,
# or when you revoke it. As a backstop, it also ends after this long with no
# agent commits ("none" turns the backstop off).
end_after_idle = "7d"

# Protect production branches (agent commits blocked unless overridden)
allow_main_branch = false
block_branches = ["main", "master"]

# Guard against runaway commit loops
max_commits_per_minute = 10

# With approval = "device-owner": true grants every lease without asking.
# Only for a machine with no screen (where agent-signd can't ask you), and
# only if every process that can reach the service is trusted. See
# docs/INSTALL.md, "Headless machines".
auto_approve = false

[attribution]
# In every mode an agent's commit is authored, committed and signed by the
# agent's own identity, such as
# "Claude Code <claude-code.1a2b3c4d@agents.local>": agent-sign never puts
# your name on an agent's commit. "agent" (the default) does only that.
# "trailers" also adds Co-Authored-By and X-Agent-* trailers to a message
# given with -m or --message. "split" and "alias", from earlier versions,
# are still accepted and work as "agent".
mode = "agent"

[agent]
# The Co-Authored-By trailer's name in "trailers" mode, when the agent
# doesn't say who it is. It never changes who authors or commits.
name = "Agent"
email = "agent@local.internal"

[human]
# Auto-detected from your git config. Override here if needed.
# name = "$HUMAN_NAME"
# email = "$HUMAN_EMAIL"

[ssh]
# Your own signing program: what git's gpg.ssh.program was before the
# installer routed your signing through agent-sign (ssh-keygen, git's
# default, if it wasn't set). Your own signing requests go on to it; one from
# a process an agent marked is refused. uninstall.sh puts it back as
# gpg.ssh.program.
fallback_program = "$(toml_escape "$FALLBACK_PROGRAM")"
EOF
    ok "Config written to $CONFIG_FILE"
else
    ok "Existing config preserved at $CONFIG_FILE"
    if [ "$ALREADY_ROUTED" = false ]; then
        set_fallback_program "$FALLBACK_PROGRAM"
        ok "fallback_program set to your signer, $FALLBACK_PROGRAM"
    fi
    # The old template's default attribution put your name on agent commits
    # as committer; per-agent identities make the agent both.
    if grep -q '^mode = "split"$' "$CONFIG_FILE"; then
        sed -i.bak 's|^mode = "split"$|mode = "agent"|' "$CONFIG_FILE"
        rm -f "$CONFIG_FILE.bak"
        ok "Attribution changed from \"split\" (the old default) to \"agent\": agent commits are authored and committed by the agent"
    fi
fi

# ─── Step 5b: Route your own signing through agent-sign ─────────────────────
# With gpg.ssh.program set to agent-ssh-sign, a signing request from a
# process an agent marked is refused even when git runs without the wrapper
# (a hook, the real git called directly), and yours go on to
# fallback_program, as before. It covers SSH signing (gpg.format = ssh) only.
step "Routing your own signing through agent-sign"
if [ "$PREVIOUS_SSH_PROGRAM" = "$AGENT_SSH_SIGN" ]; then
    ok "Your own signing already goes through $AGENT_SSH_SIGN"
else
    git config --global gpg.ssh.program "$AGENT_SSH_SIGN"
    ok "git's gpg.ssh.program is now $AGENT_SSH_SIGN (it was ${PREVIOUS_SSH_PROGRAM:-not set}); your signatures go on to $(sed -n 's/^[[:space:]]*fallback_program[[:space:]]*=[[:space:]]*//p' "$CONFIG_FILE" | head -1)"
fi
# A file the global config includes after this setting would win over it.
EFFECTIVE_SSH_PROGRAM=$(git config --global --includes --get gpg.ssh.program 2>/dev/null || echo "")
if [ "$EFFECTIVE_SSH_PROGRAM" != "$AGENT_SSH_SIGN" ]; then
    warn "A file your git config includes sets gpg.ssh.program to ${EFFECTIVE_SSH_PROGRAM:-nothing} after this setting, so your own signing doesn't go through agent-sign. Remove it there, or set it to $AGENT_SSH_SIGN."
fi

# ─── Step 6: Trust agents' signatures in allowed_signers ────────────────────
step "Trusting agents' signatures for local verification"

ALLOWED_SIGNERS_FILE=$(git config --global gpg.ssh.allowedSignersFile 2>/dev/null || echo "")

if [ -z "$ALLOWED_SIGNERS_FILE" ]; then
    ALLOWED_SIGNERS_FILE="$HOME/.config/git/allowed_signers"
    mkdir -p "$(dirname "$ALLOWED_SIGNERS_FILE")"
    git config --global gpg.ssh.allowedSignersFile "$ALLOWED_SIGNERS_FILE"
    ok "Set gpg.ssh.allowedSignersFile to $ALLOWED_SIGNERS_FILE"
fi

# Expand ~ in path
ALLOWED_SIGNERS_FILE="${ALLOWED_SIGNERS_FILE/#\~/$HOME}"

# The managed block: the lines `agent-sign trust-line` prints (one per
# authority the service has started with), between two marker lines. The
# service rewrites the block at each start, so a new authority is trusted
# with no step of yours; nothing outside the markers is changed. Making the
# block for the first time moves a bare trust line an earlier version added
# into it. Before the service's first start there may be no line yet: it
# adds its own when it starts.
TRUST_LINES=$("$INSTALL_DIR/agent-sign" trust-line 2>/dev/null || true)
write_trust_block() {
    local file="$1"
    [ -f "$file" ] || : > "$file"
    BEGIN="$TRUST_BLOCK_BEGIN" END="$TRUST_BLOCK_END" LINES="$TRUST_LINES" PREFIX="$TRUST_PREFIX" awk '
        BEGIN { b = ENVIRON["BEGIN"]; e = ENVIRON["END"]; lines = ENVIRON["LINES"]; prefix = ENVIRON["PREFIX"] }
        { all[NR] = $0 }
        $0 == b && !opened { opened = NR }
        $0 == e && opened && !closed { closed = NR }
        END {
            if (opened && closed) {
                for (i = 1; i <= NR; i++) {
                    if (i > opened && i < closed) continue
                    print all[i]
                    if (i == opened && lines != "") print lines
                }
            } else {
                for (i = 1; i <= NR; i++) if (index(all[i], prefix) != 1) print all[i]
                print b
                if (lines != "") print lines
                print e
            }
        }
    ' "$file" > "$file.agent-sign.new"
    # Written over in place, so the file keeps its permissions, and a link
    # stays a link.
    cat "$file.agent-sign.new" > "$file"
    rm -f "$file.agent-sign.new"
}
mkdir -p "$(dirname "$ALLOWED_SIGNERS_FILE")"
write_trust_block "$ALLOWED_SIGNERS_FILE"
ok "agent-sign's block in $ALLOWED_SIGNERS_FILE trusts agents' signatures for *@agents.local only; the service keeps it current"

# ─── The old shared agent key ───────────────────────────────────────────────
# Versions before per-agent identities signed every agent commit with one
# shared key, listed in allowed_signers under your own email (and perhaps on
# your GitHub account), so agent commits verified as yours. Its private half
# was stored unprotected, so it counts as exposed and was deleted above (Step
# 3); its public half stays, so commits it already signed can still be
# checked. Removing its trust is yours to decide, because commits it signed
# then stop verifying: while it's still trusted, the installer prints the
# exact commands, and runs neither.
if [ -f "$LEGACY_PUB_KEY_FILE" ]; then
    LEGACY_KEY_DATA=$(awk '{print $2}' "$LEGACY_PUB_KEY_FILE" 2>/dev/null || echo "")
    if [ -n "$LEGACY_KEY_DATA" ] && [ -f "$ALLOWED_SIGNERS_FILE" ] && grep -qF "$LEGACY_KEY_DATA" "$ALLOWED_SIGNERS_FILE"; then
        warn "$ALLOWED_SIGNERS_FILE still trusts the old shared agent key under your email, so commits it signed show as yours."
        echo "    Its private half is deleted, so it signs nothing new. To stop trusting it"
        echo "    (commits it signed will then show as unverified), remove its line:"
        echo ""
        echo "      grep -vF '$LEGACY_KEY_DATA' '$ALLOWED_SIGNERS_FILE' > '$ALLOWED_SIGNERS_FILE.new' && mv '$ALLOWED_SIGNERS_FILE.new' '$ALLOWED_SIGNERS_FILE'"
        echo ""
        echo "    If you added the old agent key to GitHub as a signing key, you can remove it"
        echo "    there too: find it with"
        echo ""
        echo "      gh ssh-key list | grep -F '${LEGACY_KEY_DATA:0:40}'"
        echo ""
        echo "    and delete it with \`gh ssh-key delete <its ID>\`, or at https://github.com/settings/keys."
        echo "    The installer removes neither."
    fi
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
    local program="$INSTALL_DIR/agent-signd"
    # On macOS, from the app bundle, so the Touch ID prompt is named right.
    [ -x "$APP_PROGRAM" ] && program="$APP_PROGRAM"
    nohup "$program" >/dev/null 2>&1 &
    disown
    ok "Service started in the background (PID: $!)"
}

# macOS: the app bundle the service runs from. The system's Touch ID prompt
# says "<name> is trying to ...", with the name of the program that asked; a
# bare background program shows as "agent-signd" (the "d" means daemon, which
# means nothing to most people), and one inside an app bundle shows the
# bundle's name, "agent-sign". The bundle is built beside the real one and
# renamed into place, only after the old service is stopped, and signed
# ad hoc (no developer account needed; it only seals the bundle).
make_service_bundle() {
    local tmp="$STATE_DIR/.agent-sign.app.new"
    rm -rf "$tmp"
    mkdir -p "$tmp/Contents/MacOS"
    # A copy, not a link: the system looks at where the running program
    # really is, and a link would lead it out of the bundle.
    cp "$INSTALL_DIR/agent-signd" "$tmp/Contents/MacOS/agent-signd"
    cp "$SCRIPT_DIR/agent-sign.Info.plist" "$tmp/Contents/Info.plist"
    if command -v codesign &>/dev/null; then
        codesign --force --sign - "$tmp" 2>/dev/null \
            || warn "Couldn't sign the app bundle; it will still run"
    fi
    rm -rf "$APP_DIR"
    mv "$tmp" "$APP_DIR"
    ok "Service app bundle ready: $APP_DIR (the Touch ID prompt should say \"agent-sign\")"
}

if [ "$OS" = "Darwin" ]; then
    # macOS: the app bundle, then the LaunchAgent that starts it.
    if [ -f "$SCRIPT_DIR/agent-sign.Info.plist" ]; then
        make_service_bundle
    else
        err "agent-sign.Info.plist not found beside the installer: the service can't be set up without it"
        exit 1
    fi
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
Git commits here go through agent-sign (`~/.agent-sign/bin/git`), which signs and commits them as the agent's own identity, never as the user.
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
verify "No agents' authority private key stored" "[ ! -e '$CA_KEY_FILE' ]"
verify "Agents' authority public key recorded at start" "[ -s '$CAS_HISTORY_FILE' ]"
verify "Config file exists"         "[ -f '$CONFIG_FILE' ]"
verify "Your own signing goes through agent-sign" "[ \"\$(git config --global --includes --get gpg.ssh.program)\" = '$AGENT_SSH_SIGN' ]"
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

# ─── Step 11: GitHub / GitLab ───────────────────────────────────────────────
# Nothing to add: agents sign with their own keys under certificates from the
# agents' authority, which GitHub doesn't check, so agent commits show there
# as Unverified. Earlier versions offered to add a shared agent key to your
# account, which made agent commits show as Verified for you.
step "GitHub / GitLab"
ok "Nothing to add: agents' commits are signed as the agents, not as you, and show on GitHub as Unverified"

# ─── Step 12: Print results & next steps ───────────────────────────────────
step "Setup Complete"

echo ""
echo -e "${BOLD}1. Open a new terminal${NC} (or run ${GREEN}source ~/.bashrc${NC} / ${GREEN}source ~/.zshrc${NC})."
echo -e "   The installer put $INSTALL_DIR first on PATH in the shell profiles"
echo -e "   it found, so agents started from a new terminal run the wrapper as git."
echo -e "   Then check the setup with: ${GREEN}agent-sign doctor${NC}"
echo ""
echo -e "${BOLD}2. Your own commits${NC} from an interactive terminal skip the wrapper and are"
echo -e "   signed by your own signer (${DETECTED_SOURCE}), through agent-ssh-sign, which"
echo -e "   refuses signing requests from agents. An editor's commit button whose git is"
echo -e "   the wrapper is left to git: unsigned, under your git name, never attributed"
echo -e "   to an agent."
echo ""
echo -e "${BOLD}3. Agents sign as themselves:${NC} each agent session's commits are signed,"
echo -e "   authored and committed as that agent, never as you. These identities are"
echo -e "   claims made by programs running as your user: attribution, not a security"
echo -e "   boundary. See the README's \"What it protects against, and what it doesn't\"."
echo ""
echo -e "   To uninstall: ${CYAN}./scripts/uninstall.sh${NC}"
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║              Installation Complete ✓             ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""
