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
# that trusts agents' signatures: once the service is up it runs
# `agent-sign trust install`, the only thing that writes that trust (a
# service's start never does). The service runs
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
#   --machine <name>                             this machine's name, such as "hetzner": agents'
#                                                names become <agent>.<session>@<name>.agents.local
#                                                ([identity] machine in config.toml, written before
#                                                the service starts)
#   --person <name>                              a person's name, such as "Taylor" (repeatable): no
#                                                agent is ever certified under it or any word of it
#                                                ([identity] people in config.toml). The people with
#                                                accounts on the machine are refused without it
#   --launcher-unit <unit>                       Linux: a systemd user service that starts agents
#                                                (repeatable). A drop-in puts ~/.agent-sign/bin
#                                                first on its PATH. The installer never restarts
#                                                it: it prints the command for you to run
# =============================================================================

# ─── Helpers that change nothing ────────────────────────────────────────────
# Defined first, so tests can load just these (AGENT_SIGN_INSTALL_FUNCTIONS_ONLY=1,
# with `source`) and check them without installing anything.

# A machine name, by the same rule as the service (check_machine_label in
# src/attribution.rs): 1 to 63 lowercase letters and digits, in words joined
# by single '-'. The rule is strict because the name goes into a trust line
# (*@<name>.agents.local), where OpenSSH's '*' would match across '@' and '.'.
is_valid_machine_label() {
    [ "${#1}" -ge 1 ] && [ "${#1}" -le 63 ] && [[ "$1" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]]
}

# A person's name for --person, by the same rule as the service
# (check_person_name in src/config.rs): 1 to 64 characters (counted as bytes
# outside a UTF-8 locale, so a long non-ASCII name may be refused here
# though the service would take it), at least one letter a-z or digit, and
# no quotes, backslashes or control characters, so it goes into config.toml
# as it is. The service also counts letters that Unicode NFKC turns into
# a-z (fullwidth letters); this check doesn't normalise, so it refuses
# such a name, which can still be written into config.toml by hand.
is_valid_person_name() {
    local name="$1"
    [ -n "${name//[[:space:]]/}" ] && [ "${#name}" -le 64 ] || return 1
    [[ "$name" =~ [A-Za-z0-9] ]] || return 1
    case "$name" in *'"'* | *'\'*) return 1 ;; esac
    ! [[ "$name" =~ [[:cntrl:]] ]]
}

# A systemd user service name given to --launcher-unit ("foo" means
# "foo.service"), printed in full, or nothing (status 1) if it isn't one: no
# '/', no leading '.' or '-', only the characters systemd allows in a name.
launcher_unit_name() {
    local unit="$1"
    case "$unit" in *.service) ;; *) unit="$unit.service" ;; esac
    [ "${#unit}" -le 255 ] && [[ "$unit" =~ ^[A-Za-z0-9_][A-Za-z0-9:_.@-]*\.service$ ]] || return 1
    printf '%s\n' "$unit"
}

# PATH with every directory inside ~/.agent-sign left out (the same rule as
# the service's is_agent_sign_bin_dir: any path component named .agent-sign).
path_without_agent_sign() {
    local dir out="" rest="$1"
    while [ -n "$rest" ]; do
        case "$rest" in
            *:*) dir="${rest%%:*}"; rest="${rest#*:}" ;;
            *) dir="$rest"; rest="" ;;
        esac
        [ -n "$dir" ] || continue
        case "/$dir/" in */.agent-sign/*) continue ;; esac
        out="${out:+$out:}$dir"
    done
    printf '%s\n' "$out"
}

# macOS: the real git for the service's AGENT_SIGN_REAL_GIT, or nothing. The
# first git on PATH outside ~/.agent-sign, unless that is Apple's shim
# (/usr/bin/git, which runs xcrun to find the real git on every call); then,
# and when there's no git on PATH, `xcrun --find git`. What's printed is
# an absolute path to an executable that answers `--version` as git does.
# GIT_SHIM can name another shim (tests do).
find_real_git() {
    local shim="${GIT_SHIM:-/usr/bin/git}" candidate="" dir rest
    rest="$(path_without_agent_sign "${PATH:-}")"
    while [ -n "$rest" ]; do
        case "$rest" in
            *:*) dir="${rest%%:*}"; rest="${rest#*:}" ;;
            *) dir="$rest"; rest="" ;;
        esac
        if [ -f "$dir/git" ] && [ -x "$dir/git" ]; then
            candidate="$dir/git"
            break
        fi
    done
    if [ -z "$candidate" ] || [ "$candidate" -ef "$shim" ]; then
        candidate="$(xcrun --find git 2>/dev/null || true)"
    fi
    [ -n "$candidate" ] || return 1
    is_real_git "$candidate" || return 1
    printf '%s\n' "$candidate"
}

# Whether $1 is a git the service can run: an absolute path on one line, to
# an executable file (not the shim) that says "git version ...".
is_real_git() {
    local git="$1" shim="${GIT_SHIM:-/usr/bin/git}"
    case "$git" in /*) ;; *) return 1 ;; esac
    case "$git" in *$'\n'*|*$'\r'*) return 1 ;; esac
    [ -f "$git" ] && [ -x "$git" ] || return 1
    [ "$git" -ef "$shim" ] && return 1
    case "$("$git" --version 2>/dev/null)" in "git version "*) return 0 ;; esac
    return 1
}

# The LaunchAgent: the template ($1) with AGENT_SIGN_REAL_GIT set to $2
# (escaped for XML), or with the EnvironmentVariables entry left out when $2
# is empty. Printed, for the installer to write.
render_launch_agent_plist() {
    local escaped
    escaped="$(printf '%s' "$2" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\&apos;/g")"
    REAL_GIT="$escaped" awk '
        BEGIN { git = ENVIRON["REAL_GIT"] }
        git == "" && /<key>EnvironmentVariables<\/key>/ { skipping = 1; next }
        skipping { if ($0 ~ /<\/dict>/) skipping = 0; next }
        {
            i = index($0, "@AGENT_SIGN_REAL_GIT@")
            if (i) $0 = substr($0, 1, i - 1) git substr($0, i + length("@AGENT_SIGN_REAL_GIT@"))
            print
        }
    ' "$1"
}

# Sourced with AGENT_SIGN_INSTALL_FUNCTIONS_ONLY=1 (by a test): stop here,
# quietly, with the helpers above defined. Executed with it, the variable is
# a mistake, and exiting 0 would let an automated deploy take a run that
# installed nothing for an install (security review fix round, 31 Oct 2026,
# L4): say so and fail.
if [ "${AGENT_SIGN_INSTALL_FUNCTIONS_ONLY:-}" = 1 ]; then
    if (return 0 2>/dev/null); then
        return 0
    fi
    echo "install.sh: AGENT_SIGN_INSTALL_FUNCTIONS_ONLY=1 is only for sourcing the installer's helper functions (in tests), so nothing was installed. Run the installer without it to install." >&2
    exit 2
fi

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
# The managed block in your allowed_signers file: `agent-sign trust install`
# rewrites the lines between these two, and nothing outside them.
TRUST_BLOCK_BEGIN="# agent-sign: agents' certificate authorities, managed; do not edit"
TRUST_BLOCK_END="# agent-sign: end of agents' certificate authorities"
# A bare trust line an earlier version added (before the managed block): one
# for plain *@agents.local, or for a machine's *@<machine>.agents.local (the
# [identity] machine setting), as an awk regular expression.
TRUST_LINE_PATTERN='^[*]@([a-z0-9-]+[.])?agents[.]local cert-authority,namespaces="git" '
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
MACHINE=""
PEOPLE=()
LAUNCHER_UNITS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --person)
            # Checked here, before anything changes.
            if [ $# -lt 2 ] || [ -z "$2" ]; then
                echo "--person needs a person's name, such as --person Taylor or --person \"Dana Example\". Nothing was changed." >&2
                exit 2
            fi
            if ! is_valid_person_name "$2"; then
                printf '%s\n' "--person \"$2\" isn't a person's name agent-sign can use: 1 to 64 characters, with at least one letter a-z or digit, and no quotes, backslashes or control characters. Nothing was changed." >&2
                exit 2
            fi
            SEEN=false
            for person in ${PEOPLE[@]+"${PEOPLE[@]}"}; do
                if [ "$person" = "$2" ]; then SEEN=true; fi
            done
            [ "$SEEN" = true ] || PEOPLE+=("$2")
            shift 2
            ;;
        --machine)
            # Checked here, before anything changes.
            if [ $# -lt 2 ] || [ -z "$2" ]; then
                echo "--machine needs this machine's name, such as --machine hetzner: 1 to 63 lowercase letters and digits, in words joined by single '-'. Nothing was changed." >&2
                exit 2
            fi
            if ! is_valid_machine_label "$2"; then
                printf '%s\n' "--machine \"$2\" isn't a valid machine name: use 1 to 63 lowercase letters and digits, in words joined by single '-' (such as \"hetzner\" or \"my-box-2\"). Nothing was changed." >&2
                exit 2
            fi
            MACHINE="$2"
            shift 2
            ;;
        --launcher-unit)
            if [ $# -lt 2 ] || [ -z "$2" ]; then
                echo "--launcher-unit needs the name of a systemd user service that starts agents, such as --launcher-unit my-agents.service. Nothing was changed." >&2
                exit 2
            fi
            if [ "$(uname -s)" != "Linux" ]; then
                printf '%s\n' "--launcher-unit $2: launcher units are systemd user services, so this is for Linux only. Nothing was changed." >&2
                exit 2
            fi
            if ! UNIT="$(launcher_unit_name "$2")"; then
                printf '%s\n' "--launcher-unit \"$2\" isn't a systemd user service name (such as my-agents.service). Nothing was changed." >&2
                exit 2
            fi
            case " ${LAUNCHER_UNITS[*]-} " in *" $UNIT "*) ;; *) LAUNCHER_UNITS+=("$UNIT") ;; esac
            shift 2
            ;;
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

# Linux: a non-interactive ssh session (as on a Raspberry Pi) has no
# XDG_RUNTIME_DIR, so `systemctl --user` can't find the user's service
# manager. Its usual place is /run/user/<uid>; set it before any systemctl.
if [ "$(uname -s)" = "Linux" ] && [ -z "${XDG_RUNTIME_DIR:-}" ] && [ -d "/run/user/$(id -u)" ] && [ -O "/run/user/$(id -u)" ]; then
    export XDG_RUNTIME_DIR="/run/user/$(id -u)"
fi

# The `machine` in config.toml's [identity] section, if there is one.
machine_in_config() {
    [ -f "$1" ] || return 0
    awk '
        /^[[:space:]]*\[/ { inside = ($0 ~ /^[[:space:]]*\[identity\][[:space:]]*(#.*)?$/); next }
        inside && /^[[:space:]]*machine[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*"/, ""); sub(/".*$/, ""); print; exit
        }
    ' "$1"
}

# Which agents' names the allowed_signers block trusts, in words.
if [ -n "$MACHINE" ]; then
    TRUSTED_NAMES="*@$MACHINE.agents.local (this machine's agents)"
elif [ -n "$(machine_in_config "$HOME/.agent-sign/config.toml")" ]; then
    TRUSTED_NAMES="*@$(machine_in_config "$HOME/.agent-sign/config.toml").agents.local (this machine's agents)"
else
    TRUSTED_NAMES="*@agents.local (or *@<machine>.agents.local once a machine name is set)"
fi

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
    echo "    for $TRUSTED_NAMES only (\`agent-sign trust install\` updates it; run it after the service restarts)"
    if [ -n "$MACHINE" ]; then
        echo "  • name this machine \"$MACHINE\" ([identity] machine in ~/.agent-sign/config.toml):"
        echo "    agents' names become <agent>.<session>@$MACHINE.agents.local"
    fi
    for person in ${PEOPLE[@]+"${PEOPLE[@]}"}; do
        echo "  • never certify an agent under the name \"$person\" or any word of it"
        echo "    ([identity] people in ~/.agent-sign/config.toml)"
    done
    for unit in ${LAUNCHER_UNITS[@]+"${LAUNCHER_UNITS[@]}"}; do
        echo "  • put ~/.agent-sign/bin first on PATH for $unit, the agents it starts, with a"
        echo "    drop-in (~/.config/systemd/user/$unit.d/agent-sign.conf); it takes effect when"
        echo "    you restart $unit, which the installer never does"
    done
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

# Sets [identity] machine in config.toml to $1 (already checked by
# is_valid_machine_label, so it needs no escaping): replaces the line in
# [identity] if there is one, adds it right under the [identity] header if
# not (keeping allowed_agents and anything else there), or adds the section
# at the end. A file that already says so is left exactly as it is.
set_machine() {
    MACHINE_LINE="machine = \"$1\"" awk '
        BEGIN { line = ENVIRON["MACHINE_LINE"]; done = 0 }
        /^[[:space:]]*\[/ {
            inside = ($0 ~ /^[[:space:]]*\[identity\][[:space:]]*(#.*)?$/)
            print
            if (inside && !done) { print line; done = 1 }
            next
        }
        inside && /^[[:space:]]*machine[[:space:]]*=/ { next }
        { print }
        END { if (!done) { print ""; print "[identity]"; print line } }
    ' "$CONFIG_FILE" > "$CONFIG_FILE.new"
    if cmp -s "$CONFIG_FILE.new" "$CONFIG_FILE"; then
        rm -f "$CONFIG_FILE.new"
        return 0
    fi
    cat "$CONFIG_FILE.new" > "$CONFIG_FILE"
    rm -f "$CONFIG_FILE.new"
}

# The `people = [...]` line in config.toml's [identity] section, if there is
# one.
people_line_in_config() {
    [ -f "$1" ] || return 0
    awk '
        /^[[:space:]]*\[/ { inside = ($0 ~ /^[[:space:]]*\[identity\][[:space:]]*(#.*)?$/); next }
        inside && /^[[:space:]]*people[[:space:]]*=/ { print; exit }
    ' "$1"
}

# Adds each name in PEOPLE (already checked by is_valid_person_name, so it
# needs no escaping) to [identity] people in config.toml, once: a name
# already listed is left as it is, and a file that already lists them all
# isn't touched. The list is kept on one line, people = ["A", "B"]; one
# written over several lines by hand is left alone, with a message, since
# rewriting it could lose what's in it.
set_people() {
    local line inner person
    line="$(people_line_in_config "$CONFIG_FILE")"
    inner=""
    if [ -n "$line" ]; then
        if ! [[ "$line" =~ ^[[:space:]]*people[[:space:]]*=[[:space:]]*\[(.*)\][[:space:]]*$ ]]; then
            err "[identity] people in $CONFIG_FILE isn't written on one line as people = [\"...\"] with nothing after it, so the installer left it alone: add ${PEOPLE[*]} to it yourself"
            exit 1
        fi
        inner="${BASH_REMATCH[1]}"
    fi
    local added=0
    for person in "${PEOPLE[@]}"; do
        case "$inner" in
            *"\"$person\""*)
                ok "\"$person\" is already in [identity] people: no agent is certified under that name"
                continue
                ;;
        esac
        ok "No agent will be certified under the name \"$person\" or any word of it ([identity] people)"
        if [ -n "${inner//[[:space:]]/}" ]; then
            inner="$inner, \"$person\""
        else
            inner="\"$person\""
        fi
        added=$((added + 1))
    done
    [ "$added" -gt 0 ] || return 0
    PEOPLE_LINE="people = [$inner]" awk '
        BEGIN { line = ENVIRON["PEOPLE_LINE"]; done = 0 }
        /^[[:space:]]*\[/ {
            inside = ($0 ~ /^[[:space:]]*\[identity\][[:space:]]*(#.*)?$/)
            print
            if (inside && !done) { print line; done = 1 }
            next
        }
        inside && /^[[:space:]]*people[[:space:]]*=/ { next }
        { print }
        END { if (!done) { print ""; print "[identity]"; print line } }
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
# Your name and email. No agent is ever certified under your name, any word
# of it, or your email's local part. Left unset, they're taken from git's
# user.name and user.email, which on a machine whose agents set user.name
# themselves name no person. Either way, the names listed as people in the
# identity section (install.sh --person), the people's accounts on this
# machine, and root, admin and administrator are never agents' names.
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

# This machine's name (--machine), in place before the service starts below,
# so no agent ever gets a name in the domain without it.
if [ -n "$MACHINE" ]; then
    PREVIOUS_MACHINE="$(machine_in_config "$CONFIG_FILE")"
    set_machine "$MACHINE"
    if [ "$PREVIOUS_MACHINE" = "$MACHINE" ]; then
        ok "This machine's name is already \"$MACHINE\": agents sign as <agent>.<session>@$MACHINE.agents.local"
    elif [ -n "$PREVIOUS_MACHINE" ]; then
        warn "This machine's name changed from \"$PREVIOUS_MACHINE\" to \"$MACHINE\": new agents sign as <agent>.<session>@$MACHINE.agents.local"
    else
        ok "This machine is named \"$MACHINE\": agents sign as <agent>.<session>@$MACHINE.agents.local"
    fi
fi

# People's names (--person), in place before the service starts below, so
# no agent ever gets one.
if [ ${#PEOPLE[@]} -gt 0 ]; then
    set_people
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
# authority `agent-sign trust install` recorded), between two marker lines;
# nothing outside the markers is changed. Making the block for the first
# time moves a bare trust line an earlier version added into it. A service's
# start never writes trust: once the service below is up, the installer runs
# `agent-sign trust install`, which adds its authority to this block.
TRUST_LINES=$("$INSTALL_DIR/agent-sign" trust-line 2>/dev/null || true)
write_trust_block() {
    local file="$1"
    [ -f "$file" ] || : > "$file"
    BEGIN="$TRUST_BLOCK_BEGIN" END="$TRUST_BLOCK_END" LINES="$TRUST_LINES" PATTERN="$TRUST_LINE_PATTERN" awk '
        BEGIN { b = ENVIRON["BEGIN"]; e = ENVIRON["END"]; lines = ENVIRON["LINES"]; pattern = ENVIRON["PATTERN"] }
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
                for (i = 1; i <= NR; i++) if (all[i] !~ pattern) print all[i]
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
ok "agent-sign's block in $ALLOWED_SIGNERS_FILE trusts agents' signatures for $TRUSTED_NAMES only; \`agent-sign trust install\` keeps it current"

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

# Linux: the background launchers (--launcher-unit), the systemd user
# services that start agents without a shell, so the shell profiles below
# never reach them. Each gets a drop-in,
# ~/.config/systemd/user/<unit>.d/agent-sign.conf, that puts
# ~/.agent-sign/bin first on its PATH, followed by the user service
# manager's own PATH (what the unit has now, unless it sets PATH itself).
# The first line marks the file as agent-sign's, which is how uninstall.sh
# knows to remove it, and a file of that name without the mark is left
# alone. The installer never restarts, stops or starts a launcher: that
# would end the agents it is running. The drop-in takes effect at the
# launcher's next restart, and the command is printed for whoever decides
# when.
LAUNCHER_DROP_IN_MARK="# agent-sign: written by agent-sign's installer; scripts/uninstall.sh removes it. Don't edit."
LAUNCHER_FAILURES=0
write_launcher_drop_ins() {
    [ ${#LAUNCHER_UNITS[@]} -gt 0 ] || return 0
    local manager_path path_value unit dir file own_path env_file file_path
    manager_path="$(systemctl --user show-environment 2>/dev/null | sed -n 's/^PATH=//p' | head -1 || true)"
    manager_path="$(path_without_agent_sign "$manager_path")"
    if [ -z "$manager_path" ]; then
        for unit in "${LAUNCHER_UNITS[@]}"; do
            err "Couldn't read the user service manager's PATH (systemctl --user show-environment), so $unit got no drop-in"
            LAUNCHER_FAILURES=$((LAUNCHER_FAILURES + 1))
        done
        return 0
    fi
    path_value="$INSTALL_DIR:$manager_path"
    # Written as is in the unit file, where '%' would be a specifier and
    # spaces or quotes would need quoting: refuse anything else.
    if ! [[ "$path_value" =~ ^[A-Za-z0-9/._:+@,=-]+$ ]]; then
        for unit in "${LAUNCHER_UNITS[@]}"; do
            err "The PATH for $unit ($path_value) has characters a drop-in can't hold as is, so $unit got no drop-in"
            LAUNCHER_FAILURES=$((LAUNCHER_FAILURES + 1))
        done
        return 0
    fi
    for unit in "${LAUNCHER_UNITS[@]}"; do
        dir="$HOME/.config/systemd/user/$unit.d"
        file="$dir/agent-sign.conf"
        if [ -e "$file" ] && [ "$(head -1 "$file")" != "$LAUNCHER_DROP_IN_MARK" ]; then
            err "$file exists and isn't agent-sign's (its first line isn't agent-sign's mark): left as it is, so $unit got no drop-in"
            LAUNCHER_FAILURES=$((LAUNCHER_FAILURES + 1))
            continue
        fi
        # A unit that sets its own PATH loses it to the drop-in: say so
        # before anyone restarts it.
        own_path="$(systemctl --user show -p Environment --value "$unit" 2>/dev/null | tr ' ' '\n' | sed -n 's/^PATH=//p' | grep -vxF "$path_value" | head -1 || true)"
        if [ -n "$own_path" ]; then
            warn "$unit sets its own PATH ($own_path); the drop-in replaces it with $path_value. Check that before restarting $unit."
        fi
        # A PATH set in one of the unit's environment files (EnvironmentFile=)
        # is worse: systemd lets those files override every Environment=
        # line, the drop-in's included, so the agents it starts wouldn't get
        # agent-sign's git at all (security review fix round, 31 Oct 2026,
        # L5). Only files this account can read are looked at.
        while IFS= read -r env_file; do
            env_file="${env_file% (ignore_errors=*}"
            env_file="${env_file#-}"
            [ -n "$env_file" ] && [ -r "$env_file" ] || continue
            file_path="$(sed -n -E 's/^[[:space:]]*(export[[:space:]]+)?PATH[[:space:]]*=[[:space:]]*//p' "$env_file" | tail -1 | sed -E "s/^[\"']//; s/[\"'][[:space:]]*$//" || true)"
            if [ -n "$file_path" ]; then
                warn "$unit sets PATH in its environment file $env_file ($file_path), and systemd lets that file override the drop-in's Environment=PATH, so the agents $unit starts won't get agent-sign's git. Put $INSTALL_DIR first on PATH in $env_file (or take PATH out of it) before restarting $unit."
            fi
        done < <(systemctl --user show -p EnvironmentFiles --value "$unit" 2>/dev/null || true)
        mkdir -p "$dir"
        {
            echo "$LAUNCHER_DROP_IN_MARK"
            echo "# Puts agent-sign's git first on PATH for the agents $unit starts, so"
            echo "# their commits are signed as themselves. Takes effect when $unit restarts."
            echo "[Service]"
            echo "Environment=PATH=$path_value"
        } > "$file.new"
        if cmp -s "$file.new" "$file"; then
            rm -f "$file.new"
            ok "$unit already has agent-sign's drop-in ($file)"
        else
            mv -f "$file.new" "$file"
            ok "$unit: drop-in written ($file), putting $INSTALL_DIR first on its PATH"
        fi
        LAUNCHERS_TO_RESTART+=("$unit")
    done
}
LAUNCHERS_TO_RESTART=()

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
        # The real git for the service (see find_real_git and the comment in
        # agent-signd.plist): under launchd, git would be Apple's slow shim.
        SERVICE_GIT="$(find_real_git || true)"
        if [ -n "$SERVICE_GIT" ]; then
            ok "The service runs git as $SERVICE_GIT (AGENT_SIGN_REAL_GIT)"
        else
            warn "Found no git outside ~/.agent-sign and Apple's shim: the service looks for git itself, which under launchd is the slower /usr/bin/git"
        fi
        render_launch_agent_plist "$PLIST_SRC" "$SERVICE_GIT" > "$PLIST_DST.new"
        mv -f "$PLIST_DST.new" "$PLIST_DST"
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
        write_launcher_drop_ins
        systemctl --user daemon-reload
        systemctl --user enable --now agent-signd
        ok "Service installed and started: systemd user service agent-signd"
        info "It runs while you're logged in. On a machine you log out of (a server),"
        info "keep it running with: loginctl enable-linger \"\$USER\""
    else
        start_by_hand
        for unit in ${LAUNCHER_UNITS[@]+"${LAUNCHER_UNITS[@]}"}; do
            err "No systemd here (systemctl not found), so $unit got no drop-in"
            LAUNCHER_FAILURES=$((LAUNCHER_FAILURES + 1))
        done
    fi
else
    start_by_hand
fi

# Trust the service's authority: wait for the service to answer (a few
# seconds at most), then `agent-sign trust install`, the only thing that
# writes trust. A start never does (P3, docs/caller-identity.md), so the
# installer's own flow ends with the new service trusted, and nothing else
# needs doing on a laptop.
TRUST_INSTALLED=false
for _ in $(seq 1 25); do
    if "$INSTALL_DIR/agent-signd" status 2>/dev/null | grep 'active' >/dev/null; then
        break
    fi
    sleep 0.2
done
if "$INSTALL_DIR/agent-sign" trust install; then
    TRUST_INSTALLED=true
    ok "The service's certificate authority is trusted for $TRUSTED_NAMES in $ALLOWED_SIGNERS_FILE"
else
    warn "The service's certificate authority isn't trusted yet: once it's running, run: agent-sign trust install"
fi

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
verify "Service's authority trusted (agent-sign trust install)" "[ '$TRUST_INSTALLED' = true ] && [ -s '$CAS_HISTORY_FILE' ]"
verify "Config file exists"         "[ -f '$CONFIG_FILE' ]"
verify "Your own signing goes through agent-sign" "[ \"\$(git config --global --includes --get gpg.ssh.program)\" = '$AGENT_SSH_SIGN' ]"
verify "Daemon socket exists"       "[ -S '$CONFIG_DIR/daemon.sock' ]"
# grep without -q reads all of the output: with -q it stops at the first match,
# agent-signd's next line then hits a closed pipe, and under pipefail the check
# failed at random.
verify "Daemon responds to ping"    "'$INSTALL_DIR/agent-signd' status 2>&1 | grep 'active' >/dev/null"
verify "Shell PATH configured"      "grep -q '# >>> agent-sign >>>' ~/.zshrc 2>/dev/null || grep -q '# >>> agent-sign >>>' ~/.bashrc 2>/dev/null || grep -q '# >>> agent-sign >>>' ~/.zprofile 2>/dev/null || grep -q '# >>> agent-sign >>>' ~/.bash_profile 2>/dev/null"
if [ ${#LAUNCHER_UNITS[@]} -gt 0 ]; then
    verify "Every launcher unit has agent-sign's drop-in" "[ '$LAUNCHER_FAILURES' -eq 0 ]"
fi

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
if [ ${#LAUNCHERS_TO_RESTART[@]} -gt 0 ]; then
    echo -e "${BOLD}4. Your launchers${NC} use agent-sign's git from their next restart. The"
    echo -e "   installer didn't restart them, since that ends the agents they're running."
    echo -e "   When no agent is running, restart each one:"
    for unit in "${LAUNCHERS_TO_RESTART[@]}"; do
        echo "     systemctl --user restart $unit"
    done
    echo ""
fi
echo -e "   To uninstall: ${CYAN}./scripts/uninstall.sh${NC}"
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║              Installation Complete ✓             ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""
