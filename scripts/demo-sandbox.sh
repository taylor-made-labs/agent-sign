#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# agent-sign sandbox demo
#
# In a throwaway folder: an agent commit, signed as the agent's own identity
# ("Sandbox Demo <sandbox-demo.nosession@agents.local>"), a second one under
# the same lease, a check of both signatures, and a commit refused by a local
# rule. Run it after building or installing; it works on macOS and Linux.
#
# The demo runs a short-lived agent-sign service of its own, with its own
# settings, in the throwaway folder (its own HOME, socket and git config), and
# stops it at the end. Your installed service, settings, leases and
# allowed-signers file are never touched, and nothing asks you anything.
#
# Why its own service: "Sandbox Demo" isn't one of the agent names agent-sign
# allows by default, so the demo's own config lists it under
# [identity] allowed_agents. Changing your own config for a demo would mean
# restarting your service; this way your setup stays as it is.
# =============================================================================

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# The agent-sign programs: the installed ones, else target/release, else
# target/debug. All four must sit together: the wrapper hands git the signing
# program next to it.
if [ -x "$HOME/.agent-sign/bin/agent-git" ]; then
    BIN_DIR="$HOME/.agent-sign/bin"
elif [ -x "$REPO_ROOT/target/release/agent-git" ]; then
    BIN_DIR="$REPO_ROOT/target/release"
else
    BIN_DIR="$REPO_ROOT/target/debug"
fi
WRAPPER="$BIN_DIR/agent-git"
AGENT_SIGND="$BIN_DIR/agent-signd"
DEMO_SIGN_CLI="$BIN_DIR/agent-sign"
for program in "$WRAPPER" "$AGENT_SIGND" "$DEMO_SIGN_CLI" "$BIN_DIR/agent-ssh-sign"; do
    if [ ! -x "$program" ]; then
        echo -e "${RED}✗ $program not found: build agent-sign (cargo build --release --locked) or install it first.${NC}" >&2
        exit 1
    fi
done

# Your real git (not agent-sign's wrapper), for everything but the agent's
# commits.
REAL_GIT="$(PATH="$(printf '%s' "$PATH" | tr ':' '\n' | grep -v -e '/\.agent-sign/' | paste -sd: -)" command -v git || true)"
if [ -z "$REAL_GIT" ]; then
    echo -e "${RED}✗ git not found on PATH.${NC}" >&2
    exit 1
fi

DEMO_DIR=$(mktemp -d -t agent-sign-demo-XXXXXX)
DEMO_HOME="$DEMO_DIR/home"
SANDBOX_DIR="$DEMO_DIR/repo"
# Kept short: a Unix socket's path is limited to about 100 characters, and
# macOS's temporary folders have long names.
DEMO_SOCKET="$DEMO_DIR/demo.sock"
SERVICE_LOG="$DEMO_DIR/service.log"
SERVICE_PID=""

cleanup() {
    if [ -n "$SERVICE_PID" ]; then
        kill "$SERVICE_PID" 2>/dev/null || true
        wait "$SERVICE_PID" 2>/dev/null || true
    fi
    rm -rf "$DEMO_DIR"
    echo -e "\n${GREEN}✓ Demo service stopped and its folder removed (${DEMO_DIR})${NC}"
}
trap cleanup EXIT

# Milliseconds since the epoch. GNU date has %N; macOS's date doesn't (it
# prints a literal N), so fall back to python3 there.
now_ms() {
    local ns
    ns=$(date +%s%N 2>/dev/null || true)
    case "$ns" in
        ''|*[!0-9]*) python3 -c 'import time; print(int(time.time() * 1000))' ;;
        *) echo $((ns / 1000000)) ;;
    esac
}

echo -e "\n${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║              agent-sign Sandbox Demo             ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}\n"

echo -e "${CYAN}1. Starting a demo agent-sign service in:${NC} $DEMO_DIR"

# Only the demo's own settings: no AGENT_SIGN_* variable from your shell (a
# socket, a signing program, a session) reaches the demo.
for var in $(compgen -v AGENT_SIGN_); do
    unset "$var"
done

# The demo's own home: agent-sign's state, its config and git's global
# config live here, so the demo service never reads or writes yours.
mkdir -p "$DEMO_HOME/.agent-sign"
chmod 700 "$DEMO_HOME/.agent-sign"
cat > "$DEMO_HOME/.agent-sign/config.toml" <<'EOF'
# The demo service's own settings (scripts/demo-sandbox.sh).
# "Sandbox Demo" isn't an agent name agent-sign allows by default, so it is
# listed here, as its slug.
[identity]
allowed_agents = ["sandbox-demo"]
EOF
export HOME="$DEMO_HOME"
export GIT_CONFIG_GLOBAL="$DEMO_HOME/.gitconfig"
export GIT_CONFIG_NOSYSTEM=1
export AGENT_SIGN_SOCKET="$DEMO_SOCKET"
: > "$GIT_CONFIG_GLOBAL"

(cd "$DEMO_DIR" && exec "$AGENT_SIGND" --socket "$DEMO_SOCKET" </dev/null >/dev/null 2>"$SERVICE_LOG") &
SERVICE_PID=$!

waited=0
while [ ! -S "$DEMO_SOCKET" ]; do
    if ! kill -0 "$SERVICE_PID" 2>/dev/null || [ "$waited" -ge 150 ]; then
        echo -e "${RED}✗ The demo service didn't start. Its log:${NC}" >&2
        cat "$SERVICE_LOG" >&2 || true
        exit 1
    fi
    sleep 0.1
    waited=$((waited + 1))
done

# Trust the demo service's agents' certificate authority, for this demo's
# git only, so the signatures below can be checked.
"$DEMO_SIGN_CLI" trust-line > "$DEMO_HOME/allowed_signers"
"$REAL_GIT" config --global gpg.ssh.allowedSignersFile "$DEMO_HOME/allowed_signers"
echo -e "${GREEN}✓ Demo service running; it allows the agent name \"Sandbox Demo\".${NC}"

echo -e "\n${CYAN}2. A throwaway repository, with a first commit made as a person would:${NC} $SANDBOX_DIR"
mkdir -p "$SANDBOX_DIR"
cd "$SANDBOX_DIR"
# The setup commit is made with the real git, unsigned: agents never commit
# on main.
"$REAL_GIT" init -q -b main
"$REAL_GIT" config user.name "Sandbox Tester"
"$REAL_GIT" config user.email "tester@example.com"
echo "Hello from the setup commit" > README.md
"$REAL_GIT" add README.md
"$REAL_GIT" -c commit.gpgsign=false commit -m "chore: initial commit" --quiet
"$REAL_GIT" checkout -q -b feat/ai-task

echo -e "\n${CYAN}3. An agent's first commit (signed as the agent; nothing asks you)...${NC}"
echo "function add(a, b) { return a + b; }" > math.js
"$REAL_GIT" add math.js

# AGENT_SIGN_FORCE makes the wrapper treat this commit as an agent's even
# though it runs in your terminal, and AGENT_SIGN_AGENT_NAME says which agent:
# a commit nothing names is left to git, unsigned (it could be your own
# editor's).
export AGENT_SIGN_AGENT_NAME="Sandbox Demo"
AGENT_SIGN_FORCE=1 "$WRAPPER" commit -m "feat: add math helper"

echo -e "\n${GREEN}✓ First agent commit signed!${NC}"
echo -e "  Author and committer, then the signature check:"
"$REAL_GIT" log -1 --format='  %an <%ae> | %cn <%ce>'
"$REAL_GIT" log -1 --show-signature 2>&1 | grep -E "Good|No principal|Author|Date" || true

echo -e "\n${CYAN}4. A second agent commit, under the same lease...${NC}"
echo "module.exports = { add };" >> math.js
"$REAL_GIT" add math.js

START_MS=$(now_ms)
AGENT_SIGN_FORCE=1 "$WRAPPER" commit -m "feat: export add function"
END_MS=$(now_ms)
echo -e "\n${GREEN}✓ Second commit signed in $((END_MS - START_MS))ms.${NC}"
"$REAL_GIT" log -1 --show-signature 2>&1 | grep -E "Good|No principal" || true

echo -e "\n${CYAN}5. An agent commit that touches .github/workflows (refused by a local rule)...${NC}"
mkdir -p .github/workflows
echo "name: CI" > .github/workflows/deploy.yml
"$REAL_GIT" add .github/workflows/deploy.yml

set +e
GUARD_OUTPUT=$(AGENT_SIGN_FORCE=1 "$WRAPPER" commit -m "ci: touch workflow" 2>&1)
set -e

if echo "$GUARD_OUTPUT" | grep -q "Security Policy Violation"; then
    echo -e "${GREEN}✓ Refused: agent commits may not change CI workflows (forbidden_paths).${NC}"
else
    echo -e "${YELLOW}⚠ Guardrail check skipped or not triggered:${NC}"
    echo "$GUARD_OUTPUT"
fi

echo -e "\n${BOLD}Demo complete.${NC}"
