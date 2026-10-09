#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# agent-sign sandbox demo
# In a throwaway repository: an agent commit that asks for a lease once, a
# second agent commit under that lease, and a commit refused by a local rule.
# Run it after installing. The lease it asks for is revoked at the end.
#
# The service decides whether to ask you: with auto_approve off (the default)
# you'll see the lease dialog once. On a machine with no screen, see
# "Headless machines" in docs/INSTALL.md.
# =============================================================================

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'

SANDBOX_DIR=$(mktemp -d -t agent-sign-sandbox-XXXXXX)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Prefer the installed wrapper (agent-git, or agent-git on an older install),
# then target/release, then target/debug.
if [ -x "$HOME/.agent-sign/bin/agent-git" ]; then
    WRAPPER="$HOME/.agent-sign/bin/agent-git"
elif [ -x "$HOME/.agent-sign/bin/agent-git" ]; then
    WRAPPER="$HOME/.agent-sign/bin/agent-git"
elif [ -x "$REPO_ROOT/target/release/agent-git" ]; then
    WRAPPER="$REPO_ROOT/target/release/agent-git"
else
    WRAPPER="$REPO_ROOT/target/debug/agent-git"
fi

AGENT_SIGN_CLI="$(dirname "$WRAPPER")/agent-sign"

cleanup() {
    # Revoke the sandbox's lease, so it doesn't outlive the repository.
    if [ -x "$AGENT_SIGN_CLI" ] && [ -d "$SANDBOX_DIR/.git" ]; then
        "$AGENT_SIGN_CLI" revoke "$SANDBOX_DIR" >/dev/null 2>&1 || true
    fi
    rm -rf "$SANDBOX_DIR"
    echo -e "\n${GREEN}✓ Sandbox removed and its lease revoked (${SANDBOX_DIR})${NC}"
}
trap cleanup EXIT

echo -e "\n${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║                agent-sign Sandbox Demo                 ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}\n"

echo -e "${CYAN}1. Initializing isolated sandbox repo at:${NC} $SANDBOX_DIR"
cd "$SANDBOX_DIR"

# The setup commit is made with your real git (not agent-sign's wrapper) and
# unsigned, so it needs no lease on main and doesn't ask for your own key.
SETUP_GIT="$(PATH="$(printf '%s' "$PATH" | tr ':' '\n' | grep -v -e '/\.agent-sign/' -e '/\.agent-sign/' | paste -sd: -)" command -v git)"
"$SETUP_GIT" init -q -b main
"$SETUP_GIT" config user.name "Sandbox Tester"
"$SETUP_GIT" config user.email "tester@example.com"

echo "Hello from the setup commit" > README.md
"$SETUP_GIT" add README.md
"$SETUP_GIT" -c commit.gpgsign=false commit -m "chore: initial commit" --quiet

git checkout -q -b feat/ai-task

echo -e "\n${CYAN}2. An agent's first commit (asks for a lease once)...${NC}"
echo "function add(a, b) { return a + b; }" > math.js
git add math.js

# AGENT_SIGN_FORCE makes the wrapper treat this commit as an agent's even though it
# runs in your terminal. Whether you're asked is up to the service.
AGENT_SIGN_FORCE=1 "$WRAPPER" commit -m "feat: add math helper"

echo -e "\n${GREEN}✓ First agent commit signed!${NC}"
echo -e "  Signature verification:"
git log -1 --show-signature | grep -E "Good|Author|Date" || true

echo -e "\n${CYAN}3. A second agent commit, under the same lease (no dialog)...${NC}"
echo "module.exports = { add };" >> math.js
git add math.js

START_TIME=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))')
AGENT_SIGN_FORCE=1 "$WRAPPER" commit -m "feat: export add function"
END_TIME=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))')

ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
echo -e "\n${GREEN}✓ Second commit signed in ${ELAPSED_MS}ms, without asking again.${NC}"

echo -e "\n${CYAN}4. An agent commit that touches .github/workflows (refused by a local rule)...${NC}"
mkdir -p .github/workflows
echo "name: CI" > .github/workflows/deploy.yml
git add .github/workflows/deploy.yml

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
