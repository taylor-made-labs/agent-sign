#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Agent-Sign Interactive Sandbox Demo
# Demonstrates 1-time session leasing, instant signing, and 100% human isolation
# in an ephemeral repository without touching your personal work.
# =============================================================================

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'

SANDBOX_DIR=$(mktemp -d -t agent-sign-sandbox-XXXXXX)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Prefer installed release or target/release, fallback to debug
if [ -x "$HOME/.agent-sign/bin/agent-git" ]; then
    BIN_DIR="$HOME/.agent-sign/bin"
elif [ -x "$REPO_ROOT/target/release/agent-git" ]; then
    BIN_DIR="$REPO_ROOT/target/release"
else
    BIN_DIR="$REPO_ROOT/target/debug"
fi

cleanup() {
    rm -rf "$SANDBOX_DIR"
    echo -e "\n${GREEN}✓ Sandbox cleaned up cleanly (${SANDBOX_DIR})${NC}"
}
trap cleanup EXIT

echo -e "\n${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║      Agent-Sign 2-Minute Interactive Sandbox     ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}\n"

echo -e "${CYAN}1. Initializing isolated sandbox repo at:${NC} $SANDBOX_DIR"
cd "$SANDBOX_DIR"
git init -q -b main

# Configure local git author in sandbox
git config user.name "Sandbox Tester"
git config user.email "tester@example.com"

echo "Hello from initial human commit" > README.md
git add README.md
git commit -m "chore: initial commit" --quiet

git checkout -q -b feat/ai-task

echo -e "\n${CYAN}2. Simulating Agent Step 1 (Triggering 1-time session lease)...${NC}"
echo "function add(a, b) { return a + b; }" > math.js
git add math.js

# Run commit via agent-git with auto-approve enabled for seamless demo
AGENT_SIGN_FORCE=1 AGENT_SIGN_AUTO_APPROVE=1 "$BIN_DIR/agent-git" commit -m "feat: add math helper"

echo -e "\n${GREEN}✓ First agent commit signed!${NC}"
echo -e "  Signature verification:"
git log -1 --show-signature | grep -E "Good|Author|Date" || true

echo -e "\n${CYAN}3. Simulating Agent Step 2 (Headless subsequent commit within lease)...${NC}"
echo "module.exports = { add };" >> math.js
git add math.js

START_TIME=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))')
AGENT_SIGN_FORCE=1 "$BIN_DIR/agent-git" commit -m "feat: export add function"
END_TIME=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))')

ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
echo -e "\n${GREEN}✓ Second commit signed headlessly in ${ELAPSED_MS}ms! Zero prompt interruptions.${NC}"

echo -e "\n${CYAN}4. Testing Enterprise Guardrails (Attempting commit touching .github/workflows)...${NC}"
mkdir -p .github/workflows
echo "name: CI" > .github/workflows/deploy.yml
git add .github/workflows/deploy.yml

set +e
GUARD_OUTPUT=$(AGENT_SIGN_FORCE=1 "$BIN_DIR/agent-git" commit -m "ci: touch workflow" 2>&1)
set -e

if echo "$GUARD_OUTPUT" | grep -q "Security Policy Violation"; then
    echo -e "${GREEN}✓ Guardrail active! Agent blocked from modifying protected CI workflows.${NC}"
else
    echo -e "${YELLOW}⚠ Guardrail check skipped or not triggered:${NC}"
    echo "$GUARD_OUTPUT"
fi

echo -e "\n${BOLD}Demo completed successfully!${NC}"
