#!/usr/bin/env bash
# Install test for Linux (release checks R5 and F1, in part): runs
# scripts/install.sh and scripts/uninstall.sh in throwaway homes and checks
# what they leave behind, for four cases:
#
#   1. a fresh install, ending in a verified agent commit
#   2. installing again over an install (an upgrade): the same key, the lease
#      kept (no new approval), one service, one PATH block
#   3. ~/.agent-sign linked to a folder kept elsewhere: used in place, not
#      moved, and left in place by the uninstaller
#   4. uninstalling: nothing left but what the docs say is left
#
# and first, that answering no at the installer's first question changes nothing.
#
# It never touches the real home or the real user services: HOME is a
# throwaway directory, git's global config is that home's, and `systemctl`
# is a stand-in on PATH that logs each call and, for `enable --now` and
# `restart`, runs the unit's program in the background the way systemd
# would. Run it from a source checkout with target/release built:
#
#   cargo build --release --locked && scripts/release/install-test.sh
#
# Prints PASS or FAIL for each check, and exits non-zero if any failed.

set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ -x "$SRC/target/release/agent-signd" ] || { echo "Build first: cargo build --release --locked" >&2; exit 2; }
[ "$(uname -s)" = "Linux" ] || { echo "This test is for Linux (it stands in for systemd)." >&2; exit 2; }

WORK="$(mktemp -d)"
# Stop every service this test started; keep the homes (and their logs) only
# if something failed.
cleanup() {
    pkill -u "$(id -u)" -f "^$WORK/" 2>/dev/null
    if [ "${FAILS:-1}" -eq 0 ]; then rm -rf "$WORK"; else echo "Homes and logs kept in $WORK"; fi
}
trap cleanup EXIT
FAILS=0
check() { # check "what" command...
    local what="$1"; shift
    if "$@" >/dev/null 2>&1; then echo "PASS  $what"; else echo "FAIL  $what"; FAILS=$((FAILS + 1)); fi
}

# A throwaway home with a git identity and a stand-in systemctl.
new_home() {
    local home="$WORK/$1"
    mkdir -p "$home/fakebin" "$home/.config"
    touch "$home/.bashrc"
    cat > "$home/fakebin/systemctl" <<'EOF'
#!/usr/bin/env bash
# Stand-in for `systemctl --user`: logs, and runs agent-signd for
# enable --now / start / restart, stops it for stop.
echo "systemctl $*" >> "$HOME/systemctl.log"
args=" $* "
stop() { pkill -u "$(id -u)" -f "^$HOME/.agent-sign/bin/agent-signd" 2>/dev/null; sleep 0.3; }
case "$args" in
  *" stop "*) stop ;;
  *" restart "*|*" start "*|*"--now"*)
    case "$args" in *agent-signd*) stop; nohup "$HOME/.agent-sign/bin/agent-signd" >>"$HOME/service.log" 2>&1 & ;; esac ;;
esac
exit 0
EOF
    chmod +x "$home/fakebin/systemctl"
    HOME="$home" GIT_CONFIG_NOSYSTEM=1 git config --global user.name "Person"
    HOME="$home" GIT_CONFIG_NOSYSTEM=1 git config --global user.email "person@example.com"
    echo "$home"
}

# Runs a command as that home's user would: its HOME, PATH with the
# stand-ins, no display (so no dialogs), no terminal.
in_home() {
    local home="$1"; shift
    env -i HOME="$home" USER="$(id -un)" LOGNAME="$(id -un)" SHELL=/bin/bash \
        PATH="$home/.agent-sign/bin:$home/fakebin:/usr/local/bin:/usr/bin:/bin" \
        GIT_CONFIG_NOSYSTEM=1 "$@" </dev/null
}

install() { (cd "$SRC" && in_home "$1" bash scripts/install.sh) >"$1/install.log" 2>&1; }
uninstall() { (cd "$SRC" && in_home "$1" bash scripts/uninstall.sh) >"$1/uninstall.log" 2>&1; }

wait_for_service() {
    local home="$1" i
    for i in $(seq 1 50); do
        in_home "$home" "$home/.agent-sign/bin/agent-sign" leases >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    return 1
}

# Turns on auto_approve (no screen here to ask on) and restarts the service.
allow_unattended() {
    local home="$1"
    sed -i 's/^auto_approve = false/auto_approve = true/' "$home/.agent-sign/config.toml"
    in_home "$home" systemctl --user restart agent-signd
    wait_for_service "$home"
}

# Makes a repository with a first commit by the person, on a work branch.
new_repo() {
    local home="$1" repo="$1/$2"
    mkdir -p "$repo"
    (cd "$repo" && in_home "$home" /usr/bin/git init -q -b main \
        && in_home "$home" /usr/bin/git commit -q --allow-empty -m first \
        && in_home "$home" /usr/bin/git checkout -q -b feat/x)
    echo "$repo"
}

# An agent commit through the installed `git` on PATH.
agent_commit() {
    local home="$1" repo="$2" file="$3"
    (cd "$repo" && echo "$file" > "$file" && in_home "$home" git add "$file" \
        && in_home "$home" git commit -q -m "add $file")
}

verified() {
    local home="$1" repo="$2"
    [ "$(cd "$repo" && in_home "$home" /usr/bin/git log -1 --format=%G?)" = "G" ]
}

echo "== 0. Saying no at the first question changes nothing"
H0="$(new_home declined)"
(cd "$SRC" && printf 'n\n' | env -i HOME="$H0" PATH="$H0/fakebin:/usr/bin:/bin" TERM=dumb \
    script -qec "bash scripts/install.sh" /dev/null) >"$H0/install.log" 2>&1
check "it showed what it would change"        grep -q 'This will:' "$H0/install.log"
check "no ~/.agent-sign"                   test ! -e "$H0/.agent-sign"
check "no PATH block"                         bash -c "! grep -q agent-sign '$H0/.bashrc'"

echo "== 1. Fresh install"
H1="$(new_home fresh)"
check "installer finishes"                    install "$H1"
check "programs in ~/.agent-sign/bin"      test -x "$H1/.agent-sign/bin/agent-signd" -a -x "$H1/.agent-sign/bin/git"
check "PATH block in .bashrc"                 grep -q '# >>> agent-sign >>>' "$H1/.bashrc"
check "systemd unit agent-signd installed" test -f "$H1/.config/systemd/user/agent-signd.service"
check "service answering"                     wait_for_service "$H1"
check "no GitHub key added without asking"    bash -c "! grep -q 'Added the agent' '$H1/install.log'"
allow_unattended "$H1"
R1="$(new_repo "$H1" work)"
check "agent commit succeeds"                 agent_commit "$H1" "$R1" a.txt
check "agent commit verifies (G)"             verified "$H1" "$R1"

echo "== 2. Installing again over an install (an upgrade)"
H2="$(new_home upgrade)"
install "$H2"; allow_unattended "$H2"
R2="$(new_repo "$H2" work)"
agent_commit "$H2" "$R2" a.txt
KEY_BEFORE="$(cat "$H2/.agent-sign/keys/agent_ed25519.pub")"
# Auto-approve off, so a new lease can't be granted: the old one must carry over.
sed -i 's/^auto_approve = true/auto_approve = false/' "$H2/.agent-sign/config.toml"
check "installer finishes"                    install "$H2"
check "same agent key"                        test "$KEY_BEFORE" = "$(cat "$H2/.agent-sign/keys/agent_ed25519.pub")"
check "config kept (auto_approve still off)"  grep -q '^auto_approve = false' "$H2/.agent-sign/config.toml"
check "one unit"                              test "$(ls "$H2/.config/systemd/user" | grep -c agent)" = 1
check "one PATH block"                        test "$(grep -c '# >>> agent-sign >>>' "$H2/.bashrc")" = 1
check "service answering"                     wait_for_service "$H2"
check "lease carried over: commit, no asking" agent_commit "$H2" "$R2" b.txt
check "commit verifies (G)"                   verified "$H2" "$R2"

echo "== 3. ~/.agent-sign linked to a folder kept elsewhere"
H3="$(new_home linked)"
install "$H3"
in_home "$H3" systemctl --user stop agent-signd
mkdir -p "$H3/elsewhere"
mv "$H3/.agent-sign" "$H3/elsewhere/state"
ln -s "$H3/elsewhere/state" "$H3/.agent-sign"
check "installer finishes"                    install "$H3"
check "~/.agent-sign still links to it"       test "$(readlink "$H3/.agent-sign")" = "$H3/elsewhere/state"
check "the folder wasn't moved"               test -d "$H3/elsewhere/state/keys"
check "uninstaller finishes"                  uninstall "$H3"
check "link removed"                          test ! -e "$H3/.agent-sign" -a ! -L "$H3/.agent-sign"
check "the folder elsewhere is left"          test -f "$H3/elsewhere/state/keys/agent_ed25519"

echo "== 4. Uninstall"
check "uninstaller finishes"                  uninstall "$H1"
check "~/.agent-sign removed"              test ! -e "$H1/.agent-sign"
check "PATH block removed"                    bash -c "! grep -q 'agent-sign' '$H1/.bashrc'"
check "unit removed"                          test ! -e "$H1/.config/systemd/user/agent-signd.service"
check "service stopped"                       bash -c "! pgrep -u $(id -u) -f '^$H1/.agent-sign/bin/agent-signd'"

echo
if [ "$FAILS" -eq 0 ]; then echo "All checks passed."; else echo "$FAILS check(s) failed. Logs are in each home's install.log."; fi
exit "$FAILS"
