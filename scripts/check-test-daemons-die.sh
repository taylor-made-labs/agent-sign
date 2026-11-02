#!/usr/bin/env bash
# =============================================================================
# check-test-daemons-die.sh: when a test run is killed, its agent-signd
# processes must die with it.
#
# Why: the tests start a real agent-signd for most checks and stop it when the
# test ends. A test run that is killed (a timeout, an agent's session ending,
# SIGKILL) never runs that cleanup, and the daemons were left running, each
# holding a socket and a folder in the temporary directory. They piled up on
# the shared server (found 31 Oct). The fix is in the tests' own spawn code
# only: the kernel is asked (PR_SET_PDEATHSIG on Linux) to kill each daemon
# when the test process that started it dies.
#
# What it does:
#   1. starts `cargo test --locked` (with --no-fail-fast) in the background
#      with its own TMPDIR;
#   2. waits until at least one agent-signd from this checkout's target
#      folder is running;
#   3. freezes every test binary of that run (SIGSTOP), so none can stop its
#      own daemon, counts the daemons alive at that moment, then kills the
#      cargo run and those test binaries with SIGKILL, and NOT the daemons;
#   4. waits 5 seconds;
#   5. counts the agent-signd processes whose command path is under this
#      checkout's target folder;
#   6. kills any that remain, so the check leaves nothing behind.
#
# Exit status: 0 if none remained; 1 if some did (the bug); 2 if the check
# could not run (cargo ended before a daemon appeared, none appeared within
# AGENT_SIGN_CHECK_WAIT_SECS (default 900), or no daemon was still alive at
# the moment of the kill in any of 5 attempts: a daemon that its test had
# already stopped by itself proves nothing).
#
# The run uses `--no-fail-fast`, so a failing test elsewhere in the suite
# does not end it before a daemon is seen.
#
# The target folder is $CARGO_TARGET_DIR if set, else <checkout>/target.
# Daemons already running from that folder when the check starts are left
# over from earlier runs of this checkout; they are killed first (and
# reported), so the count is of this run's own.
#
# Needs `ps -axo` (Linux procps, macOS). Never run this on Taylor's Mac: it runs
# the whole test suite (AGENTS.md); use the servers.
# =============================================================================
set -u

CHECKOUT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TARGET="${CARGO_TARGET_DIR:-$CHECKOUT/target}"
mkdir -p "$TARGET"
TARGET="$(cd "$TARGET" && pwd -P)"
WAIT_SECS="${AGENT_SIGN_CHECK_WAIT_SECS:-900}"

# Tests run with their own TMPDIR, inside the caller's (not the machine's
# shared /tmp when the caller has set its own), short because Unix socket
# paths are limited to about 104 bytes.
RUN_TMP="$(mktemp -d "${TMPDIR:-/tmp}/dd.XXXXXX")"
CARGO_PID=""
cleanup() {
    if [ -n "$CARGO_PID" ]; then kill -9 "$CARGO_PID" 2>/dev/null; fi
    kill_where daemons
    kill_where tests
    case "$RUN_TMP" in
        */dd.??????) rm -rf "$RUN_TMP" ;;
    esac
}
trap cleanup EXIT

# "pid command-path" for every process we can see. The command path is the
# first word of the command line, not /proc/<pid>/exe: agent-signd makes its
# own memory unreadable to the user's other programs (PR_SET_DUMPABLE 0), and
# that makes its /proc/<pid>/exe unreadable too, so the executable of exactly
# the processes this check looks for can't be read. The tests start the
# daemon and the test binaries by absolute path, so the first word is the
# path under the target folder. One `ps` run, because forking per process
# made a scan take over a second on the server, longer than a daemon lives.
list_exes() {
    ps -axo pid=,args= | awk '{ print $1, $2 }'
}

# PIDs of what is under the target folder: "daemons" are agent-signd itself;
# "tests" are the test binaries (anything in a deps/ folder).
pids_of() {
    local kind="$1" pid exe
    list_exes | while read -r pid exe; do
        case "$exe" in
            "$TARGET"/*/agent-signd | "$TARGET"/agent-signd)
                [ "$kind" = daemons ] && echo "$pid" ;;
            "$TARGET"/*/deps/*)
                [ "$kind" = tests ] && echo "$pid" ;;
        esac
    done
}

kill_where() {
    local pid
    for pid in $(pids_of "$1"); do kill -9 "$pid" 2>/dev/null; done
}

count_daemons() { pids_of daemons | wc -l | tr -d ' '; }

left_over="$(count_daemons)"
if [ "$left_over" -gt 0 ]; then
    echo "check-test-daemons-die: $left_over agent-signd from earlier runs were running from $TARGET; killing them first" >&2
    kill_where daemons
    sleep 1
fi

# One attempt: 0 = none remained, 1 = some remained, 3 = proved nothing
# (no daemon was alive at the moment of the kill); exits 2 itself when cargo
# can't get as far as a daemon.
attempt() {
    echo "check-test-daemons-die: running cargo test --locked in $CHECKOUT (TMPDIR=$RUN_TMP)"
    (
        cd "$CHECKOUT" || exit 1
        export TMPDIR="$RUN_TMP" GIT_CONFIG_GLOBAL=/dev/null CARGO_TARGET_DIR="$TARGET"
        exec cargo test --locked --no-fail-fast
    ) >"$RUN_TMP/cargo.log" 2>&1 &
    CARGO_PID=$!

    # Poll fast: a test's daemon lives for a fraction of a second. On the
    # first scan that sees a daemon, kill the run in that same scan: freeze
    # every test binary that scan saw (SIGSTOP), so no test can stop its
    # daemon itself, kill cargo, so it starts no further test binary, count
    # the daemons alive at that moment, then kill the frozen test binaries.
    # SIGKILL, so no cleanup runs, as when a session is cut off. The daemons
    # are not touched.
    #
    # EVAL FIX (fix round 1, 31 Oct 2026): the daemons alive "at the kill"
    # were counted after the test binaries were killed. With the fix in
    # place a daemon dies within milliseconds of its test (that is the fix),
    # so that count was always 0 and every attempt "proved nothing": the
    # check could exit 2, never 0. They are now counted while the tests are
    # frozen, just before the kill. The pass/fail rule is unchanged.
    local waited_ms=0 pid exe daemons tests
    while :; do
        daemons=0; tests=""
        while read -r pid exe; do
            case "$exe" in
                "$TARGET"/*/agent-signd | "$TARGET"/agent-signd) daemons=$((daemons + 1)) ;;
                "$TARGET"/*/deps/*) tests="$tests $pid" ;;
            esac
        done < <(list_exes)
        if [ "$daemons" -gt 0 ]; then
            for pid in $tests; do kill -STOP "$pid" 2>/dev/null; done
            kill -9 "$CARGO_PID" 2>/dev/null
            alive_at_kill="$(count_daemons)"
            for pid in $tests; do kill -9 "$pid" 2>/dev/null; done
            { wait "$CARGO_PID"; } 2>/dev/null
            break
        fi
        if ! kill -0 "$CARGO_PID" 2>/dev/null; then
            echo "check-test-daemons-die: cargo test ended before any agent-signd appeared; the check could not run. Its output:" >&2
            tail -n 30 "$RUN_TMP/cargo.log" >&2
            exit 2
        fi
        if [ "$waited_ms" -ge $((WAIT_SECS * 1000)) ]; then
            echo "check-test-daemons-die: no agent-signd appeared within ${WAIT_SECS}s; the check could not run" >&2
            exit 2
        fi
        sleep 0.1
        waited_ms=$((waited_ms + 100))
    done
    CARGO_PID=""

    # Any test binary started in the moment between the scan and the kill.
    for _ in 1 2 3 4 5; do
        tests="$(pids_of tests)"
        [ -n "$tests" ] || break
        for pid in $tests; do kill -9 "$pid" 2>/dev/null; done
        sleep 0.2
    done

    if [ "$alive_at_kill" -eq 0 ]; then
        echo "check-test-daemons-die: no daemon was still alive when the test run was killed (its test had already stopped it); this attempt proved nothing" >&2
        return 3
    fi
    echo "check-test-daemons-die: $alive_at_kill agent-signd alive when their test run was killed; waiting 5 seconds"
    sleep 5
    remaining="$(count_daemons)"
    if [ "$remaining" -eq 0 ]; then
        return 0
    fi
    echo "check-test-daemons-die: FAIL, $remaining agent-signd still running 5 seconds after their test run was killed:" >&2
    list_exes | while read -r pid exe; do
        case "$exe" in "$TARGET"/*/agent-signd | "$TARGET"/agent-signd) echo "  pid $pid $exe" >&2 ;; esac
    done
    return 1
}

for n in 1 2 3 4 5; do
    attempt
    result=$?
    case "$result" in
        0) echo "check-test-daemons-die: PASS, 0 agent-signd left after their test run was killed"; exit 0 ;;
        1) exit 1 ;;
    esac
    echo "check-test-daemons-die: attempt $n of 5 proved nothing; trying again" >&2
    kill_where daemons
    kill_where tests
done
echo "check-test-daemons-die: 5 attempts, and no daemon was alive at the kill in any; the check could not run" >&2
exit 2
