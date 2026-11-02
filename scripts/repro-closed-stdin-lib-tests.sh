#!/bin/bash
# Reproduces F1: the lib test
# session::tests::a_descriptor_travels_over_a_channel_and_only_a_channel_counts
# fails now and then in a plain `cargo test`.
#
# FINDING (1 Nov 2026, measured with this script on hetzner): the suspected
# cause, a run started with standard input closed, is NOT the cause.
#   * Rust's runtime reopens a closed descriptor 0..2 as /dev/null at start-up,
#     so the test never sees a socket numbered below 3; and `Channel::check(0)`
#     is always an error anyway (the fd < 3 rule), so it cannot be the line that
#     fails.
#   * Whole lib run, 40 runs each: stdin closed 5 failed, stdin /dev/null 4
#     failed: the same. Every failure whose panic line was captured (4 of 4, and the first
#     one seen in a plain cargo test) is at
#     src/session.rs:619, `assert!(channel.open_stream().is_err())`, the check
#     that the channel opens nothing once the service's end is dropped.
#   * It needs another test running at the same time that starts processes: the
#     test alone 0 of 200, `session::` tests only 0 of 120, with `repo_info::`
#     (whose tests run `git`) 12 of 60, with launch_client:: or verify:: 0 of 60.
#     Machine load makes it worse. Reproduce that pairing with
#         scripts/repro-closed-stdin-lib-tests.sh 60 'a_descriptor_travels repo_info::'
# Mechanism: a thread of another test forks to start `git`; until the child
# execs, it holds a copy of every descriptor, close-on-exec or not, including
# the test's `service` end; so `drop(service)` does not close the socket, and the
# send in `open_stream` still succeeds. CONFIRMED BY THE FIX (1 Nov 2026): the
# test now shuts the service end down (libc::shutdown, SHUT_RDWR, which acts on
# the socket whoever holds a copy) before dropping it, and uses its own
# non-channel descriptors; with the pairing above, 28 of 60 runs failed before
# and 0 of 100 fail after, in both modes. Check it again with
#     scripts/repro-closed-stdin-lib-tests.sh 100 'a_descriptor_travels repo_info::'
#
# usage: scripts/repro-closed-stdin-lib-tests.sh [RUNS=100] [FILTER=]
#   RUNS    how many times to run the lib tests in each mode
#   FILTER  passed to the test binary (e.g. a_descriptor_travels); empty = all
# Prints, per mode (stdin closed / stdin /dev/null as the control), how many
# runs failed and which tests failed how often. Exit 0 always (it measures).
set -u
runs=${1:-100}
filter=${2:-}
cd "$(dirname "$0")/.." || exit 2
export PATH="$HOME/.cargo/bin:$PATH" GIT_CONFIG_GLOBAL=/dev/null
bin=$(cargo test --lib --no-run --message-format=json 2>/dev/null | python3 -c '
import json, sys
exe = None
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["profile"]["test"] and "lib" in m["target"]["kind"]:
        exe = m["executable"]
print(exe or "")')
[ -n "$bin" ] && [ -x "$bin" ] || { echo "could not find the lib test binary" >&2; exit 2; }
work=$(mktemp -d "${TMPDIR:-/tmp}/repro-f1.XXXXXX") || exit 2
trap 'rm -rf "$work"' EXIT
run_mode() {
  mode=$1; failed_runs=0
  : > "$work/$mode.names"; : > "$work/$mode.where"
  for i in $(seq 1 "$runs"); do
    if [ "$mode" = closed ]; then
      "$bin" $filter 0<&- > "$work/o" 2>&1
    else
      "$bin" $filter < /dev/null > "$work/o" 2>&1
    fi
    if grep -q '^test .* FAILED$' "$work/o"; then
      failed_runs=$((failed_runs + 1))
      sed -n 's/^test \(.*\) \.\.\. FAILED$/\1/p' "$work/o" >> "$work/$mode.names"
      # Where it panicked and the assertion text (the line after "panicked at").
      grep -A1 'panicked at' "$work/o" | grep -v '^--$' | paste - - | sed 's/^thread [^ ]* ([0-9]*) //' >> "$work/$mode.where"
    fi
  done
  echo "stdin $mode: $failed_runs of $runs runs had a failing test"
  sort "$work/$mode.names" | uniq -c | sort -rn | sed 's/^/    /'
  sort "$work/$mode.where" | uniq -c | sort -rn | sed 's/^/      at: /'
}
echo "binary: $bin   filter: '${filter}'"
run_mode closed
run_mode devnull
