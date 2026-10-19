#!/bin/sh
# Refuses programs that contain the test stand-ins. A build made for tests
# stands in for the device owner (AGENT_SIGN_TEST_AUTH and its companions,
# which all share that prefix); installed, it would let anything that can
# set an environment variable approve its own leases. The code that reads them
# is compiled out of normal builds, and the build refuses to produce such a
# program in an optimized profile, but the installer checks anyway because it
# installs programs that already exist.
#
# Usage: check-binary-clean.sh <directory holding the programs>
# Exit status: 0 when none of them contains a stand-in, 1 when one does.
dir="$1"
[ -n "$dir" ] || { echo "usage: $0 <directory>" >&2; exit 2; }
status=0
for name in agent-signd agent-sign agent-ssh-sign agent-git; do
    [ -f "$dir/$name" ] || continue
    if grep -aq -e 'AGENT_SIGN_TEST_AUTH' "$dir/$name"; then
        echo "Refusing to install: $dir/$name is a test build (it contains a stand-in for the device owner). Rebuild with: cargo build --release --locked" >&2
        status=1
    fi
done
exit $status
