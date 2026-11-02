#!/bin/sh
# Refuses programs that contain the test stand-ins. A build made for tests
# stands in for the device owner, the machine's accounts, the system config,
# systemd, the launcher's state and I/O folders, the kernel's facts and the
# connection target through environment variables that all start with
# AGENT_SIGN_TEST_; installed, any of them would let anything that can set an
# environment variable approve its own leases or turn system mode's refusals
# off. The code that reads them is compiled out of normal builds, and the build
# refuses to produce such a program in an optimized profile, but the installer
# checks anyway because it installs programs that already exist.
#
# It matches the whole prefix, not a list of names, so a seam added later is
# refused without anyone remembering to add it here. A release program contains
# the prefix nowhere (checked on a release build); if one ever must, match the
# full seam names instead of loosening this. scripts/sitting/files/ holds an
# identical copy, which a test keeps in step.
#
# Usage: check-binary-clean.sh <directory holding the programs>
# Exit status: 0 when none of them contains a stand-in, 1 when one does.
dir="$1"
[ -n "$dir" ] || { echo "usage: $0 <directory>" >&2; exit 2; }
status=0
for name in agent-signd agent-launchd agent-sign agent-ssh-sign agent-git; do
    [ -f "$dir/$name" ] || continue
    if grep -aq -e 'AGENT_SIGN_TEST_' "$dir/$name"; then
        echo "Refusing to install: $dir/$name is a test build (it contains a stand-in for the device owner). Rebuild with: cargo build --release --locked" >&2
        status=1
    fi
done
exit $status
