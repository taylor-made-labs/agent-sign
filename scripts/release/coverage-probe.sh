#!/usr/bin/env bash
# Coverage probe (release check F7): does agent-sign catch the commits a
# given agent, or way of running git, makes?
#
#   coverage-probe.sh <label> <command...>
#
# The command runs with PROBE_REPO set to a throwaway repository, and with
# `{repo}` in any argument replaced by its path. It should make one commit
# there, the way the agent normally would: for example
#   coverage-probe.sh claude claude -p "In {repo}, run: git commit --allow-empty -m probe"
# Commands are given as arguments, never through `sh -c`, so what runs is
# exactly what's written.
#
# The repository is on `main` with one starting commit. agent-sign refuses
# agent commits on main without asking anyone, so:
#   CAUGHT  agent-sign's wrapper handled the commit (it refused it as
#           protected): no dialog, nothing signed
#   MISSED  the real git ran the commit. The repository's own config points
#           signing at a stand-in that records the attempt and fails, so the
#           person's real signer (1Password, a hardware key) is never asked;
#           "would have signed" means the person's key would have been used
#   UNKNOWN neither showed (the agent may not have run the commit at all;
#           see the output)
#
# It never shows a dialog and never touches the person's real signing. The
# throwaway repository is left in the system's temporary folder (named on
# the output line) rather than deleted. Prints one line: LABEL RESULT DETAIL.

set -uo pipefail

label="${1:?usage: coverage-probe.sh <label> <command...>}"
shift
[ $# -gt 0 ] || { echo "usage: coverage-probe.sh <label> <command...>" >&2; exit 2; }

real_git="$(PATH=/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin command -v git)"
work="$(mktemp -d -t agent-sign-probe)"
repo="$work/repo"
mkdir -p "$repo"
attempts="$work/signing-attempts"

# The repository: on main, one commit, signing pointed at the stand-in.
( cd "$repo" \
  && GIT_CONFIG_GLOBAL=/dev/null "$real_git" init -q -b main \
  && GIT_CONFIG_GLOBAL=/dev/null "$real_git" -c user.name=Probe -c user.email=probe@example.com \
       commit -q --allow-empty -m start ) || { echo "$label UNKNOWN could not create the probe repository"; exit 1; }
cat > "$work/stand-in-signer" <<EOF
#!/bin/sh
echo "\$@" >> '$attempts'
exit 1
EOF
chmod +x "$work/stand-in-signer"
GIT_CONFIG_GLOBAL=/dev/null "$real_git" -C "$repo" config gpg.ssh.program "$work/stand-in-signer"
GIT_CONFIG_GLOBAL=/dev/null "$real_git" -C "$repo" config gpg.program "$work/stand-in-signer"
GIT_CONFIG_GLOBAL=/dev/null "$real_git" -C "$repo" config gpg.x509.program "$work/stand-in-signer"

out="$work/output"
args=()
for a in "$@"; do args+=("${a//\{repo\}/$repo}"); done
( cd "$repo" && PROBE_REPO="$repo" "${args[@]}" ) < /dev/null > "$out" 2>&1
commits="$(GIT_CONFIG_GLOBAL=/dev/null "$real_git" -C "$repo" rev-list --count HEAD 2>/dev/null || echo 1)"

if grep -q "is protected" "$out"; then
    result="CAUGHT"; detail="agent-sign refused it as a protected branch"
elif [ -s "$attempts" ]; then
    result="MISSED"; detail="the real git ran it and would have signed with the person's key"
elif [ "$commits" -gt 1 ]; then
    result="MISSED"; detail="the real git committed it, unsigned"
else
    result="UNKNOWN"; detail="no sign either way; output: $(tr '\n' ' ' < "$out" | cut -c1-200)"
fi
echo "$label $result $detail (probe folder: $work)"
