# Helpers for agent-sign's server sitting (sourced by agent-sign-sitting.sh).
#
# Why these exist: every rule the sitting promises Taylor is enforced in one
# place, so a step can't forget it (the suite's REVIEW.md, "The agent-sign
# slot"; the same shape as the suite's own hetzner/lib.sh).
#
# - change: every change is named; --dry-run prints "would:" and runs
#   nothing; a failure stops the whole run with a plain "Stopped:" line.
# - as_root / as_user: the ONLY way this script uses sudo. Every prompt is
#   "${SITTING_SUDO_PROMPT_PREFIX:-<machine> sudo (<account>)}: " with every %
#   doubled, because sudo expands %h, %u and so on in a prompt. The why is one
#   short line on stderr just before the prompt, never inside it (Taylor's
#   prompt rule, 1 Nov 2026); no product name is ever in a sudo prompt.
# - keep: a step that found nothing to do says so. A second run is all "kept:".
# - check / skip: the end-of-run PASS / FAIL / SKIP lines.
# - ROOT: a prefix in front of every system path, empty on a real machine.
#   The tests set it to a throwaway folder and put stand-ins for sudo,
#   systemctl and the rest first on PATH, so the real script runs without
#   touching the machine it runs on. It (and the git override, and the folder
#   the machine settings are read from) is honoured
#   only together with AGENT_SIGN_SITTING_TEST=1 (review finding A-9): an
#   environment variable that is set by accident, or by something that runs
#   before this script, must never aim it at another folder or another git.
# - forget_sudo: ends sudo's cached ticket (review finding A-3).
#
# Nothing here prints a secret. A secret only ever travels through a pipe,
# never an argument, a file or a log line.

# git is what root runs for /etc/gitconfig, so on a real machine it is always
# /usr/bin/git and ROOT is empty. The two overrides exist for the tests only;
# the guard that honours them is below (it needs die).
ROOT=''
GIT=/usr/bin/git
MACHINE_DIR=''
DRY_RUN=${DRY_RUN:-0}
STEP_NO=0
CHANGES=0
WORK=''

say() { printf '%s\n' "$*"; }
section() { STEP_NO=$((STEP_NO + 1)); printf '\n== %s. %s\n' "$STEP_NO" "$*"; }

# die MESSAGE: stops the run. Changes already made stay: every step checks
# before it changes, so running the same command again carries on.
DIE_CLOSING='' # set by a cleanup that undid things: die prints it instead of the usual "nothing changed" line
DIE_CLEANUP='' # a function die runs once, before it exits (a step registers one while it is half-done)
die() {
  printf '\nStopped: %s\n' "$*" >&2
  if [ -n "$DIE_CLEANUP" ]; then
    local cleanup=$DIE_CLEANUP
    DIE_CLEANUP=''
    "$cleanup" || true
  fi
  if [ -n "$DIE_CLOSING" ]; then
    printf '%s\n' "$DIE_CLOSING" >&2
  else
    printf 'Nothing after this point was changed. Run the same command again once it is fixed: every step checks what is already done.\n' >&2
  fi
  exit 1
}

# Anything the script did not expect (a command failing outside `change`)
# still ends in a plain Stopped line, never a bare shell trace.
on_unexpected_error() {
  local code=$1 line=$2
  trap - ERR
  die "something unexpected failed (exit $code, script line $line). Nothing else was changed after it."
}

# A-9: the test overrides are honoured only with the explicit test flag. Set
# without it (or with it 0 or empty), the script stops here, before it has used
# sudo or changed anything.
if [ -n "${AGENT_SIGN_SITTING_ROOT:-}${AGENT_SIGN_SITTING_GIT:-}${AGENT_SIGN_SITTING_MACHINE_DIR:-}" ]; then
  [ "${AGENT_SIGN_SITTING_TEST:-}" = 1 ] \
    || die "AGENT_SIGN_SITTING_ROOT, AGENT_SIGN_SITTING_GIT or AGENT_SIGN_SITTING_MACHINE_DIR is set, but AGENT_SIGN_SITTING_TEST=1 is not. Those variables exist for the script's own tests and would aim this script at another folder, another git or other machine settings. Unset them to run it on this machine."
  ROOT=${AGENT_SIGN_SITTING_ROOT:-}
  GIT=${AGENT_SIGN_SITTING_GIT:-/usr/bin/git}
  MACHINE_DIR=${AGENT_SIGN_SITTING_MACHINE_DIR:-}
fi

# plain_text TEXT: TEXT with every character that is not printable ASCII
# replaced by "?". Anything the agents' account controls (a setting's value, a
# file name, a git origin) goes through this before it is printed, so an escape
# sequence in it can't retitle or clear the administrator's terminal (A-8).
plain_text() { printf '%s' "$*" | tr -c '[:print:]' '?'; }

# The sudo prompt: the prefix the suite gave us (default "<machine> sudo
# (<account>)"), then ": ". sudo expands %-sequences in a prompt, so every % is
# doubled to show as itself.
sudo_prompt() { printf '%s: ' "$PROMPT_PREFIX" | sed 's/%/%%/g'; }

# sudo_why WHY: the reason, one short line on the real stderr just before the
# prompt. It goes to a copy of stderr (fd 8, made here) because callers capture
# a command's output with `2>&1`, and the reason must not end up in what they
# compare or parse. fd 8 is RESERVED for this: nothing else may open or redirect
# it (undo's manifest loops read on fd 3, which used to be this one, and lost
# every reason line with "Bad file descriptor").
exec 8>&2
sudo_why() { printf '%s\n' "$1" >&8; }

# as_root WHY CMD...: runs CMD as root through sudo, with a prompt naming why.
as_root() {
  local why=$1
  shift
  sudo_why "$why"
  sudo -p "$(sudo_prompt)" -- "$@"
}

# forget_sudo: ends sudo's cached ticket. Called before anything built from the
# source or installed under /opt/agent-sign runs as the administrator, so a
# hostile dependency can't use the administrator's ticket (`sudo -n`) to become
# root (A-3). The next as_root asks for the password again, with its own named
# prompt, which also makes a new ticket.
forget_sudo() { sudo -k; }

# as_user ACCOUNT WHY CMD...: runs CMD as another unprivileged account.
as_user() {
  local account=$1 why=$2
  shift 2
  sudo_why "$why"
  sudo -p "$(sudo_prompt)" -u "$account" -- "$@"
}

# change WHAT CMD...: one named change. Dry run: shown, not run. Otherwise it
# runs, and a failure stops everything. (CMD runs in an `||` list, so bash
# ignores `set -e` inside it: every multi-command function ends each command
# with `|| return 1`.)
change() {
  local what=$1
  shift
  CHANGES=$((CHANGES + 1))
  if [ "$DRY_RUN" = 1 ]; then
    printf '  would: %s\n' "$what"
    return 0
  fi
  printf '  doing: %s\n' "$what"
  "$@" || die "$what: that step failed (exit $?)."
}

# keep WHAT: something already in place; nothing to do.
keep() { printf '  kept:  %s\n' "$1"; }

# ---------------------------------------------------------------- end checks

CHECKS_FAILED=0
CHECKS_PASSED=0
CHECKS_SKIPPED=0

# check NAME CMD...: one end-of-run check. Records PASS or FAIL, never stops.
check() {
  local name=$1
  shift
  if "$@" >/dev/null 2>&1; then
    printf '  PASS  %s\n' "$name"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
  else
    printf '  FAIL  %s\n' "$name"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
  fi
}

# skip NAME WHY: a check that cannot be made here (never a PASS, never a FAIL).
skip() {
  printf '  SKIP  %s (%s)\n' "$1" "$2"
  CHECKS_SKIPPED=$((CHECKS_SKIPPED + 1))
}

# wait_for SECONDS CMD...: retries CMD once a second until it succeeds or time runs out.
wait_for() {
  local n=$1
  shift
  while [ "$n" -gt 0 ]; do
    "$@" >/dev/null 2>&1 && return 0
    sleep 1
    n=$((n - 1))
  done
  return 1
}

# ---------------------------------------------------------------- small readers

# load_env FILE: reads KEY=value lines (upper-case keys, plain values) into
# variables. It never `source`s the file: a line that isn't a plain setting
# stops the run, so these files can't carry code.
load_env() {
  local file=$1 line key val
  [ -r "$file" ] || die "the settings file $file is missing from the sitting's folder."
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in '' | '#'*) continue ;; esac
    [[ $line =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9_./:@+-]*)$ ]] || die "$file has a line that is not a plain KEY=value setting: $line"
    key=${BASH_REMATCH[1]}
    val=${BASH_REMATCH[2]}
    printf -v "$key" '%s' "$val"
  done <"$file"
}

# version_at_least HAVE WANT: numeric comparison of dotted versions
# (2.7.10 is newer than 2.7.2; 1.19.4 is older than 2.7.2).
version_at_least() {
  local -a have want
  local i h w
  IFS=. read -r -a have <<<"${1%%[!0-9.]*}"
  IFS=. read -r -a want <<<"${2%%[!0-9.]*}"
  for i in 0 1 2; do
    h=${have[$i]:-0}
    w=${want[$i]:-0}
    [[ $h =~ ^[0-9]+$ ]] || h=0
    [[ $w =~ ^[0-9]+$ ]] || w=0
    if ((10#$h > 10#$w)); then return 0; fi
    if ((10#$h < 10#$w)); then return 1; fi
  done
  return 0
}

# toml_value FILE SECTION KEY: the plain string, number or boolean value of
# KEY in [SECTION] ("" for the top of the file). Only for the simple files
# this sitting writes itself.
toml_value() {
  awk -v want_sec="$2" -v want_key="$3" '
    /^[ \t]*(#|$)/ { next }
    /^[ \t]*\[/ { sec = $0; sub(/^[ \t]*\[/, "", sec); sub(/\][ \t]*$/, "", sec); next }
    {
      i = index($0, "=")
      if (i == 0) next
      k = substr($0, 1, i - 1); v = substr($0, i + 1)
      gsub(/^[ \t]+|[ \t]+$/, "", k); gsub(/^[ \t]+|[ \t]+$/, "", v)
      if (sec == want_sec && k == want_key) { gsub(/^"|"$/, "", v); print v; exit }
    }' "$1"
}

# toml_parses FILE: every line is blank, a comment, a [table] or key = value.
toml_parses() {
  ! grep -Evq '^[[:space:]]*(#.*|\[[A-Za-z0-9_.-]+\]|[A-Za-z0-9_-]+[[:space:]]*=.+)?$' "$1"
}

# ---------------------------------------------------------------- root-visible state

# Parent folders can be closed to Taylor (credstore.encrypted, the slots'
# folders, polkit's rules.d), so anything under a system path is looked at
# through sudo.

# root_read_to PATH OUTFILE: copies a root-visible file into OUTFILE. Fails (and leaves nothing) when absent.
root_read_to() {
  if as_root "reading $1 to see whether it is already right" cat -- "$1" >"$2" 2>/dev/null; then
    return 0
  fi
  rm -f -- "$2"
  return 1
}

# root_stat PATH: "MODE OWNER GROUP" (mode in octal, no leading zero); fails when absent.
root_stat() { as_root "looking at $1" stat -c '%a %U %G' -- "$1" 2>/dev/null; }

mode_eq() { [ "$((8#$1))" -eq "$((8#$2))" ]; }

# path_state_ok PATH MODE OWNER GROUP: the path exists with that mode and,
# on a real machine, that owner and group. Under a test root the stand-ins
# can't change owners (they keep a ledger instead), so only the mode is
# looked at there; the owner is checked on the real machine, where nothing
# is skipped.
path_state_ok() {
  local got
  got=$(root_stat "$1") || return 1
  # shellcheck disable=SC2086
  set -- "$1" "$2" "$3" "$4" $got
  mode_eq "$2" "$5" || return 1
  [ -n "$ROOT" ] && return 0
  [ "$3" = "$6" ] && [ "$4" = "$7" ]
}

# show_diff DEST CURRENT NEW: what a file change would do (public files only).
show_diff() {
  if [ -e "$2" ]; then
    diff -u --label "$1 (now)" --label "$1 (after)" "$2" "$3" | sed 's/^/        /' || true
  else
    printf '        (a new file, %s lines)\n' "$(wc -l <"$3")"
  fi
}

# ensure_parent DIR [MODE]: makes DIR (root-owned, 0755 unless MODE is given) if
# it is missing; never changes one that exists (it belongs to the system or
# another package).
ensure_parent() {
  if as_root "checking that $1 exists" test -d "$1"; then
    return 0
  fi
  change "make the folder $1" as_root "making the folder $1" install -d -m "${2:-0755}" -o root -g root "$1"
}

# ensure_dir DIR MODE OWNER GROUP: a folder of ours, with exactly this mode and owner.
# Every folder is made with an explicit mode: sudo and this script's umask (077)
# would otherwise make it private to root, as the suite's own sitting once found.
ensure_dir() {
  local dir=$1 mode=$2 owner=$3 group=$4
  if path_state_ok "$dir" "$mode" "$owner" "$group"; then
    keep "$dir ($mode $owner:$group)"
    return 0
  fi
  change "make or fix the folder $dir ($mode $owner:$group)" \
    as_root "making the folder $dir" install -d -m "$mode" -o "$owner" -g "$group" "$dir"
}

# ensure_dir_nolink DIR MODE OWNER GROUP: ensure_dir for a folder inside a place
# agent-launch owns. Root must never `install -d` (which chmods and chowns) a path
# agent-launch could have replaced with a link, or a rerun would change the link's
# target. So root first asks, without following, whether the path itself is a
# link, and stops plainly if so.
ensure_dir_nolink() {
  if as_root "checking that $1 is not a link (root would follow it)" test -L "$1"; then
    die "$1 is a link, and the sitting will not change what a link points to. Remove the link (it is in a folder the launcher owns) and run the same command again."
  fi
  ensure_dir "$@"
}

# install_file WHY SRC DEST MODE OWNER GROUP: installs a public (non-secret)
# file if it differs from what is there. Sets FILE_CHANGED=1 when it acts
# (or would, in a dry run), so a step can tell whether something needs a
# reload or a restart.
FILE_CHANGED=0
install_file() {
  local why=$1 src=$2 dest=$3 mode=$4 owner=$5 group=$6 cur
  cur="$WORK/current-$(basename "$dest")"
  FILE_CHANGED=0
  if root_read_to "$dest" "$cur" && cmp -s "$cur" "$src" && path_state_ok "$dest" "$mode" "$owner" "$group"; then
    keep "$dest ($why)"
    return 0
  fi
  FILE_CHANGED=1
  change "install $dest: $why" \
    as_root "installing $dest" install -m "$mode" -o "$owner" -g "$group" "$src" "$dest"
  if [ "$DRY_RUN" = 1 ]; then show_diff "$dest" "$cur" "$src"; fi
}
