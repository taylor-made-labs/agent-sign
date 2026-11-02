#!/usr/bin/env bash
# agent-sign's server sitting: system mode, on hetzner (and later the Pi).
#
#   agent-sign-sitting.sh --machine hetzner|pi --commit SHA --source BUNDLE
#                         [--slots N] [--dry-run [--login-pending]] [--undo]
#
# Design: docs/system-mode.md (section 8 "The sitting script", build step 5);
# decisions D5 (remove the old trust the agents can write) and D6 (static slot
# accounts, a setting with default 8). Eval: tests/test_sitting_script.rs, which
# runs this script against a throwaway root with stand-ins; read its module doc
# for the interface it assumes (AGENT_SIGN_SITTING_ROOT, ..._GIT, which are
# honoured only with AGENT_SIGN_SITTING_TEST=1, and the stand-ins first on PATH).
#
# The contract (the suite's REVIEW.md, "The agent-sign slot"):
#   - runs as Taylor with sudo, never as root and never as the agents account;
#   - --dry-run shows every change and every file diff, and changes nothing;
#   - idempotent: each step checks first and prints "kept:" when nothing is
#     left to do, so a second run changes nothing;
#   - stops at the first failure with a plain "Stopped:" message;
#   - every sudo prompt is "${SITTING_SUDO_PROMPT_PREFIX:-<machine> sudo
#     (<account>)}: " with the why on one short stderr line before it; there is no
#     other use of sudo (lib.sh: as_root, as_user);
#   - prints no secret: the OpenBao secret ID moves only by pipe;
#   - ends by checking its results (PASS / FAIL / SKIP per line);
#   - --undo reverses the changes and never deletes data.
#
# What it does not do: the OpenBao side (the SSH engine mount, the CA, the
# role, the AppRole login) belongs to agentic-credentials' logins sitting, which
# runs before this slot. This script only checks that the mount answers with
# one ed25519 CA key, and moves the delivered login from Taylor's account into
# the system credential store by pipe. The role there must accept any principal
# (OpenBao 2.7.1 matches allowed_users exactly, with no patterns); what limits
# the principals to this machine's agents is the machine's own CA and the single
# trust line "*@<machine>.agents.local" in /etc/agent-sign/allowed_signers,
# which this script writes and checks exactly.
#
# Root never runs anything from a place another account can write: the build
# runs in a throwaway account (systemd-run, DynamicUser) in two phases (a fetch
# that may reach the internet but not this machine's own or private networks,
# then a compile with no network at all), and root only copies its output, after
# check-binary-clean.sh (the sitting's own reviewed copy, never the source's) and
# a hash; D5's changes to the agents' own files are made as the agents account,
# through sudo -u, with a clean environment and absolute paths, never with a
# program from the agents' own bin folder.
#
# Nothing built from the source or installed under /opt/agent-sign ever runs
# while sudo's ticket is cached: forget_sudo (sudo -k) comes first (A-3). The
# source is a git bundle, verified by git in a fresh repository with its config
# isolated; nothing from it is run except the build, inside the sandbox (A-6).
# Root never opens a path in a folder another account controls: the files systemd
# opens for the session units live under /var/lib/agent-launch-io, whose every
# folder is root's (A-2).

set -Eeuo pipefail
shopt -u patsub_replacement 2>/dev/null || true
umask 077
export LC_ALL=C

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DRY_RUN=0
# shellcheck source=lib.sh
. "$HERE/lib.sh"
trap 'on_unexpected_error $? $LINENO' ERR

# No ambient OpenBao token or address reaches anything this script runs.
unset BAO_TOKEN VAULT_TOKEN BAO_ADDR VAULT_ADDR BAO_CACERT VAULT_CACERT 2>/dev/null || true

usage() {
  cat <<'USAGE'
agent-sign-sitting.sh --machine hetzner --commit SHA --source BUNDLE [--slots N] [--slot-memory-max SIZE] [--slot-tasks-max N] [--dry-run [--login-pending]] [--undo]

  --machine  which machine this is (hetzner; pi when its leg is built)
  --commit   the agent-sign commit to install (40 hex digits)
  --source   a git bundle that holds that commit (made with: git bundle create
             FILE refs/heads/main, in agent-sign's repository, whose main
             contains the commit). A tar is refused.
  --slots    how many session slot accounts to have (a whole number, 2 or more:
             the probe session keeps one slot busy for an hour, and the end
             checks need a second; default: what /etc/agent-sign/system.toml
             says, else 8). Raising it adds accounts; lowering it deletes nothing.
  --slot-memory-max
             the most memory one session slot may use (MemoryMax= in the two
             slot units): a percentage of the machine's memory from 1% to 100%,
             or a size with a unit suffix K, M, G or T, such as 2G or 1536M (a bare number
             like 10 is refused: it would mean 10 bytes) (default: 50%)
  --slot-tasks-max
             the most processes and threads one slot may have (TasksMax=): a
             percentage from 1% to 100% of the kernel's limit, or a whole number
             (default: 15%)
  --dry-run  show every change and change nothing
  --login-pending
             only with --dry-run: agentic-credentials' logins sitting hasn't
             delivered this machine's OpenBao login and SSH engine yet; the steps
             that need them are listed as "after the login is delivered" instead
             of stopping the dry run
  --undo     put the machine back (never deletes data); --commit and --source are not needed

Run it as your own administrator account, not as root. It asks for sudo where it must.
USAGE
}

# ---------------------------------------------------------------- arguments

MACHINE='' COMMIT='' SOURCE='' SLOTS_ARG='' SLOTS_GIVEN=0 UNDO=0 LOGIN_PENDING=0
SLOT_MEMORY_MAX='' SLOT_TASKS_MAX='' SLOT_MEMORY_GIVEN=0 SLOT_TASKS_GIVEN=0 # not given: the units keep their own defaults (50%, 15%)
LOGIN_AWAITED=0 # the login isn't delivered yet and --login-pending said that is expected
need_value() { [ "$#" -ge 2 ] || die "$1 needs a value (see --help)."; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --machine) need_value "$@"; MACHINE=$2; shift 2 ;;
    --commit) need_value "$@"; COMMIT=$2; shift 2 ;;
    --source) need_value "$@"; SOURCE=$2; shift 2 ;;
    --slots) need_value "$@"; SLOTS_ARG=$2; SLOTS_GIVEN=1; shift 2 ;;
    --slot-memory-max) need_value "$@"; SLOT_MEMORY_MAX=$2; SLOT_MEMORY_GIVEN=1; shift 2 ;;
    --slot-tasks-max) need_value "$@"; SLOT_TASKS_MAX=$2; SLOT_TASKS_GIVEN=1; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --login-pending) LOGIN_PENDING=1; shift ;;
    --undo) UNDO=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown argument \"$1\" (see --help)." ;;
  esac
done

[[ $MACHINE =~ ^[a-z][a-z0-9-]*$ ]] || die "--machine is required (hetzner or pi)."
# The slot count goes into a polkit rule (JavaScript that root's decision-maker
# runs) and into account names, so it must be a plain positive whole number.
# At least 2 (A-10): the probe session holds one slot for an hour, and the end
# checks start more sessions, so one slot can never pass them.
if [ "$SLOTS_GIVEN" = 1 ]; then
  [[ $SLOTS_ARG =~ ^([2-9]|[1-9][0-9]{1,2})$ ]] || die "--slots must be a plain whole number of slots, 2 or more (for example 8): the probe session keeps one slot busy for an hour and the end checks need a second one; got \"$(plain_text "$SLOTS_ARG")\"."
fi
# The slot limits go into unit files that root's systemd reads, so each must be
# exactly a percentage (1 to 100) or a size / whole number, and nothing else.
# Checked before anything is changed.
if [ "$SLOT_MEMORY_GIVEN" = 1 ]; then
  [[ $SLOT_MEMORY_MAX =~ ^(([1-9][0-9]?|100)%|[1-9][0-9]*[KMGT])$ ]] || die "--slot-memory-max must be a percentage from 1% to 100% (for example 50%) or a size with a unit K, M, G or T (for example 2G or 1536M); a bare number such as 10 would mean 10 bytes and is refused; got \"$(plain_text "$SLOT_MEMORY_MAX")\"."
fi
if [ "$SLOT_TASKS_GIVEN" = 1 ]; then
  [[ $SLOT_TASKS_MAX =~ ^(([1-9][0-9]?|100)%|[1-9][0-9]*)$ ]] || die "--slot-tasks-max must be a percentage from 1% to 100% (for example 15%) or a whole number of tasks (for example 4096); got \"$(plain_text "$SLOT_TASKS_MAX")\"."
fi
# A login that hasn't been delivered is only ever expected in a dry run, which
# changes nothing; a real run or an undo with it would be a way to skip the check.
if [ "$LOGIN_PENDING" = 1 ] && { [ "$DRY_RUN" = 0 ] || [ "$UNDO" = 1 ]; }; then
  die "--login-pending can only be used together with --dry-run (and not with --undo): a real run needs the login delivered. Use --dry-run --login-pending to see the steps before agentic-credentials' logins sitting has run."
fi
if [ "$UNDO" = 0 ]; then
  [[ $COMMIT =~ ^[0-9a-f]{40}$ ]] || die "--commit must be the full 40-digit commit id."
  [ -n "$SOURCE" ] || die "--source (a git bundle that holds the commit) is required."
  case $SOURCE in /*) ;; *) SOURCE=$PWD/$SOURCE ;; esac
fi
case $ROOT in '' | /*) ;; *) die "AGENT_SIGN_SITTING_ROOT must be an absolute path." ;; esac
ROOT=${ROOT%/}
cd /

load_env "$HERE/pins.env"
# The machine's own settings are a file the operator puts in files/ (git ignores
# it, and the repository holds only machine-example.env, so no real address or
# name is ever committed). The tests read theirs from another folder.
load_env "${MACHINE_DIR:-$HERE/files}/machine-$MACHINE.env"

# ---------------------------------------------------------------- paths
# $ROOT is empty on a real machine. Text written FOR the machine (unit files,
# system.toml, the trust file, git settings) always keeps the real paths below.

ETC=$ROOT/etc OPT=$ROOT/opt VAR=$ROOT/var
AS_ETC=$ETC/agent-sign
AS_OPT=$OPT/agent-sign
REL=$AS_OPT/$COMMIT
CURRENT_BIN=$AS_OPT/current/bin
CREDSTORE=$ETC/credstore.encrypted
SYSTEMD_DIR=$ETC/systemd/system
POLKIT_RULE=$ETC/polkit-1/rules.d/50-agent-launch.rules
SLOTS_ROOT=$VAR/lib/agent-slots
LAUNCH_STATE=$VAR/lib/agent-launch
# What systemd (root) opens for the session units: each slot's spec and output
# file. Root-owned folders only, so nothing can be planted in the way (A-2).
LAUNCH_IO=$VAR/lib/agent-launch-io
SAVE_ROOT=$VAR/lib/agent-sign-sitting
SAVE=$SAVE_ROOT/before
TRUST_REAL=/etc/agent-sign/allowed_signers
AGENT_PROGRAM_REAL=/opt/agent-sign/current/bin/agent-ssh-sign
BLOCK_BEGIN="# agent-sign: agents' certificate authorities, managed; do not edit"
BLOCK_END="# agent-sign: end of agents' certificate authorities"
PROGRAMS=(agent-sign agent-signd agent-launchd agent-git agent-ssh-sign)
UNITS=(agent-signd.socket agent-signd-launcher.socket agent-signd.service agent-launchd.socket agent-launchd.service 'agent-session@.service' 'agent-session-end@.service')
DEFAULT_SLOTS=8

# Things the steps tell each other.
RESTART_NEEDED=0 # something the running services read has changed
HAD_SETTINGS=0   # a system.toml of an earlier run was there (kept in $WORK/system.toml.now)
SETTINGS_PLACED=0 # this run installed or changed system.toml (so a failed start rolls it back)
RESOLVERS=''     # the DNS servers the build's fetch phase may reach
HOST_ADDRS=''    # this machine's own global addresses, which the fetch phase is denied too
CA_KEY=''        # OpenBao's CA public key, "ssh-ed25519 AAAA..."
SLOTS=''

# ---------------------------------------------------------------- who is running this

ADMIN=$(id -un)
[ "$(id -u)" != 0 ] && [ "$ADMIN" != root ] || die "run this as your own administrator account, never as root (it asks for sudo where it must)."
[ "$ADMIN" != agents ] || die "run this as the administrator's account, not as the agents account: the agents account must not be able to run it."
[[ $ADMIN =~ ^[a-z_][a-z0-9_-]*$ ]] || die "the administrator account name \"$ADMIN\" is not a plain account name."
PROMPT_PREFIX=${SITTING_SUDO_PROMPT_PREFIX:-$MACHINE sudo ($ADMIN)}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/agent-sign-sitting.XXXXXX") || die "could not make a private temporary folder."
trap 'rm -rf -- "$WORK"' EXIT

AGENTS_HOME_REAL=$(getent passwd agents | cut -d: -f6) || true
[ -n "$AGENTS_HOME_REAL" ] || die "there is no agents account on this machine, so there is nothing for D5 to clean up. Stopping rather than guessing."
AGENTS_HOME=$ROOT$AGENTS_HOME_REAL
AGENTS_GITCONFIG=$AGENTS_HOME/.gitconfig
AGENTS_SIGNERS=$AGENTS_HOME/.config/git/allowed_signers
AGENTS_BIN=$AGENTS_HOME/.agent-sign/bin
AGENTS_USER_UNIT=$AGENTS_HOME/.config/systemd/user/agent-signd.service

# Everything done as the agents account: a clean environment, absolute paths,
# and git by the path the sitting was given. The agents' own PATH starts with
# their bin folder, which holds plain copies of programs (including `git`) that
# the agents account can rewrite.
agents_git() {
  local why=$1
  shift
  as_user agents "$why" /usr/bin/env -i PATH=/usr/bin:/bin HOME="$AGENTS_HOME" "$GIT" "$@"
}
agents_cat() { as_user agents "$1" /usr/bin/cat -- "$2"; }

# ---------------------------------------------------------------- reading the machine

account_exists() { getent passwd "$1" >/dev/null 2>&1; }
group_exists() { getent group "$1" >/dev/null 2>&1; }
group_has_member() {
  local members
  members=$(getent group "$1" 2>/dev/null | cut -d: -f4) || return 1
  case ",$members," in *",$2,"*) return 0 ;; esac
  return 1
}

# An account we are about to use already exists: it must be what we would have made.
check_existing_account() { # NAME [HOME]
  local name=$1 want_home=${2:-} line uid home shell
  line=$(getent passwd "$name") || return 0
  IFS=: read -r _ _ uid _ _ home shell <<<"$line"
  if [ "$uid" -ge 1000 ] || [ "$uid" -eq 0 ]; then
    die "the account \"$name\" already exists but it is a person's login (uid $uid), not a system account. Stopping: this script never reuses or changes a person's account."
  fi
  case $shell in */nologin | /bin/false | /usr/bin/false) ;; *) die "the account \"$name\" already exists but has a login shell ($shell). Stopping: agent-sign's accounts must have none." ;; esac
  if [ -n "$want_home" ] && [ "$home" != "$want_home" ]; then
    die "the account \"$name\" already exists with the home $home, not $want_home. Stopping rather than guessing."
  fi
}

# ---------------------------------------------------------------- the source (a git bundle)

# git for anything that handles the source: a fresh empty repository, git's
# config isolated (no global or system config, so no hooksPath, template or
# filter from Taylor's or the system's settings can run), no prompts. The
# environment is cleared; nothing but git itself runs (A-6).
git_isolated() {
  env -i PATH=/usr/bin:/bin HOME="$WORK" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 "$GIT" "$@"
}

# one_line TEXT: TEXT on one line, printable ASCII only, at most 300 characters
# (text from git about a file we were given).
one_line() { local s=${1//$'\n'/ }; s=$(plain_text "$s"); printf '%s' "${s:0:300}"; }

# verify_source: --source must be a git bundle holding the commit. git recomputes
# the hash of every object it unpacks, and a commit id names its tree and
# parents by hash, so the tree `git archive` makes from that commit is exactly
# the one the commit id names. (`git get-tar-commit-id`, used before, only
# showed that a tar's header said so: the content could be anything. A-6.)
# Nothing from the source is run. Leaves the tree in $WORK/source.tar.
verify_source() {
  local repo="$WORK/source.git" out
  [ -f "$SOURCE" ] || die "the source $SOURCE does not exist."
  git_isolated init --bare -q --template= "$repo" >/dev/null 2>&1 \
    || die "I could not make a scratch repository to check the source bundle in."
  out=$(git_isolated -C "$repo" bundle verify "$SOURCE" 2>&1) \
    || die "the source $SOURCE is not a git bundle that git can verify on its own (a tar, a bundle that needs history it doesn't hold, or a damaged file). Make one in agent-sign's repository with: git bundle create FILE refs/heads/main. git said: $(one_line "$out")"
  out=$(git_isolated -C "$repo" -c fetch.fsckObjects=true fetch --no-tags --quiet "$SOURCE" '+refs/*:refs/bundle/*' 2>&1) \
    || die "git could not read the objects of the source bundle $SOURCE: $(one_line "$out")"
  git_isolated -C "$repo" cat-file -e "$COMMIT^{commit}" >/dev/null 2>&1 \
    || die "the source bundle $SOURCE does not hold the commit $COMMIT (as a commit). Make the bundle from agent-sign's main with: git bundle create FILE refs/heads/main, and be sure main contains that commit."
  git_isolated -C "$repo" archive --format=tar -o "$WORK/source.tar" "$COMMIT" >/dev/null 2>&1 \
    || die "git could not make the tree of commit $COMMIT out of the source bundle."
  say "  ok: the source bundle holds commit $COMMIT, and git checked every object's hash back from that commit id, so the tree to build is exactly what that commit id names"
}

# ---------------------------------------------------------------- the build's DNS (A-4)

# find_resolvers: RESOLVERS = the nameservers this machine's DNS client uses, as
# single addresses. The build's fetch phase is denied a list of address RANGES
# (loopback, private networks, link-local, Tailscale, multicast) and this
# machine's own global addresses, and is allowed these addresses alone
# (IPAddressAllow wins over IPAddressDeny). hetzner's /etc/resolv.conf is
# systemd-resolved's stub (127.0.0.53, a link into /run/systemd/resolve); the
# Pi's is Tailscale's (100.100.100.100 and fd7a:115c:a1e0::53). Both lie inside
# the denied ranges, which is why they are named one by one.
#
# KNOWN LIMIT (the suite PM's note, accepted for now): allowing the resolver
# addresses gives the fetch phase DNS, and an allowance by address is an
# allowance on EVERY port of that address. DNS alone is enough for small data
# leaks (queries carry data to whoever answers for a name); on the Pi it also
# reaches Tailscale's 100.100.100.100 service on any port, not just port 53;
# and a loopback service that listens on all addresses (0.0.0.0) answers on the
# allowed 127.0.0.53 on any port. Nothing in systemd narrows this to port 53
# cheaply (systemd 259, man systemd.resource-control and systemd.exec):
# IPAddressAllow=/IPAddressDeny= take addresses only; SocketBindAllow=/
# SocketBindDeny= restrict bind(2) and never connect(2); RestrictNetworkInterfaces=
# works by interface, and 127.0.0.53 lives on lo with every other local service;
# a port-level rule would be a hand-written BPF program (IPEgressFilterPath=),
# which is not cheap or reviewable here. The next step, if this is ever worth
# closing, is in the README's backlog: resolve crates.io's hosts before the
# fetch, give the fetch an /etc/hosts and no resolver at all, and drop the
# allowance. Not built.
find_resolvers() {
  local f=$ETC/resolv.conf kw addr rest found=()
  [ -r "$f" ] || die "$f is missing or unreadable, so I can't tell which DNS servers the build's fetch phase may reach."
  while read -r kw addr rest; do
    [ "$kw" = nameserver ] || continue
    addr=${addr%%\%*} # an IPv6 zone ("fe80::1%eth0") can't be named to systemd
    if [[ $addr =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { [[ $addr =~ ^[0-9A-Fa-f:]+$ ]] && [[ $addr == *:* ]]; }; then
      found+=("$addr")
    fi
  done <"$f"
  [ "${#found[@]}" -gt 0 ] || die "$f names no DNS server I can allow the build's fetch phase to reach (it lists none, or only ones that aren't plain addresses)."
  RESOLVERS="${found[*]}"
}

# find_host_addresses: HOST_ADDRS = this machine's own global addresses (read now
# with `ip`), single addresses, space separated. The fetch phase is denied them
# too: the range list alone leaves a service listening on the machine's own
# PUBLIC address reachable from build-time code (S4). A resolver that is one of
# them stays reachable, because IPAddressAllow wins. Without `ip` the machine's
# own addresses can't be read, and the run says so rather than pretend; an `ip`
# that fails is a stop, not a guess.
find_host_addresses() {
  local out addr list=()
  HOST_ADDRS=''
  command -v ip >/dev/null 2>&1 || return 0
  out=$(ip -o addr show scope global 2>&1) \
    || die "I couldn't read this machine's own addresses (ip said: $(one_line "$out")), and the build's fetch phase must be denied them."
  while read -r addr; do
    [ -n "$addr" ] || continue
    if [[ $addr =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { [[ $addr =~ ^[0-9A-Fa-f:]+$ ]] && [[ $addr == *:* ]]; }; then
      list+=("$addr")
    fi
  done < <(printf '%s\n' "$out" | awk '$3 == "inet" || $3 == "inet6" { for (i = 1; i < NF; i++) if ($i == "scope" && $(i + 1) == "global") { a = $4; sub(/\/.*/, "", a); print a } }' | sort -u)
  HOST_ADDRS="${list[*]}"
}

# ---------------------------------------------------------------- OpenBao (read-only)

[[ $AUTH_ADDRESS =~ ^https://([A-Za-z0-9.-]+):([0-9]+)$ ]] || die "the machine settings' AUTH_ADDRESS is not https://host:port."
AUTH_HOST=${BASH_REMATCH[1]} AUTH_PORT=${BASH_REMATCH[2]}

# bao_get PATH: an unauthenticated GET, TLS 1.3 only, trusting only the machine's
# OpenBao CA file and the address the settings give.
bao_get() {
  curl --silent --show-error --max-time 20 --proto '=https' --tlsv1.3 \
    --cacert "$AUTH_CA_CERT" --resolve "$AUTH_HOST:$AUTH_PORT:$AUTH_RESOLVE" "$AUTH_ADDRESS$1"
}

check_openbao() {
  local health sealed version keys n type
  if [ -z "$ROOT" ] && [ ! -r "$AUTH_CA_CERT" ]; then
    die "OpenBao's CA file $AUTH_CA_CERT is missing or unreadable, so I can't talk to OpenBao safely."
  fi
  health=$(bao_get '/v1/sys/health?standbyok=true&sealedcode=200&uninitcode=200') \
    || die "I couldn't reach OpenBao at $AUTH_ADDRESS. Is it running? (agentic-credentials' logins sitting must have run first.)"
  sealed=$(printf '%s' "$health" | sed -n 's/.*"sealed" *: *\(true\|false\).*/\1/p')
  version=$(printf '%s' "$health" | sed -n 's/.*"version" *: *"\([0-9][0-9.]*\)[^"]*".*/\1/p')
  [ -n "$sealed" ] && [ -n "$version" ] || die "OpenBao at $AUTH_ADDRESS didn't answer like OpenBao's health endpoint."
  [ "$sealed" = false ] || die "OpenBao is sealed. Unseal it, then run this again."
  version_at_least "$version" 2.7.2 \
    || die "OpenBao is version $version; this needs 2.7.2 or later (it fixes GHSA-736f-82w7-hj22). Upgrade OpenBao first."
  say "  ok: OpenBao $version is unsealed (2.7.2 or later)"

  keys=$(bao_get "/v1/$AUTH_MOUNT/public_key" | grep -oE '(ssh-[a-z0-9]+|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.-]+) [A-Za-z0-9+/]+=*' || true)
  if [ -z "$keys" ]; then n=0; else n=$(printf '%s\n' "$keys" | wc -l); fi
  if [ "$n" -eq 0 ] && [ "$LOGIN_PENDING" = 1 ]; then
    say "  after the login is delivered: OpenBao's SSH engine $AUTH_MOUNT has no CA key yet (agentic-credentials' logins sitting makes it). The steps that need the key (root's trust file and git's setting for it) can't be shown until then."
    CA_KEY=''
    return 0
  fi
  [ "$n" -ge 1 ] || die "OpenBao's mount $AUTH_MOUNT has no CA public key (its public_key answered with none). Has agentic-credentials' logins sitting made the SSH engine for this machine?"
  [ "$n" -eq 1 ] || die "OpenBao's $AUTH_MOUNT/public_key answered with $n keys; I need exactly one ed25519 CA key."
  type=${keys%% *}
  [ "$type" = ssh-ed25519 ] || die "OpenBao's CA public key is $type; I need exactly one ed25519 key."
  printf '%s\n' "$keys" >"$WORK/ca.pub"
  ssh-keygen -l -f "$WORK/ca.pub" >/dev/null 2>&1 || die "OpenBao's CA public key doesn't parse as an SSH public key."
  CA_KEY=$keys
  say "  ok: $AUTH_MOUNT answers with one ed25519 CA key"
}

# ---------------------------------------------------------------- the login (the check; the move is a step)

DELIVERED=$HOME/.config/credstore.encrypted/openbao-$LOGIN_NAME
STORED_SECRET=$CREDSTORE/agent-sign.secret-id
STORED_ROLE=$CREDSTORE/agent-sign.role-id

stored_login_present() {
  as_root "checking whether the login is already in the system credential store" test -s "$STORED_SECRET" \
    && as_root "checking whether the login is already in the system credential store" test -s "$STORED_ROLE"
}

# A login pair (secret ID file, role ID file) has the right shape. Nothing is
# printed: the value only passes through pipes into a pattern match.
login_pair_valid() { # SECRET_FILE ROLE_FILE
  as_root "checking the stored login has the right shape (nothing is printed)" systemd-creds decrypt --name=secret-id "$1" - 2>/dev/null \
    | tr -d '\n' | grep -E '^[A-Za-z0-9._-]{16,200}$' >/dev/null || return 1
  as_root "checking the stored login's name" systemd-creds decrypt --name=role-id "$2" - 2>/dev/null \
    | grep -Fx -- "$LOGIN_NAME" >/dev/null
}
stored_login_valid() { login_pair_valid "$STORED_SECRET" "$STORED_ROLE"; }

# ---------------------------------------------------------------- preflight

preflight() {
  section "Checks before anything changes"

  if [ -z "$ROOT" ]; then
    command -v tailscale >/dev/null || die "tailscale is missing, so I can't tell which machine this is."
    local self
    self=$(tailscale status --self --peers=false --json 2>/dev/null | sed -n 's/.*"DNSName": *"\([^"]*\)".*/\1/p' | head -n1) || true
    [ "${self%%.*}" = "$TAILNET_NAME" ] || die "this isn't $MACHINE (Tailscale calls this machine \"$self\")."
  fi

  local t
  for t in sudo curl tar sha256sum ssh-keygen systemd-creds systemd-run systemctl useradd usermod getent install pkaction uname python3; do
    command -v "$t" >/dev/null || die "$t is missing on this machine."
  done
  # python3 runs clean-text.py, the filter for the build's messages.
  [ -r "$HERE/clean-text.py" ] || die "clean-text.py is missing beside this script ($HERE)."
  [ -x "$GIT" ] || die "git is missing ($GIT)."

  # sudo is asked once, here, so the reason is plain; later calls name their own.
  local why='the agent-sign sitting: installing agent-sign in its own accounts'
  [ "$DRY_RUN" = 1 ] && why='dry run: reading root-only state; nothing is changed'
  sudo_why "$why"
  sudo -p "$(sudo_prompt)" -v || die "sudo was refused."

  local sd kernel pk
  sd=$(systemctl --version | sed -n '1s/^systemd \([0-9][0-9]*\).*/\1/p')
  [[ $sd =~ ^[0-9]+$ ]] && [ "$sd" -ge 257 ] || die "systemd 257 or later is needed (this machine has \"${sd:-unknown}\")."
  kernel=$(uname -r)
  version_at_least "${kernel%%-*}" 6.5 || die "kernel 6.5 or later is needed for the caller checks (this machine has $kernel)."
  pk=$(pkaction --version | sed -n 's/.* \([0-9][0-9]*\)$/\1/p')
  [[ $pk =~ ^[0-9]+$ ]] && [ "$pk" -ge 121 ] || die "polkit with JavaScript rules (121 or later) is needed; found \"${pk:-unknown}\"."
  [ -d "$ETC/polkit-1/rules.d" ] || die "polkit's rules folder /etc/polkit-1/rules.d is missing."
  say "  ok: systemd $sd, kernel $kernel, polkit $pk, tools present, sudo works for $ADMIN"

  if [ "$UNDO" = 1 ]; then
    return 0
  fi

  verify_source
  find_resolvers
  find_host_addresses
  local own=''
  [ -z "$HOST_ADDRS" ] || own=", plus the global addresses of this machine itself ($HOST_ADDRS)"
  say "  ok: the build's fetch phase may reach the internet and these DNS servers ($RESOLVERS), and is denied these address ranges: loopback, private networks, link-local, Tailscale, multicast$own"
  if ! command -v ip >/dev/null 2>&1; then
    say "  note: there is no ip command here, so this machine's own global addresses were not read; the fetch phase is denied the ranges only."
  fi
  say "  note: known limit: the DNS servers are allowed on every port of their addresses, not only port 53 (see the comments of find_resolvers)."

  check_openbao

  if [ -s "$DELIVERED" ]; then
    say "  ok: the $LOGIN_NAME login was delivered to $ADMIN's account"
  elif stored_login_present; then
    say "  ok: the $LOGIN_NAME login is already in the system credential store"
  elif [ "$LOGIN_PENDING" = 1 ]; then
    say "  after the login is delivered: the $LOGIN_NAME login isn't in $ADMIN's account or the system store yet (agentic-credentials' logins sitting makes and delivers it). The steps that need it are listed below as \"after the login is delivered\"."
    LOGIN_AWAITED=1
  else
    die "agent-sign's OpenBao login ($LOGIN_NAME) hasn't been delivered to $ADMIN's account ($DELIVERED) and isn't in the system store. agentic-credentials' logins sitting makes and delivers it; it runs before this one."
  fi

  # An earlier system.toml must be ours, for this machine; the slot count is the
  # one thing a rerun may change.
  local existing_count=''
  if root_read_to "$AS_ETC/system.toml" "$WORK/system.toml.now"; then
    HAD_SETTINGS=1
    toml_parses "$WORK/system.toml.now" || die "/etc/agent-sign/system.toml exists but doesn't parse. Look at it before running this again."
    [ "$(toml_value "$WORK/system.toml.now" '' machine)" = "$MACHINE" ] \
      && [ "$(toml_value "$WORK/system.toml.now" service account)" = agent-sign ] \
      && [ "$(toml_value "$WORK/system.toml.now" launcher account)" = agent-launch ] \
      && [ "$(toml_value "$WORK/system.toml.now" slots account_prefix)" = agent-slot- ] \
      || die "/etc/agent-sign/system.toml exists but isn't this sitting's layout for $MACHINE (a different machine or other accounts). Look at it; I won't change it."
    existing_count=$(toml_value "$WORK/system.toml.now" slots count)
    say "  ok: /etc/agent-sign/system.toml is this sitting's, from an earlier run"
  fi
  if [ "$SLOTS_GIVEN" = 1 ]; then SLOTS=$SLOTS_ARG
  elif [[ $existing_count =~ ^([2-9]|[1-9][0-9]{1,2})$ ]]; then SLOTS=$existing_count
  else SLOTS=$DEFAULT_SLOTS; fi
  say "  ok: $SLOTS session slots"

  check_existing_account agent-sign /var/lib/agent-sign
  check_existing_account agent-launch /var/lib/agent-launch
  local i
  for i in $(seq 1 "$SLOTS"); do check_existing_account "agent-slot-$i"; done
  say "  ok: the account names are free or already ours"

  # What runs today, and the one setting that would send clients past the system socket.
  local today
  today=$(agents_git "reading the agents' git settings" config --global --get gpg.ssh.allowedSignersFile 2>/dev/null || true)
  say "  today: the agents' own allowedSignersFile is $(if [ -n "$today" ]; then plain_text "$today"; else echo 'not set'; fi)"
  local found
  found=$(as_user agents "looking for AGENT_SIGN_SOCKET in the agents' login files" /usr/bin/grep -rsl -e AGENT_SIGN_SOCKET -- \
    "$AGENTS_HOME/.bashrc" "$AGENTS_HOME/.bash_profile" "$AGENTS_HOME/.bash_login" "$AGENTS_HOME/.profile" \
    "$AGENTS_HOME/.zshenv" "$AGENTS_HOME/.zshrc" "$AGENTS_HOME/.zprofile" "$AGENTS_HOME/.pam_environment" \
    "$AGENTS_HOME/.config/environment.d" 2>/dev/null || true)
  [ -z "$found" ] || die "AGENT_SIGN_SOCKET is set in the agents' login files ($(one_line "$found")). It would send their clients past the system socket. Remove it, then run this again."
  say "  ok: AGENT_SIGN_SOCKET is not set in the agents' login files"
  # Links in the agents' bin folder are saved for undo; one whose target can't be
  # saved safely is refused now, before anything changes (A-1).
  if saved_marker_present; then
    say "  ok: the agents' files are already saved (an earlier run), so their bin links are not read again"
  else
    check_agents_links_safe
    say "  ok: any link in the agents' bin folder has a target that can be saved safely"
  fi
  say "  note: approvals and signed launches stay off: the commitments key doesn't exist yet (approvers is empty, commitments_key is unset). Only $ADMIN's account can launch a session."
}

# ---------------------------------------------------------------- 1. the programs

release_installed() {
  [ -f "$REL/SHA256SUMS" ] || return 1
  (cd "$REL" && sha256sum --check --quiet --strict SHA256SUMS >/dev/null 2>&1) \
    || die "release $COMMIT is installed at $REL but its files no longer match its SHA256SUMS. I touched nothing; look at it before running this again."
}

# The throwaway build is two systemd-run calls, each in its own throwaway
# account, because one call cannot give the fetch a network and the compile none
# (A-4):
#   1. fetch: the Rust toolchain download (checked against its pinned hash) and
#      `cargo fetch --locked`. It has the network, but IPAddressDeny covers a
#      list of address RANGES (loopback, Tailscale, RFC 1918, link-local and the
#      cloud metadata address, unique-local, multicast) and this machine's own
#      global addresses (read at sitting time), so build scripts can't reach
#      NATS, the inbox, OpenBao or a tailnet node. IPAddressAllow names the
#      machine's DNS servers alone (it wins over the deny); that allowance is by
#      address, so it is a known limit, stated at find_resolvers. TemporaryFile-
#      System=/run hides every socket in /run; only /run/systemd/resolve is
#      bound back, because hetzner's /etc/resolv.conf is a link into it. Not
#      covered: abstract unix sockets, which belong to the host's network
#      namespace (an IP filter can't see them).
#   2. compile: no network at all (PrivateNetwork=yes), and no /run either: the
#      system D-Bus, the agent-sign and launcher sockets and any other unix-
#      socket service would be reachable through the filesystem, which an IP
#      filter doesn't see (S3). It gets the first phase's output, but only the
#      toolchain archive and the .crate files with the registry index; it
#      extracts the crates itself, so it trusts no source folder the fetch phase
#      made (S5). It checks both against their hashes again, and builds with
#      --frozen.
# Both phases also hide the host's own state that a build never needs
# (BUILD_HIDDEN): the credential stores, agent-sign's and the launcher's state
# and settings, the slots. Each is "-"-prefixed, so a machine that doesn't have
# the folder (the Pi has no /etc/credstore) still starts the unit. /home and
# /root are hidden by ProtectHome=yes, /tmp and /var/tmp by PrivateTmp=yes.
# Each gets one tar on standard input: the recipe and the source. Its command
# line is only the short bootstrap, so what the sandbox runs is the reviewed
# file in this folder, not text rebuilt on a command line.
FETCH_DENY='0.0.0.0/8 127.0.0.0/8 ::/128 ::1/128 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 fc00::/7 fd7a:115c:a1e0::/48 fe80::/10 ff00::/8'
BUILD_HIDDEN=(/etc/credstore.encrypted /etc/credstore /etc/agent-sign /var/lib/agent-sign /var/lib/agent-launch /var/lib/agent-launch-io /var/lib/agent-slots /var/lib/agent-sign-sitting /var/lib/tailscale)

# Both phases set ProtectProc=invisible, so build code cannot read other
# processes in /proc. ProcSubset=pid is deliberately NOT set: build tools read
# /proc/cpuinfo and similar, and an untested break at the sitting costs more.
#
# The build's messages (its standard error) are shown as they come and kept in
# $WORK/build-PHASE.log, so a failure can end with them (build_failed): Taylor's
# first real sitting (2 Nov 2026) stopped with the build's messages scrolled out
# of reach. What reaches the terminal goes through clean_text, live and in the
# tail: the compile runs third-party build scripts and proc-macros, which must
# not drive Taylor's terminal or pass for the sitting's own lines (each build
# line is indented by two spaces; the sitting's own start at the margin). Each phase's
# bootstrap first says how much room its private /tmp has (hetzner's /tmp is a
# memory filesystem shared with everything; the fetch needs about 3.1 GB of it
# and the compile 3.5 GB, measured 2 Nov 2026).
sandbox_run() { # PHASE WHY INPUT OUTPUT PROPERTY...
  local phase=$1 why=$2 input=$3 output=$4 hidden=() p rc=0
  shift 4
  for p in "${BUILD_HIDDEN[@]}"; do hidden+=(-p "InaccessiblePaths=-$p"); done
  as_root "$why" \
    systemd-run --wait --pipe --quiet --collect \
    -p DynamicUser=yes -p ProtectHome=yes -p ProtectSystem=strict -p PrivateTmp=yes \
    -p PrivateDevices=yes -p NoNewPrivileges=yes -p CapabilityBoundingSet= \
    -p RestrictSUIDSGID=yes -p LockPersonality=yes -p ProtectKernelTunables=yes \
    -p ProtectControlGroups=yes -p ProtectProc=invisible -p LimitCORE=0 -p RuntimeMaxSec=3600 \
    "${hidden[@]}" \
    "$@" \
    -E "RUST_VERSION=$RUST_VERSION" -E "TOOLCHAIN_URL=$TOOLCHAIN_URL" -E "TOOLCHAIN_SHA256=$TOOLCHAIN_SHA256" \
    /usr/bin/bash -c 'set -e; mkdir -p /tmp/agent-sign-build; cd /tmp/agent-sign-build; echo "build: free in this sandbox /tmp before unpacking: $(df -h --output=avail /tmp | tail -n 1 | tr -d " ")" >&2; tar -x -f -; exec bash ./build-in-sandbox.sh "$0"' "$phase" \
    <"$input" >"$output" 2> >({ tee -- "$WORK/build-$phase.log" || : >"$WORK/build-$phase.log.failed"; } | clean_text '  ' >&2) || rc=$?
  # Wait for the shown copy to finish, so nothing of it lands after the tail.
  # (`wait` on a process substitution's $! needs bash 4.4 or later; hetzner and
  # the Pi run bash 5.)
  wait "$!" 2>/dev/null || true
  return "$rc"
}

# clean_text [PREFIX]: a build's messages, filtered by character, not by byte
# (clean-text.py says what is removed and why: control and format characters,
# line separators, invalid UTF-8), each line cut at 300 characters and started
# with PREFIX.
clean_text() { python3 -I -S -u "$HERE/clean-text.py" "$@"; }

# build_failed STEP PHASE RC: what a failed phase leaves at the end of the
# screen: its last 40 lines (cleaned and indented), then its last line on a
# line of its own, quoted and labelled. BUILD_STOP, the line die prints, holds
# only what the sitting itself knows (the step and the exit status): the
# build's text never goes in it, so a build can't end it with "Nothing was
# installed." and an instruction of its own (review of 2 Nov 2026). tar's two
# closing lines ("Exiting with failure status due to previous errors", "Error
# is not recoverable: exiting now") are passed over for the last line, because
# the line before them says what went wrong.
BUILD_STOP=''
build_failed() {
  local step=$1 phase=$2 rc=$3 log="$WORK/build-$2.log" last=''
  BUILD_STOP="the throwaway build failed in step $step of 2 ($phase), exit status $rc. Nothing was installed."
  if [ -e "$log.failed" ] || [ ! -e "$log" ]; then
    printf "\nThe build's messages could not be kept (writing %s failed), so they can't be shown again here; they are above.\n" "$log" >&2
    return 0
  fi
  if [ ! -s "$log" ]; then
    printf '\nlast build line: none (the build printed nothing)\n' >&2
    return 0
  fi
  printf "\nThe build's last 40 lines (step %s of 2, %s):\n" "$step" "$phase" >&2
  tail -n 40 -- "$log" | clean_text '  ' >&2
  last=$(clean_text <"$log" | grep -v -x -e 'tar: Exiting with failure status due to previous errors' -e 'tar: Error is not recoverable: exiting now' | awk 'NF { l = $0 } END { print l }')
  if [ -n "$last" ]; then
    # A quote or backslash in it is escaped, so the closing quote is the sitting's.
    printf 'last build line: "%s"\n' "$(printf '%s' "$last" | sed 's/[\\"]/\\&/g')" >&2
  else
    printf 'last build line: none (only blank lines)\n' >&2
  fi
}

run_build() {
  BUILD_STOP="I could not put the build's input together in $WORK (see above). Nothing was installed."
  cp -- "$HERE/files/build-in-sandbox.sh" "$WORK/build-in-sandbox.sh" || return 1
  tar -c -f "$WORK/fetch-input.tar" -C "$WORK" build-in-sandbox.sh source.tar || return 1
  sandbox_run fetch "build, step 1 of 2: fetching the Rust toolchain and the crates in a throwaway account (network on, but not to private address ranges or this machine's own global addresses)" \
    "$WORK/fetch-input.tar" "$WORK/fetched.tar" \
    -p "IPAddressDeny=$FETCH_DENY${HOST_ADDRS:+ $HOST_ADDRS}" -p "IPAddressAllow=$RESOLVERS" \
    -p TemporaryFileSystem=/run -p BindReadOnlyPaths=-/run/systemd/resolve || { build_failed 1 fetch $?; return 1; }
  tar -c -f "$WORK/compile-input.tar" -C "$WORK" build-in-sandbox.sh source.tar fetched.tar || return 1
  sandbox_run compile "build, step 2 of 2: compiling in a throwaway account with no network at all" \
    "$WORK/compile-input.tar" "$WORK/build.tar" \
    -p PrivateNetwork=yes -p TemporaryFileSystem=/run || { build_failed 2 compile $?; return 1; }
}

# Builds, then checks everything the sandbox handed back before root sees it.
build_programs() {
  local target arch
  arch=$(uname -m)
  case $arch in
    x86_64) target=x86_64-unknown-linux-gnu TOOLCHAIN_SHA256=$RUST_SHA256_X86_64 ;;
    aarch64) target=aarch64-unknown-linux-gnu TOOLCHAIN_SHA256=$RUST_SHA256_AARCH64 ;;
    *) die "there is no pinned Rust toolchain for this machine's architecture ($arch)." ;;
  esac
  TOOLCHAIN_URL=https://static.rust-lang.org/dist/rust-$RUST_VERSION-$target.tar.xz
  run_build || die "$BUILD_STOP"

  # Only the five programs (at the top, or under bin/), as plain files.
  local member name
  tar -tf "$WORK/build.tar" >"$WORK/build.list" 2>/dev/null || die "the build's output is not a tar archive. Nothing was installed."
  while IFS= read -r member; do
    member=${member#./}
    member=${member%/}
    case $member in
      '' | bin) ;;
      agent-sign | agent-signd | agent-launchd | agent-git | agent-ssh-sign) ;;
      bin/agent-sign | bin/agent-signd | bin/agent-launchd | bin/agent-git | bin/agent-ssh-sign) ;;
      *) die "the build's output holds something that isn't one of the five programs ($(one_line "$member")). Nothing was installed." ;;
    esac
  done <"$WORK/build.list"
  mkdir -p "$WORK/out"
  tar -xf "$WORK/build.tar" -C "$WORK/out" --no-same-owner --no-same-permissions
  for name in "${PROGRAMS[@]}"; do
    [ -f "$WORK/out/$name" ] && [ ! -L "$WORK/out/$name" ] && [ -s "$WORK/out/$name" ] \
      || die "the build did not produce $name as a plain file. Nothing was installed."
  done

  # A test build stands in for the device owner; installed, it would let anything
  # that can set an environment variable approve its own leases. The check is the
  # sitting's own reviewed copy (files/check-binary-clean.sh, kept identical to
  # scripts/check-binary-clean.sh by a test), never a script from the source: the
  # source is what is being judged, and its script would run as Taylor (A-3).
  # It only greps the programs; it never runs them.
  sh "$HERE/files/check-binary-clean.sh" "$WORK/out" >"$WORK/clean.out" 2>&1 \
    || die "check-binary-clean.sh refused the build: it contains a test stand-in. $(one_line "$(cat "$WORK/clean.out")") Nothing was installed."

  for name in "${PROGRAMS[@]}"; do
    printf '%s  bin/%s\n' "$(sha256sum <"$WORK/out/$name" | cut -d' ' -f1)" "$name"
  done >"$WORK/SHA256SUMS"
}

install_release() {
  local name
  as_root "making the release folders" install -d -m 0755 -o root -g root "$REL" "$REL/bin" "$REL/wrap" || return 1
  for name in "${PROGRAMS[@]}"; do
    as_root "installing $name" install -m 0755 -o root -g root "$WORK/out/$name" "$REL/bin/$name" || return 1
  done
  as_root "linking the git wrapper" ln -sfn ../bin/agent-git "$REL/wrap/git" || return 1
  # Written last: a release counts as installed only once its hashes are there.
  as_root "recording the programs' hashes" install -m 0644 -o root -g root "$WORK/SHA256SUMS" "$REL/SHA256SUMS"
}

switch_current() {
  as_root "pointing /opt/agent-sign/current at the new release" ln -sfn "$COMMIT" "$AS_OPT/current.new" || return 1
  as_root "switching /opt/agent-sign/current in one rename" mv -T -- "$AS_OPT/current.new" "$AS_OPT/current"
}

step_programs() {
  section "The programs: built in a throwaway account, installed root-owned"
  ensure_dir "$AS_OPT" 755 root root
  if release_installed; then
    keep "release $COMMIT is installed and every file matches its recorded hash"
  else
    change "build agent-sign $COMMIT in a throwaway account (no root, no Taylor; Rust $RUST_VERSION checked against its pinned hash)" build_programs
    change "install the five programs into $REL, root-owned, with their hashes" install_release
  fi
  local now
  now=$(readlink -- "$AS_OPT/current" 2>/dev/null || true)
  if [ "$now" = "$COMMIT" ]; then
    keep "/opt/agent-sign/current already points at $COMMIT"
  else
    [ -z "$now" ] || RESTART_NEEDED=1
    change "point /opt/agent-sign/current at $COMMIT (the previous release stays for undo)" switch_current
  fi
}

# ---------------------------------------------------------------- 2. accounts

ensure_system_account() { # NAME HOME WHAT
  local name=$1 home=$2 what=$3
  if account_exists "$name"; then
    keep "the account $name"
    return 0
  fi
  change "make the system account $name ($what; no password, no shell)" \
    as_root "making the account $name" useradd --system --user-group --no-create-home \
    --home-dir "$home" --shell /usr/sbin/nologin --comment "agent-sign - $what" "$name"
}

ensure_member() { # GROUP ACCOUNT
  if group_has_member "$1" "$2"; then
    keep "$2 is in the group $1"
    return 0
  fi
  RESTART_NEEDED=1
  change "put $2 in the group $1" as_root "adding $2 to the group $1" usermod -a -G "$1" "$2"
}

# deny_accounts FILE ACCOUNT...: adds the accounts to a deny list (never removes a line).
deny_accounts() {
  local file=$1 cur="$WORK/deny.cur" new="$WORK/deny.new" a mode=644 owner=root group=root st
  shift
  local missing=()
  if root_read_to "$file" "$cur"; then
    st=$(root_stat "$file") || st="644 root root"
    read -r mode owner group <<<"$st"
  elif [ "$file" = "$ETC/at.deny" ]; then
    keep "$file doesn't exist, so only root may use at: nothing to add"
    return 0
  else
    : >"$cur"
  fi
  for a in "$@"; do
    grep -qxF -- "$a" "$cur" || missing+=("$a")
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    keep "$file already lists the slot accounts"
    return 0
  fi
  {
    cat -- "$cur"
    if [ -s "$cur" ] && [ -n "$(tail -c1 "$cur")" ]; then echo; fi
    printf '%s\n' "${missing[@]}"
  } >"$new"
  change "add ${missing[*]} to $file (the session units' NoNewPrivileges already stop at and crontab; this is a second wall)" \
    as_root "adding the slot accounts to $file" install -m "$mode" -o "$owner" -g "$group" "$new" "$file"
  if [ "$DRY_RUN" = 1 ]; then show_diff "$file" "$cur" "$new"; fi
}

step_accounts() {
  section "Accounts: agent-sign, agent-launch and $SLOTS slot accounts (no shell, no password)"
  local i slot_names=()
  ensure_system_account agent-sign /var/lib/agent-sign "the service"
  ensure_system_account agent-launch /var/lib/agent-launch "the launcher"
  for i in $(seq 1 "$SLOTS"); do
    ensure_system_account "agent-slot-$i" /nonexistent "session slot $i"
    slot_names+=("agent-slot-$i")
  done
  # agent-launch reads what a session's end step leaves for it, through the slot's group.
  for i in $(seq 1 "$SLOTS"); do ensure_member "agent-slot-$i" agent-launch; done
  deny_accounts "$ETC/at.deny" "${slot_names[@]}"
  deny_accounts "$ETC/cron.deny" "${slot_names[@]}"
}

# ---------------------------------------------------------------- 3. folders

# The I/O folders (A-2). systemd opens the session units' files as ROOT, before
# it drops to the slot's account: LoadCredential= reads each slot's spec, and
# StandardOutput= appends to each slot's output file. Those opens follow links,
# so they must never be in a folder an account other than root can put an entry
# in (a compromised launcher could plant logs/N.out -> /etc/cron.d/x, and root
# would append a slot's output to it). So:
#   /var/lib/agent-launch-io, specs/ and logs/ are root's (0750, group
#   agent-launch: the launcher can enter and read, never make, rename or remove
#   an entry);
#   the sitting makes, as root, one plain file per slot in each (specs/N.json,
#   logs/N.out), owned by agent-launch, 0600; the launcher opens only those,
#   without following links and without creating anything (src/launcher, I-A2).
# An existing entry that isn't exactly that stops the sitting: it is not
# followed, replaced or removed.
io_entry_state() { # PATH: prints "absent", "ok", or what the entry is instead
  local st kind mode links owner
  st=$(as_root "looking at $1 (it must be a plain file this sitting made)" stat -c '%F|%a|%h|%U:%G' -- "$1" 2>/dev/null) || {
    echo absent
    return 0
  }
  IFS='|' read -r kind mode links owner <<<"$st"
  case $kind in
    'regular file' | 'regular empty file') ;;
    *)
      echo "it is a $kind, not a plain file"
      return 0
      ;;
  esac
  [ "$links" = 1 ] || { echo "it has $links hard links, not one"; return 0; }
  [ "$mode" = 600 ] || { echo "its mode is $mode, not 600"; return 0; }
  # Under a test root the stand-ins keep owners in a ledger; the real machine checks them.
  if [ -z "$ROOT" ] && [ "$owner" != agent-launch:agent-launch ]; then
    echo "its owner is $owner, not agent-launch:agent-launch"
    return 0
  fi
  echo ok
}

ensure_launcher_file() { # PATH
  local state
  state=$(io_entry_state "$1")
  case $state in
    ok) keep "$1 (a plain file, 600 agent-launch:agent-launch)" ;;
    absent)
      change "make the file $1 (empty, 600 agent-launch:agent-launch; systemd opens it as root by this exact path)" \
        as_root "making the launcher's file $1" install -m 0600 -o agent-launch -g agent-launch /dev/null "$1"
      ;;
    *) die "$1: $state. The launcher's I/O folder ($LAUNCH_IO) may hold only the plain files this sitting makes, so I won't follow, change, replace or remove it. Look at it, then run this again." ;;
  esac
}

ensure_io_dir() { # DIR
  if as_root "checking that $1 is not a link" test -L "$1"; then
    die "$1 is a link. The launcher's I/O folders must be real folders of root's. Look at it, then run this again."
  fi
  ensure_dir "$1" 750 root agent-launch
}

step_folders() {
  section "Folders for the slots and the launcher"
  local i
  ensure_dir "$SLOTS_ROOT" 755 root root
  ensure_dir "$LAUNCH_STATE" 700 agent-launch agent-launch
  ensure_dir_nolink "$LAUNCH_STATE/out" 700 agent-launch agent-launch
  ensure_io_dir "$LAUNCH_IO"
  ensure_io_dir "$LAUNCH_IO/specs"
  ensure_io_dir "$LAUNCH_IO/logs"
  for i in $(seq 1 "$SLOTS"); do
    # The slot's group lets agent-launch and the slot in, no one else; the Trash is
    # the launcher's alone, so a slot can't even enter it.
    ensure_dir "$SLOTS_ROOT/$i" 750 agent-launch "agent-slot-$i"
    ensure_dir_nolink "$SLOTS_ROOT/$i/trash" 700 agent-launch agent-launch
    ensure_launcher_file "$LAUNCH_IO/specs/$i.json"
    ensure_launcher_file "$LAUNCH_IO/logs/$i.out"
  done
}

# ---------------------------------------------------------------- 4. the login

# Takes the new login out of the way if a move failed half-way. These are the
# sitting's own unfinished files; the stored login is never touched until the
# new pair is complete and checked.
drop_new_login() {
  as_root "removing the unfinished new login files (the stored login is untouched)" rm -f -- "$STORED_SECRET.new" "$STORED_ROLE.new"
}

# Moves the delivered login into the system store (A-5). It is decrypted into
# this shell's memory (never an argument, a file or a log line), checked to
# have the right shape, encrypted into NEW files next to the stored ones, and
# only when that pair decrypts to the same secret is it moved over the stored
# login. The old pipeline encrypted straight over the stored file, so a login
# that couldn't be decrypted (an empty secret) or an encryption that failed
# half-way destroyed the good stored one.
move_login() {
  local plain a b
  plain=$(systemd-creds --user decrypt --name="openbao-$LOGIN_NAME" "$DELIVERED" - 2>/dev/null && printf x) || {
    say "  problem: the delivered login can't be decrypted; the stored login was not touched and the delivered one is kept."
    return 1
  }
  plain=${plain%x}
  if ! printf '%s' "$plain" | tr -d '\n' | grep -E '^[A-Za-z0-9._-]{16,200}$' >/dev/null; then
    say "  problem: the delivered login is empty or has the wrong shape; the stored login was not touched and the delivered one is kept."
    return 1
  fi
  drop_new_login || return 1
  printf '%s' "$plain" \
    | as_root "storing the OpenBao login as a new file first (the stored one stays until this one checks out)" systemd-creds encrypt --name=secret-id - "$STORED_SECRET.new" || {
    drop_new_login
    say "  problem: encrypting the new login failed; the stored login was not touched."
    return 1
  }
  printf '%s' "$LOGIN_NAME" \
    | as_root "storing the login's name as a new file first" systemd-creds encrypt --name=role-id - "$STORED_ROLE.new" || {
    drop_new_login
    say "  problem: encrypting the login's name failed; the stored login was not touched."
    return 1
  }
  as_root "limiting the new login files to root" chmod 600 -- "$STORED_SECRET.new" "$STORED_ROLE.new" || {
    drop_new_login
    return 1
  }
  a=$(printf '%s' "$plain" | sha256sum | cut -d' ' -f1)
  b=$(as_root "checking the new login file decrypts to the delivered secret (nothing is printed)" systemd-creds decrypt --name=secret-id "$STORED_SECRET.new" - 2>/dev/null | sha256sum | cut -d' ' -f1) || b=''
  if [ -z "$a" ] || [ "$a" != "$b" ] || ! login_pair_valid "$STORED_SECRET.new" "$STORED_ROLE.new"; then
    drop_new_login
    say "  problem: the new login file is not the delivered login (an encryption that wrote nothing or something else); the stored login was not touched."
    return 1
  fi
  swap_in_login || return 1
  # Only now, once the stored copy is checked, is the delivered one removed.
  rm -f -- "$DELIVERED"
}

# Replaces the stored pair (secret ID, role ID) with the new pair so that a stop
# at any point leaves the OLD pair whole (S6): two renames can't be one atomic
# step, so the old files are first kept as hard links (.old), and any failure
# puts them back. A new secret is never left paired with an old role.
swap_in_login() {
  local had_s=0 had_r=0 moved_s=0 moved_r=0
  as_root "clearing spare copies left by an earlier swap" rm -f -- "$STORED_SECRET.old" "$STORED_ROLE.old" || return 1
  if as_root "checking whether a stored secret ID exists" test -e "$STORED_SECRET"; then
    as_root "keeping the stored secret ID as a spare while the pair is replaced" ln -- "$STORED_SECRET" "$STORED_SECRET.old" || { restore_login_pair 0 0 0 0; return 1; }
    had_s=1
  fi
  if as_root "checking whether a stored role ID exists" test -e "$STORED_ROLE"; then
    as_root "keeping the stored role ID as a spare while the pair is replaced" ln -- "$STORED_ROLE" "$STORED_ROLE.old" || { restore_login_pair "$had_s" 0 0 0; return 1; }
    had_r=1
  fi
  as_root "putting the new login in place of the stored one" mv -f -- "$STORED_SECRET.new" "$STORED_SECRET" || { restore_login_pair "$had_s" "$had_r" 0 0; return 1; }
  moved_s=1
  as_root "putting the login's name in place" mv -f -- "$STORED_ROLE.new" "$STORED_ROLE" || { restore_login_pair "$had_s" "$had_r" "$moved_s" 0; return 1; }
  moved_r=1
  stored_login_valid || { restore_login_pair "$had_s" "$had_r" "$moved_s" "$moved_r"; return 1; }
  as_root "dropping the spare copies of the earlier login" rm -f -- "$STORED_SECRET.old" "$STORED_ROLE.old" || return 1
}

# restore_login_pair HAD_SECRET HAD_ROLE MOVED_SECRET MOVED_ROLE: puts the stored
# pair back as it was after a failed swap (a file that was moved in is replaced by
# its spare, or removed when there was none), then removes the unfinished files.
# If even that fails, the spares are kept and named.
restore_login_file() { # FILE HAD_SPARE MOVED_IN
  [ "$3" = 1 ] || return 0
  if [ "$2" = 1 ]; then
    as_root "putting the earlier stored login file back" mv -f -- "$1.old" "$1"
  else
    as_root "removing the new login file that has no earlier one" rm -f -- "$1"
  fi
}
restore_login_pair() {
  local bad=0
  restore_login_file "$STORED_SECRET" "$1" "$3" || bad=1
  restore_login_file "$STORED_ROLE" "$2" "$4" || bad=1
  if [ "$bad" = 1 ]; then
    say "  problem: the stored login could not be fully put back; the earlier files are kept beside it as agent-sign.secret-id.old and agent-sign.role-id.old. Put them back by hand before running this again."
    return 1
  fi
  as_root "removing the unfinished and spare login files" rm -f -- "$STORED_SECRET.new" "$STORED_ROLE.new" "$STORED_SECRET.old" "$STORED_ROLE.old" || return 1
  say "  problem: replacing the stored login failed part-way; the earlier stored login was put back whole, and the delivered one is kept."
}

# Same secret in both places? Compared by hash, through pipes, printing nothing.
delivered_equals_stored() {
  local a b
  a=$(systemd-creds --user decrypt --name="openbao-$LOGIN_NAME" "$DELIVERED" - 2>/dev/null | sha256sum | cut -d' ' -f1) || return 1
  b=$(as_root "comparing the stored login with the delivered one (nothing is printed)" systemd-creds decrypt --name=secret-id "$STORED_SECRET" - 2>/dev/null | sha256sum | cut -d' ' -f1) || return 1
  [ -n "$a" ] && [ "$a" = "$b" ]
}

step_login() {
  section "The OpenBao login: from $ADMIN's account into the system credential store, by pipe"
  ensure_parent "$CREDSTORE" 700
  if [ "$LOGIN_AWAITED" = 1 ]; then
    say "  after the login is delivered: move the $LOGIN_NAME login into /etc/credstore.encrypted (by pipe), and add its name to the public list of installed logins"
    return 0
  fi
  if [ -s "$DELIVERED" ]; then
    if stored_login_present && stored_login_valid && delivered_equals_stored; then
      change "remove $ADMIN's delivered copy of the login (the stored one is the same)" rm -f -- "$DELIVERED"
    else
      change "move the $LOGIN_NAME login into /etc/credstore.encrypted (encrypted for this machine; the delivered copy is removed once the stored one checks out)" move_login
    fi
  elif stored_login_present && stored_login_valid; then
    keep "the $LOGIN_NAME login is stored (right shape, nothing delivered is left in $ADMIN's account)"
  else
    die "the stored OpenBao login is missing or has the wrong shape, and no new one was delivered."
  fi
  # Where the suite keeps a public list of installed logins, add ours (names only).
  if [ -d "$ETC/suite" ]; then
    local cur="$WORK/installed-logins.cur" new="$WORK/installed-logins.new"
    root_read_to "$ETC/suite/installed-logins" "$cur" || : >"$cur"
    { cat -- "$cur"; echo "$LOGIN_NAME"; } | sort -u >"$new"
    install_file "the public list of installed logins (names only)" "$new" "$ETC/suite/installed-logins" 644 root root
  else
    keep "there is no /etc/suite on this machine, so no list of installed logins to add to"
  fi
}

# ---------------------------------------------------------------- 5. trust

set_system_git() {
  as_root "pointing git's system settings at the trust file" /usr/bin/env -i PATH=/usr/bin:/bin "$GIT" config --system gpg.ssh.allowedSignersFile "$TRUST_REAL" || return 1
  # root's umask here is private; git must be readable by everyone.
  as_root "making /etc/gitconfig readable by everyone" chmod 644 -- "$ETC/gitconfig"
}

step_trust() {
  section "Trust: root's allowed_signers holds exactly OpenBao's CA, and git is pointed at it"
  ensure_dir "$AS_ETC" 755 root root
  if [ -z "$CA_KEY" ]; then
    say "  after the login is delivered: root's trust file (one CA line, OpenBao's) and git's setting that points at it; OpenBao's SSH engine has no CA key yet"
    return 0
  fi
  {
    echo "# agent-sign: the only certificate authority trusted on this machine, and root's."
    echo "# Written by agent-sign's sitting from OpenBao's $AUTH_MOUNT/public_key; do not edit."
    echo "# Scoped to this machine's agents by the principal pattern and by the CA itself."
    printf '*@%s.agents.local cert-authority,namespaces="git" %s\n' "$MACHINE" "$CA_KEY"
  } >"$WORK/allowed_signers"
  install_file "root's trust file: one CA line, OpenBao's" "$WORK/allowed_signers" "$AS_ETC/allowed_signers" 644 root root
  local now
  now=$("$GIT" config --system --get gpg.ssh.allowedSignersFile 2>/dev/null || true)
  if [ "$now" = "$TRUST_REAL" ] && path_state_ok "$ETC/gitconfig" 644 root root; then
    keep "/etc/gitconfig points git's gpg.ssh.allowedSignersFile at $TRUST_REAL"
  else
    change "set gpg.ssh.allowedSignersFile = $TRUST_REAL in /etc/gitconfig (every account's git, unless it sets its own)" set_system_git
  fi
}

# ---------------------------------------------------------------- 6. units, 7. polkit rule, 8. settings

step_units() {
  section "systemd units: the service, the launcher, and the two session templates"
  local u src reload=0
  for u in "${UNITS[@]}"; do
    src=$HERE/files/$u
    # The two slot units carry the slot limits; the flags (already checked to be
    # a percentage, a size or a number) are written over the files' defaults.
    case $u in
      agent-session@.service | agent-session-end@.service)
        src=$WORK/unit-$u
        sed -e "s|^MemoryMax=.*|MemoryMax=${SLOT_MEMORY_MAX:-50%}|" -e "s|^TasksMax=.*|TasksMax=${SLOT_TASKS_MAX:-15%}|" "$HERE/files/$u" >"$src"
        ;;
    esac
    install_file "systemd unit" "$src" "$SYSTEMD_DIR/$u" 644 root root
    if [ "$FILE_CHANGED" = 1 ]; then reload=1; fi
  done
  # A file changed by an earlier, stopped run may be on disk and not yet loaded.
  for u in "${UNITS[@]}"; do
    if [ "$(systemctl show -p NeedDaemonReload --value "$u" 2>/dev/null || true)" = yes ]; then reload=1; fi
  done
  if [ "$reload" = 1 ]; then
    change "tell systemd about the new units (systemctl daemon-reload)" as_root "telling systemd about the new units" systemctl daemon-reload
  else
    keep "systemd already knows these units"
  fi
}

step_polkit() {
  section "polkit: the launcher may start and stop the slots' session units, and nothing else"
  render "$HERE/files/50-agent-launch.rules.in" "$WORK/50-agent-launch.rules" \
    SLOTS "$SLOTS" SLOT_NUMBERS "$(seq -s'|' 1 "$SLOTS")"
  install_file "the polkit rule for $SLOTS slots" "$WORK/50-agent-launch.rules" "$POLKIT_RULE" 644 root root
}

# system.toml: its existence means system mode, so from the moment it is there
# one-account launch is refused on this machine. It is therefore placed only
# after the installed program has been seen to run (program_runs), and a start
# that then fails puts the machine back (rollback_settings). It can't be placed
# after the service is healthy: the service reads it to start in system mode, and
# `agent-sign doctor` reports the CA match only in system mode (A-10).
place_settings() {
  local clients="\"agents\"" people="\"$ADMIN\""
  [ "$ADMIN" = agents ] || clients="$clients, \"$ADMIN\""
  render "$HERE/files/system.toml.in" "$WORK/system.toml" \
    MACHINE "$MACHINE" SLOTS "$SLOTS" CLIENT_ACCOUNTS "$clients" PEOPLE_ACCOUNTS "$people" \
    IDENTITY_PEOPLE "$IDENTITY_PEOPLE" AUTH_ADDRESS "$AUTH_ADDRESS" AUTH_CA_CERT "$AUTH_CA_CERT" \
    AUTH_RESOLVE "$AUTH_RESOLVE" AUTH_MOUNT "$AUTH_MOUNT" AUTH_ROLE "$AUTH_ROLE"
  install_file "this machine's settings ($SLOTS slots)" "$WORK/system.toml" "$AS_ETC/system.toml" 644 root root
  if [ "$FILE_CHANGED" = 1 ]; then
    RESTART_NEEDED=1
    SETTINGS_PLACED=1
  fi
}

# Puts system.toml back as it was before this run (or aside, when there was none)
# and stops the units, so a service that never became healthy doesn't leave the
# machine refusing one-account launches. Run by die (DIE_CLEANUP), so it only
# says what it did.
rollback_settings() {
  local todo=() u
  echo "Rolling back: this run placed system.toml, but the service did not start healthy. Putting it back as it was, so one-account launch works again." >&2
  for u in agent-launchd.service agent-launchd.socket agent-signd.service agent-signd-launcher.socket agent-signd.socket; do
    if systemctl is-active --quiet "$u" 2>/dev/null || systemctl is-enabled --quiet "$u" 2>/dev/null; then todo+=("$u"); fi
  done
  if [ "${#todo[@]}" -gt 0 ]; then
    as_root "stopping and disabling the units of a start that failed" systemctl disable --now "${todo[@]}" || true
  fi
  if [ "$HAD_SETTINGS" = 1 ]; then
    as_root "putting the earlier system.toml back" install -m 0644 -o root -g root "$WORK/system.toml.now" "$AS_ETC/system.toml" || true
  else
    move_settings_aside || true
  fi
  # die would otherwise close with "Nothing after this point was changed", which
  # is false here: this rollback changed things back.
  DIE_CLOSING="Rolled back: the service units were stopped and disabled, and system.toml was restored to how it was before this run (or moved aside when there was none). If this was a rerun, the earlier deployment is down too until a run succeeds. Run the same command again once the cause is fixed: every step checks what is already done."
}

# render TEMPLATE OUT KEY VALUE...: fills @KEY@ in a template.
render() {
  local tpl=$1 out=$2 text k v
  shift 2
  text=$(cat -- "$tpl"; printf x)
  text=${text%x}
  while [ "$#" -ge 2 ]; do
    k=$1 v=$2
    shift 2
    text=${text//"@$k@"/$v}
  done
  printf '%s' "$text" >"$out"
  if grep -Eq '@[A-Z][A-Z_]*@' "$out"; then die "internal error: a placeholder in $tpl was not filled."; fi
}

# ---------------------------------------------------------------- 9. start

unit_up() { systemctl is-enabled --quiet "$1" 2>/dev/null && systemctl is-active --quiet "$1" 2>/dev/null; }

# bring_up UNIT: enabled and running; restarted first if what it reads changed.
bring_up() {
  local u=$1
  if unit_up "$u"; then
    if [ "$RESTART_NEEDED" = 1 ] && [[ $u == *.service ]]; then
      change "restart $u (its settings, programs or groups changed; its sessions end)" as_root "restarting $u" systemctl restart "$u"
    else
      keep "$u is enabled and running"
    fi
  else
    change "enable and start $u" as_root "starting $u" systemctl enable --now "$u"
  fi
}

# The installed agent-sign program asks the running service (Ping) and reports
# whether OpenBao's CA matches the trust file. forget_sudo first: this is a
# program built from the source, and it must not run while sudo's ticket is
# cached (A-3).
service_healthy() {
  local out
  forget_sudo
  # Its exit status is not used: doctor also warns about things that have
  # nothing to do with the service. The two lines are the contract.
  out=$("$CURRENT_BIN/agent-sign" doctor 2>&1 || true)
  grep -F 'ping: ok' <<<"$out" >/dev/null && grep -F 'authority: OpenBao CA matches the trust file' <<<"$out" >/dev/null
}

# The installed agent-sign starts and answers on this machine (before system.toml
# exists, so a program that can't run here never costs the machine its one-account
# launch). No sudo ticket while it runs (A-3).
program_runs() {
  forget_sudo
  "$CURRENT_BIN/agent-sign" --version >/dev/null 2>&1
}

step_start() {
  section "System settings, then the service and the launcher (system.toml is rolled back if the service isn't healthy)"
  if [ "$DRY_RUN" = 1 ]; then
    say "  would: run the installed agent-sign once (agent-sign --version) to see that it starts on this machine, before system.toml is placed"
  else
    program_runs \
      || die "the installed agent-sign ($CURRENT_BIN/agent-sign) didn't start on this machine, so the agent-sign service can't be started either. system.toml was not placed and nothing was started."
    say "  ok: the installed agent-sign starts on this machine"
  fi
  place_settings
  if [ "$DRY_RUN" = 0 ] && [ "$SETTINGS_PLACED" = 1 ]; then DIE_CLEANUP=rollback_settings; fi
  bring_up agent-signd.socket
  bring_up agent-signd-launcher.socket
  bring_up agent-signd.service
  if [ "$DRY_RUN" = 1 ]; then
    say "  would: wait until the service answers a ping and reports that OpenBao's CA matches the trust file"
  else
    wait_for 30 service_healthy \
      || die "agent-signd is running but didn't report a healthy OpenBao CA match within 30 seconds. See: $CURRENT_BIN/agent-sign doctor, and journalctl -u agent-signd. The agents' old service was not touched."
    say "  ok: the service answered, and OpenBao's CA matches the trust file"
  fi
  DIE_CLEANUP=''
  bring_up agent-launchd.socket
  bring_up agent-launchd.service
}

# ---------------------------------------------------------------- 10. D5: retire the old trust

BLOCK_B=0 BLOCK_E=0
# Finds the managed block in a copy of the agents' allowed_signers (BLOCK_B/E = its first and last line, 0 when none).
find_block() {
  local f=$1 nb ne
  BLOCK_B=0 BLOCK_E=0
  nb=$(grep -nxF -e "$BLOCK_BEGIN" "$f" | cut -d: -f1 || true)
  ne=$(grep -nxF -e "$BLOCK_END" "$f" | cut -d: -f1 || true)
  if [ -z "$nb" ] && [ -z "$ne" ]; then return 0; fi
  [[ $nb =~ ^[0-9]+$ ]] && [[ $ne =~ ^[0-9]+$ ]] && [ "$nb" -lt "$ne" ] \
    || die "the agents' allowed_signers has a broken agent-sign block (marks at lines '${nb//$'\n'/,}' and '${ne//$'\n'/,}'). I won't guess what to cut; fix it by hand."
  BLOCK_B=$nb BLOCK_E=$ne
}

# The agents' bin entries: name -> where it must link.
agents_link_wanted() {
  case $1 in
    agent-git) echo /opt/agent-sign/current/bin/agent-git ;;
    agent-sign) echo /opt/agent-sign/current/bin/agent-sign ;;
    agent-ssh-sign) echo /opt/agent-sign/current/bin/agent-ssh-sign ;;
    git) echo /opt/agent-sign/current/wrap/git ;;
  esac
}
AGENTS_BIN_NAMES=(agent-git agent-sign agent-signd agent-ssh-sign git)

# Root's saved copies of the agents' own files, for undo. The agents control
# these files, so nothing they write is ever used as a name, a path or a mode
# in root's manifest (A-1; the reviewer's exploit was a link whose target held a
# newline and a forged manifest line, which made --undo read /etc/shadow and
# write it into the agents' .gitconfig):
#   - the manifest has one line per label, `label|kind|mode|name`, and the only
#     labels are the fixed ones below;
#   - the name of a label's saved copy comes from saved_name (a fixed map), and
#     undo accepts a line only if its name is exactly that;
#   - a file's mode is what stat printed, and undo accepts only 3 or 4 octal digits;
#   - the agents' own user-level agent-signd.service, when it is a real file (M1),
#     is the label `user-unit`, saved like the other files (a name from
#     saved_name, a mode, a copy of root's); it is only in the manifest when the
#     file existed, so a machine without it keeps the seven lines;
#   - the same unit path, when it is a link to anything but /dev/null, is the label
#     `user-unit` with kind `link`: its target is saved as data like a bin link's
#     (read as the agents account, never followed by root), then the link is removed
#     so mask can place its own;
#   - a link's target is saved as DATA in a root file of its own (never in the
#     manifest), and a target with a newline, a `|` or a control character is
#     refused (check_agents_links_safe, at the start and again when saving).

# saved_name LABEL KIND: the one name under $SAVE that LABEL's copy has ("" for a
# label this sitting never writes).
saved_name() {
  case $1 in
    gitconfig) echo agents-gitconfig ;;
    allowed_signers) echo agents-allowed_signers ;;
    user-unit)
      if [ "$2" = link ]; then echo agents-user-unit.target; else echo agents-user-unit.service; fi
      ;;
    bin/agent-git | bin/agent-sign | bin/agent-signd | bin/agent-ssh-sign | bin/git)
      if [ "$2" = link ]; then echo "agents-bin/${1#bin/}.target"; else echo "agents-bin/${1#bin/}"; fi
      ;;
  esac
}

# link_target_safe TARGET: printable ASCII only (so no newline or control
# character), no `|`, not empty.
link_target_safe() { [[ $1 =~ ^[[:print:]]+$ ]] && [[ $1 != *'|'* ]]; }

# agents_link_target NAME: prints the target of the agents' bin link, then an x
# (so a trailing newline in the target isn't lost to command substitution).
agents_link_target() {
  as_user agents "reading where $AGENTS_BIN/$1 links" /usr/bin/readlink -- "$AGENTS_BIN/$1" && printf x
}

# The agents' user-level agent-signd.service, when it is a link: its target (then an x),
# read as the agents account, so root never follows the link.
agents_unit_link_target() {
  as_user agents "reading where the agents' agent-signd.service links" /usr/bin/readlink -- "$AGENTS_USER_UNIT" && printf x
}

# Refuses a link at the agents' unit path whose target can't be saved safely (M1, link case).
check_agents_unit_link_safe() {
  local target
  as_user agents "checking whether the agents' agent-signd.service is a link" /usr/bin/test -L "$AGENTS_USER_UNIT" || return 0
  target=$(agents_unit_link_target) || die "I couldn't read where the agents' agent-signd.service link points."
  target=${target%x}
  target=${target%$'\n'}
  link_target_safe "$target" \
    || die "the agents' agent-signd.service unit is a link whose target holds a newline, a '|' or another character I can't save safely ($(plain_text "$target")). Undo puts saved links back, so I refuse to save it, and I changed nothing. Look at the link, then run this again."
}

check_agents_links_safe() {
  local name target
  for name in "${AGENTS_BIN_NAMES[@]}"; do
    as_user agents "checking whether $AGENTS_BIN/$name is a link" /usr/bin/test -L "$AGENTS_BIN/$name" || continue
    target=$(agents_link_target "$name") || die "I couldn't read where the agents' $AGENTS_BIN/$name links."
    target=${target%x}
    target=${target%$'\n'} # the newline readlink itself adds
    link_target_safe "$target" \
      || die "the agents' $AGENTS_BIN/$name is a link whose target holds a newline, a '|' or another character I can't save safely ($(plain_text "$target")). Undo copies saved links back, so I refuse to save it, and I changed nothing. Look at the link, then run this again."
  done
  check_agents_unit_link_safe
}

# Copies of the agents' own files, as root's data, for undo. Read as the agents
# account (so a link they planted can't make root read something else), written
# by root, never overwritten once the SAVED marker exists.
save_agents_file() { # LABEL PATH
  local label=$1 path=$2 mode as
  as=$(saved_name "$label" file)
  if as_user agents "checking whether $path exists" /usr/bin/test -f "$path"; then
    mode=$(as_user agents "reading the mode of $path" /usr/bin/stat -c %a -- "$path") || return 1
    [[ $mode =~ ^[0-7]{3,4}$ ]] || return 1
    as_user agents "copying $path for root's saved copies" /usr/bin/cat -- "$path" >"$WORK/stage" || return 1
    as_root "saving a copy of $label" install -m 0600 -o root -g root "$WORK/stage" "$SAVE/$as" || return 1
    printf '%s|file|%s|%s\n' "$label" "$mode" "$as" >>"$WORK/manifest"
  else
    printf '%s|absent||\n' "$label" >>"$WORK/manifest"
  fi
}

save_agents_link() { # NAME
  local name=$1 target as
  as=$(saved_name "bin/$name" link)
  target=$(agents_link_target "$name") || return 1
  target=${target%x}
  target=${target%$'\n'}
  link_target_safe "$target" || die "the agents' $AGENTS_BIN/$name is a link whose target holds a newline, a '|' or another character I can't save safely. I refuse to save it. Look at the link, then run this again."
  printf '%s\n' "$target" >"$WORK/stage"
  as_root "saving where $name links" install -m 0600 -o root -g root "$WORK/stage" "$SAVE/$as" || return 1
  printf 'bin/%s|link||%s\n' "$name" "$as" >>"$WORK/manifest"
}

save_agents_state() {
  local name
  : >"$WORK/manifest"
  as_root "making root's folder for the saved copies" install -d -m 0700 -o root -g root "$SAVE_ROOT" "$SAVE" "$SAVE/agents-bin" || return 1
  save_agents_file gitconfig "$AGENTS_GITCONFIG" || return 1
  save_agents_file allowed_signers "$AGENTS_SIGNERS" || return 1
  for name in "${AGENTS_BIN_NAMES[@]}"; do
    if as_user agents "checking whether $AGENTS_BIN/$name is a link" /usr/bin/test -L "$AGENTS_BIN/$name"; then
      save_agents_link "$name" || return 1
    else
      save_agents_file "bin/$name" "$AGENTS_BIN/$name" || return 1
    fi
  done
  as_root "saving the manifest of the agents' saved files" install -m 0600 -o root -g root "$WORK/manifest" "$SAVE/manifest" || return 1
  printf 'saved by agent-sign-sitting for commit %s\n' "$COMMIT" >"$WORK/saved"
  as_root "marking the saved copies complete" install -m 0600 -o root -g root "$WORK/saved" "$SAVE/SAVED"
}

saved_marker_present() { as_root "checking whether the agents' files are already saved" test -f "$SAVE/SAVED"; }

# Reasons the D5 trust is not yet as it must be (empty output and status 0 when it is).
d5_trust_problem() {
  local origin expected lines
  origin=$(agents_git "checking which allowedSignersFile the agents' git uses" config --show-origin --get gpg.ssh.allowedSignersFile 2>&1) \
    || { echo "the agents' git has no allowedSignersFile at all (it should use $TRUST_REAL)"; return 1; }
  expected=$(printf 'file:/etc/gitconfig\t%s' "$TRUST_REAL")
  if [ "$origin" != "$expected" ]; then
    echo "the agents' git still takes allowedSignersFile from \"$(plain_text "$origin")\", not from /etc/gitconfig ($TRUST_REAL)"
    return 1
  fi
  lines=$(agents_cat "reading the trust file as the agents account" "$AS_ETC/allowed_signers" | grep -Ev '^[[:space:]]*(#|$)' || true)
  expected=$(printf '*@%s.agents.local cert-authority,namespaces="git" %s' "$MACHINE" "$CA_KEY")
  if [ "$lines" != "$expected" ]; then
    echo "$TRUST_REAL must hold exactly one line, OpenBao's CA for this machine's agents; it holds something else"
    return 1
  fi
  return 0
}

user_service_state() { # prints "ENABLED ACTIVE"
  local en act
  en=$(as_root "asking whether the agents' old agent-signd is enabled" systemctl --user -M agents@ is-enabled agent-signd.service 2>/dev/null || true)
  act=$(as_root "asking whether the agents' old agent-signd is running" systemctl --user -M agents@ is-active agent-signd.service 2>/dev/null || true)
  echo "${en:-unknown} ${act:-unknown}"
}
user_service_off() {
  local st
  st=$(user_service_state)
  [ "${st%% *}" = masked ] && [ "${st##* }" != active ]
}

# M1: the agents' old agent-signd.service is a real file in ~/.config/systemd/user,
# and `systemctl --user mask` refuses to mask over a real file ("File ... already
# exists", status 1; seen on hetzner's systemd 259). So, as the agents account:
# save the file for undo (a copy in root's folder, a `user-unit` line in root's
# manifest), check the saved copy is byte for byte the file, and only then remove
# the file, so mask can place its link to /dev/null. Undo unmasks and puts the
# file back. Works on a rerun too: a copy already saved is kept (the first one
# wins, like the other saved files), and a manifest saved before this change
# gets its line added. A link in that place: one to /dev/null is a mask already in
# place and is left alone; any other link (systemd's mask also fails over it) has
# its target saved as data (label `user-unit`, kind `link`), read as the agents
# account so root never follows it, and is removed the same way (save_and_remove_agents_unit_link).
save_and_remove_agents_unit_file() {
  local as mode
  if as_user agents "checking whether the agents' agent-signd.service is a link" /usr/bin/test -L "$AGENTS_USER_UNIT"; then
    save_and_remove_agents_unit_link
    return
  fi
  as_user agents "checking whether the agents have their own agent-signd.service file" /usr/bin/test -f "$AGENTS_USER_UNIT" || return 0
  as=$(saved_name user-unit file)
  mode=$(as_user agents "reading the mode of the agents' agent-signd.service" /usr/bin/stat -c %a -- "$AGENTS_USER_UNIT") || return 1
  [[ $mode =~ ^[0-7]{3,4}$ ]] || return 1
  if ! as_root "checking whether the agents' agent-signd.service is already saved" test -f "$SAVE/$as"; then
    as_user agents "copying the agents' agent-signd.service for root's saved copies" /usr/bin/cat -- "$AGENTS_USER_UNIT" >"$WORK/stage" || return 1
    as_root "saving a copy of the agents' agent-signd.service" install -m 0600 -o root -g root "$WORK/stage" "$SAVE/$as" || return 1
  fi
  if ! root_read_to "$SAVE/manifest" "$WORK/manifest"; then
    echo "root's manifest of saved files is missing, so the unit file can't be listed in it" >&2
    return 1
  fi
  if ! grep -q '^user-unit|' "$WORK/manifest"; then
    printf 'user-unit|file|%s|%s\n' "$mode" "$as" >>"$WORK/manifest"
    as_root "adding the agents' agent-signd.service to the manifest of saved files" install -m 0600 -o root -g root "$WORK/manifest" "$SAVE/manifest" || return 1
  fi
  # Remove only what is saved: the saved copy must be the file as it is now.
  root_read_to "$SAVE/$as" "$WORK/saved.unit" || return 1
  agents_cat "re-reading the agents' agent-signd.service" "$AGENTS_USER_UNIT" >"$WORK/cur.unit" 2>/dev/null || return 1
  if ! cmp -s "$WORK/saved.unit" "$WORK/cur.unit"; then
    echo "root's saved copy of the agents' agent-signd.service differs from the file now (they changed it after the first run). I won't remove a file that isn't saved as it is." >&2
    return 1
  fi
  as_user agents "removing the agents' own agent-signd.service file (saved; mask can't place its link over a real file)" /usr/bin/rm -f -- "$AGENTS_USER_UNIT"
}

save_and_remove_agents_unit_link() {
  local as target now
  as=$(saved_name user-unit link)
  target=$(agents_unit_link_target) || return 1
  target=${target%x}
  target=${target%$'\n'}
  link_target_safe "$target" || die "the agents' agent-signd.service unit is a link whose target holds a newline, a '|' or another character I can't save safely. I refuse to save it. Look at the link, then run this again."
  [ "$target" = /dev/null ] && return 0 # a mask already in place
  if ! root_read_to "$SAVE/manifest" "$WORK/manifest"; then
    echo "root's manifest of saved files is missing, so the unit link can't be listed in it" >&2
    return 1
  fi
  if ! grep -q '^user-unit|' "$WORK/manifest"; then
    printf '%s\n' "$target" >"$WORK/stage"
    as_root "saving where the agents' agent-signd.service links" install -m 0600 -o root -g root "$WORK/stage" "$SAVE/$as" || return 1
    printf 'user-unit|link||%s\n' "$as" >>"$WORK/manifest"
    as_root "adding the agents' agent-signd.service link to the manifest of saved files" install -m 0600 -o root -g root "$WORK/manifest" "$SAVE/manifest" || return 1
    # Remove only what is saved: the link must still point where the saved target says.
    now=$(agents_unit_link_target) || return 1
    now=${now%x}
    now=${now%$'\n'}
    if [ "$now" != "$target" ]; then
      echo "the agents' agent-signd.service link changed while I saved it. I won't remove a link that isn't saved as it is." >&2
      return 1
    fi
  fi
  as_user agents "removing the agents' agent-signd.service link (its target is saved; mask can't place its link over it)" /usr/bin/rm -f -- "$AGENTS_USER_UNIT"
}

retire_user_service() {
  check_agents_unit_link_safe
  as_root "stopping the agents' old agent-signd" systemctl --user -M agents@ stop agent-signd.service || return 1
  as_root "disabling the agents' old agent-signd" systemctl --user -M agents@ disable agent-signd.service || return 1
  save_and_remove_agents_unit_file || return 1
  as_root "masking the agents' old agent-signd so nothing starts it again" systemctl --user -M agents@ mask agent-signd.service
}

step_retire_old_trust() {
  section "D5: remove the old trust the agents can write, and stop their old service"
  local name want have stale=() need_save=0 do_unset=0 do_block=0 do_program=0 do_service=0

  have=$(agents_git "reading the agents' git settings" config --global --get gpg.ssh.allowedSignersFile 2>/dev/null || true)
  [ -z "$have" ] || do_unset=1
  if agents_cat "reading the agents' allowed_signers" "$AGENTS_SIGNERS" >"$WORK/agents-signers" 2>/dev/null; then
    find_block "$WORK/agents-signers"
    [ "$BLOCK_B" -eq 0 ] || do_block=1
  fi
  have=$(agents_git "reading the agents' git settings" config --global --get gpg.ssh.program 2>/dev/null || true)
  [ "$have" = "$AGENT_PROGRAM_REAL" ] || do_program=1
  if as_user agents "checking the agents' bin folder" /usr/bin/test -d "$AGENTS_BIN"; then
    for name in "${AGENTS_BIN_NAMES[@]}"; do
      want=$(agents_link_wanted "$name")
      if [ -n "$want" ]; then
        have=$(as_user agents "reading where $AGENTS_BIN/$name links" /usr/bin/readlink -- "$AGENTS_BIN/$name" 2>/dev/null || true)
        [ "$have" = "$want" ] || stale+=("$name")
      elif as_user agents "checking for the old $name copy" /usr/bin/test -e "$AGENTS_BIN/$name"; then
        stale+=("$name") # agent-signd: removed, not linked back
      fi
    done
  fi
  user_service_off || do_service=1

  if [ "$do_unset$do_block$do_program$do_service" = 0000 ] && [ "${#stale[@]}" -eq 0 ]; then
    keep "the agents' own trust, program settings and bin links are already retired"
  else
    if saved_marker_present; then
      keep "root's saved copies of the agents' git config, allowed_signers and bin copies exist (for undo)"
    else
      change "save copies of the agents' git config, allowed_signers and bin copies in $SAVE (root's, for undo)" save_agents_state
    fi
  fi

  if [ "$do_unset" = 1 ]; then
    change "remove gpg.ssh.allowedSignersFile from the agents' global git config (git then uses /etc/gitconfig's)" \
      agents_git "removing the agents' own allowedSignersFile setting" config --global --unset-all gpg.ssh.allowedSignersFile
  fi
  if [ "$do_block" = 1 ]; then
    sed "${BLOCK_B},${BLOCK_E}d" "$WORK/agents-signers" >"$WORK/agents-signers.expected"
    change "remove agent-sign's managed block of certificate authorities (lines $BLOCK_B to $BLOCK_E) from the agents' allowed_signers, keeping every other line" \
      as_user agents "removing agent-sign's block from the agents' allowed_signers" /usr/bin/sed -i -e "${BLOCK_B},${BLOCK_E}d" -- "$AGENTS_SIGNERS"
  fi
  if [ "$do_program" = 1 ]; then
    change "point the agents' gpg.ssh.program at the reviewed build ($AGENT_PROGRAM_REAL)" \
      agents_git "pointing the agents' signing program at the reviewed build" config --global gpg.ssh.program "$AGENT_PROGRAM_REAL"
  fi
  for name in "${stale[@]}"; do
    want=$(agents_link_wanted "$name")
    if [ -n "$want" ]; then
      change "replace the agents' plain copy of $name with a link to $want" \
        as_user agents "linking the agents' $name to the reviewed build" /usr/bin/ln -sfn -- "$want" "$AGENTS_BIN/$name"
    else
      change "remove the agents' old plain copy of $name (saved for undo; not linked back)" \
        as_user agents "removing the agents' old $name copy" /usr/bin/rm -f -- "$AGENTS_BIN/$name"
    fi
  done
  if [ "$do_service" = 1 ]; then
    change "stop, disable and mask the agents' old user-level agent-signd.service (the new service answered first)" retire_user_service
  fi

  # Checked, not assumed.
  if [ "$DRY_RUN" = 1 ]; then
    say "  would: check, as the agents account, that git trusts only $TRUST_REAL from /etc/gitconfig and that the old agent-signd is off"
    return 0
  fi
  local problem
  problem=$(d5_trust_problem) || die "D5: $problem. The agents' own allowedSignersFile is still in force."
  if [ "$do_block" = 1 ]; then
    agents_cat "re-reading the agents' allowed_signers" "$AGENTS_SIGNERS" >"$WORK/agents-signers.after" 2>/dev/null || true
    cmp -s "$WORK/agents-signers.after" "$WORK/agents-signers.expected" \
      || die "D5: the agents' allowed_signers is not what it should be after removing agent-sign's block (the block marks or other lines differ)."
  fi
  user_service_off || die "D5: the agents' old user-level agent-signd is still running or not masked (enabled/active: $(user_service_state)). It could still sign with a key the agents can write."
  say "  ok: as the agents account, git trusts only $TRUST_REAL; the old agent-signd is off"
}

# ---------------------------------------------------------------- 11. a probe session

probe_running() {
  local i
  for i in $(seq 1 "$SLOTS"); do
    if systemctl is-active --quiet "agent-session@$i.service" 2>/dev/null; then return 0; fi
  done
  return 1
}

start_probe() {
  forget_sudo
  # Detached: it must outlive this script and its terminal. From / so that no
  # repository goes with it. "codex" is one of the built-in agent names; the
  # service certifies no other name unless system.toml lists it.
  (cd / && setsid nohup "$CURRENT_BIN/agent-sign" launch --agent codex -- /usr/bin/sleep 3600 >/dev/null 2>&1 </dev/null &)
  wait_for 30 probe_running
}

step_probe() {
  section "A probe session for the sitting tests (left running for an hour)"
  if [ -n "$ROOT" ]; then
    say "  skipped: a session needs real accounts and units; not made under a test root"
  elif probe_running; then
    keep "a launched session is already running"
  else
    change "start a probe session as $ADMIN (agent-sign launch --agent codex -- sleep 3600) so an agent can run the six sitting tests" start_probe
  fi
}

# ---------------------------------------------------------------- the checks at the end

svc_ok() { # UNIT ACCOUNT: unit file runs as ACCOUNT, is active, has never restarted
  [ "$(systemctl show -p User --value "$1")" = "$2" ] \
    && [ "$(systemctl show -p ActiveState --value "$1")" = active ] \
    && [ "$(systemctl show -p NRestarts --value "$1")" = 0 ]
}
units_up() { local u; for u in "$@"; do unit_up "$u" || return 1; done; }
templates_idle() {
  local u
  for u in 'agent-session@.service' 'agent-session-end@.service'; do
    [ ! -e "$SYSTEMD_DIR/$u" ] && return 1
    # A template with no [Install] section answers "static" (and exit 0), which is fine.
    [ "$(systemctl is-enabled "$u" 2>/dev/null || true)" = enabled ] && return 1
    systemctl is-active --quiet "$u" 2>/dev/null && return 1
  done
  return 0
}
programs_ok() {
  (cd "$REL" && sha256sum --check --quiet --strict SHA256SUMS) \
    && [ "$(readlink -- "$AS_OPT/current")" = "$COMMIT" ] \
    && [ "$(readlink -- "$REL/wrap/git")" = ../bin/agent-git ]
}
accounts_ok() {
  local i
  for i in agent-sign agent-launch $(seq -f 'agent-slot-%g' 1 "$SLOTS"); do
    account_exists "$i" && check_existing_account_quiet "$i" || return 1
  done
}
check_existing_account_quiet() {
  local line uid shell
  line=$(getent passwd "$1") || return 1
  IFS=: read -r _ _ uid _ _ _ shell <<<"$line"
  [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ] && case $shell in */nologin | /bin/false | /usr/bin/false) true ;; *) false ;; esac
}
trust_file_ok() {
  local lines
  lines=$(grep -Ev '^[[:space:]]*(#|$)' "$AS_ETC/allowed_signers") || return 1
  [ "$lines" = "$(printf '*@%s.agents.local cert-authority,namespaces="git" %s' "$MACHINE" "$CA_KEY")" ] \
    && path_state_ok "$AS_ETC/allowed_signers" 644 root root
}
settings_ok() {
  local f="$WORK/system.toml.final"
  root_read_to "$AS_ETC/system.toml" "$f" && toml_parses "$f" \
    && [ "$(toml_value "$f" '' machine)" = "$MACHINE" ] \
    && [ "$(toml_value "$f" slots count)" = "$SLOTS" ] \
    && [ "$(toml_value "$f" authority issuer)" = openbao ] \
    && path_state_ok "$AS_ETC/system.toml" 644 root root
}
polkit_rule_ok() {
  # polkit's rules folder is closed to everyone but root and polkitd.
  root_read_to "$POLKIT_RULE" "$WORK/rule.final" \
    && grep -F "agent-session(-end)?@($(seq -s'|' 1 "$SLOTS"))" "$WORK/rule.final" >/dev/null \
    && path_state_ok "$POLKIT_RULE" 644 root root
}
login_ok() {
  stored_login_present && stored_login_valid && path_state_ok "$STORED_SECRET" 600 root root && path_state_ok "$STORED_ROLE" 600 root root \
    && [ ! -e "$DELIVERED" ]
}
folders_ok() {
  local i
  path_state_ok "$SLOTS_ROOT" 755 root root && path_state_ok "$LAUNCH_STATE" 700 agent-launch agent-launch || return 1
  path_state_ok "$LAUNCH_IO" 750 root agent-launch && path_state_ok "$LAUNCH_IO/specs" 750 root agent-launch \
    && path_state_ok "$LAUNCH_IO/logs" 750 root agent-launch || return 1
  for i in $(seq 1 "$SLOTS"); do
    path_state_ok "$SLOTS_ROOT/$i" 750 agent-launch "agent-slot-$i" && path_state_ok "$SLOTS_ROOT/$i/trash" 700 agent-launch agent-launch || return 1
    [ "$(io_entry_state "$LAUNCH_IO/specs/$i.json")" = ok ] && [ "$(io_entry_state "$LAUNCH_IO/logs/$i.out")" = ok ] || return 1
  done
}
deny_lists_ok() {
  local i
  # at.deny is usually root:daemon 0640, so both lists are read through sudo.
  root_read_to "$ETC/cron.deny" "$WORK/cron.deny.final" || return 1
  if root_read_to "$ETC/at.deny" "$WORK/at.deny.final"; then
    for i in $(seq 1 "$SLOTS"); do grep -qxF "agent-slot-$i" "$WORK/at.deny.final" || return 1; done
  fi
  for i in $(seq 1 "$SLOTS"); do grep -qxF "agent-slot-$i" "$WORK/cron.deny.final" || return 1; done
}
agents_trust_ok() { d5_trust_problem >/dev/null; }
agents_block_gone() {
  local f="$WORK/agents-signers.final"
  if agents_cat "re-reading the agents' allowed_signers" "$AGENTS_SIGNERS" >"$f" 2>/dev/null; then
    ! grep -qF -e "$BLOCK_BEGIN" -e "$BLOCK_END" -e cert-authority "$f"
  fi
}
agents_program_ok() {
  [ "$(agents_git "reading the agents' signing program" config --global --get gpg.ssh.program)" = "$AGENT_PROGRAM_REAL" ]
}
agents_links_ok() {
  local name want
  for name in "${AGENTS_BIN_NAMES[@]}"; do
    want=$(agents_link_wanted "$name")
    if [ -n "$want" ]; then
      [ "$(as_user agents "reading where $AGENTS_BIN/$name links" /usr/bin/readlink -- "$AGENTS_BIN/$name")" = "$want" ] || return 1
    else
      ! as_user agents "checking the old $name copy is gone" /usr/bin/test -e "$AGENTS_BIN/$name" || return 1
    fi
  done
}

# Checks that need a real kernel, real accounts, polkit or live sessions. They
# run on the real machine; under a test root they are named and skipped.
real_checks() {
  local why='needs the real kernel, accounts and polkit; not made under a test root'
  if [ -n "$ROOT" ]; then
    skip "the service process runs as agent-sign" "$why"
    skip "the agents account can't restart the service or the launcher" "$why"
    skip "the agents account can't read the service's state or change the trust file" "$why"
    skip "the agents account can't launch a session" "$why"
    skip "the launcher can only do what the polkit rule says" "$why"
    skip "the launcher can't make, rename or remove an entry in its I/O folders" "$why"
    skip "the probe session is running" "$why"
    skip "a launched session signs Good, and its bundle comes back" "$why"
    skip "D6: a session in one slot can't read another slot's folder" "$why"
    skip "D6: the next session in a slot finds no leftovers; the old files are in the Trash and logged" "$why"
  else
    check "the service process runs as agent-sign" service_process_ok
    check "the agents account can't restart the service or the launcher" agents_cant_restart
    check "the agents account can't read the service's state or change the trust file" agents_cant_touch_state
    check "the agents account can't launch a session" agents_cant_launch
    check "the launcher can only do what the polkit rule says" launcher_limits_ok
    check "the launcher can't make, rename or remove an entry in its I/O folders" launcher_io_closed
    check "the probe session is running" probe_running
    check "a launched session signs Good, and its bundle comes back" launched_session_signs_good
    check "D6: a session in one slot can't read another slot's folder" slots_cant_see_each_other
    check "D6: the next session in a slot finds no leftovers; the old files are in the Trash and logged" slot_leftovers_trashed
  fi
}

# The launch checks start real sessions through the installed launcher, as the
# administrator (a person's account in system.toml).

# git for the throwaway repository: no personal git settings (so no signing
# prompt), the system settings kept (they hold the trust file).
plain_git() { env GIT_CONFIG_GLOBAL=/dev/null git "$@"; }

# A session commits in its copy of a throwaway repository; the commit that comes
# back must verify against the trust file, in the administrator's own repository.
launched_session_signs_good() {
  local repo ref
  forget_sudo
  repo=$(mktemp -d "$WORK/launch-repo.XXXXXX") || return 1
  plain_git -C "$repo" init -q -b main || return 1
  plain_git -C "$repo" -c user.name=sitting -c user.email=sitting@localhost -c commit.gpgsign=false commit -q --allow-empty -m "base" || return 1
  (cd "$repo" && /usr/bin/timeout 120 "$CURRENT_BIN/agent-sign" launch --agent codex -- /bin/sh -c 'git commit --allow-empty -q -m "sitting check"') || return 1
  ref=$(plain_git -C "$repo" for-each-ref --format='%(refname)' 'refs/heads/session/*' | head -n 1)
  [ -n "$ref" ] && plain_git -C "$repo" verify-commit "$ref"
}

# While the probe runs in one slot, a second session sees only its own slot's
# folder, and none of the launcher's.
slots_cant_see_each_other() {
  local out
  forget_sudo
  probe_running || return 1
  out=$(cd / && /usr/bin/timeout 120 "$CURRENT_BIN/agent-sign" launch --agent codex -- /bin/sh -c 'n=0; for d in /var/lib/agent-slots/*; do n=$((n+1)); done; echo "visible=$n"; if ls /var/lib/agent-launch >/dev/null 2>&1; then echo LEAK; fi' 2>&1) || return 1
  grep -Fx 'visible=1' <<<"$out" >/dev/null && ! grep -Fx LEAK <<<"$out" >/dev/null
}

# Two sessions in a row in the same slot: the second finds none of the first
# one's files, the first one's folder is in the Trash, and the launcher logged it.
slot_leftovers_trashed() {
  local out1 out2 slot1 slot2 trash
  forget_sudo
  # The first session leaves a file in its temp folder, its home's parent and the
  # slot's /dev/shm, and tries to put a key in the user keyring (@u). The unit's
  # filter denies the keyring calls, so the attempt is expected to fail; it is
  # tried anyway so that a unit that lost the filter is caught by the second
  # session. The second session must find none of them. It reads /proc/keys
  # whether or not keyctl exists, because keyctl itself is denied in the slot.
  out1=$(cd / && /usr/bin/timeout 120 "$CURRENT_BIN/agent-sign" launch --agent codex -- /bin/sh -c 'touch "$TMPDIR/leftover-sitting" "$HOME/../leftover-sitting" /dev/shm/leftover-sitting; if command -v keyctl >/dev/null 2>&1; then keyctl add user leftover-sitting x @u >/dev/null 2>&1; else echo "keyctl is not installed: the key in @u cannot be tried"; fi; true' 2>&1) || return 1
  out2=$(cd / && /usr/bin/timeout 120 "$CURRENT_BIN/agent-sign" launch --agent codex -- /bin/sh -c 'found=0; if [ -e "$TMPDIR/leftover-sitting" ] || [ -e "$HOME/../leftover-sitting" ] || [ -e /dev/shm/leftover-sitting ]; then found=1; fi; if command -v keyctl >/dev/null 2>&1; then if keyctl search @u user leftover-sitting >/dev/null 2>&1; then found=1; fi; else echo "keyctl is not installed: looking in /proc/keys only"; fi; if grep -q leftover-sitting /proc/keys 2>/dev/null; then found=1; fi; if [ "$found" = 1 ]; then echo LEFTOVER; else echo fresh; fi' 2>&1) || return 1
  slot1=$(sed -n 's/.* in slot \([0-9][0-9]*\):.*/\1/p' <<<"$out1" | head -n 1)
  slot2=$(sed -n 's/.* in slot \([0-9][0-9]*\):.*/\1/p' <<<"$out2" | head -n 1)
  [ -n "$slot1" ] && [ "$slot1" = "$slot2" ] || return 1
  grep -Fx fresh <<<"$out2" >/dev/null && ! grep -Fx LEFTOVER <<<"$out2" >/dev/null || return 1
  trash=$(as_root "listing the Trash of slot $slot1" ls -A -- "$SLOTS_ROOT/$slot1/trash") && [ -n "$trash" ] || return 1
  as_root "checking sessions.log names slot $slot1" grep -Eq "\"slot\": ?$slot1[,}]" "$LAUNCH_STATE/sessions.log"
}

service_process_ok() {
  local pid
  pid=$(systemctl show -p MainPID --value agent-signd.service)
  [ "$pid" -gt 0 ] && [ "$(ps -o user= -p "$pid" | tr -d ' ')" = agent-sign ]
}
# pkcheck asks polkit without acting, so a check can never do the thing it checks
# for. Its exit status is polkit's answer: 0 yes, 1 no, 2 it would ask for a
# password. Any other status (pkcheck missing, sudo refused) is neither, so it
# counts as neither a yes nor a no (A-7: a "refused" check that passes whenever the
# command fails for any reason proves nothing).
polkit_status() { # ACCOUNT UNIT VERB
  as_user "$1" "asking polkit whether $1 may $3 $2 (it only asks)" /bin/sh -c \
    'pkcheck --action-id org.freedesktop.systemd1.manage-units --process $$ --detail unit "$1" --detail verb "$2" >/dev/null 2>&1; echo "$?"' sh "$2" "$3"
}
polkit_allows() { [ "$(polkit_status "$@")" = 0 ]; }
polkit_refuses() { case $(polkit_status "$@") in 1 | 2) true ;; *) false ;; esac; }
agents_cant_restart() {
  polkit_refuses agents agent-signd.service restart && polkit_refuses agents agent-launchd.service restart
}
agents_cant_touch_state() {
  ! as_user agents "checking the agents account can't read the service's state" /usr/bin/stat /var/lib/agent-sign/.agent-sign \
    && ! as_user agents "checking the agents account can't write the trust file" /usr/bin/test -w "$TRUST_REAL"
}
# The launcher must refuse the agents' account itself: a non-zero exit alone could
# be a missing socket or a typo. So the output must carry the launcher's OWN
# refusal text, and only that (S1 / A-7). The launcher says one of two things:
# "uid N isn't a person's account ... may launch only with a signed launch
# approval" (src/bin/agent_launchd.rs) or "launch approval refused: ..."
# (src/launch_approval.rs). The bare word "refused" is not enough: "Connection
# refused" (the launcher is down) contains it, and a dead launcher refuses
# nobody. Tested with stand-in output (tests/test_sitting_script.rs, s1_*).
agents_cant_launch() {
  local out rc=0
  out=$(as_user agents "trying to launch a session as the agents account (it must be refused)" /usr/bin/timeout 30 "$CURRENT_BIN/agent-sign" launch --agent codex -- /bin/sh -c 'echo probe' 2>&1) || rc=$?
  [ "$rc" -ne 0 ] || return 1
  ! grep -Fx probe <<<"$out" >/dev/null && grep -Eiq "isn't a person's account|launch approval refused" <<<"$out"
}
# A transient unit as root, tried as the launcher, is refused by polkit (or, for a
# name that already is a unit, by systemd); the output must say so.
transient_refused() { # UNIT
  local out
  out=$(as_user agent-launch "trying a transient unit $1 with User=root as the launcher (it must be refused)" /usr/bin/systemd-run --no-ask-password --quiet --unit="$1" -p User=root /bin/true 2>&1) && return 1
  grep -Eiq 'access denied|not authorized|authentication is required|interactive authentication|already loaded|fragment file|not allowed' <<<"$out"
}
# The launcher is allowed what the rule allows (the positive controls: a polkit
# that refused everything would pass the refusals alone) and nothing else.
launcher_limits_ok() {
  polkit_allows agent-launch "agent-session@1.service" start \
    && polkit_allows agent-launch "agent-session-end@1.service" stop \
    && polkit_refuses agent-launch agent-signd.service restart \
    && polkit_refuses agent-launch "agent-session@$((SLOTS + 1)).service" start \
    && transient_refused agent-session@1.service \
    && transient_refused agent-sitting-probe-transient
}

# A-2, on a real machine: the launcher can't make, rename or remove an entry in
# its I/O folders, and can write the files it owns.
launcher_io_closed() {
  local d
  for d in "$LAUNCH_IO" "$LAUNCH_IO/specs" "$LAUNCH_IO/logs"; do
    ! as_user agent-launch "checking the launcher can't make, rename or remove an entry in $d" /usr/bin/test -w "$d" || return 1
  done
  as_user agent-launch "checking the launcher can write its own spec file" /usr/bin/test -w "$LAUNCH_IO/specs/1.json" \
    && as_user agent-launch "checking the launcher can write its own output file" /usr/bin/test -w "$LAUNCH_IO/logs/1.out"
}

# A-2: every path the session units make systemd open as root lies under the I/O
# folder (read from the installed unit files).
units_open_only_io_paths() {
  local u f=$WORK/unit.final key val p n
  for u in 'agent-session@.service' 'agent-session-end@.service'; do
    root_read_to "$SYSTEMD_DIR/$u" "$f" || return 1
    n=0
    while IFS='=' read -r key val; do
      case $key in
        LoadCredential | LoadCredentialEncrypted) p=${val#*:} ;;
        StandardInput | StandardOutput | StandardError)
          case $val in file:* | append:* | truncate:*) p=${val#*:} ;; *) continue ;; esac
          ;;
        EnvironmentFile) p=${val#-} ;;
        *) continue ;;
      esac
      n=$((n + 1))
      case $p in *..*) return 1 ;; /var/lib/agent-launch-io/?*) ;; *) return 1 ;; esac
    done <"$f"
    [ "$n" -ge 2 ] || return 1
  done
}

final_checks() {
  section "Checks of the result"
  check "agent-signd.service runs as agent-sign, is active and has never restarted" svc_ok agent-signd.service agent-sign
  check "agent-launchd.service runs as agent-launch, is active and has never restarted" svc_ok agent-launchd.service agent-launch
  check "the three sockets and both services are enabled and running" units_up agent-signd.socket agent-signd-launcher.socket agent-signd.service agent-launchd.socket agent-launchd.service
  check "the session templates are installed and never enabled or started" templates_idle
  check "the programs match their recorded hashes and /opt/agent-sign/current is $COMMIT" programs_ok
  check "agent-sign, agent-launch and the $SLOTS slot accounts are system accounts with no shell" accounts_ok
  check "the slot folders and the launcher's folders have the designed owners and modes" folders_ok
  check "the session units open only files under $LAUNCH_IO as root" units_open_only_io_paths
  check "the slot accounts are in at.deny and cron.deny" deny_lists_ok
  check "the OpenBao login is installed at $STORED_SECRET (root-only, right shape), and the delivered copy $DELIVERED is gone" login_ok
  check "/etc/agent-sign/allowed_signers holds exactly OpenBao's CA line for this machine's agents" trust_file_ok
  check "system.toml names this machine, OpenBao and $SLOTS slots" settings_ok
  check "the polkit rule names exactly slots 1 to $SLOTS" polkit_rule_ok
  check "the agents' git trusts only $TRUST_REAL, from /etc/gitconfig (D5)" agents_trust_ok
  check "the agents' allowed_signers holds no agent-sign certificate authority (D5)" agents_block_gone
  check "the agents' signing program is the reviewed build (D5)" agents_program_ok
  check "the agents' bin entries link to the reviewed build, and the old agent-signd copy is gone (D5)" agents_links_ok
  check "the agents' old user-level agent-signd is stopped, disabled and masked (D5)" user_service_off
  real_checks
  echo
  if [ "$CHECKS_FAILED" -gt 0 ]; then
    printf '%s checks FAILED, %s passed, %s skipped. Look at the FAIL lines above; running the same command again repairs what it can.\n' "$CHECKS_FAILED" "$CHECKS_PASSED" "$CHECKS_SKIPPED"
    exit 1
  fi
  printf 'All checks passed (%s passed, %s skipped).\n' "$CHECKS_PASSED" "$CHECKS_SKIPPED"
  echo "An agent now runs the six sitting tests as the agents account on this machine (in a fresh login): AGENT_SIGN_SITTING_SOCKET=/run/agent-sign/daemon.sock cargo test --test test_caller_identity_sitting -- --ignored. The probe session stays up for an hour."
}

# ---------------------------------------------------------------- undo

# Puts back what the agents had, from root's saved copies. Reads root's copy,
# writes as the agents account; replaces a link we made before writing, so
# nothing is ever written through it.
#
# The manifest is read in two passes (A-1). First every line is checked against
# what this sitting writes (saved_name's fixed names, an octal mode, nothing
# else), and nothing changes unless the whole manifest is understood. Then the
# agents' files are put back, each from the copy whose name the fixed map gives,
# never from a name the manifest supplies.
#
# A-11: undo puts back the copies made at the FIRST run. It does not look for
# changes the agents made to these files since; it overwrites them, and puts a
# saved copy or link over whatever stands there now. It says so.
restore_agents_state() {
  local label kind arg as path cur want target seen=' '
  root_read_to "$SAVE/manifest" "$WORK/manifest" || { keep "no saved copies of the agents' files: D5 never changed them"; return 0; }
  while IFS='|' read -r -u 3 label kind arg as; do
    want=$(saved_name "$label" "$kind")
    [ -n "$want" ] || die "the saved manifest has a label I don't write ($(plain_text "$label")). Root's manifest $SAVE/manifest is not what this sitting made; I changed nothing."
    case $seen in *" $label "*) die "the saved manifest names $label twice. It is not what this sitting made; I changed nothing." ;; esac
    seen+="$label "
    case $kind in
      file) [[ $arg =~ ^[0-7]{3,4}$ ]] && [ "$as" = "$want" ] || die "the saved manifest's line for $label has a mode or a name that is not what this sitting writes. I changed nothing." ;;
      link) case $label in bin/* | user-unit) ;; *) die "the saved manifest has a link for $label, which is never a link. I changed nothing." ;; esac
        [ -z "$arg" ] && [ "$as" = "$want" ] || die "the saved manifest's link line for $label is not what this sitting writes. I changed nothing." ;;
      absent) [ -z "$arg" ] && [ -z "$as" ] || die "the saved manifest's line for $label is not what this sitting writes. I changed nothing." ;;
      *) die "the saved manifest has a kind I don't know ($(plain_text "$kind")). I changed nothing." ;;
    esac
  done 3<"$WORK/manifest"
  say "  note: this puts back the copies saved at the first run. Anything the agents changed in these files since then (their git config, allowed_signers, the five bin entries and their own user-level agent-signd.service file or link, if it was saved) is overwritten, and a bin entry they have replaced with another file or link since is replaced by the saved one. Those later changes are lost: copy any you need first."
  # L2: the manifest is read on file descriptor 3, not on standard input: sudo-rs
  # 0.2.13 may read ahead on its standard input, which would eat the other lines.
  while IFS='|' read -r -u 3 label kind arg as; do
    case $label in
      gitconfig) path=$AGENTS_GITCONFIG ;;
      allowed_signers) path=$AGENTS_SIGNERS ;;
      user-unit) path=$AGENTS_USER_UNIT ;;
      bin/*) path=$AGENTS_BIN/${label#bin/} ;;
    esac
    case $kind in
      file)
        root_read_to "$SAVE/$as" "$WORK/saved.file" || die "the saved copy $SAVE/$as is missing."
        cur="$WORK/restore.cur"
        if ! as_user agents "$(printf 'checking %s' "$label")" /usr/bin/test -L "$path" \
          && agents_cat "reading $label" "$path" >"$cur" 2>/dev/null && cmp -s "$cur" "$WORK/saved.file" \
          && [ "$(as_user agents "reading the mode of $label" /usr/bin/stat -c %a -- "$path")" = "$arg" ]; then
          keep "the agents' $label is as it was"
        else
          change "restore the agents' $label from root's saved copy" restore_one_file "$path" "$arg"
        fi ;;
      link)
        root_read_to "$SAVE/$as" "$WORK/saved.target" || die "the saved link target $SAVE/$as is missing."
        target=$(head -n 1 "$WORK/saved.target")
        link_target_safe "$target" || die "the saved link target for $label is not one this sitting would save. I changed nothing more."
        if [ "$(as_user agents "reading where $label links" /usr/bin/readlink -- "$path" 2>/dev/null || true)" = "$target" ]; then
          keep "the agents' $label links where it did"
        else
          change "restore the agents' $label link to $target" as_user agents "restoring the agents' $label link" /usr/bin/ln -sfn -- "$target" "$path"
        fi ;;
      absent)
        # It did not exist before; only a link of ours may be taken away again.
        if as_user agents "checking for a link of ours at $label" /usr/bin/test -L "$path"; then
          change "remove our link at the agents' $label (it did not exist before)" as_user agents "removing our link" /usr/bin/rm -f -- "$path"
        else
          keep "the agents' $label is as it was (absent)"
        fi ;;
    esac
  done 3<"$WORK/manifest"
  verify_restored_state
}

# L2: after restoring, read every entry back as the agents account and compare it with
# its saved copy: a file by content and mode (and not a link), a link by its target, an
# entry saved as absent by not being a link of ours. A write that was said to work and
# was lost stops the undo, naming the entries, before the user service is started again.
verify_restored_state() {
  local label kind arg as path target n=0 bad=() cur="$WORK/verify.cur" saved="$WORK/verify.saved"
  [ "$DRY_RUN" = 1 ] && return 0
  while IFS='|' read -r -u 3 label kind arg as; do
    case $label in
      gitconfig) path=$AGENTS_GITCONFIG ;;
      allowed_signers) path=$AGENTS_SIGNERS ;;
      user-unit) path=$AGENTS_USER_UNIT ;;
      bin/*) path=$AGENTS_BIN/${label#bin/} ;;
    esac
    n=$((n + 1))
    case $kind in
      file)
        root_read_to "$SAVE/$as" "$saved" || die "the saved copy $SAVE/$as is missing, so I can't check the agents' $label."
        if as_user agents "checking whether $label is a link" /usr/bin/test -L "$path" \
          || ! agents_cat "re-reading $label" "$path" >"$cur" 2>/dev/null || ! cmp -s "$cur" "$saved" \
          || [ "$(as_user agents "re-reading the mode of $label" /usr/bin/stat -c %a -- "$path" 2>/dev/null || true)" != "$arg" ]; then
          bad+=("$label")
        fi ;;
      link)
        root_read_to "$SAVE/$as" "$saved" || die "the saved link target $SAVE/$as is missing, so I can't check the agents' $label."
        target=$(head -n 1 "$saved")
        [ "$(as_user agents "re-reading where $label links" /usr/bin/readlink -- "$path" 2>/dev/null || true)" = "$target" ] || bad+=("$label") ;;
      absent)
        if as_user agents "checking for a link of ours at $label" /usr/bin/test -L "$path"; then bad+=("$label"); fi ;;
    esac
  done 3<"$WORK/manifest"
  if [ "${#bad[@]}" -gt 0 ]; then
    die "after restoring, the agents' files do not match their saved copies: $(IFS=,; echo "${bad[*]}"). The restore did not take; their user service was not started again. Look at those files, then run --undo again."
  fi
  say "  ok: every restored file matches its saved copy ($n entries compared in $SAVE: files by content and mode, links by target)"
}

restore_one_file() { # PATH MODE   (content from $WORK/saved.file)
  if as_user agents "checking for a link at $1" /usr/bin/test -L "$1"; then
    as_user agents "removing our link before restoring the file" /usr/bin/rm -f -- "$1" || return 1
  fi
  as_user agents "restoring $1" /usr/bin/tee -- "$1" <"$WORK/saved.file" >/dev/null || return 1
  as_user agents "restoring the mode of $1" /usr/bin/chmod "$2" -- "$1"
}

step_undo() {
  section "Undo: put the machine back (no data is deleted)"
  local i count u todo=() gone=0
  if root_read_to "$AS_ETC/system.toml" "$WORK/system.toml.now"; then
    count=$(toml_value "$WORK/system.toml.now" slots count)
  fi
  count=${count:-$DEFAULT_SLOTS}
  [[ $count =~ ^[1-9][0-9]{0,2}$ ]] || count=$DEFAULT_SLOTS

  # 11. any session still running (stopping it ends it; the launcher keeps its records)
  for i in $(seq 1 "$count"); do
    for u in "agent-session@$i.service" "agent-session-end@$i.service"; do
      if systemctl is-active --quiet "$u" 2>/dev/null; then
        change "stop $u" as_root "stopping $u" systemctl stop "$u"
      fi
    done
  done

  # 10. give the agents back their own trust, programs and service, BEFORE the new service stops,
  # so their commits keep working at every point.
  restore_agents_state
  local st
  st=$(user_service_state)
  if [ "${st%% *}" = enabled ] && [ "${st##* }" = active ]; then
    keep "the agents' own user-level agent-signd is enabled and running"
  elif ! as_root "checking the agents' saved bin copy" test -f "$SAVE/manifest"; then
    keep "the agents' old user-level agent-signd was never retired, so it is left alone"
  else
    change "unmask, enable and start the agents' own user-level agent-signd.service" restore_user_service
  fi

  # 9, 6. stop and disable the system units, then take their files away
  for u in agent-launchd.service agent-launchd.socket agent-signd.service agent-signd-launcher.socket agent-signd.socket; do
    if systemctl is-active --quiet "$u" 2>/dev/null || systemctl is-enabled --quiet "$u" 2>/dev/null; then todo+=("$u"); fi
  done
  if [ "${#todo[@]}" -gt 0 ]; then
    change "stop and disable ${todo[*]}" as_root "stopping and disabling the system units" systemctl disable --now "${todo[@]}"
  else
    keep "no system unit of agent-sign is running or enabled"
  fi

  # 8. system.toml aside (anything at the original path would keep one-account launch refused)
  if as_root "checking whether system.toml is in place" test -e "$AS_ETC/system.toml"; then
    change "move system.toml aside to /etc/agent-sign/undone/system.toml.$(date +%Y%m%d-%H%M%S) (one-account launch works again)" move_settings_aside
  else
    keep "there is no /etc/agent-sign/system.toml"
  fi

  # 7, 6. the polkit rule and the unit files
  if as_root "checking whether the polkit rule is in place" test -e "$POLKIT_RULE"; then
    change "remove the polkit rule 50-agent-launch.rules" as_root "removing the polkit rule" rm -f -- "$POLKIT_RULE"
  else
    keep "the polkit rule is not installed"
  fi
  for u in "${UNITS[@]}"; do
    if as_root "checking whether $u is installed" test -e "$SYSTEMD_DIR/$u"; then gone=1; fi
  done
  if [ "$gone" = 1 ]; then
    change "remove agent-sign's unit files and tell systemd" remove_unit_files
  else
    keep "agent-sign's unit files are not installed"
  fi

  # 5. git's system setting (the trust file itself stays: root's, and the CA is never destroyed)
  if [ "$("$GIT" config --system --get gpg.ssh.allowedSignersFile 2>/dev/null || true)" = "$TRUST_REAL" ]; then
    change "remove gpg.ssh.allowedSignersFile from /etc/gitconfig" as_root "removing the system git setting" /usr/bin/env -i PATH=/usr/bin:/bin "$GIT" config --system --unset-all gpg.ssh.allowedSignersFile
  else
    keep "/etc/gitconfig has no agent-sign setting"
  fi

  echo
  say "Undone. Kept, never deleted: the accounts (no shell, no password), /var/lib/agent-sign, /var/lib/agent-launch, /var/lib/agent-launch-io, /var/lib/agent-slots with every Trash, /opt/agent-sign, the stored login, root's saved copies and /etc/agent-sign/allowed_signers. The OpenBao mount, CA and login are undone, if ever, in agentic-credentials; the CA is never destroyed, so commits it certified stay verifiable."
}

# The agents' own unit file is already back (restore_agents_state put it over the mask
# link, never writing through it), so unmask finds no mask to remove and enable finds the unit.
restore_user_service() {
  as_root "unmasking the agents' own agent-signd" systemctl --user -M agents@ unmask agent-signd.service || return 1
  as_root "enabling the agents' own agent-signd" systemctl --user -M agents@ enable agent-signd.service || return 1
  as_root "starting the agents' own agent-signd" systemctl --user -M agents@ start agent-signd.service
}
move_settings_aside() {
  as_root "making the folder for the moved settings" install -d -m 0755 -o root -g root "$AS_ETC/undone" || return 1
  as_root "moving system.toml aside" mv -- "$AS_ETC/system.toml" "$AS_ETC/undone/system.toml.$(date +%Y%m%d-%H%M%S)"
}
remove_unit_files() {
  local u
  for u in "${UNITS[@]}"; do
    as_root "removing the unit file $u" rm -f -- "$SYSTEMD_DIR/$u" || return 1
  done
  as_root "telling systemd the units are gone" systemctl daemon-reload
}

# ---------------------------------------------------------------- main

main() {
  if [ "$DRY_RUN" = 1 ]; then say "Dry run: nothing below is changed; each 'would:' line is a change, each 'kept:' line is already done."; fi
  preflight
  if [ "$UNDO" = 1 ]; then
    step_undo
    exit 0
  fi
  step_programs
  step_accounts
  step_folders
  step_login
  step_trust
  step_units
  step_polkit
  step_start
  step_retire_old_trust
  step_probe
  if [ "$DRY_RUN" = 1 ]; then
    echo
    say "Dry run done: $CHANGES change(s) would be made. Nothing was changed."
    exit 0
  fi
  final_checks
}

main
