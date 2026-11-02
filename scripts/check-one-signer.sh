#!/usr/bin/env bash
# check-one-signer.sh: lists every piece of signing, checking or encoding code
# that lives outside agent-sign, on the main branch of each repo that has any.
#
# Why it exists. The signing consolidation (plan: records/plans/turn-12-product-map/
# signing-consolidation.md) makes agent-sign the one owner of the signed-record
# encoding, the signature check and the rules for whose key is whose. Its first
# measurable goal is "0 pieces outside agent-sign". This script is that
# measurement, and it is run first, before anything moves, to show today's number.
#
# How it finds a piece. By what the code DOES, not what it is called: it greps
# each repo's main tree for signing and checking primitives (WebCrypto, node:crypto,
# the Python `cryptography` package, nacl/noble, ssh-keygen -Y, WebAuthn
# fields), for hand-written canonical-JSON encoders (a sorted-keys emitter,
# sort_keys=True, a function called canonical...), and for key-trust rules
# (first key wins, key registries, trust lists). Renaming a file or a function
# does not hide it: the new name still matches, is not in the baseline, and is
# reported as NEW.
#
# The baseline (scripts/one-signer-baseline.tsv) lists the files already known,
# by piece number. A hit that is not in the baseline is NEW and fails the run
# (exit 2). A piece counts while one of its core files exists on main and still
# hits; when it is deleted or rewritten to call agent-sign it stops counting.
#
# Taylor's own passkey and browser-key checking stays in unharness (decided
# 31 Oct, plan section "Your own signatures"). It is allowed only if that file
# is built on a standard WebAuthn library: imports one listed in the baseline
# (@webauthn-libs), has the library in its package.json, and does no signature
# verification of its own (no crypto.subtle verify/importKey). Otherwise it
# counts as a piece, which is today's state.
#
# Limits, said plainly. This is a pattern check, not a proof. A hand-rolled
# encoder or checker deliberately written to avoid every pattern here would not
# be found; the sized security review of each change is the backstop. Test code
# is listed separately and does not count, but a non-test file that imports from
# a test directory is NEW, so production code cannot hide under tests/.
#
# Usage:
#   scripts/check-one-signer.sh [--root DIR] [--repo NAME=PATH]... [--ref main]
#                               [--expect N] [--baseline FILE] [--show-tests]
#   --root     directory holding the repo checkouts as DIR/<name>
#              (default: the parent of this repo's directory)
#   --repo     where one repo is, when not at ROOT/<name>; repeatable. A repo
#              named here that is not in the baseline's @repo list is scanned
#              too (everything it hits is NEW), which is how to try a repo the
#              plan does not list.
#   --expect   the number of pieces the run must find (default: the baseline's
#              @expect; 0 is the goal at the end)
# Exit: 0 count matches and nothing NEW; 1 count differs; 2 something NEW, a
# repo/ref could not be read or scanned, or the baseline is unusable (no @repo, no
# @expect, a non-numeric one, or no @piece while code still matches). A baseline that
# says nothing is never a pass.
# Works with bash 3.2 (macOS) and 5; needs git with PCRE (git grep -P).
set -u
set -f   # no globbing: a name from the baseline is never expanded into file names
tab=$(printf '\t')

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
ref=main
baseline="$here/one-signer-baseline.tsv"
expect=""
show_tests=0
extra_repos=""
repo_paths=""   # lines "name<TAB>path"

while [ $# -gt 0 ]; do
  case "$1" in
    --root) root=$(cd "$2" && pwd) || exit 2; shift 2 ;;
    --repo) n=${2%%=*}; p=${2#*=}; repo_paths="$repo_paths
$n$tab$p"; shift 2 ;;
    --ref) ref=$2; shift 2 ;;
    --expect) expect=$2; shift 2 ;;
    --baseline) baseline=$2; shift 2 ;;
    --show-tests) show_tests=1; shift ;;
    -h|--help) sed -n '2,60p' "$0"; exit 0 ;;
    *) echo "check-one-signer: unknown argument $1" >&2; exit 2 ;;
  esac
done
repo_paths=$(printf '%s\n' "$repo_paths" | awk -F'\t' 'NF==2 && $1!="" {print}')

[ -f "$baseline" ] || { echo "check-one-signer: no baseline at $baseline" >&2; exit 2; }

# ---- the baseline ----
# A baseline that says nothing must never read as a pass: without it the count of 0 means nothing was looked at.
baseline_unusable() { echo "check-one-signer: the baseline $baseline is unusable: $1" >&2; echo "RESULT: baseline unusable; nothing was measured" >&2; exit 2; }
base_repos=$(awk -F'\t' '$1=="@repo" {print $2 "|"}' "$baseline")        # "|" keeps a blank name visible
[ -n "$base_repos" ] || baseline_unusable "it lists no repo (@repo line)"
for r in $(printf '%s\n' "$base_repos" | sed 's/|$//' | sed 's/^$/<blank>/'); do
  printf '%s\n' "$r" | grep -Eq '^[A-Za-z0-9._-]+$' || baseline_unusable "it lists a repo named '$r'; names are letters, digits, . _ - only"
done
base_repos=$(printf '%s\n' "$base_repos" | sed 's/|$//')
n_expect=$(awk -F'\t' '$1=="@expect"' "$baseline" | wc -l | tr -d ' ')
[ "$n_expect" = 1 ] || baseline_unusable "it has $n_expect @expect lines; it needs exactly one"
base_expect=$(awk -F'\t' '$1=="@expect" {print $2}' "$baseline")
printf '%s\n' "$base_expect" | grep -Eq '^[0-9]+$' || baseline_unusable "its @expect is '$base_expect', not a whole number"
n_pieces=$(awk -F'\t' '$1=="@piece"' "$baseline" | wc -l | tr -d ' ')
if [ -n "$expect" ]; then
  printf '%s\n' "$expect" | grep -Eq '^[0-9]+$' || { echo "check-one-signer: --expect must be a whole number, not '$expect'" >&2; exit 2; }
else
  expect=$base_expect
fi
webauthn_libs=$(awk -F'\t' '$1=="@webauthn-libs" {print $2}' "$baseline")
all_repos=$(printf '%s\n' "$base_repos"; printf '%s\n' "$repo_paths" | cut -f1)
all_repos=$(printf '%s\n' "$all_repos" | awk 'NF && !seen[$0]++')

repo_dir() { # name -> path
  p=$(printf '%s\n' "$repo_paths" | awk -F'\t' -v n="$1" '$1==n {print $2; exit}')
  if [ -n "$p" ]; then printf '%s\n' "$p"; else printf '%s\n' "$root/$1"; fi
}

# ---- what to look for ----
LANG_SPECS="*.ts *.tsx *.js *.mjs *.cjs *.py *.sh *.rs *.go *.rb *.java *.kt *.swift"
EXCLUDES=":(exclude)*node_modules/* :(exclude)*/dist/* :(exclude)dist/*"

S_PAT='subtle\.(sign|verify|importKey|generateKey)\b|\b(createSign|createVerify|generateKeyPairSync|generateKeyPair|createPrivateKey|createPublicKey)\s*\(|\b(sign|verify)\(\s*null\s*,|\b(crypto|nodeCrypto)\.(sign|verify)\(\s*(null|"[A-Za-z0-9-]+"|'"'"'[A-Za-z0-9-]+'"'"')\s*,|import\s*\{[^}]*\b(sign|verify|createSign|createVerify)\b[^}]*\}\s*from\s*["'"'"'](node:)?crypto["'"'"']|cryptography\.hazmat|\bEd25519(Private|Public)Key\b|\bec\.ECDSA\b|@noble/(curves|ed25519|hashes)|(import|require|from)[^\n]*\b(tweetnacl|libsodium|nacl)\b|\b(ed25519_dalek|ed25519-dalek|p256::ecdsa|ssh_key|ssh-key)\b|ssh-keygen\s+-Y\b|openssl\s+(dgst|pkeyutl)\b|gpg\s+--(verify|detach-sign)\b|authenticatorData|clientDataJSON|@simplewebauthn|webauthn[-_]rs|py_webauthn|\bcreateHmac\b|\bhmac\.new\b|\bjsonwebtoken\b|\bjwt\.(sign|verify)\b'
E_PAT='JSON\.stringify\(\s*[A-Za-z_$][\w$]*\s*\)\s*\}?\s*(\+\s*["'"'"'`]:|:)|sort_keys\s*=\s*True|\b(function|def|const|let|fn)\s+(canonical\w*|stableStringify|stable_stringify|sortKeys|jcs\w*)\b|rfc8785|json-canonicalize|serde_jcs|cyberphone|canonicaljson|json-stable-stringify|safe-stable-stringify|\bjq\s+(-[A-Za-z]*S\b|--sort-keys)'
K_PAT='\bclass\s+(KeyRing|\w*Registry|\w*Trust\w*)\b|[Ff]irst[- ]key|firstKey|signing_key\(|\btrust\.(taylor|reviewers)\b|pinnedPasskeys|allowed_signers'
T_PAT='(from|import|require)[^\n]*["'"'"'][^"'"'"'\n]*/(tests?|__tests__)/'

is_test() { printf '%s\n' "$1" | grep -Eq '(^|/)(tests?|__tests__|bench)/|\.test\.[a-z]+$|(^|/)conformance/[^/]+\.py$'; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/one-signer.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT
: > "$tmp/hits"       # family<TAB>repo<TAB>path
unreadable=0
scanned=""

# git grep exits 0 (found), 1 (nothing found) or 2+ (it failed). A failure must never read as
# "nothing found", or a broken run would look like progress: it stops the run with exit 2.
grep_files() { # dir, family, then the git grep arguments after "git grep"; prints repo-relative paths
  dir=$1; fam=$2; shift 2
  out=$(git -C "$dir" grep "$@" 2>"$tmp/grep.err"); rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "check-one-signer: git grep failed in $dir (exit $rc): $(head -c 200 "$tmp/grep.err")" >&2
    unreadable=1; return
  fi
  [ -n "$out" ] || return 0
  printf '%s\n' "$out" | sed "s|^$ref:||" | while IFS= read -r f; do printf '%s\t%s\t%s\n' "$fam" "$name" "$f"; done >> "$tmp/hits"
}

for name in $all_repos; do
  dir=$(repo_dir "$name")
  if ! git -C "$dir" rev-parse --verify -q "$ref^{commit}" >/dev/null 2>&1; then
    echo "check-one-signer: cannot read $ref in $name ($dir)" >&2; unreadable=1; continue
  fi
  # shellcheck disable=SC2086
  grep_files "$dir" S -I -l -P -e "$S_PAT" "$ref" -- $LANG_SPECS $EXCLUDES
  # shellcheck disable=SC2086
  grep_files "$dir" E -I -l -P -e "$E_PAT" "$ref" -- $LANG_SPECS $EXCLUDES
  # shellcheck disable=SC2086
  grep_files "$dir" K -I -l -P -e "$K_PAT" "$ref" -- $LANG_SPECS $EXCLUDES
  # nkeys together with a .sign( / .verify( call in the same file
  # shellcheck disable=SC2086
  grep_files "$dir" S -I -l --all-match -P -e '\bnkeys\b' -e '\.(sign|verify)\(' "$ref" -- $LANG_SPECS $EXCLUDES
  # a non-test file importing from a test directory
  # shellcheck disable=SC2086
  grep_files "$dir" T -I -l -P -e "$T_PAT" "$ref" -- $LANG_SPECS $EXCLUDES
  [ "$unreadable" = 0 ] && scanned="$scanned $name "
done
# T hits in test files themselves are expected; drop them
if [ -s "$tmp/hits" ]; then
  while IFS="$tab" read -r fam repo path; do
    if [ "$fam" = T ] && is_test "$path"; then continue; fi
    printf '%s\t%s\t%s\n' "$fam" "$repo" "$path"
  done < "$tmp/hits" > "$tmp/hits2"; mv "$tmp/hits2" "$tmp/hits"
fi
[ "$unreadable" = 0 ] || { echo "RESULT: a repo, ref or search could not be read; the count is not trustworthy" >&2; exit 2; }
# every repo the baseline lists must really have been scanned
for r in $base_repos; do
  case "$scanned" in *" $r "*) ;; *) echo "check-one-signer: $r is listed in the baseline and was not scanned; the count is not trustworthy" >&2; echo "RESULT: a listed repo was not scanned" >&2; exit 2;; esac
done

# one line per file: repo, path, families
sort -u "$tmp/hits" | awk -F'\t' '{k=$2 FS $3; f[k]=f[k] $1} END {for (k in f) print k FS f[k]}' | sort > "$tmp/files"
# split tests from the rest
: > "$tmp/prod"; : > "$tmp/tests"
while IFS="$tab" read -r repo path fams; do
  if is_test "$path"; then printf '%s\t%s\t%s\n' "$repo" "$path" "$fams" >> "$tmp/tests"
  else printf '%s\t%s\t%s\n' "$repo" "$path" "$fams" >> "$tmp/prod"; fi
done < "$tmp/files"

# baseline rows: repo path class piece note
awk -F'\t' '$1 !~ /^(#|@)/ && NF>=4 {print $1 FS $2 FS $3 FS $4}' "$baseline" | sort > "$tmp/rows"

# ---- a baseline with no @piece line may only describe a world where nothing matches ----
if [ "$n_pieces" = 0 ] && [ -s "$tmp/prod" ]; then
  echo "check-one-signer: the baseline $baseline lists no piece (@piece line), yet $(wc -l < "$tmp/prod" | tr -d ' ') file(s) still match:" >&2
  awk -F'\t' '{print "  " $1 "/" $2 " [" $3 "]"}' "$tmp/prod" >&2
  echo "RESULT: baseline unusable (names no piece but code matches); nothing was measured" >&2
  exit 2
fi

# ---- NEW: a hit that is not in the baseline ----
: > "$tmp/new"
while IFS="$tab" read -r repo path fams; do
  if ! awk -F'\t' -v r="$repo" -v p="$path" '$1==r && $2==p {f=1} END {exit !f}' "$tmp/rows"; then
    printf '%s\t%s\t%s\n' "$repo" "$path" "$fams" >> "$tmp/new"
  fi
done < "$tmp/prod"

# ---- pieces ----
echo "check-one-signer: signing, checking and encoding code outside agent-sign"
echo "  ref: $ref   repos: $(printf '%s ' $all_repos)"
for name in $all_repos; do
  dir=$(repo_dir "$name")
  printf '  %-22s %s\n' "$name" "$(git -C "$dir" rev-parse --short=7 "$ref" 2>/dev/null || echo unreadable)"
done
echo
printf '%-3s %-44s %-9s %s\n' "#" "piece" "status" "where"
counted=0; allowed=0; plan_counted=0; post_counted=0
for n in $(awk -F'\t' '$1=="@piece" {print $2}' "$baseline"); do
  pname=$(awk -F'\t' -v n="$n" '$1=="@piece" && $2==n {print $3}' "$baseline")
  porigin=$(awk -F'\t' -v n="$n" '$1=="@piece" && $2==n {print $4}' "$baseline")
  status="gone"; where=""
  for row in $(awk -F'\t' -v n="$n" '$1 !~ /^(#|@)/ && $3=="piece" && $4==n {print $1 "|" $2}' "$baseline"); do
    repo=${row%%|*}; path=${row#*|}
    dir=$(repo_dir "$repo")
    git -C "$dir" cat-file -e "$ref:$path" 2>/dev/null || continue
    fams=$(awk -F'\t' -v r="$repo" -v p="$path" '$1==r && $2==p {print $3}' "$tmp/prod")
    [ -n "$fams" ] || { where="$where$repo/$path (no longer matches: rewritten?) "; [ "$status" = gone ] && status="migrated"; continue; }
    status="found"; where="$where$repo/$path [$fams] "
    # the one allowance: Taylor's own passkey check built on a standard WebAuthn library
    if [ "$(awk -F'\t' -v n="$n" '$1=="@piece" && $2==n {print $5}' "$baseline")" = "webauthn-library-ok" ]; then
      lib=""
      for l in $webauthn_libs; do
        if git -C "$dir" grep -q -P -e "from ['\"]$l['\"]" "$ref" -- "$path" 2>/dev/null \
           && git -C "$dir" grep -q -P -e "\"$l\"" "$ref" -- package.json 2>/dev/null; then lib=$l; fi
      done
      if [ -n "$lib" ] && ! git -C "$dir" grep -q -P -e 'subtle\.(verify|importKey)\b' "$ref" -- "$path" 2>/dev/null; then
        status="allowed"; where="$where(built on $lib) "
      fi
    fi
  done
  case $status in
    found) counted=$((counted+1)); [ "$porigin" = plan ] && plan_counted=$((plan_counted+1)) || post_counted=$((post_counted+1)) ;;
    allowed) allowed=$((allowed+1)) ;;
  esac
  mark=""; [ "$porigin" != plan ] && mark=" *"
  printf '%-3s %-44s %-9s %s\n' "$n" "$pname$mark" "$status" "$where"
done
echo
awk -F'\t' '$1=="@piece" && $4!="plan" {print "  * " $3 ": " $6}' "$baseline"

# ---- the parts that go with a piece (they call it or hold its lists; not counted) ----
parts=$(awk -F'\t' '$1 !~ /^(#|@)/ && $3=="part" {print $1 "/" $2 "  (piece " $4 ")"}' "$baseline")
if [ -n "$parts" ]; then
  echo; echo "Parts that go with a piece (counted with it, listed so they move with it):"
  printf '%s\n' "$parts" | sed 's/^/  /'
fi

# ---- test-only hits ----
nt=$(wc -l < "$tmp/tests" | tr -d ' ')
echo; echo "Test-only code that signs or hashes (does not count): $nt files"
if [ "$show_tests" = 1 ]; then awk -F'\t' '{print "  " $1 "/" $2 " [" $3 "]"}' "$tmp/tests"; fi
awk -F'\t' '$1 !~ /^(#|@)/ && $3=="test-support" {print "  " $1 "/" $2 "  (test support in src: " $5 ")"}' "$baseline"

# ---- checked and not signing ----
awk -F'\t' '$1 !~ /^(#|@)/ && $3=="not-signing" {print "  " $1 "/" $2 "  (" $5 ")"}' "$baseline" > "$tmp/ns"
if [ -s "$tmp/ns" ]; then echo; echo "Hit the patterns, checked, not signing code:"; cat "$tmp/ns"; fi

# ---- NEW ----
nn=$(wc -l < "$tmp/new" | tr -d ' ')
echo
if [ "$nn" -gt 0 ]; then
  echo "NEW: $nn file(s) sign, check or encode and are not in the baseline (a new piece, or an old one renamed):"
  awk -F'\t' '{print "  " $1 "/" $2 "  [" $3 "]"}' "$tmp/new"
else
  echo "NEW: none"
fi

echo
echo "pieces outside agent-sign: $counted   (plan listed 12: $plan_counted still found; added since the plan: $post_counted; allowed on a standard WebAuthn library: $allowed)"
echo "expected: $expect"
[ "$unreadable" = 0 ] || { echo "RESULT: a repo or ref could not be read"; exit 2; }
if [ "$nn" -gt 0 ]; then echo "RESULT: FAIL (new signing code outside agent-sign)"; exit 2; fi
if [ "$counted" != "$expect" ]; then echo "RESULT: count differs from expected"; exit 1; fi
echo "RESULT: ok"
exit 0
