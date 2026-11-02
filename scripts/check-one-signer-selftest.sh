#!/usr/bin/env bash
# Tests for check-one-signer.sh: the check of the check.
#
# It clones each repo's main into a temp folder, changes the clone, and asserts
# what the script says. The cases are the ones the plan needs the script to get
# right: it finds today's pieces; a renamed piece is still flagged; a brand-new
# piece (in several languages) is flagged; code hidden under a test folder is
# flagged; Taylor's passkey check is allowed only on a standard WebAuthn
# library; and when every piece has moved the count reaches 0.
#
# Usage: scripts/check-one-signer-selftest.sh [--root DIR]
# Git inside the tests never reads the user's global config (GIT_CONFIG_GLOBAL=/dev/null).
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
[ "${1:-}" = "--root" ] && root=$(cd "$2" && pwd)
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
work=$(mktemp -d "${TMPDIR:-/tmp}/one-signer-selftest.XXXXXX") || exit 2
trap 'rm -rf "$work"' EXIT
repos="unharness ntaild agentic-credentials work-loop"
for r in $repos; do
  git clone -q --branch main "file://$root/$r" "$work/$r" 2>/dev/null || { echo "cannot clone $root/$r"; exit 2; }
  git -C "$work/$r" config user.email t@example.invalid; git -C "$work/$r" config user.name selftest
done
fails=0; total=0
reset() { for r in $repos; do git -C "$work/$r" checkout -q -f main && git -C "$work/$r" reset -q --hard origin/main && git -C "$work/$r" clean -q -fdx; done; }
commit() { git -C "$work/$1" add -A && git -C "$work/$1" commit -q -m "$2"; }
run() { "$here/check-one-signer.sh" --root "$work" "$@" 2>&1; }
check() { # name, expected exit, grep pattern (must appear), extra args...
  name=$1; want=$2; pat=$3; shift 3
  out=$(run "$@"); got=$?
  total=$((total+1))
  if [ "$got" = "$want" ] && printf '%s\n' "$out" | grep -Eq -- "$pat"; then echo "PASS  $name"
  else echo "FAIL  $name (exit $got, wanted $want; pattern: $pat)"; printf '%s\n' "$out" | tail -${SELFTEST_LINES:-12} | sed 's/^/        /'; fails=$((fails+1)); fi
}

reset
check "finds today's pieces" 0 'pieces outside agent-sign: 13 .*plan listed 12: 12 still found; added since the plan: 1' 

reset
git -C "$work/unharness" mv src/ids.ts src/identifiers.ts
sed -i.bak 's/\bcanonical\b/flatten/g; s/\bsha256Hex\b/hexOf/g' "$work/unharness/src/identifiers.ts" && rm -f "$work/unharness/src/identifiers.ts.bak"
commit unharness "rename ids.ts and its function"
check "a renamed piece is NEW, and the old one is gone" 2 'NEW: 1 file.*|unharness/src/identifiers.ts' 
out=$(run); total=$((total+1))
if printf '%s\n' "$out" | grep -Eq '^1 +ids.*gone'; then echo "PASS  the renamed piece's old place reads gone"; else echo "FAIL  old place should read gone"; fails=$((fails+1)); fi

reset
cat > "$work/work-loop/src/attest.ts" <<'TS'
export async function attest(k: CryptoKey, m: Uint8Array) { return crypto.subtle.sign("Ed25519", k, m); }
TS
commit work-loop "a new signer"
check "a new TypeScript signer is NEW" 2 'NEW: 1 file.*' 
out=$(run); total=$((total+1))
printf '%s\n' "$out" | grep -q 'work-loop/src/attest.ts' && echo "PASS  it names the file" || { echo "FAIL  it should name src/attest.ts"; fails=$((fails+1)); }

reset
printf 'import nacl\ndef sig(m, k):\n    return k.sign(m)\n' > "$work/ntaild/src/ntaild/extra_sign.py"
commit ntaild "a new Python signer on another library"
check "a new Python signer on another library is NEW" 2 'ntaild/src/ntaild/extra_sign.py'

reset
printf '#!/bin/sh\nssh-keygen -Y verify -f allowed -I who -n ns -s sig < msg\n' > "$work/agentic-credentials/deploy/verify-things.sh"
commit agentic-credentials "a new shell checker"
check "a new shell checker is NEW" 2 'agentic-credentials/deploy/verify-things.sh'

reset
printf 'export const stable = (o: Record<string, unknown>) => "{" + Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + JSON.stringify(o[k])).join(",") + "}";\n' > "$work/work-loop/src/stable.ts"
commit work-loop "a new encoder under a new name"
check "a new encoder under a new name is NEW" 2 'work-loop/src/stable.ts'

reset
mkdir -p "$work/work-loop/test/support"
printf 'export const sign = (m: string) => m;\n' > "$work/work-loop/test/support/signer.ts"
printf 'import { sign } from "../test/support/signer.ts";\nexport const s = sign;\n' > "$work/work-loop/src/helper.ts"
commit work-loop "production code reaching into test support"
check "production code that imports from a test folder is NEW" 2 'work-loop/src/helper.ts'

reset
printf 'import { verifyAuthenticationResponse } from "@simplewebauthn/server";\nexport const check = verifyAuthenticationResponse;\n' > "$work/unharness/src/acts.ts"
node -e 'const f=process.argv[1];const p=JSON.parse(require("fs").readFileSync(f));p.dependencies["@simplewebauthn/server"]="13.0.0";require("fs").writeFileSync(f,JSON.stringify(p,null,2)+"\n")' "$work/unharness/package.json"
commit unharness "ActVerifier on a standard WebAuthn library"
check "Taylor's passkey check on a standard library is allowed (12 left)" 0 'pieces outside agent-sign: 12 .*allowed on a standard WebAuthn library: 1' --expect 12

reset
printf 'import { verifyAuthenticationResponse } from "@simplewebauthn/server";\nexport const check = async (k: JsonWebKey, s: Uint8Array, d: Uint8Array) => crypto.subtle.verify("ECDSA", await crypto.subtle.importKey("jwk", k, {name:"ECDSA"}, false, ["verify"]), s, d);\nexport const lib = verifyAuthenticationResponse;\n' > "$work/unharness/src/acts.ts"
node -e 'const f=process.argv[1];const p=JSON.parse(require("fs").readFileSync(f));p.dependencies["@simplewebauthn/server"]="13.0.0";require("fs").writeFileSync(f,JSON.stringify(p,null,2)+"\n")' "$work/unharness/package.json"
commit unharness "library imported but own verification kept"
check "a library import beside the code's own verification is not allowed" 0 'pieces outside agent-sign: 13 .*allowed on a standard WebAuthn library: 0'

reset
printf 'export const check = () => true;\n' > "$work/unharness/src/acts.ts"
commit unharness "ActVerifier without the library"
check "ActVerifier rewritten with no library and no match reads migrated, not allowed" 0 'pieces outside agent-sign: 12 .*allowed on a standard WebAuthn library: 0' --expect 12

reset
git -C "$work/unharness" rm -q src/ids.ts
commit unharness "ids.ts moved to agent-sign"
check "a moved piece stops counting (12 left)" 0 'pieces outside agent-sign: 12' --expect 12
check "the count is checked against the expectation" 1 'count differs'

reset
for p in unharness:src/ids.ts unharness:src/acts.ts unharness:src/person-keys.ts unharness:src/publisher.ts unharness:listeners/src/team-lead/signed.ts unharness:listeners/src/model-layer/signing.ts ntaild:src/ntaild/acts.py ntaild:src/ntaild/canonical.py ntaild:src/ntaild/review.py agentic-credentials:src/entitlement/acts.ts agentic-credentials:src/approvals/relay.ts agentic-credentials:src/admin/acts.ts work-loop:src/log/canonical.ts; do
  git -C "$work/${p%%:*}" rm -q "${p#*:}"
done
for r in unharness ntaild agentic-credentials work-loop; do git -C "$work/$r" commit -q -m "everything moved"; done
check "when every piece has moved the count reaches 0" 0 'pieces outside agent-sign: 0' --expect 0


# ---- the script must fail closed: a baseline that says nothing is never a pass ----
reset
base="$here/one-signer-baseline.tsv"
bl="$work/baselines"; mkdir -p "$bl"
: > "$bl/empty.tsv"
printf '@expect\t0\n' > "$bl/only-expect.tsv"
grep -v '^@expect' "$base" > "$bl/no-expect.tsv"
grep -v '^@repo' "$base" > "$bl/no-repo.tsv"
grep -v '^@piece' "$base" > "$bl/no-piece.tsv"
{ cat "$base"; printf '@repo\tghost-repo\n'; } > "$bl/ghost-repo.tsv"
{ cat "$base"; printf '@repo\t*\n'; } > "$bl/glob-repo.tsv"
{ cat "$base"; printf '@repo\t\n'; } > "$bl/blank-repo.tsv"
sed 's/^@expect.*/@expect	thirteen/' "$base" > "$bl/bad-expect.tsv"
check "an empty baseline with --expect 0 is not a pass" 2 'baseline' --baseline "$bl/empty.tsv" --expect 0
check "a baseline holding only @expect 0 is not a pass" 2 'baseline' --baseline "$bl/only-expect.tsv"
check "a baseline with no @expect and no --expect is not a pass" 2 'baseline' --baseline "$bl/no-expect.tsv"
check "a baseline with no @repo line is not a pass, even with --expect 0" 2 'baseline' --baseline "$bl/no-repo.tsv" --expect 0
check "a baseline with no @piece line is not a pass while the repos still hold signing code" 2 'NEW|baseline' --baseline "$bl/no-piece.tsv" --expect 0
check "a listed repo that was not scanned (not there) is not a pass" 2 'ghost-repo' --baseline "$bl/ghost-repo.tsv"
check "a listed repo name that is a glob is refused, not expanded" 2 'baseline' --baseline "$bl/glob-repo.tsv"
check "a blank @repo name is refused" 2 'baseline' --baseline "$bl/blank-repo.tsv"
check "an @expect that is not a number is refused" 2 'baseline' --baseline "$bl/bad-expect.tsv"
check "--expect that is not a number is refused" 2 'expect' --expect many

# a repo with no signing code at all, scanned for real, genuinely finds none: the one legitimate empty result
mkdir -p "$work/mini"; git init -q -b main "$work/mini/clean"
git -C "$work/mini/clean" config user.email t@example.invalid; git -C "$work/mini/clean" config user.name selftest
printf 'export const add = (a: number, b: number) => a + b;\n' > "$work/mini/clean/add.ts"; git -C "$work/mini/clean" add -A; git -C "$work/mini/clean" commit -q -m clean
printf '@repo\tclean\n@expect\t0\n' > "$bl/mini.tsv"
out=$("$here/check-one-signer.sh" --root "$work/mini" --baseline "$bl/mini.tsv" 2>&1); got=$?; total=$((total+1))
if [ "$got" = 0 ] && printf '%s\n' "$out" | grep -q 'pieces outside agent-sign: 0'; then echo "PASS  a scanned repo that really holds nothing gives 0 with no @piece line"; else echo "FAIL  clean repo, no @piece (exit $got)"; printf '%s\n' "$out" | tail -6 | sed 's/^/        /'; fails=$((fails+1)); fi
printf 'export const s = (k: CryptoKey, m: Uint8Array) => crypto.subtle.sign("Ed25519", k, m);\n' > "$work/mini/clean/sign.ts"; git -C "$work/mini/clean" add -A; git -C "$work/mini/clean" commit -q -m "a signer"
out=$("$here/check-one-signer.sh" --root "$work/mini" --baseline "$bl/mini.tsv" 2>&1); got=$?; total=$((total+1))
if [ "$got" = 2 ] && printf '%s\n' "$out" | grep -q 'clean/sign.ts'; then echo "PASS  the same repo with a signer and no @piece line fails (NEW)"; else echo "FAIL  signer with no @piece (exit $got)"; fails=$((fails+1)); fi

echo
echo "check-one-signer selftest: $((total-fails)) of $total passed"
[ "$fails" = 0 ]
