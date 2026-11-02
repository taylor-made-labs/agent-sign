#!/bin/bash
# Plants fake secrets in a throwaway clone of this repo and reports which scan catches each: gitleaks (with
# .gitleaks.toml) or agent-sign's own history scan. It proves the narrow gitleaks allowance for test-vectors/ does not hide
# a real secret: every plant below must be caught by at least one of the two, except the last, which is the one
# documented gap (a seed placed in a field that holds public keys).
#
# The planted values are random and never stored. Everything happens in a temporary clone, never in this repo; the clone is
# deleted at the end (and the deletion is logged in ~/work/deletions.log when that file exists).
# Usage: test-vectors/tools/plant-secrets-test.sh        Exit 0 when every plant except the documented gap is caught.
set -u
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
src=$(cd "$(dirname "$0")/../.." && pwd)
GL=$(command -v gitleaks || echo "$HOME/.local/bin/gitleaks")
w=$(mktemp -d "${TMPDIR:-/tmp}/plant-test.XXXXXX") || { echo "cannot make a temporary folder" >&2; exit 2; }
cleanup() {
  cd / && rm -rf "$w"
  [ -f "$HOME/work/deletions.log" ] && echo "$(date -u +%FT%TZ) agents(signing step0 builder) deleted own temp folder: $w (throwaway clone with planted fake secrets)" >> "$HOME/work/deletions.log"
}
trap cleanup EXIT
git clone -q "$src" "$w/r" || { echo "cannot clone $src" >&2; exit 2; }
cd "$w/r" || exit 2
case "$PWD" in "$w"/*) ;; *) echo "not in the throwaway clone; stopping" >&2; exit 2;; esac
git config user.email t@example.invalid; git config user.name t
cp "$src/.gitleaks.toml" .gitleaks.toml     # the working copy's config, committed or not
node -e '
const c = require("crypto"), fs = require("fs"), path = require("path");
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const rnd = (n, al) => Array.from(c.randomBytes(n), (b) => al[b % al.length]).join("");
const seed = c.randomBytes(32);
const plants = {
  "test-vectors/vectors/zz/PLANT1.json": { seed: "SU" + rnd(56, B32) },                                    // a NATS user seed in a field named seed
  "test-vectors/vectors/zz/PLANT2.json": { seed: seed.toString("base64") },                                // a raw base64 Ed25519 seed, field seed
  "test-vectors/vectors/zz/PLANT3.json": { jwk: { kty: "OKP", crv: "Ed25519", d: seed.toString("base64url") } }, // a JSON web key private d
  "test-vectors/vectors/zz/PLANT4.json": { key: seed.toString("base64") },                                 // a raw base64 seed in a field named key
  "test-vectors/vectors/zz/PLANT5.json": { seed: seed.toString("hex") },                                   // a 64-hex seed, field seed
  "test-vectors/tools/plant6.mjs": "const secret = \"" + seed.toString("hex") + "\";\n",                   // under tools/: a hex seed assigned to a secret
  "test-vectors/tools/plant7.mjs": "const nk = \"SU" + rnd(56, B32) + "\";\n",                              // under tools/: a NATS seed, no field name
  "test-vectors/vectors/zz/PLANT8.json": { rawB64: seed.toString("base64") },                              // the gap: a seed in a field that holds public keys
};
for (const [p, v] of Object.entries(plants)) { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, typeof v === "string" ? v : JSON.stringify(v, null, 2) + "\n"); }
'
git add -A && git commit -q -m plant || { echo "cannot commit the plants" >&2; exit 2; }
"$GL" detect --no-git --source . --redact -f json -r "$w/gl.json" >/dev/null 2>&1
[ -f "$w/gl.json" ] || { echo "gitleaks wrote no report" >&2; exit 2; }
python3 scripts/release/scan-history-secrets.py . HEAD > "$w/py.txt" 2>&1
printf '%-46s %-34s %s\n' plant gitleaks "agent-sign scan"
bad=0
for f in vectors/zz/PLANT1.json vectors/zz/PLANT2.json vectors/zz/PLANT3.json vectors/zz/PLANT4.json vectors/zz/PLANT5.json tools/plant6.mjs tools/plant7.mjs vectors/zz/PLANT8.json; do
  g=$(node -e 'const r=JSON.parse(require("fs").readFileSync(process.argv[1]));console.log([...new Set(r.filter(x=>x.File===process.argv[2]).map(x=>x.RuleID))].join(",")||"-")' "$w/gl.json" "test-vectors/$f")
  p=$(grep "test-vectors/$f" "$w/py.txt" | awk '{print $1}' | sort -u | paste -sd, -)
  printf '%-46s %-34s %s\n' "test-vectors/$f" "$g" "${p:--}"
  if [ "$g" = "-" ] && [ -z "$p" ] && [ "$f" != vectors/zz/PLANT8.json ]; then bad=$((bad+1)); fi
done
echo "plants caught by neither scan, apart from the documented gap: $bad"
[ "$bad" = 0 ]
