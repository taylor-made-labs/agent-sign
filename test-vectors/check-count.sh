#!/bin/sh
# Checks that the test examples are exactly the ones counted in COUNT: the number of files, the manifest's total, its
# per-file hashes, and that nothing was added or removed without the count (and the manifest) being changed on purpose.
# Changing an example is a change to the eval itself: do it as its own commit, say so, and change COUNT and the manifest in it.
# Usage: test-vectors/check-count.sh        Exit 0 when everything agrees, 1 otherwise.
cd "$(dirname "$0")" || exit 2
want=$(tr -d ' \n' < COUNT)
files=$(find vectors -name '*.json' | wc -l | tr -d ' ')
total=$(sed -n 's/^  "total": \([0-9]*\),*/\1/p' manifest.json | head -1)
bad=0
[ "$files" = "$want" ] || { echo "COUNT says $want, there are $files example files"; bad=1; }
[ "$total" = "$want" ] || { echo "COUNT says $want, the manifest says $total"; bad=1; }
# every file in the manifest exists and has its recorded hash; every file is in the manifest
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
grep -o '"file": "[^"]*",\|"sha256": "[a-f0-9]*"' manifest.json | paste - - | while IFS="	" read -r f h; do
  f=$(printf '%s' "$f" | sed 's/"file": "\(.*\)",/\1/'); h=$(printf '%s' "$h" | sed 's/"sha256": "\(.*\)"/\1/')
  [ -f "$f" ] || { echo "missing: $f"; exit 1; }
  [ "$(sha "$f")" = "$h" ] || { echo "changed: $f"; exit 1; }
done || bad=1
listed=$(grep -c '"file": "' manifest.json)
[ "$listed" = "$want" ] || { echo "the manifest lists $listed files, COUNT says $want"; bad=1; }
[ "$bad" = 0 ] && echo "test-vectors: $want examples, all present, all hashes match"
exit $bad
