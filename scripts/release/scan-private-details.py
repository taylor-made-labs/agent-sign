#!/usr/bin/env python3
"""Check that a git tree holds no private deployment details.

agent-sign is a public repository. Its real deployment (a tailnet's name, a
machine's tailnet address, a person's home folder, a map of where the keys
live) must never be in it, in any commit. This is the release check for that,
the companion to scan-history-secrets.py (which looks for secrets): it reads
every file in one revision's tree (default HEAD) and prints, for each problem,
the rule, the path and the line number, never the matched text, so running it
can't leak what it finds. Exit status: 0 when nothing matched, 1 when
something did.

Rules:
  tailnet-name        any name ending in .ts.net other than example.ts.net
                      (so hetzner.example.ts.net is fine)
  tailnet-address     any address in Tailscale's 100.64.0.0/10 range except
                      the range's own base address (100.64.0.0), Tailscale's
                      public DNS address (100.100.100.100) and the one
                      documentation example (100.64.0.10)
  home-folder         the home folder of a real account (the one the
                      maintainer works under); use /home/<user> instead
  user-folder         /Users/<name> for any name but a placeholder (me, me2,
                      alice, bob, user, example, you, or a name in angle
                      brackets); a real name is a person's account
  private-record      a file under docs/signing-step0/ (the map of where
                      signing keys live) or a per-machine settings file
                      other than the example one, scripts/sitting/files/
                      machine-example.env

The names of the real values are not written in this file (it is in the tree
it checks): the home-folder rule is built from pieces, and the others are
patterns.

Usage: scan-private-details.py [repo] [rev]
"""

import re
import subprocess
import sys

# Built from pieces so this source holds no literal of what it forbids.
REAL_ACCOUNT = "tay" + "lor"
RULES = {
    "tailnet-name": re.compile(r"\b(?:[A-Za-z0-9][A-Za-z0-9-]*\.)+ts\.net\b"),
    "tailnet-address": re.compile(r"(?<![\d.])100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}(?![\d])"),
    "home-folder": re.compile(r"/home/" + REAL_ACCOUNT + r"(?![A-Za-z0-9_-])"),
    "user-folder": re.compile(r"/Users/([A-Za-z0-9][^/\s\"'`:;,)\]}]*)"),
}
ALLOWED_ADDRESSES = {"100.64.0.0", "100.100.100.100", "100.64.0.10"}
PLACEHOLDER_USERS = {"me", "me2", "alice", "bob", "user", "example", "you", "a&b"}
PRIVATE_PATHS = [
    re.compile(r"^docs/signing-step0/"),
    re.compile(r"^scripts/sitting/files/machine-(?!example\.env$)[^/]*\.env$"),
]


def git(repo, *args, text=True):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=text, check=True).stdout


def line_findings(text):
    """Rule names that match one line of text."""
    found = []
    for m in RULES["tailnet-name"].finditer(text):
        name = m.group(0).lower()
        if name != "example.ts.net" and not name.endswith(".example.ts.net"):
            found.append("tailnet-name")
    for m in RULES["tailnet-address"].finditer(text):
        if m.group(0) not in ALLOWED_ADDRESSES:
            found.append("tailnet-address")
    if RULES["home-folder"].search(text):
        found.append("home-folder")
    for m in RULES["user-folder"].finditer(text):
        user = m.group(1)
        if user not in PLACEHOLDER_USERS and not user.startswith("<"):
            found.append("user-folder")
    return found


def main():
    repo = sys.argv[1] if len(sys.argv) > 1 else "."
    rev = sys.argv[2] if len(sys.argv) > 2 else "HEAD"
    entries = git(repo, "ls-tree", "-r", "-z", rev).split("\0")
    findings, files = [], 0
    for entry in entries:
        if not entry:
            continue
        meta, _, path = entry.partition("\t")
        sha = meta.split()[2]
        files += 1
        if any(p.search(path) for p in PRIVATE_PATHS):
            findings.append(("private-record", path, 0))
            continue
        data = git(repo, "cat-file", "blob", sha, text=False)
        if b"\0" in data[:8000]:
            continue
        for n, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            for rule in line_findings(line):
                findings.append((rule, path, n))
    print(f"Scanned {files} files in {rev}.")
    for f in findings:
        print("\t".join(map(str, f)))
    print(f"{len(findings)} finding(s).")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
