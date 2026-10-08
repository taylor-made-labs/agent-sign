#!/usr/bin/env python3
"""Scan every file version in a git repository's history for secrets.

A release check for agent-commits, whose history (inherited from agent-sign) becomes
public at release. gitleaks is the standard tool and is preferred when it is
installed (`gitleaks git --log-opts=--all`); this script is the fallback that
needs only Python and git, so the check can always be run.

It reads every blob reachable from the given revisions (default: all refs),
so a secret added and later deleted is still found. For each match it prints
the rule, the blob, the path and the line number, never the matched text, so
running it can't leak what it finds. Exit status: 0 when nothing matched,
1 when something did.

Rules follow gitleaks' commonest detectors (private keys, GitHub, AWS,
Anthropic, OpenAI, Slack, Google, Stripe and 1Password tokens, JWTs) plus two
broad ones (a quoted secret-like assignment; a 64-hex-digit value, the shape
of an ed25519 seed). Cargo.lock's checksum lines are skipped, since every one
is a 64-hex-digit hash.

Usage: scan-history-secrets.py [repo] [rev ...]
"""

import re
import subprocess
import sys

RULES = {
    "private-key-block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----"),
    "github-token": re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    "aws-access-key": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "anthropic-key": re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    "openai-key": re.compile(r"\bsk-(proj-)?[A-Za-z0-9]{32,}\b"),
    "slack-token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "stripe-live-key": re.compile(r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "1password-service-token": re.compile(r"\bops_[A-Za-z0-9]{40,}"),
    "secret-assignment": re.compile(
        r"(?i)\b(api[_-]?key|secret|token|passwd|password|private[_-]?key)\b\s*[:=]\s*['\"][A-Za-z0-9+/=_\-]{20,}['\"]"
    ),
    "hex-64": re.compile(r"\b[0-9a-fA-F]{64}\b"),
}
CARGO_LOCK_CHECKSUM = re.compile(r'^checksum = "[0-9a-f]{64}"$')


def git(repo, *args, text=True):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=text, check=True).stdout


def main():
    repo = sys.argv[1] if len(sys.argv) > 1 else "."
    revs = sys.argv[2:] or ["--all"]
    objects = git(repo, "rev-list", "--objects", *revs).splitlines()
    seen, findings, blobs = set(), [], 0
    for line in objects:
        sha, _, path = line.partition(" ")
        if not path or sha in seen:
            continue
        seen.add(sha)
        if git(repo, "cat-file", "-t", sha).strip() != "blob":
            continue
        blobs += 1
        data = git(repo, "cat-file", "blob", sha, text=False)
        if b"\0" in data[:8000]:
            findings.append(("binary-file", sha[:10], path, 0))
            continue
        for n, text in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            if path.endswith("Cargo.lock") and CARGO_LOCK_CHECKSUM.match(text):
                continue
            for rule, rx in RULES.items():
                if rx.search(text):
                    findings.append((rule, sha[:10], path, n))
    commits = git(repo, "rev-list", "--count", *revs).strip()
    print(f"Scanned {blobs} file versions in {commits} commits ({' '.join(revs)}).")
    for f in findings:
        print("\t".join(map(str, f)))
    print(f"{len(findings)} finding(s).")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
