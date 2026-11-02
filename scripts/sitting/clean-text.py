"""clean-text: the agent-sign sitting's filter for a throwaway build's messages.

The compile phase runs third-party code (dependencies' build scripts and
proc-macros), so what the build prints is untrusted text on Taylor's terminal.
Filtering bytes is not enough (review of 2 Nov 2026): U+009B, encoded or as a
raw 0x9B byte, is CSI to some terminals, and bidi overrides or zero-width
characters can make a line read differently from what it says. So each line is
filtered by character:

- decoded as strict UTF-8, with invalid bytes dropped (a raw 0x9B, 0xFF,
  overlong forms, surrogates);
- every control character (Unicode category Cc, C0 and C1 alike; tab kept),
  format character (Cf: bidi marks, overrides and isolates, zero-width
  characters, tag characters, U+061C, U+FEFF) and line or paragraph separator
  (Zl, Zp: U+2028, U+2029) removed;
- cut to 300 characters, with a note saying how many were cut.

Usage: python3 -I -S -u clean-text.py [PREFIX]
Standard input to standard output, one line at a time, flushed after each line
so the build's progress shows as it comes. PREFIX (two spaces in the sitting)
starts every line, which sets the build's lines apart from the sitting's own.
"""

import sys
import unicodedata

LIMIT = 300
# A line longer than this is read in pieces; each piece is cut to LIMIT anyway.
READ_LIMIT = 65536
DROP = {"Cc", "Cf", "Zl", "Zp"}


def clean(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="ignore")
    kept = "".join(c for c in text if c == "\t" or unicodedata.category(c) not in DROP)
    if len(kept) > LIMIT:
        kept = f"{kept[:LIMIT]} [{len(kept) - LIMIT} more characters cut]"
    return kept


def main() -> int:
    prefix = sys.argv[1] if len(sys.argv) > 1 else ""
    source, out = sys.stdin.buffer, sys.stdout.buffer
    try:
        while True:
            raw = source.readline(READ_LIMIT)
            if not raw:
                return 0
            out.write((prefix + clean(raw.rstrip(b"\n"))).encode("utf-8") + b"\n")
            out.flush()
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
