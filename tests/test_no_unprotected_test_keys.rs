//! Guard: no test, script or demo makes a private key that is not protected
//! from the moment it exists.
//!
//! The rule is Taylor's, from 28 Oct 2026, after a breach the suite PM found on
//! 1 Nov 2026: every private key is protected from the moment it exists, and
//! tests get no throwaway exception. Never a plain key file, never an empty
//! passphrase given to ssh-keygen's `-N`. A test key lives only in the test
//! process's memory (made with the `ssh-key` crate) and reaches `ssh-keygen` or
//! git through a per-test ssh agent whose socket sits in a private 0700 folder
//! and which is killed when the test ends, loaded over the agent protocol's own
//! add-identity request (`tests/support/key_agent.rs`).
//! If a file is truly unavoidable it is written encrypted, with a random
//! passphrase held in memory and handed over by `SSH_ASKPASS` with
//! `SSH_ASKPASS_REQUIRE=force`. Public keys and certificates may be files.
//!
//! This file reads every file under `tests/`, `scripts/`, `test-vectors/` (not
//! its generated vector data) and any `examples/`, `demo/`, `demos/` or
//! `benches/` folder, and fails, naming file and line, on:
//!   1. an empty `-N` passphrase in any spelling: separate empty argument,
//!      empty double or single quotes (spaced or against the flag), chained
//!      `.arg` calls, escaped quotes inside a Rust string, `String::new()`;
//!   2. an `ssh-keygen` key generation (`-t <type>`) with no `-N` at all, or
//!      with a literal (constant) passphrase;
//!   3. an unencrypted private key written from Rust: `write_openssh_file`, or
//!      any `to_openssh(<line ending>)` (the form only a private key takes; a
//!      public key or certificate calls `to_openssh()` with no argument) that
//!      is not encrypted first, or `to_openssh` on something that looks like a
//!      private key; or an armored private key block written as a literal;
//!   4. (round 2, 1 Nov 2026) the same private key in other spellings: an
//!      armored frame built at run time (`format!`, `concat!`: a `BEGIN` with
//!      `PRIVATE KEY` within 80 bytes of it in one statement, `ENCRYPTED`
//!      aside); the path or trait form `Type::to_openssh(&k, ..)` on anything
//!      but a public key or certificate; `to_pkcs8_pem` and the other private
//!      PEM encoders; the `pem` crate with a `PRIVATE KEY` tag; a private half
//!      written raw (`fs::write(p, pair.to_bytes())`); a base64 literal of the
//!      OpenSSH key-file header, and the header's own text;
//!   5. other key makers: OpenSSL `genpkey`, `genrsa` and `gendsa` without a
//!      cipher and a `-pass stdin` or `-pass fd:` source, `req` with `-nodes`
//!      or `-noenc`, and the age key tool (and its Rust twin) in any mode but
//!      `-y`;
//!   6. a `-N` value that is not a literal, in a key generation: unprotected
//!      unless it is `memory_keys::random_passphrase()` (in Rust, called there
//!      or bound by a `let` of it earlier in the file); a shell `-N` is never
//!      protected. A key generation is also found when its options are
//!      separate `.arg(..)` statements of one `Command::new(..)` builder.
//!
//! The exceptions are explicit and narrow, and keyed on the file name: the one
//! `concat!`-built frame in `tests/support/no_plain_keys.rs` (the runtime
//! backstop's own test frame; the same text in any other file, or a second
//! frame in that one, is a hit), and this file's own run-time-built samples
//! (the guard never reads itself). Every other place that needs such text
//! builds it at run time from pieces, as this file does.
//!
//! DELIBERATE EVAL CHANGE: strengthened (1 Nov 2026, after the independent
//! checker's mutation run found three spellings it missed): `&String::new()`
//! (with a leading ampersand, and `String::from("")`), `to_openssh(LineEnding)`
//! on a plainly named variable such as `key`, and an unquoted constant
//! passphrase (`-N hunter2`). Each now has a case in
//! `detector_catches_every_spelling`. No case was loosened.
//!
//! It excludes itself, and public keys and certificates (`to_openssh` on a
//! `PublicKey` or certificate) are allowed. It is a source reader, so it can be
//! evaded by building a command from pieces at run time; the runtime half,
//! `tests/support/no_plain_keys.rs`, looks at what a test actually left on disk
//! and is the backstop.
//!
//! The bad spellings in the detector's own tests are written with placeholders
//! (`@E@` is an empty double-quote pair, `@S@` an empty single-quote pair,
//! `@X@` an escaped empty pair) and expanded by [`sp`], so this source never
//! carries a literal empty passphrase itself.
//!
//! DELIBERATE EVAL CHANGE (1 Nov 2026, the suite PM's review: the guard is
//! lexical and 14 of 19 Rust bypasses got through; and the merge key check
//! refused this file's own literal constant `-N` case and its neighbour): the
//! bad spellings now build the tool name from placeholders too (`@K@`), and
//! the new `g1_*` cases at the end pin each bypass, one test each, red until the
//! guard has a rule for it. Two existing "allowed" cases changed on purpose: a
//! `-N` value that is a variable is no longer allowed on its own; in Rust it
//! must come from `memory_keys::random_passphrase()`, and a shell `-N` is never
//! protected (the two `$PASS` cases moved to `g1_10c`/`g1_10d`). The runtime
//! half's "an unparseable stand-in is not a key" became its opposite (G2).
//!
//! Std only, so it adds no dependency.

#[path = "support/memory_keys.rs"]
mod memory_keys;
#[path = "support/no_plain_keys.rs"]
mod no_plain_keys;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const ROOTS: &[&str] = &[
    "tests",
    "scripts",
    "test-vectors",
    "examples",
    "demo",
    "demos",
    "benches",
];
/// Folders never read: build output, history, and the generated vector data.
const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules", "vectors", "captured"];
const CODE_EXT: &[&str] = &[
    "rs", "sh", "bash", "zsh", "mjs", "js", "cjs", "ts", "py", "rb", "pl", "service", "plist",
    "yml", "yaml", "toml",
];
const KEY_TYPES: &[&str] = &["ed25519-sk", "ecdsa-sk", "ed25519", "ecdsa", "rsa", "dsa"];
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// How far a command's text may reach either side of a flag.
const WINDOW: usize = 800;

#[derive(Debug, Clone)]
struct Hit {
    file: String,
    line: usize,
    reason: String,
    text: String,
}

#[derive(Debug, PartialEq)]
enum Pass {
    Empty,
    Literal,
    Other,
}

// ---------------------------------------------------------------- scanning

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn find_all(hay: &[u8], needle: &str) -> Vec<usize> {
    let n = needle.as_bytes();
    let mut out = Vec::new();
    if n.is_empty() || hay.len() < n.len() {
        return out;
    }
    for i in 0..=hay.len() - n.len() {
        if &hay[i..i + n.len()] == n {
            out.push(i);
        }
    }
    out
}

/// A short flag (`-N`, `-t`) as its own token: not inside a word or a longer
/// dash run, and not followed by a word character (`-Name`).
fn flag_at(b: &[u8], i: usize, flag: &str) -> bool {
    let f = flag.as_bytes();
    if i + f.len() > b.len() || &b[i..i + f.len()] != f {
        return false;
    }
    if i > 0 && (is_word(b[i - 1]) || b[i - 1] == b'-') {
        return false;
    }
    !(i + f.len() < b.len() && is_word(b[i + f.len()]))
}

/// Comment-only lines blanked (same length, so offsets and line numbers hold).
fn blank_comments(text: &str, ext: &str) -> String {
    let slashes = matches!(ext, "rs" | "js" | "mjs" | "cjs" | "ts");
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let t = line.trim_start();
        let comment = if slashes {
            t.starts_with("//")
        } else {
            t.starts_with('#') && !t.starts_with("#!")
        };
        if comment {
            for c in line.chars() {
                out.push(if c == '\n' { '\n' } else { ' ' });
            }
        } else {
            out.push_str(line);
        }
    }
    out
}

fn shellish(ext: &str) -> bool {
    matches!(ext, "sh" | "bash" | "zsh" | "")
}

/// The statement around `i`: for shell, the logical line (backslash
/// continuations joined); otherwise from the previous `;` or blank line to the
/// next one. Capped at [`WINDOW`] either side.
fn window(b: &[u8], i: usize, sh: bool) -> (usize, usize) {
    let lo_cap = i.saturating_sub(WINDOW);
    let hi_cap = (i + WINDOW).min(b.len());
    let mut s = i;
    while s > lo_cap {
        let c = b[s - 1];
        let stop = if sh {
            c == b'\n' && !(s >= 2 && b[s - 2] == b'\\')
        } else {
            c == b';' || (c == b'\n' && s >= 2 && b[s - 2] == b'\n')
        };
        if stop {
            break;
        }
        s -= 1;
    }
    let mut e = i;
    while e < hi_cap {
        let c = b[e];
        let stop = if sh {
            c == b'\n' && !(e >= 1 && b[e - 1] == b'\\')
        } else {
            c == b';' || (c == b'\n' && e + 1 < b.len() && b[e + 1] == b'\n')
        };
        if stop {
            break;
        }
        e += 1;
    }
    (s, e)
}

/// Where the value of a flag begins, past the flag token's own closing quote,
/// separators, and a `.arg(` between two chained arguments.
fn value_start(b: &[u8], after_flag: usize) -> usize {
    let mut p = after_flag.min(b.len());
    if b[p..].starts_with(b"\\\"") {
        p += 2;
    } else if p < b.len() && (b[p] == b'"' || b[p] == b'\'') {
        p += 1;
    }
    loop {
        while p < b.len() && matches!(b[p], b' ' | b'\t' | b'\r' | b'\n' | b',' | b')') {
            p += 1;
        }
        if b[p..].starts_with(b".args(") {
            p += 6;
        } else if b[p..].starts_with(b".arg(") {
            p += 5;
        } else if b[p..].starts_with(b"&[") {
            p += 2;
        } else if b[p..].starts_with(b"[") {
            p += 1;
        } else if let Some(next) = next_statement_argument(b, p) {
            p = next;
        } else {
            return p;
        }
    }
}

/// A command builder's next statement continues its argument list:
/// `c.arg("-N"); c.arg(&*pass);`. Returns where that next argument starts.
fn next_statement_argument(b: &[u8], p: usize) -> Option<usize> {
    if b.get(p) != Some(&b';') {
        return None;
    }
    let mut q = p + 1;
    while q < b.len() && b[q].is_ascii_whitespace() {
        q += 1;
    }
    let name = q;
    while q < b.len() && is_word(b[q]) {
        q += 1;
    }
    if q == name {
        None
    } else if b[q..].starts_with(b".args(") {
        Some(q + 6)
    } else if b[q..].starts_with(b".arg(") {
        Some(q + 5)
    } else {
        None
    }
}

/// How far, in bytes, a command built over several statements may reach: one
/// `Command::new(..)` builder up to the next one.
const REGION: usize = 1600;
/// How far past `BEGIN` the `PRIVATE KEY` of a key frame may be.
const FRAME_REACH: usize = 80;
/// The one file allowed one `concat!`-built key frame: the runtime backstop's
/// own test frame. Narrow on purpose: the same text in another file, or a
/// second frame here, is a hit.
const BACKSTOP_FILE: &str = "tests/support/no_plain_keys.rs";
/// The only passphrase source a Rust test may give a key tool's `-N`.
const PASSPHRASE_HELPER: &str = "memory_keys::random_passphrase(";
/// Text that marks a statement as about a public half, a certificate or an
/// encrypted key (so a `to_openssh` or `to_bytes` there is not a plain private
/// key).
const PUBLIC_HALF: &[&str] = &[
    "PublicKey",
    "public_key",
    "Certificate",
    "cert",
    ".encrypt(",
    "verifying_key",
    "pubkey",
    "public",
];
/// Words that mark a value as a private half when it is written raw.
const RAW_PRIVATE: &[&str] = &[
    "pair",
    "Keypair",
    "keypair",
    "KeypairData",
    "PrivateKey",
    "SigningKey",
    "signing_key",
    "secret",
    "private",
    "seed",
];
/// Calls that put bytes into a file.
const FILE_SINKS: &[&str] = &[
    "fs::write(",
    "File::create(",
    "write_all(",
    "OpenOptions",
    ".write(",
];

/// The key tools' names, built from pieces so this source never holds one.
fn tool_ssl() -> String {
    ["open", "ssl"].concat()
}
fn tool_age() -> String {
    ["age", "keygen"].join("-")
}
/// The base64 start of an OpenSSH key file, and the file's own magic text.
fn key_file_head() -> String {
    ["b3BlbnNzaC1rZXkt", "djE"].concat()
}
fn key_file_magic() -> String {
    ["openssh", "key", "v1"].join("-")
}
/// Names for the 1 Nov 2026 rules (OpenSSL's curve-parameter key maker, the
/// Python `cryptography` plain private-key encoder, and the GnuPG key makers),
/// built from pieces so this source never holds a key-making command.
fn tool_gpg() -> String {
    ["g", "pg"].concat()
}
fn flag_gpg_passphrase() -> String {
    ["--pass", "phrase"].concat()
}
fn gpg_key_makers() -> Vec<String> {
    vec![
        ["--quick", "-gen-key"].concat(),
        ["--quick", "-generate-key"].concat(),
        ["--quick", "-add-key"].concat(),
        ["--gen", "-key"].concat(),
        ["--generate", "-key"].concat(),
        ["--full", "-gen-key"].concat(),
        ["--full", "-generate-key"].concat(),
    ]
}

/// Where a `-N` value comes from.
#[derive(Debug, PartialEq)]
enum Origin {
    /// Nothing that is a value (`-N` against another option, or at the end).
    NoValue,
    /// `memory_keys::random_passphrase()`, called there or bound by a `let`.
    Helper,
    /// Anything else: a variable, a call, an environment value, a shell word.
    Elsewhere,
}

/// Where the value after the `-N` that ends at `after` comes from. Only Rust
/// has the in-memory helper; a shell (or any other language) value is never
/// protected.
fn passphrase_origin(b: &[u8], after: usize, rust: bool) -> Origin {
    let p = value_start(b, after);
    let mut rest = &b[p.min(b.len())..];
    while matches!(rest.first(), Some(b'&') | Some(b'*') | Some(b'(')) {
        rest = &rest[1..];
    }
    let Some(&c) = rest.first() else {
        return Origin::NoValue;
    };
    if rust && (c.is_ascii_alphabetic() || c == b'_') {
        let end = rest
            .iter()
            .position(|&x| !(is_word(x) || x == b':'))
            .unwrap_or(rest.len());
        let path = String::from_utf8_lossy(&rest[..end]).to_string();
        if rest.get(end) == Some(&b'(') {
            return if format!("{path}(") == PASSPHRASE_HELPER {
                Origin::Helper
            } else {
                Origin::Elsewhere
            };
        }
        if path.contains("::") {
            return Origin::Elsewhere;
        }
        return if bound_to_helper(b, p, &path) {
            Origin::Helper
        } else {
            Origin::Elsewhere
        };
    }
    if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'$' | b'`' | b'{' | b'%' | b'"' | b'\'') {
        Origin::Elsewhere
    } else {
        Origin::NoValue
    }
}

/// Whether the latest `let name = ..;` before `upto` binds the helper's value.
fn bound_to_helper(b: &[u8], upto: usize, name: &str) -> bool {
    let head = &b[..upto.min(b.len())];
    let mut bound_at = None;
    for i in find_all(head, "let ") {
        if i > 0 && is_word(head[i - 1]) {
            continue;
        }
        let mut q = i + 4;
        if head[q..].starts_with(b"mut ") {
            q += 4;
        }
        let ends = q + name.len();
        if head[q..].starts_with(name.as_bytes()) && !head.get(ends).is_some_and(|&c| is_word(c)) {
            bound_at = Some(ends);
        }
    }
    let Some(from) = bound_at else {
        return false;
    };
    let end = b[from..]
        .iter()
        .position(|&c| c == b';')
        .map_or(b.len(), |x| from + x);
    String::from_utf8_lossy(&b[from..end]).contains(PASSPHRASE_HELPER)
}

/// The text a flag or tool at `i` belongs to. For Rust, one command builder:
/// from the nearest `Command::new(` before `i` to the next one, so options set
/// by separate `.arg(..)` statements are read together. Otherwise (shell, or
/// Rust with no builder near) the statement around `i`.
fn scope(b: &[u8], i: usize, sh: bool, rust: bool) -> (usize, usize) {
    const BUILDER: &[u8] = b"Command::new(";
    if rust {
        let lo = i.saturating_sub(REGION);
        if let Some(rel) = b[lo..i].windows(BUILDER.len()).rposition(|w| w == BUILDER) {
            let start = lo + rel;
            let hi = (i + REGION).min(b.len());
            let from = (start + BUILDER.len()).max(i).min(hi);
            let end = b[from..hi]
                .windows(BUILDER.len())
                .position(|w| w == BUILDER)
                .map_or(hi, |r| from + r);
            return (start, end);
        }
    }
    window(b, i, sh)
}

/// `word` as a whole word: not inside a longer word or option name.
fn word_at(b: &[u8], i: usize, word: &str) -> bool {
    let w = word.as_bytes();
    b.len() >= i + w.len()
        && &b[i..i + w.len()] == w
        && (i == 0 || !(is_word(b[i - 1]) || b[i - 1] == b'-'))
        && !b.get(i + w.len()).is_some_and(|&c| is_word(c) || c == b'-')
}

fn has_word(b: &[u8], word: &str) -> bool {
    find_all(b, word).into_iter().any(|i| word_at(b, i, word))
}

/// A tool's name at `start..end` as a command: not part of a longer name or
/// path component.
fn tool_at(b: &[u8], start: usize, end: usize) -> bool {
    let before = start.checked_sub(1).map(|k| b[k]);
    let after = b.get(end).copied();
    !before.is_some_and(|c| is_word(c) || c == b'.' || c == b'-')
        && !after.is_some_and(|c| is_word(c) || c == b'-')
}

/// Whether an OpenSSL key-making command asks for a cipher and takes the
/// passphrase from standard input or a descriptor.
fn ssl_protected(w: &[u8]) -> bool {
    let cipher = ["-aes", "-des", "-camellia", "-aria", "-cipher"]
        .iter()
        .any(|c| !find_all(w, c).is_empty());
    let pass = ["-passout", "-pass"].iter().any(|flag| {
        find_all(w, flag).into_iter().any(|j| {
            let mut v = &w[value_start(w, j + flag.len()).min(w.len())..];
            if v.first() == Some(&b'"') {
                v = &v[1..];
            }
            v.starts_with(b"stdin") || v.starts_with(b"fd:")
        })
    });
    cipher && pass
}

/// What is passed as the passphrase after the `-N` that ends at `after`.
fn passphrase_after(b: &[u8], after: usize) -> Pass {
    // The empty value right against the flag.
    let rest = &b[after.min(b.len())..];
    if rest.starts_with(b"\"\"") || rest.starts_with(b"''") || rest.starts_with(b"\\\"\\\"") {
        return Pass::Empty;
    }
    // DELIBERATE EVAL CHANGE: strengthened. A bare word after the flag and a
    // space (shell: `-N hunter2`) is a constant passphrase. A `$var`, `{pw}`
    // or `%s` does not start with a letter, digit or underscore, so it is not.
    if matches!(b.get(after), Some(b' ') | Some(b'\t')) {
        let mut q = after;
        while q < b.len() && matches!(b[q], b' ' | b'\t') {
            q += 1;
        }
        if q < b.len() && (b[q].is_ascii_alphanumeric() || b[q] == b'_') {
            return Pass::Literal;
        }
    }
    let p = value_start(b, after);
    let mut rest = &b[p..];
    // DELIBERATE EVAL CHANGE: strengthened. A borrowed value (`&String::new()`)
    // is the same value.
    while rest.first() == Some(&b'&') {
        rest = &rest[1..];
    }
    if rest.starts_with(b"\"\"")
        || rest.starts_with(b"''")
        || rest.starts_with(b"\\\"\\\"")
        || rest.starts_with(b"String::new()")
        || rest.starts_with(b"String::default()")
        || rest.starts_with(b"String::from(\"\")")
    {
        return Pass::Empty;
    }
    let (open, skip): (u8, usize) = if rest.starts_with(b"\\\"") {
        (b'"', 2)
    } else if rest.first() == Some(&b'"') || rest.first() == Some(&b'\'') {
        (rest[0], 1)
    } else {
        return Pass::Other;
    };
    let body = &rest[skip..];
    let end = body
        .iter()
        .position(|&c| c == open || c == b'\\')
        .unwrap_or(body.len());
    let lit = &body[..end];
    if lit.is_empty() {
        Pass::Empty
    } else if lit.iter().any(|&c| matches!(c, b'$' | b'{' | b'%' | b'`')) {
        Pass::Other
    } else {
        Pass::Literal
    }
}

fn line_of(text: &str, off: usize) -> usize {
    text.as_bytes()[..off.min(text.len())]
        .iter()
        .filter(|&&c| c == b'\n')
        .count()
        + 1
}

fn scan_text(name: &str, ext: &str, original: &str) -> Vec<Hit> {
    let code = blank_comments(original, ext);
    let b = code.as_bytes();
    let sh = shellish(ext);
    let rust = ext == "rs";
    let orig_lines: Vec<&str> = original.lines().collect();
    let mut hits: Vec<Hit> = Vec::new();
    let mut add = |off: usize, reason: &str| {
        let line = line_of(&code, off);
        let text = orig_lines
            .get(line - 1)
            .map(|l| l.trim().to_string())
            .unwrap_or_default();
        let text: String = text.chars().take(150).collect();
        if !hits.iter().any(|h| h.line == line && h.reason == reason) {
            hits.push(Hit {
                file: name.to_string(),
                line,
                reason: reason.to_string(),
                text,
            });
        }
    };

    // 1. An empty -N anywhere.
    for i in find_all(b, "-N") {
        if flag_at(b, i, "-N") && passphrase_after(b, i + 2) == Pass::Empty {
            add(
                i,
                "empty passphrase: `-N` with an empty value makes an unprotected key",
            );
        }
    }

    // 2. A key generation (`-t <type>`) in a keygen command with no -N, or a
    //    constant one.
    for i in find_all(b, "-t") {
        if !flag_at(b, i, "-t") {
            continue;
        }
        let mut v = value_start(b, i + 2);
        if b[v..].starts_with(b"\\\"") {
            v += 2;
        } else if v < b.len() && (b[v] == b'"' || b[v] == b'\'') {
            v += 1;
        }
        let is_type = KEY_TYPES.iter().any(|t| {
            b[v..].starts_with(t.as_bytes())
                && !b.get(v + t.len()).map(|&c| is_word(c)).unwrap_or(false)
        });
        if !is_type {
            continue;
        }
        let (s, e) = scope(b, i, sh, rust);
        if !String::from_utf8_lossy(&b[s..e]).contains("keygen") {
            continue; // ssh-keyscan -t ed25519 and the like
        }
        let w = &b[s..e];
        let mut any_n = false;
        let mut literal_at = None;
        let mut elsewhere_at = None;
        for j in find_all(w, "-N") {
            if flag_at(w, j, "-N") {
                any_n = true;
                match passphrase_after(b, s + j + 2) {
                    Pass::Literal => literal_at = Some(s + j),
                    Pass::Other if passphrase_origin(b, s + j + 2, rust) == Origin::Elsewhere => {
                        elsewhere_at = Some(s + j);
                    }
                    _ => {}
                }
            }
        }
        if let Some(off) = literal_at {
            add(
                off,
                "constant passphrase: a literal `-N` value is no protection",
            );
        }
        if let Some(off) = elsewhere_at {
            add(
                off,
                "passphrase not from the in-memory helper: a variable, call or shell word as the `-N` value is unprotected unless it is memory_keys::random_passphrase()",
            );
        }
        if !any_n {
            add(
                i,
                "key generation with no `-N`: it makes a key file without a protected passphrase",
            );
        }
    }

    // 3. Unencrypted private key written from Rust, or an armored block.
    if ext == "rs" {
        for i in find_all(b, "write_openssh_file(") {
            let (s, e) = window(b, i, false);
            if !String::from_utf8_lossy(&b[s..e]).contains(".encrypt(") {
                add(
                    i,
                    "write_openssh_file on a key that was not encrypted first",
                );
            }
        }
        const PRIVATE: &[&str] = &[
            "PrivateKey",
            "Ed25519Keypair",
            "KeypairData",
            "from_seed",
            "SigningKey",
            "private",
            "secret",
            "signing_key",
        ];

        for i in find_all(b, ".to_openssh(") {
            let (s, e) = window(b, i, false);
            let w = String::from_utf8_lossy(&b[s..e]).to_string();
            // DELIBERATE EVAL CHANGE: strengthened. Only a private key's
            // `to_openssh` takes an argument (the line ending); a public key or
            // certificate's takes none. So an argument, with no `.encrypt(` in
            // the statement, is a plain private key whatever the variable is
            // called.
            let mut a = i + ".to_openssh(".len();
            while a < b.len() && b[a].is_ascii_whitespace() {
                a += 1;
            }
            let takes_arg = a < b.len() && b[a] != b')';
            let looks_private =
                PRIVATE.iter().any(|m| w.contains(m)) && !PUBLIC_HALF.iter().any(|m| w.contains(m));
            if (takes_arg && !w.contains(".encrypt(")) || looks_private {
                add(
                    i,
                    "to_openssh on a private key (encrypt it first, or keep it in memory)",
                );
            }
        }
    }

    // 4. The same private key in other spellings (round 2, 1 Nov 2026).
    // 4a. An armored frame, literal or built (`format!`, `concat!`). The one
    //     exception is the runtime backstop's own `concat!` frame.
    let mut backstop_frame_spare = name == BACKSTOP_FILE && rust;
    for i in find_all(b, "BEGIN") {
        if (i > 0 && is_word(b[i - 1])) || b.get(i + 5).is_some_and(|&c| is_word(c)) {
            continue;
        }
        let reach = &b[i + 5..(i + 5 + FRAME_REACH).min(b.len())];
        let reach = &reach[..reach.iter().position(|&c| c == b';').unwrap_or(reach.len())];
        let text = String::from_utf8_lossy(reach);
        let Some(k) = text.find("PRIVATE KEY") else {
            continue;
        };
        if text[..k].contains("ENCRYPTED") {
            continue;
        }
        if backstop_frame_spare {
            let (s, e) = window(b, i, false);
            if String::from_utf8_lossy(&b[s..e]).contains("concat!(") {
                backstop_frame_spare = false;
                continue;
            }
        }
        add(
            i,
            "an armored private key written as a literal, or built into a frame",
        );
    }
    // 4b. The OpenSSH key file's header, in base64 or as its own text.
    for (needle, why) in [
        (
            key_file_head(),
            "the base64 header of an OpenSSH private key file",
        ),
        (key_file_magic(), "the header text of an OpenSSH key file"),
    ] {
        for i in find_all(b, &needle) {
            add(i, why);
        }
    }
    // 4c. OpenSSL's key makers without a cipher and a passphrase source.
    let ssl = tool_ssl();
    for i in find_all(b, &ssl) {
        if !tool_at(b, i, i + ssl.len()) {
            continue;
        }
        let (s, e) = scope(b, i, sh, rust);
        let w = &b[s..e];
        let makes = ["genpkey", "genrsa", "gendsa"]
            .iter()
            .any(|v| has_word(w, v));
        let plain_request = has_word(w, "req") && (has_word(w, "-nodes") || has_word(w, "-noenc"));
        if (makes && !ssl_protected(w)) || plain_request {
            add(
                i,
                "OpenSSL makes a private key with no cipher and passphrase (genpkey/genrsa/gendsa without -pass stdin, or req with -nodes)",
            );
        }
        // The curve-parameter tool's key mode writes a plain EC private key
        // unless a later stage of the same command encrypts it.
        if has_word(w, &["ecp", "aram"].concat())
            && has_word(w, &["-gen", "key"].concat())
            && !ssl_protected(w)
        {
            add(
                i,
                "OpenSSL's curve-parameter tool makes a plain EC private key (its key mode with no cipher and -pass stdin in the same command)",
            );
        }
    }
    // 4d. The age key tool writes its secret key in the clear; only `-y` (the
    //     public half) is a reading mode.
    let age = tool_age();
    for i in find_all(b, &age) {
        let start = if i > 0 && b[i - 1] == b'r' { i - 1 } else { i };
        if !tool_at(b, start, i + age.len()) {
            continue;
        }
        let (s, e) = scope(b, i, sh, rust);
        let w = &b[s..e];
        if !find_all(w, "-y").into_iter().any(|j| flag_at(w, j, "-y")) {
            add(
                i,
                "the age key tool prints a secret key in the clear (only its -y mode is a reading mode)",
            );
        }
    }
    if rust {
        // 4e. The path or trait form of `to_openssh`.
        for i in find_all(b, "::to_openssh(") {
            let (s, e) = window(b, i, false);
            let w = String::from_utf8_lossy(&b[s..e]).to_string();
            if !PUBLIC_HALF.iter().any(|m| w.contains(m)) {
                add(
                    i,
                    "to_openssh in its path or trait form on something that is not a public key or certificate",
                );
            }
        }
        // 4f. A private half written raw.
        for needle in [".to_bytes(", ".to_keypair_bytes("] {
            for i in find_all(b, needle) {
                let (s, e) = window(b, i, false);
                let w = String::from_utf8_lossy(&b[s..e]).to_string();
                if FILE_SINKS.iter().any(|m| w.contains(m))
                    && RAW_PRIVATE.iter().any(|m| w.contains(m))
                    && !PUBLIC_HALF.iter().any(|m| w.contains(m))
                {
                    add(i, "the raw private half of a key written to a file");
                }
            }
        }
        // 4g. A private key as PEM: the RustCrypto encoders, and the pem crate.
        for needle in ["to_pkcs8_pem(", "to_sec1_pem("] {
            for i in find_all(b, needle) {
                add(i, "a private key encoded as unencrypted PEM");
            }
        }
        for needle in ["to_pkcs8_der(", "to_sec1_der("] {
            for i in find_all(b, needle) {
                let (s, e) = window(b, i, false);
                if FILE_SINKS
                    .iter()
                    .any(|m| String::from_utf8_lossy(&b[s..e]).contains(m))
                {
                    add(
                        i,
                        "a private key encoded as unencrypted DER, written to a file",
                    );
                }
            }
        }
        for i in find_all(b, "PRIVATE KEY\"") {
            let (s, e) = window(b, i, false);
            let w = String::from_utf8_lossy(&b[s..e]).to_string();
            if (w.contains("pem::") || w.contains("Pem::")) && !w.contains("ENCRYPTED") {
                add(i, "the pem crate given a private key tag");
            }
        }
    }

    // 4h. Python `cryptography`: a private key serialised with the
    //     no-encryption option (any alias of it counts: the file only has to
    //     serialise a private key somewhere and construct the option).
    if ext == "py" {
        let ne = [["No", "Encryption"].concat(), "(".to_string()].concat();
        let pb = [["private", "_bytes"].concat(), "(".to_string()].concat();
        if !find_all(b, &pb).is_empty() {
            for i in find_all(b, &ne) {
                if i == 0 || !is_word(b[i - 1]) {
                    add(
                        i,
                        "a private key serialised with the no-encryption option (use a best-available-encryption option with a random passphrase)",
                    );
                }
            }
        }
    }
    // 4i. GnuPG making a key with an empty or constant passphrase.
    let gpg = tool_gpg();
    let gpg_pass = flag_gpg_passphrase();
    for i in find_all(b, &gpg) {
        let mut end = i + gpg.len();
        if b.get(end) == Some(&b'2') {
            end += 1;
        }
        if !tool_at(b, i, end) {
            continue;
        }
        let (s, e) = scope(b, i, sh, rust);
        let w = &b[s..e];
        if !gpg_key_makers().iter().any(|f| has_word(w, f)) {
            continue;
        }
        for j in find_all(w, &gpg_pass) {
            if !word_at(w, j, &gpg_pass) {
                continue; // the descriptor and file forms are other options
            }
            let mut after = s + j + gpg_pass.len();
            let eq = b.get(after) == Some(&b'=');
            if eq {
                after += 1;
            }
            let bad = match passphrase_after(b, after) {
                Pass::Empty | Pass::Literal => true,
                Pass::Other => {
                    eq && b
                        .get(after)
                        .is_some_and(|&c| c.is_ascii_alphanumeric() || c == b'_')
                }
            };
            if bad {
                add(
                    i,
                    "GnuPG makes a key with an empty or constant passphrase (take it from a descriptor, e.g. a passphrase-fd option)",
                );
            }
        }
    }

    hits.sort_by_key(|h| h.line);
    hits
}

// ------------------------------------------------------------ file walking

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        let name = entry.file_name().to_string_lossy().to_string();
        if meta.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                collect(&path, out);
            }
        } else if meta.is_file() && meta.len() <= MAX_FILE_BYTES {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext.is_empty() || CODE_EXT.contains(&ext) {
                out.push(path);
            }
        }
    }
}

fn scan_repo() -> (Vec<String>, Vec<Hit>) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let me = root.join(file!());
    let me = fs::canonicalize(&me).unwrap_or(me);
    let mut files = Vec::new();
    for r in ROOTS {
        collect(&root.join(r), &mut files);
    }
    files.sort();
    let mut scanned = Vec::new();
    let mut hits = Vec::new();
    for f in files {
        if fs::canonicalize(&f).map(|c| c == me).unwrap_or(false) {
            continue; // excludes itself
        }
        let Ok(text) = fs::read_to_string(&f) else {
            continue;
        };
        let rel = f
            .strip_prefix(&root)
            .unwrap_or(&f)
            .to_string_lossy()
            .replace('\\', "/");
        let ext = f
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_string();
        hits.extend(scan_text(&rel, &ext, &text));
        scanned.push(rel);
    }
    (scanned, hits)
}

// ------------------------------------------------------------------- tests

/// The guard. Red while any test or script makes an unprotected private key.
#[test]
fn no_test_or_script_makes_an_unprotected_private_key() {
    let (scanned, hits) = scan_repo();
    // A guard that scans nothing is green for the wrong reason.
    assert!(
        scanned.len() >= 30,
        "the guard read only {} files: did the folders it scans move?",
        scanned.len()
    );
    assert!(
        scanned.iter().any(|f| f == "tests/test_allowed_agents.rs"),
        "the guard did not read tests/test_allowed_agents.rs"
    );
    if !hits.is_empty() {
        let mut msg = format!(
            "{} place(s) make a private key that is not protected from the moment it exists \
             (rule of 28 Oct 2026: tests get no exception). Keep the key in the test's memory \
             (ssh-key crate), load it into a per-test ssh agent over the agent protocol \
             (tests/support/key_agent.rs) and sign through the agent:\n",
            hits.len()
        );
        for h in &hits {
            msg.push_str(&format!(
                "  {}:{}: {}\n      {}\n",
                h.file, h.line, h.reason, h.text
            ));
        }
        panic!("{msg}");
    }
}

/// Expands the placeholders described in the module comment.
fn sp(s: &str) -> String {
    s.replace("@E@", "\"\"")
        .replace("@S@", "''")
        .replace("@X@", "\\\"\\\"")
        // Added 1 Nov 2026 (key check: no literal tool name, constant passphrase
        // or frame next to key-making options in this source).
        .replace("@Q@", "\"")
        .replace("@K@", &["ssh", "keygen"].join("-"))
        .replace("@O@", &["open", "ssl"].concat())
        .replace("@A@", &["age", "keygen"].join("-"))
        .replace("@H@", &["b3BlbnNzaC1rZXkt", "djE"].concat())
}

fn reasons(ext: &str, src: &str) -> Vec<String> {
    scan_text("x", ext, &sp(src))
        .into_iter()
        .map(|h| h.reason)
        .collect()
}

/// Every spelling of the same mistake is caught.
#[test]
fn detector_catches_every_spelling() {
    let bad: &[(&str, &str)] = &[
        (
            "rs",
            r#"cmd.args(["-q", "-t", "ed25519", "-N", @E@, "-C", "p", "-f"]);"#,
        ),
        (
            "rs",
            "Command::new(\"@K@\").args([\"-t\",\n \"ed25519\",\n \"-N\",\n @E@,\n \"-f\"]);",
        ),
        ("rs", r#"Command::new("@K@").arg("-N").arg(@E@);"#),
        ("rs", r#"let a = ["-N", String::new()];"#),
        ("rs", r#"let a = ["-N", &String::new()];"#),
        (
            "rs",
            r#"Command::new("@K@").args(["-q", "-t", "ed25519", "-N", &String::new(), "-f", "k"]);"#,
        ),
        ("rs", r#"let a = ["-N", &String::from(@E@)];"#),
        ("rs", r#"let a = ["-N", String::default()];"#),
        ("sh", "@K@ -q -t ed25519 -N hunter2 -f k"),
        ("rs", r#"sh("@K@ -q -t ed25519 -N hunter2 -f k");"#),
        (
            "rs",
            "let key = make();\nstd::fs::write(&p, key.to_openssh(LineEnding::LF).unwrap()).unwrap();",
        ),
        (
            "rs",
            "fs::write(&p, key.to_openssh(\n    LineEnding::LF).unwrap()).unwrap();",
        ),
        ("rs", r#"sh("@K@ -q -t rsa -N @X@ -f k");"#),
        (
            "rs",
            r#"Command::new("@K@").args(["-t", "ed25519", "-N", "hunter2", "-f", "k"]);"#,
        ),
        (
            "rs",
            r#"Command::new("@K@").args(["-q", "-t", "ed25519", "-f", "k"]);"#,
        ),
        (
            "rs",
            "let k = PrivateKey::from(Ed25519Keypair::from_seed(&s)).to_openssh(LineEnding::LF).unwrap();",
        ),
        (
            "rs",
            "key.write_openssh_file(&path, LineEnding::LF).unwrap();",
        ),
        ("sh", "@K@ -q -t ed25519 -N @E@ -f k"),
        ("sh", "@K@ -q -t ed25519 -N @S@ -f k"),
        ("sh", "@K@ -q -t ed25519 -N@S@ -f k"),
        ("sh", "@K@ -q -t ed25519 -N@E@ -f k"),
        ("sh", "@K@ -q -t ed25519 -N @Q@test@Q@ -f k"),
        ("sh", "@K@ -q -t ed25519 \\\n  -f k"),
        ("sh", "@K@ -p -N @E@ -f k"),
        (
            "py",
            "subprocess.run(['@K@', '-t', 'ed25519', '-N', @S@, '-f', 'k'])",
        ),
    ];
    for (ext, src) in bad {
        assert!(!reasons(ext, src).is_empty(), "not caught ({ext}): {src}");
    }
    let armor = format!(
        "fs::write(p, \"-----BEGIN {} PRIVATE KEY-----\\nx\");",
        "OPENSSH"
    );
    assert!(
        !reasons("rs", &armor).is_empty(),
        "armor literal not caught"
    );
}

/// Protected patterns, public keys, certificates and look-alikes are allowed.
#[test]
fn detector_allows_protected_patterns() {
    let good: &[(&str, &str)] = &[
        (
            "rs",
            "let pass = memory_keys::random_passphrase();\nCommand::new(\"@K@\").args([\"-t\", \"ed25519\", \"-N\", &pass, \"-f\", \"k\"]);",
        ),
        ("sh", "ssh-keyscan -t ed25519 host"),
        (
            "rs",
            "let pass = memory_keys::random_passphrase();\nlet a = [\"-t\", \"ed25519\", \"-N\", &pass, \"-f\"]; @K@",
        ),
        (
            "rs",
            "key.encrypt(&mut rng, pass).unwrap().to_openssh(LineEnding::LF).unwrap();",
        ),
        ("sh", "ssh-keygen -Y verify -f allowed -I who -n git -s sig"),
        ("sh", "ssh-keygen -l -f ca.pub"),
        ("sh", "ssh-add - < /dev/stdin"),
        (
            "rs",
            "ssh_key::PublicKey::new(data, @E@).to_openssh().unwrap();",
        ),
        ("rs", "let s = cert.to_openssh().unwrap();"),
        ("rs", "-t|-N|-b|-A) mutation keygen \"$*\";"),
        ("rs", "let id = \"PUB-N10\"; let o = \"LOG-N01\";"),
        (
            "rs",
            "// cmd.args([\"-t\", \"ed25519\", \"-N\", @E@]) in a comment",
        ),
        ("sh", "# ssh-keygen -q -t ed25519 -N @E@ -f k  (a comment)"),
        (
            "rs",
            "key.encrypt(&mut rng, pass).unwrap().write_openssh_file(&p, LineEnding::LF).unwrap();",
        ),
    ];
    for (ext, src) in good {
        assert!(
            reasons(ext, src).is_empty(),
            "false hit ({ext}): {src}: {:?}",
            reasons(ext, src)
        );
    }
}

/// The runtime half sees an unencrypted key, and lets public keys, stand-ins
/// and (non-key) text pass. The keys here are made in memory and never written.
#[test]
fn runtime_check_tells_plain_keys_from_the_rest() {
    use ssh_key::private::Ed25519Keypair;
    use ssh_key::{LineEnding, PrivateKey};
    let seed: [u8; 32] = rand::random();
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    let plain = key.to_openssh(LineEnding::LF).unwrap();
    assert!(
        no_plain_keys::is_plain_private_key(&plain),
        "an unencrypted OpenSSH key is plain"
    );
    let public = key.public_key().to_openssh().unwrap();
    assert!(
        !no_plain_keys::is_plain_private_key(&public),
        "a public key is allowed"
    );
    assert!(!no_plain_keys::is_plain_private_key(
        "ssh-ed25519 AAAA cert"
    ));
    let fake = format!("-----BEGIN {} PRIVATE KEY-----\nx\n", "OPENSSH");
    // DELIBERATE EVAL CHANGE (1 Nov 2026, the suite PM): this used to say an
    // unparseable OpenSSH frame is "not a key". It is a hit: only a frame that
    // parses AND is encrypted passes (G2; the new cases are `g2_*` below).
    assert!(
        no_plain_keys::is_plain_private_key(&fake),
        "an unparseable OpenSSH frame counts as a hit"
    );
    let pem_enc = format!(
        "-----BEGIN ENCRYPTED {0} KEY-----\nx\n-----END ENCRYPTED {0} KEY-----",
        "PRIVATE"
    );
    assert!(!no_plain_keys::is_plain_private_key(&pem_enc));
    // A folder with only a public key passes; the walk reads real files.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("k.pub"), &public).unwrap();
    no_plain_keys::assert_no_plain_private_keys(dir.path());
    assert!(no_plain_keys::find_plain_private_keys(dir.path()).is_empty());
}

// ------------------------------------------------------------------------
// Round 2 (1 Nov 2026). The suite PM's review found the guard above is only
// lexical: 14 of 19 Rust bypasses got through. One test per bypass, so the
// red output names each one. Every sample is built at run time from
// placeholders (`@K@` the ssh key tool, `@O@` OpenSSL, `@A@` the age key tool,
// `@Q@` a bare double quote, `@H@` the base64 head of an OpenSSH key file),
// so this source never carries a literal empty or constant passphrase, a
// tool name next to key-making options, or a private-key frame. The samples
// are source text only; nothing here makes a key (except the one test that
// asks the key tool for an ENCRYPTED key, with a random in-memory passphrase).
//
// The rule these cases pin (the PM's, 1 Nov 2026):
//   * a `-N` value that is not a literal is unprotected unless it comes from
//     the in-memory passphrase helper, `memory_keys::random_passphrase()` in
//     tests/support/memory_keys.rs; a shell script has no such helper, so a
//     shell `-N` is never protected;
//   * the guard's own runtime-built cases (this file, which the guard never
//     reads) and the backstop's own test frame (one `concat!` in
//     tests/support/no_plain_keys.rs) are the only exceptions, explicit and
//     narrow: the same text in any other file, or a second frame in that file,
//     is still a hit.

macro_rules! bypass {
    ($name:ident, $ext:expr, $src:expr) => {
        #[test]
        fn $name() {
            let found = reasons($ext, $src);
            assert!(!found.is_empty(), "bypass not caught ({}): {}", $ext, $src);
        }
    };
}

// 1. fs::write of a format!-built key frame.
bypass!(
    g1_01a_fs_write_of_a_format_built_key_frame,
    "rs",
    r#"fs::write(&p, format!("-----BEGIN {} PRIVATE KEY-----\n{}\n-----END {} PRIVATE KEY-----\n", "OPENSSH", body, "OPENSSH")).unwrap();"#
);
bypass!(
    g1_01b_a_format_built_frame_with_inline_arguments,
    "rs",
    r#"let frame = format!("-----BEGIN {kind} PRIVATE KEY-----\n{body}\n");
fs::write(&p, frame).unwrap();"#
);

// 2. fs::write(p, pair.to_bytes()): the raw private half.
bypass!(
    g1_02a_fs_write_of_a_keypairs_to_bytes,
    "rs",
    r#"let pair = Ed25519Keypair::from_seed(&seed);
fs::write(&p, pair.to_bytes()).unwrap();"#
);
bypass!(
    g1_02b_fs_write_of_a_signing_keys_to_bytes,
    "rs",
    r#"let signing_key = SigningKey::from_bytes(&seed);
std::fs::write(&p, signing_key.to_bytes()).unwrap();"#
);

// 3. openssl genpkey.
bypass!(
    g1_03a_openssl_genpkey_in_rust,
    "rs",
    r#"Command::new("@O@").args(["genpkey", "-algorithm", "ed25519", "-out", "k.pem"]).status().unwrap();"#
);
bypass!(
    g1_03b_openssl_genpkey_in_shell,
    "sh",
    "@O@ genpkey -algorithm ed25519 -out k.pem"
);

// 4. openssl req -nodes -keyout.
bypass!(
    g1_04a_openssl_req_nodes_keyout_in_shell,
    "sh",
    "@O@ req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -subj /CN=x"
);
bypass!(
    g1_04b_openssl_req_nodes_keyout_in_rust,
    "rs",
    r#"Command::new("@O@").args(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "k.pem", "-out", "r.csr"]).status().unwrap();"#
);

// 5. age-keygen.
bypass!(
    g1_05a_age_keygen_in_rust,
    "rs",
    r#"Command::new("@A@").args(["-o", "k.txt"]).status().unwrap();"#
);
bypass!(g1_05b_age_keygen_in_shell, "sh", "@A@ > key.txt");

// 6. A concat! frame (the form no_plain_keys.rs builds its own test frame in).
bypass!(
    g1_06_a_concat_built_key_frame,
    "rs",
    r#"let frame = concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----\n", "AAAA\n", "-----END OPENSSH ", "PRIVATE KEY-----\n");
fs::write(&p, frame).unwrap();"#
);

// 7. to_pkcs8_pem, and the pem crate.
bypass!(
    g1_07a_to_pkcs8_pem_method,
    "rs",
    r#"let text = key.to_pkcs8_pem(LineEnding::LF).unwrap();
fs::write(&p, text.as_bytes()).unwrap();"#
);
bypass!(
    g1_07b_to_pkcs8_pem_trait_form,
    "rs",
    r#"let text = EncodePrivateKey::to_pkcs8_pem(&key, LineEnding::LF).unwrap();
fs::write(&p, text.as_bytes()).unwrap();"#
);
bypass!(
    g1_08a_the_pem_crate_private_key,
    "rs",
    r#"let block = pem::Pem::new("PRIVATE KEY", der);
fs::write(&path, pem::encode(&block)).unwrap();"#
);
bypass!(
    g1_08b_the_pem_crate_ec_private_key,
    "rs",
    r#"fs::write(&path, pem::encode(&pem::Pem::new(String::from("EC PRIVATE KEY"), der))).unwrap();"#
);

// 9. An empty variable passed as -N, in Rust; and any -N that is not the helper.
bypass!(
    g1_09a_empty_string_variable_as_passphrase_in_rust,
    "rs",
    r#"let pw = String::new();
let c = Command::new("@K@").args(["-q", "-t", "ed25519", "-N", &pw, "-f", "k"]);"#
);
bypass!(
    g1_09b_empty_literal_variable_as_passphrase_in_rust,
    "rs",
    r#"let pw = @E@;
let c = Command::new("@K@").args(["-q", "-t", "ed25519", "-N", pw, "-f", "k"]);"#
);
bypass!(
    g1_09c_a_variable_that_is_not_the_helper_is_unprotected,
    "rs",
    r#"let pw = std::env::var("PW").unwrap();
let c = Command::new("@K@").args(["-q", "-t", "ed25519", "-N", &pw, "-f", "k"]);"#
);
bypass!(
    g1_09d_a_call_that_is_not_the_helper_is_unprotected,
    "rs",
    r#"let c = Command::new("@K@").args(["-q", "-t", "ed25519", "-N", &make_passphrase(), "-f", "k"]);"#
);

// 10. An empty variable passed as -N, in shell; no shell -N can be the helper.
bypass!(
    g1_10a_empty_shell_variable_quoted,
    "sh",
    "PW=@E@\n@K@ -q -t ed25519 -N \"$PW\" -f k"
);
bypass!(
    g1_10b_empty_shell_variable_unquoted,
    "sh",
    "PW=\n@K@ -q -t ed25519 -N $PW -f k"
);
bypass!(
    g1_10c_a_shell_variable_from_elsewhere_is_unprotected,
    "sh",
    "@K@ -q -t ed25519 -N \"$PASS\" -f k"
);
bypass!(
    g1_10d_a_shell_variable_from_elsewhere_unquoted,
    "sh",
    "@K@ -q -t ed25519 -N $PASS -f k"
);

// 11. The trait form of to_openssh.
bypass!(
    g1_11a_to_openssh_trait_form,
    "rs",
    r#"fs::write(&p, ToOpenssh::to_openssh(&k)).unwrap();"#
);
bypass!(
    g1_11b_private_key_to_openssh_path_form,
    "rs",
    r#"let s = PrivateKey::to_openssh(&k, LineEnding::LF).unwrap();
fs::write(&p, s).unwrap();"#
);

// 12. A base64 literal of the openssh-key-v1 header.
bypass!(
    g1_12a_base64_literal_of_the_openssh_key_header,
    "rs",
    r#"let blob = "@H@AAAAABG5vbmU";
fs::write(&p, base64::decode(blob).unwrap()).unwrap();"#
);
bypass!(
    g1_12b_the_raw_openssh_key_magic,
    "rs",
    r#"fs::write(&p, [b"openssh-key-v1\0".as_slice(), &rest].concat()).unwrap();"#
);

// 13. ssh-keygen -t ed25519 with its arguments on separate statements, no -N.
bypass!(
    g1_13a_keygen_args_on_separate_arg_statements,
    "rs",
    r#"let mut c = Command::new("@K@");
c.arg("-t");
c.arg("ed25519");
c.arg("-f");
c.arg("k");
c.status().unwrap();"#
);
bypass!(
    g1_13b_keygen_args_on_a_separate_args_statement,
    "rs",
    r#"let mut c = Command::new("@K@");
c.args(["-q", "-t", "ed25519", "-f", "k"]);
c.status().unwrap();"#
);
bypass!(
    g1_13c_keygen_separate_statements_with_a_literal_passphrase,
    "rs",
    r#"let mut c = Command::new("@K@");
c.arg("-t");
c.arg("ed25519");
c.arg("-N");
c.arg("hunter2");
c.arg("-f");
c.arg("k");"#
);

/// The protected forms of the new rules stay allowed (green today, and must
/// stay green): the in-memory passphrase helper, public halves, encrypted
/// output, reading modes.
#[test]
fn g1_protected_forms_of_the_new_rules_stay_allowed() {
    let good: &[(&str, &str)] = &[
        (
            "rs",
            "let pass = memory_keys::random_passphrase();\nCommand::new(\"@K@\").args([\"-q\", \"-t\", \"ed25519\", \"-N\", &pass, \"-f\", \"k\"]);",
        ),
        (
            "rs",
            "let pass = memory_keys::random_passphrase();\nCommand::new(\"@K@\").args([\"-q\", \"-t\", \"ed25519\", \"-N\", &*pass, \"-f\", \"k\"]);",
        ),
        (
            "rs",
            "Command::new(\"@K@\").args([\"-q\", \"-t\", \"ed25519\", \"-N\", &memory_keys::random_passphrase(), \"-f\", \"k\"]);",
        ),
        (
            "rs",
            "let pass = memory_keys::random_passphrase();\nlet mut c = Command::new(\"@K@\");\nc.arg(\"-t\");\nc.arg(\"ed25519\");\nc.arg(\"-N\");\nc.arg(&*pass);\nc.arg(\"-f\");\nc.arg(\"k\");",
        ),
        ("rs", "fs::write(&p, verifying_key.to_bytes()).unwrap();"),
        ("rs", "fs::write(&p, digest.to_bytes()).unwrap();"),
        ("rs", "let s = PublicKey::to_openssh(&pubkey).unwrap();"),
        ("rs", "let s = Certificate::to_openssh(&cert).unwrap();"),
        (
            "rs",
            "let t = key.to_pkcs8_encrypted_pem(&mut rng, pass, LineEnding::LF).unwrap();",
        ),
        (
            "rs",
            "let t = public.to_public_key_pem(LineEnding::LF).unwrap();",
        ),
        (
            "rs",
            "let b = pem::Pem::new(\"PUBLIC KEY\", der); fs::write(&p, pem::encode(&b)).unwrap();",
        ),
        (
            "rs",
            "let b = pem::Pem::new(\"CERTIFICATE\", der); fs::write(&p, pem::encode(&b)).unwrap();",
        ),
        ("sh", "@O@ x509 -noout -text -in c.pem"),
        ("sh", "@O@ rand -hex 16"),
        ("sh", "@O@ req -new -key k.pem -out r.csr"),
        (
            "sh",
            "@O@ genpkey -algorithm ed25519 -aes-256-cbc -pass stdin -out k.pem",
        ),
        ("sh", "@A@ -y key.txt"),
        (
            "rs",
            "// concat!(\"-----BEGIN OPENSSH \", \"PRIVATE KEY-----\") in a comment",
        ),
    ];
    for (ext, src) in good {
        assert!(
            reasons(ext, src).is_empty(),
            "false hit ({ext}): {src}: {:?}",
            reasons(ext, src)
        );
    }
}

/// The backstop's own test frame, a `concat!` in tests/support/no_plain_keys.rs.
const BACKSTOP_FRAME: &str = r#"fn openssh_armor() -> String {
    concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----").to_string()
}"#;

/// Exception 1: that one frame, in that one file, is allowed (green today).
#[test]
fn g1_the_backstops_own_test_frame_is_allowed_in_its_own_file() {
    let hits = scan_text("tests/support/no_plain_keys.rs", "rs", BACKSTOP_FRAME);
    assert!(
        hits.is_empty(),
        "the backstop's own frame was refused: {hits:?}"
    );
}

/// Exception 2 is narrow: the same text in any other file is a hit.
#[test]
fn g1_the_backstops_frame_is_caught_in_any_other_file() {
    let hits = scan_text("tests/test_other.rs", "rs", BACKSTOP_FRAME);
    assert!(
        !hits.is_empty(),
        "a concat!-built key frame outside the backstop's file was allowed"
    );
}

/// Exception 3 is narrow: a second frame in the backstop's own file is a hit.
#[test]
fn g1_a_second_frame_in_the_backstops_file_is_caught() {
    let two = format!(
        "{BACKSTOP_FRAME}\nfn another() -> String {{\n    concat!(\"-----BEGIN EC \", \"PRIVATE KEY-----\").to_string()\n}}"
    );
    let hits = scan_text("tests/support/no_plain_keys.rs", "rs", &two);
    assert!(
        !hits.is_empty(),
        "a second concat!-built frame in the backstop's file was allowed"
    );
}

/// The helper the guard names exists and is not constant: two calls differ,
/// each is long enough for ssh-keygen (5+ characters) and never empty.
#[test]
fn g1_the_in_memory_passphrase_helper_exists_and_is_random() {
    let a = memory_keys::random_passphrase();
    let b = memory_keys::random_passphrase();
    assert!(a.len() >= 16, "too short: {}", a.len());
    assert_ne!(*a, *b, "two passphrases were equal");
}

// ----------------------------------------------- G2: the runtime backstop

/// OpenSSH frames that do not parse as a key: cut short, a body that is not
/// base64, and the right magic with nothing after it.
fn unparseable_frames() -> Vec<String> {
    let head = format!("-----BEGIN {} PRIVATE KEY-----", "OPENSSH");
    let foot = format!("-----END {} PRIVATE KEY-----", "OPENSSH");
    let magic = ["b3BlbnNzaC1rZXkt", "djEAAAAA"].concat();
    vec![
        format!("{head}\nx\n"),
        format!("{head}\n"),
        format!("{head}\nnot base64 at all !!!\n{foot}\n"),
        format!("{head}\n{magic}\n{foot}\n"),
    ]
}

/// G2. A frame that fails to parse counts as a hit: only a frame that parses
/// AND is encrypted passes. (Today it is read as "not a key" and passes, so a
/// truncated or hand-damaged key file slips by.)
#[test]
fn g2_an_openssh_frame_that_fails_to_parse_is_a_hit() {
    for f in unparseable_frames() {
        assert!(
            no_plain_keys::is_plain_private_key(&f),
            "an OpenSSH frame that does not parse must count as a hit: {f:?}"
        );
    }
}

/// G2, at the level a fixture sees: the folder walk names such a file.
#[test]
fn g2_the_folder_walk_names_a_file_with_an_unparseable_frame() {
    let dir = tempfile::tempdir().unwrap();
    let frames = unparseable_frames();
    for (i, f) in frames.iter().enumerate() {
        fs::write(dir.path().join(format!("f{i}")), f).unwrap();
    }
    let found = no_plain_keys::find_plain_private_keys(dir.path());
    assert_eq!(
        found.len(),
        frames.len(),
        "every unparseable frame must be named; found {found:?}"
    );
}

/// G2, the other half: a frame that parses AND is encrypted passes, and the
/// same file cut in half is a hit. The encrypted key is made by the key tool
/// with a random in-memory passphrase, so it is protected from the moment it
/// exists; it is never plain.
#[test]
fn g2_only_a_frame_that_parses_and_is_encrypted_passes() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("enc");
    let pass = memory_keys::random_passphrase();
    let tool = ["ssh", "keygen"].join("-");
    let status = Command::new(tool)
        .args(["-q", "-t", "ed25519", "-C", "g2", "-f"])
        .arg(&file)
        .arg("-N")
        .arg(&*pass)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .expect("the key tool runs");
    assert!(
        status.success(),
        "the key tool could not make an encrypted key"
    );
    let text = fs::read_to_string(&file).unwrap();
    assert!(
        !no_plain_keys::is_plain_private_key(&text),
        "a frame that parses and is encrypted must pass"
    );
    let cut = &text[..text.len() / 2];
    assert!(
        no_plain_keys::is_plain_private_key(cut),
        "the same frame cut in half must count as a hit"
    );
    // The folder walk agrees: the encrypted file and its public half pass.
    assert!(no_plain_keys::find_plain_private_keys(dir.path()).is_empty());
}

// ---------------------------------------------------------------------------
// Added 1 Nov 2026 after an independent check found three key tools the guard
// did not know: OpenSSL `ecparam -genkey`, Python `cryptography` private_bytes
// with NoEncryption, and gpg --batch with an empty passphrase. Each tool has a
// bad form per spelling and a protected form that must stay allowed. All the
// samples are built at run time (placeholders below), so this source holds no
// literal key-making command.
// ---------------------------------------------------------------------------

/// Expands the placeholders of the three new tool families on top of `sp`.
fn sp3(s: &str) -> String {
    sp(s)
        .replace("@G@", &["g", "pg"].concat())
        .replace("@GENL@", &["--quick", "-generate-key"].concat())
        .replace("@GEN2@", &["--gen", "-key"].concat())
        .replace("@GEN@", &["--quick", "-gen-key"].concat())
        .replace("@PP@", &["--pass", "phrase"].concat())
        .replace("@EP@", &["ecp", "aram"].concat())
        .replace("@GK@", &["-gen", "key"].concat())
        .replace("@NE@", &["No", "Encryption"].concat())
        .replace("@PB@", &["private", "_bytes"].concat())
}

fn reasons3(ext: &str, src: &str) -> Vec<String> {
    scan_text("x", ext, &sp3(src))
        .into_iter()
        .map(|h| h.reason)
        .collect()
}

macro_rules! bypass3 {
    ($name:ident, $ext:expr, $src:expr) => {
        #[test]
        fn $name() {
            assert!(
                !reasons3($ext, $src).is_empty(),
                "bypass not caught ({}): {}",
                $ext,
                sp3($src)
            );
        }
    };
}

macro_rules! allowed3 {
    ($name:ident, $ext:expr, $src:expr) => {
        #[test]
        fn $name() {
            let r = reasons3($ext, $src);
            assert!(r.is_empty(), "false hit ({}): {}: {:?}", $ext, sp3($src), r);
        }
    };
}

// A. OpenSSL ecparam -genkey writing an unencrypted private key.
bypass3!(
    g3_01a_ecparam_genkey_to_a_file_in_shell,
    "sh",
    "@O@ @EP@ -name prime256v1 @GK@ -noout -out k.pem"
);
bypass3!(
    g3_01b_ecparam_genkey_redirected_in_shell,
    "sh",
    "@O@ @EP@ @GK@ -name secp384r1 > k.pem"
);
bypass3!(
    g3_01c_ecparam_genkey_in_rust,
    "rs",
    r#"Command::new("@O@").args(["@EP@", "-name", "prime256v1", "@GK@", "-out", "k.pem"]).status().unwrap();"#
);
bypass3!(
    g3_01d_ecparam_genkey_in_python,
    "py",
    "subprocess.run(['@O@', '@EP@', '-name', 'prime256v1', '@GK@', '-out', 'k.pem'])"
);
allowed3!(
    g3_01e_ecparam_genkey_encrypted_by_the_next_stage_stays_allowed,
    "sh",
    "@O@ @EP@ -name prime256v1 @GK@ -noout | @O@ ec -aes256 -passout stdin -out k.pem"
);
allowed3!(
    g3_01f_ecparam_that_makes_no_key_stays_allowed,
    "sh",
    "@O@ @EP@ -list_curves"
);

// B. Python cryptography: private_bytes(..., NoEncryption()) in a .py file.
bypass3!(
    g3_02a_private_bytes_with_no_encryption,
    "py",
    "pem = key.@PB@(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=serialization.@NE@())"
);
bypass3!(
    g3_02b_private_bytes_multiline_positional,
    "py",
    "open(path, \"wb\").write(key.@PB@(\n    Encoding.PEM,\n    PrivateFormat.TraditionalOpenSSL,\n    @NE@(),\n))"
);
bypass3!(
    g3_02c_private_bytes_name_imported_bare,
    "py",
    "from cryptography.hazmat.primitives.serialization import @NE@\nblob = k.@PB@(Encoding.DER, PrivateFormat.PKCS8, @NE@())"
);
allowed3!(
    g3_02d_private_bytes_with_best_available_encryption_stays_allowed,
    "py",
    "pem = key.@PB@(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(pw))"
);
allowed3!(
    g3_02e_public_bytes_stays_allowed,
    "py",
    "pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)"
);
allowed3!(
    g3_02f_private_bytes_with_a_random_passphrase_stays_allowed,
    "py",
    "pem = key.@PB@(Encoding.PEM, PrivateFormat.PKCS8, serialization.BestAvailableEncryption(os.urandom(24).hex().encode()))"
);

// C. gpg --batch with an empty passphrase making a key.
bypass3!(
    g3_03a_gpg_quick_gen_key_empty_double_quotes,
    "sh",
    "@G@ --batch @PP@ @E@ @GEN@ someone@example.test"
);
bypass3!(
    g3_03b_gpg_quick_gen_key_empty_single_quotes,
    "sh",
    "@G@ --batch --pinentry-mode loopback @PP@ @S@ @GEN@ someone ed25519 sign never"
);
bypass3!(
    g3_03c_gpg_gen_key_empty_passphrase,
    "sh",
    "@G@ --batch @PP@ @E@ @GEN2@ params.txt"
);
bypass3!(
    g3_03d_gpg_quick_generate_key_long_spelling,
    "sh",
    "@G@ --batch @PP@ @S@ @GENL@ someone"
);
bypass3!(
    g3_03e_gpg_empty_passphrase_equals_form,
    "sh",
    "@G@ --batch @PP@=@E@ @GEN@ someone"
);
bypass3!(
    g3_03f_gpg_in_rust_args,
    "rs",
    r#"Command::new("@G@").args(["--batch", "@PP@", "", "@GEN@", "someone"]).status().unwrap();"#
);
bypass3!(
    g3_03g_gpg_in_python,
    "py",
    "subprocess.run(['@G@', '--batch', '@PP@', '', '@GEN@', 'someone'])"
);
bypass3!(
    g3_03h_gpg_with_a_constant_passphrase,
    "sh",
    "@G@ --batch @PP@ hunter2 @GEN@ someone"
);
allowed3!(
    g3_03i_gpg_passphrase_from_stdin_stays_allowed,
    "sh",
    "@G@ --batch --pinentry-mode loopback --passphrase-fd 0 @GEN@ someone < /dev/stdin"
);
allowed3!(
    g3_03j_gpg_list_keys_stays_allowed,
    "sh",
    "@G@ --list-keys someone"
);
allowed3!(
    g3_03k_gpg_verify_with_batch_stays_allowed,
    "sh",
    "@G@ --batch --verify file.sig file"
);
