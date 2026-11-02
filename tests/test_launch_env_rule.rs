//! M1, the rule itself (interface I-M1): the one place that decides which
//! environment variables a launch request may carry, tested as a plain
//! function. The launcher applies it to every request (tested end to end in
//! `test_launcher_hardening.rs`); `session-exec` applies it again to the spec
//! it is handed, as defence in depth (checked there by a static test, because
//! `session-exec` can't be run without a slot's cgroup and bind mount).
//!
//! **A NEW TEST SEAM the builder must provide (named here, so the tests can
//! be written before the build):**
//!
//! `agent_sign::launcher::check_env(env: &BTreeMap<String, String>) -> Result<(), String>`
//!
//! `Ok` when the environment holds only LANG and TERM, each value 1 to 64
//! bytes of `[A-Za-z0-9._@+-]` (the map can hold each name once; a name sent
//! twice is refused where the request is read, which the daemon-level tests
//! cover). Otherwise `Err` with a plain message that names the offending
//! variable. If the builder wants a different name or shape, they say so and
//! change only the `use` line and the call in `refuses` / `accepts` below.
//!
//! Red today: `check_env` doesn't exist, so this file doesn't compile.
//! Run on hetzner: `cargo test --locked --test test_launch_env_rule`.

use std::collections::BTreeMap;

use agent_sign::launcher::check_env;

fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn accepts(pairs: &[(&str, &str)]) -> Result<(), String> {
    check_env(&env(pairs))
}

/// Refused, and the message names `name`.
fn refuses(pairs: &[(&str, &str)], name: &str) -> Result<(), String> {
    match check_env(&env(pairs)) {
        Ok(()) => Err(format!("{pairs:?} was accepted")),
        Err(e) if e.contains(name) => Ok(()),
        Err(e) => Err(format!("{pairs:?} was refused without naming {name}: {e}")),
    }
}

#[test]
fn no_variables_and_lang_and_term_with_plain_values_are_accepted() {
    let long = "a".repeat(64);
    let mut bad = Vec::new();
    for pairs in [
        vec![],
        vec![("LANG", "en_US.UTF-8")],
        vec![("TERM", "xterm-256color")],
        vec![("LANG", "en_US.UTF-8"), ("TERM", "xterm-256color")],
        vec![("LANG", "x"), ("TERM", "y")],
        vec![("LANG", long.as_str()), ("TERM", long.as_str())],
        vec![("LANG", "C"), ("TERM", "a.b_c@d+e-f")],
    ] {
        if let Err(e) = accepts(&pairs) {
            bad.push(format!("{pairs:?}: {e}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn any_other_name_is_refused_by_name_even_next_to_good_ones() {
    let mut bad = Vec::new();
    for name in [
        "ANTHROPIC_BASE_URL",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "PATH",
        "HOME",
        "LC_ALL",
        "lang",
        "Term",
        "LANG ",
        "TERM2",
        "AGENT_SIGN_SOCKET",
        "AGENT_SIGN_AGENT",
        "CLAUDE_CODE_SESSION_ID",
    ] {
        if let Err(e) = refuses(&[(name, "x")], name) {
            bad.push(e);
        }
        // A good pair beside it doesn't make it acceptable: the whole request goes.
        if let Err(e) = refuses(&[("LANG", "C"), ("TERM", "xterm"), (name, "x")], name) {
            bad.push(e);
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn a_bad_value_for_lang_or_term_is_refused_by_name() {
    let long65 = "a".repeat(65);
    let mut bad = Vec::new();
    for var in ["LANG", "TERM"] {
        for value in [
            "",
            long65.as_str(),
            "a b",
            "a/b",
            "a;b",
            "a=b",
            "a:b",
            "a\nb",
            "a\0b",
            "caf\u{e9}",
            "$HOME",
            "a\"b",
            "~",
            "a\tb",
        ] {
            if let Err(e) = refuses(&[(var, value)], var) {
                bad.push(e);
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
