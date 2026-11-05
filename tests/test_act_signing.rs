//! agent-sign signs an act: exact bytes, as a launcher-given agent identity, or as an assigner (Taylor, the
//! launcher), and says who signed through `agent-sign act verify --format json`.
//!
//! Written before the build, by an agent other than the builder, as the eval of `EVALS.md` section "Signed acts v0".
//! They fail on main because `agent-sign act` does not exist. The interface they pin is the header of
//! `support/act_harness.rs`. The builder builds until every test here passes (the `#[ignore]`d system-mode tests
//! are run later, by Taylor's sitting) and **changes no assertion**; a wrong eval is fixed as its own commit
//! "Deliberate change to the evals: ...".
//!
//! Criteria (each test name starts with its id; thresholds are in EVALS.md):
//! * `sign_*`: signing as an agent (and the limits on payloads).
//! * `assign_*`: signing as an assigner.
//! * `keys_*`: no private key outside memory or OpenBao.
//! * `probe_*`: adversarial probes; 0 of them may succeed.
//! * `cred_*`: the credential.
//! * `system_*`: need system-mode root setup; `#[ignore]`d, run later.
//! * `harness_*`: the harness itself; must pass on main, so a failure elsewhere is never the harness.
//!
//! Run on a server, as the agents account: `cargo test --test test_act_signing`.
#![cfg(target_os = "linux")]

#[path = "support/act_harness.rs"]
mod act_harness;
#[path = "support/die_with_parent.rs"]
mod die_with_parent;
#[path = "support/key_agent.rs"]
mod key_agent;
#[path = "support/memory_keys.rs"]
mod memory_keys;
#[path = "support/no_plain_keys.rs"]
mod no_plain_keys;

use act_harness::*;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;

const BUILDER: &str = "agent:builder-1";
const OTHER: &str = "agent:verifier-1";

fn payload() -> Vec<u8> {
    assignment_payload(BUILDER, "builder", "work:x", "asg-1")
}

/// Asserts a verdict object: exactly the six keys, and the stated values.
fn expect(
    v: &Value,
    verified: bool,
    signer: Option<&str>,
    kind: Option<&str>,
    reason: &str,
    what: &str,
) {
    let obj = v
        .as_object()
        .unwrap_or_else(|| panic!("{what}: verdict is not an object: {v}"));
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "detail",
            "kind",
            "reason",
            "signer",
            "trust_sha256",
            "verified"
        ],
        "{what}: verdict keys"
    );
    assert_eq!(
        obj["verified"],
        json!(verified),
        "{what}: verified; verdict {v}"
    );
    assert_eq!(obj["reason"], json!(reason), "{what}: reason; verdict {v}");
    assert_eq!(
        obj["signer"],
        signer.map_or(Value::Null, |s| json!(s)),
        "{what}: signer; verdict {v}"
    );
    assert_eq!(
        obj["kind"],
        kind.map_or(Value::Null, |s| json!(s)),
        "{what}: kind; verdict {v}"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// harness: must pass on main
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn harness_a_launched_session_runs_and_its_output_reaches_the_caller() {
    let w = ActWorld::new(false);
    let out = w.launched(None, Path::new("/bin/echo"), &["hello-from-session"], &[]);
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("hello-from-session"),
        "harness: a launched session's stdout should reach the test:\n{}",
        text(&out)
    );
    // ... and it can read a file the test left in the home, which is how payloads reach a session.
    let file = w.write("payload", b"readable-in-session");
    let out = w.launched(None, Path::new("/bin/cat"), &[file.to_str().unwrap()], &[]);
    assert!(
        out.status.success()
            && String::from_utf8_lossy(&out.stdout).contains("readable-in-session"),
        "harness: a session should read files under the test home:\n{}",
        text(&out)
    );
}

// ---------------------------------------------------------------------------------------------------------------
// sign: an agent signs exact bytes as its launcher-given identity
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn sign_01_an_agent_signature_verifies_as_its_launcher_given_identity() {
    let w = ActWorld::new(true);
    let member = w.agent_signs(BUILDER, &payload());
    let trust = w.trust_file(&[]);
    let (code, v) = w.verify(&payload(), &member, &trust, None);
    expect(
        &v,
        true,
        Some(BUILDER),
        Some("agent"),
        "ok",
        "agent signature",
    );
    assert_eq!(code, 0, "exit code of a verified act");
    assert_eq!(
        v["trust_sha256"],
        json!(sha256_hex(&fs::read(&trust).unwrap())),
        "trust_sha256 is the digest of the file read"
    );
}

#[test]
fn sign_02_the_signature_binds_the_exact_bytes() {
    let w = ActWorld::new(true);
    let p = payload();
    let member = w.agent_signs(BUILDER, &p);
    let trust = w.trust_file(&[]);
    let mut problems = Problems::default();
    let mut flipped = p.clone();
    flipped[30] ^= 1;
    let mut longer = p.clone();
    longer.push(b'\n');
    let shorter = p[..p.len() - 1].to_vec();
    let other_work = assignment_payload(BUILDER, "builder", "work:y", "asg-1");
    let other_role = assignment_payload(BUILDER, "pm", "work:x", "asg-1");
    for (name, changed) in [
        ("one bit", flipped),
        ("a trailing newline", longer),
        ("one byte fewer", shorter),
        ("another work", other_work),
        ("another role", other_role),
    ] {
        let (code, v) = w.verify(&changed, &member, &trust, None);
        problems.check(
            v["verified"] == json!(false)
                && v["reason"] == json!("bad_signature")
                && code == 1
                && v["signer"].is_null(),
            || format!("{name}: expected bad_signature, exit 1, no signer; got exit {code}, {v}"),
        );
    }
    problems.finish();
}

#[test]
fn sign_03_two_sessions_two_identities_and_nothing_in_the_session_changes_it() {
    let w = ActWorld::new(true);
    let trust = w.trust_file(&[]);
    let (a, b) = (
        w.agent_signs(BUILDER, &payload()),
        w.agent_signs(OTHER, &payload()),
    );
    let file = w.write("payload", &payload());
    // A session that sets every variable and mark it can still signs as the identity it was launched with.
    let out = w.in_session(
        Some(BUILDER),
        &["sign", "--payload-file", file.to_str().unwrap()],
        &[
            ("AGENT_SIGN_ACT_IDENTITY", "agent:verifier-1"),
            ("AGENT_SIGN_AGENT_NAME", "Verifier One"),
            ("AGENT_SIGN_SESSION_ID", "someone-else"),
            ("CLAUDECODE", "1"),
            ("CLAUDE_CODE_SESSION_ID", "someone-else"),
            ("USER", "taylor"),
        ],
    );
    let c = member_of(&out);
    let mut problems = Problems::default();
    for (who, member, want) in [
        ("a", &a, BUILDER),
        ("b", &b, OTHER),
        ("c (hostile environment)", &c, BUILDER),
    ] {
        let (code, v) = w.verify(&payload(), member, &trust, None);
        problems.check(
            code == 0 && v["signer"] == json!(want) && v["kind"] == json!("agent"),
            || format!("{who}: expected {want}; exit {code}, {v}"),
        );
    }
    problems.finish();
}

#[test]
fn sign_04_a_session_launched_without_an_identity_cannot_sign_acts() {
    let w = ActWorld::new(true);
    let file = w.write("payload", &payload());
    let control = w.in_session(
        Some(BUILDER),
        &["sign", "--payload-file", file.to_str().unwrap()],
        &[],
    );
    assert!(
        control.status.success(),
        "control: a session with an identity should sign:\n{}",
        text(&control)
    );
    let out = w.in_session(
        None,
        &["sign", "--payload-file", file.to_str().unwrap()],
        &[],
    );
    assert!(
        !out.status.success(),
        "an anonymous session signed an act:\n{}",
        text(&out)
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("\"signature\""),
        "a refusal must print no signature:\n{}",
        text(&out)
    );
}

#[test]
fn sign_05_launch_refuses_reserved_and_malformed_identities_and_runs_nothing() {
    let w = ActWorld::new(true);
    let mut problems = Problems::default();
    let ok = w.launched(Some(BUILDER), Path::new("/bin/true"), &[], &[]);
    problems.check(ok.status.success(), || {
        format!("control: a good identity should launch:\n{}", text(&ok))
    });
    for bad in [
        "person:taylor",
        "harness:launcher",
        "taylor",
        "agent:",
        "agent:Builder",
        "agent:a b",
        "agent:x\ny",
        "agent:../x",
        "agent:",
        &format!("agent:{}", "a".repeat(200)),
    ] {
        let marker = w.fresh("ran");
        let script = format!(": > '{}'", marker.display());
        let out = w.launched(Some(bad), Path::new("/bin/sh"), &["-c", &script], &[]);
        problems.check(!out.status.success() && !marker.exists(), || {
            format!(
                "--identity {bad:?} must be refused before anything runs:\n{}",
                text(&out)
            )
        });
    }
    problems.finish();
}

#[test]
fn sign_06_the_output_is_one_json_object_with_exactly_three_keys_and_leaks_nothing() {
    let w = ActWorld::new(true);
    let file = w.write("payload", &payload());
    let out = w.in_session(
        Some(BUILDER),
        &["sign", "--payload-file", file.to_str().unwrap()],
        &[],
    );
    let member = member_of(&out);
    let mut keys: Vec<&str> = member
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort();
    assert_eq!(keys, ["certificate", "schema", "signature"]);
    assert_eq!(member["schema"], json!("agent-sign/act-signature/1"));
    assert!(
        member["signature"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN SSH SIGNATURE-----")
    );
    assert!(
        member["certificate"]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519-cert-v01@openssh.com ")
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(
        stdout.trim_end().lines().count(),
        1,
        "one line of output:\n{stdout}"
    );
    let everything = format!("{stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(
        !everything.contains("work:x") && !everything.contains("role-commitments"),
        "output must not echo the payload:\n{everything}"
    );
}

#[test]
fn sign_07_payload_limits_are_one_to_65536_bytes() {
    let w = ActWorld::new(true);
    let mut problems = Problems::default();
    for (len, ok) in [
        (0usize, false),
        (1, true),
        (65536, true),
        (65537, false),
        (1 << 20, false),
    ] {
        let file = w.write("payload", &vec![b'a'; len]);
        let out = w.in_session(
            Some(BUILDER),
            &["sign", "--payload-file", file.to_str().unwrap()],
            &[],
        );
        problems.check(out.status.success() == ok, || {
            format!("{len} bytes: expected success={ok}:\n{}", text(&out))
        });
        problems.check(
            ok || !String::from_utf8_lossy(&out.stdout).contains("\"signature\""),
            || format!("{len} bytes: a refusal printed a signature"),
        );
    }
    problems.finish();
}

#[test]
fn sign_08_no_option_lets_a_session_pick_its_identity_or_sign_as_an_assigner() {
    let w = ActWorld::new(true);
    let file = w.write("payload", &payload());
    let f = file.to_str().unwrap();
    let mut problems = Problems::default();
    let control = w.in_session(Some(BUILDER), &["sign", "--payload-file", f], &[]);
    problems.check(control.status.success(), || {
        format!("control: plain sign should work:\n{}", text(&control))
    });
    for args in [
        vec!["sign", "--payload-file", f, "--as", "agent:verifier-1"],
        vec![
            "sign",
            "--payload-file",
            f,
            "--identity",
            "agent:verifier-1",
        ],
        vec!["sign", "--payload-file", f, "--identity=person:taylor"],
        vec!["sign", "--payload-file", f, "--assigner", "person:taylor"],
        vec![
            "sign",
            "--payload-file",
            f,
            "--assigner",
            "harness:launcher",
        ],
        vec![
            "sign",
            "--payload-file",
            f,
            "--assigner=person:taylor",
            "--trust-file",
            f,
        ],
    ] {
        let out = w.in_session(Some(BUILDER), &args, &[]);
        problems.check(
            !out.status.success()
                && !String::from_utf8_lossy(&out.stdout).contains("\"signature\""),
            || {
                format!(
                    "{args:?} must be refused with no signature:\n{}",
                    text(&out)
                )
            },
        );
    }
    problems.finish();
}

// ---------------------------------------------------------------------------------------------------------------
// assign: Taylor and the launcher sign as assigners
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn assign_01_taylor_signs_through_his_own_agent_and_it_verifies_as_an_assigner() {
    let w = ActWorld::new(true);
    let dev = w.device("taylor");
    let trust = w.trust_file(&[ActWorld::taylor_line(&dev)]);
    let member = member_of(&w.taylor_signs(Some(&dev), &trust, &payload()));
    assert!(
        member["certificate"].is_null(),
        "an assigner signature has no certificate"
    );
    let (code, v) = w.verify(&payload(), &member, &trust, None);
    expect(
        &v,
        true,
        Some("person:taylor"),
        Some("assigner"),
        "ok",
        "Taylor",
    );
    assert_eq!(code, 0);
}

#[test]
fn assign_02_taylors_signing_needs_his_listed_key_in_a_reachable_agent() {
    let w = ActWorld::new(true);
    let dev = w.device("taylor");
    let stranger = w.device("not-taylor");
    let mut problems = Problems::default();
    let listed = w.trust_file(&[ActWorld::taylor_line(&dev)]);
    let unlisted = w.trust_file(&[]);
    let control = w.taylor_signs(Some(&dev), &listed, &payload());
    problems.check(control.status.success(), || {
        format!(
            "control: the right device and trust file should sign:\n{}",
            text(&control)
        )
    });
    for (what, device, trust) in [
        ("no agent reachable", None, &listed),
        ("the agent holds another key", Some(&stranger), &listed),
        (
            "Taylor's key is not in the trust file",
            Some(&dev),
            &unlisted,
        ),
    ] {
        let out = w.taylor_signs(device, trust, &payload());
        problems.check(
            !out.status.success()
                && !String::from_utf8_lossy(&out.stdout).contains("\"signature\""),
            || format!("{what}: must be refused:\n{}", text(&out)),
        );
    }
    problems.finish();
}

#[test]
fn assign_03_the_launcher_signs_as_an_assigner_outside_a_session() {
    let w = ActWorld::new(true);
    let member = member_of(&w.launcher_signs(&payload()));
    let trust = w.trust_file(&[]);
    let (code, v) = w.verify(&payload(), &member, &trust, None);
    expect(
        &v,
        true,
        Some("harness:launcher"),
        Some("assigner"),
        "ok",
        "launcher",
    );
    assert_eq!(code, 0);
}

#[test]
fn assign_04_a_session_cannot_sign_as_the_launcher_or_through_taylors_agent() {
    let w = ActWorld::new(true);
    let dev = w.device("taylor");
    let trust = w.trust_file(&[ActWorld::taylor_line(&dev)]);
    let file = w.write("payload", &payload());
    let f = file.to_str().unwrap();
    let sock = dev.agent.socket().to_str().unwrap().to_string();
    let mut problems = Problems::default();
    let control = w.taylor_signs(Some(&dev), &trust, &payload());
    problems.check(
        control.status.success() && w.launcher_signs(&payload()).status.success(),
        || {
            format!(
                "control: outside a session both assigners sign:\n{}",
                text(&control)
            )
        },
    );
    // Even with Taylor's agent socket handed into the session, and the trust file named, signing as him is refused
    // because the caller is a launched session, whatever else the arguments say.
    for args in [
        vec![
            "sign",
            "--assigner",
            "person:taylor",
            "--trust-file",
            trust.to_str().unwrap(),
            "--payload-file",
            f,
        ],
        vec![
            "sign",
            "--assigner",
            "harness:launcher",
            "--payload-file",
            f,
        ],
    ] {
        let out = w.in_session(Some(BUILDER), &args, &[("SSH_AUTH_SOCK", &sock)]);
        problems.check(
            !out.status.success()
                && !String::from_utf8_lossy(&out.stdout).contains("\"signature\""),
            || format!("{args:?} inside a session must be refused:\n{}", text(&out)),
        );
    }
    problems.finish();
}

#[test]
fn assign_05_kinds_are_not_interchangeable() {
    let w = ActWorld::new(true);
    let dev = w.device("taylor");
    let trust = w.trust_file(&[ActWorld::taylor_line(&dev)]);
    let agent = w.agent_signs(BUILDER, &payload());
    let taylor = member_of(&w.taylor_signs(Some(&dev), &trust, &payload()));
    let launcher = member_of(&w.launcher_signs(&payload()));
    let mut problems = Problems::default();
    for (who, member, signer, kind) in [
        ("agent", &agent, BUILDER, "agent"),
        ("taylor", &taylor, "person:taylor", "assigner"),
        ("launcher", &launcher, "harness:launcher", "assigner"),
    ] {
        let (_, v) = w.verify(&payload(), member, &trust, None);
        problems.check(
            v["signer"] == json!(signer) && v["kind"] == json!(kind),
            || format!("{who}: expected {signer}/{kind}, got {v}"),
        );
    }
    problems.finish();
}

// ---------------------------------------------------------------------------------------------------------------
// keys: nothing but memory or OpenBao
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn keys_01_no_private_key_is_written_anywhere_by_any_signing_path() {
    let w = ActWorld::new(true);
    let dev = w.device("taylor");
    let trust = w.trust_file(&[ActWorld::taylor_line(&dev)]);
    let _ = w.agent_signs(BUILDER, &payload());
    let _ = w.credential_of(BUILDER);
    let _ = member_of(&w.launcher_signs(&payload()));
    let _ = member_of(&w.taylor_signs(Some(&dev), &trust, &payload()));
    let found = no_plain_keys::find_plain_private_keys(&w.home);
    assert!(
        found.is_empty(),
        "private key files under the service's home: {found:?}"
    );
    // Nothing named like a key either: the services keep nothing under .agent-sign beyond config and state.
    let mut names = Vec::new();
    fn walk(dir: &Path, names: &mut Vec<String>) {
        for e in fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, names);
            } else {
                names.push(p.display().to_string());
            }
        }
    }
    walk(&w.home.join(".agent-sign"), &mut names);
    let suspicious: Vec<_> = names
        .iter()
        .filter(|n| n.contains("launcher") && (n.contains("key") || n.contains("ed25519")))
        .collect();
    assert!(suspicious.is_empty(), "a launcher key file: {suspicious:?}");
}

#[test]
fn keys_02_the_launcher_key_can_only_be_memory_or_openbao() {
    let mut problems = Problems::default();
    for (value, starts) in [
        ("memory", true),
        ("file", false),
        ("path:/tmp/k", false),
        ("", false),
        ("MEMORY", false),
    ] {
        let mut w = ActWorld::unstarted(Some(value));
        let r = w.try_start_service();
        problems.check(r.is_ok() == starts, || {
            format!("launcher_assigner = {value:?}: expected starts={starts}, got {r:?}")
        });
        w.stop_service();
    }
    // A key-file setting of any name is an unknown setting, and unknown settings stop the service.
    let mut w = ActWorld::unstarted(Some("memory"));
    fs::write(
        w.home.join(".agent-sign/config.toml"),
        "[acts]\nenabled = true\nlauncher_assigner = \"memory\"\nlauncher_key_file = \"/tmp/k\"\n",
    )
    .unwrap();
    problems.check(w.try_start_service().is_err(), || {
        "a launcher_key_file setting must stop the service".into()
    });
    problems.finish();
}

#[test]
fn keys_03_without_acts_enabled_the_service_signs_no_acts() {
    let on = ActWorld::new(true);
    assert!(
        on.launcher_signs(&payload()).status.success(),
        "control: with acts enabled the launcher signs"
    );
    let w = ActWorld::new(false);
    let out = w.launcher_signs(&payload());
    assert!(
        !out.status.success() && !String::from_utf8_lossy(&out.stdout).contains("\"signature\""),
        "acts are off by default:\n{}",
        text(&out)
    );
}

// ---------------------------------------------------------------------------------------------------------------
// probe: adversarial; 0 of 12 may succeed
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn probe_01_a_forged_signature_by_a_key_nobody_trusts() {
    let w = ActWorld::new(true);
    let dev = w.device("taylor");
    let intruder = w.device("intruder");
    // The intruder's key signs a perfectly formed act in the right namespace, claiming nothing in the file.
    let forged = w.oracle_signature(&intruder, ACT_NAMESPACE, &payload());
    let trust = w.trust_file(&[ActWorld::taylor_line(&dev)]);
    let (code, v) = w.verify(&payload(), &forged, &trust, None);
    expect(
        &v,
        false,
        None,
        None,
        "untrusted_key",
        "forged by an unlisted key",
    );
    assert_eq!(code, 1);
    // Garbage in place of a signature.
    let mut problems = Problems::default();
    for (what, member) in [
        (
            "corrupted armor",
            json!({"schema": "agent-sign/act-signature/1", "signature": corrupt_armor(forged["signature"].as_str().unwrap()), "certificate": null}),
        ),
        (
            "not armor",
            json!({"schema": "agent-sign/act-signature/1", "signature": "AAAA", "certificate": null}),
        ),
        (
            "wrong schema",
            json!({"schema": "agent-sign/act-signature/2", "signature": forged["signature"], "certificate": null}),
        ),
        (
            "missing certificate key",
            json!({"schema": "agent-sign/act-signature/1", "signature": forged["signature"]}),
        ),
        (
            "a string instead of a member",
            json!("-----BEGIN SSH SIGNATURE-----"),
        ),
    ] {
        let (code, v) = w.verify(&payload(), &member, &trust, None);
        problems.check(
            v["verified"] == json!(false) && code != 0 && v["signer"].is_null(),
            || format!("{what}: must not verify; exit {code}, {v}"),
        );
    }
    problems.finish();
}

#[test]
fn probe_02_an_identity_claimed_inside_the_signature_member_is_ignored() {
    let w = ActWorld::new(true);
    let member = w.agent_signs(BUILDER, &payload());
    let trust = w.trust_file(&[]);
    let mut problems = Problems::default();
    for claim in ["person:taylor", "harness:launcher", "agent:verifier-1"] {
        // Extra keys are refused whole; the claim never reaches the verdict.
        let mut claimed = member.clone();
        claimed["signer"] = json!(claim);
        let (code, v) = w.verify(&payload(), &claimed, &trust, None);
        problems.check(
            v["signer"] != json!(claim) && !(code == 0 && v["kind"] == json!("assigner")),
            || format!("claim {claim}: leaked into the verdict; exit {code}, {v}"),
        );
    }
    // The same through the envelope.
    let mut stdin: Value =
        serde_json::from_slice(&ActWorld::envelope(&payload(), &member)).unwrap();
    stdin["signer"] = json!("person:taylor");
    let out = w.verify_raw(&serde_json::to_vec(&stdin).unwrap(), &trust, None);
    problems.check(out.status.code() != Some(0), || {
        format!("an extra envelope key must be refused:\n{}", text(&out))
    });
    problems.finish();
}

#[test]
fn probe_03_an_agents_signature_over_an_assigner_act_is_the_agents_and_not_an_assigners() {
    let w = ActWorld::new(true);
    // The builder signs an assignment of itself to the pm role: the very bytes only an assigner's signature may carry.
    let act = assignment_payload(BUILDER, "pm", "work:x", "asg-evil");
    let member = w.agent_signs(BUILDER, &act);
    let trust = w.trust_file(&[]);
    let (code, v) = w.verify(&act, &member, &trust, None);
    expect(
        &v,
        true,
        Some(BUILDER),
        Some("agent"),
        "ok",
        "the agent's own signature stays the agent's",
    );
    assert_eq!(code, 0);
}

#[test]
fn probe_04_a_signature_for_another_domain_is_not_an_act() {
    let w = ActWorld::new(true);
    let dev = w.device("taylor");
    let trust = w.trust_file(&[ActWorld::taylor_line(&dev)]);
    let mut problems = Problems::default();
    // Taylor's trusted key signs the very same bytes, but in another domain: a git commit, role-commitments' own
    // design-doc namespace, a credential, a prefix of the right one, and a near miss.
    for ns in [
        "git",
        "role-commitments-act",
        CREDENTIAL_NAMESPACE,
        "agent-sign/act",
        "agent-sign/act/1 ",
        "agent-sign/act/2",
        "file",
    ] {
        let member = w.oracle_signature(&dev, ns, &payload());
        let (code, v) = w.verify(&payload(), &member, &trust, None);
        problems.check(
            v["verified"] == json!(false) && v["reason"] == json!("wrong_namespace") && code == 1,
            || format!("namespace {ns:?}: expected wrong_namespace, exit 1; got exit {code}, {v}"),
        );
    }
    // Control: the same key in the right namespace verifies (so the refusals above are about the domain only).
    let right = w.oracle_signature(&dev, ACT_NAMESPACE, &payload());
    let (code, v) = w.verify(&payload(), &right, &trust, None);
    expect(
        &v,
        true,
        Some("person:taylor"),
        Some("assigner"),
        "ok",
        "control: right namespace",
    );
    assert_eq!(code, 0);
    problems.finish();
}

#[test]
fn probe_05_an_act_signature_is_not_a_credential_nor_a_commit() {
    let w = ActWorld::new(true);
    let trust = w.trust_file(&[]);
    let issued = now_secs();
    // The agent asks `act sign` to sign the exact bytes a credential would carry.
    let bytes = format!("agent-sign/credential/1\n{issued}");
    let member = w.agent_signs(BUILDER, bytes.as_bytes());
    let credential =
        json!({"schema": "agent-sign/act-credential/1", "issued_at": issued, "signature": member});
    let (code, v) = w.verify_credential(&credential, &trust, None);
    assert!(
        v["verified"] == json!(false) && v["reason"] == json!("wrong_namespace") && code == 1,
        "act signature as credential: exit {code}, {v}"
    );
    // And a credential's signature is no act.
    let real = w.credential_of(BUILDER);
    let (code, v) = w.verify(bytes.as_bytes(), &real["signature"], &trust, None);
    assert!(
        v["verified"] == json!(false) && code == 1,
        "credential signature as an act: exit {code}, {v}"
    );
}

#[test]
fn probe_06_a_revoked_identity_no_longer_verifies_and_others_still_do() {
    let w = ActWorld::new(true);
    let (a, b) = (
        w.agent_signs(BUILDER, &payload()),
        w.agent_signs(OTHER, &payload()),
    );
    let fine = w.trust_file(&[]);
    let revoked = w.trust_file(&[format!("revoked {BUILDER}")]);
    let (code, v) = w.verify(&payload(), &a, &fine, None);
    assert_eq!(
        (code, v["verified"].clone()),
        (0, json!(true)),
        "before revocation: {v}"
    );
    let (code, v) = w.verify(&payload(), &a, &revoked, None);
    expect(&v, false, None, None, "revoked", "revoked identity");
    assert_eq!(code, 1);
    let (code, v) = w.verify(&payload(), &b, &revoked, None);
    expect(
        &v,
        true,
        Some(OTHER),
        Some("agent"),
        "ok",
        "an identity that was not revoked",
    );
    assert_eq!(code, 0);
    // Revoking an assigner works the same way.
    let dev = w.device("taylor");
    let with_taylor = w.trust_file(&[ActWorld::taylor_line(&dev), "revoked person:taylor".into()]);
    let t = w.oracle_signature(&dev, ACT_NAMESPACE, &payload());
    let (code, v) = w.verify(&payload(), &t, &with_taylor, None);
    expect(&v, false, None, None, "revoked", "revoked assigner");
    assert_eq!(code, 1);
}

#[test]
fn probe_07_a_trust_file_that_is_missing_relative_or_malformed_is_cannot_run_not_a_verdict() {
    let w = ActWorld::new(true);
    let member = w.agent_signs(BUILDER, &payload());
    let good = w.trust_file(&[]);
    let good_text = fs::read_to_string(&good).unwrap();
    let key_line = good_text
        .lines()
        .find(|l| l.starts_with("authority "))
        .unwrap()
        .to_string();
    let key = key_line.splitn(3, ' ').nth(2).unwrap().to_string();
    let mut problems = Problems::default();
    let (code, v) = w.verify(&payload(), &member, &good, None);
    problems.check(code == 0 && v["verified"] == json!(true), || {
        format!("control: the good trust file should verify; exit {code}, {v}")
    });
    let cases: Vec<(&str, String)> = vec![
        (
            "no header",
            good_text.lines().skip(1).collect::<Vec<_>>().join("\n"),
        ),
        (
            "wrong header",
            good_text.replacen(TRUST_HEADER, "agent-sign/acts-trust/2", 1),
        ),
        (
            "unknown word",
            format!("{good_text}allow person:taylor {key}\n"),
        ),
        (
            "malformed key",
            format!("{good_text}assigner person:taylor ssh-ed25519 AAAA\n"),
        ),
        (
            "one key, two identities",
            format!("{good_text}assigner person:taylor {key}\nassigner person:other {key}\n"),
        ),
        (
            "a key under two kinds",
            format!("{good_text}assigner person:taylor {key}\n"),
        ),
        (
            "agent as assigner",
            format!("{good_text}assigner agent:builder-1 {key}\n"),
        ),
        (
            "revoked a non-identity",
            format!("{good_text}revoked builder\n"),
        ),
        ("an empty file", String::new()),
    ];
    for (what, body) in cases {
        let f = w.trust_file_text(&body);
        let (code, v) = w.verify(&payload(), &member, &f, None);
        problems.check(code == 2 && v["verified"] == json!(false), || {
            format!("{what}: expected exit 2 and verified false; exit {code}, {v}")
        });
    }
    let (code, v) = w.verify(&payload(), &member, &w.home.join("no-such-file"), None);
    problems.check(code == 2 && v["reason"] == json!("no_trust_file"), || {
        format!("missing file: exit {code}, {v}")
    });
    let out = w.verify_raw(
        &ActWorld::envelope(&payload(), &member),
        Path::new("relative/trust"),
        None,
    );
    problems.check(out.status.code() == Some(2), || {
        format!("relative path: expected exit 2:\n{}", text(&out))
    });
    problems.finish();
}

#[test]
fn probe_08_the_validity_window_is_checked_at_the_given_time() {
    let w = ActWorld::new(true);
    let member = w.agent_signs(BUILDER, &payload());
    let trust = w.trust_file(&[]);
    let now = now_secs();
    let mut problems = Problems::default();
    for (what, at, ok) in [
        ("now", now, true),
        ("11 hours on", now + 11 * 3600, true),
        ("13 hours on", now + 13 * 3600, false),
        ("a day before", now - 24 * 3600, false),
    ] {
        let (code, v) = w.verify(&payload(), &member, &trust, Some(at));
        let good = if ok {
            v["verified"] == json!(true) && code == 0
        } else {
            v["reason"] == json!("outside_window") && code == 1
        };
        problems.check(good, || {
            format!("{what}: expected ok={ok}; exit {code}, {v}")
        });
    }
    problems.finish();
}

#[test]
fn probe_09_a_certificate_from_another_session_does_not_carry_this_signature() {
    let w = ActWorld::new(true);
    let (a, b) = (
        w.agent_signs(BUILDER, &payload()),
        w.agent_signs(OTHER, &payload()),
    );
    let trust = w.trust_file(&[]);
    // a's signature with b's certificate, and the reverse: each pair mixes one key with the other's identity.
    let mut problems = Problems::default();
    for (what, member) in [
        (
            "a's signature, b's certificate",
            json!({"schema": a["schema"], "signature": a["signature"], "certificate": b["certificate"]}),
        ),
        (
            "b's signature, a's certificate",
            json!({"schema": b["schema"], "signature": b["signature"], "certificate": a["certificate"]}),
        ),
        (
            "no certificate",
            json!({"schema": a["schema"], "signature": a["signature"], "certificate": null}),
        ),
    ] {
        let (code, v) = w.verify(&payload(), &member, &trust, None);
        problems.check(
            v["verified"] == json!(false) && code == 1 && v["signer"].is_null(),
            || format!("{what}: must not verify; exit {code}, {v}"),
        );
    }
    problems.finish();
}

#[test]
fn probe_10_a_certificate_from_an_authority_the_trust_file_does_not_name() {
    let w = ActWorld::new(true);
    let member = w.agent_signs(BUILDER, &payload());
    // A trust file that lists only the launcher's line: the session authority is absent.
    let lines = w.trust_lines();
    let body = format!(
        "{TRUST_HEADER}\n{}\n",
        lines
            .lines()
            .filter(|l| !l.starts_with("authority "))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let f = w.trust_file_text(&body);
    let (code, v) = w.verify(&payload(), &member, &f, None);
    expect(
        &v,
        false,
        None,
        None,
        "untrusted_authority",
        "authority not in the trust file",
    );
    assert_eq!(code, 1);
}

#[test]
fn probe_11_a_restarted_service_has_a_new_authority_and_old_signatures_do_not_carry_over() {
    let mut w = ActWorld::new(true);
    let old = w.agent_signs(BUILDER, &payload());
    let old_launcher = member_of(&w.launcher_signs(&payload()));
    w.stop_service();
    let _ = fs::remove_file(&w.socket);
    w.start_service();
    let trust = w.trust_file(&[]); // trust lines of the NEW service
    let mut problems = Problems::default();
    for (what, member) in [("agent", &old), ("launcher", &old_launcher)] {
        let (code, v) = w.verify(&payload(), member, &trust, None);
        problems.check(v["verified"] == json!(false) && code == 1, || {
            format!("old {what} signature under the new service's trust: exit {code}, {v}")
        });
    }
    problems.finish();
}

#[test]
fn probe_12_verify_never_hangs_or_crashes_on_hostile_input() {
    let w = ActWorld::new(true);
    let trust = w.trust_file(&[]);
    let member = w.agent_signs(BUILDER, &payload());
    let mut problems = Problems::default();
    let (code, v) = w.verify(&payload(), &member, &trust, None);
    problems.check(code == 0 && v["verified"] == json!(true), || {
        format!("control: a good envelope should verify; exit {code}, {v}")
    });
    let big = vec![b'{'; 2 << 20];
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty stdin", vec![]),
        ("not JSON", b"not json".to_vec()),
        ("a huge body", big),
        (
            "two objects",
            [
                ActWorld::envelope(&payload(), &member),
                ActWorld::envelope(&payload(), &member),
            ]
            .concat(),
        ),
        (
            "duplicate keys",
            format!("{{\"payload_b64\":\"AAAA\",\"payload_b64\":\"AAAA\",\"signature\":{member}}}")
                .into_bytes(),
        ),
        (
            "bad base64",
            format!("{{\"payload_b64\":\"***\",\"signature\":{member}}}").into_bytes(),
        ),
        (
            "non-canonical base64",
            format!("{{\"payload_b64\":\"{}\",\"signature\":{member}}}", "QQ").into_bytes(),
        ),
        (
            "a payload over the limit",
            ActWorld::envelope(&vec![b'a'; 65537], &member),
        ),
        (
            "null payload",
            format!("{{\"payload_b64\":null,\"signature\":{member}}}").into_bytes(),
        ),
    ];
    for (what, stdin) in cases {
        let out = w.verify_raw(&stdin, &trust, None);
        let ok = matches!(out.status.code(), Some(1) | Some(2))
            && !String::from_utf8_lossy(&out.stdout).contains("\"verified\":true")
            && !String::from_utf8_lossy(&out.stdout).contains("\"verified\": true");
        problems.check(ok, || {
            format!(
                "{what}: expected exit 1 or 2 and no success:\n{}",
                &text(&out)[..text(&out).len().min(600)]
            )
        });
    }
    problems.finish();
}

// ---------------------------------------------------------------------------------------------------------------
// cred: how a session shows who it is
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn cred_01_a_session_credential_identifies_the_agent_and_goes_stale() {
    let w = ActWorld::new(true);
    let c = w.credential_of(BUILDER);
    let trust = w.trust_file(&[]);
    let issued = c["issued_at"].as_u64().expect("issued_at is a unix time");
    assert!(issued.abs_diff(now_secs()) < 60, "issued_at should be now");
    let mut problems = Problems::default();
    let (code, v) = w.verify_credential(&c, &trust, None);
    problems.check(
        code == 0
            && v["signer"] == json!(BUILDER)
            && v["kind"] == json!("agent")
            && v["reason"] == json!("ok"),
        || format!("fresh: exit {code}, {v}"),
    );
    let (code, v) = w.verify_credential(&c, &trust, Some(issued + 299));
    problems.check(code == 0, || format!("299 s old: exit {code}, {v}"));
    let (code, v) = w.verify_credential(&c, &trust, Some(issued + 301));
    problems.check(code == 1 && v["reason"] == json!("stale"), || {
        format!("301 s old: exit {code}, {v}")
    });
    let (code, v) = w.verify_credential(&c, &trust, Some(issued - 61));
    problems.check(code == 1 && v["reason"] == json!("stale"), || {
        format!("dated 61 s ahead: exit {code}, {v}")
    });
    // Backdating the stamp breaks the signature, not just the clock.
    let mut forged = c.clone();
    forged["issued_at"] = json!(issued + 1000);
    let (code, v) = w.verify_credential(&forged, &trust, Some(issued + 1000));
    problems.check(code == 1 && v["verified"] == json!(false), || {
        format!("moved issued_at: exit {code}, {v}")
    });
    problems.finish();
}

#[test]
fn cred_02_only_agents_have_credentials_and_a_revoked_agent_has_none() {
    let w = ActWorld::new(true);
    let c = w.credential_of(BUILDER);
    let out = w.in_session(None, &["credential"], &[]);
    assert!(
        !out.status.success() && !String::from_utf8_lossy(&out.stdout).contains("\"signature\""),
        "an anonymous session has no credential:\n{}",
        text(&out)
    );
    let out = w.agent_sign().args(["act", "credential"]).output().unwrap();
    assert!(
        !out.status.success(),
        "outside a session there is no credential:\n{}",
        text(&out)
    );
    let revoked = w.trust_file(&[format!("revoked {BUILDER}")]);
    let (code, v) = w.verify_credential(&c, &revoked, None);
    assert!(
        code == 1 && v["reason"] == json!("revoked"),
        "revoked: exit {code}, {v}"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// system: need the root setup of docs/system-mode.md; run later, with `--ignored`
// ---------------------------------------------------------------------------------------------------------------

fn system_cmd(args: &[&str]) -> std::process::Output {
    // The installed programs, the system socket and settings; no test seams. Run as the agents account.
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_agent-sign"));
    cmd.env_remove("AGENT_SIGN_SOCKET")
        .env_remove("AGENT_SIGN_TEST_SYSTEM_CONFIG")
        .args(args);
    run_within(
        cmd,
        Some(b"role-commitments/act/1\nx"),
        "system-mode agent-sign",
    )
}

#[test]
#[ignore = "needs system mode: root-owned /etc/agent-sign/system.toml and the OpenBao issuer (docs/system-mode.md)"]
fn system_01_the_agents_account_cannot_sign_as_the_launcher_or_launch_with_an_identity() {
    assert!(
        Path::new("/etc/agent-sign/system.toml").exists(),
        "system mode is not set up on this machine"
    );
    let out = system_cmd(&["act", "sign", "--assigner", "harness:launcher"]);
    assert!(
        !out.status.success() && !String::from_utf8_lossy(&out.stdout).contains("\"signature\""),
        "the agents account signed as the launcher:\n{}",
        text(&out)
    );
    let out = system_cmd(&[
        "launch",
        "--agent",
        "claude-code",
        "--identity",
        "agent:builder-1",
        "--",
        "/bin/true",
    ]);
    assert!(
        !out.status.success(),
        "the agents account launched a session with an identity:\n{}",
        text(&out)
    );
}

#[test]
#[ignore = "needs system mode: the launcher's assigner key lives in OpenBao"]
fn system_02_the_launchers_key_is_in_openbao_and_trust_lines_come_from_it() {
    let out = system_cmd(&["act", "trust-lines"]);
    assert!(
        out.status.success(),
        "trust-lines should work in system mode:\n{}",
        text(&out)
    );
    let lines = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        lines
            .lines()
            .any(|l| l.starts_with("assigner harness:launcher ssh-ed25519 ")),
        "no launcher line:\n{lines}"
    );
    let config = fs::read_to_string("/etc/agent-sign/system.toml").unwrap_or_default();
    assert!(
        config.contains("launcher_assigner = \"openbao\""),
        "system.toml must name OpenBao for the launcher's assigner key:\n{config}"
    );
}

#[test]
#[ignore = "needs system mode: root-owned trust file"]
fn system_03_the_trust_file_is_root_owned_and_unwritable_by_agents() {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata("/etc/agent-sign/acts_trust").expect("the system trust file for acts");
    assert_eq!(meta.uid(), 0, "root must own it");
    assert_eq!(meta.mode() & 0o022, 0, "nobody but root may write it");
}
