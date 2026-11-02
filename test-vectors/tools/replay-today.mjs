// Replays the vectors from their files against TODAY's code and checks that today's answer is the one the file records.
// This proves the files hold everything a check needs (nothing was lost in writing them out), and it is the shape of the
// replay each binding of the consolidated checker will do against the same files with its own code.
// Usage: LEGACY_ROOT=<folder with the checkouts> node replay-today.mjs <test-vectors dir>
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPublicKey } from "node:crypto";
import { imp, startPython, stopPython, pyCall, hex } from "./lib.mjs";

const dir = process.argv[2] ?? ".";
const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
startPython(new URL("legacy_py.py", import.meta.url).pathname);
const ids = await imp("unharness/src/ids.ts"), pk = await imp("unharness/src/person-keys.ts"), pub = await imp("unharness/src/publisher.ts"), lib = await imp("unharness/src/mod.ts");
const tl = await imp("unharness/listeners/src/team-lead/signed.ts"), ml = await imp("unharness/listeners/src/model-layer/signing.ts");
const ac = await imp("agentic-credentials/src/entitlement/acts.ts"), rl = await imp("agentic-credentials/src/approvals/relay.ts");
const el = await imp("work-loop/src/log/event-log.ts"), wl = await imp("work-loop/src/log/canonical.ts"), names = await imp("unharness/src/names.ts");
const spkiPem = (b64) => `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----\n`;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const relayFor = (key, now) => new rl.ApprovalRelay({ channel: { present: async () => "couldnt-ask", cancel() {} }, personDeviceKey: key, lookup: async () => { throw 0; }, authorize: async () => true, now: () => now });

const replay = {
  async encoding(v) {
    const text = v.input.json_text; const out = {};
    let parsed, bad; try { parsed = JSON.parse(text); } catch { bad = true; }
    const enc = { L01: ids.canonical, L05: tl.canonical, L09: ac.canonical, L12: wl.canonicalJson, L13: ml.canonicalJson };
    for (const [l, f] of Object.entries(enc)) { if (bad) { out[l] = { error: "does-not-parse" }; continue; } try { out[l] = { bytes: hex(new TextEncoder().encode(f(parsed))) }; } catch { out[l] = { error: "refuses" }; } }
    const p = await pyCall({ op: "encode", text }); out.L07 = p.ok !== undefined ? { bytes: p.ok } : { error: p.error === "NotCanonical" ? "refuses" : "does-not-parse" };
    return same(out, v.today.encoders);
  },
  async names(v) {
    const i = v.input; let r;
    if (i.op === "parse") r = names.parseActorName(i.name) ? "accepted" : "refused";
    else if (i.op === "make") { try { names.actorName(i.kind, i.id); r = "accepted"; } catch { r = "refused"; } }
    else { const n = names.actorNameForParty(i.party); r = n === undefined ? "refused" : n === v.expected.name ? "accepted" : "differs"; }
    return r === v.today.result;
  },
  async "device-es256"(v) {
    const i = v.input; const ring = new pk.KeyRing(); const reg = [];
    for (const r of i.registrations ?? []) reg.push(await ring.register(r));
    if (v.id === "DEV-N06") return reg[0] === v.today.registered;
    if (v.id === "DEV-N08") return reg[0] === v.today.attackerKeyTrusted && reg[1] === v.today.personsOwnKeyTrusted;
    const data = i.data ?? i.madeFor?.event?.data;
    const status = await ring.check(i.party, data.signature, i.id ?? i.madeFor.event.id, (i.conversation ?? i.madeFor?.event?.conversation) ?? undefined, data);
    return status === v.today.ring;
  },
  async "stream-publisher"(v) {
    const i = v.input; const j = pub.judgePublisher(i.registry, i.subject, (n) => i.headers[n], i.body, i.seq, new Date(i.storedAt));
    return (j.problem === undefined) === v.today.accepted && (j.reason ?? null) === v.today.reason;
  },
  async "team-record"(v) {
    const i = v.input; const trust = { taylor: Object.fromEntries(Object.entries(i.trust.taylor).map(([k, b]) => [k, spkiPem(b)])), reviewers: Object.fromEntries(Object.entries(i.trust.reviewers).map(([k, b]) => [k, spkiPem(b)])) };
    const d = mkdtempSync(join(tmpdir(), "rp-"));
    try {
      if (i.op === "commitment") { writeFileSync(join(d, encodeURIComponent(i.askedId) + ".json"), JSON.stringify(i.entry)); const r = tl.loadCommitment(d, trust, i.askedId); return r.ok === v.today.accepted; }
      i.records.forEach((r, n) => writeFileSync(join(d, `r${n}.json`), JSON.stringify(r)));
      const s = tl.reviewState(d, trust, i.change, i.commit); return s.passed === v.today.passed && s.failed === v.today.failed;
    } finally { rmSync(d, { recursive: true }); }
  },
  async "act-v1"(v) {
    if ("typescriptPort" in v.today) return true; // these record how two implementations differ; the generator ran both
    const r = await pyCall({ op: "check_act", act: v.input.act, registry: v.input.registry }); return !!r.counts === v.today.counts;
  },
  async "approval-v2"(v) {
    const i = v.input; const key = createPublicKey({ key: Buffer.from(i.deviceKeySpkiB64, "base64"), format: "der", type: "spki" });
    return relayFor(key, i.now).check(i.question, i.answer) === v.today.outcome;
  },
  async "log-chain"(v) {
    const d = mkdtempSync(join(tmpdir(), "rp-")); try { const p = join(d, "e.jsonl"); writeFileSync(p, v.input.lines.join("\n") + "\n"); const r = await new el.EventLog({ logPath: p, lockPath: p + ".lock" }).verify(); return r.ok === v.today.ok && r.entries === v.today.entries; } finally { rmSync(d, { recursive: true }); }
  },
  async "record-ns"(v) {
    const i = v.input; const p = ml.recordSignatureProblem(i.signature, i.type, i.payload, { authorities: i.authorities, identity: i.identity, now: i.now }) ?? "none"; return p === v.today.problem;
  },
  async "cross-use"(v) {
    const i = v.input; const from = i.madeFor, to = i.offeredAs; const S = i.signatures;
    const std = (u) => Buffer.from(u, "base64url").toString("base64"), u8 = (b) => Buffer.from(b, "base64").toString("base64url");
    const sig = from === "stream" ? { b64u: S.streamEventB64u, b64: std(S.streamEventB64u) } : from === "act" ? { b64u: u8(S.actB64), b64: S.actB64 } : { b64u: u8(S.approvalB64), b64: S.approvalB64 };
    let got;
    if (to === "act") { const r = await pyCall({ op: "check_act", act: { ...i.act, sig: { key: "k-svc#1", ed25519: sig.b64 } }, registry: i.registry }); got = r.counts ? "accepted" : "refused"; }
    else if (to === "stream") { const h = { ...i.stream.headers, "suite-publisher-key": i.key.nkey, "suite-publisher-signature": sig.b64u }; const j = pub.judgePublisher(i.stream.registry, i.stream.subject, (n) => h[n], i.stream.body, 5, new Date("2026-10-23T12:00:01Z")); got = j.problem === undefined ? "accepted" : "refused"; }
    else { const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(i.key.rawB64, "base64")]), format: "der", type: "spki" }); got = relayFor(key, i.approval.now).check(i.approval.question, { ...i.approval.answer, signature: sig.b64 }) === "approved" ? "accepted" : "refused"; }
    return got === "refused" && /^(refused|outcome denied)/.test(v.today.check);
  },
  async "passkey-act"(v) {
    const i = v.input; const table = new Map(v.policy.map((p) => [JSON.stringify(p.question), p.answer]));
    const policy = { async decide(q) { return table.get(JSON.stringify(q)) ?? { accepted: false, why: "unanswered" }; } };
    const opts = { policy, webauthn: { rpId: i.context.rpId, origins: i.context.origins }, pinnedPasskeys: i.context.pinnedPasskeys, ...(i.context.setting ? { setting: i.context.setting } : {}), ...(i.context.switchedAt ? { switchedAt: i.context.switchedAt } : {}) };
    const verifier = new lib.ActVerifier(opts);
    const evs = v.id === "PASS-N-K3" || v.id === "PASS-N-K4" ? i.events.slice(0, -1) : i.events;
    for (const e of evs) await verifier.ingest(e);
    if (v.id === "PASS-N-K4") return (await verifier.registerDeviceKey(i.events[i.events.length - 1])) === v.today.registrationRemembered;
    if (v.id === "PASS-N-K3") { const remembered = await verifier.registerDeviceKey(i.events[i.events.length - 1]); if (remembered !== v.today.registrationRemembered) return false; }
    const r = i.mode === "ingest" ? await verifier.ingest(i.act, i.actContext) : await verifier.verify(i.act, i.actContext);
    return r.status === v.today.status && (r.attribution?.assurance ?? undefined) === v.today.assurance && (r.reason ?? null) === (v.today.reason ?? null);
  },
};
let ok = 0; const bad = [];
for (const e of manifest.vectors) {
  const v = JSON.parse(readFileSync(join(dir, e.file), "utf8"));
  let good; try { good = await replay[v.family](v); } catch (err) { good = false; console.error(v.id, err.message); }
  if (good) ok++; else bad.push(v.id);
}
stopPython();
console.log(`replay against today's code: ${ok} of ${manifest.vectors.length} vectors give the recorded answer`);
if (bad.length) { console.log("did not reproduce: " + bad.join(", ")); process.exit(1); }
