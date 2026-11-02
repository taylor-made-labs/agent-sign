// Family "stream-publisher": the signature every stream event carries, by the publisher's NATS key (Ed25519), over a
// versioned list of the subject, the ce- attributes and the body (src/publisher.ts).
import { imp, vec, nkeyUser, b64u } from "./lib.mjs";

export async function publisherFamily() {
  const pub = await imp("unharness/src/publisher.ts");
  const svc = nkeyUser("stream-publisher/service-a");
  const svc2 = nkeyUser("stream-publisher/service-b");
  // a made seed must round-trip through the real library
  const nk = (await imp("unharness/node_modules/@nats-io/nats-core/lib/mod.js")).nkeys;
  if (nk.fromSeed(svc.seedBytes).getPublicKey() !== svc.publicText) throw new Error("NATS key encoding disagrees with the library");
  const key = pub.publisherKey(svc.seedBytes);
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const subject = "ev.unharness.run-started.mac";
  const headers = { "ce-id": "ev-0001", "ce-type": "suite.unharness.run-started", "ce-source": "unharness/mac", "ce-time": "2026-10-23T12:00:00.000Z", "ce-conversation": "c-1" };
  const body = JSON.stringify({ run: "run-1", engine: "x" });
  const sigHeaders = pub.signEvent(key, subject, headers, body);
  const sigV1 = (() => { const input = pub.publisherSigningInput(subject, (n) => headers[n], body, 1); return b64u(key.sign(input)); })();
  const registry = (extra = {}) => ({ unsignedThrough: 0, publishers: [{ publicKey: svc.publicText, product: "unharness" }], ...extra });
  const judge = (reg, subj, hdrs, bod, seq = 5, storedAt = "2026-10-23T12:00:01Z") => {
    const all = { ...hdrs };
    const j = pub.judgePublisher(reg, subj, (n) => all[n], bod, seq, new Date(storedAt));
    return { accepted: j.problem === undefined, reason: j.reason ?? null, signed: j.signed ?? false };
  };
  const full = { ...headers, ...sigHeaders };
  const pass = (reg) => judge(reg, subject, full, body);
  const ok = { result: "accepted", signer: `service:${svc.publicText}`, onBehalfOf: "product:unharness", strength: "service-key" };
  const no = (reason) => ({ result: "refused", reason });
  const P = (id, o) => vec({ id, family: "stream-publisher", legacy: "L04", ...o });
  const input = (reg, subj, hdrs, bod, extra = {}) => ({ registry: reg, subject: subj, headers: hdrs, body: bod, seq: 5, storedAt: "2026-10-23T12:00:01Z", ...extra });
  P("PUB-P01", { kind: "positive", tags: [], about: "a version 2 event from a key listed for its product", input: input(registry(), subject, full, body), expected: ok, today: pass(registry()) });
  {
    const hv1 = { ...headers, "suite-publisher-key": svc.publicText, "suite-publisher-signature": sigV1 };
    const reg = registry({ v1Through: 100 });
    P("PUB-P02", { kind: "positive", tags: ["legacy"], about: "a version 1 event stored within the recorded history (v1Through)", input: input(reg, subject, hv1, body), expected: ok, today: judge(reg, subject, hv1, body) });
  }
  {
    const reg = { unsignedThrough: 0, publishers: [{ publicKey: svc.publicText, product: "unharness", from: "2026-10-01T00:00:00Z", until: "2026-12-01T00:00:00Z" }] };
    P("PUB-P03", { kind: "positive", tags: [], about: "stored inside the key's enrolment period", input: input(reg, subject, full, body), expected: ok, today: judge(reg, subject, full, body) });
  }
  {
    const reg = registry({ unsignedThrough: 10 });
    const unsigned = { ...headers };
    P("PUB-P04", { kind: "positive", tags: ["legacy"], about: "an event with no signature stored at or below the recorded unsigned history", input: input(reg, subject, unsigned, body, { seq: 3 }), expected: { result: "accepted", signer: "none", onBehalfOf: "none", strength: "none" }, today: judge(reg, subject, unsigned, body, 3) });
  }
  P("PUB-N01", { kind: "negative", tags: [], about: "the body was changed after signing", input: input(registry(), subject, full, body + " "), expected: no("bad-signature"), today: judge(registry(), subject, full, body + " ") });
  P("PUB-N02", { kind: "negative", tags: ["cross-use"], about: "a genuine event replayed on another subject", input: input(registry(), "ev.unharness.run-ended.mac", full, body), expected: no("bad-signature"), today: judge(registry(), "ev.unharness.run-ended.mac", full, body) });
  { const h = { ...full, "ce-time": "2026-10-23T12:00:02.000Z" }; P("PUB-N03", { kind: "negative", tags: [], about: "an attribute (ce-time) changed", input: input(registry(), subject, h, body), expected: no("bad-signature"), today: judge(registry(), subject, h, body) }); }
  { const reg = { unsignedThrough: 0, publishers: [] }; P("PUB-N04", { kind: "negative", tags: [], about: "a key the registry does not list", input: input(reg, subject, full, body), expected: no("unknown-key"), today: judge(reg, subject, full, body) }); }
  { const reg = { unsignedThrough: 0, publishers: [{ publicKey: svc.publicText, product: "cas" }] }; P("PUB-N05", { kind: "negative", tags: [], about: "a key listed for another product publishing on this one", input: input(reg, subject, full, body), expected: no("wrong-product"), today: judge(reg, subject, full, body) }); }
  { const reg = { unsignedThrough: 0, publishers: [{ publicKey: svc.publicText, product: "unharness", from: "2026-10-24T00:00:00Z" }] }; P("PUB-N06", { kind: "negative", tags: [], about: "stored before the key's enrolment began", input: input(reg, subject, full, body), expected: no("outside-its-periods"), today: judge(reg, subject, full, body) }); }
  {
    const raw = Buffer.from(sigHeaders["suite-publisher-signature"], "base64url");
    let s = 0n; for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(raw[i]);
    const s2 = s + L; const out = Buffer.from(raw);
    for (let i = 32; i < 64; i++) out[i] = Number((s2 >> BigInt(8 * (i - 32))) & 255n);
    const h = { ...full, "suite-publisher-signature": b64u(out) };
    P("PUB-N07", { kind: "negative", tags: [], about: "the same signature with S raised by the group order (a second encoding of one signature)", input: input(registry(), subject, h, body), expected: no("bad-encoding"), today: judge(registry(), subject, h, body) });
  }
  { const hv1 = { ...headers, "suite-publisher-key": svc.publicText, "suite-publisher-signature": sigV1 }; P("PUB-N08", { kind: "negative", tags: ["legacy"], about: "a version 1 signature where no v1 history is recorded", input: input(registry(), subject, hv1, body), expected: no("bad-signature"), today: judge(registry(), subject, hv1, body) }); }
  { const reg = registry({ unsignedThrough: 10 }); P("PUB-N09", { kind: "negative", tags: [], about: "no signature, stored after the unsigned history ended", input: input(reg, subject, { ...headers }, body, { seq: 50 }), expected: no("unsigned"), today: judge(reg, subject, { ...headers }, body, 50) }); }
  {
    const reg = { unsignedThrough: 0, publishers: [{ publicKey: svc.publicText, product: "unharness" }, { publicKey: svc2.publicText, product: "unharness" }] };
    const h = { ...full, "suite-publisher-key": svc2.publicText };
    P("PUB-N10", { kind: "negative", tags: [], about: "a signature by one listed key with another listed key named in the header", input: input(reg, subject, h, body), expected: no("bad-signature"), today: judge(reg, subject, h, body) });
  }
  return { svc, key, subject, headers, body, sigHeaders };
}
