// Family "device-es256": the person's browser/device-key signature on an expression (src/ids.ts, checked per party
// by the first-key-wins ring in src/person-keys.ts). Expected strengths use the turn 7 ladder.
import { imp, vec, deviceKey, p256, b64u } from "./lib.mjs";

export async function deviceFamily() {
  const ids = await imp("unharness/src/ids.ts");
  const pk = await imp("unharness/src/person-keys.ts");
  const mk = (label) => deviceKey(label, ids.keyIdFor);
  const taylor = await mk("device-es256/taylor-browser");
  const other = await mk("device-es256/other-browser");
  const attacker = await mk("device-es256/attacker-browser");
  const ME = "person:me", YOU = "person:you";
  const regEvent = (k, party) => ({ party, keyId: k.keyId, publicKey: k.jwk, device: "test-browser" });
  const ring = async (regs) => { const r = new pk.KeyRing(); const res = []; for (const [k, party] of regs) res.push(await r.register(regEvent(k, party))); return { r, res }; };
  const signed = async (k, id, conv, data) => ({ ...data, signature: await ids.sign(k.pair.privateKey, k.keyId, id, conv, data) });
  const check = async (regs, party, data, id, conv) => { const { r } = await ring(regs); return r.check(party, data.signature, id, conv, data); };
  const accepted = (k, party) => ({ result: "accepted", signer: `device:${k.keyId}`, onBehalfOf: party, strength: "device" });
  const refusedWith = (reason) => ({ result: "refused", reason });
  const today = (status) => ({ ring: status });
  const base = { act: "message", content: "hello there", party: ME };
  const D = (id, o) => vec({ id, family: "device-es256", legacy: o.legacy ?? "L01 L03", ...o });

  {
    const id = "e-1", conv = "c-1";
    const data = await signed(taylor, id, conv, base);
    const ok = await check([[taylor, ME]], ME, data, id, conv);
    D("DEV-P01", { kind: "positive", tags: [], about: "an expression signed by the person's registered browser key", input: { registrations: [regEvent(taylor, ME)], party: ME, id, conversation: conv, data }, expected: accepted(taylor, ME), today: today(ok) });
    const data2 = await signed(taylor, "e-2", undefined, { act: "answer", content: "yes", party: ME, widens: false });
    D("DEV-P02", { kind: "positive", tags: [], about: "no conversation, a boolean field: the signed bytes drop an absent conversation", input: { registrations: [regEvent(taylor, ME)], party: ME, id: "e-2", conversation: null, data: data2 }, expected: accepted(taylor, ME), today: today(await check([[taylor, ME]], ME, data2, "e-2", undefined)) });
    const data3 = await signed(taylor, "e-3", "c-3", { act: "message", content: "café 日本 😀", party: ME });
    D("DEV-P03", { kind: "positive", tags: [], about: "non-ASCII content, including a character outside the BMP", input: { registrations: [regEvent(taylor, ME)], party: ME, id: "e-3", conversation: "c-3", data: data3 }, expected: accepted(taylor, ME), today: today(await check([[taylor, ME]], ME, data3, "e-3", "c-3")) });
    // negatives
    D("DEV-N01", { kind: "negative", tags: [], about: "the content was changed after signing", input: { registrations: [regEvent(taylor, ME)], party: ME, id, conversation: conv, data: { ...data, content: "goodbye" } }, expected: refusedWith("bad-signature"), today: today(await check([[taylor, ME]], ME, { ...data, content: "goodbye" }, id, conv)) });
    D("DEV-N02", { kind: "negative", tags: ["cross-use"], about: "the same signature presented under another event id", input: { registrations: [regEvent(taylor, ME)], party: ME, id: "e-other", conversation: conv, data }, expected: refusedWith("bad-signature"), today: today(await check([[taylor, ME]], ME, data, "e-other", conv)) });
    D("DEV-N03", { kind: "negative", tags: ["cross-use"], about: "the same signature presented in another conversation", input: { registrations: [regEvent(taylor, ME)], party: ME, id, conversation: "c-other", data }, expected: refusedWith("bad-signature"), today: today(await check([[taylor, ME]], ME, data, id, "c-other")) });
    const dOther = await signed(other, id, conv, base);
    D("DEV-N04", { kind: "negative", tags: [], about: "a valid signature by another person's key, presented as the person's", input: { registrations: [regEvent(taylor, ME), regEvent(other, YOU)], party: ME, id, conversation: conv, data: dOther }, expected: refusedWith("wrong-key-for-party"), today: today(await check([[taylor, ME], [other, YOU]], ME, dOther, id, conv)) });
    D("DEV-N05", { kind: "negative", tags: ["divergence:first-key-wins"], about: "a second key for the same person: today only the first key counts, and a later one is ignored", input: { registrations: [regEvent(taylor, ME), regEvent(other, ME)], party: ME, id, conversation: conv, data: dOther }, expected: refusedWith("not-the-enrolled-key"), today: today(await check([[taylor, ME], [other, ME]], ME, dOther, id, conv)) });
    {
      const bad = { ...regEvent(other, ME), keyId: "x-" + "0".repeat(32) };
      const r = new pk.KeyRing(); const reg = await r.register(bad);
      D("DEV-N06", { kind: "negative", tags: [], about: "a key whose id is not the hash of its public key is not registered", input: { registrations: [bad], party: ME }, expected: refusedWith("key-id-is-not-the-key-hash"), today: { registered: reg } });
    }
    // cross-use: a signature for one kind of event reused as another kind
    {
      const asDelegation = { event: { kind: "delegation-granted", id, conversation: conv, data } };
      const as1 = { event: { kind: "expression", id, conversation: conv, data } };
      D("DEV-N07", { kind: "negative", tags: ["cross-use", "divergence:no-context"], about: "a signature made for an expression, reattached to an event of another kind (a delegation grant) with the same id, conversation and data: the signed bytes name no kind, so today it checks out", input: { registrations: [regEvent(taylor, ME)], party: ME, madeFor: as1, presentedAs: asDelegation }, expected: refusedWith("wrong-context"), today: today(await check([[taylor, ME]], ME, data, id, conv)) });
    }
    {
      const r = new pk.KeyRing(); const first = await r.register(regEvent(attacker, ME)); const second = await r.register(regEvent(taylor, ME));
      D("DEV-N08", { kind: "negative", tags: ["divergence:enrolled-by-anything-but-a-passkey", "divergence:first-key-wins"], about: "a key registered for the person by whoever published first, with no passkey involved: today the ring trusts it and then refuses the person's own key", input: { registrations: [regEvent(attacker, ME), regEvent(taylor, ME)], enrolledBy: "unauthenticated-event", party: ME }, expected: refusedWith("not-enrolled-by-passkey"), today: { attackerKeyTrusted: first, personsOwnKeyTrusted: second } });
    }
    {
      const sigBad = { ...data.signature, alg: "ES384" };
      D("DEV-N09", { kind: "negative", tags: [], about: "a signature that names another algorithm", input: { registrations: [regEvent(taylor, ME)], party: ME, id, conversation: conv, data: { ...data, signature: sigBad } }, expected: refusedWith("unsupported-algorithm"), today: today(await check([[taylor, ME]], ME, { ...data, signature: sigBad }, id, conv)) });
      // a DER-encoded signature in place of the raw r||s form
      const { sign: nsign } = await import("node:crypto");
      const k = p256("device-es256/taylor-browser");
      const payload = Buffer.from(ids.signedPayload(id, conv, base), "utf8");
      const der = nsign("sha256", payload, { key: k.privateKey, dsaEncoding: "der" });
      const sigDer = { ...data.signature, value: b64u(der) };
      D("DEV-N10", { kind: "negative", tags: [], about: "a correct ECDSA signature in DER form where the raw form is required", input: { registrations: [regEvent(taylor, ME)], party: ME, id, conversation: conv, data: { ...base, signature: sigDer } }, expected: refusedWith("bad-signature"), today: today(await check([[taylor, ME]], ME, { ...base, signature: sigDer }, id, conv)) });
      D("DEV-N11", { kind: "negative", tags: [], about: "no signature at all", input: { registrations: [regEvent(taylor, ME)], party: ME, id, conversation: conv, data: base }, expected: refusedWith("unsigned"), today: today(await check([[taylor, ME]], ME, base, id, conv)) });
    }
  }
}
