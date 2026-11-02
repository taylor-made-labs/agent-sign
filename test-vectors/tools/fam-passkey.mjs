// Family "passkey-act": the checker for Taylor's own signatures (unharness src/acts.ts, ActVerifier): passkey assertions
// (WebAuthn ES256), browser device-key signatures, plain acts, and the registrations that make keys count. Turn 7's
// probes P1-P5, P8, P12 (and P6, P7) are built here from the signing plan's own test fixtures (test/support/signing.ts,
// probes.ts), with keys made from public labels. Expected strengths are the turn 7 ladder: presence (a user-verified
// passkey), device (a registered browser key), agent, os-account.
//
// The decision "is that strength enough for this act" is the commitments checker's (ntaild decide-act), not the
// verifier's. Each vector therefore carries the questions the verifier asked and the live checker's answers
// (policy), so a replay needs no checker. The answers come from a run of `ntaild decide-act` at the ntaild main the
// repo checkout was at (see POLICY.json in this folder for the revision).
import { createHash, sign as nodeSign } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { imp, vec, p256, deviceKey, seedOf, b64u } from "./lib.mjs";

export const unanswered = new Map();

export async function passkeyFamily(answersFile) {
  const lib = await imp("unharness/src/mod.ts");
  const S = await imp("unharness/test/support/signing.ts");
  const answers = existsSync(answersFile) ? JSON.parse(readFileSync(answersFile, "utf8")) : {};
  const makePolicy = (used) => ({
    async decide(q) {
      const key = JSON.stringify(q);
      if (key in answers) { used.set(key, answers[key]); return answers[key]; }
      unanswered.set(key, q);
      return { accepted: false, why: "unanswered", say: "unanswered" };
    },
  });
  const { SoftPasskey, stored, deviceSigned, passkeySigned, passkeySignature, deviceKeyEvent, signedActData, withData, unsigned, SENTENCES, ME, RP_ID, ORIGIN, BROWSER_PUBLISHER } = S;
  const WEBAUTHN = { rpId: RP_ID, origins: [ORIGIN] };
  const challengeOf = (id, conv, data) => lib.actChallenge(id, conv, data);

  function detPasskey(label, o = {}) {
    const pk = new SoftPasskey({ id: Buffer.from(seedOf("credential-id:" + label)), ...o });
    const k = p256("passkey-act/" + label);
    Object.assign(pk, { privateKey: k.privateKey, publicKey: k.jwk, x: k.x, y: k.y });
    return pk;
  }
  const sha = (b) => createHash("sha256").update(b).digest();
  // an assertion with any single thing wrong, made by hand over the same bytes an authenticator signs
  function craft(pk, challenge, o = {}) {
    const rpId = o.rpId ?? pk.rpId, origin = o.origin ?? pk.origin;
    const counter = Buffer.alloc(4); counter.writeUInt32BE(++pk.counter);
    const flags = o.flags ?? 0x05;
    const authData = Buffer.concat([sha(rpId), Buffer.from([flags]), counter]);
    const clientData = Buffer.from(JSON.stringify({ type: o.type ?? "webauthn.get", challenge, origin, crossOrigin: false }), "utf8");
    const signature = nodeSign("sha256", Buffer.concat([authData, sha(clientData)]), { key: pk.privateKey, dsaEncoding: "der" });
    return { credentialId: pk.credentialId, authenticatorData: b64u(authData), clientDataJSON: b64u(clientData), signature: b64u(signature) };
  }
  async function craftedAct(actKind, pk, o = {}, craftOpts = {}) {
    const id = o.id ?? "act-" + actKind; const conversation = o.conversation ?? "c-test";
    const data = signedActData(actKind, o);
    const a = craft(pk, await challengeOf(id, conversation, data), craftOpts);
    return stored({ id, conversation, product: o.product ?? "chat-app", kind: o.kind ?? "signed-act", data: { ...data, signature: passkeySignature(a) } });
  }

  // one world per vector: Taylor's browser key, an agent's key, and (unless told otherwise) Taylor's pinned, registered passkey.
  // register:false leaves the passkey unregistered; pin:false leaves it unpinned (the local step never approved it).
  async function world(o = {}) {
    const register = o.register ?? true, pin = o.pin ?? true;
    const passkey = detPasskey("taylor-passkey");
    const stranger = detPasskey("stranger-passkey");
    const browser = await deviceKey("passkey-act/taylor-browser", lib.keyIdFor);
    const agent = await deviceKey("passkey-act/agent-pm", lib.keyIdFor);
    const events = [];
    const used = new Map();
    const pinned = pin ? [passkey.credentialId, ...(o.alsoPin ?? [])] : [...(o.alsoPin ?? [])];
    const context = { rpId: WEBAUTHN.rpId, origins: WEBAUTHN.origins, pinnedPasskeys: pinned, ...(o.setting ? { setting: o.setting } : {}), ...(o.switchedAt ? { switchedAt: o.switchedAt } : {}) };
    const verifier = new lib.ActVerifier({ policy: makePolicy(used), webauthn: WEBAUTHN, pinnedPasskeys: pinned, ...(o.setting ? { setting: o.setting } : {}), ...(o.switchedAt ? { switchedAt: o.switchedAt } : {}) });
    const ingest = async (e) => { events.push(e); return verifier.ingest(e); };
    await ingest(deviceKeyEvent(browser, ME, "chat-app", "test-browser", BROWSER_PUBLISHER));
    await ingest(deviceKeyEvent(agent, "agent:pm", "unharness", "pm-worker"));
    if (register) {
      const id = "reg-taylor-passkey", sentence = SENTENCES["register-passkey"];
      const reg = passkey.register(await lib.registrationChallenge(id, ME, sentence));
      await ingest(stored({ id, conversation: "c-test", product: "chat-app", kind: "passkey-registered", data: { party: ME, sentence, ...reg } }));
    }
    return { verifier, events, context, passkey, stranger, browser, agent, ingest, used };
  }

  const strength = { presence: "presence", device: "device", agent: "agent", "os-account": "os-account" };
  const summarize = (v) => v.status === "accepted"
    ? { status: "accepted", signer: v.attribution.signer, onBehalfOf: v.attribution.onBehalfOf, assurance: v.attribution.assurance }
    : { status: v.status, reason: v.reason ?? null, say: v.say ?? null, ...(v.attribution ? { signer: v.attribution.signer, assurance: v.attribution.assurance } : {}) };
  const policyOf = (used) => [...used.entries()].map(([q, a]) => ({ question: JSON.parse(q), answer: a }));
  const dump = (e) => JSON.parse(JSON.stringify(e));
  const P = (id, o) => vec({ id, family: "passkey-act", legacy: "L02", ...o });

  // run one case: judge `act` in world `w` (events before it already ingested), as `mode` ingest|verify
  async function judge(w, act, ctx, mode = "verify") {
    const v = mode === "ingest" ? await w.verifier.ingest(act, ctx) : await w.verifier.verify(act, ctx);
    return { v: summarize(v), policy: policyOf(w.used) };
  }
  const refused = (reason) => ({ result: "refused", reason });
  const acceptedAs = (s) => ({ result: "accepted", signer: s.signer, onBehalfOf: s.onBehalfOf, strength: strength[s.assurance] });
  const NOTE = "reason strings are today's vocabulary; a replay compares result, signer and strength";

  const add = async (id, kind, tags, about, w, act, expectedFrom, extra = {}) => {
    const { v, policy } = await judge(w, act, extra.ctx, extra.mode);
    const complete = unanswered.size === 0;
    if (kind === "positive" && complete && v.status !== "accepted") throw new Error(`${id} should be accepted today but was ${JSON.stringify(v)}`);
    const expected = kind === "positive" ? (v.status === "accepted" ? acceptedAs(v) : { result: "accepted", signer: "?", onBehalfOf: "?", strength: "?" }) : refused(expectedFrom ?? v.reason);
    P(id, { kind, tags, about, input: { context: w.context, events: dump(w.events), act: dump(act), ...(extra.ctx ? { actContext: extra.ctx } : {}), mode: extra.mode ?? "verify" }, policy, expected, today: { ...v, note: NOTE, ...(extra.divergence ? { divergence: extra.divergence } : {}) } });
    return v;
  };
  const vecSkipped = [];
  const STAKES = "approve-intent";

  // ---------------- positives ----------------
  { const w = await world(); await add("PASS-P01", "positive", [], "Taylor's finger (user-verified passkey) approves an intent: recorded as Taylor, at presence", w, await passkeySigned(STAKES, w.passkey, challengeOf)); }
  { const w = await world(); await add("PASS-P02", "positive", [], "an ordinary message signed by Taylor's registered browser key: recorded as the browser, for Taylor, at device", w, await deviceSigned("message", w.browser)); }
  { const w = await world(); const e = await passkeySigned("message", w.passkey, challengeOf); await add("PASS-P03", "positive", [], "an ordinary message with Taylor's finger", w, e); }
  {
    const w = await world({ switchedAt: "2026-10-24T00:00:00Z" });
    const e = await deviceSigned("message", w.browser, { order: Date.parse("2026-10-23T12:00:00Z") * 1000 });
    await add("PASS-P04", "positive", ["legacy"], "a browser-signed message stored before the switch: still valid, read as the browser's, at device", w, e);
  }
  {
    const w = await world({ switchedAt: "2026-10-24T00:00:00Z", register: false, pin: false });
    const e = await deviceSigned(STAKES, w.browser, { order: Date.parse("2026-10-23T12:00:00Z") * 1000 });
    await add("PASS-P05", "positive", ["legacy"], "a browser-signed high-stakes act stored before the switch, when no passkey existed: read at device", w, e);
  }
  {
    const w = await world({ register: false });
    const pk = w.passkey; const id = "reg-first", sentence = SENTENCES["register-passkey"];
    const reg = pk.register(await lib.registrationChallenge(id, ME, sentence));
    const e = stored({ id, conversation: "c-test", product: "chat-app", kind: "passkey-registered", data: { party: ME, sentence, ...reg } });
    await add("PASS-P06", "positive", [], "the first passkey, approved by the local step (its credential id is pinned) and made with a user-verified ceremony bound to this registration", w, e, undefined, { mode: "ingest" });
  }
  {
    const w = await world();
    const second = detPasskey("taylor-second-passkey", {});
    const id = "reg-second", sentence = SENTENCES["register-passkey"];
    const base = { party: ME, sentence, ...second.register(await lib.registrationChallenge(id, ME, sentence)) };
    const assertion = w.passkey.assert(await lib.actChallenge(id, "c-test", base));
    const e = stored({ id, conversation: "c-test", product: "chat-app", kind: "passkey-registered", data: { ...base, signature: { alg: "webauthn-es256", ...assertion } } });
    await add("PASS-P07", "positive", [], "a second passkey, added with an existing passkey's user-verified assertion over exactly this registration", w, e, undefined, { mode: "ingest" });
  }
  // ---------------- turn 7 probes ----------------
  { const w = await world(); await add("PASS-N-P1", "negative", ["P1"], "code in the chat page signs a high-stakes act with the browser's key alone", w, await deviceSigned(STAKES, w.browser)); }
  { const w = await world(); await add("PASS-N-P2a", "negative", ["P2"], "a program driving the page clicks Approve: only an unsigned act, run by an operating-system account", w, unsigned(STAKES), undefined, { ctx: { osAccount: "account1", device: "mac" } }); }
  { const w = await world(); await add("PASS-N-P2b", "negative", ["P2"], "an unsigned act with no context at all", w, unsigned(STAKES)); }
  { const w = await world(); await add("PASS-N-P3", "negative", ["P3"], "a passkey signature with presence but without user verification (no Touch ID)", w, await passkeySigned(STAKES, w.passkey.withoutUserVerification(), challengeOf)); }
  {
    const w = await world();
    const earlier = await passkeySigned("message", w.passkey, challengeOf, { id: "earlier-act" });
    const signature = earlier.data.signature;
    const fresh = stored({ id: "new-act", conversation: earlier.conversation, product: "chat-app", kind: "signed-act", data: { ...signedActData(STAKES), signature } });
    await add("PASS-N-P4", "negative", ["P4", "cross-use"], "a valid earlier passkey signature attached to a new act", w, fresh);
  }
  {
    const w = await world();
    const a = await passkeySigned("message", w.passkey, challengeOf, { id: "act-a", sentence: "Say hello." });
    await add("PASS-N-P5", "negative", ["P5", "cross-use"], "the page shows act A, the signature covers act A, act B is submitted with it", w, withData(a, { actKind: STAKES, sentence: SENTENCES[STAKES] }));
  }
  {
    const w = await world(); let n = 0;
    for (const party of ["person:Me", "person:mе", "person:me ", "person:ME"]) {
      const withKind = n++;
      await add(`PASS-N-P8${String.fromCharCode(97 + withKind * 2)}`, "negative", ["P8"], `a validly signed passkey act whose party is the look-alike ${JSON.stringify(party)}`, w, await passkeySigned(STAKES, w.passkey, challengeOf, { party }));
      await add(`PASS-N-P8${String.fromCharCode(98 + withKind * 2)}`, "negative", ["P8"], `a validly signed browser-key act whose party is the look-alike ${JSON.stringify(party)}`, w, await deviceSigned("message", w.browser, { party }));
    }
  }
  { const w = await world(); await add("PASS-N-P12a", "negative", ["P12"], "a passkey nobody registered, with user verification, claims to be Taylor", w, await passkeySigned(STAKES, w.stranger, challengeOf)); }
  {
    const you = detPasskey("other-persons-passkey");
    const w = await world({ alsoPin: [you.credentialId] });
    const id = "reg-you", sentence = SENTENCES["register-passkey"];
    const reg = you.register(await lib.registrationChallenge(id, "person:you", sentence));
    await w.ingest(stored({ id, conversation: "c-test", product: "chat-app", kind: "passkey-registered", data: { party: "person:you", sentence, ...reg } }));
    await add("PASS-N-P12b", "negative", ["P12"], "another person's registered passkey, with user verification, claims to be Taylor", w, await passkeySigned(STAKES, you, challengeOf));
  }
  { const w = await world(); await add("PASS-N-P6", "negative", ["P6"], "an agent's key publishes an approval for Taylor", w, await deviceSigned(STAKES, w.agent, { party: ME, product: "unharness", machine: "pm-worker" })); }
  {
    const w = await world(); const attacker = detPasskey("attacker-passkey");
    const id = "reg-attacker", sentence = SENTENCES["register-passkey"];
    const reg = attacker.register(await lib.registrationChallenge(id, ME, sentence));
    const e = stored({ id, conversation: "c-test", product: "unharness", kind: "passkey-registered", machine: "pm-worker", data: { party: ME, sentence, ...reg } });
    await add("PASS-N-P7", "negative", ["P7", "enrolled-by-anything-but-a-passkey"], "an agent registers a passkey of its own for Taylor", w, e, undefined, { mode: "ingest" });
  }
  {
    const w = await world({ register: false, pin: false }); const unpinned = detPasskey("unpinned-first-passkey");
    const id = "reg-unpinned", sentence = SENTENCES["register-passkey"];
    const reg = unpinned.register(await lib.registrationChallenge(id, ME, sentence));
    const e = stored({ id, conversation: "c-test", product: "chat-app", kind: "passkey-registered", data: { party: ME, sentence, ...reg } });
    await add("PASS-N-K1", "negative", ["enrolled-by-anything-but-a-passkey"], "a first passkey published through the chat page and never approved by the local step: a creation ceremony alone proves nothing", w, e, undefined, { mode: "ingest" });
  }
  {
    const w = await world();
    const e = await deviceSigned("enroll-device", w.browser, { subject: "U" + "C".repeat(55) });
    await add("PASS-N-K2", "negative", ["enrolled-by-anything-but-a-passkey"], "adding a device signed by a browser key alone (not a finger)", w, e);
  }
  {
    const w = await world();
    const attacker = await deviceKey("passkey-act/attacker-browser", lib.keyIdFor);
    const reg = deviceKeyEvent(attacker, ME, "chat-app", "attacker-browser", BROWSER_PUBLISHER);
    const first = await w.verifier.registerDeviceKey(reg);
    const e = await deviceSigned("message", attacker);
    const { v, policy } = await judge(w, e);
    P("PASS-N-K3", { kind: "negative", tags: ["enrolled-by-anything-but-a-passkey", "divergence:enrolled-by-anything-but-a-passkey"], about: "a device-key registration for Taylor published as the chat app, with no passkey involved: today the verifier remembers the key, and what it signs is accepted as the browser's, for Taylor", input: { context: w.context, events: dump([...w.events, reg]), act: dump(e), mode: "verify" }, policy, expected: refused("not-enrolled-by-passkey"), today: { registrationRemembered: first, ...v, note: NOTE } });
  }
  {
    const w = await world();
    const attacker = await deviceKey("passkey-act/agent-registered-for-taylor", lib.keyIdFor);
    const reg = deviceKeyEvent(attacker, ME, "unharness", "pm-worker");
    const remembered = await w.verifier.registerDeviceKey(reg);
    P("PASS-N-K4", { kind: "negative", tags: ["enrolled-by-anything-but-a-passkey"], about: "a device key for Taylor published by an agent's product", input: { context: w.context, events: dump([...w.events, reg]) }, policy: [], expected: refused("wrong-product"), today: { registrationRemembered: remembered } });
  }
  // ---------------- one thing wrong in an otherwise good assertion ----------------
  { const w = await world(); await add("PASS-N-W1", "negative", [], "an assertion made for another site's origin", w, await craftedAct(STAKES, w.passkey, {}, { origin: "https://evil.example" })); }
  { const w = await world(); await add("PASS-N-W2", "negative", [], "an assertion made for another relying party id", w, await craftedAct(STAKES, w.passkey, {}, { rpId: "evil.example" })); }
  { const w = await world(); await add("PASS-N-W3", "negative", [], "client data of the wrong type (a creation, not an assertion)", w, await craftedAct(STAKES, w.passkey, {}, { type: "webauthn.create" })); }
  { const w = await world(); await add("PASS-N-W4", "negative", [], "the user-present flag is off", w, await craftedAct(STAKES, w.passkey, {}, { flags: 0x04 })); }
  { const w = await world(); const otherData = signedActData(STAKES, { sentence: "Something else entirely." }); const id = "act-w5", conversation = "c-test"; const data = signedActData(STAKES); const a = craft(w.passkey, await challengeOf(id, conversation, otherData)); await add("PASS-N-W5", "negative", [], "an assertion over the challenge of different words than the act carries", w, stored({ id, conversation, product: "chat-app", kind: "signed-act", data: { ...data, signature: passkeySignature(a) } })); }
  return { skipped: vecSkipped };
}
