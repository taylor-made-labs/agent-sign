// Family "act-v1": ntaild's signed acts (Ed25519 over "ntaild-act-v1\n" + canonical JSON), made by four pieces of code:
// ntaild's own (acts.py), its reviewer, and agentic-credentials' port and warrant tool. The check is ntaild's.
import { imp, vec, ed, edSign, pyCall, hex, nkeyUser } from "./lib.mjs";

export async function actFamily() {
  const ac = await imp("agentic-credentials/src/entitlement/acts.ts");
  const admin = await imp("agentic-credentials/src/admin/acts.ts");
  const key = (label) => ed(label);
  const me = "person:me";
  const keys = { me: key("act-v1/person-me"), me2: key("act-v1/person-me-second"), a1: key("act-v1/agent-a1"), a2: key("act-v1/agent-a2"), atk: key("act-v1/attacker") };
  const reg = (spec) => ({ parties: Object.fromEntries(Object.entries(spec).map(([p, [person, ...ks]]) => [p, { person, keys: ks.map(([id, k]) => ({ id, ed25519: k.rawB64 })) }])) });
  const R = reg({ [me]: [true, ["k-me#1", keys.me]], "agent:a1": [false, ["k-a1#1", keys.a1]], "agent:a2": [false, ["k-a2#1", keys.a2]] });
  const act = (o = {}) => ({ id: "a1", kind: "assert", party: me, domain: "suite:test", seq: 1, claims: [["_:self", "rdf:type", "ex:Thing"]], ...o });
  const signPy = async (a, k, keyId) => (await pyCall({ op: "sign_act", act: a, label: k.label, key_id: keyId })).act;
  const check = async (a, registry = R) => { const r = await pyCall({ op: "check_act", act: a, registry }); return r.counts ? { counts: true } : { counts: false, reason: r.ignored }; };
  const ok = (party, person) => ({ result: "accepted", signer: `key:${party}`, onBehalfOf: party, strength: "registry-key", person });
  const no = (reason) => ({ result: "refused", reason });
  const A = (id, o) => vec({ id, family: "act-v1", ...o });

  const aMe = await signPy(act(), keys.me, "k-me#1");
  A("ACT-P01", { legacy: "L06", kind: "positive", tags: [], about: "a person's act signed by the first key in the registry", input: { act: aMe, registry: R }, expected: ok(me, true), today: await check(aMe) });
  const aAg = await signPy(act({ id: "a2", party: "agent:a1", seq: 1 }), keys.a1, "k-a1#1");
  A("ACT-P02", { legacy: "L06", kind: "positive", tags: [], about: "an agent's act signed by its first key", input: { act: aAg, registry: R }, expected: ok("agent:a1", false), today: await check(aAg) });
  // the TypeScript port signs; the Python check counts it
  const tsKey = (k, party, keyId) => ({ party, keyId, privateKey: k.privateKey, publicB64: k.rawB64 });
  const tsReq = ac.signAct(ac.requestAct({ party: "agent:a1", id: "r1", seq: 5, task: "task:model-call", scope: ac.secretScope("svc/mac/key") }), tsKey(keys.a1, "agent:a1", "k-a1#1"));
  A("ACT-P03", { legacy: "L09", kind: "positive", tags: ["cross-implementation"], about: "an agent's request signed by the TypeScript port, counted by the Python check", input: { act: tsReq, registry: R }, expected: ok("agent:a1", false), today: await check(tsReq) });
  const pem = keys.me.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const unsignedW = admin.unsignedWarrant({ party: me, keyId: "k-me#1", holder: "agent:a1", scope: ["sc:secret:svc/mac/key/read"], task: "task:model-call", days: 7, id: "w-1", seq: 6, now: Date.parse("2026-10-23T12:00:00Z") });
  const warrant = admin.signWarrantAct(pem, "k-me#1", unsignedW);
  A("ACT-P04", { legacy: "L11", kind: "positive", tags: ["cross-implementation"], about: "a warrant made by the warrant tool's code, counted by the Python check", input: { act: warrant, registry: R }, expected: ok(me, true), today: await check(warrant) });
  // reviewer: ntaild's Reviewer signs through acts.sign_act; same code path as ACT-P01 with the reviewer's domain
  const rv = await signPy({ id: "a0", party: "agent:a2", domain: "suite:review", seq: 0, kind: "assert", claims: [["_:self", "rv:approves", "ev:x"]] }, keys.a2, "k-a2#1");
  A("ACT-P05", { legacy: "L08", kind: "positive", tags: [], about: "a reviewer's act (the review domain), signed with the reviewer's in-memory key", input: { act: rv, registry: R }, expected: ok("agent:a2", false), today: await check(rv) });
  // negatives
  const aOther = await signPy(act(), keys.atk, "k-me#1");
  A("ACT-N01", { legacy: "L06", kind: "negative", tags: [], about: "the person's act signed with someone else's key under the person's key id", input: { act: aOther, registry: R }, expected: no("bad-signature"), today: await check(aOther) });
  const R2 = reg({ [me]: [true, ["k-me#1", keys.me], ["k-me#2", keys.me2]] });
  const aSecond = await signPy(act(), keys.me2, "k-me#2");
  A("ACT-N02", { legacy: "L06", kind: "negative", tags: ["divergence:first-key-wins"], about: "signed by the person's second registered key: only the first key counts today", input: { act: aSecond, registry: R2 }, expected: no("not-the-enrolled-key"), today: await check(aSecond, R2) });
  const aUnknown = await signPy(act({ party: "agent:nobody" }), keys.atk, "k-x#1");
  A("ACT-N03", { legacy: "L06", kind: "negative", tags: [], about: "a party the registry does not know", input: { act: aUnknown, registry: R }, expected: no("unknown-party"), today: await check(aUnknown) });
  const aTamper = { ...aMe, claims: [["_:self", "rdf:type", "ex:Other"]] };
  A("ACT-N04", { legacy: "L06", kind: "negative", tags: [], about: "the claims changed after signing", input: { act: aTamper, registry: R }, expected: no("bad-signature"), today: await check(aTamper) });
  const { sig: _s, ...aUns } = aMe;
  A("ACT-N05", { legacy: "L06", kind: "negative", tags: [], about: "no signature", input: { act: aUns, registry: R }, expected: no("unsigned"), today: await check(aUns) });
  const aSeqBig = await signPy(act({ seq: 2 ** 60 }), keys.me, "k-me#1");
  A("ACT-N06", { legacy: "L06 L09", kind: "negative", tags: ["divergence:large-integer"], about: "a sequence number of 2^60: Python signs and counts it, the TypeScript port cannot encode it", input: { act: aSeqBig, registry: R }, expected: no("unsafe-integer"), today: { ...(await check(aSeqBig)), typescriptPort: (() => { try { ac.signingPayload(aSeqBig); return "encodes"; } catch { return "refuses"; } })() } });
  const aFloat = { ...act(), claims: [["_:self", "ex:weight", { lit: 1.5 }]] };
  const pf = await pyCall({ op: "sign_act", act: aFloat, label: keys.me.label, key_id: "k-me#1" });
  A("ACT-N07", { legacy: "L06 L09", kind: "negative", tags: ["divergence:float"], about: "a fraction inside a claim: neither side can sign it", input: { act: aFloat, registry: R }, expected: no("non-integer-number"), today: { python: pf.error ? "refuses to sign" : "signs", typescriptPort: (() => { try { ac.signingPayload(aFloat); return "encodes"; } catch { return "refuses"; } })() } });
  const aSur = act({ text: "x\ud800y" });
  const ps = await pyCall({ op: "sign_act", act: aSur, label: keys.me.label, key_id: "k-me#1" });
  const tsEnc = (() => { try { ac.signingPayload(aSur); return "encodes"; } catch { return "refuses"; } })();
  A("ACT-N08", { legacy: "L06 L09", kind: "negative", tags: ["divergence:lone-surrogate"], about: "text holding a lone surrogate: the Python encoder cannot write it, the TypeScript one escapes it", input: { act: aSur, registry: R }, expected: no("lone-surrogate"), today: { python: ps.error ? "refuses to sign" : "signs", typescriptPort: tsEnc } });
  const Ratk = reg({ [me]: [true, ["k-me#1", keys.atk]] });
  const aAtk = await signPy(act(), keys.atk, "k-me#1");
  A("ACT-N09", { legacy: "L06", kind: "negative", tags: ["divergence:enrolled-by-anything-but-a-passkey"], about: "a registry that lists the attacker's key as the person's first key: the check counts what that key signs as the person's", input: { act: aAtk, registry: Ratk, enrolledBy: "caller-supplied registry" }, expected: no("not-enrolled-by-passkey"), today: await check(aAtk, Ratk) });
  const aDomain = await signPy(act({ domain: "" }), keys.me, "k-me#1");
  A("ACT-N10", { legacy: "L06", kind: "negative", tags: [], about: "an empty domain", input: { act: aDomain, registry: R }, expected: no("malformed"), today: await check(aDomain) });
  return { keys, R, aMe, warrant, tsReq };
}
