// Family "record-ns": the model layer's signed records (unharness listeners/src/model-layer/signing.ts, added after the
// plan): Ed25519 over "suite-record" + a zero byte + canonical {"type", "payload"}, with an authority-signed
// certificate per identity. The check is recordSignatureProblem.
import { imp, vec, ed, edSign } from "./lib.mjs";

export async function recordFamily() {
  const ml = await imp("unharness/listeners/src/model-layer/signing.ts");
  const authority = ed("record-ns/authority"), rogue = ed("record-ns/rogue-authority"), who = ed("record-ns/requester"), other = ed("record-ns/approver");
  const NOW = Date.parse("2026-10-31T12:00:00Z");
  const auth = { id: "authority-1", publicKey: authority.spkiB64 };
  const certBody = (c) => Buffer.from(`suite-certificate\n${ml.canonicalJson({ identity: c.identity, publicKey: c.publicKey, notBefore: c.notBefore, notAfter: c.notAfter, authority: c.authority })}`, "utf8");
  const cert = (identity, k, o = {}, issuer = authority) => { const c = { identity, publicKey: k.spkiB64, notBefore: "2026-10-31T11:00:00Z", notAfter: "2026-10-31T23:00:00Z", authority: "authority-1", ...o }; return { ...c, signature: edSign(issuer, certBody(c)).toString("base64") }; };
  const sig = (identity, k, type, payload, o = {}) => ({ identity, namespace: "suite-record", format: "ed25519", signature: edSign(k, Buffer.concat([Buffer.from("suite-record\0"), Buffer.from(ml.canonicalRecord(type, payload), "utf8")])).toString("base64"), certificate: cert(identity, k), ...o });
  const payload = { id: "ev-1", envelope: { conversation: "c-1", turn: "t-1", causes: null, machine: "mac" }, data: { tool: "read", run: "run-1" } };
  const check = (s, type, p, identity = "id:requester", authorities = [auth]) => ml.recordSignatureProblem(s, type, p, { authorities, identity, now: NOW }) ?? "none";
  const R = (id, o) => vec({ id, family: "record-ns", legacy: "L13", ...o });
  const I = (s, type, p, extra = {}) => ({ signature: s, type, payload: p, identity: "id:requester", authorities: [auth], now: NOW, ...extra });
  const ok = { result: "accepted", signer: "agent:id:requester", onBehalfOf: "agent:id:requester", strength: "agent" };
  const no = (reason) => ({ result: "refused", reason });
  const s0 = sig("id:requester", who, "tool-use-requested", payload);
  R("REC-P01", { kind: "positive", tags: [], about: "a request signed by its identity, with a certificate from a trusted authority", input: I(s0, "tool-use-requested", payload), expected: ok, today: { problem: check(s0, "tool-use-requested", payload) } });
  const p2 = { ...payload, data: { ...payload.data, tool: "write" } };
  R("REC-N01", { kind: "negative", tags: [], about: "the data was changed after signing", input: I(s0, "tool-use-requested", p2), expected: no("bad-signature"), today: { problem: check(s0, "tool-use-requested", p2) } });
  R("REC-N02", { kind: "negative", tags: ["cross-use"], about: "a signature for a request presented as an approval (the type is inside what is signed)", input: I(s0, "tool-use-approved", payload), expected: no("bad-signature"), today: { problem: check(s0, "tool-use-approved", payload) } });
  const pId = { ...payload, id: "ev-2" };
  R("REC-N03", { kind: "negative", tags: ["cross-use"], about: "the same signature under another event id", input: I(s0, "tool-use-requested", pId), expected: no("bad-signature"), today: { problem: check(s0, "tool-use-requested", pId) } });
  const sWrong = sig("id:approver", other, "tool-use-requested", payload);
  R("REC-N04", { kind: "negative", tags: [], about: "signed by another identity than the one whose act it is", input: I(sWrong, "tool-use-requested", payload), expected: no("wrong-identity"), today: { problem: check(sWrong, "tool-use-requested", payload) } });
  const sRogue = { ...sig("id:requester", who, "tool-use-requested", payload), certificate: cert("id:requester", who, {}, rogue) };
  R("REC-N05", { kind: "negative", tags: [], about: "a certificate signed by an authority nobody trusts", input: I(sRogue, "tool-use-requested", payload), expected: no("untrusted-authority"), today: { problem: check(sRogue, "tool-use-requested", payload) } });
  const sOld = { ...sig("id:requester", who, "tool-use-requested", payload), certificate: cert("id:requester", who, { notAfter: "2026-10-31T11:30:00Z" }) };
  R("REC-N06", { kind: "negative", tags: [], about: "an expired certificate", input: I(sOld, "tool-use-requested", payload), expected: no("expired"), today: { problem: check(sOld, "tool-use-requested", payload) } });
  const sGit = { ...s0, namespace: "git" };
  R("REC-N07", { kind: "negative", tags: ["cross-use"], about: "a signature claiming the git namespace: a record signature must never pass as a commit signature, nor the reverse", input: I(sGit, "tool-use-requested", payload), expected: no("wrong-namespace"), today: { problem: check(sGit, "tool-use-requested", payload) } });
  R("REC-N08", { kind: "negative", tags: [], about: "no signature", input: I(undefined, "tool-use-requested", payload), expected: no("unsigned"), today: { problem: check(undefined, "tool-use-requested", payload) } });
  const sCertMismatch = { ...s0, certificate: cert("id:approver", other) };
  R("REC-N09", { kind: "negative", tags: [], about: "another identity's certificate attached to the signature", input: I(sCertMismatch, "tool-use-requested", payload), expected: no("wrong-identity"), today: { problem: check(sCertMismatch, "tool-use-requested", payload) } });
  return { s0, payload, auth };
}
