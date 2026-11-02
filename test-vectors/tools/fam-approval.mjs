// Family "approval-v2": the person's signed answer to "may this credential be used?" (agentic-credentials
// src/approvals/relay.ts): Ed25519 over canonical JSON tagged v: "ac-approval-v2", checked against one device key.
import { imp, vec, ed, edSign } from "./lib.mjs";

export async function approvalFamily() {
  const rl = await imp("agentic-credentials/src/approvals/relay.ts");
  const device = ed("approval-v2/person-device"), other = ed("approval-v2/other-device");
  const NOW = 1_800_000_000;
  const relay = (key = device) => new rl.ApprovalRelay({ channel: { present: async () => "couldnt-ask", cancel() {} }, personDeviceKey: key.publicKey, lookup: async () => { throw new Error("unused"); }, authorize: async () => true, now: () => NOW });
  const req = { accessor: "acc-1", path: "secret/data/svc/mac/key", operation: "read", requester: "agent:a1" };
  const content = { ...req, requestHash: rl.requestHash(req) };
  const q = { id: "q-1", accessor: "acc-1", content, contentHash: rl.ApprovalRelay.contentHash(content), choices: ["approve", "deny"], expiresAt: NOW + 300 };
  const answer = (o = {}, k = device) => {
    const a = { questionId: q.id, accessor: q.accessor, requestPath: content.path, operation: content.operation, requestHash: content.requestHash, contentHash: q.contentHash, choice: "approve", expiresAt: q.expiresAt, ...o };
    return { ...a, signature: edSign(k, rl.answerPayload(a)).toString("base64") };
  };
  const run = (a, question = q, key = device) => relay(key).check(question, a);
  const A = (id, o) => vec({ id, family: "approval-v2", legacy: "L10", ...o });
  const pub = (k) => k.spkiB64;
  const ok = { result: "accepted", signer: "device:person-device", onBehalfOf: "person:me", strength: "device" };
  const no = (reason) => ({ result: "refused", reason });
  const I = (a, extra = {}) => ({ question: q, answer: a, deviceKeySpkiB64: pub(device), now: NOW, ...extra });
  const a0 = answer();
  A("APP-P01", { kind: "positive", tags: [], about: "an approve answer for this exact question, signed by the configured device key", input: I(a0), expected: ok, today: { outcome: run(a0) } });
  const aDeny = answer({ choice: "deny" });
  A("APP-N01", { kind: "negative", tags: [], about: "a signed deny is a denial", input: I(aDeny), expected: no("denied"), today: { outcome: run(aDeny) } });
  const aOtherKey = answer({}, other);
  A("APP-N02", { kind: "negative", tags: [], about: "signed by a key that is not the configured device key", input: I(aOtherKey), expected: no("bad-signature"), today: { outcome: run(aOtherKey) } });
  const aQ = answer({ questionId: "q-other" });
  A("APP-N03", { kind: "negative", tags: ["cross-use"], about: "an answer to another question", input: I(aQ), expected: no("wrong-question"), today: { outcome: run(aQ) } });
  const aAcc = answer({ accessor: "acc-2" });
  A("APP-N04", { kind: "negative", tags: ["cross-use"], about: "an answer naming another accessor", input: I(aAcc), expected: no("wrong-request"), today: { outcome: run(aAcc) } });
  const aPath = answer({ requestPath: "secret/data/other" });
  A("APP-N05", { kind: "negative", tags: [], about: "an answer naming another path", input: I(aPath), expected: no("wrong-request"), today: { outcome: run(aPath) } });
  const aHash = { ...a0, requestHash: "0".repeat(64) };
  A("APP-N06", { kind: "negative", tags: [], about: "the request hash was changed after signing", input: I(aHash), expected: no("wrong-request"), today: { outcome: run(aHash) } });
  A("APP-N07", { kind: "negative", tags: [], about: "after the question's expiry", input: I(a0, { now: NOW + 301 }), expected: no("expired"), today: { outcome: new rl.ApprovalRelay({ channel: { present: async () => "couldnt-ask", cancel() {} }, personDeviceKey: device.publicKey, lookup: async () => { throw 0; }, authorize: async () => true, now: () => NOW + 301 }).check(q, a0) } });
  const aSig = { ...a0, signature: Buffer.alloc(64).toString("base64") };
  A("APP-N08", { kind: "negative", tags: [], about: "a signature of zeros", input: I(aSig), expected: no("bad-signature"), today: { outcome: run(aSig) } });
  const aExp = answer({ expiresAt: q.expiresAt + 1000 });
  A("APP-N09", { kind: "negative", tags: [], about: "an answer that moved the expiry out", input: I(aExp), expected: no("wrong-request"), today: { outcome: run(aExp) } });
  return { device, q, a0, relay, answer };
}
