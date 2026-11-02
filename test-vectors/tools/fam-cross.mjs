// Family "cross-use": one key signs three different things (the way a service's NATS key signs both its stream events and
// its acts): a stream event, an ntaild act and an approval answer. Each signature is then offered to the other two
// checks. All six must be refused: a signature made for one use never passes as another.
import { imp, vec, nkeyUser, edSign, pyCall, b64u } from "./lib.mjs";

export async function crossFamily(ctx) {
  const pub = await imp("unharness/src/publisher.ts");
  const rl = await imp("agentic-credentials/src/approvals/relay.ts");
  const ac = await imp("agentic-credentials/src/entitlement/acts.ts");
  const k = nkeyUser("cross-use/one-key-for-three-uses");
  const pk = pub.publisherKey(k.seedBytes);
  const subject = "ev.unharness.run-started.mac";
  const headers = { "ce-id": "ev-9", "ce-type": "suite.unharness.run-started", "ce-source": "unharness/mac", "ce-time": "2026-10-23T12:00:00.000Z" };
  const body = JSON.stringify({ run: "run-9" });
  const streamSigB64u = pub.signEvent(pk, subject, headers, body)["suite-publisher-signature"];
  const keyId = "k-svc#1", party = "agent:svc";
  const act = { id: "a9", kind: "assert", party, domain: "suite:test", seq: 9, claims: [["_:self", "rdf:type", "ex:Thing"]] };
  const actSigned = ac.signAct(act, { party, keyId, privateKey: k.privateKey, publicB64: k.rawB64 });
  const NOW = 1_800_000_000;
  const req = { accessor: "acc-9", path: "secret/data/x", operation: "read", requester: party };
  const content = { ...req, requestHash: rl.requestHash(req) };
  const q = { id: "q-9", accessor: "acc-9", content, contentHash: rl.ApprovalRelay.contentHash(content), choices: ["approve", "deny"], expiresAt: NOW + 300 };
  const aBase = { questionId: q.id, accessor: q.accessor, requestPath: content.path, operation: content.operation, requestHash: content.requestHash, contentHash: q.contentHash, choice: "approve", expiresAt: q.expiresAt };
  const approvalSig = edSign(k, rl.answerPayload(aBase)).toString("base64");
  const relay = new rl.ApprovalRelay({ channel: { present: async () => "couldnt-ask", cancel() {} }, personDeviceKey: k.publicKey, lookup: async () => { throw 0; }, authorize: async () => true, now: () => NOW });
  const R = { parties: { [party]: { person: false, keys: [{ id: keyId, ed25519: k.rawB64 }] } } };
  const reg = { unsignedThrough: 0, publishers: [{ publicKey: k.publicText, product: "unharness" }] };
  const sigs = { stream: streamSigB64u, act: actSigned.sig.ed25519, approval: approvalSig };
  const asB64u = (s) => b64u(Buffer.from(s, "base64"));
  // the three checks, each given a signature that was made for another use
  const checkAct = async (sigB64) => { const a = { ...act, sig: { key: keyId, ed25519: sigB64 } }; const r = await pyCall({ op: "check_act", act: a, registry: R }); return r.counts ? "accepted" : `refused (${r.ignored})`; };
  const checkStream = (sigB64u) => { const h = { ...headers, "suite-publisher-key": k.publicText, "suite-publisher-signature": sigB64u }; const j = pub.judgePublisher(reg, subject, (n) => h[n], body, 5, new Date("2026-10-23T12:00:01Z")); return j.problem === undefined ? "accepted" : `refused (${j.reason})`; };
  const checkApproval = (sigB64) => `outcome ${relay.check(q, { ...aBase, signature: sigB64 })}`;
  const pairs = [
    ["stream", "act", "a stream-event signature offered as the signature on an act", async () => checkAct(sigs.stream && b64Std(sigs.stream))],
    ["approval", "act", "an approval answer's signature offered as the signature on an act", async () => checkAct(sigs.approval)],
    ["act", "stream", "an act's signature offered as the signature on a stream event", async () => checkStream(asB64u(sigs.act))],
    ["approval", "stream", "an approval answer's signature offered as the signature on a stream event", async () => checkStream(asB64u(sigs.approval))],
    ["act", "approval", "an act's signature offered as an approval answer's signature", async () => checkApproval(sigs.act)],
    ["stream", "approval", "a stream-event signature offered as an approval answer's signature", async () => checkApproval(b64Std(sigs.stream))],
  ];
  function b64Std(u) { return Buffer.from(u, "base64url").toString("base64"); }
  // sanity: each signature is accepted by its own check
  const own = { act: await checkAct(sigs.act), stream: checkStream(sigs.stream), approval: checkApproval(sigs.approval) };
  let n = 0;
  for (const [from, to, about, f] of pairs) {
    vec({
      id: `CROSS-N${String(++n).padStart(2, "0")}`, family: "cross-use", legacy: "L04 L06 L09 L10", kind: "negative", tags: ["cross-use"],
      about: `one key, three uses: ${about}`,
      input: { key: { nkey: k.publicText, rawB64: k.rawB64 }, madeFor: from, offeredAs: to, signatures: { streamEventB64u: sigs.stream, actB64: sigs.act, approvalB64: sigs.approval }, stream: { subject, headers, body, registry: reg }, act, approval: { question: q, answer: aBase, now: NOW }, registry: R },
      expected: { result: "refused", reason: "wrong-context" },
      today: { check: await f(), eachOwnCheck: own },
    });
  }
}
