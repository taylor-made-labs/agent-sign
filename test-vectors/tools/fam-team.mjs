// Family "team-record": the signed commitments and review verdicts the team lead trusts (listeners/src/team-lead/signed.ts):
// Ed25519 over canonical JSON, no domain tag, keys from the deployment's trust lists.
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { imp, vec, ed, edSign } from "./lib.mjs";

export async function teamFamily() {
  const tl = await imp("unharness/listeners/src/team-lead/signed.ts");
  const taylor = ed("team-record/taylor-device"), reviewer = ed("team-record/reviewer-1"), stranger = ed("team-record/stranger");
  const trust = { taylor: { "dev-taylor-1": taylor.spkiPem }, reviewers: { "reviewer-1": reviewer.spkiPem } };
  const trustPublic = { taylor: { "dev-taylor-1": taylor.spkiB64 }, reviewers: { "reviewer-1": reviewer.spkiB64 } };
  const sha = (s) => createHash("sha256").update(s).digest("hex");
  const sign = (k, o) => edSign(k, Buffer.from(tl.canonical(o), "utf8")).toString("base64");
  const body = { rule: "merge when checks and review pass", checks: ["npm test"] };
  const hash = sha(tl.canonical(body));
  const entry = (o = {}) => { const e = { id: "suite:merge-rule", version: 1, body, hash, signedBy: "dev-taylor-1", ...o }; return { ...e, signature: o.signature ?? sign(taylor, { id: e.id, version: e.version, hash: e.hash }) }; };
  const loadC = (e, askedId = "suite:merge-rule", t = trust) => {
    const dir = mkdtempSync(join(tmpdir(), "tr-")); writeFileSync(join(dir, encodeURIComponent(askedId) + ".json"), JSON.stringify(e));
    const r = tl.loadCommitment(dir, t, askedId); rmSync(dir, { recursive: true }); return r.ok ? { accepted: true, signedBy: r.value.signedBy } : { accepted: false, why: r.why.replace(/\s*\(.*$/, "").slice(0, 90) };
  };
  const review = (o = {}, k = reviewer) => { const r = { change: "chg-1", commit: "abc123", verdict: "pass", reviewer: "reviewer-1", ...o }; return { ...r, signature: sign(k, { change: r.change, commit: r.commit, verdict: r.verdict, reviewer: r.reviewer }) }; };
  const state = (recs, change = "chg-1", commit = "abc123", t = trust) => {
    const dir = mkdtempSync(join(tmpdir(), "tr-")); recs.forEach((r, i) => writeFileSync(join(dir, `r${i}.json`), JSON.stringify(r)));
    const s = tl.reviewState(dir, t, change, commit); rmSync(dir, { recursive: true }); return { passed: s.passed, failed: s.failed, by: s.by };
  };
  const T = (id, o) => vec({ id, family: "team-record", legacy: "L05", ...o });
  const okC = { result: "accepted", signer: "device:dev-taylor-1", onBehalfOf: "person:me", strength: "device" };
  const noC = (reason) => ({ result: "refused", reason });
  const c0 = entry();
  T("TEAM-P01", { kind: "positive", tags: [], about: "a commitment signed by a key enrolled for Taylor", input: { op: "commitment", trust: trustPublic, askedId: "suite:merge-rule", entry: c0 }, expected: okC, today: loadC(c0) });
  const r0 = review();
  T("TEAM-P02", { kind: "positive", tags: [], about: "a pass by an enrolled reviewer for this change and commit", input: { op: "review", trust: trustPublic, change: "chg-1", commit: "abc123", records: [r0] }, expected: { result: "accepted", signer: "agent:reviewer-1", onBehalfOf: "agent:reviewer-1", strength: "agent" }, today: state([r0]) });
  const cS = entry({ signedBy: "dev-stranger", signature: sign(stranger, { id: "suite:merge-rule", version: 1, hash }) });
  T("TEAM-N01", { kind: "negative", tags: [], about: "signed by a key nobody enrolled for Taylor", input: { op: "commitment", trust: trustPublic, askedId: "suite:merge-rule", entry: cS }, expected: noC("key-not-enrolled"), today: loadC(cS) });
  const cE = { ...c0, body: { ...body, checks: [] } };
  T("TEAM-N02", { kind: "negative", tags: [], about: "the rule's body was edited after it was signed", input: { op: "commitment", trust: trustPublic, askedId: "suite:merge-rule", entry: cE }, expected: noC("content-changed"), today: loadC(cE) });
  T("TEAM-N03", { kind: "negative", tags: ["cross-use"], about: "an entry signed for one id presented as another", input: { op: "commitment", trust: trustPublic, askedId: "suite:merge-policy", entry: c0 }, expected: noC("wrong-id"), today: loadC(c0, "suite:merge-policy") });
  const cV = { ...c0, version: 2 };
  T("TEAM-N04", { kind: "negative", tags: [], about: "the version was raised without signing again", input: { op: "commitment", trust: trustPublic, askedId: "suite:merge-rule", entry: cV }, expected: noC("bad-signature"), today: loadC(cV) });
  const cR = entry({ signedBy: "reviewer-1", signature: sign(reviewer, { id: "suite:merge-rule", version: 1, hash }) });
  T("TEAM-N05", { kind: "negative", tags: ["cross-use"], about: "a reviewer's key signing the merge rule: reviewers are not Taylor", input: { op: "commitment", trust: trustPublic, askedId: "suite:merge-rule", entry: cR }, expected: noC("key-not-enrolled"), today: loadC(cR) });
  const rO = review({ commit: "zzz999" });
  T("TEAM-N06", { kind: "negative", tags: ["cross-use"], about: "a pass for another commit, offered for this one", input: { op: "review", trust: trustPublic, change: "chg-1", commit: "abc123", records: [rO] }, expected: { result: "refused", reason: "wrong-commit" }, today: state([rO]) });
  const rF = { ...review({ verdict: "fail" }), verdict: "pass" };
  T("TEAM-N07", { kind: "negative", tags: [], about: "a fail edited to pass", input: { op: "review", trust: trustPublic, change: "chg-1", commit: "abc123", records: [rF] }, expected: { result: "refused", reason: "bad-signature" }, today: state([rF]) });
  const rS = review({}, stranger);
  T("TEAM-N08", { kind: "negative", tags: [], about: "a pass signed by a key that is not the named reviewer's", input: { op: "review", trust: trustPublic, change: "chg-1", commit: "abc123", records: [rS] }, expected: { result: "refused", reason: "bad-signature" }, today: state([rS]) });
  const rT = review({ reviewer: "dev-taylor-1" }, taylor);
  T("TEAM-N09", { kind: "negative", tags: [], about: "Taylor's device key signing a review: only enrolled reviewers count", input: { op: "review", trust: trustPublic, change: "chg-1", commit: "abc123", records: [rT] }, expected: { result: "refused", reason: "not-a-reviewer" }, today: state([rT]) });
  return { trust, trustPublic, c0, r0, taylor, reviewer };
}
