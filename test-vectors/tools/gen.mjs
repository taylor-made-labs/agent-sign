// Step 0 vector generator. Run on the agents host: LEGACY_ROOT=<folder with the four checkouts> OUT=<dir> node gen.mjs
// It loads today's signing code from the checkouts, builds records with public-label test keys, runs today's checks on
// them, and writes one JSON file per vector plus manifest.json. Nothing here is the consolidated implementation.
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { startPython, stopPython, vectors, writeAll, OUT, imp, ed, p256, nkeyUser } from "./lib.mjs";
import { encodingFamily } from "./fam-encoding.mjs";
import { namesFamily } from "./fam-names.mjs";
import { deviceFamily } from "./fam-device.mjs";
import { publisherFamily } from "./fam-publisher.mjs";
import { teamFamily } from "./fam-team.mjs";
import { actFamily } from "./fam-act.mjs";
import { approvalFamily } from "./fam-approval.mjs";
import { logFamily } from "./fam-log.mjs";
import { recordFamily } from "./fam-record.mjs";
import { crossFamily } from "./fam-cross.mjs";
import { passkeyFamily, unanswered } from "./fam-passkey.mjs";

const here = new URL(".", import.meta.url).pathname;
startPython(join(here, "legacy_py.py"));
const answersFile = process.env.POLICY_ANSWERS ?? join(here, "policy-answers.json");
await encodingFamily();
await namesFamily();
await deviceFamily();
await publisherFamily();
await teamFamily();
await actFamily();
await approvalFamily();
await logFamily();
await recordFamily();
await crossFamily();
const pk = await passkeyFamily(answersFile);
stopPython();
mkdirSync(OUT, { recursive: true });
if (unanswered.size > 0) {
  writeFileSync(join(OUT, "policy-questions.json"), JSON.stringify([...unanswered.values()], null, 1));
  console.log(`NEED-ANSWERS ${unanswered.size} (written to policy-questions.json); skipped: ${pk.skipped.join(",")}`);
  process.exit(3);
}
// does today's code already do what the consolidated checker must? (false = a divergence to fix, kept as a vector)
function agrees(v) {
  const t = v.today ?? {}, want = v.expected.result;
  const acc = want === "accepted" || want === "encoded";
  switch (v.family) {
    case "device-es256": return "ring" in t ? (t.ring === "valid") === acc : "registered" in t ? t.registered === acc : false;
    case "stream-publisher": case "team-record": return (t.accepted ?? t.passed) === acc;
    case "act-v1": return "counts" in t ? t.counts === acc : t.python === "refuses to sign" && t.typescriptPort === "refuses";
    case "approval-v2": return (t.outcome === "approved") === acc;
    case "log-chain": return t.ok === acc;
    case "record-ns": return (t.problem === "none") === acc;
    case "cross-use": return /^(refused|outcome denied)/.test(t.check);
    case "passkey-act": return "registrationRemembered" in t ? (t.registrationRemembered === acc && (t.status === undefined || (t.status === "accepted") === acc)) : (t.status === "accepted") === acc;
    case "names": return (t.result === "accepted") === acc;
    case "encoding": { const rs = Object.values(t.encoders); return acc ? rs.every((r) => r.bytes === v.expected.bytes) : rs.every((r) => r.bytes === undefined); }
  }
}
for (const v of vectors) v.today = { ...v.today, agreesWithExpected: agrees(v) };
writeAll(OUT);
const count = (f) => vectors.filter(f).length;
const families = [...new Set(vectors.map((v) => v.family))];
const manifest = {
  schema: "agent-sign-test-vectors/1",
  total: vectors.length, todayDisagrees: vectors.filter((v) => !v.today.agreesWithExpected).length, positive: count((v) => v.kind === "positive"), negative: count((v) => v.kind === "negative"),
  byFamily: Object.fromEntries(families.map((f) => [f, { positive: count((v) => v.family === f && v.kind === "positive"), negative: count((v) => v.family === f && v.kind === "negative") }])),
  vectors: vectors.map((v) => ({ id: v.id, family: v.family, legacy: v.legacy, kind: v.kind, tags: v.tags, file: `vectors/${v.family}/${v.id}.json`, sha256: createHash("sha256").update(readFileSync(join(OUT, "vectors", v.family, v.id + ".json"))).digest("hex") })),
};
writeFileSync(join(OUT, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(JSON.stringify({ total: manifest.total, positive: manifest.positive, negative: manifest.negative, byFamily: manifest.byFamily }));
