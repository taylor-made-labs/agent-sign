// Indexes ntaild's conformance logs (synthetic, public-by-design, test keys): every file with its sha256, and for every act
// whether today's signature check counts it. Also lists the warrants in them. Content is test data and is not copied here.
// LEGACY_ROOT=<checkouts> node capture-ntaild.mjs <out.json> [<warrants-out.json>]
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, relative } from "node:path";
import { startPython, stopPython, pyCall, ROOT } from "./lib.mjs";
startPython(new URL("legacy_py.py", import.meta.url).pathname);
const dir = join(ROOT, "ntaild/conformance/logs");
const files = []; (function walk(d) { for (const n of readdirSync(d).sort()) { const p = join(d, n); statSync(p).isDirectory() ? walk(p) : n.endsWith(".json") && files.push(p); } })(dir);
const out = { about: "Index of ntaild's conformance logs (test data): per file, per act, does today's signature check count the act.", tool: "capture-ntaild.mjs", sumsFile: "conformance/logs/SHA256SUMS", files: [], totals: { files: 0, acts: 0, counted: 0, ignored: 0, warrants: 0, warrantsCounted: 0 } };
const sums = new Map(readFileSync(join(dir, "SHA256SUMS"), "utf8").trim().split("\n").map((l) => { const [h, p] = l.split(/\s+/); return [p.replace(/^\.\//, ""), h]; }));
for (const f of files) {
  const rel = relative(dir, f); const raw = readFileSync(f); const j = JSON.parse(raw);
  const sha = createHash("sha256").update(raw).digest("hex");
  const acts = [];
  for (const a of j.acts ?? []) {
    const r = await pyCall({ op: "check_act", act: a, registry: j.registry });
    const warrant = Array.isArray(a.claims) && a.claims.some((c) => c[1] === "rdf:type" && c[2] === "cr:Warrant");
    acts.push({ party: a.party, id: a.id, kind: a.kind, signed: !!a.sig, warrant, counts: !!r.counts, ...(r.counts ? {} : { ignoredBecause: r.ignored }) });
    out.totals.acts++; r.counts ? out.totals.counted++ : out.totals.ignored++; if (warrant) { out.totals.warrants++; if (r.counts) out.totals.warrantsCounted++; }
  }
  out.files.push({ path: `conformance/logs/${rel}`, sha256: sha, matchesSha256Sums: sums.get(rel) === sha, name: j.name ?? null, acts });
  out.totals.files++;
}
stopPython();
out.totals.allMatchSha256Sums = out.files.every((x) => x.matchesSha256Sums);
writeFileSync(process.argv[2], JSON.stringify(out, null, 1) + "\n");
if (process.argv[3]) {
  const warrants = { about: "Warrants (a person's signed grant of use of a credential) found in ntaild's conformance logs, all signed with public test keys. No warrant signed with a real key is readable from the agents account: real ones, if any, live in ntaild's store on the server, under the service's own account.", tool: "capture-ntaild.mjs", count: 0, countedByToday: 0, warrants: [] };
  for (const f of out.files) for (const a of f.acts) if (a.warrant) { warrants.warrants.push({ file: f.path, fileSha256: f.sha256, party: a.party, id: a.id, counts: a.counts, ...(a.ignoredBecause ? { ignoredBecause: a.ignoredBecause } : {}) }); warrants.count++; if (a.counts) warrants.countedByToday++; }
  writeFileSync(process.argv[3], JSON.stringify(warrants, null, 1) + "\n");
}
console.log(JSON.stringify(out.totals));
