// Indexes the work log's real entries WITHOUT copying any content: for each entry, its seq, its recorded hash, whether
// the hash recomputes from the entry (the check the log's own hash chain uses), and which edge cases it holds.
// Read-only. LEGACY_WORKLOOP=<work-loop checkout (main's src/log/canonical.ts)> node capture-worklog.mjs <events.jsonl> <out.json>
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
const cn = await import(pathToFileURL(join(process.env.LEGACY_WORKLOOP, "src/log/canonical.ts")).href);
const file = process.argv[2];
const raw = readFileSync(file);
const lines = raw.toString("utf8").split("\n").filter((l) => l.trim());
const strip = (s) => s.replace(/"(?:\\.|[^"\\])*"/g, '""');
const entries = []; let prev = cn.GENESIS_HASH, chainOk = true, recomputes = 0;
for (const [i, line] of lines.entries()) {
  const e = JSON.parse(line);
  const recomputed = cn.entryHash(e) === e.hash;
  if (recomputed) recomputes++;
  const linked = e.prevhash === prev; if (!linked || e.seq !== i) chainOk = false; prev = e.hash;
  entries.push({ seq: e.seq, hash: e.hash, prevhash: e.prevhash, type: e.type, lineBytes: Buffer.byteLength(line) + 1, lineSha256: createHash("sha256").update(line).digest("hex"), hashRecomputes: recomputed, linksToPrevious: linked,
    flags: { hasFloat: /[0-9]\.[0-9]|[0-9][eE][+-]?[0-9]/.test(strip(line)), hasNonAscii: /[^\x00-\x7f]/.test(line), bigInteger: /(^|[^0-9.])[0-9]{16,}([^0-9.]|$)/.test(strip(line)) } });
}
const out = { about: "Index of real work-log entries: hash, position, edge-case flags; never content.", tool: "capture-worklog.mjs", file: { path: "~/.work-loop/events.jsonl (the frozen log on the Mac)", bytes: raw.length, sha256: createHash("sha256").update(raw).digest("hex"), entries: entries.length, headHash: entries.at(-1)?.hash, chainOk, hashesThatRecompute: recomputes }, edgeCaseEntries: { hasFloat: entries.filter((e) => e.flags.hasFloat).map((e) => e.seq), hasNonAscii: entries.filter((e) => e.flags.hasNonAscii).map((e) => e.seq), bigInteger: entries.filter((e) => e.flags.bigInteger).map((e) => e.seq) }, entries };
writeFileSync(process.argv[3], JSON.stringify(out, null, 1) + "\n");
console.log(JSON.stringify({ ...out.file, edge: Object.fromEntries(Object.entries(out.edgeCaseEntries).map(([k, v]) => [k, v.length])) }));
