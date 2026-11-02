// Family "log-chain": the work log's hash chain (work-loop src/log/canonical.ts and event-log.ts). Nothing is signed;
// each entry hashes its canonical JSON with the previous hash inside it. The consolidated encoder must keep these
// hashes (old entries are read with a legacy reader), so the chain is a vector too.
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { imp, vec } from "./lib.mjs";

export async function logFamily() {
  const el = await imp("work-loop/src/log/event-log.ts");
  const cn = await imp("work-loop/src/log/canonical.ts");
  const dir = mkdtempSync(join(tmpdir(), "wl-"));
  const logPath = join(dir, "events.jsonl");
  const log = new el.EventLog({ logPath, lockPath: logPath + ".lock" });
  const evs = [
    { source: "agent:test", type: "wl.test.one", subject: "item-1", data: { n: 1, text: "plain" } },
    { source: "agent:test", type: "wl.test.two", subject: "item-1", data: { text: "café 日本 😀", nested: { b: 2, a: [1, 2, { z: 0, y: 1 }] } } },
    { source: "agent:test", type: "wl.test.three", subject: "item-2", data: { ratio: 0.1, big: 1e21, small: 5e-324 } },
    { source: "agent:test", type: "wl.test.four", subject: "item-2", data: { empty: {}, none: null, flag: true } },
  ];
  for (const e of evs) await log.append(e);
  const lines = readFileSync(logPath, "utf8").trimEnd().split("\n");
  const verify = async (ls) => { writeFileSync(logPath, ls.join("\n") + "\n"); const r = await new el.EventLog({ logPath, lockPath: logPath + ".lock" }).verify(); return { ok: r.ok, entries: r.entries, break: r.firstBreak ? { line: r.firstBreak.line, reason: r.firstBreak.reason } : null }; };
  const L = (id, o) => vec({ id, family: "log-chain", legacy: "L12", ...o });
  const good = await verify(lines);
  L("LOG-P01", { kind: "positive", tags: [], about: "a four-entry chain, including non-ASCII text and floats (0.1, 1e21, 5e-324), which today's encoder writes with JavaScript's number format", input: { lines }, expected: { result: "accepted", entries: 4, headHash: JSON.parse(lines[3]).hash }, today: good });
  const e1 = JSON.parse(lines[1]); e1.data.nested.b = 3;
  const tamper = [lines[0], JSON.stringify(e1), lines[2], lines[3]];
  L("LOG-N01", { kind: "negative", tags: [], about: "an entry's data changed after it was written", input: { lines: tamper }, expected: { result: "refused", reason: "hash-mismatch", atEntry: 1 }, today: await verify(tamper) });
  const reorder = [lines[0], lines[2], lines[1], lines[3]];
  L("LOG-N02", { kind: "negative", tags: [], about: "two entries swapped", input: { lines: reorder }, expected: { result: "refused", reason: "prevhash-mismatch", atEntry: 1 }, today: await verify(reorder) });
  const missing = [lines[0], lines[2], lines[3]];
  L("LOG-N03", { kind: "negative", tags: [], about: "an entry removed", input: { lines: missing }, expected: { result: "refused", reason: "prevhash-mismatch", atEntry: 1 }, today: await verify(missing) });
  const e0 = JSON.parse(lines[0]); const { hash: _h, ...rest } = e0; const forged = { ...rest, data: { n: 99, text: "plain" } };
  forged.hash = cn.entryHash(forged);
  const rehash = [JSON.stringify(forged), lines[1], lines[2], lines[3]];
  L("LOG-N04", { kind: "negative", tags: [], about: "an entry rewritten and re-hashed: its own hash is right but the next entry's prevhash no longer matches", input: { lines: rehash }, expected: { result: "refused", reason: "prevhash-mismatch", atEntry: 1 }, today: await verify(rehash) });
  rmSync(dir, { recursive: true });
  return { lines };
}
