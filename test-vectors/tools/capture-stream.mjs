// Indexes real, valid records from the unharness event stream WITHOUT copying any of their content.
// For each stored record it writes: where it is (the stream's file store, offset, length), the sha256 of the
// record's bytes, and the facts a checker cares about (event type, which key published it, whether that publisher
// signature verifies, whether a person's device-key signature verifies). The records themselves, which can hold chat,
// never leave the machine they are on; to look at one, read the file at the recorded path and offset and check its hash.
//
// Read-only. Reads the JetStream file store of a local NATS server directly (no login, no connection), as the user
// that owns it. Run it where the store is: LEGACY_UNHARNESS=<unharness checkout> STORE=<store dir> node capture-stream.mjs <out.json>
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const U = process.env.LEGACY_UNHARNESS, STORE = process.env.STORE;
const imp = (rel) => import(pathToFileURL(join(U, rel)).href);
const pub = await imp("src/publisher.ts"), pk = await imp("src/person-keys.ts"), ids = await imp("src/ids.ts");
const base = join(STORE, "jetstream/streams/streams");
const streams = ["EV_CHAT_APP", "SUITE", "EV_MIG", "EV_UNHARNESS", "EV_CAS", "EV_CLAUDE_CODE"]; // the chat app's own stream first, so its device keys are known when the older stream is read

function* records(path) {
  const b = readFileSync(path); let o = 0;
  while (o + 30 <= b.length) {
    const rlRaw = b.readUInt32LE(o), hbit = (rlRaw & 0x80000000) !== 0, rl = rlRaw & 0x7fffffff;
    if (rl < 30 || o + rl > b.length) break;
    const seqRaw = b.readBigUInt64LE(o + 4), slen = b.readUInt16LE(o + 20);
    let p = o + 22; const subject = b.subarray(p, p + slen).toString("utf8"); p += slen;
    let hdr = Buffer.alloc(0);
    if (hbit) { const hlen = b.readUInt32LE(p); p += 4; hdr = b.subarray(p, p + hlen); p += hlen; }
    yield { seq: Number(seqRaw & ~(1n << 63n)), erased: (seqRaw & (1n << 63n)) !== 0n, subject, hdr, body: b.subarray(p, o + rl - 8), offset: o, length: rl };
    o += rl;
  }
}
const parseHeaders = (h) => { const m = {}; for (const line of h.toString("utf8").split("\r\n").slice(1)) { const i = line.indexOf(":"); if (i > 0) m[line.slice(0, i)] = line.slice(i + 1).trim(); } return m; };
const sha = (...bufs) => { const h = createHash("sha256"); for (const x of bufs) h.update(x); return h.digest("hex"); };

const ring = new pk.KeyRing(); // one ring across streams, fed in order, as a reader of the chat app's device-key events would build it
// the ring is fed with every device-key registration of the chat app, from every stream, in the order they were published
const regs0 = [];
for (const stream of streams) {
  let recs; try { recs = [...records(join(base, stream, "msgs", "1.blk"))]; } catch { continue; }
  for (const r of recs) { const h = parseHeaders(r.hdr); if (h["ce-type"] === "suite.chat-app.device-key-registered") { try { regs0.push({ time: h["ce-time"], data: JSON.parse(r.body.toString("utf8")) }); } catch {} } }
}
regs0.sort((a, b) => (a.time < b.time ? -1 : a.time > b.time ? 1 : 0));
for (const r of regs0) await ring.register(r.data);
// the other rule in use: any key registered for the party counts (what the act verifier does)
const anyKey = new Map(); for (const r of regs0) if (r.data?.keyId && r.data?.publicKey) anyKey.set(r.data.keyId, r.data.publicKey);
const out = { about: "Index of real stream records: where each is and its hash, never its content.", tool: "capture-stream.mjs", records: [], summary: {} };
for (const stream of streams) {
  const file = join(base, stream, "msgs", "1.blk");
  let recs; try { recs = [...records(file)]; } catch { continue; }
  let regs = 0;
  const sum = { records: recs.length, byType: {}, publisherSignatureValid: 0, publisherSignatureInvalid: 0, unsigned: 0, personSigned: 0, personSignatureValid: 0, personSignatureInvalid: 0, personValidIfAnyRegisteredKeyCounts: 0, personSignatureNotChecked: 0 };
  for (const r of recs) {
    if (r.erased) continue;
    const h = parseHeaders(r.hdr); const type = h["ce-type"] ?? "?";
    sum.byType[type] = (sum.byType[type] ?? 0) + 1;
    const bodyText = r.body.toString("utf8");
    let data; try { data = JSON.parse(bodyText); } catch { data = undefined; }
    // publisher signature: valid under the key it names (a cryptographic check; whether that key is enrolled is the registry's)
    const key = h["suite-publisher-key"]; const product = r.subject.split(".")[1];
    let pubStatus = "unsigned", ver = null;
    if (key && h["suite-publisher-signature"]) {
      for (const v1 of [false, true]) {
        const reg = { unsignedThrough: 0, ...(v1 ? { v1Through: 1_000_000_000 } : {}), publishers: [{ publicKey: key, product }] };
        const j = pub.judgePublisher(reg, r.subject, (n) => h[n], bodyText, r.seq, undefined);
        if (j.problem === undefined) { pubStatus = "valid"; ver = v1 ? 1 : 2; break; }
        pubStatus = "invalid";
      }
    }
    if (pubStatus === "valid") sum.publisherSignatureValid++; else if (pubStatus === "invalid") sum.publisherSignatureInvalid++; else sum.unsigned++;
    // the person's own signature, where the record carries one
    let person = null;
    if (data && typeof data === "object") {
      const s = data.signature;
      if (s && typeof s === "object") {
        sum.personSigned++;
        if (s.alg === "ES256" && typeof data.party === "string") {
          const { signature: _ignored, ...rest } = data;
          const status = await ring.check(data.party, s, h["ce-id"], h["ce-conversation"], data);
          let any = false; try { any = await ids.verify(s, anyKey, h["ce-id"], h["ce-conversation"], data); } catch {}
          person = { alg: "ES256", firstKeyWinsRing: status, anyRegisteredKey: any ? "valid" : "invalid" };
          if (status === "valid") sum.personSignatureValid++; else sum.personSignatureInvalid++;
          if (any) sum.personValidIfAnyRegisteredKeyCounts++;
        } else { person = { alg: String(s.alg), firstKeyWinsRing: "not-checked-here" }; sum.personSignatureNotChecked++; }
      }
    }
    const flags = { hasFloat: /[0-9]\.[0-9]|[0-9][eE][+-]?[0-9]/.test(bodyText.replace(/"(?:\\.|[^"\\])*"/g, '""')), hasNonAscii: /[^\x00-\x7f]/.test(bodyText), bigInteger: /(^|[^0-9.])[0-9]{16,}([^0-9.]|$)/.test(bodyText.replace(/"(?:\\.|[^"\\])*"/g, '""')) };
    out.records.push({ stream, seq: r.seq, path: `jetstream/streams/streams/${stream}/msgs/1.blk`, offset: r.offset, length: r.length, sha256: sha(r.hdr, r.body), type, subjectParts: r.subject.split("."), bodyBytes: r.body.length, publisher: { key: key ?? null, signature: pubStatus, version: ver }, person, flags });
  }
  out.summary[stream] = sum;
}
// a sample: the first and last 5 of each stream, every person-signed record, one of each type, and every edge-case record
const keep = new Set(); const seenType = new Set(); const byStream = {};
out.records.forEach((r, i) => { (byStream[r.stream] ??= []).push(i); });
for (const idxs of Object.values(byStream)) { idxs.slice(0, 5).forEach((i) => keep.add(i)); idxs.slice(-5).forEach((i) => keep.add(i)); }
out.records.forEach((r, i) => { if (r.person || r.flags.hasFloat || r.flags.hasNonAscii || r.flags.bigInteger || !seenType.has(r.stream + r.type)) keep.add(i); seenType.add(r.stream + r.type); });
const sample = out.records.filter((_, i) => keep.has(i));
const result = { about: out.about, tool: out.tool, store: "the local NATS server's JetStream file store (path recorded relative to its store directory)", summary: out.summary, sampleSize: sample.length, sample };
writeFileSync(process.argv[2], JSON.stringify(result, null, 1) + "\n");
console.log(JSON.stringify({ summary: out.summary, sampleSize: sample.length }));
