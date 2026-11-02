// Shared helpers for the step 0 vector generator: public-label test keys, the Python bridge,
// the vector writer. TEST KEYS ONLY: every private key here is derived from a public label, so
// anyone can regenerate it, which is the point for fixtures and exactly why they protect nothing.
import { createECDH, createHash, createPrivateKey, createPublicKey, sign as nodeSign, webcrypto } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

export const LABEL_PREFIX = "agent-sign test key, public by design, never for real use:";
export const ROOT = process.env.LEGACY_ROOT;
if (!ROOT) throw new Error("set LEGACY_ROOT to the folder that holds the repo checkouts");
export const OUT = process.env.OUT ?? "out";
export const imp = (rel) => import(pathToFileURL(join(ROOT, rel)).href);

export const sha256 = (b) => createHash("sha256").update(b).digest();
export const b64u = (b) => Buffer.from(b).toString("base64url");
export const hex = (b) => Buffer.from(b).toString("hex");
export const seedOf = (label) => sha256(LABEL_PREFIX + label);

// ---- Ed25519 from a label ----
const ED_PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
export function ed(label) {
  const seed = seedOf(label);
  const privateKey = createPrivateKey({ key: Buffer.concat([ED_PKCS8, seed]), format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(privateKey);
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  return { label, seed, privateKey, publicKey, raw, rawB64: raw.toString("base64"), spkiB64: publicKey.export({ format: "der", type: "spki" }).toString("base64"), spkiPem: publicKey.export({ format: "pem", type: "spki" }).toString() };
}
export const edSign = (k, bytes) => nodeSign(null, Buffer.from(bytes), k.privateKey);

// ---- P-256 from a label ----
export function p256(label) {
  const d = seedOf(label);
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(d);
  const pub = ecdh.getPublicKey();
  const x = pub.subarray(1, 33), y = pub.subarray(33, 65);
  const jwk = { kty: "EC", crv: "P-256", x: b64u(x), y: b64u(y) };
  const privJwk = { ...jwk, d: b64u(d) };
  const privateKey = createPrivateKey({ key: privJwk, format: "jwk" });
  return { label, jwk, privJwk, x, y, privateKey, publicKey: createPublicKey(privateKey) };
}
export async function deviceKey(label, keyIdFor) {
  const k = p256(label);
  const alg = { name: "ECDSA", namedCurve: "P-256" };
  const priv = await webcrypto.subtle.importKey("jwk", k.privJwk, alg, true, ["sign"]);
  const pub = await webcrypto.subtle.importKey("jwk", k.jwk, alg, true, ["verify"]);
  return { pair: { privateKey: priv, publicKey: pub }, jwk: k.jwk, keyId: await keyIdFor(k.jwk), label };
}

// ---- NATS user keys (the stream publisher's key) ----
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function crc16(bytes) { let crc = 0; for (const b of bytes) { crc ^= b << 8; for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff; } return crc; }
function base32(bytes) { let bits = 0, acc = 0, out = ""; for (const b of bytes) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { out += B32[(acc >>> (bits - 5)) & 31]; bits -= 5; } acc &= (1 << bits) - 1; } if (bits) out += B32[(acc << (5 - bits)) & 31]; return out; }
const withCrc = (raw) => { const c = crc16(raw); return Buffer.concat([raw, Buffer.from([c & 255, c >> 8])]); };
export function nkeyUser(label) {
  const k = ed(label);
  const userPrefix = 20 << 3;
  const seedText = base32(withCrc(Buffer.concat([Buffer.from([(18 << 3) | (userPrefix >> 5), (userPrefix & 31) << 3]), k.seed])));
  const publicText = base32(withCrc(Buffer.concat([Buffer.from([userPrefix]), k.raw])));
  return { ...k, seedText, seedBytes: new TextEncoder().encode(seedText), publicText };
}

// ---- Python bridge ----
let py, pending = [], buf = "";
export function startPython(script) {
  py = spawn("python3", ["-I", script], { env: { ...process.env, LEGACY_ROOT: ROOT }, stdio: ["pipe", "pipe", "inherit"] });
  py.stdout.on("data", (d) => { buf += d; let i; while ((i = buf.indexOf("\n")) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 1); pending.shift()(JSON.parse(line)); } });
}
export const pyCall = (req) => new Promise((res) => { pending.push(res); py.stdin.write(JSON.stringify(req) + "\n"); });
export const stopPython = () => py?.stdin.end();

// ---- vectors ----
export const vectors = [];
let lastLegacy = {};
export function vec(v) {
  if (vectors.some((x) => x.id === v.id)) throw new Error("duplicate vector id " + v.id);
  vectors.push({ schema: "agent-sign-test-vector/1", ...v });
  return v;
}
export function writeAll(dir) {
  for (const v of vectors) {
    const p = join(dir, "vectors", v.family, v.id + ".json");
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, JSON.stringify(v, null, 2) + "\n");
  }
}
export const sortedJson = (o) => JSON.stringify(o, (k, v) => (v && typeof v === "object" && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) : v));
