// Family "encoding": one JSON text in, the bytes each of today's six encoders makes, and the bytes (or refusal)
// the consolidated encoder must give: RFC 8785 canonical JSON restricted as the plan says (integers within
// +-(2^53-1) only, no floats, valid Unicode only, no duplicate keys).
import { imp, vec, pyCall, hex } from "./lib.mjs";

// ---- the oracle: a strict parser and the restricted RFC 8785 serialiser. Written for step 0 from the RFC and the plan. ----
function strictParse(t) {
  let i = 0;
  const ws = () => { while (" \t\n\r".includes(t[i])) i++; };
  const fail = (m) => { throw Object.assign(new Error(m), { parse: true }); };
  function value() {
    ws();
    const c = t[i];
    if (c === "{") {
      i++; const members = []; ws();
      if (t[i] === "}") { i++; return { o: members }; }
      for (;;) { ws(); if (t[i] !== '"') fail("key"); const k = str(); ws(); if (t[i++] !== ":") fail(":"); members.push([k, value()]); ws(); if (t[i] === ",") { i++; continue; } if (t[i] === "}") { i++; return { o: members }; } fail("object"); }
    }
    if (c === "[") {
      i++; const items = []; ws();
      if (t[i] === "]") { i++; return { a: items }; }
      for (;;) { items.push(value()); ws(); if (t[i] === ",") { i++; continue; } if (t[i] === "]") { i++; return { a: items }; } fail("array"); }
    }
    if (c === '"') return { s: str() };
    for (const [lit, v] of [["true", true], ["false", false], ["null", null]]) if (t.startsWith(lit, i)) { i += lit.length; return { l: v }; }
    const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(t.slice(i));
    if (!m) fail("value " + c);
    i += m[0].length; return { n: m[0] };
  }
  function str() {
    i++; let out = "";
    for (;;) {
      const c = t[i++];
      if (c === undefined) fail("unterminated");
      if (c === '"') return out;
      if (c === "\\") {
        const e = t[i++];
        if (e === "u") { const h = t.slice(i, i + 4); if (!/^[0-9a-fA-F]{4}$/.test(h)) fail("\\u"); out += String.fromCharCode(parseInt(h, 16)); i += 4; }
        else if ('"\\/bfnrt'.includes(e)) out += { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" }[e];
        else fail("escape");
      } else { if (c < " ") fail("control"); out += c; }
    }
  }
  const v = value(); ws(); if (i !== t.length) fail("trailing"); return v;
}
const loneSurrogate = (s) => /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(s);
export function oracle(text) {
  let ast;
  try { ast = strictParse(text); } catch { return { refused: "not-json" }; }
  const go = (n) => {
    if ("o" in n) {
      const keys = n.o.map(([k]) => k);
      if (new Set(keys).size !== keys.length) throw { why: "duplicate-key" };
      for (const k of keys) if (loneSurrogate(k)) throw { why: "lone-surrogate" };
      return "{" + [...n.o].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, v]) => JSON.stringify(k) + ":" + go(v)).join(",") + "}";
    }
    if ("a" in n) return "[" + n.a.map(go).join(",") + "]";
    if ("s" in n) { if (loneSurrogate(n.s)) throw { why: "lone-surrogate" }; return JSON.stringify(n.s); }
    if ("l" in n) return JSON.stringify(n.l);
    if (!/^-?(0|[1-9]\d*)$/.test(n.n)) throw { why: "non-integer-number" };
    const b = BigInt(n.n);
    if (b > 9007199254740991n || b < -9007199254740991n) throw { why: "unsafe-integer" };
    return b === 0n ? "0" : b.toString();
  };
  try { return { bytes: Buffer.from(go(ast), "utf8") }; } catch (e) { if (e && e.why) return { refused: e.why }; throw e; }
}

export async function encodingFamily() {
  const ids = await imp("unharness/src/ids.ts");
  const tl = await imp("unharness/listeners/src/team-lead/signed.ts");
  const ml = await imp("unharness/listeners/src/model-layer/signing.ts");
  const ac = await imp("agentic-credentials/src/entitlement/acts.ts");
  const wl = await imp("work-loop/src/log/canonical.ts");
  const encoders = {
    L01: (v) => ids.canonical(v), L05: (v) => tl.canonical(v), L09: (v) => ac.canonical(v), L12: (v) => wl.canonicalJson(v), L13: (v) => ml.canonicalJson(v),
  };
  const cases = [
    // [id, json text, about, tags]
    ["ENC-P01", '{"b":1,"a":[true,null,"x"]}', "keys come out sorted, no spaces", []],
    ["ENC-P02", '{"z":3,"\u00e9":1,"e":2,"\u65e5":4}', "BMP keys in code-unit order (e, z, e-acute, a CJK character)", []],
    ["ENC-P03", '{"s":"a\\"b\\\\c\\/\\u0001\\u001f\\u007f\\u2028\\n"}', "string escapes: quote, backslash, slash, control characters, DEL, line separator", []],
    ["ENC-P04", '{"a":0,"b":-1,"c":9007199254740991,"d":-9007199254740991}', "integers up to +-(2^53-1)", []],
    ["ENC-P05", '{"a":{},"b":[],"c":[{},[],{"d":[]}]}', "empty objects and arrays", []],
    ["ENC-P06", '{"a":-0}', "an integer written -0 comes out 0", ["divergence:negative-zero"]],
    ["ENC-P07", '{"k":{"k":{"k":{"k":{"k":{"k":{"k":{"k":[1,[2,[3,[4]]]]}}}}}}}}', "deep nesting", []],
    ["ENC-P08", '{"a":"caf\u00e9","b":"cafe\u0301"}', "NFC and NFD forms of the same word stay different strings (no normalisation)", []],
    ["ENC-P09", '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}', "the RFC 8785 sorting example (section 3.2.3); today the Python encoder sorts by code point and gets it wrong", ["divergence:key-order"]],
    ["ENC-D01", '{"\\uff5e":1,"\\ud83d\\ude00":2}', "key order: a BMP character above U+D800 against an astral one (UTF-16 order puts the astral key first; code-point order puts it last)", ["divergence:key-order"]],
    ["ENC-D02", '{"\\ud7ff":1,"\\ue000":2,"\\ud800\\udc00":3}', "key order across the surrogate range", ["divergence:key-order"]],
    ["ENC-D03", '{"s":"\\ud800"}', "a lone high surrogate in a value", ["divergence:lone-surrogate"]],
    ["ENC-D04", '{"s":"\\udc00"}', "a lone low surrogate in a value", ["divergence:lone-surrogate"]],
    ["ENC-D05", '{"\\ud800":1}', "a lone surrogate in a key", ["divergence:lone-surrogate"]],
    ["ENC-D06", '{"n":9007199254740992}', "2^53: the first integer a JavaScript number cannot tell from its neighbour", ["divergence:large-integer"]],
    ["ENC-D07", '{"n":9007199254740993}', "2^53+1: JavaScript reads it as 2^53 without complaint", ["divergence:large-integer"]],
    ["ENC-D08", '{"n":18446744073709551616}', "2^64", ["divergence:large-integer"]],
    ["ENC-D09", '{"n":-9007199254740992}', "-2^53", ["divergence:large-integer"]],
    ["ENC-D10", '{"n":1.0}', "1.0: JavaScript turns it into 1", ["divergence:float"]],
    ["ENC-D11", '{"n":1e3}', "1e3: JavaScript turns it into 1000", ["divergence:float"]],
    ["ENC-D12", '{"n":1.5}', "a fraction", ["divergence:float"]],
    ["ENC-D13", '{"n":0.1}', "0.1", ["divergence:float"]],
    ["ENC-D14", '{"n":1e21}', "1e21, which JavaScript writes as 1e+21", ["divergence:float"]],
    ["ENC-D15", '{"n":-0.0}', "-0.0", ["divergence:float", "divergence:negative-zero"]],
    ["ENC-D16", '{"a":1,"a":2}', "a duplicate key: parsers keep the last", ["divergence:duplicate-key"]],
    ["ENC-D17", '{"n":NaN}', "NaN is not JSON; Python's parser accepts it", ["divergence:non-finite"]],
    ["ENC-D18", '{"n":1e400}', "a number too big for a double: JavaScript reads Infinity", ["divergence:non-finite"]],
  ];
  const out = [];
  for (const [id, text, about, tags] of cases) {
    const today = {};
    let parsed, parseErr;
    try { parsed = JSON.parse(text); } catch (e) { parseErr = true; }
    for (const [lid, f] of Object.entries(encoders)) {
      if (parseErr) { today[lid] = { error: "does-not-parse" }; continue; }
      try { today[lid] = { bytes: hex(new TextEncoder().encode(f(parsed))) }; } catch (e) { today[lid] = { error: "refuses" }; }
    }
    const p = await pyCall({ op: "encode", text });
    today.L07 = p.ok !== undefined ? { bytes: p.ok } : { error: p.error === "NotCanonical" ? "refuses" : "does-not-parse" };
    const o = oracle(text);
    const expected = o.bytes ? { result: "encoded", bytes: hex(o.bytes), text: o.bytes.toString("utf8") } : { result: "refused", reason: o.refused };
    const distinct = new Set(Object.values(today).map((r) => JSON.stringify(r)));
    const agrees = Object.entries(today).filter(([, r]) => r.bytes !== undefined && expected.bytes !== undefined && r.bytes === expected.bytes).map(([l]) => l);
    const accepts = Object.entries(today).filter(([, r]) => r.bytes !== undefined).map(([l]) => l);
    out.push({ id, text, expected });
    vec({
      id, family: "encoding", legacy: "L01 L05 L07 L09 L12 L13", kind: expected.result === "encoded" ? "positive" : "negative", tags,
      about, input: { json_text: text },
      expected,
      today: { encoders: today, encodersDisagree: distinct.size > 1, matchExpected: agrees, wronglyEncode: expected.result === "refused" ? accepts : undefined },
    });
  }
  // the RFC example's published order, as an independent check of the oracle
  const rfc = out.find((o) => o.id === "ENC-P09").expected.text;
  const order = [...rfc.matchAll(/"((?:\\.|[^"\\])*)":"/g)].map((m) => JSON.parse('"' + m[1] + '"'));
  const want = ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\ud83d\ude00", "\ufb33"];
  if (JSON.stringify(order) !== JSON.stringify(want)) throw new Error("oracle disagrees with the RFC 8785 sorting example: " + JSON.stringify(order));
  return out;
}
