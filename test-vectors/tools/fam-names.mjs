// Family "names": turn 7's SPIFFE-style actor names, with look-alikes refused (probe P8). The lists are the ones the
// signing plan's own tests use (unharness test/signing-names.test.ts), so the examples are not invented here.
import { imp, vec } from "./lib.mjs";
export async function namesFamily() {
  const n = await imp("unharness/src/names.ts");
  const SEVEN = [["person", "me"], ["device", "mac"], ["browser", "x-0123456789abcdef0123456789abcdef"], ["service", "nats-hub"], ["agent-role", "pm"], ["worker-run", "run-2026-10-23-0001"], ["chat", "claude-code-session"]];
  let i = 0; const id = (p) => `${p}-${String(++i).padStart(3, "0")}`;
  const real = n.actorName("person", "me");
  for (const [kind, ident] of SEVEN) {
    const name = n.actorName(kind, ident);
    vec({ id: id("NAME-P"), family: "names", legacy: "L02", kind: "positive", tags: [], about: `the ${kind} ${ident} has this one name`, input: { op: "parse", name }, expected: { result: "accepted", kind, id: ident }, today: { result: n.parseActorName(name) ? "accepted" : "refused" } });
  }
  for (const [party, want] of [["person:me", ["person", "me"]], ["agent:pm", ["agent-role", "pm"]], ["person:you", ["person", "you"]], ["agent:a.b_c-d", ["agent-role", "a.b_c-d"]]]) {
    const name = n.actorNameForParty(party);
    vec({ id: id("NAME-P"), family: "names", legacy: "L02", kind: "positive", tags: ["party-mapping"], about: `today's party ${party} maps to one name`, input: { op: "party-to-name", party }, expected: { result: "accepted", name: n.actorName(...want) }, today: { result: name === n.actorName(...want) ? "accepted" : "differs", name } });
  }
  const look = [
    ["uppercase id", real.replace("/me", "/Me")], ["Cyrillic ie in the id", real.replace("/me", "/m\u0435")], ["trailing space", `${real} `], ["leading space", ` ${real}`], ["trailing newline", `${real}\n`], ["trailing slash", `${real}/`], ["percent-encoded space", `${real}%20`],
    ["uppercase scheme", real.replace("spiffe://", "SPIFFE://")], ["uppercase trust domain", real.replace(n.TRUST_DOMAIN, n.TRUST_DOMAIN.toUpperCase())], ["trust domain with a suffix", real.replace(n.TRUST_DOMAIN, `${n.TRUST_DOMAIN}.evil.example`)], ["another trust domain", real.replace(n.TRUST_DOMAIN, `other-${n.TRUST_DOMAIN}`)],
    ["dot-dot path", `${real}/../person/me`], ["query string", `${real}?x=1`], ["fragment", `${real}#f`], ["user info", real.replace("spiffe://", "spiffe://me@")], ["double slash", real.replace("/person/", "/person//")], ["uppercase kind", real.replace("/person/", "/Person/")], ["Cyrillic o in the kind", real.replace("/person/", "/pers\u043en/")],
  ];
  for (const [why, name] of look) {
    vec({ id: id("NAME-N"), family: "names", legacy: "L02", kind: "negative", tags: ["P8"], about: `look-alike name for Taylor: ${why}`, input: { op: "parse", name }, expected: { result: "refused", reason: "look-alike-name" }, today: { result: n.parseActorName(name) !== undefined || n.isActorName(name) ? "accepted" : "refused" } });
  }
  for (const [why, ident] of [["uppercase", "Me"], ["Cyrillic ie", "m\u0435"], ["trailing space", "me "], ["leading space", " me"], ["trailing newline", "me\n"], ["empty", ""], ["slash", "a/b"], ["dot", "."], ["dot dot", ".."], ["65 characters", "x".repeat(65)], ["percent", "%41"], ["zero-width space", "m\u200be"], ["accented letter", "m\u00e9"]]) {
    let made; try { made = n.actorName("person", ident); } catch { made = undefined; }
    vec({ id: id("NAME-N"), family: "names", legacy: "L02", kind: "negative", tags: ["P8"], about: `an id that cannot be made into a name: ${why}`, input: { op: "make", kind: "person", id: ident }, expected: { result: "refused", reason: "bad-id" }, today: { result: made === undefined ? "refused" : "accepted" } });
  }
  for (const [why, kind] of [["capital letter", "Person"], ["not a kind", "robot"]]) {
    let made; try { made = n.actorName(kind, "me"); } catch { made = undefined; }
    vec({ id: id("NAME-N"), family: "names", legacy: "L02", kind: "negative", tags: ["P8"], about: `a kind that is not one of the seven: ${why}`, input: { op: "make", kind, id: "me" }, expected: { result: "refused", reason: "bad-kind" }, today: { result: made === undefined ? "refused" : "accepted" } });
  }
  for (const [why, party] of [["capital M", "person:Me"], ["Cyrillic ie", "person:m\u0435"], ["trailing space", "person:me "], ["leading space", " person:me"], ["capital kind", "PERSON:me"], ["empty id (agent)", "agent:"], ["empty id (person)", "person:"], ["another kind", "robot:me"], ["no kind", "me"], ["extra part", "person:me:extra"], ["58-character id", "person:" + "a".repeat(58)]]) {
    const name = n.actorNameForParty(party);
    vec({ id: id("NAME-N"), family: "names", legacy: "L02", kind: "negative", tags: ["P8"], about: `a look-alike party: ${why}`, input: { op: "party-to-name", party }, expected: { result: "refused", reason: "look-alike-name" }, today: { result: name === undefined ? "refused" : "accepted" } });
  }
}
