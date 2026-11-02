# Shared test examples for signing, checking and encoding

Step 0 of the signing consolidation (`records/plans/turn-12-product-map/signing-consolidation.md`). Written before any
building, by an agent other than the builder. These are the evals the consolidated checker is judged by. A binding
(Rust, Node, browser, Python) passes when it gives the answer each file asks for.

**The count is fixed at 201** (`COUNT`): 46 positive, 155 negative. `check-count.sh` fails if a file is added, removed
or changed without `COUNT` and `manifest.json` changing with it. Changing an example is a change to the eval itself: do
it as its own commit and say so.

| Family | What it holds | Positive | Negative |
|---|---|---|---|
| `encoding` | One JSON text in; the bytes each of today's six encoders makes; the bytes (or refusal) the consolidated encoder must give | 11 | 16 |
| `names` | Actor names, look-alikes (probe P8), bad ids and kinds, and the mapping from today's parties | 11 | 44 |
| `device-es256` | A browser device key's signature on an expression, and the first-key-wins ring | 3 | 11 |
| `passkey-act` | Taylor's own signatures: passkey assertions, browser-key signatures, registrations; probes P1 to P8, P12 | 7 | 27 |
| `stream-publisher` | The signature on every stream event, and its key registry | 4 | 10 |
| `team-record` | Signed commitments and review verdicts | 2 | 9 |
| `act-v1` | Signed acts in ntaild's format, made by four different pieces of code | 5 | 10 |
| `approval-v2` | The person's signed answer to a credential-use question | 1 | 9 |
| `record-ns` | The model layer's signed records and their certificates | 1 | 9 |
| `log-chain` | The work log's hash chain | 1 | 4 |
| `cross-use` | One key signs three uses; each signature offered as the others | 0 | 6 |
| **Total** | | **46** | **155** |

## What a vector holds

`vectors/<family>/<id>.json`:

- `kind`: `positive` (a valid record: must be accepted, or encoded to exactly these bytes) or `negative` (must be refused).
- `input`: everything a check needs, as plain JSON (records, keys as public data, registries, the clock, the policy).
- `expected`: what the consolidated checker must give. For an accepted record: `signer`, `onBehalfOf` and `strength`.
  For a refusal: `result: "refused"` and a `reason`. **A replay compares result, signer and strength, not the reason
  text**; reasons are informative (they are today's words where today refuses, and short codes otherwise).
- `today`: what today's code gives, run on the checkouts named in the step-0 record (kept privately, not in this repository), and
  `agreesWithExpected`.
- `tags`: the probe (`P1` ... `P12`), the divergence (`divergence:key-order` ...), `cross-use`, `legacy`.
- `legacy`: which of today's pieces made it, as `L01` to `L13` (mapped in the step-0 record, kept privately).

**Strength** uses turn 7's ladder: `presence` (a passkey with the user verified), `device` (a registered browser or
device key), `agent`, `os-account`. Two formats carry no grade today, so two labels are used until step 1 decides:
`registry-key` (a key in a registry the caller supplied: ntaild's acts) and `service-key` (a stream publisher's key).
Changing a label changes no count.

## Where today's code and the requirement differ: 24 vectors

`today.agreesWithExpected` is false for these. They are the divergences the plan lists, kept as examples so they cannot
come back:

- **Byte recipe** (`encoding`, 14 of 24 incl. the act-level ones below): key order for characters above U+D7FF
  (`ENC-D01`, `D02`, and the RFC's own sorting example `ENC-P09`, where today's Python encoder is wrong); lone
  surrogates (`D03` to `D05`, and `ACT-N08`); integers beyond 2^53 (`D06` to `D09`, `ACT-N06`); floats (`D10` to `D15`);
  duplicate keys (`D16`); a number too big for a double (`D18`).
- **Cross-use** (`DEV-N07`): a browser-key signature made for one kind of event checks out when attached to another,
  because the signed bytes name no kind.
- **A key enrolled for Taylor by anything but their passkey** (`DEV-N08`, `ACT-N09`, `PASS-N-K3`): whoever publishes a
  key first becomes the person's trusted key; a caller-supplied registry makes anything its first key signs the person's.
- Not in the 24 because today already refuses them (they must stay refused): the other `cross-use` cases, probes
  P1 to P8 and P12, wrong origin and relying party, unpinned first passkey, device-key registration from an agent's
  product.

## Replaying against today's code

`tools/replay-today.mjs` reads the vector files (not the generator's memory) and runs today's checks:
`LEGACY_ROOT=<folder holding the four checkouts> node tools/replay-today.mjs test-vectors`. Result at step 0:
**201 of 201 give the answer the file records**, so the files lose nothing in being written out.

## Where the expected answers come from

- **Encoding.** An oracle in `tools/fam-encoding.mjs`: a strict parser and a serialiser for RFC 8785 canonical JSON
  restricted as the plan says (integers within +-(2^53-1) only, no floats, valid Unicode only, no duplicate keys).
  It reproduces the RFC's own sorting example (asserted when the vectors are made). It is step 0's own code, so
  **step 1 should confirm it against an independent RFC 8785 implementation** before relying on it.
- **Positives and probes.** Turn 7's spec (`records/plans/turn-7/spec.md`, the probe table) and the signing plan's own
  tests (`unharness test/signing-*.test.ts`, `test/support/*.ts`), whose fixtures and look-alike lists the vectors reuse.
- **The commitments decision** ("is that strength enough for this act") is ntaild's, not the verifier's. Each
  `passkey-act` vector carries the questions the verifier asked and the answers **ntaild's live `decide-act` gave** (run
  at ntaild main `32e7fc4`; the 15 distinct answers are in `tools/policy-answers.json`), so a replay needs no checker.
- **Today's answers.** Today's code, run on the main of each repo (the step-0 record, kept privately, names the commits).

## Keys

Every key is made from a public label (`agent-sign test key, public by design, never for real use:` plus a name), so
anyone can regenerate it. They protect nothing and must never be given a role outside tests. No private key is stored
in these files: only public keys, signatures and the records. Labels are in `tools/` where the keys are made.

## What these examples do not cover (said plainly)

- **The new formats.** SSHSIG records, agent certificates and the new envelope do not exist yet; their examples are
  written in step 1 beside the code. These cover only today's formats and the refusals the plan lists.
- **The signature counter rule** (a non-zero WebAuthn counter that goes backwards) is new in the plan, needs state, and
  is not in these files.
- **Rules across records** (unique ids, single-use challenges) stay with the stores, as the plan says; not here.
- **Probes P9 to P11** are about the operating system and the held delegate, not the checker.
- **In-memory-only differences** between today's encoders (an `undefined` field, `NaN` as a JavaScript number, which one
  encoder writes as `null`) cannot be written as JSON text, so they are not examples. The JSON-text forms are (`ENC-D17`).
- **Reason vocabulary** is not fixed.

## Regenerating, and layering

The generator (`tools/gen.mjs` and the `fam-*.mjs` files) loads today's code from the four checkouts and writes the files;
it makes new random event ids each run, so a regeneration is a deliberate change to the eval (see above). The policy
answers come from `tools/answer-policy.mjs`, run where `ntaild` is installed. The captured real records are indexed
under `captured/` (see `captured/INDEX.md`).

These examples and `tools/` carry the names of other products because the records they test do: event `product`
fields, stream subjects, file paths. When the layering check (`scripts/check-product-names.sh`) exists it must exempt
`test-vectors/`, and `scripts/check-one-signer*`, or those are removed when the one-signer count
reaches 0.
