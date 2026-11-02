# Captured real records

Part of step 0. A sample of today's real, valid records, so the consolidation can prove that "nothing old breaks": every
record valid today must still check out, with the same signer and strength, through the legacy readers.

**Nothing here holds conversation content or private text.** Each record is stored by *where it is and its hash*: its
location (file, offset, length, or line), the sha256 of its bytes, and the facts a checker needs (type, which key, whether
it verifies today, edge-case flags). To use a record, read it from its location on the machine that holds it and check the
hash. A replay of the captured records is therefore run where they are.

| Source | Index | What it covers | Where the records are |
|---|---|---|---|
| unharness stream | `unharness-stream.index.json` | 199 sampled of the 882 records in the Mac's stream store: 832 in the three signed streams (chat-app 29, mig 203, unharness 600), **all with a valid publisher signature** (832 of 832, none invalid), and 50 unsigned records of the older stream. 20 records carry a person's device-key signature (18 chat-app, 2 older): **20 of 20 verify when any key registered for the party counts** (how the act verifier works), but the two key-trust rules disagree on this real data, see below. The sample keeps the first and last 5 of each stream, every person-signed record and one of each type. | The Mac's local server: `~/.local/share/suite/nats/jetstream/streams/streams/<stream>/msgs/1.blk` |
| ntaild conformance logs | `ntaild-conformance.index.json` | All 156 log files, 539 acts: **515 counted** by today's signature check, 24 deliberately invalid (the logs' own negative cases). Every file's sha256 matches ntaild's `SHA256SUMS`. Test data, so the content is not private; it is indexed rather than copied because it is already fixed in ntaild's repo. | `ntaild/conformance/logs/` at ntaild main `32e7fc4` |
| agentic-credentials warrants | `warrants.index.json` | The 79 warrants in those logs, **77 counted** (2 are deliberate negatives). Also `ACT-P04`, a warrant made by the warrant tool's own code. **No warrant signed with a real key could be read**: real ones live in ntaild's store on the server, under the service's own account, outside the agents account. | `ntaild/conformance/logs/` (test keys) |
| work-loop log | `work-loop-log.index.json` | All 188 entries of the frozen log on the Mac (read-only file, last written 30 Sep): the chain is intact, **188 of 188 entry hashes recompute**, one entry has non-ASCII text, none has a float or an integer over 15 digits. Per entry: seq, hash, previous hash, line size and line hash. | `~/.work-loop/events.jsonl` on the Mac |

## A finding in the real records: two rules for whose key is whose disagree

The person's 20 signed records were made with two different browser keys (the older stream's, and the chat app's
current one). Under unharness's `KeyRing` (first key per party wins), fed in publication order from both streams, the
older key owns the person: **2 of 20 verify and the 18 newer ones fail**. Fed from the chat app's stream alone, the 18
verify and the 2 older ones fail. Under the act verifier's rule (any registered key for the party counts) all 20 verify.
Both readers are in use today, so "the same signer and strength as before" depends on which rule a record was read by.
Each person-signed record in the index carries both answers (`firstKeyWinsRing`, `anyRegisteredKey`). Step 1 has to
choose one rule for the legacy reader and say which answer the 18 are kept at.

## What is not covered, and why

- **The hetzner stream and the live work log.** Both belong to other accounts (the NATS server's own user; Taylor's
  hub). The agents account cannot read them and was not given a way to. The Mac's copies are older and smaller. The
  replay at step 1 should be run once by whoever can read those, using the same tools.
- **Passkey-signed acts.** The Mac's stream holds none: no passkey is pinned on the Mac yet, so no presence-strength
  act exists to capture. Passkey acts are covered only by the synthetic `passkey-act` examples until one is made.
- **Edge cases in real data.** Real records hold no floats, no big integers and one non-ASCII entry, so the real
  records cannot show the encoder divergences; the synthetic `encoding` examples do.

## How these were made

`tools/capture-stream.mjs` reads a local NATS server's file store directly, read-only, as its owner, without logging in
(no credential was used or read). `tools/capture-worklog.mjs` reads the log file and recomputes each hash with
work-loop's own function. `tools/capture-ntaild.mjs` runs ntaild's own signature check over every act. Each tool is
re-runnable: a new index must match the old one for every record the old one lists.
