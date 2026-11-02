#!/usr/bin/env python3
"""Runs the Python side of today's signing code for the vector generator (step 0).

Reads one JSON request per line on stdin, writes one JSON answer per line on stdout.
It loads ntaild's canonical.py and acts.py *as they are* (from LEGACY_ROOT/ntaild/src/ntaild), without the
package's heavy imports (the rule engine), by giving acts.py stand-ins for the two modules it imports only for
shape checks it does not use here. Nothing about signing is re-implemented: encode, sign and check are the real
functions. Keys come from public labels (TEST KEYS ONLY, as ntaild's own conformance keys do).

Requests:
  {"op":"encode","text":<json text>}                      -> {"ok":bytes-hex} | {"error":..}
  {"op":"sign_act","act":{..},"label":..,"key_id":..}     -> {"act":{..signed..}}
  {"op":"pub","label":..}                                 -> {"b64":..}
  {"op":"check_act","act":{..},"registry":{..}}           -> {"counts":true} | {"ignored":reason}
  {"op":"payload","act":{..}}                             -> {"hex":..}   (the bytes the check expects signed)
"""
import hashlib, importlib.util, json, os, sys, types, base64

root = os.environ["LEGACY_ROOT"]
src = os.path.join(root, "ntaild", "src", "ntaild")
pkg = types.ModuleType("ntaild"); pkg.__path__ = [src]; sys.modules["ntaild"] = pkg
base = types.ModuleType("ntaild.base"); base.Base = type("Base", (), {}); sys.modules["ntaild.base"] = base
terms = types.ModuleType("ntaild.terms")
terms.NT = "https://ntaild.invalid/"; terms.RDF_NS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
terms.BadTerm = type("BadTerm", (ValueError,), {}); terms.to_triple = lambda c: tuple(c)
sys.modules["ntaild.terms"] = terms
def load(name):
    spec = importlib.util.spec_from_file_location(f"ntaild.{name}", os.path.join(src, name + ".py"))
    m = importlib.util.module_from_spec(spec); sys.modules[f"ntaild.{name}"] = m; spec.loader.exec_module(m); return m
canonical = load("canonical"); acts = load("acts")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PREFIX = b"agent-sign test key, public by design, never for real use:"
def key(label): return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(PREFIX + label.encode()).digest())

def handle(r):
    op = r["op"]
    if op == "encode":
        try:
            v = json.loads(r["text"])
            return {"ok": canonical.canonical_bytes(v).hex()}
        except Exception as e:
            return {"error": f"{type(e).__name__}"}
    if op == "pub": return {"b64": acts.public_key_b64(key(r["label"]))}
    if op == "sign_act":
        try: return {"act": acts.sign_act(r["act"], key(r["label"]), r["key_id"])}
        except Exception as e: return {"error": f"{type(e).__name__}: {e}"}
    if op == "payload":
        try: return {"hex": acts._shape(r["act"]).hex()}
        except Exception as e: return {"error": str(e)}
    if op == "check_act":
        try:
            reg = acts.Registry.load(r["registry"]); a = r["act"]
            payload = acts._shape(a)
            acts._signature(a, reg, payload)
            return {"counts": True}
        except acts.Ignored as e: return {"ignored": str(e)}
        except Exception as e: return {"ignored": f"error {type(e).__name__}: {e}"}
    return {"error": "unknown op"}

for line in sys.stdin:
    line = line.strip()
    if not line: continue
    print(json.dumps(handle(json.loads(line))), flush=True)
