"""Cross-implementation test: the browser bundle (noble, JavaScript) and the
official C reference code must produce byte-identical results from the same
randomness, and interoperate in both directions."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from kybergate.kem import ML_KEM_768

BUNDLE = Path(__file__).resolve().parents[1] / "kybergate/web/static/vendor/mlkem.js"
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed")

NODE = r"""
const fs = require("fs"); const vm = require("vm");
const ctx = { crypto: globalThis.crypto, Uint8Array, TextEncoder, console }; vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[1], "utf8") + ";globalThis.MLKEM=MLKEM;", ctx);
const kem = ctx.MLKEM.ml_kem768;
const h = (u) => Buffer.from(u).toString("hex"); const b = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const req = JSON.parse(fs.readFileSync(0, "utf8")); const out = { version: ctx.MLKEM.version };
if (req.seed) { const k = kem.keygen(b(req.seed)); out.pk = h(k.publicKey); out.sk = h(k.secretKey);
  const e = kem.encapsulate(k.publicKey, b(req.coins)); out.ct = h(e.cipherText); out.ss = h(e.sharedSecret); }
if (req.c_pk) { const e = kem.encapsulate(b(req.c_pk)); out.js_ct = h(e.cipherText); out.js_ss = h(e.sharedSecret); }
if (req.c_ct) { out.js_dec = h(kem.decapsulate(b(req.c_ct), b(req.js_sk))); }
process.stdout.write(JSON.stringify(out));
"""


def node(req):
    r = subprocess.run(["node", "-e", NODE, str(BUNDLE)], input=json.dumps(req),
                       capture_output=True, text=True, check=True)
    return json.loads(r.stdout)


@pytest.mark.parametrize("trial", range(3))
def test_identical_output_from_identical_randomness(trial):
    seed, coins = os.urandom(64), os.urandom(32)
    js = node({"seed": seed.hex(), "coins": coins.hex()})
    pk, sk = ML_KEM_768.keypair(seed)
    ct, ss = ML_KEM_768.encaps(pk, coins)
    assert js["pk"] == pk.hex()
    assert js["sk"] == sk.hex()
    assert js["ct"] == ct.hex()
    assert js["ss"] == ss.hex()


def test_browser_encaps_c_decaps_and_back():
    pk, sk = ML_KEM_768.keypair()
    js_pk_seed = os.urandom(64)
    js_pk, js_sk = ML_KEM_768.keypair(js_pk_seed)  # same key the JS side derives from the seed
    c_ct, c_ss = ML_KEM_768.encaps(js_pk)
    js = node({"seed": js_pk_seed.hex(), "coins": os.urandom(32).hex(),
               "c_pk": pk.hex(), "c_ct": c_ct.hex(), "js_sk": js_sk.hex()})
    assert ML_KEM_768.decaps(bytes.fromhex(js["js_ct"]), sk).hex() == js["js_ss"]   # JS -> C
    assert js["js_dec"] == c_ss.hex()                                               # C -> JS
