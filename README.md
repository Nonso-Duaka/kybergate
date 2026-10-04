# kybergate

Post-quantum encryption with **CRYSTALS-Kyber / ML-KEM (NIST FIPS 203)**, built on the
official reference implementation from [pq-crystals/kyber](https://github.com/pq-crystals/kyber).

It has two parts:

1. **A command-line tool** (`python -m kybergate`) that creates Kyber key pairs, seals
   messages into portable armored envelopes, and opens them again. `kybergate assignment`
   encrypts and decrypts *"Dear All Good luck with your Job interview with Bloomberg"* and
   prints every step.
2. **A website** where sign-up and log-in credentials are sealed **in the browser** with
   ML-KEM-768 before they are sent. Once logged in, the *Message lab* page seals any message in
   the browser and the server opens it with the official C code.

---

## Run the assignment

```sh
python -m kybergate assignment
```

It prints the ML-KEM-768 key pair sizes, the Kyber ciphertext, the shared secret on both sides,
the **ciphertext** (hex and base64), the **decrypted text**, and six checks: shared secrets
match, decrypted text equals the original, plaintext not visible in the ciphertext, a flipped
AES bit is rejected, a flipped Kyber bit is rejected, and a different secret key is rejected.
Nothing is written to disk. A fresh key pair is generated on every run, so the ciphertext is
different each time.

The ciphertext is 73 bytes: the 57-byte message plus the 16-byte GCM authentication tag.

### Why Kyber *and* AES?

Kyber is a **key encapsulation mechanism**. It doesn't encrypt a sentence. It lets a sender
and a receiver agree on a random 32-byte secret in a way that resists quantum computers. We run
that secret through HKDF-SHA256 (with a context label) to get an AES-256 key, then encrypt
the message with AES-256-GCM. This KEM + KDF + AEAD pattern (as in HPKE, RFC 9180) is the
standard way to use ML-KEM.

```
 RECEIVER                                    SENDER
 (pk, sk) = ML-KEM.KeyGen()
            ───────────── pk ─────────────▶
                                             (ct, ss) = ML-KEM.Encaps(pk)
                                             key      = HKDF-SHA256(ss, salt=header, info="kybergate/v1/seal")
                                             box      = AES-256-GCM(key, nonce, message, aad=header)
            ◀──── header ‖ ct ‖ nonce ‖ box ──
 ss  = ML-KEM.Decaps(ct, sk)
 key = HKDF-SHA256(ss, ...)
 message = AES-256-GCM-Open(key, nonce, box)
```

---

## The command-line tool

```sh
python -m kybergate keygen -o keys/alice --level 1024     # alice.pub / alice.key (armored)
python -m kybergate seal --to keys/alice.pub "hello" -o hello.kge
python -m kybergate open --key keys/alice.key hello.kge
python -m kybergate assignment                            # the assignment run (prints only)
python -m kybergate bench                                 # timing for 512 / 768 / 1024
```

All three parameter sets are supported (`--level 512|768|1024`, NIST security categories 1/3/5).
Keys and envelopes are ASCII-armored text files, so they can be pasted into an email.

**Envelope format v1:** `"KGE1"` ‖ level (2 bytes) ‖ Kyber ciphertext ‖ 12-byte nonce ‖
AES-GCM output. The 6-byte header is both the HKDF salt and the GCM associated data, so the
parameter set cannot be changed without decryption failing.

---

## The website

```
 browser (@noble/post-quantum, WebCrypto)              server (FastAPI + official C code)
 ─────────────────────────────────────────              ─────────────────────────────────
 POST /api/kex {purpose}                       ──▶    fresh ML-KEM-768 key pair; sk saved in
                                               ◀──    SQLite under a random kid (2 min, single use)
 (ct, ss) = encapsulate(pk)
 key = HKDF-SHA256(ss, salt=kid, info="kybergate/v1/web/<purpose>")
 box = AES-256-GCM(key, iv, {username,password}, aad="<purpose>|<kid>")
 POST /api/auth/<purpose> {kid, kem_ct, iv, box} ──▶  sk = take(kid)  → decaps → HKDF → open box
                                                      → scrypt password check
```

* **Only ciphertext crosses the wire.** The *Wire inspector* next to the form shows the exact
  request body as it is sent, so you can see that no readable username or password is in it.
* **Two independent implementations must agree.** The browser uses
  [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) (JavaScript). The server
  uses the pq-crystals C code. A login can only succeed if both derive the same secret.
* **Handshake keys are single-use, expire, and are bound to a purpose.** A replayed request, a
  sign-up key used for a login, or a request older than 2 minutes is rejected.
* **Accounts:** scrypt password hashes (N=2¹⁴, r=8, p=1). After 5 failed attempts the account
  is locked for 60 seconds. Unknown usernames take the same time and get the same error as a
  wrong password.
* **Hardening:** strict Content-Security-Policy (no inline scripts), `SameSite=Strict` session
  cookie, `no-store` caching.
* **Message lab** (after login): the browser seals the message as raw UTF-8, and the server opens
  it with the C code. The page shows the ciphertext (hex and base64), the decrypted text, and both
  sides' secret fingerprints, plus a server-side check that a flipped bit is rejected.
* **Sign-in history:** the vault lists what each of your sign-ins looked like on the wire.

---

## Tests

The pytest suite covers:

* **KEM** (`test_kem.py`): FIPS 203 sizes for all levels, encaps/decaps agreement, implicit
  rejection, wrong key, the deterministic API, and input validation.
* **Envelope and CLI** (`test_envelope.py`): round trip at every level. A flipped bit anywhere
  (Kyber ciphertext, nonce, body, tag) is rejected. Also covers malformed or truncated input,
  key files, `seal`/`open`, and that `assignment` passes all checks without writing any files.
* **Website protocol** (`test_web.py`): sign-up, login, logout, wrong password, lockout,
  duplicates, tampering, replay, purpose binding, expiry, the lab, and security headers.
* **Browser** (`tests/e2e/run_e2e.py`, Playwright): sign up, message lab, wrong password, log in.
  Every `/api/` request is searched for the password, username and message (none may appear),
  and the run fails on any browser console error.
* **Cross-implementation** (`test_interop.py`): from the same random seed, the browser bundle
  (noble JS) and the C reference code produce **byte-identical** public keys, secret keys,
  ciphertexts and shared secrets. They also interoperate in both directions (JS→C and C→JS).

---

## Run it

Needs Python 3.10+ and a C compiler. Node.js is only needed for the interop test and for
rebuilding the browser bundle.

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
make                       # compile kyber ref → kybergate/_native/libkyber{512,768,1024}.so
.venv/bin/python -m kybergate assignment
make kat                   # official Kyber self-tests + test vectors
make test                  # pytest

.venv/bin/uvicorn kybergate.web.asgi:app --reload     # http://127.0.0.1:8000

.venv/bin/playwright install chromium
make e2e                   # browser test (starts its own server, saves nothing)
.venv/bin/python tests/e2e/run_e2e.py --base https://your-deployed-site   # test a deployed copy
```

## Deploy

The `Dockerfile` is a two-stage build. The first stage compiles the Kyber code, runs the
official known-answer tests and pytest, and fails the build if any of them fail. The runtime
stage has no compiler. Set `SECRET_KEY` and deploy it to any container host (Render, Railway,
Fly.io, …). Because handshake keys are stored in SQLite, the container runs two workers.
Mount a volume at `/app/instance` if accounts should survive a redeploy.

## Layout

```
third_party/pq-crystals-kyber/   official Kyber source, unmodified (ref/, LICENSE, SHA256SUMS)
kybergate/kem.py                 ctypes bridge: Kyber(level).keypair / encaps / decaps
kybergate/envelope.py            HKDF + AES-GCM envelopes and ASCII armor
kybergate/keys.py                armored key files and fingerprints
kybergate/cli.py                 keygen / seal / open / assignment / bench
kybergate/kat.py                 runs the official upstream tests
kybergate/web/                   FastAPI app, SQLite store, templates, browser JS/CSS
kybergate/web/static/vendor/     ML-KEM-768 bundle built from @noble/post-quantum
tools/vendor/                    how that bundle is built (make vendor)
tests/                           pytest suites and the Playwright browser test
```

## Limitations

This is a teaching demo, not a production identity system.

* The server's one-time public key is not signed, so the Kyber layer by itself does not
  authenticate the server. In deployment HTTPS does that. Kyber adds post-quantum
  confidentiality for the credentials inside it.
* The upstream authors say the reference code is meant for clarity, not production use, and
  point to [mlkem-native](https://github.com/pq-code-package/mlkem-native) for production.
* SQLite works for a single host. Several hosts would need a shared database.

## Credits

* CRYSTALS-Kyber reference implementation, the Kyber team, CC0 / Apache-2.0 (`third_party/pq-crystals-kyber/LICENSE`)
* `@noble/post-quantum` by Paul Miller, MIT (`kybergate/web/static/vendor/LICENSE-noble-post-quantum`)
