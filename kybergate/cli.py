"""kybergate command line.

    python -m kybergate keygen  -o keys/alice [--level 768]
    python -m kybergate seal    --to keys/alice.pub "message" [-o msg.kge]
    python -m kybergate open    --key keys/alice.key msg.kge
    python -m kybergate assignment [--level 768]
    python -m kybergate bench   [--rounds 200]
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import platform
import sys
import textwrap
import time
from pathlib import Path

from . import ASSIGNMENT_MESSAGE, KYBER_UPSTREAM, __version__
from .envelope import EnvelopeError, algorithm_label, dearmor, open_envelope, seal
from .kem import NIST_CATEGORY, Kyber
from .keys import fingerprint, read_public, read_secret, write_keypair

USE_COLOR = sys.stdout.isatty()


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def ok(flag: bool) -> str:
    return c("PASS", "32;1") if flag else c("FAIL", "31;1")


# -- small commands ---------------------------------------------------------------

def cmd_keygen(a):
    kem = Kyber(a.level)
    pk, sk = kem.keypair()
    pub, sec = write_keypair(a.out, a.level, pk, sk)
    print(f"{kem.name} key pair created")
    print(f"  public  {pub}  ({len(pk)} bytes)")
    print(f"  secret  {sec}  ({len(sk)} bytes, keep private)")
    print(f"  fingerprint {fingerprint(pk)}")


def cmd_seal(a):
    level, pk = read_public(a.to)
    text = a.message if a.message is not None else sys.stdin.read()
    env = seal(pk, text.encode(), level)
    out = env.armor()
    if a.out:
        Path(a.out).write_text(out)
        print(f"sealed {len(text.encode())} bytes -> {a.out} ({len(env.to_bytes())} bytes)")
    else:
        sys.stdout.write(out)


def cmd_open(a):
    _, sk = read_secret(a.key)
    _, _, blob = dearmor(Path(a.envelope).read_text(), "KYBERGATE SEALED MESSAGE")
    try:
        print(open_envelope(sk, blob).plaintext.decode())
    except EnvelopeError as exc:
        sys.exit(f"error: {exc}")


def cmd_bench(a):
    print(f"Kyber reference code ({KYBER_UPSTREAM}), {a.rounds} rounds each, {platform.machine()}")
    print(f"{'algorithm':<14}{'NIST cat.':>10}{'pk':>7}{'sk':>7}{'ct':>7}{'keygen':>12}{'encaps':>12}{'decaps':>12}")
    for level in (512, 768, 1024):
        kem = Kyber(level)
        pk, sk = kem.keypair()
        ct, _ = kem.encaps(pk)
        times = []
        for fn in (lambda: kem.keypair(), lambda: kem.encaps(pk), lambda: kem.decaps(ct, sk)):
            t0 = time.perf_counter()
            for _ in range(a.rounds):
                fn()
            times.append((time.perf_counter() - t0) / a.rounds * 1e6)
        print(f"{kem.name:<14}{NIST_CATEGORY[level]:>10}{kem.public_key_bytes:>7}{kem.secret_key_bytes:>7}"
              f"{kem.ciphertext_bytes:>7}" + "".join(f"{t:>9.1f} us" for t in times))


# -- the assignment ---------------------------------------------------------------

def flip(data: bytes, index: int = 0) -> bytes:
    b = bytearray(data)
    b[index] ^= 0x01
    return bytes(b)


def rejected(fn) -> bool:
    try:
        fn()
    except EnvelopeError:
        return True
    return False


def cmd_assignment(a):
    """Encrypt and decrypt the assignment message. Prints only, saves nothing."""
    kem = Kyber(a.level)
    message = a.message

    def block(label: str, value: str, width: int = 64):
        print(f"  {label}")
        for part in textwrap.wrap(value, width):
            print(f"    {part}")

    rule = c("#" * 74, "36")
    print(rule)
    print(c(f"  KYBERGATE  -  {algorithm_label(a.level)}", "1"))
    print(rule)
    print(f"  run at        {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M:%S} UTC")
    print(f"  host          {platform.system()} {platform.release()} {platform.machine()}, Python {platform.python_version()}")
    print(f"  PQC library   {KYBER_UPSTREAM}")
    print(f"  kybergate     v{__version__}")
    print()
    print(f"  plaintext     {message}")
    print()

    # [1] receiver
    pk, sk = kem.keypair()
    print(c("[1] RECEIVER  key generation", "33;1"))
    print(f"  {kem.name}: public key {len(pk)} B, secret key {len(sk)} B")
    print(f"  fingerprint   {fingerprint(pk)}")
    print()

    # [2] sender
    env = seal(pk, message.encode(), a.level)
    blob = env.to_bytes()
    print(c("[2] SENDER  encapsulate + encrypt", "33;1"))
    print(f"  Kyber ciphertext  {len(env.kem_ciphertext)} B   (first 32 B: {env.kem_ciphertext[:32].hex()}...)")
    print(f"  shared secret     {env.shared_secret.hex()}")
    print("  AES key = HKDF-SHA256(shared secret, salt=header, info='kybergate/v1/seal')")
    print(f"  nonce             {env.nonce.hex()}")
    print()
    print(c("  CIPHERTEXT", "1"))
    print(f"  {len(env.ciphertext)} bytes = {len(message.encode())} B message + 16 B GCM tag")
    block("hex", env.ciphertext.hex())
    block("base64", base64.b64encode(env.ciphertext).decode())
    print()

    # [3] receiver opens the serialized envelope (not the sender's in-memory object)
    opened = open_envelope(sk, blob)
    decrypted = opened.plaintext.decode()
    print(c("[3] RECEIVER  decapsulate + decrypt", "33;1"))
    print(f"  shared secret     {opened.shared_secret.hex()}")
    print(c("  DECRYPTED TEXT", "1"))
    print(f"    {decrypted}")
    print()

    # [4] checks
    _, other_sk = kem.keypair()
    n = len(env.kem_ciphertext)
    checks = {
        "shared secrets match (sender == receiver)": opened.shared_secret == env.shared_secret,
        "decrypted text == original plaintext": decrypted == message,
        "plaintext not visible in ciphertext": message.encode() not in blob,
        "1 flipped bit in AES ciphertext is rejected":
            rejected(lambda: open_envelope(sk, blob[:-1] + bytes([blob[-1] ^ 1]))),
        "1 flipped bit in Kyber ciphertext is rejected":
            rejected(lambda: open_envelope(sk, blob[:6] + flip(env.kem_ciphertext, 100) + blob[6 + n:])),
        "a different secret key is rejected": rejected(lambda: open_envelope(other_sk, blob)),
    }
    print(c("[4] CHECKS", "33;1"))
    for name, passed in checks.items():
        print(f"  {ok(passed)}  {name}")
    all_ok = all(checks.values())
    print()
    print(rule)
    print(c("  ALL CHECKS PASSED" if all_ok else "  SOME CHECKS FAILED", "32;1" if all_ok else "31;1"))
    print(rule)
    return 0 if all_ok else 1


# -- entry point --------------------------------------------------------------------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="kybergate", description="Post-quantum message sealing with Kyber (ML-KEM).")
    p.add_argument("--version", action="version", version=f"kybergate {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    level = dict(type=int, choices=(512, 768, 1024), default=768, help="Kyber parameter set (default 768)")

    s = sub.add_parser("keygen", help="create a key pair")
    s.add_argument("-o", "--out", required=True, help="path stem, writes STEM.pub and STEM.key")
    s.add_argument("--level", **level)
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("seal", help="encrypt a message to a public key")
    s.add_argument("--to", required=True, help="recipient .pub file")
    s.add_argument("message", nargs="?", help="text to seal (default: read stdin)")
    s.add_argument("-o", "--out", help="write the armored envelope here")
    s.set_defaults(fn=cmd_seal)

    s = sub.add_parser("open", help="decrypt an envelope with a secret key")
    s.add_argument("--key", required=True, help="your .key file")
    s.add_argument("envelope")
    s.set_defaults(fn=cmd_open)

    s = sub.add_parser("assignment", help="encrypt + decrypt the assignment message (prints only)")
    s.add_argument("--message", default=ASSIGNMENT_MESSAGE)
    s.add_argument("--level", **level)
    s.set_defaults(fn=cmd_assignment)

    s = sub.add_parser("bench", help="time keygen / encaps / decaps for all levels")
    s.add_argument("--rounds", type=int, default=200)
    s.set_defaults(fn=cmd_bench)

    a = p.parse_args(argv)
    try:
        return a.fn(a) or 0
    except (EnvelopeError, ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
