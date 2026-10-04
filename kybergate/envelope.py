"""Sealed envelopes: Kyber (ML-KEM) key agreement + HKDF-SHA256 + AES-256-GCM.

Kyber is a KEM, not a cipher: it gives sender and receiver the same random
32-byte secret. We never use that secret directly as a cipher key. It is run
through HKDF with a context label, and the derived key drives AES-256-GCM.

Binary layout of a sealed envelope (version 1)

    offset  size            field
    0       4               magic  b"KGE1"
    4       2               Kyber level, big-endian (512 / 768 / 1024)
    6       ciphertext_len  Kyber ciphertext (encapsulated key)
    ...     12              AES-GCM nonce
    ...     rest            AES-GCM ciphertext (message + 16-byte tag)

The 6-byte header is both the HKDF salt and the GCM associated data, so the
level cannot be swapped without decryption failing.
"""
from __future__ import annotations

import base64
import os
import struct
import textwrap
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .kem import Kyber

MAGIC = b"KGE1"
NONCE_BYTES = 12
TAG_BYTES = 16
SEAL_INFO = b"kybergate/v1/seal"


class EnvelopeError(ValueError):
    """The envelope is malformed, was tampered with, or the key is wrong."""


def derive_key(shared_secret: bytes, salt: bytes, info: bytes) -> bytes:
    """HKDF-SHA256 -> 32-byte AES key. Mirrored in static/js/kyber-client.js."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(shared_secret)


@dataclass(frozen=True)
class Sealed:
    level: int
    kem_ciphertext: bytes
    nonce: bytes
    ciphertext: bytes          # AES-GCM output: message + tag
    shared_secret: bytes = b""  # sender-side only, for reports; never serialized

    @property
    def header(self) -> bytes:
        return MAGIC + struct.pack(">H", self.level)

    def to_bytes(self) -> bytes:
        return self.header + self.kem_ciphertext + self.nonce + self.ciphertext

    def armor(self) -> str:
        return armor("KYBERGATE SEALED MESSAGE", self.to_bytes(), {"Algorithm": algorithm_label(self.level)})


@dataclass(frozen=True)
class Opened:
    plaintext: bytes
    shared_secret: bytes


def algorithm_label(level: int) -> str:
    return f"ML-KEM-{level} (Kyber{level}) + HKDF-SHA256 + AES-256-GCM"


def seal(public_key: bytes, plaintext: bytes, level: int = 768) -> Sealed:
    kem = Kyber(level)
    kem_ct, ss = kem.encaps(public_key)
    header = MAGIC + struct.pack(">H", level)
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(derive_key(ss, header, SEAL_INFO)).encrypt(nonce, plaintext, header)
    return Sealed(level, kem_ct, nonce, ct, ss)


def parse(blob: bytes) -> Sealed:
    if len(blob) < 6 or blob[:4] != MAGIC:
        raise EnvelopeError("not a kybergate envelope")
    (level,) = struct.unpack(">H", blob[4:6])
    try:
        kem = Kyber(level)
    except ValueError as exc:
        raise EnvelopeError(str(exc)) from None
    n = kem.ciphertext_bytes
    body = blob[6:]
    if len(body) < n + NONCE_BYTES + TAG_BYTES:
        raise EnvelopeError("envelope is truncated")
    return Sealed(level, body[:n], body[n:n + NONCE_BYTES], body[n + NONCE_BYTES:])


def open_envelope(secret_key: bytes, blob: bytes | Sealed) -> Opened:
    env = blob if isinstance(blob, Sealed) else parse(blob)
    ss = Kyber(env.level).decaps(env.kem_ciphertext, secret_key)
    try:
        pt = AESGCM(derive_key(ss, env.header, SEAL_INFO)).decrypt(env.nonce, env.ciphertext, env.header)
    except InvalidTag:
        raise EnvelopeError("authentication failed: wrong key or tampered envelope") from None
    return Opened(pt, ss)


# -- ASCII armor ----------------------------------------------------------------

def armor(label: str, data: bytes, headers: dict[str, str] | None = None) -> str:
    lines = [f"-----BEGIN {label}-----"]
    lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
    if headers:
        lines.append("")
    lines += textwrap.wrap(base64.b64encode(data).decode(), 64)
    lines.append(f"-----END {label}-----")
    return "\n".join(lines) + "\n"


def dearmor(text: str, label: str | None = None) -> tuple[str, dict[str, str], bytes]:
    lines = [ln.strip() for ln in text.strip().splitlines()]
    if not lines or not lines[0].startswith("-----BEGIN ") or not lines[-1].startswith("-----END "):
        raise EnvelopeError("missing armor lines")
    found = lines[0][len("-----BEGIN "):-5]
    if label and found != label:
        raise EnvelopeError(f"expected {label}, found {found}")
    headers, body = {}, []
    for ln in lines[1:-1]:
        if ": " in ln and not body:
            k, v = ln.split(": ", 1)
            headers[k] = v
        elif ln:
            body.append(ln)
    try:
        return found, headers, base64.b64decode("".join(body), validate=True)
    except ValueError:
        raise EnvelopeError("armor body is not valid base64") from None
