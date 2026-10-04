"""Save and load Kyber key pairs as armored text files (name.pub / name.key)."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .envelope import armor, dearmor
from .kem import Kyber

PUB_LABEL = "KYBERGATE PUBLIC KEY"
SEC_LABEL = "KYBERGATE SECRET KEY"


def fingerprint(public_key: bytes) -> str:
    """Short, human-comparable SHA-256 fingerprint, e.g. 3f2a:91c0:..."""
    h = hashlib.sha256(public_key).hexdigest()[:20]
    return ":".join(h[i:i + 4] for i in range(0, 20, 4))


def write_keypair(stem: str | Path, level: int, pk: bytes, sk: bytes) -> tuple[Path, Path]:
    stem = Path(stem)
    stem.parent.mkdir(parents=True, exist_ok=True)
    meta = {"Level": str(level), "Fingerprint": fingerprint(pk)}
    pub, sec = stem.with_suffix(".pub"), stem.with_suffix(".key")
    pub.write_text(armor(PUB_LABEL, pk, meta))
    sec.write_text(armor(SEC_LABEL, sk, meta))
    os.chmod(sec, 0o600)
    return pub, sec


def read_key(path: str | Path, label: str) -> tuple[int, bytes]:
    _, headers, data = dearmor(Path(path).read_text(), label)
    level = int(headers.get("Level", "768"))
    kem = Kyber(level)
    want = kem.public_key_bytes if label == PUB_LABEL else kem.secret_key_bytes
    if len(data) != want:
        raise ValueError(f"{path}: {kem.name} key must be {want} bytes, got {len(data)}")
    return level, data


def read_public(path):
    return read_key(path, PUB_LABEL)


def read_secret(path):
    return read_key(path, SEC_LABEL)
