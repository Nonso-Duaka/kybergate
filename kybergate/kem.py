"""ctypes bridge to the official CRYSTALS-Kyber reference implementation.

`make` compiles third_party/pq-crystals-kyber/ref three times (K = 2, 3, 4) into
kybergate/_native/libkyber{512,768,1024}.so. Each library exports the five
functions of the upstream api.h; this module wraps them in a small class:

    kem = Kyber(768)
    pk, sk = kem.keypair()
    ct, ss = kem.encaps(pk)
    ss2    = kem.decaps(ct, sk)          # == ss

The *_derand variants take caller-supplied randomness. They are only used by
the tests, to prove that the browser library produces byte-identical output.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_NATIVE = Path(__file__).with_name("_native")

# Sizes from FIPS 203 / upstream api.h:  (public key, secret key, ciphertext)
_SIZES = {
    512: (800, 1632, 768),
    768: (1184, 2400, 1088),
    1024: (1568, 3168, 1568),
}
SHARED_SECRET_BYTES = 32
NIST_CATEGORY = {512: 1, 768: 3, 1024: 5}


class KyberError(RuntimeError):
    pass


@dataclass(frozen=True)
class Kyber:
    level: int

    def __post_init__(self):
        if self.level not in _SIZES:
            raise ValueError(f"Kyber level must be one of {sorted(_SIZES)}")

    # -- sizes -----------------------------------------------------------
    @property
    def public_key_bytes(self) -> int:
        return _SIZES[self.level][0]

    @property
    def secret_key_bytes(self) -> int:
        return _SIZES[self.level][1]

    @property
    def ciphertext_bytes(self) -> int:
        return _SIZES[self.level][2]

    @property
    def name(self) -> str:
        return f"ML-KEM-{self.level}"

    # -- operations ------------------------------------------------------
    def keypair(self, coins: bytes | None = None) -> tuple[bytes, bytes]:
        pk = ctypes.create_string_buffer(self.public_key_bytes)
        sk = ctypes.create_string_buffer(self.secret_key_bytes)
        if coins is None:
            rc = self._fn("keypair")(pk, sk)
        else:
            _expect(coins, 64, "keypair coins")
            rc = self._fn("keypair_derand")(pk, sk, coins)
        if rc != 0:
            raise KyberError("key generation failed")
        return pk.raw, sk.raw

    def encaps(self, public_key: bytes, coins: bytes | None = None) -> tuple[bytes, bytes]:
        _expect(public_key, self.public_key_bytes, "public key")
        ct = ctypes.create_string_buffer(self.ciphertext_bytes)
        ss = ctypes.create_string_buffer(SHARED_SECRET_BYTES)
        if coins is None:
            rc = self._fn("enc")(ct, ss, public_key)
        else:
            _expect(coins, 32, "encapsulation coins")
            rc = self._fn("enc_derand")(ct, ss, public_key, coins)
        if rc != 0:
            raise KyberError("encapsulation failed")
        return ct.raw, ss.raw

    def decaps(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        # ML-KEM uses implicit rejection: a bad ciphertext does not raise, it
        # yields an unrelated pseudo-random secret, so the AEAD layer fails later.
        _expect(ciphertext, self.ciphertext_bytes, "ciphertext")
        _expect(secret_key, self.secret_key_bytes, "secret key")
        ss = ctypes.create_string_buffer(SHARED_SECRET_BYTES)
        if self._fn("dec")(ss, ciphertext, secret_key) != 0:
            raise KyberError("decapsulation failed")
        return ss.raw

    def _fn(self, op: str):
        return getattr(_library(self.level), f"pqcrystals_kyber{self.level}_ref_{op}")


def _expect(value: bytes, size: int, what: str) -> None:
    if not isinstance(value, (bytes, bytearray)) or len(value) != size:
        got = len(value) if isinstance(value, (bytes, bytearray)) else type(value).__name__
        raise ValueError(f"{what} must be {size} bytes, got {got}")


@lru_cache(maxsize=None)
def _library(level: int) -> ctypes.CDLL:
    path = _NATIVE / f"libkyber{level}.so"
    try:
        lib = ctypes.CDLL(str(path))
    except OSError as exc:
        raise ImportError(f"{path} is missing - run `make` to compile the Kyber reference code") from exc
    p = ctypes.c_char_p
    sigs = {"keypair": [p, p], "keypair_derand": [p, p, p],
            "enc": [p, p, p], "enc_derand": [p, p, p, p], "dec": [p, p, p]}
    for op, args in sigs.items():
        fn = getattr(lib, f"pqcrystals_kyber{level}_ref_{op}")
        fn.argtypes, fn.restype = args, ctypes.c_int
    return lib


ML_KEM_768 = Kyber(768)
