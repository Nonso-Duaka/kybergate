import os

import pytest

from kybergate.kem import Kyber

LEVELS = (512, 768, 1024)
SIZES = {512: (800, 1632, 768), 768: (1184, 2400, 1088), 1024: (1568, 3168, 1568)}


@pytest.mark.parametrize("level", LEVELS)
def test_sizes_match_fips_203(level):
    kem = Kyber(level)
    pk, sk = kem.keypair()
    ct, ss = kem.encaps(pk)
    assert (len(pk), len(sk), len(ct)) == SIZES[level]
    assert len(ss) == 32


@pytest.mark.parametrize("level", LEVELS)
def test_encaps_decaps_agree(level):
    kem = Kyber(level)
    for _ in range(25):
        pk, sk = kem.keypair()
        ct, ss = kem.encaps(pk)
        assert kem.decaps(ct, sk) == ss


def test_fresh_randomness_every_time():
    kem = Kyber(768)
    pk, _ = kem.keypair()
    assert kem.keypair()[0] != pk
    assert kem.encaps(pk) != kem.encaps(pk)


def test_wrong_secret_key_gives_unrelated_secret():
    kem = Kyber(768)
    pk, _ = kem.keypair()
    _, other = kem.keypair()
    ct, ss = kem.encaps(pk)
    assert kem.decaps(ct, other) != ss


def test_implicit_rejection_on_corrupted_ciphertext():
    kem = Kyber(768)
    pk, sk = kem.keypair()
    ct, ss = kem.encaps(pk)
    bad = bytearray(ct)
    bad[500] ^= 0x80
    out = kem.decaps(bytes(bad), sk)
    assert out != ss and len(out) == 32  # no exception, just a useless secret


def test_derandomized_api_is_deterministic():
    kem = Kyber(768)
    seed, coins = bytes(range(64)), bytes(range(32))
    pk1, sk1 = kem.keypair(seed)
    pk2, _ = kem.keypair(seed)
    assert pk1 == pk2
    assert kem.encaps(pk1, coins) == kem.encaps(pk1, coins)


@pytest.mark.parametrize("bad", [b"", b"x" * 1183, b"x" * 1185, "not-bytes"])
def test_rejects_bad_lengths(bad):
    with pytest.raises(ValueError):
        Kyber(768).encaps(bad)


def test_rejects_unknown_level():
    with pytest.raises(ValueError):
        Kyber(256)
