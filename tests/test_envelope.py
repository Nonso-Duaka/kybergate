import pytest

from kybergate import ASSIGNMENT_MESSAGE
from kybergate.cli import main
from kybergate.envelope import EnvelopeError, dearmor, open_envelope, parse, seal
from kybergate.kem import Kyber
from kybergate.keys import read_public, read_secret, write_keypair


@pytest.mark.parametrize("level", (512, 768, 1024))
def test_assignment_message_round_trip(level):
    pk, sk = Kyber(level).keypair()
    env = seal(pk, ASSIGNMENT_MESSAGE.encode(), level)
    blob = env.to_bytes()
    assert ASSIGNMENT_MESSAGE.encode() not in blob
    assert len(env.ciphertext) == len(ASSIGNMENT_MESSAGE) + 16
    opened = open_envelope(sk, blob)
    assert opened.plaintext.decode() == ASSIGNMENT_MESSAGE
    assert opened.shared_secret == env.shared_secret


def test_armor_round_trip():
    pk, sk = Kyber(768).keypair()
    text = seal(pk, b"hello", 768).armor()
    label, headers, blob = dearmor(text)
    assert label == "KYBERGATE SEALED MESSAGE" and "ML-KEM-768" in headers["Algorithm"]
    assert open_envelope(sk, blob).plaintext == b"hello"


@pytest.mark.parametrize("where", ["kem", "nonce", "body", "tag"])
def test_any_flipped_bit_is_rejected(where):
    pk, sk = Kyber(768).keypair()
    blob = bytearray(seal(pk, b"attack at dawn", 768).to_bytes())
    index = {"kem": 6 + 10, "nonce": 6 + 1088 + 3, "body": 6 + 1088 + 12 + 2, "tag": len(blob) - 1}[where]
    blob[index] ^= 0x01
    with pytest.raises(EnvelopeError):
        open_envelope(sk, bytes(blob))


def test_wrong_key_is_rejected():
    pk, _ = Kyber(768).keypair()
    _, sk = Kyber(768).keypair()
    with pytest.raises(EnvelopeError):
        open_envelope(sk, seal(pk, b"x", 768).to_bytes())


def test_malformed_envelopes():
    with pytest.raises(EnvelopeError):
        parse(b"nope")
    with pytest.raises(EnvelopeError):
        parse(b"KGE1\x01\x00" + b"\x00" * 2000)  # level 256
    pk, _ = Kyber(768).keypair()
    with pytest.raises(EnvelopeError):
        parse(seal(pk, b"x", 768).to_bytes()[:1000])


def test_keyfiles_round_trip(tmp_path):
    pk, sk = Kyber(1024).keypair()
    pub, sec = write_keypair(tmp_path / "bob", 1024, pk, sk)
    assert read_public(pub) == (1024, pk)
    assert read_secret(sec) == (1024, sk)
    with pytest.raises(EnvelopeError):
        read_secret(pub)  # wrong armor label


def test_cli_seal_and_open(tmp_path, capsys):
    stem = tmp_path / "carol"
    assert main(["keygen", "-o", str(stem), "--level", "512"]) == 0
    msg = tmp_path / "m.kge"
    assert main(["seal", "--to", f"{stem}.pub", "quantum hello", "-o", str(msg)]) == 0
    capsys.readouterr()
    assert main(["open", "--key", f"{stem}.key", str(msg)]) == 0
    assert capsys.readouterr().out.strip() == "quantum hello"


def test_cli_assignment_prints_and_saves_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["assignment"]) == 0
    out = capsys.readouterr().out
    assert "DECRYPTED TEXT" in out and ASSIGNMENT_MESSAGE in out
    assert "73 bytes" in out and "ALL CHECKS PASSED" in out and "FAIL" not in out
    assert list(tmp_path.iterdir()) == []
