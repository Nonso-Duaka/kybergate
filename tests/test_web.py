"""Website protocol tests. `client_seal` does in Python exactly what
static/js/kyber-client.js does in the browser."""
import base64
import json
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

from kybergate import ASSIGNMENT_MESSAGE
from kybergate.envelope import derive_key
from kybergate.kem import ML_KEM_768
from kybergate.web.app import create_app, key_fp
from kybergate.web.store import Store, check_password, hash_password


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(str(tmp_path / "kg.db"), "test-secret")) as c:
        yield c


def b64(x):
    return base64.b64encode(x).decode()


def client_seal(client, purpose, payload, tamper=False, kex_purpose=None):
    kx = client.post("/api/kex", json={"purpose": kex_purpose or purpose}).json()
    ct, ss = ML_KEM_768.encaps(base64.b64decode(kx["public_key"]))
    key = derive_key(ss, kx["kid"].encode(), f"kybergate/v1/web/{purpose}".encode())
    iv = os.urandom(12)
    data = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
    box = AESGCM(key).encrypt(iv, data, f"{purpose}|{kx['kid']}".encode())
    if tamper:
        box = bytes([box[0] ^ 1]) + box[1:]
    return {"kid": kx["kid"], "kem_ct": b64(ct), "iv": b64(iv), "box": b64(box)}, ss


def signup(client, user="nonso", pw="kyber-rocks-2026"):
    body, _ = client_seal(client, "signup", {"username": user, "password": pw})
    return client.post("/api/auth/signup", json=body), body


def login(client, user="nonso", pw="kyber-rocks-2026", **kw):
    body, _ = client_seal(client, "login", {"username": user, "password": pw}, **kw)
    return client.post("/api/auth/login", json=body), body


def test_password_hashing():
    h = hash_password("hunter22")
    assert h.startswith("scrypt$") and "hunter22" not in h
    assert check_password("hunter22", h) and not check_password("hunter23", h)
    assert not check_password("x", "garbage")


def test_signup_login_logout(client):
    r, _ = signup(client)
    assert r.status_code == 200 and r.json()["redirect"] == "/vault"
    assert r.json()["wire"]["kem_ct_len"] == 1088
    page = client.get("/vault").text
    assert "nonso" in page and "crossed the wire" in page
    client.post("/api/logout")
    assert client.get("/vault", follow_redirects=False).status_code == 303
    r, _ = login(client)
    assert r.status_code == 200


def test_credentials_never_cross_the_wire_in_clear(client):
    _, body = signup(client, "dora", "Sup3r-Secret-Pass")
    raw = json.dumps(body)
    assert "Sup3r-Secret-Pass" not in raw and "dora" not in raw


def test_wrong_password_rejected(client):
    signup(client)
    client.post("/api/logout")
    r, _ = login(client, pw="not-the-password")
    assert r.status_code == 401 and "Incorrect" in r.json()["error"]


def test_unknown_user_gets_same_error(client):
    r, _ = login(client, user="ghost")
    assert r.status_code == 401 and "Incorrect" in r.json()["error"]


def test_lockout_after_repeated_failures(client):
    signup(client)
    client.post("/api/logout")
    codes = [login(client, pw=f"wrong-{i}")[0].status_code for i in range(Store.MAX_FAILED)]
    assert codes[-1] == 429 and set(codes[:-1]) == {401}
    assert login(client)[0].status_code == 429  # even the right password, while locked


def test_duplicate_and_invalid_signups(client):
    signup(client)
    client.post("/api/logout")
    assert signup(client, "NONSO")[0].status_code == 409  # usernames are case-insensitive
    assert signup(client, "x")[0].status_code == 400
    assert signup(client, "eve", "short")[0].status_code == 400


def test_tampered_request_rejected(client):
    signup(client)
    client.post("/api/logout")
    r, _ = login(client, tamper=True)
    assert r.status_code == 400 and "tampered" in r.json()["error"]


def test_handshake_key_is_single_use(client):
    signup(client)
    client.post("/api/logout")
    r, body = login(client)
    assert r.status_code == 200
    client.post("/api/logout")
    assert client.post("/api/auth/login", json=body).status_code == 400


def test_handshake_key_is_bound_to_its_purpose(client):
    # A key issued for sign-up cannot be used to log in.
    r, _ = login(client, kex_purpose="signup")
    assert r.status_code == 400


def test_expired_handshake_rejected(client, monkeypatch):
    body, _ = client_seal(client, "signup", {"username": "late", "password": "password123"})
    import kybergate.web.store as store_mod
    real = store_mod.time.time
    monkeypatch.setattr(store_mod.time, "time", lambda: real() + 3600)
    assert client.post("/api/auth/signup", json=body).status_code == 400


def test_garbage_input_is_a_clean_400(client):
    kx = client.post("/api/kex", json={"purpose": "login"}).json()
    r = client.post("/api/auth/login", json={"kid": kx["kid"], "kem_ct": "!!!", "iv": "", "box": ""})
    assert r.status_code == 400
    assert client.post("/api/kex", json={"purpose": "admin"}).status_code == 400


def test_credentials_must_be_json(client):
    body, _ = client_seal(client, "login", "not json")
    assert client.post("/api/auth/login", json=body).status_code == 400


def test_lab_requires_login(client):
    assert client.post("/api/kex", json={"purpose": "lab"}).status_code == 401


def test_lab_opens_browser_sealed_message(client):
    signup(client)
    body, ss = client_seal(client, "lab", ASSIGNMENT_MESSAGE)
    body["client_fp"] = key_fp(ss)
    r = client.post("/api/lab", json=body).json()
    assert r["decrypted"] == ASSIGNMENT_MESSAGE
    assert r["ciphertext_bytes"] == len(ASSIGNMENT_MESSAGE) + 16
    assert r["fp_match"] and r["tamper_rejected"]
    assert ASSIGNMENT_MESSAGE not in json.dumps(body)


def test_security_headers(client):
    h = client.get("/auth").headers
    assert "script-src 'self'" in h["content-security-policy"]
    assert h["x-content-type-options"] == "nosniff"
