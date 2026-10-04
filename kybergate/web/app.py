"""kybergate website: sign-up and log-in protected with ML-KEM-768.

Protocol (one round trip after the handshake)

  browser                                         server
  -------                                         ------
  POST /api/kex {purpose}               ->        fresh Kyber768 key pair, sk stored
                                        <-        {kid, public_key}
  (ct, ss) = ML-KEM.encaps(public_key)
  key = HKDF-SHA256(ss, salt=kid, info="kybergate/v1/web/<purpose>")
  box = AES-256-GCM(key, iv, json(credentials), aad="<purpose>|<kid>")
  POST /api/auth/<purpose> {kid, kem_ct, iv, box}  ->  sk = take(kid)  (single use, 2 min TTL)
                                                      ss = Kyber.decaps(kem_ct, sk)   (official C code)
                                                      open box, check scrypt hash

The browser uses @noble/post-quantum; the server uses the pq-crystals
reference code. A login can only succeed if both derive the same secret.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from .. import ASSIGNMENT_MESSAGE, KYBER_UPSTREAM
from ..envelope import derive_key
from ..kem import ML_KEM_768
from ..keys import fingerprint
from .store import Store

HERE = Path(__file__).parent
KEX_TTL = 120
PURPOSES = {"signup", "login", "lab"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


class KexRequest(BaseModel):
    purpose: str


class Sealed(BaseModel):
    kid: str
    kem_ct: str
    iv: str
    box: str


class LabSealed(Sealed):
    client_fp: str = ""


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(400, "Malformed request.")


def key_fp(shared_secret: bytes) -> str:
    """Public fingerprint of a shared secret (the secret itself is never shown)."""
    return hashlib.sha256(b"kybergate/fp" + shared_secret).hexdigest()[:16]


def create_app(database: str | None = None, secret_key: str | None = None) -> FastAPI:
    """`database` is a SQLite file path or a postgresql:// URL. Defaults to
    $DATABASE_URL (set by the Neon integration on Vercel), then $KYBERGATE_DB."""
    app = FastAPI(title="kybergate", docs_url=None, redoc_url=None, openapi_url=None)
    # On Vercel without a database the app folder is read-only, so fall back to
    # /tmp (works, but accounts reset when the instance is recycled).
    default_db = "/tmp/kybergate.db" if os.environ.get("VERCEL") else "instance/kybergate.db"
    store = Store(database or os.environ.get("DATABASE_URL")
                  or os.environ.get("KYBERGATE_DB", default_db))
    app.state.store = store
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret_key or os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        session_cookie="kg_session",
        same_site="strict",
        https_only=os.environ.get("COOKIE_SECURE") == "1",
        max_age=8 * 3600,
    )
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # -- crypto helpers -----------------------------------------------------------
    def unseal(body: Sealed, purpose: str) -> tuple[bytes, dict, bytes]:
        """Decrypt a browser-sealed payload. Returns (plaintext, wire summary, shared secret)."""
        sk = store.take_kex(body.kid, purpose)
        if sk is None:
            raise HTTPException(400, "Secure channel expired or already used. Please try again.")
        kem_ct, iv, box = unb64(body.kem_ct), unb64(body.iv), unb64(body.box)
        try:
            ss = ML_KEM_768.decaps(kem_ct, sk)
            key = derive_key(ss, body.kid.encode(), f"kybergate/v1/web/{purpose}".encode())
            plain = AESGCM(key).decrypt(iv, box, f"{purpose}|{body.kid}".encode())
        except (ValueError, InvalidTag):
            raise HTTPException(400, "Encrypted request could not be opened (tampered or wrong key).")
        wire = {"kem_ct_len": len(kem_ct), "kem_ct_head": kem_ct[:20].hex(), "iv": iv.hex(),
                "box_b64": body.box, "key_fp": key_fp(ss)}
        return plain, wire, ss

    def unseal_credentials(body: Sealed, purpose: str) -> tuple[str, str, dict]:
        plain, wire, _ = unseal(body, purpose)
        try:
            creds = json.loads(plain)
            return str(creds["username"]).strip(), str(creds["password"]), wire
        except (ValueError, KeyError, TypeError):
            raise HTTPException(400, "Malformed credentials.")

    def current_user(request: Request):
        name = request.session.get("user")
        return store.get_user(name) if name else None

    def sign_in(request: Request, user, purpose: str, wire: dict):
        store.log_wire(user.id, purpose, wire)
        request.session.clear()
        request.session["user"] = user.username
        return {"ok": True, "redirect": "/vault", "wire": wire}

    # -- pages ----------------------------------------------------------------------
    @app.get("/")
    def index(request: Request):
        return RedirectResponse("/vault" if current_user(request) else "/auth", 303)

    @app.get("/auth")
    def auth_page(request: Request, mode: str = "login"):
        if current_user(request):
            return RedirectResponse("/vault", 303)
        return templates.TemplateResponse(request, "auth.html", {
            "mode": "signup" if mode == "signup" else "login", "upstream": KYBER_UPSTREAM})

    @app.get("/vault")
    def vault(request: Request):
        user = current_user(request)
        if user is None:
            return RedirectResponse("/auth", 303)
        return templates.TemplateResponse(request, "vault.html", {
            "user": user.username, "wire": store.recent_wire(user.id),
            "message": ASSIGNMENT_MESSAGE, "upstream": KYBER_UPSTREAM})

    # -- API --------------------------------------------------------------------------
    @app.post("/api/kex")
    def kex(body: KexRequest, request: Request):
        if body.purpose not in PURPOSES:
            raise HTTPException(400, "Unknown purpose.")
        if body.purpose == "lab" and not current_user(request):
            raise HTTPException(401, "Log in first.")
        pk, sk = ML_KEM_768.keypair()
        kid = secrets.token_urlsafe(18)
        store.put_kex(kid, body.purpose, sk, KEX_TTL)
        return {"kid": kid, "public_key": b64(pk), "algorithm": "ML-KEM-768",
                "fingerprint": fingerprint(pk), "expires_in": KEX_TTL}

    @app.post("/api/auth/signup")
    def signup(body: Sealed, request: Request):
        username, password, wire = unseal_credentials(body, "signup")
        if not USERNAME_RE.fullmatch(username):
            raise HTTPException(400, "Username must be 3-32 letters, digits, dots, dashes or underscores.")
        if len(password) < 8:
            raise HTTPException(400, "Password must be at least 8 characters.")
        user = store.create_user(username, password)
        if user is None:
            raise HTTPException(409, "That username is already taken.")
        return sign_in(request, user, "signup", wire)

    @app.post("/api/auth/login")
    def login(body: Sealed, request: Request):
        username, password, wire = unseal_credentials(body, "login")
        user, reason = store.authenticate(username, password)
        if reason == "locked":
            raise HTTPException(429, f"Too many failed attempts. Try again in {Store.LOCK_SECONDS} seconds.")
        if user is None:
            raise HTTPException(401, "Incorrect username or password.")
        return sign_in(request, user, "login", wire)

    @app.post("/api/logout")
    def logout(request: Request):
        request.session.clear()
        return {"ok": True, "redirect": "/auth"}

    @app.post("/api/lab")
    def lab(body: LabSealed, request: Request):
        """The browser sealed a message with ML-KEM; open it here with the C code.
        The message is encrypted as raw UTF-8, so the ciphertext is len(message) + 16 bytes."""
        if not current_user(request):
            raise HTTPException(401, "Log in first.")
        plain, wire, ss = unseal(body, "lab")
        message = plain.decode("utf-8", errors="replace")
        box = unb64(body.box)
        # Tamper check: same key, one flipped bit in the ciphertext must fail.
        key = derive_key(ss, body.kid.encode(), b"kybergate/v1/web/lab")
        try:
            AESGCM(key).decrypt(unb64(body.iv), bytes([box[0] ^ 1]) + box[1:], f"lab|{body.kid}".encode())
            tamper_rejected = False
        except InvalidTag:
            tamper_rejected = True
        return {
            "decrypted": message,
            "ciphertext_hex": box.hex(),
            "ciphertext_b64": body.box,
            "ciphertext_bytes": len(box),
            "kem_ct_bytes": wire["kem_ct_len"],
            "iv": wire["iv"],
            "server_fp": wire["key_fp"],
            "fp_match": secrets.compare_digest(wire["key_fp"], body.client_fp),
            "tamper_rejected": tamper_rejected,
            "server_impl": "pq-crystals/kyber ref (C)",
        }

    @app.exception_handler(HTTPException)
    async def json_errors(request: Request, exc: HTTPException):
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    return app
