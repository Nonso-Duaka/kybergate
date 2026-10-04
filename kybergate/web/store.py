"""Persistence for the website: SQLite locally, Postgres (Neon) when deployed.

Three tables:
  users     accounts, scrypt password hashes, failed-login lockout
  kex       one-time Kyber key pairs waiting for the browser to use them.
            Kept in the database (not process memory) so any worker or
            serverless instance can finish a handshake another one started.
  wire_log  what the browser actually sent for each sign-in, shown on /vault

Store("path/to.db") uses SQLite; Store("postgresql://...") uses Postgres.
Queries are written once with ? placeholders and translated for Postgres.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    REAL NOT NULL,
    failed        INTEGER NOT NULL DEFAULT 0,
    locked_until  REAL NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_ci ON users (lower(username));
CREATE TABLE IF NOT EXISTS kex (
    kid        TEXT PRIMARY KEY,
    purpose    TEXT NOT NULL,
    secret_key BLOB NOT NULL,
    expires    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS wire_log (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    purpose     TEXT NOT NULL,
    at          REAL NOT NULL,
    kem_ct_len  INTEGER NOT NULL,
    kem_ct_head TEXT NOT NULL,
    iv          TEXT NOT NULL,
    box_b64     TEXT NOT NULL,
    key_fp      TEXT NOT NULL
);
"""

_POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    DOUBLE PRECISION NOT NULL,
    failed        INTEGER NOT NULL DEFAULT 0,
    locked_until  DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_ci ON users (lower(username));
CREATE TABLE IF NOT EXISTS kex (
    kid        TEXT PRIMARY KEY,
    purpose    TEXT NOT NULL,
    secret_key BYTEA NOT NULL,
    expires    DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS wire_log (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id),
    purpose     TEXT NOT NULL,
    at          DOUBLE PRECISION NOT NULL,
    kem_ct_len  INTEGER NOT NULL,
    kem_ct_head TEXT NOT NULL,
    iv          TEXT NOT NULL,
    box_b64     TEXT NOT NULL,
    key_fp      TEXT NOT NULL
);
"""

# scrypt parameters (RFC 7914 interactive-login guidance: N=2^14, r=8, p=1)
_N, _R, _P = 2 ** 14, 8, 1


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def check_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt),
                             n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(got, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


# Spent on unknown usernames so response time does not reveal which names exist.
_DUMMY_HASH = hash_password("kybergate-timing-equaliser")


@dataclass
class User:
    id: int
    username: str
    password_hash: str
    failed: int
    locked_until: float


class _Conn:
    """Tiny adapter so the same SQL (with ? placeholders) runs on both backends."""

    def __init__(self, raw, postgres: bool):
        self.raw, self.postgres = raw, postgres

    def execute(self, sql: str, params: tuple = ()):
        if self.postgres:
            sql = sql.replace("?", "%s")
        return self.raw.execute(sql, params)


class Store:
    MAX_FAILED = 5
    LOCK_SECONDS = 60

    def __init__(self, target: str):
        self.postgres = target.startswith(("postgres://", "postgresql://"))
        if self.postgres:
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool
            # prepare_threshold=None: safe behind Neon's PgBouncer (transaction pooling).
            self._pool = ConnectionPool(target, min_size=0, max_size=4, open=True,
                                        kwargs={"row_factory": dict_row, "prepare_threshold": None})
            self._integrity = __import__("psycopg").errors.UniqueViolation
            with self._db() as db:
                for stmt in filter(str.strip, _POSTGRES_SCHEMA.split(";")):
                    db.execute(stmt)
        else:
            self.path = target
            if os.path.dirname(target):
                os.makedirs(os.path.dirname(target), exist_ok=True)
            self._integrity = sqlite3.IntegrityError
            with self._db() as db:
                db.raw.executescript(_SQLITE_SCHEMA)

    @contextmanager
    def _db(self):
        if self.postgres:
            with self._pool.connection() as raw:  # commits on success, rolls back on error
                yield _Conn(raw, True)
            return
        raw = sqlite3.connect(self.path, timeout=10)
        raw.row_factory = sqlite3.Row
        try:
            with raw:
                yield _Conn(raw, False)
        finally:
            raw.close()

    # -- one-time handshake keys ------------------------------------------------
    def put_kex(self, kid: str, purpose: str, secret_key: bytes, ttl: float) -> None:
        now = time.time()
        with self._db() as db:
            db.execute("DELETE FROM kex WHERE expires < ?", (now,))
            db.execute("INSERT INTO kex (kid, purpose, secret_key, expires) VALUES (?, ?, ?, ?)",
                       (kid, purpose, secret_key, now + ttl))

    def take_kex(self, kid: str, purpose: str) -> bytes | None:
        """Remove and return the secret key. A kid works exactly once."""
        with self._db() as db:
            row = db.execute("DELETE FROM kex WHERE kid = ? RETURNING purpose, secret_key, expires",
                             (kid,)).fetchone()
        if row is None or row["purpose"] != purpose or row["expires"] < time.time():
            return None
        return bytes(row["secret_key"])

    # -- users ------------------------------------------------------------------
    def create_user(self, username: str, password: str) -> User | None:
        try:
            with self._db() as db:
                db.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                           (username, hash_password(password), time.time()))
        except self._integrity:
            return None
        return self.get_user(username)

    def get_user(self, username: str) -> User | None:
        with self._db() as db:
            row = db.execute("SELECT id, username, password_hash, failed, locked_until FROM users "
                             "WHERE lower(username) = lower(?)", (username,)).fetchone()
        return User(**dict(row)) if row else None
    def authenticate(self, username: str, password: str) -> tuple[User | None, str | None]:
        """Returns (user, None) on success or (None, reason) where reason is 'bad' or 'locked'."""
        user = self.get_user(username)
        if user is None:
            check_password(password, _DUMMY_HASH)
            return None, "bad"
        if user.locked_until > time.time():
            return None, "locked"
        if check_password(password, user.password_hash):
            with self._db() as db:
                db.execute("UPDATE users SET failed = 0, locked_until = 0 WHERE id = ?", (user.id,))
            return user, None
        failed = user.failed + 1
        lock = time.time() + self.LOCK_SECONDS if failed >= self.MAX_FAILED else 0
        with self._db() as db:
            db.execute("UPDATE users SET failed = ?, locked_until = ? WHERE id = ?",
                       (0 if lock else failed, lock, user.id))
        return None, "locked" if lock else "bad"

    # -- wire log ---------------------------------------------------------------
    def log_wire(self, user_id: int, purpose: str, wire: dict) -> None:
        with self._db() as db:
            db.execute("INSERT INTO wire_log (user_id, purpose, at, kem_ct_len, kem_ct_head, iv, box_b64, key_fp) "
                       "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       (user_id, purpose, time.time(), wire["kem_ct_len"], wire["kem_ct_head"],
                        wire["iv"], wire["box_b64"], wire["key_fp"]))

    def recent_wire(self, user_id: int, limit: int = 6) -> list[dict]:
        with self._db() as db:
            rows = db.execute("SELECT * FROM wire_log WHERE user_id = ? ORDER BY id DESC LIMIT ?",
                              (user_id, limit)).fetchall()
        return [dict(r) for r in rows]
