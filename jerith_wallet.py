"""Jerith Coin wallet security: encryption at rest, password + TOTP 2FA,
auto-sign policy, export and rebind gating.

Threat model / layering:
  - Layer 1 (node hot key): random master key in keys/master.key (chmod 600)
    encrypts every wallet secret in the DB. Protects against DB-file theft.
  - Layer 2 (user sovereignty): the secret is ALSO wrapped with a key derived
    from the user's password (scrypt, AES-256-GCM). Export/rebind/large-sign
    require password + TOTP, so the node alone cannot hand out keys.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import struct
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ------------------------------------------------------------------ config ---
AUTO_SIGN_DEFAULT_UJ = 100 * 1_000_000        # 100 JER
AUTO_SIGN_DAILY_CAP_UJ = 2_000 * 1_000_000    # 2000 JER/day auto-sign budget
EXPORT_COOLDOWN_S = 3600                      # key export at most once/hour
REBIND_COOLDOWN_S = 3600
OWNER_DISCORD_ID = "285471197825859584"


# ------------------------------------------------------------- primitives ---
def _aesgcm(key: bytes) -> AESGCM:
    return AESGCM(key)


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + _aesgcm(key).encrypt(nonce, plaintext, None)


def aes_decrypt(key: bytes, blob: bytes) -> bytes:
    return _aesgcm(key).decrypt(blob[:12], blob[12:], None)


SCRYPT_MAXMEM = 64 * 1024 * 1024  # OpenSSL default cap is exactly at our N need


def scrypt_key(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt,
                          n=2**15, r=8, p=1, dklen=32, maxmem=SCRYPT_MAXMEM)


def wrap_with_password(sk: bytes, password: str) -> dict:
    """Second-layer wrap of the secret key with a password."""
    salt = secrets.token_bytes(16)
    key = scrypt_key(password, salt)
    nonce = secrets.token_bytes(12)
    ct = _aesgcm(key).encrypt(nonce, sk, None)
    return {"salt": salt.hex(), "nonce": nonce.hex(), "ct": ct.hex()}


def unwrap_with_password(wrapped: dict, password: str) -> bytes:
    key = scrypt_key(password, bytes.fromhex(wrapped["salt"]))
    return _aesgcm(key).decrypt(bytes.fromhex(wrapped["nonce"]),
                                bytes.fromhex(wrapped["ct"]), None)


def hash_password(password: str, salt: bytes | None = None) -> dict:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1,
                        dklen=32, maxmem=SCRYPT_MAXMEM)
    return {"salt": salt.hex(), "hash": dk.hex()}


def verify_password(password: str, stored: dict) -> bool:
    dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(stored["salt"]),
                        n=2**15, r=8, p=1, dklen=32, maxmem=SCRYPT_MAXMEM)
    return hmac.compare_digest(dk.hex(), stored["hash"])


# ------------------------------------------------------------------- TOTP ---
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def totp_generate_secret() -> str:
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode().rstrip("=")


def totp_code(secret_b32: str, at: int | None = None, step: int = 30) -> str:
    at = at or int(time.time())
    pad = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32.upper() + pad)
    counter = struct.pack(">Q", at // step)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def totp_verify(secret_b32: str, code: str, window: int = 1) -> bool:
    code = code.strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return False
    now = int(time.time())
    return any(hmac.compare_digest(totp_code(secret_b32, now + i * 30), code)
               for i in range(-window, window + 1))


def otpauth_uri(secret_b32: str, account: str, issuer: str = "JerithCoin") -> str:
    from urllib.parse import quote
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}"
            f"?secret={secret_b32}&issuer={quote(issuer)}&algorithm=SHA1"
            f"&digits=6&period=30")


# ------------------------------------------------------------- master key ---
def load_or_create_master_key(keys_dir: str) -> bytes:
    os.makedirs(keys_dir, exist_ok=True)
    path = os.path.join(keys_dir, "master.key")
    if os.path.exists(path):
        with open(path, "rb") as f:
            key = f.read()
        if len(key) != 32:
            raise RuntimeError("master.key corrupted")
        return key
    key = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


def load_or_create_api_token(keys_dir: str) -> str:
    os.makedirs(keys_dir, exist_ok=True)
    path = os.path.join(keys_dir, "api.token")
    if os.path.exists(path):
        with open(path) as f:
            tok = f.read().strip()
        if tok:
            return tok
    tok = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(tok)
    return tok


# ------------------------------------------------------------- user record ---
@dataclass
class WalletUser:
    discord_id: str
    address: str
    vk_hex: str
    enc_sk: bytes                  # AES(master) of 64B secret
    wrapped_sk: dict | None        # password wrap (set when user sets password)
    password_stored: dict | None   # scrypt hash for verification
    totp_enc: bytes | None         # AES(master) of b32 secret
    totp_confirmed: bool
    auto_sign_limit: int
    daily_spent: int
    daily_date: str
    opted_in: bool
    created_at: int
    last_export: int
    last_rebind: int

    DDL = """
    CREATE TABLE IF NOT EXISTS users (
        discord_id TEXT PRIMARY KEY,
        address TEXT UNIQUE NOT NULL,
        vk_hex TEXT NOT NULL,
        enc_sk BLOB NOT NULL,
        wrapped_sk TEXT,
        password_stored TEXT,
        totp_enc BLOB,
        totp_confirmed INTEGER NOT NULL DEFAULT 0,
        auto_sign_limit INTEGER NOT NULL,
        daily_spent INTEGER NOT NULL DEFAULT 0,
        daily_date TEXT NOT NULL DEFAULT '',
        opted_in INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        last_export INTEGER NOT NULL DEFAULT 0,
        last_rebind INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS mining_state (
        discord_id TEXT PRIMARY KEY,
        last_success INTEGER NOT NULL DEFAULT 0,
        last_fail INTEGER NOT NULL DEFAULT 0,
        success_count INTEGER NOT NULL DEFAULT 0,
        fail_count INTEGER NOT NULL DEFAULT 0,
        total_mined INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        type TEXT NOT NULL,
        discord_id TEXT,
        details TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS seen_messages (
        message_id TEXT PRIMARY KEY,
        ts INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_seen_ts ON seen_messages(ts);
    """

    @staticmethod
    def create_tables(conn: sqlite3.Connection) -> None:
        conn.executescript(WalletUser.DDL)


def daily_auto_budget_left(user: WalletUser, now: int | None = None) -> int:
    now = now or int(time.time())
    today = time.strftime("%Y-%m-%d", time.gmtime(now))
    spent = user.daily_spent if user.daily_date == today else 0
    return max(0, AUTO_SIGN_DAILY_CAP_UJ - spent)


def auto_sign_allowed(user: WalletUser, amount_uj: int, now: int | None = None) -> tuple[bool, str]:
    if amount_uj <= 0:
        return False, "amount must be positive"
    if amount_uj > user.auto_sign_limit:
        return False, (f"amount {amount_uj/1e6:.2f} JER exceeds auto-sign limit "
                       f"{user.auto_sign_limit/1e6:.2f} JER — password + 2FA required")
    left = daily_auto_budget_left(user, now)
    if amount_uj > left:
        return False, (f"daily auto-sign budget exhausted ({left/1e6:.2f} JER left today) "
                       "— password + 2FA required")
    return True, "ok"
