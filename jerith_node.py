"""Jerith Coin node: HTTP API + chain writer.

Listens on 127.0.0.1:8300 only. Auth: Authorization: Bearer <token from
keys/api.token>. The OpenClaw agent (Jerith) calls this API on behalf of
Discord users; users never talk to the node directly.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

import jerith_core as core                     # noqa: E402
import jerith_validate
from jerith_validate import validate_block
import jerith_wallet as sec                    # noqa: E402

DATA_DIR = Path(os.environ.get("JERITH_DATA_DIR", BASE_DIR / "data"))
KEYS_DIR = Path(os.environ.get("JERITH_KEYS_DIR", BASE_DIR / "keys"))
DB_PATH = DATA_DIR / "jerith.db"
DATA_DIR.mkdir(parents=True, exist_ok=True)
KEYS_DIR.mkdir(parents=True, exist_ok=True)

COIN_NAME = "Jerith Coin"
TICKER = "JER"
FEE_UJ = 100_000                                # 0.1 JER per transfer (burned)
MINE_REWARD_UJ = 10 * 1_000_000                 # 10 JER per mined block
MINE_COOLDOWN_SUCCESS_S = 300                   # 5 minutes after success
MINE_COOLDOWN_FAIL_S = 180                      # 3 minutes after failure
PASSIVE_SOURCE = "passive"
EXPLICIT_SOURCE = "explicit"
PASSIVE_REWARD_UJ = 2 * 1_000_000               # 2 JER per passive block

MASTER_KEY = sec.load_or_create_master_key(str(KEYS_DIR))
API_TOKEN = sec.load_or_create_api_token(str(KEYS_DIR))

conn = sqlite3.connect(DB_PATH, check_same_thread=False)
conn.execute("PRAGMA journal_mode=WAL")
conn.execute("PRAGMA synchronous=NORMAL")
ledger = core.Ledger(conn)
sec.WalletUser.create_tables(conn)

WRITE_LOCK = threading.RLock()
AUTH_FAILS: dict[str, list[int]] = {}
AUTH_FAIL_LOCK = threading.Lock()
MAX_AUTH_FAILS = 5
AUTH_LOCKOUT_S = 900


def audit(etype: str, discord_id: Optional[str], details: str = "") -> None:
    with WRITE_LOCK:
        conn.execute("INSERT INTO events (ts, type, discord_id, details) VALUES (?,?,?,?)",
                     (int(time.time()), etype, discord_id, details))
        conn.commit()


class _ChainState:
    """Canonical-validator view over the live Ledger: the balance/nonce and
    difficulty the validator sees are the chain's actual current state."""

    def balance_nonce(self, address: str) -> tuple[int, int]:
        return (ledger.balance(address), ledger.nonce(address))

    def total_emitted(self) -> int:
        return core.PREMINE + self._emitted_since_genesis()

    def _emitted_since_genesis(self) -> int:
        row = conn.execute(
            "SELECT COALESCE(SUM(amount),0) FROM txs WHERE kind IN ('mine')").fetchone()
        return int(row[0])

    def expected_difficulty(self) -> int:
        return ledger.next_difficulty()


def _prev_block_view(height: int):
    """Reconstruct the tip block (prev of the candidate) for the validator.
    Returns None only if the chain is empty (candidate is genesis)."""
    row = conn.execute(
        "SELECT height, hash, prev_hash, timestamp, miner, reward, nonce"
        " FROM blocks WHERE height=?", (height - 1,)).fetchone()
    if not row:
        return None
    tx_rows = conn.execute(
        "SELECT kind, sender, recipient, amount, fee, nonce, timestamp, memo,"
        " vk, signature FROM txs WHERE height=?", (row[0],)).fetchall()
    txs = [dict(zip(("kind", "sender", "recipient", "amount", "fee", "nonce",
                     "timestamp", "memo", "vk", "signature"), t))
           for t in tx_rows]
    # column order: height, hash, prev_hash, timestamp, miner, reward, nonce
    return core.Block(height=row[0], prev_hash=row[2], timestamp=row[3],
                      txs=txs, miner=row[4], reward=row[5], nonce=row[6])


# ------------------------------------------------------------------ auth ----
def require_token(authorization: str = Header(default="")) -> None:
    expected = f"Bearer {API_TOKEN}"
    if not authorization or not sec.hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="invalid or missing API token")


app = FastAPI(title="JerithChain Node", version="1.0.0",
              description=f"{COIN_NAME} ({TICKER}) node — internal API for the Jerith agent")


# ------------------------------------------------------------- user helpers --
def get_user(discord_id: str) -> Optional[sec.WalletUser]:
    row = conn.execute(
        """SELECT discord_id, address, vk_hex, enc_sk, wrapped_sk, password_stored,
                  totp_enc, totp_confirmed, auto_sign_limit, daily_spent, daily_date,
                  opted_in, created_at, last_export, last_rebind
           FROM users WHERE discord_id=?""", (discord_id,)).fetchone()
    if not row:
        return None
    return sec.WalletUser(
        discord_id=row[0], address=row[1], vk_hex=row[2], enc_sk=row[3],
        wrapped_sk=json.loads(row[4]) if row[4] else None,
        password_stored=json.loads(row[5]) if row[5] else None,
        totp_enc=row[6], totp_confirmed=bool(row[7]), auto_sign_limit=row[8],
        daily_spent=row[9], daily_date=row[10], opted_in=bool(row[11]),
        created_at=row[12], last_export=row[13], last_rebind=row[14])


def user_from_address(address: str) -> Optional[sec.WalletUser]:
    row = conn.execute("SELECT discord_id FROM users WHERE address=?", (address,)).fetchone()
    return get_user(row[0]) if row else None


def decrypt_sk(user: sec.WalletUser) -> bytes:
    return sec.aes_decrypt(MASTER_KEY, user.enc_sk)


def create_wallet(discord_id: str, password: Optional[str] = None,
                  source: str = "api") -> sec.WalletUser:
    existing = get_user(discord_id)
    if existing:
        return existing
    sk, vk = core.generate_keypair()
    address = core.addr_from_vk(vk)
    enc_sk = sec.aes_encrypt(MASTER_KEY, sk)
    totp_enc = sec.aes_encrypt(MASTER_KEY, sec.totp_generate_secret().encode())
    now = int(time.time())
    with WRITE_LOCK:
        conn.execute(
            """INSERT INTO users (discord_id, address, vk_hex, enc_sk, wrapped_sk,
               password_stored, totp_enc, totp_confirmed, auto_sign_limit,
               daily_spent, daily_date, opted_in, created_at, last_export, last_rebind)
               VALUES (?,?,?,?,NULL,NULL,?,0,?,0,'',1,?,0,0)""",
            (discord_id, address, vk.hex(), enc_sk, totp_enc,
             sec.AUTO_SIGN_DEFAULT_UJ, now))
        conn.execute("INSERT OR IGNORE INTO mining_state (discord_id) VALUES (?)",
                     (discord_id,))
        conn.commit()
    if password:
        set_password(discord_id, "", password, confirm_totp=False)
    audit("wallet.created", discord_id, f"address={address} source={source}")
    return get_user(discord_id)  # type: ignore[return-value]


def ensure_owner_wallet() -> sec.WalletUser:
    owner = get_user(sec.OWNER_DISCORD_ID)
    if owner:
        return owner
    owner = create_wallet(sec.OWNER_DISCORD_ID, source="genesis")
    # emergency offline copy of the owner key (operator is the host owner)
    em = KEYS_DIR / "owner-emergency.hex"
    if not em.exists():
        fd = os.open(em, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(decrypt_sk(owner).hex())
    return owner


def owner_address() -> str:
    return ensure_owner_wallet().address


# ----------------------------------------------------------------- genesis --
def init_chain() -> None:
    if ledger.tip():
        return
    owner = ensure_owner_wallet()
    block = ledger.build_genesis(owner.address, premine_sk=None)
    bhash = ledger.commit_genesis(block)
    audit("chain.genesis", sec.OWNER_DISCORD_ID,
          f"premine={core.PREMINE/1e6:.0f} JER to {owner.address} hash={bhash[:16]}…")


# ------------------------------------------------------------------- mine ---
def _cooldowns(discord_id: str) -> tuple[int, int]:
    row = conn.execute("SELECT last_success, last_fail FROM mining_state WHERE discord_id=?",
                       (discord_id,)).fetchone()
    return (row[0], row[1]) if row else (0, 0)


def mine_attempt(discord_id: str, source: str, guild_id: str = "",
                 channel_id: str = "") -> dict:
    with WRITE_LOCK:   # cooldowns, tip read, PoW and append are one critical section
        now = int(time.time())
        last_ok, last_fail = _cooldowns(discord_id)
        if now - last_ok < MINE_COOLDOWN_SUCCESS_S:
            return {"ok": False, "reason": "cooldown",
                    "message": f"Your last mine succeeded {now-last_ok}s ago. "
                               f"Try again in {MINE_COOLDOWN_SUCCESS_S-(now-last_ok)}s."}
        if now - last_fail < MINE_COOLDOWN_FAIL_S:
            return {"ok": False, "reason": "cooldown",
                    "message": f"Your last mine failed {now-last_fail}s ago. "
                               f"Try again in {MINE_COOLDOWN_FAIL_S-(now-last_fail)}s."}

        user = get_user(discord_id) or create_wallet(discord_id, source=source)
        redirected = not user.opted_in
        credit_addr = user.address if user.opted_in else owner_address()

        height = ledger.next_height()
        reward = core.reward_for_height(height)
        if source == PASSIVE_SOURCE:
            reward = min(reward, PASSIVE_REWARD_UJ)
        remaining = core.MAX_SUPPLY - ledger.circulating()
        if remaining <= 0:
            return {"ok": False, "reason": "supply_exhausted",
                    "message": "Max supply reached — no more JER can be mined."}
        reward = min(reward, remaining)

        reward_tx = core.Tx(kind="mine", sender=core.COINBASE_SENDER,
                            recipient=credit_addr, amount=reward, fee=0, nonce=0,
                            timestamp=now,
                            memo=f"reward discord:{discord_id} src:{source}"
                                 + (f" guild:{guild_id}" if guild_id else ""))
        block = core.Block(height=height, prev_hash=ledger.tip()[1], timestamp=now,
                           txs=[reward_tx.to_dict()], miner=credit_addr,
                           reward=reward, nonce=0)
        difficulty = ledger.next_difficulty()
        try:
            core.mine_block(block, difficulty)
            vres = validate_block(block, _prev_block_view(block.height), _ChainState())
            if not vres:
                audit("block.reject", discord_id,
                      f"self-mined reward block failed validation: "
                      f"{vres.code}: {vres.reason}")
                return {"ok": False, "reason": "validation_failed",
                        "message": f"mined block failed consensus validation "
                                   f"({vres.code})"}
            with WRITE_LOCK:
                bhash = ledger.append_block(block, difficulty)
        except RuntimeError as e:
            with WRITE_LOCK:
                conn.execute("UPDATE mining_state SET last_fail=?, fail_count=fail_count+1 "
                             "WHERE discord_id=?", (now, discord_id))
                conn.commit()
            audit(        "mine.fail", discord_id, str(e))
            return {"ok": False, "reason": "pow_failed", "message": str(e)}

        with WRITE_LOCK:
            conn.execute("""INSERT INTO mining_state (discord_id, last_success, last_fail,
                            success_count, fail_count, total_mined) VALUES (?,?,0,1,0,?)
                            ON CONFLICT(discord_id) DO UPDATE SET last_success=?,
                            success_count=success_count+1, total_mined=total_mined+?""",
                         (discord_id, now, reward, now, reward))
            conn.commit()
        audit("mine.success", discord_id,
              f"reward={reward} src={source} guild={guild_id} channel={channel_id} "
              f"credit={credit_addr} redirected={redirected} height={height}")
        return {"ok": True, "reward_uj": reward, "reward_jer": reward / 1e6,
                "block_height": height, "block_hash": bhash,
                "difficulty_bits": difficulty,
                "credited_address": credit_addr,
                "redirected_to_owner": redirected,
                "message": (f"Mined {reward/1e6:g} {TICKER} in block {height}!"
                            if not redirected else
                            f"Mined {reward/1e6:g} {TICKER} in block {height} — "
                            f"credited to the pool owner because you are opted out.")}


# --------------------------------------------------------------- transfers --
def resolve_recipient(to: str) -> str:
    to = to.strip()
    if to.startswith("JER") and len(to) == 35:
        return to
    target = get_user(to)
    if target:
        return target.address
    raise HTTPException(status_code=404,
                        detail=f"No wallet found for '{to}' and it is not a valid "
                               f"{TICKER} address")


def _new_block_with_txs(txs: list[core.Tx], miner: str) -> tuple[int, str]:
    """Mine a block containing txs and append it. Self-locking; RLock makes
    nested acquisition from lock-holding routes safe. The block must pass
    canonical validation (same rules a follower applies) before it lands."""
    with WRITE_LOCK:
        height = ledger.next_height()
        now = int(time.time())
        block = core.Block(height=height, prev_hash=ledger.tip()[1], timestamp=now,
                           txs=[tx.to_dict() for tx in txs], miner=miner,
                           reward=0, nonce=0)
        difficulty = ledger.next_difficulty()
        core.mine_block(block, difficulty)
        vres = validate_block(block, _prev_block_view(block.height), _ChainState())
        if not vres:
            audit("block.reject", None, f"self-mined block failed validation: "
                                        f"{vres.code}: {vres.reason}")
            raise HTTPException(status_code=500,
                                detail=f"internal error: mined block failed consensus "
                                       f"validation ({vres.code})")
        bhash = ledger.append_block(block, difficulty)
    return height, bhash


def build_transfer(user: sec.WalletUser, to_address: str, amount_uj: int,
                   memo: str) -> core.Tx:
    sk = decrypt_sk(user)
    nonce = ledger.nonce(user.address)
    tx = core.make_tx(sk, to_address, amount_uj, nonce=nonce, fee=FEE_UJ,
                      memo=memo[:120])
    ok, why = ledger.validate_tx(tx)
    if not ok:
        raise HTTPException(status_code=400, detail=f"transaction invalid: {why}")
    return tx


def _seen_once(message_id: str) -> bool:
    """True if message_id was unseen (records it). Unknown/empty ids are
    always processed: rate limits already bound the controllable surface,
    and manual CLI mines carry no message id by design."""
    if not message_id or not message_id.isdigit():
        return True
    now = int(time.time())
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO seen_messages (message_id, ts) VALUES (?,?)",
                (message_id, now))
    return cur.rowcount > 0


class MineReq(BaseModel):
    discord_id: str
    source: str = EXPLICIT_SOURCE          # "explicit" | "passive"
    guild_id: str = ""
    channel_id: str = ""
    message_id: str = ""


class TransferReq(BaseModel):
    discord_id: str
    to: str                                 # discord id or JER… address
    amount_jer: float
    description: str = ""
    password: str = ""
    totp: str = ""


class ConstructReq(BaseModel):
    discord_id: str
    to: str
    amount_jer: float
    description: str = ""


class SignReq(BaseModel):
    discord_id: str
    unsigned_tx: dict
    password: str = ""
    totp: str = ""


class CreateWalletReq(BaseModel):
    discord_id: str
    password: str = ""


class SetPasswordReq(BaseModel):
    discord_id: str
    current_password: str = ""
    new_password: str
    totp: str = ""


class TotpConfirmReq(BaseModel):
    discord_id: str
    code: str


class ExportReq(BaseModel):
    discord_id: str
    password: str
    totp: str


class RebindReq(BaseModel):
    discord_id: str
    new_discord_id: str
    password: str
    totp: str


class OptReq(BaseModel):
    discord_id: str
    opt_in: bool


def _auth_gate(user: sec.WalletUser, password: str, totp: str,
               action: str) -> None:
    """Password + TOTP verification with lockout on repeated failures."""
    now = int(time.time())
    with AUTH_FAIL_LOCK:
        fails = [t for t in AUTH_FAILS.get(user.discord_id, []) if now - t < 600]
        AUTH_FAILS[user.discord_id] = fails
        if len(fails) >= MAX_AUTH_FAILS:
            raise HTTPException(status_code=429,
                                detail="too many failed attempts — try again later")
    if not user.password_stored or not user.wrapped_sk:
        raise HTTPException(status_code=403,
                            detail="wallet has no password set yet — set one with "
                                   "/wallet password first")
    if not sec.verify_password(password, user.password_stored):
        with AUTH_FAIL_LOCK:
            AUTH_FAILS.setdefault(user.discord_id, []).append(now)
        audit("auth.fail", user.discord_id, f"action={action} reason=password")
        raise HTTPException(status_code=401, detail="invalid password")
    if not user.totp_confirmed:
        raise HTTPException(status_code=403,
                            detail="2FA not enrolled yet — confirm a TOTP code first")
    if not user.totp_enc or not sec.totp_verify(
            sec.aes_decrypt(MASTER_KEY, user.totp_enc).decode(), totp):
        with AUTH_FAIL_LOCK:
            AUTH_FAILS.setdefault(user.discord_id, []).append(now)
        audit("auth.fail", user.discord_id, f"action={action} reason=totp")
        raise HTTPException(status_code=401, detail="invalid 2FA code")
    audit("auth.ok", user.discord_id, f"action={action}")


# ------------------------------------------------------------------- routes --
@app.post("/mine", dependencies=[Depends(require_token)])
def api_mine(req: MineReq):
    if req.source not in (PASSIVE_SOURCE, EXPLICIT_SOURCE):
        raise HTTPException(status_code=400, detail="source must be passive|explicit")
    if req.source == PASSIVE_SOURCE and not _seen_once(req.message_id.strip()):
        return {"ok": False, "reason": "duplicate", "message": ""}
    with WRITE_LOCK:
        return mine_attempt(req.discord_id.strip(), req.source,
                            req.guild_id, req.channel_id)


@app.get("/balance", dependencies=[Depends(require_token)])
def api_balance(discord_id: str = "", address: str = ""):
    user = get_user(discord_id) if discord_id else user_from_address(address)
    if not user:
        if discord_id:
            return {"exists": False, "balance_uj": 0, "balance_jer": 0.0,
                    "message": f"No wallet yet — say 'create my wallet' to get one."}
        raise HTTPException(status_code=404, detail="unknown wallet")
    bal = ledger.balance(user.address)
    mempool_out = sum(tx.amount + tx.fee for tx in ledger.mempool_list(500)
                      if tx.sender == user.address)
    return {"exists": True, "address": user.address, "balance_uj": bal,
            "balance_jer": bal / 1e6, "available_jer": (bal - mempool_out) / 1e6,
            "opted_in": user.opted_in,
            "has_password": bool(user.password_stored),
            "totp_confirmed": user.totp_confirmed,
            "auto_sign_limit_jer": user.auto_sign_limit / 1e6,
            "nonce": ledger.nonce(user.address)}


@app.get("/history", dependencies=[Depends(require_token)])
def api_history(discord_id: str, limit: int = 10):
    user = get_user(discord_id)
    if not user:
        raise HTTPException(status_code=404, detail="no wallet for that discord id")
    return {"address": user.address,
            "transactions": ledger.history(user.address, min(limit, 50))}


@app.post("/wallet/create", dependencies=[Depends(require_token)])
def api_wallet_create(req: CreateWalletReq):
    with WRITE_LOCK:
        user = create_wallet(req.discord_id.strip(), req.password or None,
                             source="api")
    totp_setup = None
    if not user.totp_confirmed:
        secret = sec.aes_decrypt(MASTER_KEY, user.totp_enc).decode()
        totp_setup = {"secret_b32": secret,
                      "otpauth_uri": sec.otpauth_uri(secret, f"discord:{user.discord_id}"),
                      "note": "Scan with any authenticator app, then confirm with a code."}
    return {"ok": True, "address": user.address,
            "password_set": bool(user.password_stored),
            "totp_setup": totp_setup,
            "note": "One wallet per discord ID. Set a password + 2FA to enable "
                    "key export and wallet rebinding."}


@app.post("/wallet/password", dependencies=[Depends(require_token)])
def api_wallet_password(req: SetPasswordReq):
    with WRITE_LOCK:
        user = get_user(req.discord_id.strip())
        if not user:
            raise HTTPException(status_code=404, detail="no wallet for that discord id")
        if len(req.new_password) < 10:
            raise HTTPException(status_code=400,
                                detail="password must be at least 10 characters")
        if user.password_stored:
            _auth_gate(user, req.current_password, req.totp, "password.change")
        set_password(user.discord_id, req.current_password, req.new_password,
                     confirm_totp=bool(user.password_stored))
    return {"ok": True, "message": "Password set. Keep it private — it protects "
                                   "key export and wallet rebinding."}


def set_password(discord_id: str, current: str, new: str,
                 confirm_totp: bool = True) -> None:
    user = get_user(discord_id)
    assert user
    wrapped = sec.wrap_with_password(decrypt_sk(user), new)
    stored = sec.hash_password(new)
    with WRITE_LOCK:
        conn.execute("UPDATE users SET wrapped_sk=?, password_stored=? WHERE discord_id=?",
                     (json.dumps(wrapped), json.dumps(stored), discord_id))
        conn.commit()
    audit("wallet.password_set", discord_id)


@app.post("/wallet/totp/confirm", dependencies=[Depends(require_token)])
def api_totp_confirm(req: TotpConfirmReq):
    user = get_user(req.discord_id.strip())
    if not user or not user.totp_enc:
        raise HTTPException(status_code=404, detail="no wallet / no TOTP secret")
    if user.totp_confirmed:
        return {"ok": True, "message": "2FA already confirmed."}
    secret = sec.aes_decrypt(MASTER_KEY, user.totp_enc).decode()
    if not sec.totp_verify(secret, req.code):
        audit("totp.fail", user.discord_id, "confirm")
        raise HTTPException(status_code=401, detail="invalid code — check your "
                                                   "authenticator app clock")
    with WRITE_LOCK:
        conn.execute("UPDATE users SET totp_confirmed=1 WHERE discord_id=?",
                     (user.discord_id,))
        conn.commit()
    audit("totp.confirmed", user.discord_id)
    return {"ok": True, "message": "2FA enrolled. Export/rebind now require "
                                   "password + 2FA."}


@app.post("/wallet/export", dependencies=[Depends(require_token)])
def api_wallet_export(req: ExportReq):
    user = get_user(req.discord_id.strip())
    if not user:
        raise HTTPException(status_code=404, detail="no wallet for that discord id")
    _auth_gate(user, req.password, req.totp, "key.export")
    now = int(time.time())
    if now - user.last_export < sec.EXPORT_COOLDOWN_S:
        raise HTTPException(status_code=429,
                            detail=f"key export allowed once per hour "
                                   f"({sec.EXPORT_COOLDOWN_S - (now - user.last_export)}s left)")
    sk = decrypt_sk(user)
    with WRITE_LOCK:
        conn.execute("UPDATE users SET last_export=? WHERE discord_id=?",
                     (now, user.discord_id))
        conn.commit()
    audit("key.exported", user.discord_id, f"address={user.address}")
    return {"ok": True, "address": user.address, "secret_key_hex": sk.hex(),
            "warning": "This is the ONLY copy channel: store it offline, never "
                       "share it. Anyone with this key controls the wallet. "
                       "Use it to rebind your wallet to a new discord ID."}


@app.post("/wallet/rebind", dependencies=[Depends(require_token)])
def api_wallet_rebind(req: RebindReq):
    with WRITE_LOCK:
        user = get_user(req.discord_id.strip())
        if not user:
            raise HTTPException(status_code=404, detail="no wallet for that discord id")
        new_id = req.new_discord_id.strip()
        if not new_id.isdigit():
            raise HTTPException(status_code=400, detail="new discord id must be numeric")
        if get_user(new_id):
            raise HTTPException(status_code=409,
                                detail="that discord ID already has a wallet — "
                                       "one wallet per discord ID")
        _auth_gate(user, req.password, req.totp, "wallet.rebind")
        now = int(time.time())
        if now - user.last_rebind < sec.REBIND_COOLDOWN_S:
            raise HTTPException(status_code=429,
                                detail=f"rebind allowed once per hour "
                                       f"({sec.REBIND_COOLDOWN_S - (now - user.last_rebind)}s left)")
        conn.execute("UPDATE users SET discord_id=?, last_rebind=? WHERE discord_id=?",
                     (new_id, now, user.discord_id))
        conn.execute("UPDATE mining_state SET discord_id=? WHERE discord_id=?",
                     (new_id, user.discord_id))
        conn.commit()
        audit("wallet.rebound", new_id,
              f"old={user.discord_id} address={user.address} (address unchanged)")
    return {"ok": True, "message": f"Wallet {user.address} now bound to discord "
                                   f"ID {new_id}. Balance and history unchanged."}


@app.post("/wallet/optin", dependencies=[Depends(require_token)])
def api_wallet_optin(req: OptReq):
    with WRITE_LOCK:
        user = get_user(req.discord_id.strip()) or create_wallet(req.discord_id.strip())
        conn.execute("UPDATE users SET opted_in=? WHERE discord_id=?",
                     (1 if req.opt_in else 0, user.discord_id))
        conn.commit()
    audit("wallet.opt_" + ("in" if req.opt_in else "out"), user.discord_id)
    msg = ("Mining rewards will credit your own wallet." if req.opt_in else
           "You are opted out. Any coins your activity mines are credited to "
           "the pool owner's wallet until you opt back in. Your wallet and "
           "balance are untouched.")
    return {"ok": True, "opted_in": req.opt_in, "message": msg}


@app.post("/tx/construct", dependencies=[Depends(require_token)])
def api_tx_construct(req: ConstructReq):
    user = get_user(req.discord_id.strip())
    if not user:
        raise HTTPException(status_code=404, detail="no wallet for that discord id")
    amount_uj = int(round(req.amount_jer * 1_000_000))
    if amount_uj <= 0:
        raise HTTPException(status_code=400, detail="amount must be positive")
    to_address = resolve_recipient(req.to)
    ok, why = sec.auto_sign_allowed(user, amount_uj)
    needs_2fa = (not ok)
    tx = core.Tx(kind="spend", sender=user.address, recipient=to_address,
                 amount=amount_uj, fee=FEE_UJ, nonce=ledger.nonce(user.address),
                 timestamp=int(time.time()), memo=req.description[:120])
    bal = ledger.balance(user.address)
    return {
        "unsigned_tx": tx.to_dict(),
        "description": (f"Send {amount_uj/1e6:g} {TICKER} from {user.address} "
                        f"to {to_address} (fee {FEE_UJ/1e6:g} {TICKER}, burned)"
                        + (f' — "{tx.memo}"' if tx.memo else "")),
        "auto_signable": ok,
        "requires_password_2fa": needs_2fa,
        "balance_jer": bal / 1e6,
        "note": why if not ok else "within auto-sign limits",
    }


@app.post("/tx/sign", dependencies=[Depends(require_token)])
def api_tx_sign(req: SignReq):
    with WRITE_LOCK:
        user = get_user(req.discord_id.strip())
        if not user:
            raise HTTPException(status_code=404, detail="no wallet for that discord id")
        utx = req.unsigned_tx
        amount = int(utx.get("amount", 0))
        if amount <= 0:
            raise HTTPException(status_code=400, detail="amount must be positive")
        if utx.get("sender") not in ("", user.address):
            raise HTTPException(status_code=403,
                                detail="unsigned tx sender does not match your wallet")
        ok, why = sec.auto_sign_allowed(user, amount)
        if ok:
            today = time.strftime("%Y-%m-%d", time.gmtime())
            spent = user.daily_spent if user.daily_date == today else 0
            conn.execute("UPDATE users SET daily_spent=?, daily_date=? WHERE discord_id=?",
                         (spent + amount, today, user.discord_id))
            conn.commit()
            audit("tx.autosign", user.discord_id, f"amount={amount}")
        else:
            _auth_gate(user, req.password, req.totp, "tx.sign")
        to_address = utx.get("recipient", "")
        if not (to_address.startswith("JER") and len(to_address) == 35):
            raise HTTPException(status_code=400, detail="recipient must be a JER address")
        tx = build_transfer(user, to_address, amount, str(utx.get("memo", "")))
        height, bhash = _new_block_with_txs([tx], miner=user.address)
        txid = __import__("hashlib").sha256(
            tx.payload() + bytes.fromhex(tx.signature)).hexdigest()
        audit("tx.signed", user.discord_id,
              f"txid={txid[:16]}… amount={amount} to={to_address} height={height}")
        return {"ok": True, "txid": txid, "block_height": height,
                "block_hash": bhash, "amount_jer": amount / 1e6,
                "to": to_address, "fee_jer": FEE_UJ / 1e6,
                "signed_via": "auto" if ok else "password+2fa"}


@app.post("/transfer", dependencies=[Depends(require_token)])
def api_transfer(req: TransferReq):
    """One-shot: construct + authorize + sign + on-chain."""
    with WRITE_LOCK:
        user = get_user(req.discord_id.strip())
        if not user:
            raise HTTPException(status_code=404, detail="no wallet for that discord id")
        amount_uj = int(round(req.amount_jer * 1_000_000))
        if amount_uj <= 0:
            raise HTTPException(status_code=400, detail="amount must be positive")
        ok, why = sec.auto_sign_allowed(user, amount_uj)
        if ok:
            today = time.strftime("%Y-%m-%d", time.gmtime())
            spent = user.daily_spent if user.daily_date == today else 0
            conn.execute("UPDATE users SET daily_spent=?, daily_date=? WHERE discord_id=?",
                         (spent + amount_uj, today, user.discord_id))
            conn.commit()
            audit("tx.autosign", user.discord_id, f"amount={amount_uj}")
        else:
            _auth_gate(user, req.password, req.totp, "tx.transfer")
        to_address = resolve_recipient(req.to)
        tx = build_transfer(user, to_address, amount_uj, req.description)
        height, bhash = _new_block_with_txs([tx], miner=user.address)
        import hashlib
        txid = hashlib.sha256(tx.payload() + bytes.fromhex(tx.signature)).hexdigest()
        audit("tx.applied", user.discord_id,
              f"txid={txid[:16]}… amount={amount_uj} to={to_address} height={height}")
        return {"ok": True, "txid": txid, "block_height": height,
                "block_hash": bhash, "to": to_address,
                "amount_jer": amount_uj / 1e6, "fee_jer": FEE_UJ / 1e6,
                "signed_via": "auto" if ok else "password+2fa"}


@app.get("/tx/{txid}", dependencies=[Depends(require_token)])
def api_tx(txid: str):
    row = conn.execute("SELECT * FROM txs WHERE txid=?", (txid,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="unknown txid")
    cols = [c[1] for c in conn.execute("SELECT * FROM txs LIMIT 1").description]
    return dict(zip(cols, row))


@app.get("/block/{height}", dependencies=[Depends(require_token)])
def api_block(height: int):
    row = conn.execute("SELECT * FROM blocks WHERE height=?", (height,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="unknown height")
    cols = [c[1] for c in conn.execute("SELECT * FROM blocks LIMIT 1").description]
    blk = dict(zip(cols, row))
    blk["txs"] = [dict(zip(["txid", "height", "kind", "sender", "recipient", "amount",
                            "fee", "nonce", "timestamp", "memo", "vk", "signature", "status"],
                           r)) for r in conn.execute(
                               "SELECT * FROM txs WHERE height=?", (height,)).fetchall()]
    return blk


@app.get("/status", dependencies=[Depends(require_token)])
def api_status():
    tip = ledger.tip()
    users = conn.execute("SELECT COUNT(*), COALESCE(SUM(opted_in),0) FROM users").fetchone()
    ms = conn.execute("""SELECT COUNT(*), COALESCE(SUM(success_count),0),
                         COALESCE(SUM(fail_count),0), COALESCE(SUM(total_mined),0)
                         FROM mining_state""").fetchone()
    return {
        "coin": COIN_NAME, "ticker": TICKER,
        "chain": {"height": (tip[0] if tip else -1), "tip_hash": (tip[1] if tip else None),
                  "difficulty_bits": ledger.current_difficulty(),
                  "target_block_seconds": core.TARGET_BLOCK_SECONDS,
                  "block_reward_jer": core.reward_for_height(ledger.next_height()) / 1e6,
                  "circulating_jer": ledger.circulating() / 1e6,
                  "max_supply_jer": core.MAX_SUPPLY / 1e6,
                  "premine_jer": core.PREMINE / 1e6,
                  "transfer_fee_jer": FEE_UJ / 1e6},
        "wallets": {"count": users[0], "opted_in": users[1]},
        "mining": {"miners": ms[0], "successful_mines": ms[1],
                   "failed_mines": ms[2], "total_mined_uj": ms[3],
                   "cooldown_success_s": MINE_COOLDOWN_SUCCESS_S,
                   "cooldown_fail_s": MINE_COOLDOWN_FAIL_S,
                   "passive_reward_jer": PASSIVE_REWARD_UJ / 1e6},
        "security": {"auto_sign_limit_jer": sec.AUTO_SIGN_DEFAULT_UJ / 1e6,
                     "auto_sign_daily_cap_jer": sec.AUTO_SIGN_DAILY_CAP_UJ / 1e6,
                     "export_cooldown_s": sec.EXPORT_COOLDOWN_S},
    }


@app.on_event("startup")
def _startup() -> None:
    init_chain()


if __name__ == "__main__":
    _port = int(os.environ.get("JERITH_PORT", "8300"))
    uvicorn.run(app, host="127.0.0.1", port=_port, log_level="info")
