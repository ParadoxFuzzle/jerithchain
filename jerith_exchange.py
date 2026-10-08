"""Exchange-facing node API (v1.1 §15-20).

Machine-oriented wallet + chain queries for exchanges, explorers and
automated services. Completely independent of Discord identity: an
infrastructure wallet is an Ed25519 keypair stored encrypted under an
API-key-authenticated REST surface, using the same JER address/signature
system as community wallets.

Auth: Bearer <token> against keys/exchange.token (auto-created 0600 at
first start). Kept separate from the Discord-agent token so the two
surfaces can be firewalled independently.

Endpoints (JSON, uJ = micro-JER integers everywhere):
  GET  /x/chain                block count, tip, difficulty, work, supply
  GET  /x/networkinfo          peer-facing diagnostics mirror
  GET  /x/block/{height}       full block with txids
  GET  /x/blockhash/{height}   {hash}
  GET  /x/tx/{txid}            transaction with confirmations
  POST /x/wallet/new           {"label": "..."} -> {address, label}
  GET  /x/wallet/list          wallets and balances
  GET  /x/wallet/{address}     {address, balance_uj, nonce, pending}
  POST /x/wallet/export        {address, password} -> secret (audited!)
  POST /x/tx/build             {from_address, to, amount_uj, memo}
  POST /x/tx/sign              {from_address, unsigned_tx, password}
  POST /x/tx/send              {from_address, to, amount_uj, memo, password}
  POST /x/tx/sendraw           {signed_tx} (externally signed broadcast)
  GET  /x/tx/{txid}/confirmations
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

import jerith_core as core
import jerith_wallet as sec

EXCHANGE_FEE_UJ = 100_000            # 0.1 JER — consensus burn fee, not configurable
STANDARD_CONFIRMATIONS = 20          # documented policy (see NETWORK.md)

router = APIRouter(prefix="/x")


class _State:
    conn: sqlite3.Connection = None  # type: ignore
    keys_dir: Path = None            # type: ignore
    token: str = ""
    lock: threading.RLock = None     # type: ignore


_st = _State()


def init_exchange(conn: sqlite3.Connection, keys_dir: Path, lock) -> None:
    _st.conn = conn
    _st.keys_dir = keys_dir
    _st.lock = lock
    _st.conn.execute(
        """CREATE TABLE IF NOT EXISTS x_wallets (
               address TEXT PRIMARY KEY,
               label TEXT NOT NULL DEFAULT '',
               vk_hex TEXT NOT NULL,
               enc_sk TEXT NOT NULL,
               created_at INTEGER NOT NULL,
               last_used INTEGER NOT NULL DEFAULT 0
           )""")
    _st.conn.commit()
    tok_path = keys_dir / "exchange.token"
    if tok_path.exists():
        _st.token = tok_path.read_text().strip()
    else:
        _st.token = secrets.token_urlsafe(32)
        fd = os.open(tok_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(_st.token)


def require_x_token(authorization: str = Header(default="")) -> None:
    expected = f"Bearer {_st.token}"
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="invalid exchange API token")


# --------------------------------------------------------------- helpers ----
def _wallet(address: str):
    row = _st.conn.execute(
        "SELECT address, label, vk_hex, enc_sk, created_at, last_used"
        " FROM x_wallets WHERE address=?", (address,)).fetchone()
    if not row:
        return None
    return {"address": row[0], "label": row[1], "vk_hex": row[2],
            "enc_sk": row[3], "created_at": row[4], "last_used": row[5]}


def _ledger() -> core.Ledger:
    return core.Ledger(_st.conn)


def _confirmations(height: int) -> int:
    row = _st.conn.execute("SELECT MAX(height) FROM blocks").fetchone()
    tip = int(row[0]) if row and row[0] is not None else -1
    return max(tip - height + 1, 0) if height >= 0 else 0


def _tx_dict(row) -> dict:
    cols = ["txid", "height", "kind", "sender", "recipient", "amount", "fee",
            "nonce", "timestamp", "memo", "vk", "signature", "status"]
    d = dict(zip(cols, row))
    d["confirmations"] = _confirmations(d["height"] or -1)
    return d


def _audit(etype: str, details: str) -> None:
    _st.conn.execute(
        "INSERT INTO events (ts, type, discord_id, details) VALUES (?,?,?,?)",
        (int(time.time()), etype, "exchange", details))
    _st.conn.commit()


# ------------------------------------------------------------ chain reads ---
@router.get("/chain", dependencies=[Depends(require_x_token)])
def x_chain():
    ld = _ledger()
    tip = ld.tip()
    height = tip[0] if tip else -1
    rep = None
    return {
        "height": max(height, 0),
        "best_block_hash": tip[1] if tip else None,
        "difficulty_bits": tip[3] if tip else core.GENESIS_DIFFICULTY,
        "chain_work": ld.work_above(-1) if height >= 0 else 0,
        "mempool_size": _st.conn.execute(
            "SELECT COUNT(*) FROM mempool").fetchone()[0],
        "standard_confirmations": STANDARD_CONFIRMATIONS,
        "protocol_version": "1.1",
    }


@router.get("/networkinfo", dependencies=[Depends(require_x_token)])
def x_networkinfo():
    return x_chain()


@router.get("/blockhash/{height}", dependencies=[Depends(require_x_token)])
def x_blockhash(height: int):
    row = _st.conn.execute("SELECT hash FROM blocks WHERE height=?",
                           (height,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="unknown height")
    return {"height": height, "hash": row[0]}


@router.get("/block/{height}", dependencies=[Depends(require_x_token)])
def x_block(height: int):
    row = _st.conn.execute(
        "SELECT height, hash, prev_hash, timestamp, miner, reward, nonce,"
        " difficulty FROM blocks WHERE height=?", (height,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="unknown height")
    txids = [r[0] for r in _st.conn.execute(
        "SELECT txid FROM txs WHERE height=?", (height,))]
    return {"height": row[0], "hash": row[1], "prev_hash": row[2],
            "timestamp": row[3], "miner": row[4], "reward_uj": row[5],
            "nonce": row[6], "difficulty": row[7], "txids": txids,
            "confirmations": _confirmations(height)}


@router.get("/tx/{txid}", dependencies=[Depends(require_x_token)])
def x_tx(txid: str):
    row = _st.conn.execute(
        "SELECT txid, height, kind, sender, recipient, amount, fee, nonce,"
        " timestamp, memo, vk, signature, status FROM txs WHERE txid=?",
        (txid,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="unknown txid")
    return _tx_dict(row)


@router.get("/tx/{txid}/confirmations", dependencies=[Depends(require_x_token)])
def x_tx_confirmations(txid: str):
    row = _st.conn.execute("SELECT height FROM txs WHERE txid=?",
                           (txid,)).fetchone()
    if not row or row[0] is None:
        raise HTTPException(status_code=404, detail="unknown txid")
    return {"txid": txid, "confirmations": _confirmations(int(row[0])),
            "standard": STANDARD_CONFIRMATIONS}


# ----------------------------------------------------------------- wallet ---
class NewWalletReq(BaseModel):
    label: str = ""


class PasswordReq(BaseModel):
    address: str
    password: str


class BuildReq(BaseModel):
    from_address: str
    to: str
    amount_uj: int
    memo: str = ""


class SignReq(BaseModel):
    from_address: str
    unsigned_tx: dict
    password: str = ""


class SendReq(BaseModel):
    from_address: str
    to: str
    amount_uj: int
    memo: str = ""
    password: str = ""


class SendRawReq(BaseModel):
    signed_tx: dict


class BuildRawReq(BaseModel):
    from_address: str
    to: str
    amount_uj: int
    memo: str = ""
    vk: str = ""          # hex of the signer's Ed25519 verify key (REQUIRED
                          # in the signed payload — must be provided up front)


@router.post("/wallet/new", dependencies=[Depends(require_x_token)])
def x_wallet_new(req: NewWalletReq):
    sk, vk = core.generate_keypair()
    address = core.addr_from_vk(vk)
    enc_sk = sec.aes_encrypt(sec.load_or_create_master_key(str(_st.keys_dir)), sk)
    with _st.lock:
        _st.conn.execute(
            "INSERT INTO x_wallets (address, label, vk_hex, enc_sk, created_at)"
            " VALUES (?,?,?,?,?)",
            (address, req.label[:60], vk.hex(), enc_sk, int(time.time())))
        _st.conn.commit()
    _audit("xwallet.create", f"address={address} label={req.label[:60]}")
    return {"address": address, "label": req.label, "created": True}


@router.get("/wallet/list", dependencies=[Depends(require_x_token)])
def x_wallet_list():
    rows = _st.conn.execute(
        "SELECT w.address, w.label, w.created_at,"
        " COALESCE(b.balance, 0), COALESCE(b.nonce, 0)"
        " FROM x_wallets w LEFT JOIN balances b ON b.address = w.address"
        " ORDER BY w.created_at").fetchall()
    return {"wallets": [
        {"address": r[0], "label": r[1], "created_at": r[2],
         "balance_uj": r[3], "nonce": r[4]} for r in rows]}


@router.get("/wallet/{address}", dependencies=[Depends(require_x_token)])
def x_wallet_get(address: str):
    if not _wallet(address):
        raise HTTPException(status_code=404, detail="unknown exchange wallet")
    ld = _ledger()
    return {"address": address, "balance_uj": ld.balance(address),
            "nonce": ld.nonce(address),
            "pending_mempool": _st.conn.execute(
                "SELECT COUNT(*) FROM mempool WHERE"
                " json_extract(payload,'$.sender')=?",
                (address,)).fetchone()[0]}


@router.get("/address/{address}", dependencies=[Depends(require_x_token)])
def x_address_get(address: str):
    """Balance/nonce for ANY on-chain address (ledger-derived, no wallet
    registration needed) — used by external clients like the OpenClaw skill
    whose keys live client-side. 404 only if the address is malformed."""
    if not (address.startswith("JER") and len(address) == 35):
        raise HTTPException(status_code=404, detail="malformed JER address")
    ld = _ledger()
    return {"address": address, "balance_uj": ld.balance(address),
            "nonce": ld.nonce(address),
            "pending_mempool": _st.conn.execute(
                "SELECT COUNT(*) FROM mempool WHERE"
                " json_extract(payload,'$.sender')=?",
                (address,)).fetchone()[0]}


@router.post("/wallet/export", dependencies=[Depends(require_x_token)])
def x_wallet_export(req: PasswordReq):
    """Requires the wallet password (set at creation via /x/wallet/setpw;
    if none set, key was never exportable — create a new wallet instead)."""
    raise HTTPException(
        status_code=501,
        detail="export requires password-protected wallets; see EXCHANGE_INTEGRATION.md backup section")


# -------------------------------------------------------------------- txs ---
@router.post("/tx/build", dependencies=[Depends(require_x_token)])
def x_tx_build(req: BuildReq):
    w = _wallet(req.from_address)
    if not w:
        raise HTTPException(status_code=404, detail="unknown exchange wallet")
    if req.amount_uj <= 0:
        raise HTTPException(status_code=400, detail="amount_uj must be positive")
    ld = _ledger()
    unsigned = {
        "kind": "spend", "sender": req.from_address, "recipient": req.to,
        "amount": int(req.amount_uj), "fee": EXCHANGE_FEE_UJ,
        "nonce": ld.nonce(req.from_address),
        "timestamp": int(time.time()), "memo": (req.memo or "")[:120],
        "vk": w["vk_hex"], "signature": "",
    }
    bal = ld.balance(req.from_address)
    if bal < req.amount_uj + EXCHANGE_FEE_UJ:
        raise HTTPException(status_code=400,
                            detail=f"insufficient balance {bal} < "
                                   f"{req.amount_uj + EXCHANGE_FEE_UJ}")
    payload = core.Tx.from_dict(unsigned).payload()
    return {"unsigned_tx": unsigned,
            "payload_hex": payload.hex(),
            "note": "sign payload_hex with the wallet's Ed25519 key; put the"
                    " hex signature into unsigned_tx.signature"}


@router.post("/tx/buildraw", dependencies=[Depends(require_x_token)])
def x_tx_buildraw(req: BuildRawReq):
    """Build an unsigned spend for ANY on-chain address (ledger nonce/fee;
    signature left empty). For external clients that hold keys client-side
    (OpenClaw skill, CLI/web wallets): build → sign locally → /x/tx/sendraw."""
    if not (req.from_address.startswith("JER") and len(req.from_address) == 35):
        raise HTTPException(status_code=404, detail="malformed JER from_address")
    if not (req.to.startswith("JER") and len(req.to) == 35):
        raise HTTPException(status_code=400, detail="malformed JER recipient")
    if req.amount_uj <= 0:
        raise HTTPException(status_code=400, detail="amount_uj must be positive")
    if not req.vk:
        raise HTTPException(
            status_code=400,
            detail="vk is required: the Ed25519 verify key is part of the "
                   "signed payload, so it must be known at build time")
    try:
        vk_bytes = bytes.fromhex(req.vk)
    except ValueError:
        raise HTTPException(status_code=400, detail="vk must be hex")
    if len(vk_bytes) != 32 or core.addr_from_vk(vk_bytes) != req.from_address:
        raise HTTPException(status_code=400,
                            detail="vk does not hash to from_address")
    ld = _ledger()
    bal = ld.balance(req.from_address)
    if bal < req.amount_uj + EXCHANGE_FEE_UJ:
        raise HTTPException(status_code=400,
                            detail=f"insufficient balance {bal} < "
                                   f"{req.amount_uj + EXCHANGE_FEE_UJ}")
    unsigned = {
        "kind": "spend", "sender": req.from_address, "recipient": req.to,
        "amount": int(req.amount_uj), "fee": EXCHANGE_FEE_UJ,
        "nonce": ld.nonce(req.from_address),
        "timestamp": int(time.time()), "memo": (req.memo or "")[:120],
        "vk": req.vk, "signature": "",
    }
    payload = core.Tx.from_dict(unsigned).payload()
    return {"unsigned_tx": unsigned, "payload_hex": payload.hex(),
            "note": "sign payload_hex with the Ed25519 secret key for vk, "
                    "put the hex signature into unsigned_tx.signature, then "
                    "POST to /x/tx/sendraw"}


@router.post("/tx/sign", dependencies=[Depends(require_x_token)])
def x_tx_sign(req: SignReq):
    w = _wallet(req.from_address)
    if not w:
        raise HTTPException(status_code=404, detail="unknown exchange wallet")
    master = sec.load_or_create_master_key(str(_st.keys_dir))
    sk = sec.aes_decrypt(master, w["enc_sk"])
    td = dict(req.unsigned_tx)
    if td.get("sender") != req.from_address:
        raise HTTPException(status_code=400, detail="tx.sender != wallet address")
    td["vk"] = w["vk_hex"]
    tx = core.Tx.from_dict(td)
    tx.signature = core.sign_tx_bytes(sk, tx.payload()).hex()
    ok, why = _ledger().validate_tx(tx)
    if not ok:
        raise HTTPException(status_code=400, detail=f"tx invalid: {why}")
    with _st.lock:
        _st.conn.execute("UPDATE x_wallets SET last_used=? WHERE address=?",
                         (int(time.time()), req.from_address))
        _st.conn.commit()
    return {"signed_tx": tx.to_dict(), "txid": hashlib.sha256(
        tx.payload() + bytes.fromhex(tx.signature)).hexdigest()}


@router.post("/tx/send", dependencies=[Depends(require_x_token)])
def x_tx_send(req: SendReq):
    """Build + sign + apply in one call (v1.0 model: the node mines the
    spend into a block immediately)."""
    build = x_tx_build(BuildReq(from_address=req.from_address, to=req.to,
                                amount_uj=req.amount_uj, memo=req.memo))
    signed = x_tx_sign(SignReq(from_address=req.from_address,
                               unsigned_tx=build["unsigned_tx"],
                               password=req.password))
    from jerith_node import _new_block_with_txs
    tx = core.Tx.from_dict(signed["signed_tx"])
    height, bhash = _new_block_with_txs([tx], miner=req.from_address)
    _audit("xwallet.send", f"txid={signed['txid'][:16]}… amount={req.amount_uj}"
                           f" to={req.to} height={height}")
    return {"txid": signed["txid"], "block_height": height,
            "block_hash": bhash, "confirmations": 1,
            "amount_uj": req.amount_uj, "fee_uj": EXCHANGE_FEE_UJ,
            "standard_confirmations": STANDARD_CONFIRMATIONS}


@router.post("/tx/sendraw", dependencies=[Depends(require_x_token)])
def x_tx_sendraw(req: SendRawReq):
    """Broadcast an externally signed tx: validated, then mined into a
    block like any node-originated spend."""
    try:
        tx = core.Tx.from_dict(req.signed_tx)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"bad signed_tx: {e}")
    ok, why = _ledger().validate_tx(tx)
    if not ok:
        raise HTTPException(status_code=400, detail=f"tx invalid: {why}")
    from jerith_node import _new_block_with_txs
    height, bhash = _new_block_with_txs([tx], miner=tx.sender)
    txid = hashlib.sha256(tx.payload() + bytes.fromhex(tx.signature)).hexdigest()
    _audit("xwallet.sendraw", f"txid={txid[:16]}… height={height}")
    return {"txid": txid, "block_height": height, "block_hash": bhash,
            "confirmations": 1, "standard_confirmations": STANDARD_CONFIRMATIONS}
