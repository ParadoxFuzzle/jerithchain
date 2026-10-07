#!/usr/bin/env python3
"""JerithChain public explorer API (read-only).

Binds 127.0.0.1:8303. Intended to be published via the user's reverse proxy
or served directly on the LAN. Only chain data is exposed — no wallets, no
discord IDs, no user tables. Read-only SQLite handle; per-IP rate limiting.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import uvicorn

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("JERITH_DATA_DIR", BASE_DIR / "data"))
DB_PATH = DATA_DIR / "jerith.db"
SITE_DIR = Path(os.environ.get("JERITH_SITE_DIR",
                               Path.home() / ".openclaw" / "workspace" / "website"))
PORT = int(os.environ.get("JERITH_EXPLORER_PORT", "8303"))
RATE_LIMIT_PER_MIN = 120

import sqlite3  # noqa: E402
conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, check_same_thread=False)
conn.execute("PRAGMA journal_mode=WAL")

app = FastAPI(title="JerithChain Explorer API", version="1.0.0", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET"],
                   allow_headers=["*"])

BUCKETS: dict[str, deque] = defaultdict(lambda: deque(maxlen=RATE_LIMIT_PER_MIN))


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    bucket = BUCKETS[ip]
    while bucket and now - bucket[0] > 60:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_PER_MIN:
        return JSONResponse({"detail": "rate limited"}, status_code=429)
    bucket.append(now)
    return await call_next(request)


COIN = {"coin": "Jerith Coin", "ticker": "JER"}
MAX_SUPPLY_UJ = 1_000_000_000 * 1_000_000
PREMINE_UJ = 200_000_000 * 1_000_000


def q(sql: str, args: tuple = ()) -> list[tuple]:
    return conn.execute(sql, args).fetchall()


def tip() -> tuple | None:
    rows = q("SELECT height, hash, timestamp, difficulty FROM blocks ORDER BY height DESC LIMIT 1")
    return rows[0] if rows else None


@app.get("/api/status")
def status():
    t = tip()
    height = t[0] if t else -1
    circulating = q("SELECT COALESCE(SUM(balance),0) FROM balances")[0][0]
    wallets = q("SELECT COUNT(*) FROM balances")[0][0]
    mines = q("SELECT COALESCE(SUM(success_count),0), COALESCE(SUM(fail_count),0) FROM mining_state")[0]
    reward = 50 * 1_000_000
    if height >= 0:
        r = reward
        for _ in range((height + 1) // 210_000):
            r = max(1, r // 2)
        reward = r
    return {**COIN,
            "height": height,
            "tip_hash": t[1] if t else None,
            "last_block_ts": t[2] if t else None,
            "difficulty_bits": t[3] if t else 18,
            "target_block_seconds": 60,
            "block_reward_uj": reward,
            "circulating_uj": circulating,
            "max_supply_uj": MAX_SUPPLY_UJ,
            "premine_uj": PREMINE_UJ,
            "addresses": wallets,
            "mines_ok": mines[0], "mines_fail": mines[1]}


@app.get("/api/blocks")
def blocks(limit: int = 20, offset: int = 0):
    limit = max(1, min(limit, 100))
    rows = q("""SELECT b.height, b.hash, b.timestamp, b.miner, b.reward, b.difficulty,
                       (SELECT COUNT(*) FROM txs t WHERE t.height=b.height) AS ntx
                FROM blocks b ORDER BY b.height DESC LIMIT ? OFFSET ?""", (limit, offset))
    return {"blocks": [dict(zip(["height", "hash", "timestamp", "miner", "reward_uj",
                                 "difficulty", "txs"], r)) for r in rows]}


@app.get("/api/block/{height}")
def block(height: int):
    rows = q("""SELECT height, hash, prev_hash, timestamp, miner, reward, nonce, difficulty
                FROM blocks WHERE height=?""", (height,))
    if not rows:
        raise HTTPException(404, "unknown height")
    r = rows[0]
    txs = q("""SELECT txid, kind, sender, recipient, amount, fee, memo
               FROM txs WHERE height=?""", (height,))
    return {"height": r[0], "hash": r[1], "prev_hash": r[2], "timestamp": r[3],
            "miner": r[4], "reward_uj": r[5], "nonce": r[6], "difficulty": r[7],
            "transactions": [dict(zip(["txid", "kind", "sender", "recipient",
                                       "amount_uj", "fee_uj", "memo"], t)) for t in txs]}


@app.get("/api/tx/{txid}")
def tx(txid: str):
    rows = q("""SELECT txid, height, kind, sender, recipient, amount, fee, nonce,
                       timestamp, memo FROM txs WHERE txid=?""", (txid,))
    if not rows:
        raise HTTPException(404, "unknown txid")
    r = rows[0]
    return dict(zip(["txid", "height", "kind", "sender", "recipient", "amount_uj",
                     "fee_uj", "nonce", "timestamp", "memo"], r))


@app.get("/api/address/{address}")
def address(address: str):
    bal = q("SELECT balance, nonce FROM balances WHERE address=?", (address,))
    if not bal:
        raise HTTPException(404, "unknown address")
    txs = q("""SELECT txid, height, kind, sender, recipient, amount, timestamp, memo
               FROM txs WHERE sender=? OR recipient=?
               ORDER BY height DESC, timestamp DESC LIMIT 50""", (address, address))
    return {"address": address, "balance_uj": bal[0][0], "nonce": bal[0][1],
            "transactions": [dict(zip(["txid", "height", "kind", "sender", "recipient",
                                       "amount_uj", "timestamp", "memo"], t)) for t in txs]}


@app.get("/")
def index():
    page = SITE_DIR / "explorer.html"
    if not page.exists():
        raise HTTPException(404, "explorer page not installed")
    return FileResponse(page, media_type="text/html")


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
