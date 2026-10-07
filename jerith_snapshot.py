#!/usr/bin/env python3
"""JerithChain public snapshot builder.

Emits a JSON document the static explorer page can consume:
{ generated, status, blocks[last 100 w/ transactions], addresses{addr:{balance_uj, transactions[20]}} }
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("JERITH_DATA_DIR", BASE_DIR / "data"))
DB_PATH = DATA_DIR / "jerith.db"

MAX_SUPPLY_UJ = 1_000_000_000 * 1_000_000
PREMINE_UJ = 200_000_000 * 1_000_000


def build() -> dict:
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.execute("PRAGMA journal_mode=WAL")

    tip = conn.execute(
        "SELECT height, hash, timestamp, difficulty FROM blocks ORDER BY height DESC LIMIT 1").fetchone()
    height = tip[0] if tip else -1
    circulating = conn.execute("SELECT COALESCE(SUM(balance),0) FROM balances").fetchone()[0]
    addresses_n = conn.execute("SELECT COUNT(*) FROM balances").fetchone()[0]
    mines = conn.execute("""SELECT COALESCE(SUM(success_count),0),
                            COALESCE(SUM(fail_count),0) FROM mining_state""").fetchone()
    reward = 50 * 1_000_000
    for _ in range((height + 1) // 210_000):
        reward = max(1, reward // 2)

    status = {"coin": "Jerith Coin", "ticker": "JER", "height": height,
              "tip_hash": tip[1] if tip else None,
              "last_block_ts": tip[2] if tip else None,
              "difficulty_bits": tip[3] if tip else 18,
              "target_block_seconds": 60, "block_reward_uj": reward,
              "circulating_uj": circulating, "max_supply_uj": MAX_SUPPLY_UJ,
              "premine_uj": PREMINE_UJ, "addresses": addresses_n,
              "mines_ok": mines[0], "mines_fail": mines[1]}

    blocks = []
    for h, in conn.execute(
            "SELECT height FROM blocks ORDER BY height DESC LIMIT 100"):
        b = conn.execute("""SELECT height, hash, prev_hash, timestamp, miner,
                            reward, nonce, difficulty FROM blocks WHERE height=?""", (h,)).fetchone()
        txs = conn.execute("""SELECT txid, kind, sender, recipient, amount, fee, memo
                              FROM txs WHERE height=?""", (h,)).fetchall()
        blocks.append({
            "height": b[0], "hash": b[1], "prev_hash": b[2], "timestamp": b[3],
            "miner": b[4], "reward_uj": b[5], "nonce": b[6], "difficulty": b[7],
            "txs": len(txs),
            "transactions": [{"txid": t[0], "kind": t[1], "sender": t[2],
                              "recipient": t[3], "amount_uj": t[4], "fee_uj": t[5],
                              "memo": t[6]} for t in txs]})

    addr_rows = conn.execute(
        "SELECT address, balance FROM balances WHERE balance > 0 ORDER BY balance DESC LIMIT 500").fetchall()
    addresses = {}
    for addr, bal in addr_rows:
        txs = conn.execute("""SELECT txid, height, kind, sender, recipient, amount, timestamp, memo
                              FROM txs WHERE sender=? OR recipient=?
                              ORDER BY height DESC, timestamp DESC LIMIT 20""", (addr, addr)).fetchall()
        addresses[addr] = {"balance_uj": bal,
                           "transactions": [{"txid": t[0], "height": t[1], "kind": t[2],
                                             "sender": t[3], "recipient": t[4],
                                             "amount_uj": t[5], "timestamp": t[6],
                                             "memo": t[7]} for t in txs]}

    return {"generated": int(__import__("time").time()), "snapshot": True,
            "status": status, "blocks": blocks, "addresses": addresses}


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "snapshot.json"
    Path(out).write_text(json.dumps(build(), separators=(",", ":")))
    print(f"snapshot written to {out}")
