#!/usr/bin/env python3
"""JerithChain read-only follower.

Mirrors the host chain over gRPC into a local SQLite DB for exploration.
Never writes blocks to any authoritative store; refuses to run against the
host's own data dir. Reconnects with backoff; fork-safe (a shorter local
chain is wiped back to the common ancestor... conservatively, the tail).
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "gen"))

import grpc                                  # noqa: E402

import jerith_sync_pb2 as pb                 # noqa: E402
import jerith_sync_pb2_grpc as pb_grpc       # noqa: E402

DATA_DIR = Path(os.environ.get("JERITH_FOLLOW_DATA_DIR", BASE_DIR / "data-follow"))
DB_PATH = DATA_DIR / "jerith.db"
HOST = os.environ.get("JERITH_HOST_TARGET", "127.0.0.1:8301")
FOLLOWER_ID = os.environ.get("JERITH_FOLLOWER_ID", "jetson-follower")
POLL_BACKOFF_S = 5.0

DATA_DIR.mkdir(parents=True, exist_ok=True)

DDL = """
CREATE TABLE IF NOT EXISTS blocks (
    height INTEGER PRIMARY KEY,
    hash TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    miner TEXT NOT NULL,
    reward INTEGER NOT NULL,
    nonce INTEGER NOT NULL,
    difficulty INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS txs (
    txid TEXT PRIMARY KEY,
    height INTEGER,
    kind TEXT NOT NULL,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    amount INTEGER NOT NULL,
    fee INTEGER NOT NULL,
    nonce INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    memo TEXT DEFAULT '',
    vk TEXT DEFAULT '',
    signature TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'applied'
);
CREATE INDEX IF NOT EXISTS idx_txs_height ON txs(height);
CREATE TABLE IF NOT EXISTS sync_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


def local_height(conn) -> int:
    row = conn.execute("SELECT MAX(height) FROM blocks").fetchone()
    return int(row[0]) if row and row[0] is not None else -1


def wipe_tail(conn, keep_through: int) -> None:
    """Drop local blocks above keep_through (fork safety)."""
    with conn:
        conn.execute("DELETE FROM blocks WHERE height > ?", (keep_through,))
        conn.execute("DELETE FROM txs WHERE height > ?", (keep_through,))


def apply_block(conn, blk) -> None:
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO blocks (height, hash, prev_hash, timestamp,"
            " miner, reward, nonce, difficulty) VALUES (?,?,?,?,?,?,?,?)",
            (blk.height, blk.hash, blk.prev_hash, blk.timestamp, blk.miner,
             blk.reward_uj, blk.nonce, blk.difficulty))
        for raw in blk.tx_raw:
            d = json.loads(raw)
            txid = json.dumps({k: d[k] for k in sorted(d)}).encode()
            import hashlib as _h
            # txid mirrors host-side derivation from payload+signature
            tx_dict = {k: d[k] for k in ("kind", "sender", "recipient", "amount",
                                         "fee", "nonce", "timestamp", "memo", "vk")}
            payload = json.dumps(tx_dict, sort_keys=True, separators=(",", ":")).encode()
            sig = bytes.fromhex(d["signature"]) if d.get("signature") else b"\x00"
            txid = _h.sha256(payload + sig).hexdigest()
            conn.execute(
                "INSERT OR REPLACE INTO txs (txid, height, kind, sender, recipient,"
                " amount, fee, nonce, timestamp, memo, vk, signature, status)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'applied')",
                (txid, blk.height, d["kind"], d["sender"], d["recipient"],
                 d["amount"], d["fee"], d["nonce"], d["timestamp"], d["memo"],
                 d["vk"], d["signature"]))


def _metadata() -> list[tuple[str, str]]:
    tok = os.environ.get("JERITH_SYNC_TOKEN_FILE") and Path(
        os.environ["JERITH_SYNC_TOKEN_FILE"]).read_text().strip() \
        or os.environ.get("JERITH_SYNC_TOKEN", "")
    return [("authorization", f"Bearer {tok}")] if tok else []


def run() -> None:
    if DB_PATH.resolve() == (BASE_DIR / "data" / "jerith.db").resolve():
        raise SystemExit("refusing to follow into the authoritative data dir")
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.executescript(DDL)
    ca_path = os.environ.get("JERITH_SYNC_TLS_CA", "")
    if ca_path:
        creds = grpc.ssl_channel_credentials(
            root_certificates=Path(ca_path).read_bytes())
        channel = grpc.secure_channel(HOST, creds)
        mode = "TLS"
    else:
        channel = grpc.insecure_channel(HOST)
        mode = "insecure"
    stub = pb_grpc.ChainSyncStub(channel)
    print(f"follower following {HOST} ({mode}) into {DB_PATH}", flush=True)
    while True:
        try:
            h = local_height(conn)
            req = pb.SyncRequest(from_height=max(h + 1, 0), follower_id=FOLLOWER_ID)
            for blk in stub.StreamBlocks(req, timeout=3600, metadata=_metadata()):
                if blk.height <= local_height(conn):
                    continue
                if blk.prev_hash and blk.height > 0:
                    prev = conn.execute("SELECT hash FROM blocks WHERE height=?",
                                        (blk.height - 1,)).fetchone()
                    if prev and prev[0] != blk.prev_hash:
                        # fork: our tail diverged — drop our tail, let host re-send
                        wipe_tail(conn, blk.height - 2)
                        break
                apply_block(conn, blk)
                if blk.height % 25 == 0:
                    print(f"  synced height {blk.height}", flush=True)
        except grpc.RpcError as e:
            print(f"stream error ({e.code()}); reconnecting in {POLL_BACKOFF_S}s", flush=True)
            time.sleep(POLL_BACKOFF_S)
        except Exception as e:  # noqa: BLE001
            print(f"unexpected error: {e!r}; retrying", flush=True)
            time.sleep(POLL_BACKOFF_S)


if __name__ == "__main__":
    run()
