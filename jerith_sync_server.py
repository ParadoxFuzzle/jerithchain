#!/usr/bin/env python3
"""JerithChain gRPC sync server (host side).

Streams the local ledger to follower nodes. Read-only over the wire: a
follower can never push anything back; compromise impact = information only.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "gen"))

import grpc                                  # noqa: E402
from concurrent import futures               # noqa: E402

import jerith_core as core                   # noqa: E402
import jerith_wallet as sec                  # noqa: E402
import jerith_sync_pb2 as pb                 # noqa: E402
import jerith_sync_pb2_grpc as pb_grpc       # noqa: E402

DATA_DIR = Path(os.environ.get("JERITH_DATA_DIR", BASE_DIR / "data"))
DB_PATH = DATA_DIR / "jerith.db"
PORT = int(os.environ.get("JERITH_SYNC_PORT", "8301"))
POLL_SECONDS = 2.0
PROTOCOL_VERSION = "1.1"
SOFTWARE_VERSION = "1.1.0"

STARTED = time.time()

# v1.0 sync used a read-only connection; gossip needs write access for
# mempool and (on full nodes) branch acceptance. Read-only mode is kept
# for pure followers via JERITH_SYNC_READONLY=1.
READONLY = os.environ.get("JERITH_SYNC_READONLY", "") == "1"
_uri = f"file:{DB_PATH}?mode=ro" if READONLY else f"file:{DB_PATH}"
conn = sqlite3.connect(_uri, uri=True, check_same_thread=False)
conn.execute("PRAGMA journal_mode=WAL")
_gossip_lock = threading.Lock()


def _block_to_wire(blk, difficulty: int):
    txs = conn.execute(
        "SELECT kind, sender, recipient, amount, fee, nonce, timestamp, memo,"
        " vk, signature FROM txs WHERE height=?", (blk.height,)).fetchall()
    wire = pb.SyncBlock(
        height=blk.height, hash=blk.hash(), prev_hash=blk.prev_hash,
        timestamp=blk.timestamp, miner=blk.miner, reward_uj=blk.reward,
        nonce=blk.nonce, difficulty=difficulty)
    for t in txs:
        d = dict(zip(("kind", "sender", "recipient", "amount", "fee",
                      "nonce", "timestamp", "memo", "vk", "signature"), t))
        wire.tx_raw.append(json.dumps(d, sort_keys=True).encode())
    return wire


def fetch_block(height: int):
    row = conn.execute(
        "SELECT height, hash, prev_hash, timestamp, miner, reward, nonce, difficulty"
        " FROM blocks WHERE height=?", (height,)).fetchone()
    if not row:
        return None
    txs = conn.execute(
        "SELECT kind, sender, recipient, amount, fee, nonce, timestamp, memo, vk, signature"
        " FROM txs WHERE height=?", (height,)).fetchall()
    blk = pb.SyncBlock(
        height=row[0], hash=row[1], prev_hash=row[2], timestamp=row[3],
        miner=row[4], reward_uj=row[5], nonce=row[6], difficulty=row[7])
    for t in txs:
        d = {"kind": t[0], "sender": t[1], "recipient": t[2], "amount": t[3],
             "fee": t[4], "nonce": t[5], "timestamp": t[6], "memo": t[7],
             "vk": t[8], "signature": t[9]}
        blk.tx_raw.append(json.dumps(d, sort_keys=True).encode())
    return blk


def tip_height() -> int:
    row = conn.execute("SELECT MAX(height) FROM blocks").fetchone()
    return int(row[0]) if row and row[0] is not None else -1


class ChainSync(pb_grpc.ChainSyncServicer):
    def StreamBlocks(self, request, context):
        height = int(request.from_height)
        follower = request.follower_id or "anonymous"
        active = context.is_active()
        while context.is_active():
            tip = tip_height()
            while height <= tip:
                blk = fetch_block(height)
                if blk is None:
                    break
                yield blk
                height += 1
            time.sleep(POLL_SECONDS)

    def GetStatus(self, request, context):
        height = tip_height()
        row = None
        if height >= 0:
            row = conn.execute(
                "SELECT hash, difficulty FROM blocks WHERE height=?", (height,)).fetchone()
        return pb.SyncStatus(
            height=max(height, 0),
            tip_hash=row[0] if row else "",
            difficulty=row[1] if row else core.GENESIS_DIFFICULTY,
            uptime_s=int(time.time() - STARTED))

    # ---------------- v1.1 gossip ----------------

    def SubmitTransaction(self, request, context):
        if READONLY:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION,
                          "read-only sync node does not accept gossip")
        try:
            td = json.loads(request.tx_json)
        except Exception:  # noqa: BLE001
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "tx_json not valid JSON")
        try:
            tx = core.Tx.from_dict(td)
        except Exception as e:  # noqa: BLE001
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"bad tx fields: {e}")
        with _gossip_lock:
            ok, why = core.Ledger(conn).mempool_add(tx)
        if not ok:
            return pb.SubmitTxResponse(accepted=False, txid="", reason=str(why))
        return pb.SubmitTxResponse(accepted=True, txid=str(why), reason="ok")

    def SubmitBlock(self, request, context):
        if READONLY:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION,
                          "read-only sync node does not accept gossip")
        try:
            bd = json.loads(request.block_json)
        except Exception:  # noqa: BLE001
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "block_json not valid JSON")

        def _mk(d):
            return core.Block(
                height=int(d["height"]), prev_hash=str(d["prev_hash"]),
                timestamp=int(d["timestamp"]),
                txs=list(d.get("txs") or []), miner=str(d.get("miner", "")),
                reward=int(d.get("reward", 0)), nonce=int(d.get("nonce", 0)))

        # single block (dict) or a whole competing branch (list of dicts)
        try:
            blocks = [_mk(d) for d in bd] if isinstance(bd, list) else [_mk(bd)]
        except Exception as e:  # noqa: BLE001
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"bad block fields: {e}")
        import jerith_reorg
        with _gossip_lock:
            try:
                res = jerith_reorg.accept_branch(conn, blocks)
            except Exception as e:  # noqa: BLE001  # never kill the streamer on bad input
                return pb.SubmitBlockResponse(accepted=False, reason=f"error: {e}")
        row = conn.execute(
            "SELECT MAX(height), (SELECT hash FROM blocks b2 WHERE b2.height ="
            " blocks.height) FROM blocks").fetchone()
        tip_h = conn.execute("SELECT MAX(height) FROM blocks").fetchone()[0]
        tip_hash_row = conn.execute(
            "SELECT hash FROM blocks WHERE height=?", (tip_h,)).fetchone()
        return pb.SubmitBlockResponse(
            accepted=bool(res["accepted"]), reason=res["reason"],
            tip_height=max(int(tip_h or 0), 0),
            tip_hash=tip_hash_row[0] if tip_hash_row else "")

    def GetMempool(self, request, context):
        limit = int(request.limit or 500)
        rows = conn.execute(
            "SELECT payload FROM mempool ORDER BY received LIMIT ?",
            (min(limit, 2000),)).fetchall()
        snap = pb.MempoolSnapshot(size=len(rows))
        for (p,) in rows:
            snap.tx_json.append(p.encode())
        return snap

    def GetNetworkInfo(self, request, context):
        tip_h = conn.execute("SELECT MAX(height) FROM blocks").fetchone()[0]
        tip_h = int(tip_h) if tip_h is not None else -1
        tip_row = conn.execute(
            "SELECT hash, difficulty FROM blocks WHERE height=?", (tip_h,)).fetchone()
        work = 0
        if tip_h >= 0:
            work = core.Ledger(conn).work_above(-1)
        mem = conn.execute("SELECT COUNT(*) FROM mempool").fetchone()[0]
        return pb.NetworkInfo(
            height=max(tip_h, 0), tip_hash=tip_row[0] if tip_row else "",
            difficulty=tip_row[1] if tip_row else core.GENESIS_DIFFICULTY,
            chain_work=work, mempool_size=int(mem),
            protocol_version=PROTOCOL_VERSION,
            software_version=SOFTWARE_VERSION,
            uptime_s=int(time.time() - STARTED))


def _load_env_file(path_env: str) -> str:
    p = Path(path_env)
    return p.read_text().strip() if p.exists() else ""


TOKEN = os.environ.get("JERITH_SYNC_TOKEN_FILE") and _load_env_file(os.environ["JERITH_SYNC_TOKEN_FILE"]) \
    or os.environ.get("JERITH_SYNC_TOKEN", "")


class _Auth(grpc.ServerInterceptor):
    """Rejects calls without a valid Bearer token when TOKEN is configured."""

    def intercept_service(self, continuation, handler_call_details):
        if not TOKEN:
            return continuation(handler_call_details)
        md = dict(handler_call_details.invocation_metadata or ())
        auth = md.get("authorization", "")
        if auth and sec.hmac.compare_digest(auth, f"Bearer {TOKEN}"):
            return continuation(handler_call_details)
        def deny(request, context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid sync token")
        return grpc.unary_unary_rpc_method_handler(deny)


def serve() -> None:
    cert_path = os.environ.get("JERITH_SYNC_TLS_CERT", "")
    key_path = os.environ.get("JERITH_SYNC_TLS_KEY", "")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8),
                         interceptors=[_Auth()])
    pb_grpc.add_ChainSyncServicer_to_server(ChainSync(), server)
    if cert_path and key_path:
        creds = grpc.ssl_server_credentials(
            [(open(key_path, "rb").read(), open(cert_path, "rb").read())])
        bound = server.add_secure_port(f"[::]:{PORT}", creds)
        mode = "TLS"
    else:
        bound = server.add_insecure_port(f"[::]:{PORT}")
        mode = "insecure"
    if bound == 0:
        raise RuntimeError(f"could not bind sync server port {PORT}")
    server.start()
    auth = "token-auth" if TOKEN else "NO-AUTH"
    print(f"JerithChain sync server on :{PORT} ({mode}, {auth}) tip={tip_height()}", flush=True)
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
