"""JerithChain v1.1 gossip client.

Shared client-side plumbing for nodes and followers: static peer
configuration (peers.json), transaction/block relay, and network info.

peers.json format (same dir as the repo, or JERITH_PEERS_FILE):
{
  "peers": [
    {"target": "127.0.0.1:8301", "tls": false, "name": "founder"},
    {"target": "node-b.example.com:8301", "tls": true,
     "ca": "/path/ca.pem", "token_file": "/path/token", "name": "node-b"}
  ]
}
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import grpc

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "gen"))

import jerith_sync_pb2 as pb                 # noqa: E402
import jerith_sync_pb2_grpc as pb_grpc       # noqa: E402

PROTOCOL_VERSION = "1.1"
SOFTWARE_VERSION = "1.1.0"


def load_peers(path: str | None = None) -> list[dict]:
    """Read peers.json; returns list of peer dicts. Missing file = no peers."""
    p = Path(path or os.environ.get("JERITH_PEERS_FILE", BASE_DIR / "peers.json"))
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError:
        return []
    out = []
    for entry in data.get("peers", []):
        if isinstance(entry, dict) and entry.get("target"):
            out.append(entry)
    return out


def _channel(peer: dict) -> grpc.Channel:
    target = peer["target"]
    if peer.get("tls"):
        ca = peer.get("ca")
        creds = grpc.ssl_channel_credentials(
            root_certificates=Path(ca).read_bytes() if ca else None)
        return grpc.secure_channel(target, creds)
    return grpc.insecure_channel(target)


def _metadata(peer: dict) -> list[tuple[str, str]]:
    tok_file = peer.get("token_file")
    tok = ""
    if tok_file and Path(tok_file).exists():
        tok = Path(tok_file).read_text().strip()
    elif peer.get("token"):
        tok = peer["token"]
    return [("authorization", f"Bearer {tok}")] if tok else []


def relay_transaction(peer: dict, tx_dict: dict, timeout: float = 5.0) -> dict:
    """Submit a signed tx dict to one peer. Returns {accepted, txid, reason}."""
    with _channel(peer) as ch:
        stub = pb_grpc.ChainSyncStub(ch)
        r = stub.SubmitTransaction(
            pb.SubmitTxRequest(tx_json=json.dumps(tx_dict).encode()),
            timeout=timeout, metadata=_metadata(peer))
        return {"accepted": r.accepted, "txid": r.txid, "reason": r.reason}


def relay_block(peer: dict, block, timeout: float = 10.0) -> dict:
    """Submit a mined core.Block, or a whole branch (list of core.Block),
    to one peer. Returns {accepted, reason, tip_height, tip_hash}."""
    if isinstance(block, (list, tuple)):
        bd = [{"height": b.height, "prev_hash": b.prev_hash,
               "timestamp": b.timestamp, "txs": b.txs, "miner": b.miner,
               "reward": b.reward, "nonce": b.nonce} for b in block]
    else:
        bd = {"height": block.height, "prev_hash": block.prev_hash,
              "timestamp": block.timestamp, "txs": block.txs,
              "miner": block.miner, "reward": block.reward, "nonce": block.nonce}
    with _channel(peer) as ch:
        stub = pb_grpc.ChainSyncStub(ch)
        r = stub.SubmitBlock(
            pb.SubmitBlockRequest(block_json=json.dumps(bd).encode()),
            timeout=timeout, metadata=_metadata(peer))
        return {"accepted": r.accepted, "reason": r.reason,
                "tip_height": int(r.tip_height), "tip_hash": r.tip_hash}


def broadcast(peer_list: list[dict], fn, *args) -> list[dict]:
    """Fan out to all peers; never raises. Returns per-peer results."""
    results = []
    for peer in peer_list:
        try:
            results.append({"peer": peer.get("target", "?"), **fn(peer, *args)})
        except grpc.RpcError as e:
            results.append({"peer": peer.get("target", "?"),
                            "accepted": False, "reason": f"rpc {e.code()}"})
        except Exception as e:  # noqa: BLE001
            results.append({"peer": peer.get("target", "?"),
                            "accepted": False, "reason": f"error: {e}"})
    return results


def broadcast_transaction(peer_list: list[dict], tx_dict: dict) -> list[dict]:
    return broadcast(peer_list, relay_transaction, tx_dict)


def broadcast_block(peer_list: list[dict], block) -> list[dict]:
    return broadcast(peer_list, relay_block, block)


def network_info(peer: dict, timeout: float = 5.0) -> dict:
    with _channel(peer) as ch:
        stub = pb_grpc.ChainSyncStub(ch)
        r = stub.GetNetworkInfo(pb.NetworkInfoRequest(),
                                timeout=timeout, metadata=_metadata(peer))
        return {"height": int(r.height), "tip_hash": r.tip_hash,
                "difficulty": int(r.difficulty), "chain_work": int(r.chain_work),
                "mempool_size": int(r.mempool_size),
                "protocol_version": r.protocol_version,
                "software_version": r.software_version,
                "uptime_s": int(r.uptime_s)}


def fetch_mempool(peer: dict, limit: int = 500, timeout: float = 5.0) -> list[dict]:
    with _channel(peer) as ch:
        stub = pb_grpc.ChainSyncStub(ch)
        r = stub.GetMempool(pb.GetMempoolRequest(limit=limit),
                            timeout=timeout, metadata=_metadata(peer))
        return [json.loads(t) for t in r.tx_json]
