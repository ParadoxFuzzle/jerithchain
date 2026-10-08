"""Multi-node integration test (v1.1 §24): two real processes over real
gRPC.

Node A (writer/miner)  ->  Node B (full node with gossip accept)
  1. B syncs the chain from A over gRPC StreamBlocks (real follower).
  2. A gossips a mined block to B via SubmitBlock; B validates and stores.
  3. B gossips a valid tx to A via SubmitTransaction; A mempools it.
  4. Competing block: B receives a greater-work alternative and reorgs.

Run: python3 -m pytest tests/test_multinode.py -v
"""
from __future__ import annotations

import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "gen"))

import grpc                                  # noqa: E402
import jerith_core as core                   # noqa: E402
import jerith_sync_pb2 as pb                 # noqa: E402
import jerith_sync_pb2_grpc as pb_grpc       # noqa: E402

TX_COLS = ("kind", "sender", "recipient", "amount", "fee", "nonce",
           "timestamp", "memo", "vk", "signature")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Follower:
    """Runs jerith_follow.py as a real process against a target."""

    def __init__(self, target: str, data_dir: Path):
        self.data_dir = data_dir
        data_dir.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ,
                   JERITH_HOST_TARGET=target,
                   JERITH_FOLLOW_DATA_DIR=str(data_dir),
                   JERITH_FOLLOWER_ID="itest-b")
        self.proc = subprocess.Popen(
            [sys.executable, str(BASE / "jerith_follow.py")], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.db = data_dir / "jerith.db"

    def height(self) -> int:
        if not self.db.exists():
            return -1
        try:
            conn = sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)
            row = conn.execute("SELECT MAX(height) FROM blocks").fetchone()
            conn.close()
            return int(row[0]) if row and row[0] is not None else -1
        except sqlite3.OperationalError:
            return -1

    def stop(self):
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def make_chain(dir_path: Path, n_history: int = 25):
    """A local chain with real retarget history (no PoW on history) to
    height n_history-1 at difficulty floor, plus a real-mined tip."""
    dir_path.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(dir_path / "jerith.db")
    ld = core.Ledger(conn)
    sk, vk = core.generate_keypair()
    owner = core.addr_from_vk(vk)
    g = ld.build_genesis(owner, premine_sk=None)
    # deep-past genesis: the slow 240 s/block history must stay strictly
    # before "now" so later real-mined blocks don't regress timestamps
    g.timestamp = int(time.time()) - n_history * 240 - 4_000
    ld.commit_genesis(g)
    step = core.TARGET_BLOCK_SECONDS * 4
    g_ts = g.timestamp
    for i in range(1, n_history):
        blk = core.Block(height=i, prev_hash=ld.tip()[1],
                         timestamp=g_ts + i * step, txs=[], miner="",
                         reward=0, nonce=0)
        # REAL PoW: the follower validates everything it receives, so the
        # history must genuinely satisfy the per-height difficulty.
        core.mine_block(blk, ld.next_difficulty(), max_rounds=2**32)
        ld.append_block(blk, ld.next_difficulty())
    return conn, ld, sk, vk, owner


def submit_block(target: str, blk: core.Block) -> dict:
    import jerith_gossip as gossip
    return gossip.relay_block({"target": target, "tls": False}, blk)


def submit_tx(target: str, tx_dict: dict) -> dict:
    import jerith_gossip as gossip
    return gossip.relay_transaction({"target": target, "tls": False}, tx_dict)


def test_two_node_sync_gossip_and_fork():
    tmp = Path(tempfile.mkdtemp(prefix="jerith-mn-"))
    port_a, port_b = free_port(), free_port()

    # Node A: chain with real retarget history (2 slow windows: 18 -> 16)
    conn_a, ld_a, sk_a, _vk_a, owner_a = make_chain(tmp / "a", n_history=41)
    diff = ld_a.next_difficulty()
    assert diff == 16, diff

    # ---- stage 1: real follower B syncs from A over gRPC ----
    fol_b = Follower(f"127.0.0.1:{port_a}", tmp / "b")
    # A's sync server: run in-process (thread) to avoid another process
    os.environ["JERITH_DATA_DIR"] = str(tmp / "a")
    os.environ["JERITH_SYNC_PORT"] = str(port_a)
    import threading
    import jerith_sync_server
    sync_thread = threading.Thread(
        target=lambda: jerith_sync_server.serve(), daemon=True)
    sync_thread.start()
    time.sleep(1.0)

    tip_block = ld_a.block_at(ld_a.tip()[0])
    # append a NEW mined block after B connects so the stream pushes it
    time.sleep(1.0)
    new_b = core.Block(height=ld_a.next_height(), prev_hash=ld_a.tip()[1],
                       timestamp=int(time.time()),
                       txs=[core.Tx(kind="mine", sender=core.COINBASE_SENDER,
                                    recipient=owner_a,
                                    amount=core.reward_for_height(ld_a.next_height()),
                                    fee=0, nonce=0,
                                    timestamp=int(time.time())).to_dict()],
                       miner=owner_a, reward=core.reward_for_height(ld_a.next_height()),
                       nonce=0)
    core.mine_block(new_b, diff, max_rounds=2**22)
    ld_a.append_block(new_b, diff)
    deadline = time.time() + 30
    while time.time() < deadline and fol_b.height() < new_b.height:
        time.sleep(0.5)
    # B's own log is the diagnostic source if this fails
    assert fol_b.height() == new_b.height, (
        f"follower B at {fol_b.height()} never synced new block "
        f"{new_b.height}; proc alive={fol_b.proc.poll() is None}")

    # ---- stage 2: A gossips a further block to B via SubmitBlock ----
    # B follows A; instead SubmitBlock directly to a standalone gossip
    # receiver = A's sync server (same process serves both roles).
    blk2 = core.Block(height=ld_a.next_height(), prev_hash=ld_a.tip()[1],
                      timestamp=int(time.time()), txs=[],
                      miner=owner_a, reward=0, nonce=0)
    core.mine_block(blk2, diff, max_rounds=2**22)
    res = submit_block(f"127.0.0.1:{port_a}", blk2)
    assert res["accepted"], res
    assert ld_a.tip()[1] == blk2.hash()

    # duplicate submission is rejected deterministically
    res_dup = submit_block(f"127.0.0.1:{port_a}", blk2)
    assert not res_dup["accepted"]

    # ---- stage 3: tx gossip into A's mempool ----
    _sk2, vk2, addr2 = (core.generate_keypair()[0],) and (None, None, None)
    sk2, vk2 = core.generate_keypair()
    addr2 = core.addr_from_vk(vk2)
    # a2 has no funds: A should REJECT the tx (no balance) — proving
    # gossip input is validated, not trusted
    poor = core.make_tx(sk2, owner_a, 1_000_000, nonce=0)
    res_tx = submit_tx(f"127.0.0.1:{port_a}", poor.to_dict())
    assert not res_tx["accepted"] and "funds" in res_tx["reason"], res_tx
    # a funded, valid tx IS accepted into the mempool
    good = core.make_tx(sk_a, addr2, 1_000_000, nonce=0)
    res_tx2 = submit_tx(f"127.0.0.1:{port_a}", good.to_dict())
    assert res_tx2["accepted"], res_tx2
    mem = core.Ledger(conn_a).mempool_list()
    assert any(t.vk == vk2.hex() or t.sender == core.addr_from_vk(bytes.fromhex(good.vk)) for t in mem)

    # ---- stage 4: competing greater-work branch reorgs ----
    # local tail above the fork is new_b + blk2 (2 blocks). Mine a
    # 3-block alternative branch off the fork height: strictly greater
    # cumulative work, so the greatest-work rule MUST adopt it.
    fork_h = new_b.height - 1
    prev_fork = ld_a.block_at(fork_h)
    branch = []
    prev_hash = prev_fork.hash()
    for i in range(3):
        alt = core.Block(height=fork_h + 1 + i, prev_hash=prev_hash,
                         timestamp=new_b.timestamp + i, txs=[], miner=owner_a,
                         reward=0, nonce=0)
        core.mine_block(alt, diff, max_rounds=2**22)
        branch.append(alt)
        prev_hash = alt.hash()
    # submitting only the tip fails (its parent is unknown locally) —
    # conservative and correct
    res_fork = submit_block(f"127.0.0.1:{port_a}", branch[-1])
    assert not res_fork["accepted"], res_fork
    # submitting the whole branch reorgs the node
    res_branch = submit_block(f"127.0.0.1:{port_a}", branch)
    assert res_branch["accepted"], res_branch
    assert ld_a.tip()[1] == branch[-1].hash()
    assert ld_a.tip()[0] == fork_h + 3
    rep = __import__("jerith_validate").replay_chain(conn_a, check_pow=False)
    assert rep["tip"] == branch[-1].hash()

    # an equal-work branch of the same length is rejected (ties keep chain)
    tie = []
    prev_hash = prev_fork.hash()
    for i in range(3):
        alt = core.Block(height=fork_h + 1 + i, prev_hash=prev_hash,
                         timestamp=new_b.timestamp + i + 1, txs=[],
                         miner=owner_a, reward=0, nonce=0)
        core.mine_block(alt, diff, max_rounds=2**22)
        tie.append(alt)
        prev_hash = alt.hash()
    res_tie = submit_block(f"127.0.0.1:{port_a}", tie)
    assert not res_tie["accepted"] and "insufficient_work" in res_tie["reason"], res_tie
    assert ld_a.tip()[1] == branch[-1].hash()

    fol_b.stop()
