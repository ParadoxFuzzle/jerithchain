"""Fork selection / reorg tests (v1.1 stage 4, spec §7).

Rule under test: the valid chain with the greatest cumulative chain work
wins; ties keep the current chain; evicted txs re-enter the mempool.
Real PoW at legitimately retargeted difficulty (10 bits).
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import jerith_core as core                     # noqa: E402
import jerith_reorg as reorg                   # noqa: E402
import jerith_validate as val                  # noqa: E402


# ----------------------------------------------------------------- helpers --
def build_chain_with_fork(*, spend_in_main=True):
    """Chain to height 100 (slow history, diff 10), then main tail block A
    (height 101) and a competing branch A' (101) + C' (102).
    Returns (conn, ld, accounts, A, branch)."""
    conn = __import__("sqlite3").connect(":memory:")
    ld = core.Ledger(conn)
    sk, vk, owner = new_acct()
    sk2, vk2, miner2 = new_acct()
    _sk3, _vk3, a3 = new_acct()

    g = ld.build_genesis(owner, premine_sk=None)
    g.timestamp = int(time.time()) - 26_000
    ld.commit_genesis(g)
    step = core.TARGET_BLOCK_SECONDS * 4
    g_ts = g.timestamp
    for i in range(1, 101):
        # history without PoW: validate_branch only checks candidates; the
        # pre-fork tail is trusted local state (as in replay tools)
        blk = core.Block(height=i, prev_hash=ld.tip()[1],
                         timestamp=g_ts + i * step, txs=[], miner="",
                         reward=0, nonce=0)
        ld.append_block(blk, ld.next_difficulty())
    assert ld.next_difficulty() == 10

    now = int(time.time())
    # main tail: A pays owner's reward onward to a3 (spend inside the tail)
    rw = core.reward_for_height(101)
    reward_tx = core.Tx(kind="mine", sender=core.COINBASE_SENDER,
                        recipient=owner, amount=rw, fee=0, nonce=0,
                        timestamp=now)
    if spend_in_main:
        spend = core.make_tx(sk, a3, 1_000_000, nonce=0)
        A = core.Block(height=101, prev_hash=ld.tip()[1], timestamp=now,
                       txs=[reward_tx.to_dict(), spend.to_dict()],
                       miner=owner, reward=rw, nonce=0)
    else:
        A = core.Block(height=101, prev_hash=ld.tip()[1], timestamp=now,
                       txs=[reward_tx.to_dict()], miner=owner, reward=rw,
                       nonce=0)
    core.mine_block(A, 10, max_rounds=2**26)
    ld.append_block(A, 10)

    # competing branch: A' rewards miner2; C' extends it
    A2 = core.Block(height=101, prev_hash=ld.tip() and A.prev_hash,
                    timestamp=now, txs=[core.Tx(
                        kind="mine", sender=core.COINBASE_SENDER,
                        recipient=miner2, amount=rw, fee=0, nonce=0,
                        timestamp=now).to_dict()],
                    miner=miner2, reward=rw, nonce=0)
    core.mine_block(A2, 10, max_rounds=2**26)
    C2 = core.Block(height=102, prev_hash=A2.hash(), timestamp=now,
                    txs=[], miner=miner2, reward=0, nonce=0)
    core.mine_block(C2, 10, max_rounds=2**26)
    return conn, ld, (sk, vk, owner, sk2, vk2, miner2, a3), A, [A2, C2]


def new_acct():
    sk, vk = core.generate_keypair()
    return sk, vk, core.addr_from_vk(vk)


# ------------------------------------------------------------------- tests --
def test_branch_with_more_work_wins_and_reorgs():
    conn, ld, accts, A, branch = build_chain_with_fork()
    _sk, _vk, owner, _sk2, _vk2, miner2, _a3 = accts
    assert ld.tip()[0] == 101
    res = reorg.accept_branch(conn, branch)
    assert res["accepted"], res
    assert ld.tip()[0] == 102
    assert ld.tip()[1] == branch[-1].hash()
    # replay of the reorged chain is fully valid
    rep = val.replay_chain(conn, check_pow=False)
    assert rep["tip"] == ld.tip()[1]
    # balances were rewritten: owner lost A's reward, miner2 got it
    assert ld.balance(owner) == core.PREMINE
    assert ld.balance(miner2) == core.reward_for_height(101)


def test_equal_work_tie_keeps_current_chain():
    conn, ld, accts, A, branch = build_chain_with_fork(spend_in_main=False)
    A2 = branch[0]
    res = reorg.accept_branch(conn, [A2])          # same height, same work
    assert not res["accepted"]
    assert "insufficient_work" in res["reason"]
    assert ld.tip()[1] == A.hash()                  # unchanged


def test_invalid_branch_never_touches_ledger():
    conn, ld, accts, A, branch = build_chain_with_fork()
    _sk, _vk, owner, _sk2, vk2, _miner2, a3 = accts
    # corrupt the branch: forged spend from owner signed by miner2's key
    forged = core.Tx(kind="spend", sender=owner, recipient=a3, amount=1,
                     fee=100_000, nonce=0, timestamp=int(time.time()),
                     vk=vk2.hex())
    forged.signature = core.sign_tx_bytes(_sk2, forged.payload()).hex()
    bad = core.Block(height=branch[0].height, prev_hash=branch[0].prev_hash,
                     timestamp=branch[0].timestamp, txs=[forged.to_dict()],
                     miner=owner, reward=0, nonce=0)
    core.mine_block(bad, 10, max_rounds=2**26)
    before_tip, before_bal = ld.tip()[1], ld.balance(owner)
    res = reorg.accept_branch(conn, [bad, branch[1]])
    assert not res["accepted"]
    assert "tx_sender_mismatch" in res["reason"]
    assert ld.tip()[1] == before_tip and ld.balance(owner) == before_bal


def test_fork_point_mismatch_rejected():
    conn, ld, accts, A, branch = build_chain_with_fork()
    branch[0].prev_hash = "f" * 64
    res = reorg.accept_branch(conn, branch)
    assert not res["accepted"] and "fork_point" in res["reason"]


def test_evicted_tx_requeues_to_mempool():
    conn, ld, accts, A, branch = build_chain_with_fork(spend_in_main=True)
    _sk, _vk, owner, _sk2, _vk2, _miner2, a3 = accts
    # the spend inside A is displaced when the branch wins
    res = reorg.accept_branch(conn, branch)
    assert res["accepted"]
    assert len(res["requeued"]) == 1
    tx = core.Tx.from_dict(res["requeued"][0])
    # it validates against the post-reorg state (owner still has premine)
    ok, why = ld.validate_tx(tx)
    assert ok, why
    mem = ld.mempool_list()
    assert any(t.nonce == tx.nonce and t.sender == tx.sender for t in mem)


def test_simple_extension_accepted_without_reorg():
    """A branch starting at tip+1 is just an append — always accepted when
    valid (its work strictly exceeds the empty tail)."""
    conn, ld, accts, A, _branch = build_chain_with_fork(spend_in_main=False)
    _sk, _vk, owner, _sk2, _vk2, miner2, _a3 = accts
    now = int(time.time())
    ext = core.Block(height=102, prev_hash=ld.tip()[1], timestamp=now,
                     txs=[], miner=owner, reward=0, nonce=0)
    core.mine_block(ext, 10, max_rounds=2**26)
    res = reorg.accept_branch(conn, [ext])
    assert res["accepted"], res
    assert ld.tip()[1] == ext.hash()


def test_reward_from_displaced_tail_requeues_or_drops():
    """Reward txs (chain-minted) are NOT requeued — they are re-mintable;
    only signed spends return to the mempool."""
    conn, ld, accts, A, branch = build_chain_with_fork(spend_in_main=False)
    res = reorg.accept_branch(conn, branch)
    assert res["accepted"] and res["requeued"] == []
