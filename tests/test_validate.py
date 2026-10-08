"""Canonical-validator consensus tests (v1.1 stages 1-3).

Run: python3 -m pytest tests/test_validate.py -v

Speed: real blocks are mined at low difficulty reached LEGITIMATELY via
the retarget rule — history is appended without PoW (trusted local
build, as replay tools do) with slow timestamps so
core.expected_difficulty itself drives difficulty down 18 -> 10.
"""
from __future__ import annotations

import sqlite3
import sys
import time
from pathlib import Path

import pytest

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import jerith_core as core                     # noqa: E402
import jerith_validate as val                  # noqa: E402

TX_COLS = ("kind", "sender", "recipient", "amount", "fee", "nonce",
           "timestamp", "memo", "vk", "signature")


# ----------------------------------------------------------------- helpers --
def fresh_ledger():
    conn = sqlite3.connect(":memory:")
    return conn, core.Ledger(conn)


def new_account():
    sk, vk = core.generate_keypair()
    return sk, vk, core.addr_from_vk(vk)


BLK_COLS = "height, hash, prev_hash, timestamp, miner, reward, nonce"


def seed_chain(ld, owner, aged: bool = True):
    """Genesis with an aged timestamp (so slow retarget history can span
    24k s without touching the future-timestamp bound)."""
    g = ld.build_genesis(owner, premine_sk=None)
    if aged:
        g.timestamp = int(time.time()) - 26_000
    ld.commit_genesis(g)
    return g


def slow_history(ld, windows: int = 5):
    """Append `windows` retarget windows without PoW, timestamps anchored
    to the (aged) genesis and increasing 240 s/block: difficulty
    18 -> 10 (-2 bits/window, 4x clamp), all in the past."""
    step = core.TARGET_BLOCK_SECONDS * 4
    g_ts = ld.tip()[2]
    height = ld.tip()[0] if ld.tip() else -1
    for i in range(1, windows * core.RETARGET_INTERVAL + 1):
        height += 1
        blk = core.Block(height=height, prev_hash=ld.tip()[1],
                         timestamp=g_ts + i * step, txs=[], miner="",
                         reward=0, nonce=0)
        ld.append_block(blk, ld.next_difficulty())
    assert ld.next_difficulty() == 10, ld.next_difficulty()


def state_from_chain(conn) -> val.ReplayState:
    """ReplayState rebuilt from a Ledger DB (trusted local state)."""
    st = val.ReplayState()
    for (h, ts, diff) in conn.execute(
            "SELECT height, timestamp, difficulty FROM blocks ORDER BY height"):
        st.snapshot_rows(h, ts, diff)
    for row in conn.execute(
            f"SELECT {','.join(TX_COLS)} FROM txs ORDER BY height, rowid"):
        st.apply(dict(zip(TX_COLS, row)))
    return st


def recon_prev(conn, height: int):
    """Reconstruct the local block at height-1 (same as the node does)."""
    row = conn.execute(
        "SELECT height, hash, prev_hash, timestamp, miner, reward, nonce"
        " FROM blocks WHERE height=?", (height - 1,)).fetchone()
    if not row:
        return None
    txs = [dict(zip(TX_COLS, t)) for t in conn.execute(
        f"SELECT {','.join(TX_COLS)} FROM txs WHERE height=?", (row[0],))]
    # columns: height, hash, prev_hash, timestamp, miner, reward, nonce
    return core.Block(height=row[0], prev_hash=row[2], timestamp=row[3],
                      txs=txs, miner=row[4], reward=row[5], nonce=row[6])


def reward_block(ld, miner_addr, height=None, ts=None, reward=None):
    height = ld.next_height() if height is None else height
    ts = int(time.time()) if ts is None else ts
    reward = core.reward_for_height(height) if reward is None else reward
    tx = core.Tx(kind="mine", sender=core.COINBASE_SENDER, recipient=miner_addr,
                 amount=reward, fee=0, nonce=0, timestamp=ts)
    return core.Block(height=height, prev_hash=ld.tip()[1], timestamp=ts,
                      txs=[tx.to_dict()], miner=miner_addr, reward=reward,
                      nonce=0)


def mine(blk, difficulty=None):
    core.mine_block(blk, difficulty or 10, max_rounds=2**24)
    return blk


# ------------------------------------------------------------------ genesis --
def test_genesis_validates():
    conn, ld = fresh_ledger()
    _sk, _vk, owner = new_account()
    g = seed_chain(ld, owner, aged=False)
    assert val.validate_block(g, None, val.ReplayState())
    bad = core.Block(height=0, prev_hash="0" * 64, timestamp=g.timestamp,
                     txs=[dict(g.txs[0], amount=core.PREMINE + 1)],
                     miner=owner, reward=0, nonce=0)
    assert val.validate_block(bad, None, val.ReplayState()).code == "genesis_premine"
    bad2 = core.Block(height=0, prev_hash="0" * 64, timestamp=g.timestamp,
                      txs=[g.txs[0], dict(g.txs[0])], miner=owner, reward=0,
                      nonce=0)
    assert val.validate_block(bad2, None, val.ReplayState()).code == "genesis_txs"


# --------------------------------------------------------------------- PoW --
def test_good_block_passes_after_legit_retarget():
    conn, ld = fresh_ledger()
    _sk, _vk, owner = new_account()
    g = seed_chain(ld, owner)
    slow_history(ld)
    prev = recon_prev(conn, ld.next_height())
    st = state_from_chain(conn)
    blk = reward_block(ld, owner)
    assert val.validate_block(mine(blk), prev, st), val.validate_block(blk, prev, st).reason
    # supply consistency: emitted = premine + schedule
    st2 = state_from_chain(conn)
    assert st2.total_emitted() == core.PREMINE


def test_bad_pow_rejected():
    conn, ld = fresh_ledger()
    _sk, _vk, owner = new_account()
    g = seed_chain(ld, owner)
    slow_history(ld)
    prev = recon_prev(conn, ld.next_height())
    st = state_from_chain(conn)
    blk = mine(reward_block(ld, owner))
    blk.nonce += 1                                    # break the PoW
    r = val.validate_block(blk, prev, st)
    assert not r and r.code == "pow", r
    blk2 = mine(reward_block(ld, owner), difficulty=8)   # below expected 10
    # avoid the ~25% chance an 8-bit nonce also satisfies 10 bits
    while core.meets_difficulty(bytes.fromhex(blk2.hash()), 10):
        blk2.nonce += 1
    r2 = val.validate_block(blk2, prev, st)
    assert not r2 and r2.code == "pow", r2


def test_claimed_hash_mismatch_rejected():
    conn, ld = fresh_ledger()
    _sk, _vk, owner = new_account()
    g = seed_chain(ld, owner)
    slow_history(ld)
    prev = recon_prev(conn, ld.next_height())
    st = state_from_chain(conn)
    blk = mine(reward_block(ld, owner))
    r = val.validate_block(blk, prev, st, claimed_hash="a" * 64)
    assert not r and r.code == "hash_mismatch", r


def test_wrong_height_and_prev_rejected():
    conn, ld = fresh_ledger()
    _sk, _vk, owner = new_account()
    g = ld.build_genesis(owner, premine_sk=None)
    ld.commit_genesis(g)
    st = state_from_chain(conn)
    blk = reward_block(ld, owner, height=2)
    blk.nonce = 0
    assert val.validate_block(blk, g, st).code == "height"
    blk2 = reward_block(ld, owner, height=1)
    blk2.prev_hash = "f" * 64
    assert val.validate_block(blk2, g, st).code == "prev_hash"


# ------------------------------------------------------------------ reward --
def test_inflated_reward_rejected():
    conn, ld = fresh_ledger()
    _sk, _vk, owner = new_account()
    g = seed_chain(ld, owner)
    slow_history(ld)
    prev = recon_prev(conn, ld.next_height())
    st = state_from_chain(conn)
    blk = mine(reward_block(ld, owner, reward=core.reward_for_height(ld.next_height()) * 2))
    r = val.validate_block(blk, prev, st)
    assert not r and r.code == "reward_too_large", r


def test_reward_field_mismatch_rejected():
    conn, ld = fresh_ledger()
    _sk, _vk, owner = new_account()
    g = seed_chain(ld, owner)
    slow_history(ld)
    prev = recon_prev(conn, ld.next_height())
    st = state_from_chain(conn)
    blk = reward_block(ld, owner, reward=1)
    blk.reward = 99                                   # header/tx disagree...
    mine(blk)                                          # ...then hash it
    r = val.validate_block(blk, prev, st)
    assert not r and r.code == "reward_field", r


def test_multiple_rewards_rejected():
    conn, ld = fresh_ledger()
    _sk, _vk, owner = new_account()
    g = seed_chain(ld, owner)
    slow_history(ld)
    prev = recon_prev(conn, ld.next_height())
    st = state_from_chain(conn)
    t1 = core.Tx(kind="mine", sender=core.COINBASE_SENDER, recipient=owner,
                 amount=1, fee=0, nonce=0, timestamp=int(time.time())).to_dict()
    blk = core.Block(height=ld.next_height(), prev_hash=ld.tip()[1],
                     timestamp=int(time.time()), txs=[t1, dict(t1)],
                     miner=owner, reward=0, nonce=0)
    r = val.validate_block(mine(blk), prev, st)
    assert not r and r.code == "reward_multiple", r


# ------------------------------------------------------------- transactions --
def _two_block_fund():
    """genesis -> slow history -> reward block 101 -> spend block 102.
    Returns (conn, ld, st_after_101, prev2, spend_tx, a2)."""
    conn, ld = fresh_ledger()
    sk, vk, owner = new_account()
    g = seed_chain(ld, owner)
    slow_history(ld)
    _sk2, _vk2, a2 = new_account()
    now = int(time.time())
    b1 = mine(reward_block(ld, owner, ts=now))
    assert val.validate_block(b1, recon_prev(conn, ld.next_height()),
                              state_from_chain(conn))
    ld.append_block(b1, 10)
    st = state_from_chain(conn)
    spend = core.make_tx(sk, a2, 1_000_000, nonce=0)
    b2 = core.Block(height=ld.next_height(), prev_hash=b1.hash(),
                    timestamp=now, txs=[spend.to_dict()], miner=owner,
                    reward=0, nonce=0)
    prev2 = recon_prev(conn, ld.next_height())
    return conn, ld, st, prev2, b1, b2, spend, a2, owner


def test_spend_good_and_nonce_enforced():
    conn, ld, st, prev2, _b1, b2, _spend, _a2, _owner = _two_block_fund()
    assert val.validate_block(mine(b2), prev2, st), val.validate_block(b2, prev2, st).reason
    # replay the spend into state, then resend the SAME tx (nonce replay)
    st.apply(b2.txs[0])
    st.snapshot_rows(b2.height, b2.timestamp, 10)
    b3 = core.Block(height=b2.height + 1, prev_hash=b2.hash(),
                    timestamp=int(time.time()), txs=[b2.txs[0]],
                    miner=_owner, reward=0, nonce=0)
    r = val.validate_block(mine(b3), b2, st)
    assert not r and r.code == "tx_nonce", r


def test_forged_sender_rejected():
    conn, ld = fresh_ledger()
    sk, vk, owner = new_account()
    g = seed_chain(ld, owner)
    slow_history(ld)
    st = state_from_chain(conn)
    _sk2, vk2, a2 = new_account()
    now = int(time.time())
    forged = core.Tx(kind="spend", sender=owner, recipient=a2, amount=1,
                     fee=100_000, nonce=0, timestamp=now, vk=vk2.hex())
    forged.signature = core.sign_tx_bytes(_sk2, forged.payload()).hex()
    b1 = core.Block(height=ld.next_height(), prev_hash=ld.tip()[1],
                    timestamp=now, txs=[forged.to_dict()], miner=owner,
                    reward=0, nonce=0)
    prev = recon_prev(conn, ld.next_height())
    r = val.validate_block(mine(b1), prev, st)
    assert not r and r.code == "tx_sender_mismatch", r


def test_bad_signature_and_insufficient_balance_rejected():
    conn, ld = fresh_ledger()
    sk, vk, owner = new_account()
    g = seed_chain(ld, owner)
    slow_history(ld)
    st = state_from_chain(conn)
    _sk2, _vk2, a2 = new_account()
    now = int(time.time())
    # a2 has zero balance but signs a real spend
    spend = core.make_tx(_sk2, owner, 1_000_000, nonce=0)
    b1 = core.Block(height=ld.next_height(), prev_hash=ld.tip()[1],
                    timestamp=now, txs=[spend.to_dict()], miner=owner,
                    reward=0, nonce=0)
    r = val.validate_block(mine(b1), recon_prev(conn, ld.next_height()), st)
    assert not r and r.code == "tx_balance", r
    # owner sends with a corrupted signature
    bad = core.make_tx(sk, a2, 1_000_000, nonce=0)
    bad.signature = "00" * 64
    b2 = core.Block(height=ld.next_height(), prev_hash=ld.tip()[1],
                    timestamp=now, txs=[bad.to_dict()], miner=owner,
                    reward=0, nonce=0)
    r2 = val.validate_block(mine(b2), recon_prev(conn, ld.next_height()), st)
    assert not r2 and r2.code == "tx_signature", r2


def test_duplicate_txid_in_block_rejected():
    conn, ld, st, prev2, _b1, b2, _spend, _a2, _owner = _two_block_fund()
    b2.txs.append(dict(b2.txs[0]))
    b2.nonce = 0
    r = val.validate_block(mine(b2), prev2, st)
    assert not r and r.code == "tx_duplicate", r


def test_premine_outside_genesis_rejected():
    conn, ld = fresh_ledger()
    _sk, _vk, owner = new_account()
    g = seed_chain(ld, owner)
    slow_history(ld)
    st = state_from_chain(conn)
    now = int(time.time())
    td = core.Tx(kind="premine", sender=core.COINBASE_SENDER, recipient=owner,
                 amount=core.PREMINE, fee=0, nonce=0, timestamp=now,
                 vk="", signature="").to_dict()
    b1 = core.Block(height=ld.next_height(), prev_hash=ld.tip()[1],
                    timestamp=now, txs=[td], miner=owner, reward=0, nonce=0)
    r = val.validate_block(mine(b1), recon_prev(conn, ld.next_height()), st)
    assert not r and r.code == "premine_outside_genesis", r


# ---------------------------------------------------------------- timestamp --
def test_timestamp_rules():
    conn, ld = fresh_ledger()
    _sk, _vk, owner = new_account()
    g = seed_chain(ld, owner)
    slow_history(ld)
    st = state_from_chain(conn)
    prev = recon_prev(conn, ld.next_height())
    now = int(time.time())
    # regression vs tip (mined so the cheap checks are the ones firing)
    b1 = mine(reward_block(ld, owner, ts=prev.timestamp - 10))
    assert val.validate_block(b1, prev, st).code == "timestamp"
    b2 = mine(reward_block(ld, owner, ts=now + val.TIMESTAMP_FUTURE_S + 5))
    assert val.validate_block(b2, prev, st).code == "timestamp_future"
    # equal timestamp with tip is legal (on-demand mining shares a second)
    b3 = mine(reward_block(ld, owner, ts=prev.timestamp))
    assert val.validate_block(b3, prev, st)


# --------------------------------------------------------------- difficulty --
def test_difficulty_derived_not_trusted():
    conn, ld = fresh_ledger()
    _sk, _vk, owner = new_account()
    g = seed_chain(ld, owner)
    slow_history(ld)
    prev = recon_prev(conn, ld.next_height())
    st = state_from_chain(conn)
    blk = mine(reward_block(ld, owner))
    blk.difficulty = 99                                  # peer-supplied lie
    r = val.validate_block(blk, prev, st)
    assert not r and r.code == "difficulty", r


# ------------------------------------------------------------------ replay --
def test_replay_valid_chain_and_supply():
    conn, ld, _st, _prev2, _b1, b2, _spend, _a2, _owner = _two_block_fund()
    assert val.validate_block(mine(b2), recon_prev(conn, ld.next_height()),
                              state_from_chain(conn))
    ld.append_block(b2, 10)
    rep = val.replay_chain(conn, check_pow=False)   # history built without PoW
    assert rep["blocks_checked"] == ld.next_height()
    assert rep["emitted_uj"] == core.PREMINE + core.reward_for_height(101)
    assert rep["burned_uj"] == 100_000
    assert rep["supply_ok"]
    # circulating drops only by the burned fee; the spend moved to a2
    assert rep["circulating_uj"] == core.PREMINE + core.reward_for_height(101) \
        - 100_000


def test_replay_detects_tampered_balance():
    conn, ld = fresh_ledger()
    _sk, _vk, owner = new_account()
    g = seed_chain(ld, owner)
    with conn:
        conn.execute("UPDATE balances SET balance=balance+1000 WHERE address=?",
                     (owner,))
    with pytest.raises(val.ValidationError) as e:
        val.replay_chain(conn)
    assert e.value.code == "balance_mismatch"


def test_replay_detects_tampered_block():
    conn, ld, _st, _prev2, _b1, b2, _spend, _a2, _owner = _two_block_fund()
    assert val.validate_block(mine(b2), recon_prev(conn, ld.next_height()),
                              state_from_chain(conn))
    ld.append_block(b2, 10)
    with conn:
        conn.execute("UPDATE blocks SET difficulty=11 WHERE height=102")
    with pytest.raises(val.ValidationError) as e:
        val.replay_chain(conn, check_pow=False)
    assert e.value.code == "difficulty", e.value.reason


def test_replay_detects_tampered_hash():
    conn, ld, _st, _prev2, _b1, b2, _spend, _a2, _owner = _two_block_fund()
    assert val.validate_block(mine(b2), recon_prev(conn, ld.next_height()),
                              state_from_chain(conn))
    ld.append_block(b2, 10)
    with conn:
        conn.execute("UPDATE blocks SET hash='a'*64 WHERE height=102")
    with pytest.raises(val.ValidationError) as e:
        val.replay_chain(conn, check_pow=False)
    assert e.value.code == "hash_mismatch", e.value.reason
