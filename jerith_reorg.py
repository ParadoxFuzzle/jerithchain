"""Fork selection and reorganization for JerithChain (v1.1 §7).

Rule: the canonical chain is the valid chain with the greatest cumulative
chain work (sum of 2^difficulty per block). Peer identity, arrival time,
and insertion order are never used. On an exact work tie the current
chain is kept (deterministic; no flip-flopping).

accept_branch validates every candidate block through the canonical
validator (jerith_validate.validate_block) against replayed state BEFORE
any mutation; a branch that fails validation can never rewrite the
ledger. Evicted transactions (in the displaced tail but not the new
chain) are requeued to the mempool.
"""
from __future__ import annotations

import jerith_core as core
import jerith_validate as val
from jerith_validate import ValidationError, ReplayState, validate_block

TX_COLS = ("kind", "sender", "recipient", "amount", "fee", "nonce",
           "timestamp", "memo", "vk", "signature")


class _BranchState:
    """Validator state view over a ReplayState (used during branch checks)."""

    def __init__(self, rs: ReplayState):
        self._rs = rs

    def balance_nonce(self, address: str) -> tuple[int, int]:
        return self._rs.balance_nonce(address)

    def total_emitted(self) -> int:
        return self._rs.total_emitted()

    def expected_difficulty(self) -> int:
        return self._rs.expected_difficulty()


def _replay_to(conn, height: int) -> ReplayState:
    """Rebuild validator state from genesis through `height` (inclusive)."""
    rs = ReplayState()
    rows = conn.execute(
        "SELECT height, timestamp, difficulty FROM blocks"
        " WHERE height <= ? ORDER BY height", (height,))
    for (h, ts, diff) in rows:
        rs.snapshot_rows(h, ts, diff)
    for t in conn.execute(
            f"SELECT {','.join(TX_COLS)} FROM txs WHERE height <= ?"
            " ORDER BY height, rowid", (height,)):
        rs.apply(dict(zip(TX_COLS, t)))
    return rs


def validate_branch(conn, blocks: list, *, check_pow: bool = True) -> val.ValidationResult:
    """Fully validate a candidate branch against the stored chain.
    Returns the ValidationResult; on success the branch's cumulative work
    is attached as `result.branch_work`."""
    if not blocks:
        return val.ValidationResult(False, "empty_branch", "no candidate blocks")

    fork = blocks[0].height - 1
    tip_height = conn.execute("SELECT MAX(height) FROM blocks").fetchone()[0]
    tip_height = int(tip_height) if tip_height is not None else -1
    if fork < 0 or fork > tip_height:
        return val.ValidationResult(False, "fork_point",
                                    f"fork height {fork} not on local chain")
    stored = conn.execute("SELECT hash FROM blocks WHERE height=?",
                          (fork,)).fetchone()
    if not stored or stored[0] != blocks[0].prev_hash:
        return val.ValidationResult(False, "fork_point",
                                    "candidate does not extend the local chain")

    rs = _replay_to(conn, fork)
    prev = core.Ledger(conn).block_at(fork) if fork >= 0 else None
    work = 0
    for blk in blocks:
        r = validate_block(blk, prev, _BranchState(rs), check_pow=check_pow)
        if not r:
            return r
        diff = rs.expected_difficulty()
        work += core.block_work(diff)
        for td in blk.txs:
            rs.apply(td)
        rs.snapshot_rows(blk.height, blk.timestamp, diff)
        prev = blk
    result = val.ValidationResult(True)
    result.branch_work = work          # type: ignore[attr-defined]
    return result


def accept_branch(conn, blocks: list, *, check_pow: bool = True) -> dict:
    """Validate a branch; if its cumulative work strictly exceeds the work
    of the current tail above the fork point, perform the reorg. Returns:
      {"accepted": bool, "reason": str, "requeued": [tx dicts], "work": int}
    On rejection the database is untouched."""
    ledger = core.Ledger(conn)
    fork = blocks[0].height - 1 if blocks else -1
    tip_height = conn.execute("SELECT MAX(height) FROM blocks").fetchone()[0]
    tip_height = int(tip_height) if tip_height is not None else -1

    vr = validate_branch(conn, blocks, check_pow=check_pow)
    if not vr:
        return {"accepted": False, "reason": f"{vr.code}: {vr.reason}",
                "requeued": [], "work": 0}
    branch_work = getattr(vr, "branch_work", 0)
    tail_work = ledger.work_above(fork)

    if branch_work <= tail_work:
        return {"accepted": False,
                "reason": (f"insufficient_work: branch {branch_work} <= "
                           f"current tail {tail_work} (ties keep the current chain)"),
                "requeued": [], "work": branch_work}

    displaced = ledger.revert_to(fork)
    requeued: list[dict] = []
    new_txids = {val.compute_txid(td) for blk in blocks for td in blk.txs}
    for td in displaced:
        if val.compute_txid(td) in new_txids or td["kind"] != "spend":
            continue
        ok, why = ledger.mempool_add(core.Tx.from_dict(td))
        if ok:
            requeued.append(td)
    applied = []
    for blk in blocks:
        diff = ledger.next_difficulty()
        ledger.append_block(blk, diff)
        applied.append(blk.height)
    return {"accepted": True, "reason": "greater chain work",
            "requeued": requeued, "work": branch_work,
            "applied_heights": applied}
