"""Canonical block validator for JerithChain.

Single source of truth for consensus rules. Every component that touches
a block goes through validate_block: full node (before append), follower
(before persisting a received block), sync code, future p2p code,
exchange-facing node, tests, and replay/audit tools.

Consensus parameters live in jerith_core and are NOT redefined here.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

import jerith_core as core


class ValidationError(Exception):
    def __init__(self, code: str, reason: str):
        super().__init__(reason)
        self.code = code
        self.reason = reason


@dataclass
class ValidationResult:
    ok: bool
    code: str = ""
    reason: str = ""

    def __bool__(self) -> bool:
        return self.ok


def _vfail(code: str, reason: str) -> ValidationResult:
    return ValidationResult(False, code, reason)


def _ok() -> ValidationResult:
    return ValidationResult(True)


# Timestamp policy (documented in whitepaper §consensus):
#  - block.timestamp must be >= previous block timestamp (non-decreasing).
#    v1.0 mines transfer blocks on demand, so two blocks CAN share the same
#    wall-clock second; strict > would reject legitimate live-chain blocks.
#  - block.timestamp <= now + TIMESTAMP_FUTURE_S (anti-future-spam)
TIMESTAMP_FUTURE_S = 7200  # 2 hours


def compute_txid(tx_dict: dict) -> str:
    tx = core.Tx.from_dict(tx_dict)
    sig = bytes.fromhex(tx.signature or "00")
    import hashlib
    return hashlib.sha256(tx.payload() + sig).hexdigest()


def _vtxfail(tx_index: int, code: str, reason: str) -> ValidationResult:
    return _vfail(code, f"tx[{tx_index}]: {reason}")


def _validate_tx_in_block(td, index: int, state, height: int,
                          seen_txids: set) -> ValidationResult:
    if not isinstance(td, dict):
        return _vtxfail(index, "tx_malformed", "tx is not an object")
    required = {"kind", "sender", "recipient", "amount", "fee", "nonce",
                "timestamp", "vk", "signature"}
    missing = required - set(td)
    if missing:
        return _vtxfail(index, "tx_malformed", f"missing fields {sorted(missing)}")
    try:
        tx = core.Tx.from_dict(td)
    except Exception as e:  # noqa: BLE001
        return _vtxfail(index, "tx_malformed", f"cannot parse: {e}")

    if tx.kind == "mine":
        # chain-native reward; structural rules only
        if tx.sender != core.COINBASE_SENDER:
            return _vtxfail(index, "reward_sender", "mine tx must come from COINBASE")
        if tx.fee != 0 or tx.nonce != 0 or tx.amount <= 0:
            return _vtxfail(index, "reward_shape", "mine tx fee/nonce/amount invalid")
        if td.get("vk") or td.get("signature"):
            return _vtxfail(index, "reward_signed", "mine tx must be chain-native")
        expected_reward = core.reward_for_height(height)
        if tx.amount > expected_reward:
            return _vtxfail(index, "reward_too_large",
                            f"reward {tx.amount} exceeds schedule {expected_reward}")
        if height == 0:
            if tx.kind == "mine":
                return _vtxfail(index, "reward_genesis", "no mine reward in genesis")
    elif tx.kind == "premine":
        if height != 0:
            return _vtxfail(index, "premine_outside_genesis",
                            "premine tx only valid in genesis block")
        if tx.sender != core.COINBASE_SENDER or tx.amount != core.PREMINE:
            return _vtxfail(index, "premine_shape",
                            "premine must be COINBASE -> exact PREMINE amount")
        if td.get("vk") or td.get("signature"):
            return _vtxfail(index, "premine_signed",
                            "chain-native premine must not carry vk/signature")
    elif tx.kind == "spend":
        ok, why = _validate_spend(tx, td, index, state, seen_txids)
        if not ok:
            code, msg = why
            return _vfail(code, msg)
    else:
        return _vtxfail(index, "tx_kind", f"unknown kind {tx.kind}")
    return _ok()


def _validate_spend(tx, td, index: int, state, seen_txids: set):
    """Validate a signed spend. Returns (True, 'ok') or (False, (code, msg))."""
    if td.get("memo", "") and len(str(td["memo"])) > 200:
        return False, ("tx_memo", f"tx[{index}]: memo too long")
    if not td.get("vk") or not td.get("signature"):
        return False, ("tx_unsigned", f"tx[{index}]: spend missing vk/signature")
    try:
        vk = bytes.fromhex(td["vk"])
    except ValueError:
        return False, ("tx_bad_vk", f"tx[{index}]: bad vk hex")
    if len(vk) != 32:
        return False, ("tx_bad_vk", f"tx[{index}]: vk must be 32 bytes")
    if core.addr_from_vk(vk) != tx.sender:
        return False, ("tx_sender_mismatch", f"tx[{index}]: sender/vk mismatch")
    if tx.recipient == tx.sender:
        return False, ("tx_self_send", f"tx[{index}]: self-send")
    if tx.amount <= 0 or tx.fee < 0:
        return False, ("tx_amount", f"tx[{index}]: amount/fee invalid")
    try:
        sig = bytes.fromhex(td["signature"])
    except ValueError:
        return False, ("tx_bad_sig", f"tx[{index}]: bad signature hex")
    if not core.verify_sig(vk, tx.payload(), sig):
        return False, ("tx_signature", f"tx[{index}]: invalid signature")
    txid = compute_txid(td)
    if txid in seen_txids:
        return False, ("tx_duplicate", f"tx[{index}]: duplicate txid in block")
    seen_txids.add(txid)
    bal, nonce = state.balance_nonce(tx.sender)
    if tx.nonce != nonce:
        return False, ("tx_nonce",
                       f"tx[{index}]: nonce {tx.nonce} != expected {nonce}")
    need = tx.amount + tx.fee
    if bal < need:
        return False, ("tx_balance",
                       f"tx[{index}]: balance {bal} < amount+fee {need}")
    return True, "ok"


def _validate_pow(blk, prev_difficulty: int, claimed_hash: str = "") -> ValidationResult:
    actual_hash = blk.hash()
    claimed = claimed_hash or ""
    if claimed and claimed != actual_hash:
        return _vfail("hash_mismatch",
                      f"claimed hash {claimed[:16]}… != recomputed {actual_hash[:16]}…")
    h = bytes.fromhex(actual_hash)
    if not core.meets_difficulty(h, prev_difficulty):
        return _vfail("pow",
                      f"hash does not meet difficulty {prev_difficulty} bits")
    return _ok()


def validate_block(blk, prev_block, state, *, check_pow: bool = True,
                   claimed_hash: str = "", now: int | None = None) -> ValidationResult:
    """Canonical validation. `state` supplies balance/nonce queries plus the
    tip height/difficulty context (see ChainState). `prev_block` is None
    only when validating genesis. check_pow=False is reserved for the
    genesis block of a private testnet."""
    now = int(time.time()) if now is None else now

    # ---- structure ----
    for attr in ("height", "prev_hash", "timestamp", "txs", "miner", "reward", "nonce"):
        if not hasattr(blk, attr):
            return _vfail("malformed", f"missing field {attr}")
    if not isinstance(blk.txs, list):
        return _vfail("malformed", "txs must be a list")
    if not isinstance(blk.height, int) or not isinstance(blk.timestamp, int) \
            or not isinstance(blk.nonce, int) or not isinstance(blk.reward, int):
        return _vfail("malformed", "height/timestamp/nonce/reward must be ints")
    if not isinstance(blk.miner, str):
        return _vfail("malformed", "miner must be a string")

    if prev_block is None:
        return _validate_genesis(blk)

    # ---- linkage ----
    if blk.height != prev_block.height + 1:
        return _vfail("height",
                      f"height {blk.height} != prev height {prev_block.height} + 1")
    if blk.prev_hash != prev_block.hash():
        return _vfail("prev_hash",
                      f"prev_hash {blk.prev_hash[:16]}… != tip hash {prev_block.hash()[:16]}…")

    # ---- timestamp ----
    if blk.timestamp < prev_block.timestamp:
        return _vfail("timestamp", "timestamp must not regress")
    if blk.timestamp > now + TIMESTAMP_FUTURE_S:
        return _vfail("timestamp_future", "timestamp too far in the future")

    # ---- difficulty (computed independently, never trusted from peer) ----
    difficulty = state.expected_difficulty()
    if getattr(blk, "difficulty", None) is not None and \
            int(getattr(blk, "difficulty")) != difficulty:
        return _vfail("difficulty",
                      f"block difficulty {blk.difficulty} != expected {difficulty}")

    # ---- PoW over canonical serialization ----
    if check_pow:
        r = _validate_pow(blk, difficulty, claimed_hash)
        if not r:
            return r

    # ---- reward accounting ----
    mine_txs = [td for td in blk.txs
                if isinstance(td, dict) and td.get("kind") == "mine"]
    premine_txs = [td for td in blk.txs
                   if isinstance(td, dict) and td.get("kind") == "premine"]
    if premine_txs:
        return _vfail("premine_outside_genesis", "premine only valid in genesis")
    expected_reward = core.reward_for_height(blk.height)
    if len(mine_txs) > 1:
        return _vfail("reward_multiple", "at most one mine reward per block")
    if mine_txs:
        # v1.0 convention: block.reward mirrors the mine tx amount (the
        # "reward is the mine tx" rule, reflected into the header field).
        amount = int(mine_txs[0].get("amount", 0))
        if int(blk.reward) != amount:
            return _vfail("reward_field",
                          f"block.reward {blk.reward} != mine tx amount {amount}")
        if amount > expected_reward:
            return _vfail("reward_too_large",
                          f"reward {amount} exceeds schedule {expected_reward}")
        if amount > core.MAX_SUPPLY - state.total_emitted():
            return _vfail("supply_cap", "reward would exceed maximum supply")

    # ---- transactions (sequential state application) ----
    seen_txids: set = set()
    total_fees = 0
    for i, td in enumerate(blk.txs):
        r = _validate_tx_in_block(td, i, state, blk.height, seen_txids)
        if not r:
            return r
        if isinstance(td, dict) and td.get("kind") == "spend":
            total_fees += int(td.get("fee", 0))
    # fee burn accounting: burned fees reduce circulating supply; the
    # emitted-supply ledger is checked by replay (fees never re-enter as
    # rewards because mine amounts are capped by reward_for_height).

    # ---- canonical serialization: the hash must hash the block as given ----
    try:
        blk.hash()
    except Exception as e:  # noqa: BLE001
        return _vfail("serialization", f"cannot serialize block: {e}")

    return _ok()


def _validate_genesis(blk) -> ValidationResult:
    if blk.height != 0:
        return _vfail("genesis_height", "genesis must be height 0")
    if blk.prev_hash != "0" * 64:
        return _vfail("genesis_prev", "genesis prev_hash must be 0x64 zeros")
    if not blk.txs:
        return _vfail("genesis_empty", "genesis must contain the premine tx")
    premine = [td for td in blk.txs
               if isinstance(td, dict) and td.get("kind") == "premine"]
    if len(premine) != 1 or len(blk.txs) != 1:
        return _vfail("genesis_txs", "genesis must contain exactly the premine tx")
    td = premine[0]
    if int(td.get("amount", 0)) != core.PREMINE:
        return _vfail("genesis_premine", "premine amount must be exactly 200M JER")
    if td.get("vk") or td.get("signature"):
        return _vfail("genesis_premine_signed",
                      "chain-native premine must not carry vk/signature")
    if int(td.get("fee", 0)) != 0:
        return _vfail("genesis_fee", "genesis premine fee must be 0")
    return _ok()


# --------------------------------------------------------------- replay -----


@dataclass
class ReplayState:
    """Balance/nonce/supply accumulator used by replay and (in-memory) by
    the node's pre-append validation via a snapshot view."""

    _bal: dict = field(default_factory=dict)
    _nonce: dict = field(default_factory=dict)
    emitted: int = 0
    burned: int = 0
    last_rows: list = field(default_factory=list)

    def balance_nonce(self, address: str) -> tuple[int, int]:
        return (self._bal.get(address, 0), self._nonce.get(address, 0))

    def total_emitted(self) -> int:
        return self.emitted

    def apply(self, td: dict) -> None:
        kind = td["kind"]
        if kind == "spend":
            amt, fee = int(td["amount"]), int(td["fee"])
            self._bal[td["sender"]] = self._bal.get(td["sender"], 0) - amt - fee
            self._nonce[td["sender"]] = int(td["nonce"]) + 1
            self.burned += fee
            self._bal[td["recipient"]] = self._bal.get(td["recipient"], 0) + amt
        else:  # premine | mine
            amt = int(td["amount"])
            self.emitted += amt
            self._bal[td["recipient"]] = self._bal.get(td["recipient"], 0) + amt

    def snapshot_rows(self, height: int, timestamp: int, difficulty: int) -> None:
        self.last_rows.append((height, timestamp, difficulty))
        if len(self.last_rows) > core.RETARGET_INTERVAL + 1:
            self.last_rows.pop(0)

    def expected_difficulty(self) -> int:
        return core.expected_difficulty(self.last_rows)


def replay_chain(db_conn, *, max_blocks: int | None = None,
                 check_pow: bool = True) -> dict:
    """Rebuild and validate chain state from genesis against a Ledger DB.
    check_pow=False is for testnet/fabricated history without real PoW.
    Returns a report dict; raises ValidationError on the first bad block."""
    rows = db_conn.execute(
        "SELECT height, hash, prev_hash, timestamp, miner, reward, nonce, difficulty"
        " FROM blocks ORDER BY height").fetchall()
    if not rows:
        raise ValidationError("empty_chain", "no blocks in database")

    state = ReplayState()
    txs_checked = 0
    prev_blk = None
    prev_hash = ""
    max_h = rows[-1][0] if max_blocks is None else min(rows[-1][0], max_blocks)

    for (height, stored_hash, prev_hash_stored, ts, miner, reward, nonce,
         difficulty) in rows:
        if height > max_h:
            break
        # rebuild the block from DB + txs
        tx_rows = db_conn.execute(
            "SELECT kind, sender, recipient, amount, fee, nonce, timestamp,"
            " memo, vk, signature FROM txs WHERE height=? ORDER BY txid",
            (height,)).fetchall()
        txs = [dict(zip(("kind", "sender", "recipient", "amount", "fee", "nonce",
                         "timestamp", "memo", "vk", "signature"), t))
               for t in tx_rows]
        blk = core.Block(height=height, prev_hash=prev_hash_stored, timestamp=ts,
                         txs=txs, miner=miner, reward=reward, nonce=nonce)
        # stored hash must match canonical serialization
        if blk.hash() != stored_hash:
            raise ValidationError("hash_mismatch",
                                  f"height {height}: stored hash != canonical hash")
        r = validate_block(blk, prev_blk, state,
                           check_pow=(check_pow and height > 0),
                           claimed_hash=stored_hash)
        if not r:
            raise ValidationError(r.code, f"height {height}: {r.reason}")
        # difficulty column must equal the rule
        if height > 0 and int(difficulty) != state.expected_difficulty():
            raise ValidationError(
                "difficulty", f"height {height}: stored difficulty {difficulty}"
                f" != expected {state.expected_difficulty()}")
        for td in txs:
            state.apply(td)
        txs_checked += len(txs)
        state.snapshot_rows(height, ts, int(difficulty))
        prev_blk = blk
        prev_hash = stored_hash

    circulating = sum(v for v in state._bal.values() if v > 0) \
        - sum(-v for v in state._bal.values() if v < 0)

    # stored state must match replayed state (balance + nonce)
    stored_rows = db_conn.execute(
        "SELECT address, balance, nonce FROM balances").fetchall()
    stored_bal = {r[0]: int(r[1]) for r in stored_rows}
    stored_nonce = {r[0]: int(r[2]) for r in stored_rows}
    for addr, bal in stored_bal.items():
        if state._bal.get(addr, 0) != bal:
            raise ValidationError(
                "balance_mismatch",
                f"stored balance {bal} for {addr[:16]}… != replayed "
                f"{state._bal.get(addr, 0)}")
    for addr, nonce in stored_nonce.items():
        if state._nonce.get(addr, 0) != nonce:
            raise ValidationError(
                "nonce_mismatch",
                f"stored nonce {nonce} for {addr[:16]}… != replayed "
                f"{state._nonce.get(addr, 0)}")
    extra = set(state._bal) - set(stored_bal)
    if extra:
        raise ValidationError(
            "balance_mismatch",
            f"replayed state has balances missing from DB: "
            f"{sorted(a[:16] + '…' for a in extra)[:5]}")

    return {
        "height": prev_blk.height if prev_blk else -1,
        "tip": prev_hash,
        "blocks_checked": (prev_blk.height + 1) if prev_blk else 0,
        "txs_checked": txs_checked,
        "emitted_uj": state.emitted,
        "burned_uj": state.burned,
        "circulating_uj": circulating,
        "supply_ok": state.emitted <= core.MAX_SUPPLY,
    }
