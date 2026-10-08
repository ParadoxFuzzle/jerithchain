"""JerithChain core: accounts, transactions, Ed25519 signatures, PoW blocks.

Unit convention: all amounts are integer micro-JER (uJ). 1_000_000 uJ = 1 JER.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

import nacl.signing
import nacl.exceptions

MAX_U64 = 2**64 - 1


# --------------------------------------------------------------- accounts ---
def generate_keypair() -> tuple[bytes, bytes]:
    """Return (secret_seed_32B, verify_key_32B). The 32-byte seed is the
    canonical private key (standard Ed25519); hex = 64 chars."""
    sk = nacl.signing.SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


def secret_to_seed(sk: bytes) -> str:
    """Hex export string for the DM/export path."""
    return sk.hex()


def parse_seed(seed_hex: str) -> bytes:
    """Accept 32-byte seed hex (64 chars) or 64-byte seed‖vk hex (128 chars)."""
    raw = bytes.fromhex(seed_hex.strip())
    if len(raw) == 64:
        raw = raw[:32]
    if len(raw) != 32:
        raise ValueError("seed must be 32-byte hex (64 chars) or 64-byte hex (128 chars)")
    return raw


def addr_from_vk(vk: bytes) -> str:
    return "JER" + hashlib.sha256(b"jerith-addr" + vk).hexdigest()[:32].upper()


def addr_from_secret(sk: bytes) -> str:
    sk_obj = nacl.signing.SigningKey(sk)
    return addr_from_vk(bytes(sk_obj.verify_key))


def sign_tx_bytes(sk: bytes, tx_bytes: bytes) -> bytes:
    return nacl.signing.SigningKey(sk).sign(tx_bytes).signature


def verify_sig(vk: bytes, tx_bytes: bytes, sig: bytes) -> bool:
    try:
        nacl.signing.VerifyKey(vk).verify(tx_bytes, sig)
        return True
    except (nacl.exceptions.BadSignatureError, nacl.exceptions.ValueError):
        return False


# ------------------------------------------------------------ transactions ---
@dataclass
class Tx:
    kind: str              # "spend" | "premine" | "mine"
    sender: str            # address; "JER000...COINBASE" for rewards
    recipient: str
    amount: int            # uJ
    fee: int
    nonce: int
    timestamp: int
    memo: str = ""
    vk: str = ""           # hex of 32B verify key (sender)
    signature: str = ""    # hex

    def payload(self) -> bytes:
        body = {
            "kind": self.kind, "sender": self.sender,
            "recipient": self.recipient, "amount": self.amount,
            "fee": self.fee, "nonce": self.nonce,
            "timestamp": self.timestamp, "memo": self.memo,
            "vk": self.vk,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Tx":
        return cls(**{k: d[k] for k in cls.__dataclass_fields__ if k in d})


COINBASE_SENDER = "JER" + "0" * 32


def make_tx(sk: bytes, recipient: str, amount: int, nonce: int,
            kind: str = "spend", fee: int = 100_000, memo: str = "") -> Tx:
    sk_obj = nacl.signing.SigningKey(sk)
    vk = bytes(sk_obj.verify_key)
    tx = Tx(kind=kind, sender=addr_from_vk(vk), recipient=recipient,
            amount=amount, fee=fee, nonce=nonce,
            timestamp=int(time.time()), memo=memo,
            vk=vk.hex())
    tx.signature = sign_tx_bytes(sk, tx.payload()).hex()
    return tx


# ------------------------------------------------------------------ blocks ---
@dataclass
class Block:
    height: int
    prev_hash: str
    timestamp: int
    txs: list = field(default_factory=list)   # list of tx dicts
    miner: str = ""
    reward: int = 0
    nonce: int = 0

    def hash(self) -> str:
        body = json.dumps({
            "height": self.height, "prev_hash": self.prev_hash,
            "timestamp": self.timestamp, "txs": self.txs,
            "miner": self.miner, "reward": self.reward,
            "nonce": self.nonce,
        }, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(body).hexdigest()


GENESIS_DIFFICULTY = 18          # leading zero bits
TARGET_BLOCK_SECONDS = 60
RETARGET_INTERVAL = 20           # blocks
MIN_DIFFICULTY_BITS = 8
MAX_DIFFICULTY_BITS = 30
RETARGET_CLAMP = 4               # max 4x easier/harder per retarget window
MAX_BLOCK_REWARD = 50 * 1_000_000          # 50 JER in uJ
MAX_SUPPLY = 1_000_000_000 * 1_000_000     # 1B JER in uJ
PREMINE = 200_000_000 * 1_000_000          # 200M JER in uJ


def retarget(prev_window_difficulty: int, actual_dt: int,
             expected_dt: int) -> int:
    """New difficulty bits from measured window time. Easier (fast window)
    raises bits; harder lowers them. Clamped to 4x and to absolute bounds."""
    if actual_dt <= 0:
        ratio = float(RETARGET_CLAMP)
    else:
        ratio = expected_dt / actual_dt
    ratio = max(1.0 / RETARGET_CLAMP, min(float(RETARGET_CLAMP), ratio))
    # bits scale linearly with log2 of the work ratio: doubling work = +1 bit
    import math
    delta_bits = math.log2(ratio)
    new_bits = int(round(prev_window_difficulty + delta_bits))
    return max(MIN_DIFFICULTY_BITS, min(MAX_DIFFICULTY_BITS, new_bits))


def expected_difficulty(rows) -> int:
    """Single source of truth for retargeting. `rows` is the last
    RETARGET_INTERVAL+1 (height, timestamp, difficulty) tuples, oldest
    first; rows[-1] must be the chain tip. Returns the difficulty the
    NEXT block must satisfy. Used by Ledger.next_difficulty and the
    canonical validator so they can never diverge."""
    if not rows:
        return GENESIS_DIFFICULTY
    height = rows[-1][0]
    diff = int(rows[-1][2])
    nxt = int(height) + 1
    if nxt % RETARGET_INTERVAL != 0 or len(rows) < RETARGET_INTERVAL + 1:
        return diff
    window = rows[-(RETARGET_INTERVAL + 1):]
    actual_dt = int(window[-1][1]) - int(window[0][1])
    expected = TARGET_BLOCK_SECONDS * RETARGET_INTERVAL
    return retarget(diff, actual_dt, expected)


def reward_for_height(height: int) -> int:
    """Halving every 210k blocks, floor 1 uJ. Pure — no global mutation."""
    r = MAX_BLOCK_REWARD
    for _ in range(height // 210_000):
        r = max(1, r // 2)
    return r


def block_work(difficulty_bits: int) -> int:
    """Expected hashes for one block at this difficulty: 2^bits. Cumulative
    chain work is the sum over blocks — the fork-selection rule (v1.1 §7)."""
    return 1 << int(difficulty_bits)


def meets_difficulty(h: bytes, difficulty_bits: int) -> bool:
    """True if h has at least difficulty_bits leading zero bits."""
    full = difficulty_bits // 8
    if h[:full] != b"\x00" * full:
        return False
    rem = difficulty_bits % 8
    if rem == 0:
        return True
    return h[full] <= (0xFF >> rem)


def mine_block(block: Block, difficulty_bits: int = GENESIS_DIFFICULTY,
               max_rounds: int = 2**32) -> Block:
    nonce = 0
    while nonce < max_rounds:
        block.nonce = nonce
        if meets_difficulty(bytes.fromhex(block.hash()), difficulty_bits):
            return block
        nonce += 1
    raise RuntimeError("mining round exhausted")


def leading_zero_bits(h: bytes) -> int:
    bits = 0
    for b in h:
        if b == 0:
            bits += 8
        else:
            bits += 8 - b.bit_length()
            break
    return bits


# ------------------------------------------------------------------- chain ---
class Ledger:
    """SQLite-backed account ledger. Balances derived only from applied txs."""

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
    CREATE INDEX IF NOT EXISTS idx_txs_recipient ON txs(recipient);
    CREATE INDEX IF NOT EXISTS idx_txs_sender ON txs(sender);
    CREATE TABLE IF NOT EXISTS balances (
        address TEXT PRIMARY KEY,
        balance INTEGER NOT NULL,
        nonce INTEGER NOT NULL DEFAULT 0,
        locked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS mempool (
        txid TEXT PRIMARY KEY,
        payload TEXT NOT NULL,
        received INTEGER NOT NULL
    );
    """

    def __init__(self, conn):
        self.conn = conn
        self.conn.executescript(self.DDL)

    # -- balances ---------------------------------------------------------
    def balance(self, address: str) -> int:
        row = self.conn.execute(
            "SELECT balance FROM balances WHERE address=?", (address,)).fetchone()
        return int(row[0]) if row else 0

    def nonce(self, address: str) -> int:
        row = self.conn.execute(
            "SELECT nonce FROM balances WHERE address=?", (address,)).fetchone()
        return int(row[0]) if row else 0

    def circulating(self) -> int:
        row = self.conn.execute("SELECT COALESCE(SUM(balance),0) FROM balances").fetchone()
        return int(row[0])

    # -- tx validation ------------------------------------------------------
    def validate_tx(self, tx: Tx, in_mempool: bool = False) -> tuple[bool, str]:
        if tx.amount <= 0:
            return False, "amount must be positive"
        if tx.amount + tx.fee <= 0:
            return False, "overflow"
        if tx.kind not in ("spend", "premine", "mine"):
            return False, f"unknown kind {tx.kind}"
        if tx.kind != "spend":
            return False, f"kind {tx.kind} is only minted by the chain itself"
        if not tx.vk or not tx.signature:
            return False, "missing vk or signature"
        try:
            vk = bytes.fromhex(tx.vk)
        except ValueError:
            return False, "bad vk hex"
        if addr_from_vk(vk) != tx.sender:
            return False, "sender/vk mismatch"
        if not verify_sig(vk, tx.payload(), bytes.fromhex(tx.signature)):
            return False, "bad signature"
        if tx.recipient == tx.sender:
            return False, "self-send"
        bal = self.balance(tx.sender)
        if bal < tx.amount + tx.fee:
            return False, f"insufficient funds ({bal} < {tx.amount + tx.fee})"
        if tx.nonce != self.nonce(tx.sender):
            return False, f"bad nonce (have {self.nonce(tx.sender)}, want sequential)"
        return True, "ok"

    # -- apply (inside open transaction) ------------------------------------
    def apply_tx(self, cur, tx: Tx, height: Optional[int]) -> str:
        txid = hashlib.sha256(tx.payload() + bytes.fromhex(tx.signature or "00")).hexdigest()
        cur.execute(
            """INSERT INTO txs (txid, height, kind, sender, recipient, amount,
               fee, nonce, timestamp, memo, vk, signature, status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (txid, height, tx.kind, tx.sender, tx.recipient, tx.amount,
             tx.fee, tx.nonce, tx.timestamp, tx.memo, tx.vk, tx.signature,
             "applied"))
        if tx.kind == "spend":
            cur.execute(
                "UPDATE balances SET balance=balance-?, nonce=? WHERE address=?",
                (tx.amount + tx.fee, tx.nonce + 1, tx.sender))
            self._credit(cur, tx.recipient, tx.amount)
        elif tx.kind == "premine":
            self._credit(cur, tx.recipient, tx.amount)
        elif tx.kind == "mine":
            self._credit(cur, tx.recipient, tx.amount)
        return txid

    @staticmethod
    def _credit(cur, address: str, amount: int) -> None:
        cur.execute(
            "INSERT INTO balances (address, balance, nonce, locked) VALUES (?, ?, 0, 0) "
            "ON CONFLICT(address) DO UPDATE SET balance = balance + ?",
            (address, amount, amount))

    # -- genesis & blocks -----------------------------------------------------
    def build_genesis(self, premine_recipient: str, premine_sk: Optional[bytes] = None) -> Block:
        """Genesis block with premine tx. Signed by premine_sk if provided,
        otherwise the premine is a chain-native allocation (vk empty)."""
        if self.conn.execute("SELECT 1 FROM blocks LIMIT 1").fetchone():
            raise RuntimeError("chain already initialized")
        if premine_sk is not None:
            sk_obj = nacl.signing.SigningKey(premine_sk)
            vk = bytes(sk_obj.verify_key)
            tx = Tx(kind="premine", sender=COINBASE_SENDER,
                    recipient=premine_recipient, amount=PREMINE, fee=0,
                    nonce=0, timestamp=int(time.time()),
                    memo="genesis premine", vk=vk.hex())
            tx.signature = sign_tx_bytes(premine_sk, tx.payload()).hex()
        else:
            tx = Tx(kind="premine", sender=COINBASE_SENDER,
                    recipient=premine_recipient, amount=PREMINE, fee=0,
                    nonce=0, timestamp=int(time.time()),
                    memo="genesis premine (chain-native allocation)", vk="", signature="")
        block = Block(height=0, prev_hash="0" * 64,
                      timestamp=tx.timestamp, txs=[tx.to_dict()],
                      miner=premine_recipient, reward=0, nonce=0)
        return block

    def commit_genesis(self, block: Block) -> str:
        bhash = block.hash()
        with self.conn:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO blocks (height, hash, prev_hash, timestamp, miner, reward, nonce, difficulty)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (block.height, bhash, block.prev_hash, block.timestamp,
                 block.miner, block.reward, block.nonce, GENESIS_DIFFICULTY))
            for td in block.txs:
                self.apply_tx(cur, Tx.from_dict(td), block.height)
        return bhash

    def tip(self) -> Optional[tuple]:
        return self.conn.execute(
            "SELECT height, hash, timestamp, difficulty FROM blocks ORDER BY height DESC LIMIT 1").fetchone()

    def next_height(self) -> int:
        row = self.tip()
        return (row[0] + 1) if row else 0

    def current_difficulty(self) -> int:
        row = self.tip()
        return int(row[3]) if row else GENESIS_DIFFICULTY

    def next_difficulty(self) -> int:
        """Difficulty for the upcoming block. Delegates to
        core.expected_difficulty (the single source of truth shared with
        the canonical validator) over the last window+1 rows."""
        rows = self.conn.execute(
            "SELECT height, timestamp, difficulty FROM blocks"
            " ORDER BY height DESC LIMIT ?", (RETARGET_INTERVAL + 1,)).fetchall()
        return expected_difficulty(rows[::-1])

    def append_block(self, block: Block, difficulty: int) -> str:
        bhash = block.hash()
        with self.conn:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO blocks (height, hash, prev_hash, timestamp, miner, reward, nonce, difficulty)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (block.height, bhash, block.prev_hash, block.timestamp,
                 block.miner, block.reward, block.nonce, difficulty))
            for td in block.txs:
                self.apply_tx(cur, Tx.from_dict(td), block.height)
            cur.execute("DELETE FROM mempool WHERE txid IN (%s)"
                        % ",".join("?" * len(block.txs)) if block.txs else "SELECT 1",
                        [hashlib.sha256(
                            Tx.from_dict(td).payload() + bytes.fromhex(Tx.from_dict(td).signature or "00")
                        ).hexdigest() for td in block.txs])
        return bhash

    # -- mempool ---------------------------------------------------------------
    # Resource limits (v1.1 §8): prevent unbounded memory/DB growth from
    # tx flooding. Defaults are conservative for a small-network node.
    MEMPOOL_MAX_ENTRIES = 5_000
    MEMPOOL_MAX_TX_BYTES = 64 * 1024
    MEMPOOL_TTL_S = 3_600            # drop unconfirmed txs after 1 hour
    MEMPOOL_MAX_PER_SENDER = 10

    def mempool_add(self, tx: Tx) -> tuple[bool, str]:
        ok, why = self.validate_tx(tx)
        if not ok:
            return False, why
        try:
            sig = bytes.fromhex(tx.signature)
        except ValueError:
            return False, "bad signature hex"
        txid = hashlib.sha256(tx.payload() + sig).hexdigest()
        payload = json.dumps(tx.to_dict())
        if len(payload) > self.MEMPOOL_MAX_TX_BYTES:
            return False, "transaction too large"
        now = int(time.time())
        with self.conn:
            cur = self.conn.cursor()
            # per-sender cap: one outstanding spend per nonce is enough for
            # sequential nonces; 10 allows replacement headroom
            n = cur.execute(
                "SELECT COUNT(*) FROM mempool WHERE json_extract(payload, '$.sender')=?",
                (tx.sender,)).fetchone()[0]
            if n >= self.MEMPOOL_MAX_PER_SENDER:
                return False, "too many pending transactions for sender"
            cur.execute(
                "INSERT OR REPLACE INTO mempool (txid, payload, received) VALUES (?,?,?)",
                (txid, payload, now))
            # TTL expiry + global size cap (evict oldest)
            cur.execute("DELETE FROM mempool WHERE received < ?", (now - self.MEMPOOL_TTL_S,))
            cur.execute(
                "DELETE FROM mempool WHERE txid IN ("
                "  SELECT txid FROM mempool ORDER BY received DESC LIMIT -1 OFFSET ?)",
                (self.MEMPOOL_MAX_ENTRIES,))
        return True, txid

    def mempool_list(self, limit: int = 50) -> list[Tx]:
        rows = self.conn.execute(
            "SELECT payload FROM mempool ORDER BY received LIMIT ?", (limit,)).fetchall()
        return [Tx.from_dict(json.loads(r[0])) for r in rows]

    def history(self, address: str, limit: int = 20) -> list[dict]:
        rows = self.conn.execute(
            """SELECT txid, height, kind, sender, recipient, amount, timestamp, memo
               FROM txs WHERE sender=? OR recipient=?
               ORDER BY height DESC, timestamp DESC LIMIT ?""",
            (address, address, limit)).fetchall()
        cols = ["txid", "height", "kind", "sender", "recipient", "amount", "timestamp", "memo"]
        return [dict(zip(cols, r)) for r in rows]

    def chain_length(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) FROM blocks").fetchone()
        return int(row[0])

    # -- reorg support (v1.1 §7: greatest cumulative chain work) ----------
    def block_at(self, height: int) -> Optional[Block]:
        """Reconstruct a block from storage (hash-comparable). None if absent."""
        row = self.conn.execute(
            "SELECT height, hash, prev_hash, timestamp, miner, reward, nonce"
            " FROM blocks WHERE height=?", (height,)).fetchone()
        if not row:
            return None
        txs = [dict(zip(
            ("kind", "sender", "recipient", "amount", "fee", "nonce",
             "timestamp", "memo", "vk", "signature"), t))
            for t in self.conn.execute(
                "SELECT kind, sender, recipient, amount, fee, nonce, timestamp,"
                " memo, vk, signature FROM txs WHERE height=?", (height,))]
        # columns: height, hash, prev_hash, timestamp, miner, reward, nonce
        return Block(height=row[0], prev_hash=row[2], timestamp=row[3],
                     txs=txs, miner=row[4], reward=row[5], nonce=row[6])

    def work_above(self, height: int) -> int:
        """Cumulative chain work of all blocks above `height` (the current
        tail). 0 if the tip is at or below height."""
        row = self.conn.execute(
            "SELECT COALESCE(SUM(power),0) FROM ("
            "  SELECT difficulty, (1 << difficulty) AS power FROM blocks"
            "  WHERE height > ?)", (height,)).fetchone()
        return int(row[0])

    def revert_to(self, height: int) -> list[dict]:
        """Drop the chain above `height` and rebuild balances/nonces by
        replaying the surviving txs. Returns the evicted tx dicts (the
        caller may requeue them to the mempool). Does NOT silently repair:
        callers must validate replacement branches first."""
        evicted = [dict(zip(
            ("kind", "sender", "recipient", "amount", "fee", "nonce",
             "timestamp", "memo", "vk", "signature"), t))
            for t in self.conn.execute(
                "SELECT kind, sender, recipient, amount, fee, nonce, timestamp,"
                " memo, vk, signature FROM txs WHERE height > ?", (height,))]
        locked = {r[0]: int(r[1]) for r in self.conn.execute(
            "SELECT address, locked FROM balances WHERE locked != 0")}
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM blocks WHERE height > ?", (height,))
            cur.execute("DELETE FROM txs WHERE height > ?", (height,))
            cur.execute("DELETE FROM balances")
            for t in self.conn.execute(
                    "SELECT kind, sender, recipient, amount, fee, nonce"
                    " FROM txs ORDER BY height, rowid"):
                kind, sender, recipient, amount, fee, nonce = t
                if kind == "spend":
                    cur.execute(
                        "INSERT INTO balances (address, balance, nonce, locked)"
                        " VALUES (?, ?, ?, 0) ON CONFLICT(address) DO UPDATE SET"
                        " balance = balance - ?, nonce = ?",
                        (sender, -amount - fee, nonce + 1, amount + fee,
                         nonce + 1))
                    self._credit(cur, recipient, amount)
                else:
                    self._credit(cur, recipient, amount)
            for addr, lk in locked.items():
                cur.execute("UPDATE balances SET locked=? WHERE address=?",
                            (lk, addr))
        return evicted
