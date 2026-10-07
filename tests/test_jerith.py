"""Jerith Coin test suite. Run: python3 -m pytest tests/ -v"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import sqlite3

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import jerith_core as core                     # noqa: E402
import jerith_wallet as sec                    # noqa: E402


# ---------------------------------------------------------------- crypto ----
def test_keypair_and_address() -> None:
    sk, vk = core.generate_keypair()
    assert len(sk) == 32 and len(vk) == 32
    a = core.addr_from_vk(vk)
    assert a.startswith("JER") and len(a) == 35
    assert core.addr_from_secret(sk) == a
    # import formats: 64-char hex (seed) and 128-char hex (seed||vk)
    assert core.parse_seed(sk.hex()) == sk
    assert core.parse_seed((sk + vk).hex()) == sk


def test_sign_verify_roundtrip() -> None:
    sk, _ = core.generate_keypair()
    sk2, _ = core.generate_keypair()
    sk_obj = __import__("nacl").signing.SigningKey(sk)
    vk = bytes(sk_obj.verify_key)
    tx = core.make_tx(sk, core.addr_from_vk(bytes(__import__("nacl").signing.SigningKey(sk2).verify_key)),
                      1_000_000, nonce=0)
    payload = tx.payload()
    assert core.verify_sig(vk, payload, bytes.fromhex(tx.signature))
    assert not core.verify_sig(vk, payload + b"x", bytes.fromhex(tx.signature))
    assert not core.verify_sig(bytes(__import__("nacl").signing.SigningKey(sk2).verify_key),
                               payload, bytes.fromhex(tx.signature))


def test_premine_tx_signature() -> None:
    sk, vk = core.generate_keypair()
    addr = core.addr_from_vk(vk)
    tx = core.Tx(kind="premine", sender=core.COINBASE_SENDER, recipient=addr,
                 amount=core.PREMINE, fee=0, nonce=0, timestamp=1,
                 memo="genesis premine", vk=vk.hex())
    tx.signature = core.sign_tx_bytes(sk, tx.payload()).hex()
    assert core.verify_sig(vk, tx.payload(), bytes.fromhex(tx.signature))


# ------------------------------------------------------------------ pow -----
def test_meets_difficulty_and_mine() -> None:
    h = b"\x00\x00\x40" + b"\xff" * 29        # 16 zero bits + 1 more = 17
    assert core.meets_difficulty(h, 16)
    assert core.meets_difficulty(h, 17)
    assert not core.meets_difficulty(h, 18)
    assert core.leading_zero_bits(h) == 17
    blk = core.Block(height=1, prev_hash="0" * 64, timestamp=1, txs=[], miner="x")
    core.mine_block(blk, 12)
    assert core.leading_zero_bits(bytes.fromhex(blk.hash())) >= 12


def test_retarget_math_and_clamp() -> None:
    # fast window (8x faster than target) → clamped to 4x → +2 bits
    assert core.retarget(18, core.TARGET_BLOCK_SECONDS * 20 // 8,
                         core.TARGET_BLOCK_SECONDS * 20) == 20
    # slow window (4x slower) → -2 bits
    assert core.retarget(18, core.TARGET_BLOCK_SECONDS * 20 * 4,
                         core.TARGET_BLOCK_SECONDS * 20) == 16
    # insane speedup clamped to 4x → +2 bits max
    assert core.retarget(18, 1, core.TARGET_BLOCK_SECONDS * 20) == 20
    # degenerate actual_dt treated as max clamp
    assert core.retarget(18, 0, 100) == 20
    # bounds enforced
    assert core.retarget(29, 1, 100) == 30
    assert core.retarget(9, core.TARGET_BLOCK_SECONDS * 20 * 1000,
                         core.TARGET_BLOCK_SECONDS * 20) == 8


def test_ledger_next_difficulty_ends_window() -> None:
    conn = sqlite3.connect(":memory:")
    ld = core.Ledger(conn)
    sk, vk = core.generate_keypair()
    owner = core.addr_from_vk(vk)
    ld.commit_genesis(ld.build_genesis(owner, premine_sk=None))
    tip = ld.tip()
    # backdate blocks to build a fast window of 19 blocks ending at height 19
    fast_ts = tip[2]  # genesis ts
    rows = []
    for i in range(1, 20):
        blk = core.Block(height=i, prev_hash=ld.tip()[1], timestamp=fast_ts + i * 3,
                         txs=[], miner=owner, reward=0, nonce=0)
        core.mine_block(blk, 12)
        bhash = ld.append_block(blk, 12)
        rows.append((i, bhash))
    # next height is 20 → boundary: window 1..19 over 57s vs 1200s expected
    assert ld.next_difficulty() >= 12
    assert ld.current_difficulty() == 12
    conn.close()


def test_reward_halving_pure() -> None:
    r0 = core.reward_for_height(0)
    r1 = core.reward_for_height(1)
    r210k = core.reward_for_height(210_000)
    assert r0 == r1 == 50 * 1_000_000
    assert r210k == 25 * 1_000_000
    # purity: calling again returns same value
    assert core.reward_for_height(210_000) == 25 * 1_000_000


# ---------------------------------------------------------------- ledger ----
@pytest.fixture()
def ledger():
    conn = __import__("sqlite3").connect(":memory:")
    conn.execute("PRAGMA journal_mode=WAL")
    ld = core.Ledger(conn)
    sk, vk = core.generate_keypair()
    owner = core.addr_from_vk(vk)
    blk = ld.build_genesis(owner, premine_sk=None)
    ld.commit_genesis(blk)
    yield ld, sk, owner
    conn.close()


def test_genesis_premine_balance(ledger) -> None:
    ld, sk, owner = ledger
    assert ld.balance(owner) == core.PREMINE
    assert ld.chain_length() == 1


def test_spend_and_double_spend(ledger) -> None:
    ld, sk, owner = ledger
    sk2, vk2 = core.generate_keypair()
    to = core.addr_from_vk(vk2)
    amt, fee = 5_000_000, 100_000
    tx = core.make_tx(sk, to, amt, nonce=0, fee=fee)
    ok, why = ld.validate_tx(tx)
    assert ok, why
    blk = core.Block(height=1, prev_hash=ld.tip()[1], timestamp=int(time.time()),
                     txs=[tx.to_dict()], miner=owner, reward=0, nonce=0)
    core.mine_block(blk, 12)
    ld.append_block(blk, 12)
    assert ld.balance(to) == amt
    assert ld.balance(owner) == core.PREMINE - amt - fee
    # double spend: same nonce again must fail
    ok, why = ld.validate_tx(core.make_tx(sk, to, amt, nonce=0, fee=fee))
    assert not ok and "nonce" in why
    # overspend
    ok, _ = ld.validate_tx(core.make_tx(sk, to, core.PREMINE, nonce=1, fee=fee))
    assert not ok and "insufficient" in _


def test_forged_sender_rejected(ledger) -> None:
    ld, sk, owner = ledger
    sk2, vk2 = core.generate_keypair()
    tx = core.make_tx(sk, core.addr_from_vk(vk2), 1_000_000, nonce=0)
    tx.sender = core.addr_from_vk(vk2)          # lie about sender
    ok, why = ld.validate_tx(tx)
    assert not ok and "mismatch" in why


def test_bad_kind_rejected(ledger) -> None:
    ld, sk, owner = ledger
    sk2, vk2 = core.generate_keypair()
    tx = core.make_tx(sk, core.addr_from_vk(vk2), 1_000_000, nonce=0, kind="mine")
    ok, why = ld.validate_tx(tx)
    assert not ok and "only minted" in why


# ---------------------------------------------------------------- wallet ----
def test_password_wrap_roundtrip() -> None:
    sk, _ = core.generate_keypair()
    w = sec.wrap_with_password(sk, "correct horse battery")
    assert sec.unwrap_with_password(w, "correct horse battery") == sk
    with pytest.raises(Exception):
        sec.unwrap_with_password(w, "wrong password")


def test_password_hash_verify() -> None:
    h = sec.hash_password("s3cret-password")
    assert sec.verify_password("s3cret-password", h)
    assert not sec.verify_password("other", h)


def test_totp_roundtrip_and_window() -> None:
    s = sec.totp_generate_secret()
    assert len(s) == 32
    code = sec.totp_code(s)
    assert sec.totp_verify(s, code)
    assert not sec.totp_verify(s, "000000") or code == "000000"
    assert not sec.totp_verify(s, "abcdef")
    prev = sec.totp_code(s, int(time.time()) - 30)
    assert sec.totp_verify(s, prev)             # window=1 accepts prev step
    far = sec.totp_code(s, int(time.time()) - 300)
    assert not sec.totp_verify(s, far)


def test_master_key_and_api_token(tmp_path) -> None:
    k1 = sec.load_or_create_master_key(str(tmp_path))
    k2 = sec.load_or_create_master_key(str(tmp_path))
    assert k1 == k2 and len(k1) == 32
    t1 = sec.load_or_create_api_token(str(tmp_path))
    t2 = sec.load_or_create_api_token(str(tmp_path))
    assert t1 == t2


def test_auto_sign_policy() -> None:
    u = sec.WalletUser(
        discord_id="1", address="JERX", vk_hex="", enc_sk=b"",
        wrapped_sk=None, password_stored=None, totp_enc=None,
        totp_confirmed=True, auto_sign_limit=100 * 1_000_000,
        daily_spent=0, daily_date="", opted_in=True, created_at=0,
        last_export=0, last_rebind=0)
    ok, _ = sec.auto_sign_allowed(u, 50 * 1_000_000)
    assert ok
    ok, why = sec.auto_sign_allowed(u, 150 * 1_000_000)
    assert not ok and "exceeds" in why
    u.daily_spent = 1_950 * 1_000_000
    u.daily_date = time.strftime("%Y-%m-%d", time.gmtime())
    ok, why = sec.auto_sign_allowed(u, 100 * 1_000_000)
    assert not ok and "budget" in why


# ------------------------------------------------------------ node E2E ------
class Node:
    def __init__(self, port: int, data_dir: Path, keys_dir: Path):
        env = dict(os.environ, JERITH_PORT=str(port),
                   JERITH_DATA_DIR=str(data_dir), JERITH_KEYS_DIR=str(keys_dir))
        self.proc = subprocess.Popen(
            [sys.executable, str(BASE / "jerith_node.py")], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.port = port
        for _ in range(120):
            try:
                self.token = (keys_dir / "api.token").read_text().strip()
                self.get("/status")
                break
            except Exception:
                time.sleep(0.5)
        else:
            raise RuntimeError("node did not come up")

    def _call(self, method: str, path: str, body=None, auth=True):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json",
                     **({"Authorization": f"Bearer {self.token}"} if auth else {})},
            method=method)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def get(self, path):
        return self._call("GET", path)[1]

    def post(self, path, body):
        return self._call("POST", path, body)[1]

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


@pytest.fixture(scope="module")
def node():
    tmp = Path(tempfile.mkdtemp(prefix="jerith-test-"))
    n = Node(8377, tmp / "data", tmp / "keys")
    yield n
    n.stop()


def test_auth_required(node) -> None:
    st, body = node._call("GET", "/status", auth=False)
    assert st == 401


def test_genesis_and_owner(node) -> None:
    st = node.get("/status")
    assert st["chain"]["height"] >= 0
    assert st["chain"]["premine_jer"] == 200_000_000
    owner_bal = node.get("/balance?discord_id=285471197825859584")
    assert owner_bal["exists"] and owner_bal["balance_uj"] == core.PREMINE


def test_wallet_create_optin_mine(node) -> None:
    did = "111111111111111111"
    w = node.post("/wallet/create", {"discord_id": did})
    assert w["ok"] and w["address"].startswith("JER")
    # balance shows not exists -> exists
    b = node.get(f"/balance?discord_id={did}")
    assert b["exists"] and b["balance_uj"] == 0
    # opt out -> redirect flag on mine
    node.post("/wallet/optin", {"discord_id": did, "opt_in": False})
    m1 = node.post("/mine", {"discord_id": did, "source": "explicit"})
    assert m1["ok"] and m1["redirected_to_owner"] is True
    # user got nothing, owner got the reward
    assert node.get(f"/balance?discord_id={did}")["balance_uj"] == 0
    # cooldown: immediate second attempt fails
    m2 = node.post("/mine", {"discord_id": did, "source": "explicit"})
    assert not m2["ok"] and m2["reason"] == "cooldown"
    # opt back in
    o = node.post("/wallet/optin", {"discord_id": did, "opt_in": True})
    assert o["opted_in"] is True
    # fail cooldown is 180s; success cooldown is 300s — can't mine again yet
    m3 = node.post("/mine", {"discord_id": did, "source": "explicit"})
    assert not m3["ok"] and "succeeded" in m3["message"]


def test_full_transfer_and_history(node) -> None:
    owner = "285471197825859584"
    did = "222222222222222222"
    node.post("/wallet/create", {"discord_id": did})
    # within auto-sign limit → signs automatically
    t = node.post("/transfer", {"discord_id": owner, "to": did,
                                "amount_jer": 50.0, "description": "test pay"})
    assert t["ok"] and t["signed_via"] == "auto", t
    assert node.get(f"/balance?discord_id={did}")["balance_jer"] == 50.0
    h = node.get(f"/history?discord_id={did}&limit=5")
    assert h["transactions"] and h["transactions"][0]["kind"] == "spend"
    # over auto-sign limit without password+2fa → refused (403)
    t2 = node.post("/transfer", {"discord_id": owner, "to": did,
                                 "amount_jer": 5000.0})
    assert "password" in json.dumps(t2).lower()


def test_passive_dedupe(node) -> None:
    did = "555555555555555555"
    m = {"discord_id": did, "source": "passive", "message_id": "msg-dedupe-1"}
    r1 = node.post("/mine", m)
    r2 = node.post("/mine", m)          # same message id → duplicate
    assert r2.get("reason") in ("duplicate", "cooldown")
    if r2.get("reason") == "duplicate":
        assert not r2.get("ok")
    # message_id without dedupe eligibility (non-numeric) processes every time
    m2 = {"discord_id": did, "source": "passive", "message_id": ""}
    r3 = node.post("/mine", m2)
    assert r3.get("reason") in ("cooldown",) or r3.get("ok") is True or r3.get("reason") == "duplicate"


def test_construct_and_sign(node) -> None:
    owner = "285471197825859584"
    did = "222222222222222222"
    c = node.post("/tx/construct", {"discord_id": owner, "to": did,
                                    "amount_jer": 10.0, "description": "construct test"})
    assert c["unsigned_tx"]["amount"] == 10_000_000
    assert c["unsigned_tx"]["recipient"].startswith("JER")
    assert c["auto_signable"] is True
    s = node.post("/tx/sign", {"discord_id": owner, "unsigned_tx": c["unsigned_tx"]})
    assert s["ok"] and s["signed_via"] == "auto"
    assert node.get(f"/balance?discord_id={did}")["balance_jer"] == 60.0


def test_password_totp_export_rebind_flow(node) -> None:
    did = "333333333333333333"
    node.post("/wallet/create", {"discord_id": did})
    b0 = node.get(f"/balance?discord_id={did}")
    addr = b0["address"]
    # export before password → refused
    e0 = node.post("/wallet/export", {"discord_id": did, "password": "x", "totp": "000000"})
    assert "password" in json.dumps(e0).lower()
    # set password
    pw = "super-secret-pw-123"
    sp = node.post("/wallet/password", {"discord_id": did, "new_password": pw})
    assert sp["ok"]
    # get TOTP secret via re-create (returns setup when unconfirmed)
    w = node.post("/wallet/create", {"discord_id": did})
    secret = w["totp_setup"]["secret_b32"]
    code = sec.totp_code(secret)
    cf = node.post("/wallet/totp/confirm", {"discord_id": did, "code": code})
    assert cf["ok"]
    # wrong 2FA export refused
    e1 = node.post("/wallet/export", {"discord_id": did, "password": pw, "totp": "000000"})
    assert "2fa" in json.dumps(e1).lower()
    # correct export works, returns 64-byte hex key
    e2 = node.post("/wallet/export", {"discord_id": did, "password": pw,
                                      "totp": sec.totp_code(secret)})
    assert e2["ok"] and len(bytes.fromhex(e2["secret_key_hex"])) == 32
    assert core.addr_from_secret(bytes.fromhex(e2["secret_key_hex"])) == addr
    # rebind to new discord id (password + totp)
    new_did = "444444444444444444"
    rb = node.post("/wallet/rebind", {"discord_id": did, "new_discord_id": new_did,
                                      "password": pw, "totp": sec.totp_code(secret)})
    assert rb["ok"]
    b1 = node.get(f"/balance?discord_id={new_did}")
    assert b1["exists"] and b1["address"] == addr
    # old id no longer resolves
    b2 = node.get(f"/balance?discord_id={did}")
    assert not b2["exists"]
