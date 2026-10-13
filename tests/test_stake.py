"""Phase 5 stake escrow test suite. Run: python3 -m pytest tests/test_stake.py -v

Covers the jerith-mesh slashing contract end-to-end against a fresh
temporary node: escrow lock (on-chain transfer into the node-held escrow
wallet), the read view, unlock-over-escrow rejection, unlock, and the
Ed25519-signed /stake/slash evidence flow (bad signature rejected,
application moves escrow -> treasury, seen-once replays blocked).
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import jerith_core as core  # noqa: E402
from test_jerith import Node  # noqa: E402

import json as _json
import urllib.error as _uerr
import urllib.request as _ureq


def post_slash(node: Node, body: dict, headers: dict):
    """POST /stake/slash with mesh Ed25519 headers (the Node helper sends
    only the bearer token; slashing is NOT token-authed)."""
    req = _ureq.Request(
        f"http://127.0.0.1:{node.port}/stake/slash",
        data=_json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **headers},
        method="POST")
    try:
        with _ureq.urlopen(req, timeout=60) as r:
            return r.status, _json.loads(r.read() or b"{}")
    except _uerr.HTTPError as e:
        return e.code, _json.loads(e.read() or b"{}")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

OWNER = "285471197825859584"  # mirrors jerith_wallet OWNER_DISCORD_ID


def _mesh_headers(reporter: Ed25519PrivateKey, reporter_id: str, target: str,
                  amount_uj: int, stamp_ms: int) -> dict:
    """Build the exact stake.rs slashing payload + x-jerith-* headers."""
    payload = f"jerith-slash1|{reporter_id}|{target}|{amount_uj}|{stamp_ms}"
    pub = reporter.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "x-jerith-pubkey": pub.hex(),
        "x-jerith-stamp": str(stamp_ms),
        "x-jerith-sig": reporter.sign(payload.encode()).hex(),
    }


def _mesh_reporter(node) -> tuple[Ed25519PrivateKey, str]:
    """A valid mesh reporter identity: reporter node_id == pubkey[:16]."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub.hex()[:16]


@pytest.fixture(scope="module")
def stake_node():
    tmp = Path(f"/tmp/jerith-stake-test-{int(time.time())}")
    n = Node(8398, tmp / "data", tmp / "keys")
    yield n
    n.stop()


def test_stake_lock_escrows_on_chain(stake_node: Node) -> None:
    bal_before = stake_node.get(f"/balance?discord_id={OWNER}")
    assert bal_before["exists"] and bal_before["balance_uj"] == core.PREMINE

    st, body = stake_node._call(
        "POST", "/stake/lock", {"discord_id": OWNER, "amount_jer": 1.0})
    assert st == 200 and body["ok"], body
    assert body["staked_uj"] == 1_000_000
    assert body["block_height"] >= 1  # a real on-chain transfer back popped
    assert "escrow_address" in body

    bal_after = stake_node.get(f"/balance?discord_id={OWNER}")
    assert bal_after["balance_uj"] == bal_before["balance_uj"] - 1_000_000 - 100_000

    view = stake_node.get(f"/stake?discord_id={OWNER}")
    assert view["staked_uj"] == 1_000_000
    assert view["slashed_total_uj"] == 0
    assert view["events"] and view["events"][0]["kind"] == "lock"


def test_stake_unlock_over_escrow_rejected(stake_node: Node) -> None:
    st, body = stake_node._call(
        "POST", "/stake/unlock", {"discord_id": OWNER, "amount_jer": 200_000.0})
    assert st == 409 and "insufficient stake" in body["detail"]


def test_stake_unlock(stake_node: Node) -> None:
    st, body = stake_node._call(
        "POST", "/stake/unlock", {"discord_id": OWNER, "amount_jer": 0.5})
    assert st == 200 and body["ok"], body
    assert body["staked_uj"] == 500_000
    view = stake_node.get(f"/stake?discord_id={OWNER}")
    assert view["staked_uj"] == 500_000


def test_stake_lock_requires_known_identity(stake_node: Node) -> None:
    st, body = stake_node._call(
        "POST", "/stake/lock", {"discord_id": "nobody-here", "amount_jer": 1.0})
    assert st == 404


def test_stake_lock_rejects_bad_amount(stake_node: Node) -> None:
    st, _body = stake_node._call(
        "POST", "/stake/lock", {"discord_id": OWNER, "amount_jer": 0.0})
    assert st == 400


def test_slash_rejects_unsigned(stake_node: Node) -> None:
    st, _body = stake_node._call(
        "POST", "/stake/slash",
        {"reporter": "some-mesh-peer", "target": OWNER, "amount_uj": 100})
    assert st == 401


def test_slash_rejects_self_report(stake_node: Node) -> None:
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    reporter = pub_hex[:16]
    headers = _mesh_headers(priv, reporter, reporter, 100, int(time.time() * 1000))
    st, _body = post_slash(stake_node, {"reporter": reporter, "target": reporter,
                                        "amount_uj": 100}, headers)
    assert st == 401


def test_slash_rejects_tampered_payload(stake_node: Node) -> None:
    priv, reporter = _mesh_reporter(stake_node)
    headers = _mesh_headers(priv, reporter, OWNER, 100, int(time.time() * 1000))
    # Correct signature, wrong declared stamp -> rebuilt payload mismatch.
    headers["x-jerith-stamp"] = str(int(time.time() * 1000) - 7)
    st, _body = post_slash(stake_node, {"reporter": reporter, "target": OWNER,
                                        "amount_uj": 100}, headers)
    assert st == 401


def test_slash_applies_and_moves_escrow_to_treasury(stake_node: Node) -> None:
    priv, reporter = _mesh_reporter(stake_node)
    headers = _mesh_headers(priv, reporter, OWNER, 400_000, int(time.time() * 1000))
    st, body = post_slash(
        stake_node,
        {"reporter": reporter, "target": OWNER, "amount_uj": 400_000,
         "evidence_digest": "abc123"},
        headers)
    assert st == 200 and body["ok"], body
    assert body["slashed_uj"] == 400_000
    assert body["staked_uj"] == 100_000  # 500_000 escrowed - 400_000 slashed

    view = stake_node.get(f"/stake?discord_id={OWNER}")
    assert view["staked_uj"] == 100_000
    assert view["slashed_total_uj"] == 400_000
    kinds = [e["kind"] for e in view["events"]]
    assert "slash" in kinds


def test_slash_seen_once_replay_blocked(stake_node: Node) -> None:
    priv, reporter = _mesh_reporter(stake_node)
    headers = _mesh_headers(priv, reporter, OWNER, 100, int(time.time() * 1000))
    body = {"reporter": reporter, "target": OWNER, "amount_uj": 100}
    st, _ = post_slash(stake_node, body, headers)
    assert st == 200
    # Same signed payload within the stamp window -> deduped.
    st2, _ = post_slash(stake_node, body, headers)
    assert st2 == 409


def test_slash_capped_at_escrowed_stake(stake_node: Node) -> None:
    # Fresh escrow for a clean cap check (prior tests may have drained it).
    view = stake_node.get(f"/stake?discord_id={OWNER}")
    staked_before = view["staked_uj"]
    st, body = stake_node._call(
        "POST", "/stake/lock", {"discord_id": OWNER, "amount_jer": 2.0})
    assert st == 200, body
    priv, reporter = _mesh_reporter(stake_node)
    headers = _mesh_headers(priv, reporter, OWNER, 10_000_000, int(time.time() * 1000))
    st, body = post_slash(
        stake_node,
        {"reporter": reporter, "target": OWNER, "amount_uj": 10_000_000},
        headers)
    # A single report clamps at what is actually escrowed (residue from prior
    # tests + this lock) — never drives stake negative.
    assert st == 200 and body["slashed_uj"] == staked_before + 2_000_000
    assert body["staked_uj"] == 0
