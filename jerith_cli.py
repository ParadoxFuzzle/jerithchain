#!/usr/bin/env python3
"""Jerith Coin agent CLI — how the OpenClaw agent (Jerith) talks to the node.

All commands take --discord-id (the Discord user the action is for).
Output is human-readable text suitable for pasting into Discord, or JSON
with --json. Requires JERITH_TOKEN (or reads keys/api.token directly).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent
NODE = os.environ.get("JERITH_NODE", "http://127.0.0.1:8300")


def _load_token() -> str:
    """Lazy so offline commands (verify-chain) work on a fresh machine."""
    env = os.environ.get("JERITH_TOKEN")
    if env:
        return env
    p = BASE / "keys" / "api.token"
    return p.read_text().strip() if p.exists() else ""


TOKEN = _load_token()


def call(method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(
        NODE + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {TOKEN}",
                 "Content-Type": "application/json"},
        method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read()).get("detail", "")
        except Exception:
            detail = ""
        return {"error": f"HTTP {e.code}", "detail": detail}


def _verify_chain(data_dir: Path, as_json: bool) -> int:
    """Rebuild and validate chain state from genesis, offline. Reports the
    first invalid block. Exit 0 = VALID, 1 = INVALID, 2 = no chain found."""
    import sqlite3

    import jerith_validate

    db_path = data_dir / "jerith.db"
    if not db_path.exists():
        print(f"RESULT: INVALID\nReason: no chain database at {db_path}")
        return 2
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    print("Chain verification started")
    try:
        rep = jerith_validate.replay_chain(conn)
    except jerith_validate.ValidationError as e:
        print(f"Genesis: OK" if e.code != "empty_chain" else "Genesis: MISSING")
        print(f"RESULT: INVALID\nReason: {e.reason}")
        return 1
    finally:
        conn.close()
    print(f"Genesis: OK")
    print(f"Blocks checked: {rep['blocks_checked']}")
    print(f"Transactions checked: {rep['txs_checked']}")
    print(f"Supply emitted: {rep['emitted_uj']/1e6:,.1f} JER")
    print(f"Burned (fees): {rep['burned_uj']/1e6:,.1f} JER")
    print(f"Circulating (balances): {rep['circulating_uj']/1e6:,.1f} JER")
    print(f"Tip: {rep['tip']}")
    print("RESULT: VALID" if rep["supply_ok"] else "RESULT: INVALID\nReason: supply exceeds maximum")
    return 0 if rep["supply_ok"] else 1


def fmt_bal(d: dict) -> str:
    if d.get("error"):
        return f"⚠️ {d['error']}: {d.get('detail', '')}"
    if not d.get("exists"):
        return d.get("message", "No wallet yet — ask me to create one!")
    lines = [f"💰 **{d['balance_jer']:,.2f} JER** (available: {d['available_jer']:,.2f})",
             f"Address: `{d['address']}`",
             f"Mining: {'✅ opted in' if d['opted_in'] else '⛔ opted out (rewards go to the pool owner)'}",
             f"Security: password {'✅' if d['has_password'] else '❌ not set'} · "
             f"2FA {'✅' if d['totp_confirmed'] else '❌ not enrolled'} · "
             f"auto-sign limit {d['auto_sign_limit_jer']:g} JER"]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(prog="jerith")
    ap.add_argument("--json", action="store_true", help="raw JSON output")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("balance")
    p.add_argument("--discord-id", required=True)

    p = sub.add_parser("mine")
    p.add_argument("--discord-id", required=True)
    p.add_argument("--source", default="explicit", choices=["explicit", "passive"])
    p.add_argument("--guild-id", default="")
    p.add_argument("--channel-id", default="")

    p = sub.add_parser("history")
    p.add_argument("--discord-id", required=True)
    p.add_argument("--limit", type=int, default=10)

    p = sub.add_parser("create-wallet")
    p.add_argument("--discord-id", required=True)
    p.add_argument("--password", default="")

    p = sub.add_parser("set-password")
    p.add_argument("--discord-id", required=True)
    p.add_argument("--current-password", default="")
    p.add_argument("--new-password", required=True)
    p.add_argument("--totp", default="")

    p = sub.add_parser("confirm-2fa")
    p.add_argument("--discord-id", required=True)
    p.add_argument("--code", required=True)

    p = sub.add_parser("totp-setup")
    p.add_argument("--discord-id", required=True)

    p = sub.add_parser("export-key")
    p.add_argument("--discord-id", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--totp", required=True)

    p = sub.add_parser("rebind")
    p.add_argument("--discord-id", required=True)
    p.add_argument("--new-discord-id", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--totp", required=True)

    p = sub.add_parser("optin")
    p.add_argument("--discord-id", required=True)
    p.add_argument("--opt-in", required=True, choices=["true", "false"])

    p = sub.add_parser("construct")
    p.add_argument("--discord-id", required=True)
    p.add_argument("--to", required=True)
    p.add_argument("--amount", type=float, required=True)
    p.add_argument("--description", default="")

    p = sub.add_parser("transfer")
    p.add_argument("--discord-id", required=True)
    p.add_argument("--to", required=True)
    p.add_argument("--amount", type=float, required=True)
    p.add_argument("--description", default="")
    p.add_argument("--password", default="")
    p.add_argument("--totp", default="")

    p = sub.add_parser("sign")
    p.add_argument("--discord-id", required=True)
    p.add_argument("unsigned_tx_json")

    p = sub.add_parser("status")

    p = sub.add_parser("tx")
    p.add_argument("txid")

    p = sub.add_parser("block")
    p.add_argument("height", type=int)

    p = sub.add_parser("verify-chain",
                       help="OFFLINE: replay and validate the whole chain "
                            "from genesis (no node required)")
    p.add_argument("--data-dir", default=os.environ.get(
        "JERITH_DATA_DIR", str(BASE / "data")))

    args = ap.parse_args()
    d = args.__dict__

    if args.cmd == "verify-chain":
        return _verify_chain(Path(d["data_dir"]), as_json=args.json)

    if args.cmd == "balance":
        out = call("GET", f"/balance?discord_id={d['discord_id']}")
        text = fmt_bal(out)
    elif args.cmd == "mine":
        out = call("POST", "/mine", {"discord_id": d["discord_id"], "source": d["source"],
                                     "guild_id": d["guild_id"], "channel_id": d["channel_id"]})
        text = ("⛏️ " + out["message"]) if out.get("message") else json.dumps(out)
        if out.get("ok") and out.get("redirected_to_owner"):
            text += "\n_Tip: opt back in any time to earn for yourself again._"
    elif args.cmd == "history":
        out = call("GET", f"/history?discord_id={d['discord_id']}&limit={d['limit']}")
        if out.get("error"):
            text = f"⚠️ {out['error']}: {out.get('detail', '')}"
        else:
            txs = out.get("transactions", [])
            text = f"📜 Last {len(txs)} transactions for `{out.get('address', '')}`:" if txs else "No transactions yet."
            for t in txs:
                direction = "→" if t["sender"] == out.get("address") else "←"
                text += (f"\n• #{t.get('height')} {direction} {t['amount']/1e6:,.2f} JER "
                         f"({t['kind']}) {t.get('memo', '')}").rstrip()
    elif args.cmd == "create-wallet":
        out = call("POST", "/wallet/create", d)
        if out.get("error"):
            text = f"⚠️ {out['error']}: {out.get('detail', '')}"
        else:
            text = f"✅ Wallet created: `{out['address']}`"
            if not out.get("password_set"):
                text += "\nNext: set a password (`set-password`) and enroll 2FA for key export & rebind."
            ts = out.get("totp_setup")
            if ts:
                text += f"\n2FA secret (one-time): `{ts['secret_b32']}`\nURI: {ts['otpauth_uri']}"
    elif args.cmd == "totp-setup":
        out = call("POST", "/wallet/create", {"discord_id": d["discord_id"]})
        ts = out.get("totp_setup")
        text = (f"2FA secret: `{ts['secret_b32']}`\nURI: {ts['otpauth_uri']}"
                if ts else "2FA already enrolled or wallet missing.")
    elif args.cmd == "set-password":
        out = call("POST", "/wallet/password", d)
        text = out.get("message") or f"⚠️ {out.get('error')}: {out.get('detail', '')}"
    elif args.cmd == "confirm-2fa":
        out = call("POST", "/wallet/totp/confirm", d)
        text = out.get("message") or f"⚠️ {out.get('error')}: {out.get('detail', '')}"
    elif args.cmd == "export-key":
        out = call("POST", "/wallet/export", d)
        if out.get("ok"):
            text = (f"🔐 **PRIVATE KEY for `{out['address']}`** (DM only — delete after saving):\n"
                    f"`{out['secret_key_hex']}`\n"
                    f"{out['warning']}")
        else:
            text = f"⚠️ {out.get('error')}: {out.get('detail', '')}"
    elif args.cmd == "rebind":
        out = call("POST", "/wallet/rebind", d)
        text = out.get("message") or f"⚠️ {out.get('error')}: {out.get('detail', '')}"
    elif args.cmd == "optin":
        out = call("POST", "/wallet/optin", {"discord_id": d["discord_id"],
                                             "opt_in": d["opt_in"] == "true"})
        text = out.get("message") or f"⚠️ {out.get('error')}: {out.get('detail', '')}"
    elif args.cmd == "construct":
        out = call("POST", "/tx/construct", d)
        if out.get("error"):
            text = f"⚠️ {out['error']}: {out.get('detail', '')}"
        else:
            text = (f"🧾 {out['description']}\n"
                    f"Auto-sign: {'✅ yes' if out['auto_signable'] else '❌ needs password + 2FA'}"
                    f"\nNonce/fee/timestamp are filled at signing time.")
    elif args.cmd == "sign":
        out = call("POST", "/tx/sign", {"discord_id": d["discord_id"],
                                        "unsigned_tx": json.loads(d["unsigned_tx_json"]),
                                        "password": d.get("password", ""),
                                        "totp": d.get("totp", "")})
        text = (f"✅ Signed & on-chain: {out['amount_jer']:g} JER → `{out['to']}` "
                f"(tx {out['txid'][:16]}…, block {out['block_height']}, via {out['signed_via']})"
                if out.get("ok") else f"⚠️ {out.get('error')}: {out.get('detail', '')}")
    elif args.cmd == "transfer":
        out = call("POST", "/transfer", d)
        text = (f"✅ Sent {out['amount_jer']:g} JER → `{out['to']}` "
                f"(fee {out['fee_jer']:g}, tx `{out['txid'][:16]}…`, block {out['block_height']}, "
                f"via {out['signed_via']})"
                if out.get("ok") else f"⚠️ {out.get('error')}: {out.get('detail', '')}")
    elif args.cmd == "status":
        out = call("GET", "/status")
        c = out.get("chain", {})
        m = out.get("mining", {})
        text = (f"⛓️ JerithChain — height {c.get('height')}, diff {c.get('difficulty_bits')} bits, "
                f"reward {c.get('block_reward_jer'):g} JER, "
                f"circulating {c.get('circulating_jer'):,.0f} / {c.get('max_supply_jer'):,} JER\n"
                f"⛏️ {m.get('successful_mines', 0)} successful / {m.get('failed_mines', 0)} failed mines "
                f"across {m.get('miners', 0)} miners · wallet cap {out.get('wallets', {}).get('count', 0)}")
    elif args.cmd == "tx":
        out = call("GET", f"/tx/{d['txid']}")
        text = json.dumps(out, indent=2) if not out.get("error") else f"⚠️ {out['error']}: {out.get('detail', '')}"
    elif args.cmd == "block":
        out = call("GET", f"/block/{d['height']}")
        text = json.dumps(out, indent=2) if not out.get("error") else f"⚠️ {out['error']}: {out.get('detail', '')}"
    else:
        ap.error("unknown command")

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
