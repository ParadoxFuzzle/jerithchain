# JerithChain — Jerith Coin (JER)

The cryptocurrency of the [Jerith AI](https://jerithai.com) Discord agent.
Users mine **JER** by chatting with Jerith — every message to the bot has a
chance to mine. This repository is the **full node software**: run your own
node, mirror the chain, or host an explorer.

- **Live explorer:** https://paradoxfuzzle.github.io/jerithchain/ (auto-updating snapshot)
- **Coin:** Jerith Coin (JER) · max supply 1,000,000,000 · premine 200,000,000 to the founder
- **Consensus:** SHA-256 proof-of-work (18 bits, retargets every 20 blocks toward 60s blocks)
- **Transactions:** Ed25519-signed, every balance change is on-chain
- **Fees:** 0.1 JER per transfer (burned)

## Quickstart (run a node)

Requirements: Python 3.10+, ~100 MB disk. Linux/macOS (Windows via WSL).

```bash
git clone https://github.com/ParadoxFuzzle/jerithchain.git
cd jerithchain
python3 -m venv .venv && . .venv/bin/activate     # optional but recommended
pip install -r requirements.txt

# Start the node (creates ./data/jerith.db, ./keys/master.key, ./keys/api.token)
python3 jerith_node.py
```

In a second shell:

```bash
# The CLI reads keys/api.token automatically
python3 jerith_cli.py status
python3 jerith_cli.py balance --discord-id <your-discord-id>
python3 jerith_cli.py mine --discord-id <your-discord-id> --source explicit
```

The first run initializes the genesis block. A fresh node starts its **own
chain**; to mirror the public chain instead, use a follower (below).

### Run it as a service

```bash
mkdir -p ~/.config/systemd/user
cp deploy/jerith-coin-node.service ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now jerith-coin-node
```

## Mirror the public chain (follower)

A follower keeps a read-only copy of another node's chain, verified
block-by-block (PoW + linkage + reward schedule) and synced over gRPC TLS.

```bash
# 1. Get ca.pem + sync token from the node operator, put them in ./keys/
# 2. Configure and run:
export JERITH_HOST_TARGET=<node-ip>:8301
export JERITH_SYNC_TLS_CA=$PWD/keys/ca.pem
export JERITH_SYNC_TOKEN_FILE=$PWD/keys/sync.token
python3 jerith_follow.py
```

The mirror lands in `./data-follow/jerith.db` and follows live (new blocks
stream in as they are mined). Service template: `deploy/jerith-follower.service`.

## Host a sync server (share your chain)

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout keys/sync-server.key -out keys/sync-server.pem \
  -subj "/CN=jerithchain-sync" -addext "subjectAltName=IP:<your-lan-ip>,DNS:localhost"
openssl rand -hex 24 > keys/sync.token
python3 jerith_sync_server.py        # TLS + token required
```

## Explorer

`jerith_explorer.py` serves a read-only public API (`/api/status`, `/api/blocks`,
`/api/block/{h}`, `/api/tx/{id}`, `/api/address/{addr}`) plus the static page in
`website/explorer.html`. Bind it behind your reverse proxy; CORS + per-IP rate
limiting are built in. The page also works as a **static snapshot** consumer —
see `website/explorer.html` (`SNAP_URL`).

## Architecture

```
Discord user ──▶ Jerith agent ──▶ node API (127.0.0.1:8300, bearer token)
                                     ├── jerith_core.py     Ed25519 txs, PoW blocks, SQLite ledger
                                     ├── jerith_wallet.py   AES-GCM at rest, scrypt password, TOTP 2FA
                                     └── jerith.db          blocks · txs · balances · users · mining_state
jerith_sync_server.py (:8301, gRPC TLS) ──▶ followers (read-only mirrors)
jerith_explorer.py   (:8303, read-only) ──▶ public explorer / snapshot publisher
```

### Tokenomics

| Parameter | Value |
|---|---|
| Max supply | 1,000,000,000 JER |
| Premine | 200,000,000 JER (genesis) |
| Block reward | 50 JER, halving every 210,000 blocks |
| Passive mine | 2 JER cap, ~12% of messages |
| Mine cooldowns | 300s after success · 180s after failure |
| Transfer fee | 0.1 JER, burned |
| Retarget | every 20 blocks, 4× clamp, 8–30 bits |

### Security model

- Node binds `127.0.0.1` with bearer-token auth; wallet keys are encrypted at
  rest (master key + scrypt(password) wrap).
- Key export / wallet rebind / large transfers require **password + TOTP 2FA**
  (RFC 6238); small transfers auto-sign (≤100 JER, ≤2,000 JER/day).
- Sync is gRPC over TLS with a shared bearer token; followers verify PoW,
  block linkage, and reward schedule before applying blocks.
- One wallet per Discord ID; wallets rebind by exporting the private key.

## Tests

```bash
python3 -m pytest tests/ -q      # 23 tests: crypto, PoW, ledger, wallet, E2E
```

## License

MIT — see [LICENSE](LICENSE).
