# JerithCoin (JER) Exchange Integration Guide — v1.1

For exchange engineers integrating JER deposits and withdrawals. This
documents **what is implemented in v1.1.0** — nothing here is aspirational.
Companion reference: [NETWORK.md](NETWORK.md).

## Overview

Jerith Coin is the native asset of JerithChain (SHA-256 PoW, account/balance
ledger, Ed25519 signatures, integer micro-JER arithmetic). The node exposes:

- `/x/*` — the exchange RPC (this guide). Bearer token from
  `keys/exchange.token`, auto-created `0600` on first node start. **Fully
  independent of Discord identity.**
- (legacy `/` agent API — Discord-wallet surface, do not use for exchange
  custody)

## Installation

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git
git clone https://github.com/ParadoxFuzzle/jerithchain
cd jerithchain
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Environment variables (all optional):

```bash
export JERITH_DATA_DIR=/srv/jerith/data      # chain database (default ./data)
export JERITH_KEYS_DIR=/srv/jerith/keys      # tokens + master key (default ./keys)
export JERITH_PORT=8300                      # REST API port (localhost)
export JERITH_SYNC_PORT=8301                 # peer gRPC port
export JERITH_PEERS_FILE=/srv/jerith/peers.json
export JERITH_SYNC_TLS_CERT=/srv/jerith/tls/node.crt
export JERITH_SYNC_TLS_KEY=/srv/jerith/tls/node.key
export JERITH_SYNC_TOKEN_FILE=/srv/jerith/keys/sync.token
```

## Running a node

```bash
python3 jerith_node.py            # REST API on 127.0.0.1:$JERITH_PORT
python3 jerith_sync_server.py     # peer gRPC on :$JERITH_SYNC_PORT
```

Run both on every node. Bind the REST API behind a firewall or SSH tunnel —
it is localhost-only by default and holds wallet secrets.

## Synchronization

A new node starts from genesis and builds its own chain — **it does not
copy another node's database**. To follow an existing chain, run a follower:

```bash
export JERITH_HOST_TARGET=seed.example.com:8301
export JERITH_SYNC_TOKEN_FILE=/srv/jerith/keys/sync.token   # if peer requires auth
python3 jerith_follow.py
```

The follower validates every received block (PoW, linkage, signatures,
rewards, supply, difficulty derived from its own view) before persisting
anything. Adopting a competing tip is decided by cumulative chain work.

## Chain verification (do this after initial sync, and periodically)

```bash
python3 jerith_cli.py verify-chain --data-dir /srv/jerith/data
```

Replays the entire chain from genesis: block hashes, PoW, difficulty rule,
signatures, rewards, supply cap, and stored-balances-vs-replay. Prints
`RESULT: VALID` / `RESULT: INVALID` with the first failing height. Exit
code 0 = valid.

## Wallet

Create infrastructure wallets (each is an independent Ed25519 keypair
encrypted under the node master key):

```bash
XTOK=$(cat keys/exchange.token)
curl -s -X POST -H "Authorization: Bearer $XTOK" -H 'content-type: application/json' \
     -d '{"label":"deposit-hot-1"}' http://127.0.0.1:8300/x/wallet/new
# -> {"address":"JER...","label":"deposit-hot-1","created":true}

curl -s -H "Authorization: Bearer $XTOK" http://127.0.0.1:8300/x/wallet/list
curl -s -H "Authorization: Bearer $XTOK" http://127.0.0.1:8300/x/wallet/JER831896DD6F6B23B231CEAF035D8E0EC7
# -> {"address":"...","balance_uj":29900000,"nonce":1,"pending_mempool":0}
```

Wallets require **no Discord account**. Addresses are the standard JER
format (`JER` + 32 hex chars, 35 chars total).

## Deposits

1. `POST /x/wallet/new {"label":"customer:<uid>"}` — one address per
   customer deposit lane.
2. Give the address to the customer.
3. Poll deposits:

```bash
# every block, for each deposit address:
curl -s -H "Authorization: Bearer $XTOK" \
  http://127.0.0.1:8300/x/tx/<txid>/confirmations
# -> {"txid":"...","confirmations":13,"standard":20}
```

4. Credit the customer when `confirmations >= 20` (see policy below).
5. Match deposits by `recipient` address and `amount_uj` (integer uJ).

### Confirmation policy

**20 confirmations (~20 min)** for standard amounts; **50** for large
amounts. Rationale and reorg behavior: [NETWORK.md](NETWORK.md).
Never cache confirmation counts — reorgs subtract confirmations.

### Minimums (recommended, application-layer — not consensus)

- Minimum deposit: 1 JER (below this the 0.1 JER network fee dominates)
- Minimum withdrawal: exchange-defined (≥ 0.1 JER fee)
- Network fee: 0.1 JER (100,000 uJ), burned

## Withdrawals

Simplest path — build, sign, broadcast in one call:

```bash
curl -s -X POST -H "Authorization: Bearer $XTOK" -H 'content-type: application/json' \
  -d '{"from_address":"JER62AE...","to":"JER1B0E...","amount_uj":10000000,"memo":"withdrawal"}' \
  http://127.0.0.1:8300/x/tx/send
# -> {"txid":"933d...","block_height":3,"block_hash":"0000...","confirmations":1,
#     "amount_uj":10000000,"fee_uj":100000,"standard_confirmations":20}
```

Cold-storage path — build and sign on an online hot node, or sign
externally:

```bash
# 1. build (returns the canonical payload to sign)
curl -s -X POST .../x/tx/build -d '{"from_address":"JER...","to":"JER...","amount_uj":10000000}'
# 2. sign payload_hex with the wallet's Ed25519 key (offline/HSM)
# 3. broadcast
curl -s -X POST .../x/tx/sendraw -d '{"signed_tx":{...signed tx dict...}}'
```

The v1.0 model mines a valid spend into a new block immediately, so
`/x/tx/send` returns a confirmed height and txid in one call.

## Reorganizations

If a greater-work branch displaces the tip, transactions in displaced
blocks lose confirmations and return to the mempool (signed spends; the
block reward reverts automatically). Practical policy:

1. Credit only at the documented threshold.
2. On reorg detection (`confirmations` dropping below threshold, or tip
   hash changing at a height you credited), reverse the credit and
   re-credit when the tx re-confirms.
3. Orphaned spends are re-mined automatically by the node that had them
   in its mempool — the txid is stable (it hashes the signed payload).

## RPC/API summary

| Endpoint | Method | Purpose |
|---|---|---|
| `/x/chain` | GET | height, tip hash, difficulty, chain work, mempool size |
| `/x/networkinfo` | GET | same as /x/chain |
| `/x/blockhash/{height}` | GET | block hash at height |
| `/x/block/{height}` | GET | full block + txids + confirmations |
| `/x/tx/{txid}` | GET | transaction + confirmations |
| `/x/tx/{txid}/confirmations` | GET | confirmation count + standard |
| `/x/wallet/new` | POST | create infra wallet (`{"label": "..."}`) |
| `/x/wallet/list` | GET | wallets with balances/nonces |
| `/x/wallet/{address}` | GET | balance_uj, nonce, pending mempool |
| `/x/tx/build` | POST | unsigned tx + canonical payload hex |
| `/x/tx/sign` | POST | sign with node-held key (validates before signing) |
| `/x/tx/send` | POST | build+sign+broadcast (returns txid + block) |
| `/x/tx/sendraw` | POST | broadcast externally-signed tx |

Amounts are **integer micro-JER (uJ)** everywhere. 1 JER = 1,000,000 uJ.

Peer-side diagnostics over gRPC: `GetNetworkInfo` (height, tip, work,
protocol/software version), `GetMempool`, `SubmitTransaction`,
`SubmitBlock` (single or branch).

## Ports

| Port | Bind | Exposure |
|---|---|---|
| 8300 (or `JERITH_PORT`) | 127.0.0.1 | never expose publicly; REST + wallet keys |
| 8301 (or `JERITH_SYNC_PORT`) | all interfaces | peer gRPC; TLS + token recommended |

## Security

- Exchange token (`keys/exchange.token`) is created `0600` on first start;
  treat it as a custody credential — separate from the Discord-agent token
  so you can firewall the two surfaces independently.
- Wallet secret keys are AES-encrypted under `keys/master.key` (`0600`).
  Back up `keys/` offline (see Backup).
- Chain data writes go through canonical validation and a global write
  lock; a block or tx that fails validation is never persisted.
- The mempool has hard caps (5,000 entries, 64 KiB/tx, 1 h TTL, 10 per
  sender) — flooding is bounded.
- No private key, password, or TOTP code is ever logged; the audit log
  records events (wallet.create, xwallet.send, …) with addresses only.
- All peer input (blocks and transactions) is validated with the same
  rules as locally mined content — there is no trusted-peer shortcut.
- TLS for peer links is optional but strongly recommended off-host;
  mutual pinning can be layered via the `peers.json` `ca` field today.

## Upgrade procedure

1. Stop the node process (`jerith_node.py`) and sync server.
2. `git fetch && git checkout <release-tag> && pip install -r requirements.txt`
3. Restart. The SQLite schema is additively migrated on start
   (`CREATE TABLE IF NOT EXISTS`); consensus rules for existing blocks are
   unchanged unless a release explicitly states a coordinated hard fork.
4. Run `python3 jerith_cli.py verify-chain` after upgrading — it must print
   `RESULT: VALID` before you resume processing deposits.

## Backup

What must be backed up, in order of importance:

1. `keys/master.key` — without it, wallet secret keys are unrecoverable.
2. `keys/exchange.token`, `keys/api.token` (rotate on restore instead).
3. `data/jerith.db` (chain + wallets + mempool). Use `sqlite3 .backup`
   or copy while the node is stopped. WAL mode: copy `jerith.db`,
   `jerith.db-wal`, `jerith.db-shm` together.
4. `peers.json` and TLS material (recreatable).

For custody wallets, also keep an offline copy of exported secret keys
(`JER` seed hex) in cold storage. Note: `/x/wallet/export` is deliberately
not implemented in v1.1.0 (returns 501) — create custody keys via
`/x/wallet/new` and back up `master.key` instead, or sign externally.

## Disaster recovery

- Node lost, keys intact: restore `data/` + `keys/`, restart, re-sync any
  missing tail from peers (validated automatically), run `verify-chain`.
- Node lost, keys lost: chain funds in node-managed wallets are
  unrecoverable (by design — there is no escrow). This is why `master.key`
  backup is step 1.
- Chain corruption: `verify-chain` reports the first bad height. Restore
  from backup and re-sync; never hand-edit the database.

## Honest limitations (v1.1.0)

- The network is small (currently operator + follower); confirmation
  thresholds may need revisiting as third-party hashpower arrives.
- Block production is federated but not yet permissionless — see
  NETWORK.md "Decentralization status".
- `/x/wallet/export` is intentionally unimplemented; external signing is
  the supported path for cold wallets.
- Mempool propagation is store-and-forward (no inv/getdata yet): peers
  relay txs/blocks they have; discovery is static `peers.json`.
