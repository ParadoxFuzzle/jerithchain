# JerithChain node operator guide (first install)

Everything needed to install, operate and verify a JerithChain node —
the chain that backs JER rewards and the mesh's stake escrow. The live
reference deployment runs alongside the mesh bootstrap (see jerith-mesh
`docs/DEPLOY-BOOTSTRAP.md` / `docs/RUNBOOK.md`; slashing evidence flows
from the mesh's fraud flush into this chain's `/stake/slash`).

## 1. Prerequisites & install

```bash
git clone https://github.com/ParadoxFuzzle/jerithchain.git
cd jerithchain
python3 --version        # tested on 3.12
pip install -r requirements.txt
```

Everything else (database, keys, genesis) is created on first boot and
persists across restarts in `data/` (chain state) and `keys/` (wallets,
api token, emergency key). Schema migrations are additive
(`CREATE TABLE IF NOT EXISTS`), so upgrades never rewrite history.

## 2. Start the node

```bash
# Foreground dev run (port via env):
JERITH_PORT=8322 python3 jerith_node.py

# Proper restartable unit: the repo ships the launcher the transient
# systemd unit calls, so /tmp cleanup can never break a restart:
bash deploy/start_jerith_node.sh &                # foreground
# or:
systemd-run --user --unit=jerith-node-dev \
  "$PWD/deploy/start_jerith_node.sh"              # background, survives logout
systemctl --user restart jerith-node-dev          # ordinary restart
```

On very first boot the node: creates the genesis block with a 200M JER
premine credited to the owner wallet (`OWNER_DISCORD_ID` in
`jerith_wallet.py`), writes an **emergency offline copy of the owner
key** to `keys/owner-emergency.hex` (mode 0600 — back this up to cold
storage; it is the only way to recover the premine wallet), and
generates the API token (next section).

## 3. Keys & API token

- `keys/api.token` — auto-created at first boot. Every privileged call
  needs `Authorization: Bearer $(cat keys/api.token)` (constant-time
  compare server-side). The one exception is `/stake/slash`, which is
  authenticated by **mesh wire signatures** instead (section 6);
  everything else
  (`/mine`, `/balance`, `/wallet/*`, `/tx/*`, `/stake*`, `/status`, …)
  is Bearer-token gated.
- Wallet signing keys live under `keys/` as encrypted per-identity
  files; wallets can be hardened with a password and TOTP via
  `POST /wallet/password` / `POST /wallet/totp/confirm`.
- One wallet per `discord_id`; the id is any stable string you control.

## 4. Health & basic ops

```bash
TOK="Authorization: Bearer $(cat keys/api.token)"
curl -s -H "$TOK" http://127.0.0.1:8322/status | head -c 300   # tip/height
curl -s -H "$TOK" "http://127.0.0.1:8322/balance?discord_id=<id>" | head -c 200

# create a wallet for an operator id (or let /mine auto-create):
curl -s -X POST -H "$TOK" -H 'content-type: application/json' \
     -d '{"discord_id":"my-id"}' http://127.0.0.1:8322/wallet/create

# sanity mining block:
curl -s -X POST -H "$TOK" -H 'content-type: application/json' \
     -d '{"discord_id":"my-id","source":"explicit"}' \
     http://127.0.0.1:8322/mine
```

## 5. Stake escrow (what the mesh talks to)

The Phase 5 anti-fraud tier: a mesh node escrows JER as skin-in-the-game;
proven dishonesty moves escrow → treasury. All token-authed:

```bash
TOK="Authorization: Bearer $(cat keys/api.token)"
BASE=http://127.0.0.1:8322

# escrow 2 JER for identity "mesh-node-x" (on-chain transfer into the
# node-held escrow wallet):
curl -s -X POST -H "$TOK" -H 'content-type: application/json' \
     -d '{"discord_id":"mesh-node-x","amount_jer":2.0}' $BASE/stake/lock
# → {"ok":true,"staked_uj":2000000,"block_height":N,...}

# read the escrow view (stake totals + recent events):
curl -s -H "$TOK" "$BASE/stake?discord_id=mesh-node-x"

# return escrow (chain clamps to whatever remains after slashes):
curl -s -X POST -H "$TOK" -H 'content-type: application/json' \
     -d '{"discord_id":"mesh-node-x","amount_jer":2.0}' $BASE/stake/unlock
```

Alternatively drive it from the mesh side — `jerith stake
status|lock|unlock` uses the same endpoints with the mesh node's chain
api token. The escrow wallet always covers transfer fees out of a small
owner-mastered liquidity buffer, so locks/unlocks/slashes never fail
because of gas; owner top-ups are logged as `stake.escrow.topup`.

## 6. Slashing (mesh → chain, Ed25519 evidence path)

`POST /stake/slash` is **not** Bearer-authenticated by design: evidence
arrives mesh-signed. The mesh's verification tracker flushes
DishonestResults reports to the bootstrap, and on flush posts a slash
notice with `x-jerith-pubkey` (64 hex), `x-jerith-stamp` (ms) and
`x-jerith-sig` over the payload
`jerith-slash1|{reporter}|{target}|{amount_uj}|{stamp}`, where the
reporter's node_id must equal the first 16 chars of its pubkey. The node
verifies the signature, binds reporter↔pubkey, enforces a stamp freshness
window, clamps the amount to what is actually escrowed (never negative),
and blocks replays seen-once (409). You normally never post slashes
manually; to exercise the path, see `tests/test_stake.py::_mesh_headers`.

Audit trail: `GET /stake` events, the block containing the escrow→
treasury transfer, and the operator log (`stake.slash`,
`stake.escrow.topup` entries).

## 7. Upgrades & rollback

```bash
git pull
systemctl --user restart jerith-node-dev
# then the usual post-restart checks: /status, /balance, /stake 200s
```

Rollback: `git checkout <previous commit>` + restart. The node's store is
additive-schema, so only downgrades that predate a schema addition need a
quick review (see `docs/RUNBOOK.md` in jerith-mesh for the pattern).
