# JerithChain Network Parameters (v1.1)

Machine-readable reference for exchanges and node operators. These are the
**actual implemented parameters** as of software version 1.1.0. Anything
not implemented is labeled as such — this document never lists planned
features as existing.

## Identity

| Field | Value |
|---|---|
| Network name | JerithChain |
| Asset | Jerith Coin |
| Ticker | `JER` |
| Source repository | https://github.com/ParadoxFuzzle/jerithchain |
| Explorer | https://jerithai.com/explorer.html |
| Website | https://jerithai.com/ |

## Consensus (implemented)

| Parameter | Value |
|---|---|
| Consensus | SHA-256 proof-of-work (single SHA-256 of canonical JSON block header) |
| Block time target | ~60 s (on-demand mining: transfer blocks are mined when transfers occur) |
| Initial difficulty | 18 leading zero bits |
| Minimum difficulty | 8 bits |
| Maximum difficulty | 30 bits |
| Retarget interval | 20 blocks |
| Retarget clamp | 4× per window (±2 bits typical per window) |
| Block structure | `height, prev_hash, timestamp, txs, miner, reward, nonce` over canonical JSON (sorted keys, no whitespace) |
| Fork selection | Greatest cumulative chain work, `Σ 2^difficulty_bits`; exact ties keep the current chain |
| Signatures | Ed25519 over canonical JSON tx payload |
| Ledger model | Account/balance with sequential per-account nonces |

## Economics (implemented)

| Parameter | Value |
|---|---|
| Unit | 1 JER = 1,000,000 micro-JER (uJ); all APIs use integer uJ |
| Maximum supply | 1,000,000,000 JER |
| Genesis premine | 200,000,000 JER (20%, chain-native allocation in genesis block, publicly disclosed) |
| Block reward | 50 JER, halving every 210,000 blocks, floor 1 uJ |
| Transfer fee | 0.1 JER (100,000 uJ), **burned** (reduces circulating supply) |
| Passive mining reward | capped at 2 JER (application-layer, below consensus reward cap) |

## Transactions (implemented)

| Field | Rule |
|---|---|
| Kinds | `spend` (user), `mine` (chain-native reward), `premine` (genesis only) |
| Nonce | Sequential, must equal sender's current nonce |
| Validation | Full canonical validation before mempool and before block acceptance |

## Timestamp policy (implemented)

- `block.timestamp >= previous block timestamp` (non-decreasing; on-demand
  mining means blocks can share a wall-clock second)
- `block.timestamp <= now + 7200 s` (2-hour future bound)

## Address format (implemented)

`JER` + first 32 hex chars (uppercased) of `SHA-256("jerith-addr" || ed25519_verify_key)`.
35 characters total. Example: `JER831896DD6F6B23B231CEAF035D8E0EC7`

## Network / ports (implemented)

| Service | Default | Config |
|---|---|---|
| Node REST API (agent + exchange RPC) | `127.0.0.1:8300` | `JERITH_PORT` |
| Peer sync/gRPC (gossip + block streaming) | `:8301` | `JERITH_SYNC_PORT` |
| Peer TLS | optional | `JERITH_SYNC_TLS_CERT` / `JERITH_SYNC_TLS_KEY` |
| Peer auth | optional bearer token | `JERITH_SYNC_TOKEN` / `JERITH_SYNC_TOKEN_FILE` |
| Static peers | `peers.json` | `JERITH_PEERS_FILE` |

## Confirmation policy (recommendation, v1.1)

With a small federated network and bounded difficulty (currently 18 bits,
max 30), reorg risk is dominated by a minority miner producing a longer
valid branch. The cumulative-work rule makes reorgs deterministic but not
impossible.

**Recommended exchange confirmation threshold: 20 confirmations**
(~20 minutes at the 60 s target). For large amounts, 50 confirmations.
Re-examine once real third-party hashpower exists on the network.

During a reorg: transactions in displaced blocks return to the mempool
automatically (signed spends only) and lose their confirmations; a credit
based on an orphaned tx must be reversed. Monitor
`GET /x/tx/{txid}/confirmations` rather than caching confirmation counts.

## Supply accounting (implemented, see explorer + verify-chain)

- `emitted` = premine + all mine rewards
- `burned` = sum of all transfer fees
- `circulating` = emitted − burned (sum of all balances)
- The founder premine is part of emitted supply from block 0; treat it as
  founder-held, not distributed circulating supply, in your own models.

## Decentralization status (honest)

- **v1.0 (current live):** operator-rooted — the founder node produces
  blocks; followers validate and mirror.
- **v1.1 (this release):** any node can produce valid blocks and any
  other node can validate and adopt them by cumulative work. The gossip
  protocol and fork rule remove the *technical* requirement to trust the
  founder node. In practice the network is still small (operator +
  follower); block production is not yet permissionless-mining at scale.
- Do not represent JER as more decentralized than this.
