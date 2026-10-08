# Changelog

## v1.1.0 — Exchange Readiness (2026-10-08)

### Consensus
- **Canonical block validator** (`jerith_validate.validate_block`): single
  implementation of all block rules — structure, linkage, timestamps
  (non-decreasing, 2 h future bound), independently derived difficulty,
  SHA-256 PoW with claimed-hash verification, reward schedule, supply cap,
  per-transaction signature/sender/nonce/balance, duplicate txid, genesis
  rules. Both node mining paths validate before append and audit rejects.
- **Single-source difficulty** (`core.expected_difficulty`): miner and
  validator share one retarget implementation.
- **Chain-work fork selection** (`jerith_reorg`): greatest cumulative work
  (`Σ 2^difficulty`) decides competing branches; exact ties keep the
  current chain; branches validate fully before any mutation; evicted
  signed spends requeue to the mempool. `core.block_work`,
  `Ledger.block_at/work_above/revert_to`.
- `replay_chain` verifies stored balances/nonces against replayed state
  and supports `check_pow=False` for testnet history.

### Tools
- `jerith_cli verify-chain` — offline full-chain replay audit from genesis;
  prints blocks/txs checked, emitted/burned/circulating supply, tip, and
  `RESULT: VALID/INVALID` with the first failing height (exit 0/1/2).

### Networking
- gRPC protocol v1.1 (field-number compatible with v1.0): new
  `SubmitTransaction`, `SubmitBlock` (single block or whole branch),
  `GetMempool`, `GetNetworkInfo` RPCs.
- `jerith_gossip.py`: `peers.json` static peer config (per-peer TLS and
  token), tx/block fan-out, network info.
- Sync server accepts remote blocks only through `accept_branch`
  (canonical validation + strictly greater work); read-only mode preserved
  (`JERITH_SYNC_READONLY=1`).
- Node broadcasts mined blocks/transfer txs to configured peers.
- Follower resolves competing blocks via the greatest-work rule
  (replacing the v1.0 conservative tail-wipe).

### Resource limits
- Mempool: 5,000 entries, 64 KiB per tx, 1 h TTL, 10 pending per sender.

### Exchange
- `jerith_exchange.py`: `/x/*` REST surface with its own bearer token
  (`keys/exchange.token`) and **no Discord identity**: infra wallets
  (create/list/balance), chain/block/tx queries with confirmations,
  `tx/build`, `tx/sign`, `tx/send`, `tx/sendraw`.
- Standard confirmation policy documented: 20 (~20 min); 50 for large
  amounts. Reorg policy documented.

### Tests
- 19 canonical-validator/replay tests, 7 fork/reorg tests, 1 two-process
  integration test (real gRPC sync of real-PoW history, gossip tx
  validation, branch reorg, tie rejection). Suite: 50 passed.

### Docs
- `NETWORK.md` (machine-readable parameters + honest decentralization
  status), `EXCHANGE_INTEGRATION.md` (operator guide), README v1.1 section.

### Security
- No secrets in logs; exchange token 0600; peer input fully validated;
  mempool flooding bounded; `x/wallet/export` deliberately unimplemented
  (501) pending password-protected infra wallets.
