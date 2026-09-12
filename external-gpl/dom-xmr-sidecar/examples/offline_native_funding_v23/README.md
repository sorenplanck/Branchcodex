# Explicit local mutable route scenario

This GPL example is a local component/scenario fixture. It is not a Monero
node, wallet funding utility, consensus implementation or mainnet miner. Its
initial funding transactions use synthetic source custody; its headers have no
PoW. A Mainnet address/profile and genesis pin do **not** make this generated
history real Mainnet data. Never use its responses as evidence of actual network
funding or confirmations.

Existing requests remain immutable by default. The two-leg `route_peer` input
must explicitly include `"mutable_scenario_v23":true` to enable the new mode.
That mode still binds only `127.0.0.1` listeners, opens no outbound network
connection, and never forwards a transaction to any external daemon.

Mutable startup differs deliberately from the historical scan fixture: it
creates three explicitly synthetic coinbase source outputs at heights 1, 2 and
3, with real indexed keys and transparent commitments. The two contract-funding
transactions are built and verified against those actual source rings, then
returned only as **unconfirmed candidates**, absent from both history and pool.
Only the separate solver-inventory transaction is initially included, at height
102, so its real wallet scanner can establish the solver's available inventory.
Contract funding requires the daemon's later authorized exact submission and
the parent's separate private inclusion command. Candidate construction alone
must never count as funding, custody authorization or F7 progress.

The mutable startup envelope adds
`funding_state_v23:"unconfirmed-route-candidates-inventory-confirmed"` and
`source_outputs_v23`, an array of three public source descriptions containing
`position` (`upstream`, `downstream`, `inventory`), `tx_hash`, `block_height`,
`global_output_index`, `amount_piconero`, `public_key` and `commitment`. Hashes and
points are lowercase hex. Legacy read-only envelopes omit both fields. The
existing `legs` carry candidate hash/raw/destination data, not confirmations;
the parent's mutable preflight must verify their absence rather than demand
pre-funded contracts.

## Candidates and cryptography

Only in mutable mode does `/send_raw_transaction` exist. It accepts canonical
lowercase raw-transaction hex and the ordinary optional `do_not_relay` and
`do_sanity_checks` fields used by the real clients. Neither flag disables a
verification step or enables external relay.

Before retaining a new local-pool candidate, the helper verifies:

- complete canonical V2 serialization, CLSAG/Bulletproofs+ profile, input/output
  cardinality bounds and no additional output timelock;
- every absolute ring index against the actual retained local output table,
  with strict relative-offset ordering and unlock heights;
- each CLSAG using its exact retained ring, raw-derived key image, pseudo-output
  and actual transaction signature hash;
- nonzero/valid output keys, subgroup-valid commitments, unique/unspent input
  key images, and real Bulletproofs+ verification over output commitments;
- conservation of commitments including the fee, with a positive fee capped
  at one billion piconero. This local resource bound does not replace each
  route's independently negotiated fee and payout checks.

This verifies actual cryptography and ring membership, not the whole Monero
consensus rule set. Destination ownership and negotiated amounts remain subject
to the existing real scanner and route authorization. Initial synthetic funding
roots are explicitly fixture seeds, not retrospectively claimed valid spends of
the local miner-output table. That legacy exception is not used for mutable
route funding: its candidates and initial inventory spend the explicit local
source entries. New candidates must spend real entries in the retained table;
arbitrary signed bytes from an unrelated ring are refused.

A valid submission enters only the local pool. Exact same-byte resubmission is
idempotent. A competing transaction with a reserved or confirmed key image is
refused. Key-image RPC statuses distinguish `0` absent, `2` local pool and `1`
confirmed in this synthetic history. Transaction lookups report `in_pool:true`
until the supervisor explicitly includes the candidate. At most 32 candidates
are pending and 256 non-miner transactions exist across pending/confirmed state.
Raw candidates are bounded at 128 KiB.

## Private control pipe

After the existing `DOM-XMR-OFFLINE-ROUTE-FUNDING-V23` startup envelope, the parent
owns the child's stdin and reads newline-delimited control acknowledgments on
stdout. There is no HTTP administrative endpoint. Control lines are limited to
8192 bytes. Sequences are contiguous, starting at 1. Malformed JSON, unknown
fields, wrong schema or a noncontiguous sequence close the scenario; semantic
refusal acknowledges the sequence with the actual unchanged/retained state.

Status request:

```json
{"schema":"DOM-XMR-OFFLINE-CONTROL-V23","sequence":1,"operation":"status"}
```

Advance request, with values selected from the previous status and actual
pending transaction hashes:

```text
{"schema":"DOM-XMR-OFFLINE-CONTROL-V23","sequence":2,"operation":"advance","height":TARGET_HEIGHT,"timestamp":TARGET_TIMESTAMP,"include_tx_hashes":["EXACT_LOWERCASE_TRANSACTION_HASH"]}
```

The placeholder line describes the shape, not an executable request. An empty
inclusion list advances without confirming any pending transaction. At most 16
distinct pending hashes can be selected. All selected transactions are included
at the **first** new height (`previous_tip + 1`); remaining intervening heights
are generated so the final tip establishes the requested local confirmations.
Unknown/duplicate hashes, height rollback or heights above 1,000,000 are refused
before changing history. Pending candidates not selected remain pending.

The target timestamp must be at least the retained tip timestamp and no later
than the real system clock. Intervening timestamps are deterministically
interpolated and nondecreasing; equal timestamps are allowed in this explicitly
synthetic scenario. Rapidly generating hundreds of thousands of heights is not
a claim that real Monero mined those heights or that elapsed-time rules permit
the route. Real signed time authorities and freshness guards can still reject
such a scenario; they must not be weakened to accommodate it.

Acknowledgment shape:

```text
{
  "schema": "DOM-XMR-OFFLINE-CONTROL-ACK-V23",
  "sequence": 2,
  "accepted": true,
  "status": {
    "scope": "local-synthetic-history-not-mainnet-confirmation",
    "tip_height": HEIGHT,
    "tip_hash": "LOWERCASE_BLOCK_HASH",
    "tip_timestamp": TIMESTAMP,
    "pool_tx_hashes": ["LOWERCASE_PENDING_HASH"],
    "transactions": [{"tx_hash":"LOWERCASE_HASH","block_height":HEIGHT}]
  },
  "error": null
}
```

`transactions` initially contains only the included inventory transaction in
mutable route mode, then any explicitly included candidates; it never lists
miner transactions. A semantic refusal has `accepted:false`
and `error:"control-refused"`; the status always describes retained state, not
the requested state. Parents should bound acknowledgment lines at 64 KiB.

`operation:"stop"` takes only schema/sequence, acknowledges current state, and
closes both listeners. EOF also closes the scenario. The ordinary immutable
route still owns its listeners until EOF and accepts no control mutation.

## History cost and lifetime

No advancement merely changes a reported tip. Every intermediate header, miner
transaction, output, index, cumulative distribution count and parent hash is
constructed and retained. Heights 1–200 keep the existing fixture unchanged;
later heights add one deterministic miner output per block. Memory and work are
linear in the number of generated heights, potentially hundreds of megabytes
at the large upstream refund deadline. Large advances should have a separate
bounded supervisor timeout (up to 300 seconds suggested, not benchmarked here).
Coordinate them with the observer loop: the common ledger lock keeps both RPC
views consistent while materializing an advance, so RPC requests may wait/retry.
Each voter permits at most 16 concurrent client sockets, with five-second read
and write timeouts; idle keep-alive clients do not monopolize the listener.
Finished connection threads are reaped and all owned connections joined during
shutdown. The ledger lock is taken only after reading the bounded request and
released before writing either JSON or binary responses to a potentially slow
client.

Block-hash lookup and non-miner status use dedicated indexes. Scan requests
remain bounded at 200 blocks/4 MiB; output lookup stays at 128 entries. Only the
cumulative distribution endpoint grows to 1,000,001 heights/8 MiB, matching the
explicit scenario cap and serving the real decoy selector without invented
rows or truncated history.

This ledger is an in-memory test owner, not durable custody: EOF/termination
discards its synthetic history. Production custody and transaction journals
remain the daemon's durable stores. The written regressions cover a genuinely
signed spend of a retained miner output, pool/replay/double-spend behavior,
explicit inclusion, scan/index/height coherence, malformed/ring/fee/proof
refusal, and administrative bounds. No test execution or network-funding claim
is implied by the presence of these regressions.
