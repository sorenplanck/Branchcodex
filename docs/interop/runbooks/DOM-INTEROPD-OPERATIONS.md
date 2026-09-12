# dom-interopd — operations runbook

Written for the Stage 13 requirement-by-requirement audit. Every claim below
names the code that enforces it; nothing here is aspiration. The daemon is
fail-closed by construction: when a section says "the daemon refuses", that
refusal is the specified behaviour, printed and exit-coded, not an error to
work around.

## 0. Building the daemon

```sh
cargo build --release --locked -p dom-interopd --no-default-features --features production
```

`--no-default-features` is not optional. The default feature set selects
`development`, and `production` and `development` are mutually exclusive by
`compile_error!` (`lib.rs`), so `cargo build --release -p dom-interopd
--features production` does not build at all. Worse, a plain `cargo build
--release -p dom-interopd` *succeeds* and produces a binary with no `run`
subcommand: `run` is `#[cfg(feature = "production")]` (`main.rs`), so that
artifact prints the usage text and exits 2 for every route. Check the artifact
before trusting it:

```sh
./target/release/dom-interopd run --state-dir /nonexistent --create </dev/null
```

A production artifact refuses on the secret stream or the manifest. A
development artifact prints `usage: dom-interopd self-check [--json]`.

## 1. What the operator runs

```text
dom-interopd self-check [--json]     # environment and artifact self-check
dom-interopd run --state-dir PATH [--create]
```

`run` refuses a debug-profile or otherwise incomplete artifact before parsing
anything (`require_operational_artifact_v1`, `main.rs`). Merely selecting the
`production` Cargo feature does not make an artifact operational.

### Secrets — one pass on standard input, never on the command line

The V3 secret stream is read once from stdin, in this exact order
(`PRODUCTION_USAGE_V1`, `main.rs`):

```text
DOM-INTEROPD-SECRETS-V3
<bearer token>
<upstream Relay signing secret: 64 lowercase hex>
<downstream Relay signing secret: 64 lowercase hex>
<Contracts identity passphrase>
<DOM wallet passphrase>
<Bitcoin participant secret: 64 lowercase hex>
<route-secret seal key: 64 lowercase hex>
<refund-arming credential: 64 lowercase hex>
<local EVM signing secret: 64 lowercase hex>
upstream_f6_hsm_credentials=<count, then that many 64-hex lines>
downstream_f6_hsm_credentials=<count, then that many 64-hex lines>
```

No secret is ever a flag, an environment variable or a file path; nothing
echoes them (I6 guard: every `eprintln!` in the binary is inventoried).

That V3 stream names one Bitcoin participant and one EVM signer because that
is the only pair its family can express. The V11 per-position bootstrap reads
the universal V4 stream instead, which names the *family* of each position and
then that family's own secrets (`production_node_universal.rs`, `parse`):

```text
DOM-INTEROPD-SECRETS-V4
<bearer token>
<upstream Relay signing secret: 64 lowercase hex>
<downstream Relay signing secret: 64 lowercase hex>
<Contracts identity passphrase>
<DOM wallet passphrase>
<route-secret seal key: 64 lowercase hex>
<refund-arming credential: 64 lowercase hex>
upstream_family=BTC|EVM|SOL|XMR
<that family's secrets, 64 lowercase hex each>
downstream_family=BTC|EVM|SOL|XMR
<the downstream family's own secrets>
upstream_f6_hsm_credentials=<count, then that many 64-hex lines>
downstream_f6_hsm_credentials=<count, then that many 64-hex lines>
```

How many secret lines a family contributes is fixed by the family: BTC one
participant secret, EVM one signing secret, SOL a seed then a peer-auth key,
XMR a local-store key then a sidecar-auth key. Both headers are read on the
same stdin and the header alone selects the family; there is no flag.

Every field above must differ from every other one — the bearer token, both
passphrases, both Relay secrets, the seal key, the refund credential, every
leg secret and every HSM credential are compared pairwise, and any repeat is
refused as a reused key. This is the rule an operator scripting the stream is
most likely to break, because reusing one placeholder while filling in the
others looks harmless and is not.

### Known limits are printed at startup

Before driving a route, `run` prints one `known limit:` line per entry of
`PRODUCTION_KNOWN_LIMITS_V1` (`production_run.rs:311`). Today that names the
Bitcoin claim-materialization refusal, the EVM reextraction refusal, the
Solana and Monero route-shape refusals and the extended chain-services
refusal. An operator reading the startup output knows exactly which paths
refuse by policy.

### The manifest refusal names the check that refused

`run` loads the bootstrap manifest before anything else it can name, and that
load now reports which check refused rather than a single collapsed line:

```text
production configuration refused: ConfigUnavailable: production bootstrap manifest unavailable
```

The variant and its sentence both come from `ProductionConfigErrorV1`, whose
every variant is already free of paths, endpoints, input bytes and nested
error strings — that is what makes naming it at this boundary safe. An
operator assembling a state directory reads the *class* of the defect (the
manifest is missing, or oversized, or its digest disagrees, or a path
reference is not owner-only) without the daemon ever describing the bytes it
rejected.

This is deliberately the first check and not the only one worth naming. Later
refusals in the universal startup path still collapse to `production
configuration refused`; when one of those blocks you, the manifest load has
already succeeded, which is itself the information that narrows it.

## 2. State directory — the unit of operation, backup and restore

The state directory is a capability: the daemon opens it exactly once per
stage of the ordered provisioning journal. Fixed names, all pinned in
`production_config.rs`:

```text
bootstrap-create-v1.conf … bootstrap-create-v10.conf   (config family)
bootstrap-reopen-v1.conf … bootstrap-reopen-v10.conf
node.v1                          production-relay-network.v1
inputs/registry.sqlite3          state/route.sqlite3
refund-arming.v1.sqlite3
solana-actuator.v1.sqlite3       (created only by a route whose admitted
xmr-actuator.v1.sqlite3           shape carries that leg)
```

Wallet stores pin their parent directory to owner-only `0700` at creation and
the envelope audit refuses any other mode (`audit_parent_authority`,
dom-wallet; commit 1a35bab). SQLite stores validate their sidecar journals on
open (`validate_sqlite_sidecar`, `production_refund_arming.rs`), refusing a
foreign or displaced journal.

### Backup

Back up the state directory as a whole, cold (daemon stopped): every store is
a file under it, and the config digests bind them together. The Contracts
Store additionally has an authenticated canonical backup format
(`dom-scriptless-store/src/canonical/backup.rs`) whose restore path
(`canonical/restore.rs`) verifies an authenticated restore-transaction
manifest — a tampered or truncated backup refuses instead of half-loading.
The wallet has its own sealed backup (`dom-wallet/src/backup.rs`, exercised
by `shield_backup_fix005.rs`; V2 chain-id binding by
`shield_backup_chain_id_fix026.rs`).

### Restore and restart semantics

Reopen is the restore path: `run` without `--create` reopens every store from
its exact journaled prefix or refuses (`prepare_open_resumed_production`,
session store). The crash matrix is executed, not assumed
(`dom-interopd/tests/simulation.rs` + store/vault/solver crash suites):

- crash after broadcast → reopen reconciles the SAME transaction once —
  economically idempotent, no duplicate effect
  (`claim_cli_is_terminal_and_reopen_is_economically_idempotent`);
- crash after a timer-event commit → redelivery is detected as duplicate and
  the route refunds;
- store mid-write SIGKILL → `dom-store` crash-consistency suites;
- relay database loss → `f6-engine` relay-loss suite + the route-transport
  recovery path (`authenticate_recovery`/`reconstruct`).

Operator rule: never edit a store file. If a store refuses to open, that is
the tamper/corruption detector working; restore the cold backup.

## 3. Credential and key rotation

Rotation is epoch-based provisioning, not in-place mutation:

- **Refund-arming authority**: `refund_arming_authority_epoch` (config V9,
  `production_config.rs:1227`) identifies the provisioned refund authority
  configuration; a new credential is a new epoch through the create path.
- **Registry rollback floor**: `registry_minimum_epoch` must be non-zero
  (`production_config.rs:677`) and the registry refuses any document below
  it — a rolled-back registry is refused, not silently accepted.
- **F6 HSM credentials**: the V3 secret stream carries explicit
  upstream/downstream credential lists with counts; rotation is a new stream
  on the next start. No credential persists outside its sealed store.
- **Route leases**: `lease_duration_ms` / `renew_before_ms` /
  `dispatch_lease_ms` are validated together (`production_config.rs:740-752`);
  degenerate combinations refuse at config load.

## 4. Upgrades and rollback — fail-closed

- The config family match in `production_config.rs` has **no wildcard arm**:
  a V(n+1) document cannot be written with a V(n) header, and an unknown
  family refuses at load.
- `Cargo.lock` digest is verified unchanged by `ci_local.sh` around the
  production gates; the release surface is pinned by
  `check-release-surface.sh` and `check-relay-fault-surface.sh`.
- Durable rollback floors: the authenticated composition anchor carries a
  rollback floor (`production_relay_stage12.rs:178`); the supervisor treats
  clock zero/rollback as refusal (`supervisor.rs:43`); the registry epoch
  floor is §3. Rolling back to an older store or registry **refuses**.

## 5. Limits and DoS posture

Every externally-fed surface is bounded by named constants, closed at compile
time: `MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES` (= the Relay's own
`MAX_PAYLOAD_BYTES`), `MAX_FRAMED_DSC1_BYTES_V2`,
`MAX_ROUTE_FRAME_CHUNK_BYTES_V2`, `MAX_ROUTE_FRAME_COUNT` (route-transport);
`MAX_PROOF_BYTES = 256 KiB` (xmr-dleq-sigma); the EVM observer's hostile-RPC
paging fix (adversarial audit A-08); fuzzing evidence on the two Bitcoin
parsers (41.9M + 1.02M executions, zero findings, Stage 11). The relay
refuses unregistered message kinds for every role (D-019/D-029 closed
registry).

## 6. Observability, metrics and alerting

The daemon deliberately exposes **no network metrics endpoint**: a metrics
listener on a custody daemon is attack surface, and nothing here may bind a
port that the route does not require. Observability is:

1. **stderr** — startup known-limits, refusals, and terminal errors; under
   systemd this is journald, and alerting is a journal match on
   `known limit:`, `refus`, or a non-zero exit.
2. **exit code** — the process is its own health check: `SUCCESS` only on a
   terminal route outcome; any refusal is `FAILURE` with the reason printed.
3. **durable journals** — the ordered provisioning journal and the per-store
   SQLite journals are the auditable record; `self-check --json` gives a
   machine-readable environment report.

A future metrics surface, if ever wanted, is an operator decision that must
be ratified; it is not assumed here.

### Native XMR inventory restart artifact (V23)

On the local solver of a native XMR/XMR route, production startup now requires
`native-xmr-inventory-authority-v23.bin` at the state-directory root. It is a
bounded, owner-only, canonical public descriptor: route/network IDs, both
session and terms digests, solver ID, Mainnet genesis, exact funding txid and
raw bytes, owned output index/public spend key/destination, amount and fee cap,
followed by its domain-separated checksum. It contains no spend key, view key,
V4 credential, sidecar credential, or broadcast permission.

The corresponding spend/view pair must already be an authenticated row in the
selected XMR `EncryptedSqliteSecretStore`, encrypted under the local store key
supplied by the normal V4 supervisor stream. Provision it offline with
`dom-interopd prepare-xmr-inventory-v23 --state-dir ABS --secret-store ABS`.
The command reads one bounded strict JSON object from non-terminal stdin,
imports explicit spend/view/master scalars, verifies the Mainnet genesis,
funding txid/raw/output/amount/fee/destination and non-aliasing route funding
txids, inserts the AEAD-bound row idempotently, then publishes the descriptor
atomically without replacement. It performs no RPC call and cannot broadcast.
Normal daemon create/reopen never creates a missing descriptor, Store or row.

Before F6 can consume the signed observation, the solver process reloads that
row with descriptor-derived AEAD associated data, recomputes public spend,
destination, output and economics, asks the authenticated sidecar to scan the
same output, obtains byte-identical raw transaction evidence plus
inclusion/finality from the configured Mainnet quorum, and requires its key
image unspent. The resulting move-only proof is matched exactly once against
the XMR `InventoryObservationV1`; any absent or divergent component refuses F6.

## 7. What this runbook deliberately does not cover

Sepolia execution (operator credentials + explicit order;
`docs/SEPOLIA-RUNBOOK.md` and the f3/f4 workflows), Signet (cancelled by
operator decision — the BTC leg validates on regtest only), and the
Solana/Monero route shapes (refused at counterparty selection until their
composition chain exists; the refusal is printed at startup, §1).
