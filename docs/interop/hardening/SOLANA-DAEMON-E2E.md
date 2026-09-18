# DOM↔Solana through two real `dom-interopd` daemons

Status: **written, not executed.** Nothing in this document has been compiled
or run on this branch. It records the design the code follows, the decisions
taken while reading the tree, and the risks that only an execution can settle.

## 1. Where the Solana leg already lives

The universal V4/V11 run (`production_run_universal.rs`) already carries a
Solana counterparty leg end to end in code:

| Stage | Where |
|---|---|
| V4 secret stream, `*_family=SOL` (Ed25519 seed + reserved `peer_auth`) | `production_node_universal.rs` |
| Position selection, `SelectedLegV11::Solana` | `production_run_universal.rs` |
| Signer pair: one local key, one scoped Unix peer | `production_universal_leg_authority.rs` `bind_signers` |
| F6 counterparty face (`ProductionSolanaF6TermsOwnerV7`) | `production_f6/extended_terms.rs` |
| Materializing child: initialize+fund, claim, refund, observe, reconcile | `production_child_solana.rs` |
| Refund face (permissionless on-chain refund) | `production_refund_arming.rs` |
| F7 funding/claim consumers, receiver on every leg | `production_relay_stage12.rs`, `production_f7_runtime_v12.rs` |
| Public-secret source | DOM downstream leg; the external source is the upstream leg by design |

No scenario proves any non-XMR leg through this run. Solana is the first.

Two things that looked like gaps are not:

- **Claim on the daemon that did not fund.** `step_f7_claim_v20` is driven by
  the funding party (its observer must hold the exact retained funding
  signature); the other daemon takes part through `step_f7_claim_receiver_v15`,
  which runs for every leg. EVM follows the same shape.
- **A Solana downstream leg as secret source.** The route exposes the secret on
  the DOM downstream leg, which is always a source; only the upstream
  counterparty is an external source.

## 2. The peer signer is an external local process, by design

`bind_signers` gives each daemon one local signer (its own role's key) and one
`ProductionSolanaUnixSignerV7` connected at startup to `peer_socket`. The daemon
holds that connection for its lifetime and never reconnects after an error.

Nothing in `dom-interopd` listens on that socket, and the same is true for the
Bitcoin `claim_peer_socket`. The architecture notes state it for Bitcoin: *the
local peer implements the `DOMBTCX6` envelope*. The Solana peer implements the
V7 envelope (`DOMSLSQ7` request / `DOMSLSA7` response). The two-daemon scenario
therefore serves the socket from the fixture with the crate's own
`ProductionSolanaLocalSignerV7::serve_once`, looping on one accepted
connection — exactly as the XMR scenario runs its sidecars as external
executables.

Operational gap for a real two-machine deployment: an operator-run process has
to serve that envelope. V7 has no handshake; `peer_auth` is validated and wiped,
never sent.

## 3. Profile: the local validator must be attested, not exempted

The production input loader and the F7 funding authority refuse a profile whose
`require_immutable_program` is false. `SolanaAdapterProfileV1::new` sets it
false for `LocalValidator`. Relaxing the daemon would be wrong, because the
observer then skips the attestation entirely.

`SolanaAdapterProfileV1::new_attested` builds the same profile with the flag set
on every network. A validator can honestly satisfy it: loading the escrow with

```text
solana-test-validator --reset --ledger <dir> --bind-address 127.0.0.1 \
  --rpc-port <port> \
  --upgradeable-program 3KN5WMzZsmwDCfKYheaVgx8Xo4veke815LJo3iYrdeNw <so> none
```

creates the upgradeable-loader ProgramData with no upgrade authority that
`attest_immutable_program` checks. `--bpf-program` would not: it uses the
non-upgradeable loader and has no ProgramData. `--reset` is required whenever
the `.so` changes, otherwise the program flags are ignored silently.
`program_data_hash` is computed over the ProgramData account bytes the
validator returns.

## 3a. V25: the escrow pays real accounts, and the terms pin the registry

Two production defects blocked any Solana leg with real DOM participants, and
both are closed additively (every V1 path and byte stays as it was):

- **Accounts.** The frozen V1 `validate_setup` requires the escrow recipient
  to be the beneficiary's `ParticipantId` and the refund recipient to be
  `refund_to`. A DOM participant id is a Blake2b digest with no Ed25519 key, so
  both claim and refund would pay addresses nobody controls. V25 follows the
  EVM pattern: `participant_binding::SolanaAccountBindingProofV25` is signed by
  the Solana account (Ed25519, strict) and by the participant's frozen Relay
  roster key (BIP340) over network, registry, route, settlement, session, frozen
  terms digest, roster snapshot, position, role, validity, genesis and escrow
  program. `bind_solana_session_v25` matches funder↔`refund_to` and
  beneficiary↔`beneficiary`; the refund goes to the funding account. The
  participant bundle carries the proofs in layout bit 4; the loader verifies
  them and validates the setup with `validate_setup_for_chain_profile_v25`.
  A leg without proofs keeps V1.
- **Profile hash.** The daemon admission and the route-time policy require the
  terms to pin the registry chain-profile digest; V1 setup validation required
  the operational adapter hash. V25 pins the registry digest (as XMR V24 does);
  the operational hash stays inside the DLEQ context only. F6 and F7 accept
  exactly one of the two rules, since the hashes are distinct domains.
- **Time policy.** `RouteTimePolicyV2::from_registry_dom_sol_v25`
  (`RouteTimeProfileV2::DomSolMainnetV25`, codec tag 2) admits DOM mainnet with
  both legs on the same Solana cluster; one chain observation serves both
  positions. The loader selects the constructor by the signed profile tag.
- **Leg authority.** `encode_solana_leg_authority_bundle_v25` writes the SOL
  authority bundle from the decoder's own wire type.

- **F6 claim profile (DOMF6A25).** A pre-signed DOMF6A07 plan cannot serve a
  policy-17 route: its downstream `LocalOrigin` source must commit the real
  native DOM claim template, which exists only after the bilateral bootstrap.
  The XMR enrollment (DOMF6A23) solves that for Monero only. The Solana
  enrollment signs roles and T; the decoder accepts it only for two Solana
  sessions with V25 account bindings, and the PreF6 policy is the DOM-mainnet
  one (it reads only the DOM clock). The enrollment constructor also
  refuses any non-policy-17 or non-conditioned-counterparty terms. At
  materialization, the runtime rechecks both V25 account bindings before it
  reads either bootstrap-derived template. After activation the run reads the
  downstream claim template hash from the Store
  (`bootstrapped_claim_template_hash_v25`, the same reconstruction the V20 gate
  binds) and materializes: upstream `VerifiedCounterpartyClaim` on the Solana
  chain (origin = the upstream DOM receiver, who publishes T by claiming the
  escrow; source commitment = the upstream Solana setup binding hash) and
  downstream `LocalOrigin`/`DomRevealsFirst` with the real template. The
  operator CLI `prepare-f6-artifact` emits it with
  `"claim_profile": {"profile": "solana_enrollment"}`.

  A25 requires the ordinary `X -> DOM -> Y` topology, in which the DOM roles
  swap between positions: the party that receives DOM upstream funds it
  downstream. `ComposedFinalClaimRolePlanV1::bind` admits exactly one T origin
  for the route, and with the upstream reacting to the Solana claim that origin
  is the upstream DOM receiver, which must therefore be the downstream DOM
  sender. The enrollment refuses any other terms before they are signed. The
  XMR scenarios keep their symmetric terms because their upstream source is
  `VerifiedDownstreamDomClaimV23`, which the Store admits only for a Monero
  `XmrBounded` leg — it is not available to a Solana leg. The Solana scenario
  fixture therefore inverts the upstream roles: the user funds the position it
  gives, and the solver funds and owns T on the position it delivers.

## 4. Building the escrow offline

`scripts/build-solana-program-v8.sh` uses platform-tools v1.48
(`$HOME/platform-tools`). Its `cargo` resolves `rustc` through `PATH`; under
rustup the program's `rust-toolchain.toml` then selects the stable toolchain,
which has no `sbf-solana-solana` target. Point `RUSTC` at the platform-tools
compiler explicitly:

```text
PT=$HOME/platform-tools
PATH="$PT/rust/bin:$PT/llvm/bin:$PATH" RUSTC="$PT/rust/bin/rustc" \
PLATFORM_TOOLS=$PT CARGO_NET_OFFLINE=true bash scripts/build-solana-program-v8.sh
```

Output: `programs/dom-solana-escrow/target/sbf-solana-solana/release/dom_solana_escrow.so`.
Do not run `cargo build-sbf` without arguments: it downloads platform-tools
v1.54.

## 5. The two-daemon scenario

Modelled on the XMR native daemon scenario, with both legs Solana (`[Sol; 2]`):

1. Start `solana-test-validator` with the escrow loaded immutable, then the
   peer signer owners (they must be listening before either daemon starts).
2. Run the Contracts bootstrap ceremony with the production `bootstrap-v13`
   producer (`xmr = false`); the validator's genesis hash goes into the signed
   registry, so the validator has to exist first.
3. Reuse the in-process DOM snapshot ledger (generic).
4. Counterparty deadlines are `TimestampSeconds`; route-time applies a ±3600 s
   Solana clock drift, so they sit well beyond the DOM `BlockHeight` deadlines.
5. Export both state directories and V4 secret streams, launch both release
   daemons, wait for both claims, reap, replay, reopen, and require identical
   economic state. Claims are confirmed by reading the escrow state PDAs.

The first scenario is claim + reopen. A refund scenario needs real wall-clock
waiting past `refund_after_unix` (plus the drift window); the test validator's
clock follows wall time and cannot be warped.

## 6. Risks only an execution can settle

- **Ordinary bootstrap stall.** The non-XMR ("ordinary") DOM bootstrap path was
  observed stalling in the early-share round: the staged envelope is committed
  to the relay and the scoped delivery page comes back empty
  (commits `4cb050d`, `08bddfa`). Every non-XMR leg uses that path, Solana
  included. The scoped durable inbox cursor work in progress upstream is the
  fix; this branch must be rebased on it before the scenario can pass.
- SBPF / feature compatibility between a platform-tools v1.48 build and
  validator 4.2.2, including the `multiply_edwards` curve25519 syscall.
- The exact byte range hashed into `program_data_hash` from the RPC account.
- Unfulfilled `expect(dead_code)` markers on Solana modules once they are
  exercised; only a build shows which.
- **Upstream claim race, cross-daemon.** Before exposing the upstream DOM
  claim, the F7 runtime re-observes the upstream Solana escrow and requires it
  still `Funded` with no revealed secret. The party that claims that escrow is
  the same party that owns T, so if it claims before the peer has materialized
  its upstream pair, the peer's observation fails with evidence that is not
  retryable and its upstream DOM claim can never be exposed; the DOM returns to
  the funder by refund. Inside one daemon the order is safe, because the
  counterparty and DOM children are materialized in the same call and the DOM
  exposure happens first. The same shape exists on EVM
  (`require_open_at`/`require_open_lock`), so it is not specific to Solana, but
  it decides this route: only an execution shows whether the ordering holds.
- **Two legs on one chain.** Both counterparty legs sit on the same Solana
  cluster and both DOM legs on the same DOM chain, while the public-secret
  router selects a source by the exposure's chain id and holds one external
  source (built from the upstream leg) and one DOM source (bound to the
  downstream claim). This plan never routes the other way, and a wrong route
  is refused rather than served, but there is no margin: a future plan that
  exposes on the other position would need a per-position router.
- **Operator input for a real deployment.** The Solana enrollment profile reads
  the signed `native-f6-observations-v23.bin` from the state root, as the XMR
  enrollment does. The scenario fixture publishes it for both actors; a real
  deployment has to produce and sign it with the bundle's status authorities.
