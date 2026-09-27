# BTC ↔ DOM ↔ SOL: what the two-leg hub needs from this leg

Written 2026-09-27, after the Solana↔DOM leg went green. No code accompanies it,
by request: the DOM-side modules this laboratory copied are being changed in
another working tree, and touching the same files from two places is the problem
this document exists to avoid.

## 0. The question, and why it is already answered

A route that moves BTC to SOL is not one transfer. It is two legs — BTC↔DOM and
DOM↔SOL — sharing one DOM hub. Each leg, on its own, is what this laboratory now
settles: a jointly owned DOM reserve spent by an adapted claim, a counterparty
lock, one 252-bit scalar with a face on each curve, and two deadlines ordered so
that whoever must act second has the later one.

The obvious way to join two such legs is to condition all four locks on the same
scalar. **That is not the design this project chose**, and it is worth reading why
before anyone builds it that way.

The decision is `docs/specifications/design/DR-PRIV-001-leg-unlinkability-blinding-and-a2lplus.en.md`,
dated 2026-09-02, and it is explicit about its own standing:

> Status: **DESIGN RECORD / NOT IMPLEMENTED / NOT NORMATIVE / UNSIGNED**

It approves nothing until ratified and signed. But it is not idle either: Level 1
of it exists in the tree as `crates/route-composer/src/leg_blinding.rs` and
`ComposedBindingV3`, so the record is behind the code rather than ahead of it.

## 1. What it decides

**Level 1 — per-leg witness blinding.** One route stops carrying one witness.
Each leg carries its own, and the two are joined by a secret integer offset δ:

```
s_downstream = s_upstream + δ            translate_witness_v1
D            = δ · G                     prove_offset_relation_v1  → (D, proof)
S_downstream = S_upstream + D            verify_offset_relation_v1
```

The point relation is publicly checkable; δ is not public. The Schnorr
proof-of-knowledge of δ writes DLEQ role byte `4`
(`ROLE_LEG_OFFSET_RELATION`) into its transcript, drawn from the same closed
registry as roles 1–3, and its nonce is derived RFC-6979 style so a broken RNG
cannot leak δ through nonce reuse.

What this buys: an observer watching both chains sees two unrelated locks. What it
costs: the party holding δ is the only one who can carry a revealed upstream
witness across to the downstream leg — which is precisely the hub's position, and
is the reason the hub is a hub.

**Level 2 — solver-blind puzzles, A²L+ shape.** Removes the solver's *own* ability
to link the two legs it serves. The record restricts its first version to routes
whose two legs share a curve, and the curve in question is the one each leg's
counterparty lock is verified on, not DOM's. DOM signs on secp256k1 throughout;
this leg's condition is checked on ed25519 by the curve25519 syscall.

So a route qualifies when both counterparty locks sit on the same curve — this leg
paired with a Monero leg would, since `CrossCurveSharedSpend` opens an ed25519
spend key, and a Bitcoin leg paired with an EVM leg would, both being secp256k1 —
and does not when they differ, which is the case for BTC↔DOM↔SOL. Level 2 is
therefore not a near-term property of that particular route, and saying so now is
cheaper than discovering it later.

On the Bitcoin side this document claims only what its own sources say:
`crates/adapters/btc` describes a Taproot contract with a MuSig2 2-of-2 adaptor,
which is secp256k1. Which `LockMechanism` byte that leg carries is not recorded in
those crates and is not asserted here; it belongs to whoever owns that leg.

## 2. What this leg must accept in order to participate

Three things, all small, and the first is already possible.

**(a) Take the witness instead of minting one.** Today `SolanaLegV1::establish`
calls `prepare_route_secret`, which generates a fresh secret. Under Level 1 the
witness is either derived from the route seed (`derive_leg_witness_v1`) or is the
*translation* of the other leg's witness by δ. The leg must therefore be able to
be established from a witness it is handed.

The hook exists and needs no new cryptography: `SolanaRouteSecret::restore(witness_le,
proof, rng)` already rebuilds a session from a supplied witness and refuses one
that does not reproduce the registered public claim. What is missing is only an
entry point on `SolanaLegV1` that uses it — the same shape as `EstablishedLegV1::resume`,
which already does exactly this for a restart.

Constraint to respect: `derive_leg_witness_v1` produces values below 2^251 and a
translated value may use the extra bit, so up to 2^252. This leg's on-chain check
is `little_endian[31] & 0xf0 == 0`, i.e. below 2^252, so both fit. A witness at or
above 2^252 would be refused by the escrow, not by the client, which is the right
place but an expensive one to find out.

**(b) Verify the relation against its own claim point.** A leg receiving a
translated witness should check `S_this = S_other + D` with
`verify_offset_relation_v1` before it funds anything, rather than trusting that
the hub translated correctly. The leg already refuses an opening that does not
open both of its faces; this is the same discipline one level up.

**(c) Take its deadline from the route, not from itself.** `LegScheduleV1` in this
laboratory enforces the per-leg inequality — the second claimant gets the later
deadline — and chooses one side freely. A route needs more: the outer leg must
dominate the inner one on both clocks. That policy already exists as
`route_composer::ComposedWindowPolicyV1`, with a `hub_margin` in DOM blocks and a
`counterparty_margin` in the counterparty clock's seconds. Composition is
therefore: the route fixes the two margins, and each leg's schedule is derived
inside them instead of picking its own relative deadline.

## 3. What must not change, and why

The escrow program, the condition check on both curves, the observation path, the
evidence records and the per-leg inequality are all unaffected by leg blinding. The
blinding is arithmetic on the witness *above* the leg: the leg still receives one
scalar, still proves one DLEQ under role 3, still verifies `s·G_ed == P` on chain.
Anything that changed inside the leg to accommodate the hub would be a sign the
layering is wrong.

One consequence worth stating plainly: `ROLE_SOLANA_CONDITION_LOCK = 3` stays as
it is. The record says so — "Roles 1–3 are unchanged by the per-leg witness split
— each leg still proves its own witness" — and the role registry is closed, so a
leg that wanted a new byte would be a ratification line of its own.

## 4. What is open, and whose call it is

- **Does DXP1 keep DR-PRIV-001?** The record and its implementation belong to the
  current composed-route design. If DXP1 replaces that spine, the question is
  whether leg blinding is carried over as a property or re-derived. Either way the
  three items in §2 are the same, because they are about the leg, not the spine.
- **Ratification.** The record is unsigned, and unsigned bytes grant no authority.
  Level 1 running in `route-composer` does not settle that.
- **Who holds δ, and what happens when the hub vanishes mid-route.** The record
  freezes constructions and state machines; the operational question of a hub that
  stops answering between the two legs' claims is a recovery question, and this
  document does not pretend to answer it.

## 5. What this document is not

It is not a plan to edit anything. It reports a decision that already exists,
measures this leg against it, and names the three points of contact. The merge of
the two working trees, and the timing of it, stay with the operator.
