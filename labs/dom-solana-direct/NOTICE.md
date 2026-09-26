# Provenance of the DOM-side modules in this laboratory

`src/native_dom.rs`, `src/dom_joint.rs` and `src/dom_reserve.rs` were copied,
unmodified except where noted below, from the DXP1 laboratory the operator is
developing at `labs/dom-xmr-direct/clsag-lab` in their own working copy, with
their explicit authorization to copy anything from the DOM side of that
environment into this one. Nothing was created or changed there.

Those three modules contain no Monero, CLSAG or XMR-specific code. They are the
asset-neutral DOM side of a swap leg:

* `native_dom.rs` — freezes a one-input/one-output DOM transaction (plain, or
  height-locked for the refund), computes the native kernel message, binds an
  adaptor pre-signature, completes the claim with the revealed secret and
  extracts that secret back out of a published claim.
* `dom_joint.rs`  — 2-of-2 additive signing of that kernel with two bound
  nonces and possession proofs, ending in a `DomClaimOffer`.
* `dom_reserve.rs`— the jointly-owned DOM reserve: shared spend key, joint
  Pedersen commitment and a two-party bulletproof over it.

The only edit applied to the copies is in `dom_joint.rs`: the `compile_fail`
doctest referenced the source crate by name (`dxp1_clsag_lab`) and now
references this one (`dom_solana_direct_lab`), so the test still asserts that a
signing round cannot be reused.

Everything else in this directory is written for the Solana leg:
`src/time_bounds.rs`, `src/condition.rs`, `src/leg.rs`,
`tests/support/solana_cluster.rs` and `tests/solana_leg_live.rs`.

`tests/support/dom_regtest.rs` is also copied from that laboratory and adapted:
the Monero recovery-window types it took as parameters are replaced by this
lab's Solana escrow window, and the evidence record names the Solana leg. Its
DOM node handling — genesis, mining, admission, the funded joint reserve, the
height-locked refund and the abandonment paths — is the operator's.

The warnings in those modules' own headers still apply and are not weakened
here: they are experimental, they do not authenticate identities or a fair
reserve setup, and they hold no durable anti-rollback state.
