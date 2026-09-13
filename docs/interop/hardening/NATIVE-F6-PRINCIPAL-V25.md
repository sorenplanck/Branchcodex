# Native DOM/XMR principal ingress, without a consensus change

## Observed failure

Run `34739866064`, job `103677628901`, commit `0d079731` reached actual
`dom-interopd run` startup after original private custody mounted. The retained
public actuator databases contain six sessions and four payout preparations
and four payout evidences **per actor**. Startup nevertheless selected the
ordinary parent-session C0 payout for both actors. Native XMR principal payouts
belong to their policy-derived payout session; the DOM payer is not the DOM
principal beneficiary. Importing the peer wallet, creating another arbitrary
C0, or weakening `AdapterAuthenticatedRefundFaceV2::from_dom` is not a fix.

## Implemented ingress

- The original local ceremony journal plus its exact retained graph packet
  scopes local proof provenance. A peer proof also requires the opaque
  candidate emitted by the existing authenticated Noise graph exchange.
- Only `ClaimPrincipal` belonging to the policy's XMR funder and the settlement's
  DOM beneficiary produces the new opaque token. Original graph and payout
  decoding, range proof, ownership proof, chain, direction and roster checks
  remain mandatory. Public bytes alone cannot construct this token.
- The native terms owner revalidates that proof and the composition, RFQ and
  signed DOM deployment. Its distinct `DOM-XMR/V25` canonical record contains
  the complete public policy and proof, not a local wallet revision or a
  local/remote provenance flag. Its revision is the authenticated registry
  epoch. It is not a signing, custody, finality or funding capability.
- A move-only deferred slot holds each native terms owner. Both RFQs and both
  slots must be ready before the F6 factory obtains an inventory lease or
  creates a lazy store effect. A missing peer principal preserves the exact
  factory and RFQs as `Awaiting(AdapterTerms)`; a mismatch still fails closed.
- The peer graph is retained under `xmr-peer-graph-offer-v25` in the original
  scope-bound journal before publishing the slot. Different bytes cannot
  overwrite it, including across concurrent inserts. Generic runtime public
  writes are forbidden for this key. Restart revalidates that original record
  before applied-F6-history replay. No history or peer custody is fabricated.
- Exact retransmission is idempotent even after slot consumption and never
  regenerates a consumed owner. Existing generic DOM/BTC/EVM/Solana paths and
  the legacy DOM payout constructor remain unchanged.

The journal audit admits this one additional public record; individual and
aggregate byte limits remain unchanged. No L1, consensus rule, block finality,
negotiated availability, deadline, deployment or fund transfer is changed.

## Validation and timing claims

Fifteen dedicated regressions cover real public principal proofs and scope
mutations, immutable one-shot publication, and activation waiting versus hard
refusal. The provenance tests reopen the original small native ceremony,
prepare each actor's own real wallet proofs, compare the local/peer tokens and
construct their actual native terms owners. They exercise a candidate seam
inside the Noise boundary, not a socket handshake. A different independently
valid beneficiary proof is refused before and after restart without replacing
the retained packet. The full RFQ-late `into_face` bilateral comparison remains
part of the complete daemon scenario, not asserted by these unit tests.
Local work is limited to source checks, formatting and the mocked Python CI
dispatcher tests. Rust and cryptographic execution belong to GitHub.

The five previously published public-equation optimizations already passed
their real-vector and uncached-verifier comparisons in GitHub. The sixth,
SharePoK, was published as `38b9d1f2` and is independently selected by CI.
These memoize only exact successful public mathematics, never F6/F7 grants,
private nonces, chain observations or time authority.

The unchanged native graph/template scenario previously improved from
975.04 seconds to 541.94 seconds on separate GitHub runners, retaining all
prefix audits and durable replays. This is **not** a measurement of a complete
mainnet swap. A complete real-daemon success and recovery run must still
validate this ingress; no minutes-level end-to-end or mainnet-ready claim is
made here. Calculation, transport and actual network confirmation waits must
be reported separately rather than reducing the required confirmations.
