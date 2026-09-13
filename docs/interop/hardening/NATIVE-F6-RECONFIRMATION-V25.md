# Native F6 reconfirmation work and remaining integration

The legacy relation cannot construct a normal post-enrollment request: the RFQ
identifier hashes its composition identifier, the composition hashes the original
terms, and legacy adapter authentication requires those terms' intent identifier
to equal the RFQ identifier. No original terms or negotiated deadlines are
rewritten to manufacture that cryptographic fixed point.

The V25 public preparation records original intent and RFQ identifiers separately
and commits the actual `ComposedBindingV2`, both full original terms, ordered
position, wire/roster scope, RFQ, quote and reservation identifier. Preparation is
not authentication, consent, a reservation certificate or a funding grant.

`NativeAcceptanceV25` is an explicitly versioned public ACCEPTANCE payload. Its
canonical bytes bind a literal V25 domain, the prepared record digest, full F6 V2
terms and the initiator. The old decoder rejects it. A future receiver must verify
the **original complete signed Relay envelope**; stripping the wrapper cannot
create an authenticated inner delivery. Local adapter evidence alone is
insufficient: that evidence is outside the V2 terms hash signed by the initiator.

The separate initiator receiver owns only its distinct receipt/binding mirror,
portable signed candidate book, RFQ-scoped time and adapter terms source. It has
no solver inventory, lease, reservation signer or terminal-release authority.
Its currently implemented receive path remains strictly legacy V2. It is not yet
selected by the production actor factory.

Written additive regressions cover eight public-record cases (including actual
signed temporal policy/evidence, consumed time capability and real composition),
nine public-acceptance codec cases, and seven initiator boundary cases. These are
not proof of an accepted native negotiation or a completed XMR swap. They have
not yet run in GitHub at this handoff.

Still required before native F6 is operational:

- Native adapter-terms preparation with all original cross-object guards and
  explicit V25 opt-in, leaving legacy identity semantics unchanged.
- Actor-specific factory/activation, without assigning solver inventory powers
  to the initiator.
- Durable production RFQ/quote/selection/acceptance producer and authenticated
  replay of local outbound envelopes.
- Original V25 signed acceptance validation and immutable profile/record/envelope
  recovery, not merely a local evidence digest or decoded V2 terms.
- Economic-ready projection and real solver reservation commitment, followed by
  the existing current-time, funding, custody and claim/recovery authorities.
- End-to-end daemon evidence for claim and noncooperative recovery.
