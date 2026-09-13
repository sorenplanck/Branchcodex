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
terms and the initiator. The old decoder rejects it. The native receiver verifies
the **original complete signed Relay envelope**; stripping the wrapper cannot
create an authenticated inner delivery. Local adapter evidence alone is
insufficient: that evidence is outside the V2 terms hash signed by the initiator.

The separate initiator receiver owns only its distinct receipt/binding mirror,
portable signed candidate book, RFQ-scoped time and adapter terms source. It has
no solver inventory, lease, reservation signer or terminal-release authority.
It now has a closed choice of legacy authority or concrete native proposal owner,
with a distinct original V25 acceptance branch. It is not yet selected by the
production actor factory; the live negotiation remains incomplete.

The native proposal owns the actual adapter faces and frozen composition. It
preserves all original scope/economic/refund/time guards, replacing only the
impossible intent/RFQ equality with an explicitly versioned full reconfirmation
record. It never implements the legacy authenticated-terms trait. A successful
proposal retains its owners in process; exact repeated access rederives all
public inputs. A restarted process must reacquire the actual owners, not decode
an authority from a proposal receipt. The complete proposal is immutably retained
in a separate namespace; legacy terms receipts cannot opt into native consent.

Both native receivers use distinct physical log and receipt bindings, separate
from each other and from both legacy roles. Opening an existing or interrupted
native store with a legacy source therefore refuses before replay/activation.
The source is not merely a process-local flag that can downgrade persisted state.

Native acceptance still requires the original current candidate/time checks,
exact deterministic Selected snapshot, and complete outer terms/record equality.
The solver's original Bound/inventory-commit path runs only afterward. Retaining
the original accepted envelope identity happens after its Applied receipt;
byte-exact delivery retry repairs that crash boundary. The initiator owns only
a local mirror, never the solver inventory capability.

An explicit solver post-commit confirmation binds the full accepted V25 payload,
original acceptance envelope/sequence, complete wire, Selected snapshot and real
committed state/evidence/revision/fence. Its producer takes no caller-shaped
commit fields and requires the real committed capability and native receipt.
It travels as a versioned QUOTE confirmation under the unchanged Relay role
policy: the solver cannot emit ACCEPTANCE. The initiator verifies the original
solver envelope and retains it; a write before its Applied receipt is not a
completed durable agreement. This is historical signed agreement evidence, not
a remote inventory capability, current-time proof, Ready vote or transport ACK.

The native execution accessor also rechecks current status/time, exact quote
capability and its original accepted ledger evidence. That accessor still needs
to be connected to the live funding gate; adding an accessor is not a claim that
every existing funding caller already uses it.

Written additive regressions cover eight public-record cases (including actual
signed temporal policy/evidence, consumed time capability and real composition),
nine public-acceptance codec cases, and seven initiator boundary cases. These are
not proof of an accepted native negotiation or a completed XMR swap. Those
previous 24 regressions passed on `f418d20` in
[preflight 103687850889](https://github.com/sorenplanck/Branchcodex/actions/runs/34743791959/job/103687850889).
New proposal/receiver/certificate regressions include genuine signed temporal
composition and wallet payout construction, real signed Relay/inbox delivery,
physical store reopen/refusal, malformed messages and immutable receipt recovery.
The new tests have not yet executed at this handoff. In particular, the positive
proposal receipt-reopen test keeps its original owner alive; it is not evidence
of reacquiring that same wallet/adapter owner after process exit.

Still required before native F6 is operational:

- Actor-specific factory/activation, without assigning solver inventory powers
  to the initiator.
- Durable production RFQ/quote/selection/acceptance producer and authenticated
  replay of local outbound envelopes.
- Exact post-commit quote confirmation publication and local outbound replay,
  without treating it as a new candidate or silently renewing a changed fence.
- Economic-ready projection into actual funding signing and dispatch, followed
  by the existing current-time, funding, custody and claim/recovery authorities.
  Claim/refund/recovery and exact signed-byte retransmission must not depend on
  the availability of a fresh negotiation/funding grant.
- Positive complete receiver/Bound/real-inventory-commit/certificate validation,
  and actual same-owner physical restart evidence.
- End-to-end daemon evidence for claim and noncooperative recovery.
