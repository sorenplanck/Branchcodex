# V12 native family authority — implementation state

This is a new native profile, not a claim that all routes execute end to end.
Rust compilation and Rust tests were not executed in the editing environment.

## Implemented boundaries

- `VerifiedF7AnchorAuthorizationV12` holds an actual tagged external family and
  complete transaction identity. Solana retains all 64 signature bytes.
- EVM/Solana authorization consumes their concrete native observer results and
  runs the actual DOM funding scanner. XMR promotion consumes the stricter
  native DOM/XMR graph evidence.
- The Contracts Store's `f7_v12` module freezes native shared-output formation,
  complete role, exact templates and family-appropriate recovery evidence.
- `0x17` readiness is domain-separated from M.8 `0x11`. Both actual native
  identity signatures must be durably journaled before the Store authorizes
  the exact DOM funding template.
- Funding commits exact signed transaction bytes before publishing a submission
  capability. The record retains its original validation context and successor.
- Claim authorization consumes fresh F7 evidence and the exact Store funding
  commit. Issuance and consumption precede native ClaimAdaptor nonce entry.
- The six native nonce/partial messages are reauthenticated before aggregate
  pre-signature reconstruction and the separate V12 `0x0f` exchange.
- Reopening preserves the original claim transcript rather than substituting
  the mutable current signing transcript.
- XMR recovery scope is recovered from the actual gate and authenticated local
  signer role. DOM funding alone grants no daemon compensation action: that
  action additionally requires fresh native verification of the XMR funding.

## Explicit remaining boundaries

- The new V12 aggregate pre-signature does not implement the V12 `0x12`
  FinalClaim exposure, receipt, transport and submission lifecycle.
- XMR's C/D/refund-adaptor signing purposes require a complete native purpose
  profile and real auxiliary journals. Existing strict validators remain in
  force. Gate/observer implementations cannot substitute for that producer.
- **Production XMR startup must remain refused.** A plain compensation
  transaction pre-signed before XMR funding can be broadcast directly after
  its timelock. A daemon-only funding check cannot constrain an adversarial
  participant who already holds those bytes. The on-chain/economic design
  needs to address this before enabling the route.
- Fresh process-local observations are not a mainnet security proof. Reorg,
  disconnect, late broadcast and crash campaigns remain acceptance work.

## Native regression tests added

The Store child module contains five Rust tests for complete Solana identity
retention, strict record length/tag decoding, canonical Hash32 padding,
issuance-specific consumption, and bounded length/digest-overlap decoding.
They have been written but not executed here. They do not constitute an E2E
swap or acceptance of the 16-route objective.

## Retained inventory and interrupted publication

V12 final records live in the existing `artifacts` directory. The root keeps its
nine-object closed inventory. A separate bounded V12 census checks the six
exact lowercase session names, native decoders, ancestor records, native
signing bindings and complete pre-signatures, including pre-funding and
unconsumed prefixes. The namespace is limited to 1,536 finals and 64 MiB.

The existing retained-inode staging recovery handles empty/proper-prefix
writes; complete staged records must pass their exact typed decoder. A durable
funding commit without its successor is resumed from its exact retained bytes.
An issuance without consumption can be resumed only with fresh native anchors.
Native signing bindings are audited at their immutable historical start, so
later lifecycle transitions do not retroactively invalidate their history.

Four additional Rust regressions exercise native reopening: all 105 byte cuts
of a consumption publication, orphan final rejection without mutation, wrong
kind/session staging rejection, and wrong-directory rejection. These tests are
written, not executed in this environment.

XMR readiness now binds both the validated setup digest and exact funding
transaction ID. Recovery and claim consumers require both, preserving this
identity through native DOM/XMR evidence promotion. This does not establish the
missing pre-funding refund-share curve binding or solve the manual compensation
attack described above. Production startup remains closed.
