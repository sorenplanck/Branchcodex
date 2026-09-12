# Native DOM refund consumption and bounded revalidation

This is an interop consumer. It changes neither L1 consensus nor network
activation and performs no deployment. Production readiness still requires
executing the integration scenarios; implementation is not test evidence.

## Economic boundary

The native XMR graph's public `D -> refund` is not a legacy plain refund.
The plain-refund Store guard continues to reject Monero. The DOM child instead
uses the same retained recovery driver and a fresh `VerifiedDomRefundSecretV11`
to authenticate the actual canonical refund against its Contracts gate,
graph, funding transaction, session, chain, terms and negotiated finality.

`DomContractsActuatorV1` records the completed native custody mirror, exact
coordinator locator and canonical finality. Dispatch/reconciliation do not
submit another DOM transaction. This consumer never calls the token's scalar
accessor. DOM compensation remains a different outcome and cannot enter this
path or stand in for an XMR refund.

Reopening reinstalls the exact authenticated recovery driver in the shared
Contracts owner. Recorded locators alone do not grant fresh economic finality.

## Forks and replay

The revalidator decodes only the native `DOMXRFIN11` refund checkpoint: version,
kind, scope, digest, policy, exact depth and consecutive canonical tail are
checked. It does not invoke the incompatible plain-refund checkpoint decoder.
The selected DOM scanner then revalidates the complete graph and checkpoint
against the current canonical chain. Its exclusive results are:

- Still final: a fresh native U token; the original durable evidence identity
  is preserved when the inclusion is unchanged, even if the tip advances.
- Invalidated: a fresh typed proof binding the old evidence, actual common
  ancestor, removed depth and current tip. The actuator compares it to the
  original fenced journal before recording the invalidation.

Depth loss alone is pending, not proof of removal. Missing transactions in an
unchanged block are inconsistent evidence. A fork exceeding the negotiated
reorganization window fails closed. Crash recovery replays the exact durable
invalidation; reinclusion requires new canonical finality before reactivation.

## Bounded work

Each scanner observation is bounded by its caller's remaining lease, capped at
60 seconds in the DOM child. Store/custody preparation consumes that budget;
each RPC page uses the remaining deadline. Completion after the deadline does
not issue a capability. Existing observation APIs retain their signatures and
use a 60-second observation bound.

A maximum of four in-memory graph/checkpoint scopes retain authenticated scan
prefixes with LRU eviction. Every reuse revalidates the canonical cursor;
anchor forks reset the prefix, malformed evidence discards it, and partial
progress never asserts absence or finality. Freshness is checked again at the
actuator boundary. The recovery driver also carries one absolute deadline
from before Store preparation through both observations and the actual DOM
submission. HTTP timeout is the lesser of its configured bound and the time
remaining; an expired deadline starts no POST. An uncertain or late response
does not erase the retained exact attempt or establish non-externalization.
A definite admission is durably recorded, but no late success capability is
returned. Synchronous durable filesystem I/O cannot safely be cancelled:
finishing it late blocks further sends/grants rather than pretending it met a
hard real-time filesystem limit.

Written regression coverage includes native inclusion identity and policy,
checkpoint mutation, bounded forks, reinclusion, capability expiry, cache
isolation/reset/limits and remaining-lease budgets. The real daemon refund
scenario is the integration consumer; these unit checks do not replace it.
