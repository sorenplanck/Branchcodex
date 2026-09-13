# Native daemon F6 producer compatibility — 2026-09-13

This is a failure diagnosis and correction record, not a mainnet-readiness or
completed-swap latency certificate. No L1 rule or network deployment changes.

## Executed evidence

GitHub run `34735383569`, commit
`b8c1420367ab777a6e0403fbb115d32684fa7745`, executed the real production daemon
and GPL dependencies against synthetic, isolated histories. All three economic
scenarios stopped with the public `f6` refusal before their required funding or
claim boundary. The original-store claim job was `103665773901`.

The retained synthetic fixture showed two distinct startup defects:

* Alice completed stage 10 and started stage 11, with one actuator lease and
  two parent session rows but no payout preparation. The configured basename
  was `native-contracts-bootstrap.bin`. The production mount deliberately
  selects private V13 custody only for `contracts-bootstrap-v13.bin`; otherwise
  it returns `None` for the externally prepared path. Both public files had
  identical 2,538-byte contents. Stage 10's public artifact authentication was
  therefore **not** evidence that private custody had been mounted.
* Bob completed stage 10 but did not start stage 11. Its fixture inventory
  writer used a little-endian version, a different layout without genesis and
  output index, and fixture-only checksum/custody domains. The production
  reader requires the original big-endian layout and production domains.
  The fixture's inventory evidence digest also included transient observation
  fields and used a different domain from the production consumer.

## Corrections and unchanged requirements

The fixture now selects the original reserved bootstrap file in the original
ceremony directory. It requires owner-only bounded reading and byte equality;
it does not rename, recreate, or overwrite a bootstrap to satisfy the mount.
The production basename guard remains unchanged.

The inventory producer now shares the production descriptor codec, bounded
reader, and custody associated-data derivation. The output index is derived
from the independently owned raw transaction. Its stable evidence digest uses
the same original production domain and all sixteen original public operands.
Computing a descriptor or digest does not mint an inventory/funding capability.
Actual ownership, sidecar authentication, quorum, absence, freshness, scope,
fees, finality and secret-store authentication remain required on every use.
The fixture's shared fee cap is the minimum of both negotiated caps.

Eight new boundary regressions reject the legacy wire, changed scopes and
bytes, unsafe file permissions, and altered custody/evidence bindings. They
also select and reopen the actual original private C/D owners on both legs;
the public-only copy remains outside that native custody path. The original
full daemon claim and non-cooperative recovery scenarios remain required;
these boundary regressions do not substitute for their economic outcomes.

## Performance evidence is separate

The unchanged native graph-template scenario passed in job `103665773962`
at commit `b8c1420` in 975.04 seconds, and in job `103667580870` at commit
`d5ae969` in 541.94 seconds. All prefix audits, original-store reopens and six
durable round replays remained selected. This is about 44% less wall time on
different GitHub runners, not a controlled same-host benchmark or a whole
swap. The additional caches memoize exact successful public equations only;
state, nonce, custody, time and complete transaction validation remain intact.

The native funding component also passed on `d5ae969` in job `103667580819`
(2,012.87 seconds), including deliberate reopen/replay coverage. Neither
component timing proves a normal daemon swap latency, and neither removes the
negotiated public-network confirmation or spendability requirements.

### Additional SharePoK equation memo

`dom-adaptor::verify_share_knowledge_v1` now retains only exact successful
public proof equations in a fixed, process-local 64-entry ring. Its original
mathematical body is retained unchanged as the private uncached verifier.
The key contains a separate domain, all 202 statement bytes, the authenticated
32-byte roster digest, the actual 33-byte share point, and the full 65-byte
proof. The roster digest is **not** contained in the 202-byte encoding; omitting
it would incorrectly reuse a result after changing another roster member.

Parsing and authenticated roster construction remain outside this memo. All
state/custody/nonce checks in its callers remain in place. Proof generation is
unchanged, and no secret share or private nonce enters the cache. There is no
heap allocation or lazy initialization in the memo; contention and poisoning
use the original verifier without waiting, and eviction is not a validity
limit. A false result or error is never remembered.

Seven separately selected regressions compare real proofs against the original
verifier, mutate every operand, test identical encodings under another roster,
exercise the actual point separately, preserve backend errors, exceed capacity,
and cover contention/poisoning. Their timing record includes one cold check plus
63 exact reuses versus 64 original verifications. Writing these tests is not
execution evidence; the new primitive and complete daemon scenarios must still
pass in CI before claiming any additional measured speedup.
