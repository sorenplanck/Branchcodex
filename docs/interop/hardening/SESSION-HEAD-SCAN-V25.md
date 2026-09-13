# Bounded, fresh session-head collection

## Scope and cost

The production `ContractsSessionStoreV1::load_session_locked` collector does not
depend on filesystem enumeration order: it already sorts decoded session records
by revision before checking the complete chain of successors. Its former generic
lexicographic scanner nevertheless reopened and checked the entire global records
directory to select each next name. For a stable directory of N entries, that is
N+1 scans and N(N+1) physical entry checks per head load. Transport audits call
this loader repeatedly, including from the real daemon's signing resume path.

Only this read-only collector uses the new private scanner. All generic
lexicographic consumers, their ordering and their constant-memory algorithm stay
unchanged. The new path uses three fresh physical scans and a bounded, sorted
inventory, with O(N log N) in-memory comparisons instead of quadratic filesystem
work. This is a complexity reduction, not an end-to-end latency measurement.

## Integrity before speed

The inventory contains exact names, retained `NodeIdentity` values, and the
original exclusion decision. It is local to one call and discarded afterwards:

1. Preflight validates every physical entry and captures the bounded inventory.
   Excluded names must match their retained identities too. No consumer callback
   has run at this point.
2. Collection requires exact membership and identity, visits every captured entry
   once, and invokes the read-only collector once per non-excluded entry.
3. Postflight independently checks exact membership, identity and coverage again.
   The retained directory's current named identity is revalidated before success.

Additions, deletions, replacements and unsafe metadata observed in these passes
cannot be silently accepted as the inventory originally read. There is no timestamp,
directory digest, cached head or cached authorization in this decision. The same
registered-name, owner, mode, file-type, hardlink, bounded-file-read and named-file
identity requirements still apply. The collector still parses the canonical
record, binds filename/session/revision and refuses invalid foreign entry names.
Recovery projection, revision sorting, revision-zero requirement, gap detection
and every exact-successor check remain in the original loader.

The optimized inventory is limited to 16,384 entries and the existing registered
component length limit. Allocation/capacity fallback takes the **unchanged**
lexicographic path before any collector callback; this is not a new protocol or
directory-size refusal. A physical error, identity mismatch or changed inventory
is an error, never a reason to fall back and forgive the observation. The bounded
inventory adds memory for names and metadata, not secrets or trusted state.

The Store operation mutex and retained cooperative file lock remain required.
This scanner is not a filesystem transaction or a generic replacement for
callbacks that mutate the namespace. An uncooperative same-uid process can race
any final check; transient changes between observations are not claimed detectable.
Content checks still use the original bounded read and canonical successor
validation. Concurrent multiple defects may change which refusal is observed
first because payload reads are unordered; failures are never converted to
successful heads. No atomic-snapshot guarantee is introduced.

## Verification and limits

Additive tests cover the physical scanner, exact inventory mutation refusals,
capacity fallback, and real Store session heads, including corrupted histories
and recovery projection. Existing scanner, custody, transport, funding, claim and
restart tests remain mandatory. Their closed CI selections require named tests
and nonzero successful results; compiling the crate alone is not evidence of
passing these regressions.

`store-session-head-exact-scan` requires eight Store regressions;
`store-readonly-physical-inventory` requires nine filesystem regressions.
Test-only, opt-in thread-local counters check three actual physical passes of
64 entries and exactly one collector callback per entry. They do not instrument
or modify the original scanner, and do not label its source-derived N(N+1)
complexity as a measured syscall count or measured swap speedup.

The Store source's F1 pin requires a separate exact-source review and re-freeze;
the Sponsor/strict-purpose bodies and authority inventory must not change. See
`../XMR_RECOVERY_WITHOUT_L1_REVIEW.md` for that review record. L1, consensus,
confirmation policies, negotiated availability, nonce custody, and signing
authorization are outside this optimization and unchanged.

At implementation handoff these new Rust regressions have not been run locally;
GitHub is the execution environment. No reduced verification mode, skipped
recovery audit or shortened security window is used. Neither this change nor a
primitive timing result establishes that a mainnet swap completes in minutes:
full daemon, restart, recovery and end-to-end timing evidence is still required.
