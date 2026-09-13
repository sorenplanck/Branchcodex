# Bounded, fresh session-head collection

## Scope and cost

The production `ContractsSessionStoreV1::load_session_locked` collector does not
depend on filesystem enumeration order: it already sorts decoded session records
by revision before checking the complete chain of successors. Its former generic
lexicographic scanner nevertheless reopened and checked the entire global records
directory to select each next name. For a stable directory of N entries, that is
N+1 scans and N(N+1) physical entry checks per head load. Transport audits call
this loader repeatedly, including from the real daemon's signing resume path.

The first integration used only this read-only collector. The subsequent
message-scan integration below adds three reviewed read-only consumers; all
remaining generic lexicographic consumers and their constant-memory algorithm
stay unchanged. The new path uses three fresh physical scans and a bounded, sorted
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

## Message-prefix and transport-sequence integration

The native graph commitment-prefix and signing-round readers now use one private
`collect_untrusted_messages_v25` helper. It preserves the original physical
checks before filtering by session, bounded reads and canonical transport-record
decoder. It sorts the collected records by lexical filename before returning
them. The complete original code after collection remains unchanged in both
readers: identity authentication, revision sorting, exact successor, transcript,
purpose, sequence and public-signing-semantics checks still run. The helper
does **not** return authenticated records or a capability, and never deduplicates
records. Its added physical inventory is bounded; the decoded-record vector has
the same scope and limits as the former collectors.

`transport_sequence_at_revision` also uses the bounded scanner. This is a shared
Store reader used beyond XMR, including funding, claim and refund paths. Its
original session/sender filter, inclusive revision bound, decoder, sequence sort,
zero origin, gap/duplicate refusals and final conversions remain unchanged.
It is still only a sequence reader, not independent transport authentication.
`next_transport_sequence` and other generic scans are not changed.

For one complete three-edge graph reconstruction, source inspection finds six
global message collections and twelve revision-bounded sequence scans. On the
bounded path each physical inventory now takes three passes instead of M+1
passes over M entries. This removes a multiplicative filesystem cost without
skipping any existing signing or recovery audit. These counts are a source-level
cost model, **not** a measured speedup or proof of a minutes-long swap. Remaining
generic scans, cryptographic work, RPC and negotiated confirmation requirements
still need complete runtime timing evidence.

The seven `store-graph-message-exact-scan` regressions compare original lexical
collection with the new helper over real retained directories and record codecs:
shuffled records, foreign and equivocation filters, invalid physical entries,
corruption, reopen/mutation, exclusion identity, and non-deduplication. Their
deliberately unsigned envelopes prove only physical collection behavior;
successful graph authentication remains the responsibility of the unchanged
signed graph scenarios. Concurrent multiple corruptions may change the first
read error, but never become success. No filesystem-transaction guarantee is made.

The six `store-transport-sequence-exact-scan` regressions use the existing real
early transport ingress and signed envelopes, with an independent copy of the
original lexical sequence reader. They cover live append, zero and inclusive
revision bounds, shuffled publication and complete Store reopen, session/sender
scope, gaps, duplicate embedded sequence numbers and tampering even outside the
requested revision cutoff. The physical scanner's nine negative regressions
remain mandatory as well.

The existing unsigned graph-candidate test contained an obsolete assertion that
DSC1 type `0x18` was unregistered. Its current 32-byte registration is now checked
exactly, alongside stronger real refusals: a validly identity-signed envelope
cannot enter through generic derived transport, and no graph signing request
can be issued without native context. Both refusals are checked again after
Store reopen, with the head and complete physical tree unchanged. Conflict and
tamper checks remain. `store-unsigned-graph-candidate-refusal` requires this same
test; no test was removed, ignored or converted into compilation-only evidence.

Local non-cryptographic checks for this message-scan integration passed: 35
closed-CI-selection checks, 53 policy/guard regressions (including the full
repository contract), formatting for all eight affected Rust files, whitespace
validation and the unchanged frozen-consensus baseline. These results do not
count any of the new Rust regressions as executed; those await GitHub evidence.
