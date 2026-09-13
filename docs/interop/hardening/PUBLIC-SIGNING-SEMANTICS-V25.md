# Native signing verification reuse and remaining latency

This change is in the actual Store signing paths, not just a test fixture.
Six call sites in graph recovery, XMR funding and XMR claim now memoize the
unchanged deterministic `validate_signing_round_semantics_v23` result for exact
public prefixes of four, five or six messages. The frozen parent Store source,
message registry, nonce code, transcript rules and L1 remain unchanged.

## Exact inputs and unchanged authority

The key includes its own domain and graph/funding/claim origin pins; full chain,
session and purpose; ordered participant IDs, signing keys, directions and the
actual signing-index mapping; complete transaction bytes (including all proofs,
kernel signatures and offset), template hash, kernel index and optional adaptor;
starting/terminal/reveal transcripts, both sender sequence bases and every byte
of every original envelope. A candidate with an unsigned outer envelope cannot
alias a signed envelope. The bounded transaction encoder destructures all fields
exhaustively and has byte-equivalence tests against the original codec.

Only a successful public semantic result is retained: either no completed plain
signature or its public signature bytes. No private scalar, nonce, Store handle,
time observation, lease, custody state, revision or funding authority is cached.
Every caller still authenticates its origin, transport, physical/durable state,
current heads/successors and existing F7 conditions before producing authority.
The semantic verifier does not authenticate outer envelope signatures on its own;
the existing transport authentication remains mandatory outside this memo.

The cache is process-local and bounded to 64 entries with at most 32 KiB of key
bytes each. Errors never enter it. Ineligible or oversized input, allocation
failure, a busy mutex or a poisoned mutex goes through the original verifier.
No new protocol size limit or reduced verification mode is introduced.

## Evidence and limits

Eight additive regressions use real two-party Schnorr transcripts for Funding,
Refund, ClaimAdaptor and RefundAdaptor. They compare prefixes 4/5/6, one cold
plus 63 warm replays against 64 original replays, every public key component,
complete encoding, candidate/signature separation, errors, eviction, contention,
poison and over-bound fallback. The minimal public transaction is deliberately
only a semantic input, not a spendable transaction or manufactured Store/F7 grant.
The original full funding, claim, recovery, transport and restart tests remain.
All eight Rust regressions passed on published `77a4e0b` in GitHub preflight job
`103693319292`, through the closed `store-public-signing-semantics-cache`
selection: eight passed, none failed or ignored. That preflight job was **not
green overall**: two F6 selections reported eight `InvalidTerms` failures.
Their failures are separate from the successful semantic-verification evidence.

On that runner, 64 original verifications took 37,651–39,117 microseconds across
the four tested purposes; one cold verification plus 63 exact warm replays took
692–872 microseconds. These are public-semantic-only measurements, excluding
Store filesystem audits, ancestry reconstruction, network and blockchain waits.
They establish neither a complete lifecycle result nor a minutes-long swap.

The previous Round1 optimization has measured GitHub evidence: 5,797 to 1,937
microseconds for two actors' repeated first phase on `f418d20`. That approximately
3.9 ms saving is **not** a measurement of the whole Store audit or a swap.
This memo's timing label likewise explicitly excludes Store audits and swaps.

## Structural work still needed

The separately reviewed [session-head scan change](SESSION-HEAD-SCAN-V25.md)
addresses the quadratic records-directory item below, for bounded inventories,
without changing the generic scanner or the successor validator. The inventory
is fresh per load, not a retained authorization cache. Repeated ancestry work
and complete daemon timing still require separate evidence.

Static inspection identifies repeated work beyond the public equations:

- The real daemon resumes signing through `production_xmr_round_runtime_v12`.
  Resume, request and ingress operations invoke full transport auditing.
- The audit traverses rosters, origins, sessions and resource/outbound records.
  Repeated ancestry authentication reconstructs the same C/D output journals,
  offers, outputs and templates. Message-successor authentication repeats that
  ancestry for retained messages as the journal grows.
- `load_session_locked` in the frozen parent scans the global records directory
  on each call. A primitive memo does not eliminate those scans or repeated
  decoding/reconstruction.
- More specifically, `scan_lexicographic_including_exclusions` in `linux.rs`
  chooses one next name by independently rescanning and checking every entry.
  A stable directory with N entries therefore needs N+1 complete scans and
  N(N+1) entry checks. The call to `load_session_locked` for each of M roster
  entries multiplies this to at least M×N(N+1) record-directory checks, before
  message and ancestry work. This is verified loop complexity, not yet a measured
  timing attribution. The existing deterministic/no-directory-sized-allocation
  test is intentional; a replacement must retain bounded memory, ordering and
  protections against directory/file changes during callbacks.
- One edge's deliberate restart/replay fixture includes at least eleven full
  audits, including resource provisioning, ingress, six replayed messages and
  final resume. These required recovery checks are not removed.
- Identity/vault opening has a strong password KDF, but signers stay open during
  the six-message signing loop. Weakening that KDF would neither preserve custody
  nor explain the increasing per-turn time.

The next structural optimization needs operation-scoped, exactly bound public
dependency reconstruction, preserving fresh physical/head/transcript/successor
checks and never caching an authority verdict. Fixed calls in the frozen parent
limit a leaf-only explicit-context refactor; removing global scans needs a
separately reviewed integration design, not an unbounded cache of trusted state.
Old multi-hour logs do not quantify the current residual cost after successive
optimizations. Full real-daemon timing and recovery evidence remain necessary
before claiming a DOM↔XMR swap completes in minutes.
