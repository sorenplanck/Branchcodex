# DOM↔XMR recovery with unchanged L1 — design review

Status: operator-authorized design direction; implementation incomplete, no funding permission.
Date: 2026-09-10. The operator prohibits changing L1.

The operator subsequently authorized ordinary DOM compensation even if the
original XMR remains locked, under the stated obligation for the honest party
to act within the recovery window. This approves the design direction, not
deployment, live funds, or a claim that the protocol is already proven.

## What the existing native graph actually guarantees

Use role names rather than Alice/Bob: **D** deposits DOM and owns refund
witness U; **M** deposits XMR and owns claim witness T. XMR is locked to the
sum of the two spend shares. C is the shared DOM funding output and D_out is
the cancelled DOM output (not the participant D).

| Edge | Input → recipient | Earliest height | Witness exposed |
| --- | --- | --- | --- |
| claim | C → M | no native lower lock | T, with the claim adaptor |
| cancel | C → D_out | Hc | none |
| refund | D_out → D | Hc | U, with the refund adaptor |
| ordinary compensation | D_out → M | Hp, where Hp > Hc | none |

These are the legacy graph's transaction shapes, not currently admitted
production signing paths. Production wallet admission and new funding remain
refused; V23 mathematical assembly from native partials is now available.

The local claim/refund windows are issuance/broadcast policy, **not native
transaction expiry**. A previously signed claim remains individually valid
after Hc; refund remains individually valid after Hp. Conflicting spends cannot
both consume the same canonical UTXO, but that does not erase a signature that
has been disclosed. Extracting U requires the refund signature, not a block or
a finality proof. Native validation alone also does not prove UTXO availability.

Evidence in `crates/dom-scriptless-crypto/tests/xmr_recovery_graph_v11.rs`:

- `v22_local_claim_deadline_does_not_expire_a_signed_claim` checks individual
  validity of conflicting claim/cancel transactions beyond the local deadline.
  Its ordinary test claim signature isolates transaction validity; it does not
  exercise production claim-adaptor admission.
- `v22_refund_witness_is_extractable_after_local_deadline_without_confirmation`
  checks refund/compensation validity at and after Hp and extracts U from the
  signature alone. It does not execute a live mempool race.
- `v13_legacy_signed_compensation_remains_spendable_without_xmr_and_must_not_be_newly_armed`
  already demonstrates that an ordinary compensation transaction requires no
  Monero funding evidence under DOM consensus.

## Availability is distinct from counterparty cooperation

The objective requires recovery when the counterparty disappears, restart
recovery, no premature secrets, and formal properties under explicit premises.
It does not establish an unlimited outage allowance for the honest participant.
That distinction must be made explicit, not converted into an undocumented
promise or treated as authorization to modify consensus.

The [COMIT protocol description](https://comit.network/blog/2020/10/06/monero-bitcoin/)
uses cancel, adaptor refund and ordinary punish transactions. Its punish path
compensates the Monero depositor if the Bitcoin depositor remains inactive past
the second deadline. The description explicitly requires the first depositor
to act before that deadline to avoid punishment. This is a protocol reference,
not a security proof for DOM or for the current daemon.

Candidate analysis for an ordinary-compensation DOM construction:

| Counterparty behavior | Required honest action | Unproven obligation |
| --- | --- | --- |
| M never deposits XMR and disappears | D confirms cancel then refund before Hp | A bounded outage/inclusion budget leaves time for both finality steps |
| D disappears after XMR funding, without releasing claim material | M confirms cancel then ordinary compensation | Compensation value/fees satisfy the agreed economic recovery criterion; XMR itself may remain locked |
| M claims DOM | D observes T and recovers XMR | Claim finality, extraction, reorg handling and durable XMR execution |
| D refunds DOM | M observes U and recovers XMR | Refund finality, extraction, reorg handling and durable XMR execution |

A malicious M can retain compensation and exercise it even without depositing
XMR if D misses the refund window. A local funding check does not restrict M's
already signed transaction. Thus this candidate does **not** protect a DOM
depositor who remains offline beyond the recovery deadline.

Even if D broadcasts refund while its local window is open, a delayed losing
refund can expose U while M confirms compensation and subsequently spends XMR.
Preventing this outcome requires a justified inclusion/finality bound, not just
an inequality checked before broadcast. No such bound is proven here.

## Constraints on the replacement

1. Keep native DOM consensus, serialization, kernel features and miner/mempool
   rules unchanged. No certificate or local witness may masquerade as a native
   restriction on a counterparty-held signature.
2. Do not release claim material before independently revalidated XMR funding.
   Do not disclose the completed refund while preparing private recovery.
3. Cancellation must be canonically confirmed and revalidated before releasing
   U; passing Hc alone does not disable an already signed claim.
4. Do not make punishment reveal T as a shortcut: refund and punishment
   signatures may both become visible even if only one confirms. Such a change
   needs a new witness-exposure analysis, not merely a double-spend check.
5. A bounded-availability candidate needs an explicit height budget for honest
   outage/restart, observation lag, cancellation inclusion and finality, refund
   inclusion and finality, plus the accepted reorg and fee assumptions. The
   daemon must derive and enforce it from authenticated negotiated terms before
   funding and revalidate it at every secret-exposure boundary.
6. Account for economic recovery separately from recovering the original XMR.
   Ordinary DOM compensation can leave XMR locked. An exchange-value assumption
   must not be silently reported as conservation of each asset's units.

## Legacy timing terms and the explicit V23 extension

`crates/adapters/xmr-refund-policy/src/compensation.rs` already binds the
policy hash through `SettlementTermsV1.assurance_policy_hash`. Its policy has
Hc, Hp, `cooperative_window_blocks`, `reveal_safety_blocks`, fixed fees and
collateral confirmation depth. `validate_for` requires each of the cooperative
and reveal budgets to cover DOM minimum confirmations plus maximum reorg
depth. Canonical policy validation requires, with checked arithmetic:

`Hc + cooperative_window_blocks + reveal_safety_blocks < Hp`.

The legacy V11 encoding does not name an honest outage bound. The optional
`bounded_availability_v23` field now selects a distinct `DOMXCM23` encoding
and V23 hash domain, committing four DOM-block bounds: total unavailability,
observation/dispatch delay, cancel inclusion, and refund inclusion. Without
this field, V11 bytes and hash remain unchanged; old signatures are not upgraded.

With F = signed minimum confirmations + maximum reorg depth, validation requires:

- cooperative window >= total unavailability + 2 × observation delay + cancel inclusion + F;
- reveal safety >= refund inclusion + F;
- Hc + cooperative window + reveal safety < Hp, still strictly.

Total unavailability covers all crashes/restarts and local processing delays
across the recovery episode, not a fresh allowance per restart. The two
observation allowances cover the cancellation deadline and the final cancelled
output. These are explicit assumptions about the environment and exact-fee
inclusion, not something policy arithmetic can make a chain guarantee.
The existing policy type name is retained for source continuity; its encoder
selects the wire version explicitly.

`crates/adapters/dom-real/src/xmr_recovery_execution_v12.rs` uses a fresh
authenticated graph observation and requires cancelled finality before refund.
Its private-refund role stops selecting refund when
`height + reveal_safety_blocks >= Hp`. That prevents a new late attempt;
it does not expire an earlier disclosed signature or prove its timely inclusion.

## Verification of this review's native examples

The full `xmr_recovery_graph_v11` test binary passed **12 tests, zero failures**
on 2026-09-10 (18.78 seconds; compilation 1 minute 47 seconds), with one Cargo
job and one test thread. Existing four library warnings remain. The frozen
consensus-source guard and `git diff --check` passed. These results prove the
stated native examples, not bounded-availability recovery by the daemon.

## Verification of the V23 policy extension

On 2026-09-10, all 29 `xmr-refund-policy` library tests passed (1.69 seconds,
zero failures), including five new V23 cases. The targeted compensation run
also passed all 10 cases. Tests cover strict decoding/version substitution,
legacy bytes/hash compatibility, commitment of every availability bound,
insufficient reserves, strict deadline equality and overflow. A finite
arithmetic schedule test distributes the total outage across both recovery
phases; it is not a live-chain/crash test or a general formal proof.

Production `dom-interopd --all-targets` passed cargo check in 55.08 seconds
with existing warnings. All targets of dom-actuator also passed cargo check
in 30.09 seconds. The frozen-consensus guard, rustfmt check on changed
policy sources and diff whitespace check passed. Heavy checks were serial,
with one Cargo job and one test thread when applicable.

## V23 native partial-signature integration

Canonical policy validation now lives in `crates/xmr-compensation-policy`,
which depends only on canonical Kaystra terms (without the storage engine),
SHA-256 and error types. The old `xmr_refund_policy::compensation` path
reexports the same types. Its ten policy tests moved with it; the remaining
nineteen adapter-policy tests still pass. No policy bytes or hash domains
changed during this extraction.

`XmrOrdinaryRecoveryRoundV12::begin_bounded_compensation_v23` accepts the
opaque arithmetic/scope-validated policy, requires the V23 envelope, and matches
chain, session, terms digest, deadlines, safety budget, three recovery fees and
refund/compensation recipients before processing participant nonces. Its
auxiliary session uses a separate V23 domain and the policy hash. Completion
still checks both ordinary partial equations and original DOM consensus.
The old V13 and V22 entries still reject compensation, including local markers.

The graph builder now offers `begin_compensation_round_v23` with its retained
policy and exact template. Completion requires V23 and its precise auxiliary
session; a legacy compensation session is not accepted. This is mathematical
assembly, not an authenticated wallet/Store signing grant. Payout value and
ownership checks remain in the existing economic graph verifier.

After this integration, the native graph test binary passed all fourteen tests
(21.41 seconds, compilation 13.60 seconds). Its two new tests produce ordinary
compensation from native partials, verify original height-lock acceptance,
distinguish the V23 session from V12, reject a legacy policy and reject eleven
binding substitutions. The policy suites passed ten plus nineteen tests
(0.00 and 1.67 seconds, compilation 17.03 seconds). These are not live wallet,
full graph-builder or daemon recovery scenarios. All production daemon targets
passed cargo check after the native integration (45.54 seconds, existing
warnings), and the frozen-consensus and formatting/diff guards passed again.

## V23 Store transcript identity binding

The graph now derives both expected ordinary-session IDs through
`ordinary_recovery_sessions_v23`, using the same policy/binding check as
compensation assembly and the native signature-omitting template codec.
The Store auditor requires the actual session pair to equal that derived
pair, not merely consist of two distinct nonzero identifiers.

The auditor revalidates the economic policy against the authenticated role,
checks C and T against that role, and requires both auxiliary records to carry
the parent terms hash. Existing checks of current parent state, custody,
transport identities, local owner, no auxiliary funding authority and full
ordinary signature transcripts remain in place. Revalidation repeats the new
checks; the production graph driver and F7 preparation pass the exact economic
policy. This token remains read-only and confers no signing/funding capability.

Validation on 2026-09-10: all fifteen native graph tests passed (22.89 seconds,
compilation 3.28 seconds). The added native test compares derived IDs with
actual cancel/compensation round contexts and rejects legacy/foreign policy.
Both targeted Store identity tests passed (0.00 seconds, compilation 1 minute
04 seconds); the new case rejects distinct foreign IDs and swapped roles.
These do not constitute a full two-Store authenticated graph/custody test.
All production daemon targets passed cargo check in 30.29 seconds with
existing warnings. Consensus-source, formatting and diff checks passed.

## V23 wallet and round identity integration

The public checked identity helper `xmr_bounded_compensation_session_v23`
checks the validated V23 policy against the graph and rejects a null template
hash. The native graph, template builder and participant binding share this
derivation. The participant binding preserves every other authority field and
rejects a participant outside the policy or recursive derivation.

The wallet's new `take_compensation_share_v23` checks the retained auxiliary
terms, native operational template, ordinary Refund purpose, absent adaptor,
two policy participants and exact local signing key before consuming the share.
The legacy share entry refuses compensation. These checks are not a signing
permit and do not create early/BP/template journals.

The round runtime now derives V23 compensation scope and uses the new wallet
binding. Before binding or advancing a round it checks the stored parent terms
hash. Completion reconstructs authenticated public envelopes and invokes the
V23 native equation; the old funding-witness entry still refuses compensation.
No nonce-custody, identity-signing or Relay staging check was removed.

Validation: fifteen native graph tests passed (22.94 seconds), including the
checked identity's legacy, zero-template and eleven foreign-binding refusals.
The new actuator identity-only test passed (0.00 seconds); it checks preserved
authority, foreign participant, recursion and changed fee. Two initial compile
attempts exposed a moved fixture value, corrected without changing production
types. All production daemon targets passed cargo check (23.78 seconds, with
94 lib-test warnings). The frozen-consensus source guard passed.

This is not a full two-wallet/two-Store signing or crash-recovery demonstration.
The new share-transfer method still needs direct retained-journal failure and
success tests and wiring at the bilateral composition site. The graph-custody
driver and selected-DOM funding prerequisite retain the retired-path refusal.
They must be migrated coherently with authenticated native Store transcripts,
not by deleting those checks in isolation.

## Additional F7 restart defect found during serial validation

The full actuator library run finished with 96 passes and two failures
(558.61 seconds). Both `native_f7_claim_v21` preparation tests reproduced
in isolation. Reopening a newly prepared F7 claim returned UnsupportedFormat:
the preparation-owner marker used the operation's effect ID, while the strict
operation auditor requires zero completion events for a prepared operation.

The marker now uses a domain-separated effect ID derived from the exact claim
scope. Both its writer and recovery lookup use that identity. The owner, old
fence and authorization remain bound in its digest. The operation auditor,
schema and L1 were not changed; old inconsistent databases remain refused,
with no automatic migration or deletion.

Four targeted tests passed after the fix (17.93 seconds): the two failing
cases, a new successive-restart case and the neighboring refusal of takeover
without custody. The new case verifies three distinct preparation revisions
and zero completion events for the operation across two re-fencings. This is
not a rerun of the full library and not a successful daemon swap.

## Runtime formation from the live C/D owners

Stage 12 now calls the native five-template constructor after receiving a
bilateral offer and after progressing C/D formation. It reopens formation
evidence through each live Contracts owner, uses the authenticated setup's
terms, negotiated tip and U point, and requires an explicit V23 policy.
The exact native refund template must match the admitted bundle's separate
template pin; U's cross-curve proof by itself does not establish that equality.
All five contributor key/offset bindings are checked against the formed graph.

The result is memory-only unsigned material, discarded and rebuilt after a
restart. It is not a durable graph agreement, signing permit, recovery archive
or funding capability. No readiness flag is changed. The existing
XmrRecoveryGraphRequired refusal still propagates through the composite loop;
full bilateral agreement/signing/readiness integration remains necessary.
The combined two-wallet/C-D scenario below validates the shared formation
function, not the outer setup-admission checks or the complete composite loop.

After the F7 fix, the entire actuator library was rerun serially: 99 passed,
zero failed, 583.42 seconds (12.56 seconds Cargo setup). This replaces the
earlier 96/2 result for the actuator library only, not the daemon integration
binaries or the requested route scenarios. All production daemon targets
passed cargo check after the formation wiring (28.44 seconds, 95 lib-test
warnings). Formatting, diff and frozen-consensus guards passed. No live swap,
commit, publication or deployment was performed.

## Combined C/D and wallet formation scenario passed

A new daemon-library scenario reuses one actual ceremony to drive both C and D
through the native early/BP journals, reopening participant owners after every
tick. It then reopens both encrypted wallets and feeds their canonical offers
and native output proofs to the same formation function used by Stage 12.
The runtime separately authenticates setup and the refund-template pin; the
test uses a public U fixture and does not claim those admission guarantees.

The first combined execution terminated after 1606.15 seconds with
Relay(Sender(AlreadyExists)) when the second phase attempted to create the
sender. The tested binary retained the old shared sender name. Worker paths
are now generated once and used by both the existence check and constructor.
A dedicated disjoint-path regression passed after recompilation (0.00 seconds,
compilation 1 minute 28 seconds).

The complete rerun passed: one test, zero failures, 501 filtered out, in
2899.62 seconds (compilation 24.96 seconds), with one Cargo job and one test
thread. Both participants formed identical hashes for all five unsigned native
templates and the same V23 compensation session, distinct from the parent and
legacy compensation IDs. The scenario also exercised wallet reopen and native
Noise/Relay public-offer exchange. It did not sign the graph, admit a real XMR
setup, release funding, or execute a live swap.

After this run, all production daemon targets passed cargo check in 45.97
seconds, with 94 library-test warnings. This is compile coverage, not execution
of every integration test.

The Stage-12 owner also explicitly matches contributor roles to its native
shared-binding roster, in addition to route, chain, session and terms. This
still produces only unsigned material, never signing or funding authority.

## Durable signing dependencies verified in the Store

Read-only inspection confirms that `bind_operational_signing_session` cannot
consume the memory-only graph directly. Ordinary Refund provenance requires
the session's authenticated early/BP/template journals, the exact committed
template hash and an input equal to that session's proven output. The current
template agreement commits three transaction hashes plus the BP statement and
recovery binding; it is not an agreement on the five-edge XMR graph.

Signing-key ancestry also matters: the existing V18 wallet authority rebuilds
the ordinary three-template bootstrap and revalidates both template messages.
It cannot authorize the five XMR kernel shares merely by copying a roster or
renaming a session. The graph's derived auxiliary IDs do not create their
required native journals, key authority or signing permission.

The transport decoder recognizes graph-commit type 0x18, but the Store does
not currently admit that type. Its retired V22 candidate reader checks framing
only and is not a graph-agreement producer. A replacement must authenticate
the bilateral graph and reconstruct its provenance durably before connecting
auxiliary signing; enabling a message type or removing the runtime refusal
alone would not satisfy those requirements. These are integration findings,
not additional test results, and do not require a consensus change.

## V23 local proposal persistence, bilateral agreement still pending

Stage 12 now pins the locally reconstructed proposal in the existing C Store
after auditing the actual C and D owners. The record includes the complete
704-byte proposal and both native proof digests, in a bounded, checksummed
808-byte frame. It requires V23 policy, route, participant roles, matching
transport identities and the exact native graph. Publication is immutable;
different bytes conflict, and identical reconstruction is idempotent.

The narrow Contracts-owner operation checks both session owners and their
local/remote participants; no raw Store accessor was added. Reopen auditing
checks record framing and parent scope only. Neither the checksum nor this
local pin authenticates peer agreement or grants signing/funding authority.
The graph is rebuilt and both live proof origins are audited again on use.
This snapshot does not replace secret-exposure-time revalidation.

The new framing/conflict test passed (one test, 0.03 seconds). The interrupted
publication test initially exposed the missing low-level filename registry
entry; after registration, the rerun passed (one test, 7.07 seconds).
All production daemon targets passed cargo check (1 minute, 94 library-test
warnings). Frozen-consensus, diff and selected-source formatting checks passed.

The existing combined scenario has now been extended to pin the proposal,
close/reopen both actual Stores, revalidate the same digest, refuse a foreign
route and check that funding/signing are still unavailable. The first extended
debug run failed with Conflict after 3017.03 seconds. An opt-in crypto-test
profile retains debug assertions and overflow checks, with opt-level 2, no LTO
and one build job/test thread. The unchanged scenario passed in 564.90 seconds
after a 14m19s initial build; this single-run comparison is not a statistical
benchmark, and the participant identities are freshly generated each run.

Review found that the Store keeps direction order while graph keys use terms
roster order. The pin now matches IDs exactly and carries each retained role
into terms order, preserving the exact C/D identity comparison. Two deterministic
tests covering both orders, invalid/duplicate IDs and frame integrity passed
(0.00 seconds, 457 filtered). The integrated scenario then passed after the fix:
one passed, zero failed, 501 filtered, 559.55 seconds (5m17s rebuild).
Cumulative stage times were 79.35 seconds for the fixture, 282.25 for C and
497.66 for D. This exercises the direct Store pin/reopen path and unsigned
formation, not the complete runtime wrapper or bilateral signing/funding.
The earlier 2899.62-second success predates this persistence extension.

## Remaining implementation

The ordinary graph is now an authorized design direction under bounded honest
availability, not a proven replacement. The new envelope is checked by policy
validation and native compensation assembly, but authenticated bilateral graph
signing, durable Store custody and runtime funding still need integration. Adversarial
message withholding, late inclusion, fee pressure, reorg and restart need
end-to-end evidence against the accepted bounds.

The current refusal gates remain in force. This review does not establish DOM↔XMR completion, the sixteen route outcomes,
independent verification, audits or reproducible operation.

## 2026-09-12 F1/I6 guard inventory review

This is a source/inventory review, not a Rust test result, a completed swap or
permission to fund/deploy. The global guard reported the same 39 F1/I6 findings
on `5206cbd` and the worktree; they were not introduced by choosing a dirty
baseline. No Sponsor purpose, L1 rule, TTL or Relay policy is authorized here.

I6's 36 findings were 30 changed exact signatures/counts and six obsolete
compact signatures replaced by formatting. The revised inventory still pins
each source line and multiplicity: `println!("{json}")` occurs 10 times,
`eprintln!("{error}")` 12, and multiline `eprintln!(` twice. The remaining
additions are 20 static usage signatures and seven fixed refusal signatures.
No library-wide or file-wide output exception was added.

The reviewed public producers are `production_prepare_planning_v23`,
`production_prepare_f6_artifact_v23`, `production_prepare_xmr_leg_v23`,
`production_prepare_xmr_enrollment_v23`, `production_route_services`,
`production_xmr_inventory_v23` and `production_xmr_funding_command_v12`.
Planning's JSON Value comes only from the seven typed public route pins;
enrollment's Store filenames are constants. Reports contain scope IDs,
digests, public keys/addresses, economic amounts, counts and fixed status
fields, not private scalars, passphrases, authentication keys, raw signed
transactions or RPC bodies. New error enums render fixed redacted messages;
the funding error's nested wallet variant also renders only fixed messages.
Existing bootstrap/self-check/simulation output remains in the exact inventory.

F1 records a new review of the current Sponsor surface, with these source hashes:

| Source | SHA-256 |
| --- | --- |
| `crates/dom-adaptor/src/context.rs` | `982c2d34ea636303bc6ca80d9c7e82b4070f158f37955b22d0f1215a7ae73561` |
| `crates/dom-actuator/src/contracts.rs` | `f2f69b87bb09730239c601189667aedf02d4f048f55150fc8d04b323854d944c` |
| `crates/dom-scriptless-store/src/runtime/linux/session_store.rs` | `122140f075bcbd2256b35b63ccdfe6745342c44431e3984a3f49d85621515371` |

The old context hash `5b9c9486...` is present in `38dd705` and both supplied
V21/V22 archives. Its nine-line diff extracts a private public-key audit while
preserving `require_strict_phase1`, participant checks and explicit Sponsor
refusal. Public reservation-audit wrappers return only a digest and require
their exact Funding, ClaimAdaptor or Refund/RefundAdaptor purpose; Store funding
and claim consumers use the respective wrappers, not the recovery-only entry.

Provenance limitation: the old actuator `898be8d7...` and Store `13db3311...`
frozen hashes were NOT found in available Git revisions or the two archives.
The new values do not assert a comparison against those unavailable bytes.
Review instead inspected current code and history from `38dd705`/`37d9da7`:
actuator `action_for_purpose` retains Sponsor -> CapabilityMismatch and both
consumers; its added native paths require authenticated Store custody and exact
chain/transaction bindings. Store's operational/replay auditors retain strict
purpose checks, and the shared equation helper explicitly excludes Sponsor.
Native claim ancestry is checked under its exclusive profile; purpose-specific
wallet keys reject unknown purposes. Claim publication's callback adds only a
veto under the operation lock, preserving the original unguarded wrapper.
The refund-kernel helper still admits only legacy HEIGHT_LOCKED, not a new
consensus feature. Current Sponsor line allowances were not expanded.

The inventory remains fail-closed on an extra/missing output line, multiplicity
change, unreviewed Sponsor surface or any subsequent frozen-file byte change.
Validation: all 51 `scripts.tests.test_guard_layer_policy` tests passed in
29.258 seconds, including the complete workspace guard (F1/I6 and the other
absorbed checks), mutation/refusal regressions and the new exact-output-count
case. `git diff --check` passed. No Cargo, Rust compilation, chain operations,
commit or publication was executed for this review.

## 2026-09-13 public signature memo and F1 source review

The off-chain verification optimization first failed the F1 whole-file pin;
that refusal was retained until an exact source review. Unlike the historical
provenance limitation above, the immediately preceding approved bytes are
available in commit `b8c1420367ab777a6e0403fbb115d32684fa7745`:

| Store source | SHA-256 |
| --- | --- |
| Prior `session_store.rs`, from that commit | `122140f075bcbd2256b35b63ccdfe6745342c44431e3984a3f49d85621515371` |
| Reviewed `session_store.rs`, after the hook | `3ac4f8d43120647edc73865d57ba1ff808548b1bc94655900f026c87dded4b7d` |

The complete diff has eight inserted and two removed lines: private module
declaration, import adjustment and the call in `ParsedTransportEnvelopeV1::verify`.
The existing signature parser and its `Canonical` error mapping remain before
and after that call. The helper remembers only successful, exact Schnorr
equations: signature (65 bytes), public key (33), chain (32), message digest
(32). The digest is still freshly derived by the existing DSC1 parser, not
manufactured by the cache. Capacity is 1,024 entries. Failed verification,
contention and poisoned locks use the original mathematical verifier; no
record, roster, transcript, nonce, current state or F7 decision is cached.

Comparison using the guard's production/test source mask found all 1,161
existing function signatures unchanged. All 15 enclosing functions containing
`Sponsor`, `require_strict_phase1` or `is_strict_v1_authorized` are byte-identical:
14 operational functions and one evidence-only `PreparedSigningPayloads::new`.
Occurrence counts remain five Sponsor arms, four strict-phase checks and six
strict-authorization checks. The existing Sponsor refusals and exact inventory
were not expanded; the sole changed existing function body is the envelope's
pure verification wrapper. The new module has no public re-export.

The reviewed file remains pinned in full, with no hash wildcard or excluded
region. Added negative tests copy its real bytes into an isolated temporary
directory and require a one-byte change to fail the approved pin; a separate
test rejects an additional Sponsor occurrence and an accepting Sponsor arm
independently of the file digest. No node/consensus source, signing purpose,
confirmation count, availability bound or custody transition changes here.

This is source-review evidence, not a completed mainnet swap or a measured
end-to-end speedup. Seven real envelope-cache regressions and five additional
collaborative-proof-cache regressions are mandatory in the remote boundary
suite, including cold-plus-warm measurements and adversarial failures. No
local Rust build or cryptographic test is implied by this review.

## 2026-09-13 bounded session-head scan and F1 source review

This separate, narrowly scoped re-freeze follows exact source comparison against
published commit `77a4e0bd3b7cf8d2b589f160db3b8dd32af51e40`. It does not refresh
the pin merely because the guard refuses a changed source file.

| Store source | SHA-256 |
| --- | --- |
| Prior `session_store.rs`, from that commit | `3ac4f8d43120647edc73865d57ba1ff808548b1bc94655900f026c87dded4b7d` |
| Reviewed `session_store.rs`, after the scan hook and test include | `bda8fe04b472459ae87a9fadf857c3a04f7ef61189e202c1a82fa83a9d4a3ef9` |

Two source reviews using the guard's offset-preserving Rust sanitizer found
1,485 existing function spans: 1,484 byte-identical and only
`load_session_locked` changed. After whitespace normalization, that function's
sole change is the scanner name. Its complete suffix starting at recovery
projection, including sort, revision zero, gaps and exact successors, is
byte-identical. The additional parent source change is a test-only leaf include.
All 15 enclosing Sponsor/strict-purpose bodies, including the evidence-only
constructor, remain byte-identical; homonymous functions were compared as
separate spans rather than overwritten in a name-keyed map.

The new helper is private and used only by this read-only collector. It captures
a bounded exact name/physical-identity inventory, verifies exact coverage in
collection and postflight, and revalidates the retained directory before
returning. Excluded entries remain identity-checked. Capacity/allocation fallback
runs the original scanner **before** callbacks; real errors and detected changes
remain refusals. The generic lexicographic scanner is byte-identical. The design
review rejected a simpler three-pass implementation that checked physical types
but could miss a newly appended revision without comparing inventory membership.

No nonce state, transcript, signing purpose, F7 decision, ownership authority,
confirmation or availability condition is changed or cached. The complete source
hash remains pinned, the exact Sponsor inventory remains unchanged, and the
existing one-byte pin-mutation and extra-Sponsor-occurrence regressions remain.
The separate frozen L1 baseline and its path inventory are untouched.

Details, concurrency limits, capacity fallback and execution-evidence limits:
[Session-head scan V25](hardening/SESSION-HEAD-SCAN-V25.md). This is source-review
evidence, not an external security audit, a completed real-daemon lifecycle, or
proof of a swap completing in minutes. The new Rust regressions run in GitHub;
no local cryptographic build/test is asserted.

## 2026-09-13 bounded transport-sequence scan and F1 source review

This next review compares the complete parent Store source to published commit
`1ae798dd4efbe0bac92353ed90a48f3d726ce3fe`. The old whole-file SHA-256 is
`bda8fe04b472459ae87a9fadf857c3a04f7ef61189e202c1a82fa83a9d4a3ef9`; the reviewed
source including its additive test leaf has SHA-256
`71b64b2d83fc82b7d15e59404bfd2c60c5c521937157f0be7a58e3def735dc8e`.

Two source reviews find 1,485 ordered function spans with 1,484 literally
unchanged. The sole changed function is `transport_sequence_at_revision`.
Replacing its old scanner name and normalizing whitespace yields exactly the
new function. The suffix beginning `sequences.sort_unstable` is byte-identical
(SHA-256 `ae1ff21ea5685aac55ab2d6f4a6cd97aff0bfe594bafeba9b291cdd52325f077`).
All 15 Sponsor/strict-purpose-containing bodies remain byte-identical, with
homonymous functions compared by their separate ordered spans. The second
parent edit only includes additive test evidence inside the existing test module.

This shared reader still parses the original transport record, filters by the
same session/sender and inclusive revision, sorts without deduplication and
rejects a missing zero origin, gap or duplicate. It grants no transport or
funding authority. The bounded scanner and original fallback are unchanged;
`next_transport_sequence` and the remaining generic scanners stay unchanged.
No strict-purpose inventory expansion, hash wildcard, nonce or signing gate
change is authorized by this re-freeze. L1 and the frozen baseline stay unchanged.

Separately, two native graph leaf readers use a shared physical message collector.
Their complete code after collection is literally identical to the prior source,
including all authentication and signing-semantic validation. Lexical filename
order is restored before authentication; revision order is still checked by the
original readers. The physical collector itself is not authenticated authority.
See [scan scope and limits](hardening/SESSION-HEAD-SCAN-V25.md) for the three-pass
cost model, mandatory negative regressions and remaining timing-evidence gap.
These are source reviews, not Rust execution or an external security audit.
