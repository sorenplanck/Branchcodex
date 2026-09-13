# Native activation: retained evidence and closed diagnostics

## Observed failure, not a completed swap

Commit `1ae798dd4efbe0bac92353ed90a48f3d726ce3fe` reached real-daemon launch in
[claims/reopen job 103696564064](https://github.com/sorenplanck/Branchcodex/actions/runs/34746969642/job/103696564064),
but failed before funding. The only emitted failure category was
`DOM_NATIVE_EXIT_DIAGNOSTIC_V24 code=composite_loop`. The test failed; its
112.18-second duration is **not** a successful swap latency measurement.
Cold preparation took 96,526 ms, including test infrastructure; export/launch
took 3,285 ms, and the incomplete launch-to-claims phase stopped after 7,571 ms.

The retained synthetic artifact `10314676997` was inspected without executing
any binary or Rust test. Both actors completed provisioning stage 12; neither
started stage 13. The main C histories remained at revision zero. Alice retained
the first signed D/cancelled TermsOffer for each leg; Bob retained neither.
Bob's Relay contained the exact upstream D message and Alice retained its
delivery acknowledgement. The examined main and cancelled inboxes contained no
accepted or quarantined rows. This demonstrates delivery to Relay, not acceptance
by Contracts, graph completion, F6 consent or funding readiness. The peer graph
offer journal key was absent from all four inspected shared C stores.

Those observations narrow the failure to early activation but do not identify
its exact cause. They do not justify relaxing a binding, bypassing ingress, or
blaming F6 negotiation: an initial route snapshot exists before activation, and
graph exchange/local bootstrap can fail before the first F6 RFQ. The original
stderr capture does not retain a detailed cause that can be recovered afterwards.

## Implementation

Both composition roots now preserve a typed diagnostic when composite config,
construction or bounded activation fails. The existing unit `CompositeLoop`
variant remains for compatibility; `CompositeLoopDetail` contains only a closed
`ProductionCompositeFailureV25`, not an original error, path, payload or string.

The projection matches concrete error enums and emits fixed `stage/cause` tags.
It separates bootstrap, native Store refusals, F7 readiness, outbound, network,
Noise, network configuration, main/cancelled/recovery inbound, F6, route and
control failures. Two former configuration mappers retain typed Noise/network
causes. Existing retry and polling logic is unchanged: those newly distinguished
errors are still terminal, as their former `InvalidConfiguration` mapping was.
The three bootstrap call boundaries are distinguished as local preparation,
received graph candidate and post-exchange preparation. The same underlying
error remains a refusal; no previously missing peer material becomes authority.

The test-process reporter recognizes only a complete exact production error line.
It decodes at most 96 bytes into permitted closed tag pairs and prints static
stage/cause values. It never forwards stderr, formats an original error, follows
an error source chain, or turns an unknown input into a diagnostic string.
Multiple recognized errors, injected suffixes, invalid pairs and oversized
captures cannot produce a single detailed report. A diagnostic is not authority.

Five new projection regressions cover real error enums, all 15 Store error
variants, unchanged network retry, exact decoding and a generic error whose
Display/Debug/source methods panic if consulted. Two additional process tests
cover the actual production Display and ambiguity/injection/capture bounds.
All existing diagnostic tests remain required. Seven new Rust tests are mandatory
in the closed GitHub selections; no local Rust execution is claimed.

Local lightweight validation passed: 36 closed-selection checks, 53 policy/guard
regressions including the repository contract, formatting for all six affected
Rust files, whitespace checks and the unchanged frozen-consensus baseline.
An exact source comparison found 101 of the 106 pre-existing composite-loop
function spans byte-identical. The five changed spans contain only the three
contextual error mappings and the two typed Noise/configuration mappings; the
retry predicates and exchange/poll ordering remain unchanged.

Some existing upstream variants still deliberately coalesce several binding
checks. A `bootstrap/binding` result narrows the stage but does not identify a
particular operand; further investigation must use the actual next result.

## Separate positive evidence and remaining work

[Preflight job 103696564048](https://github.com/sorenplanck/Branchcodex/actions/runs/34746969658/job/103696564048)
passed on the same commit. Its logs show the eight session-head and nine physical
inventory regressions passed, as did the DOM profile-domain regressions and the
previously failing F6 proposal/acceptance boundary tests. These are useful
boundary results, not evidence that real F6 publication/role selection or the
full daemon lifecycle is operational. The new graph/sequence integration in
`1cfcfd34b83df538fd3f566b5f6f8dea1efdbcd3` awaits its own remote evidence.

The mission still requires the complete actual-daemon claim, noncooperative
refund/compensation, original-store recovery and end-to-end timing. No L1,
consensus, confirmation, negotiated availability, signing or custody guard is
changed by this diagnostic work.
