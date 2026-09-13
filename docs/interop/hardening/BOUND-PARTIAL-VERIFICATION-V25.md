# Exact public bound-partial verification memo

This optimization changes only repeated public mathematics at
`ValidatedSigningRoundStateV1::verify_partial`. The original
`PartialSignatureV1::verify_bound` and the frozen consensus sources are unchanged.
Direct calls to that original method, including the frozen Store semantic audit,
are not accelerated by this wrapper. New proof generation is also unchanged.

The caller still derives authenticated public inputs and checks roster and
participant indices on every call. Purpose and template guards run before every
lookup, preserving their original error order. A hit requires byte equality of
the full canonical partial signature, expected purpose/template, all four public
points, chain and complete length-delimited kernel message. The memo does not
represent authorization, current chain state, funding readiness or secret custody.

Only `Ok(true)` from the original verifier enters the 64-entry fixed ring. Misses,
eviction, contention and poisoned locks use the original verifier. Messages over
1024 bytes bypass the memo without changing their acceptance rules. There is no
persistent cache, key material, nonce material, unbounded allocation or lock held
during cryptography.

Seven additive Rust regressions compare real partial equations with the original
verifier, mutate public operands and context, preserve strict guards and failures,
exercise message length and padding, eviction, contention and poison. The backend
error insertion test obtains an actual zero-challenge backend refusal and checks
the shared insertion policy; it does not claim to construct a kernel-message
preimage that produces a zero challenge. Timing reports cold plus 63 warm calls
against 64 original calls, explicitly labelled `primitive_only`, not swap latency.

The closed CI selector `adaptor-bound-partial-equation-cache` requires all seven
named regressions, in addition to existing production, replay and recovery tests.
At implementation handoff these new Rust regressions have not yet run. Local
validation is restricted to formatting, dispatch-policy tests and frozen-source
checks; cryptographic execution belongs to GitHub CI.
