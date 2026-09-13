# Native proof latency: continuation, not reduced verification

The production bootstrap previously reconstructed the first private BP phase
at RoundCommit, Round1 and Round2. The new runtime retains its single move-only
Round1Done continuation between these stages. Before each reuse it still:

1. Authenticates the original Contracts session and complete Store transcript.
2. Checks the current vault custody stage and original nonce binding.
3. Reopens the original nonce material and verifies all common commitments and
   reveals using the original `finish_common_nonce` path.
4. Compares the complete statement, participant index, raw recovery capsule and
   exact private blinding/common/private nonce origin. The 96 private bytes are
   compared in constant time and retained only in a zeroizing opaque holder.

A mismatch refuses without replacing the original continuation. There is no
global private cache, serializer, private getter, new persistence format or new
signing authority. The same state moves once into the original vault-backed
round-two implementation; persistence and nonce retirement still precede
transport. A process restart has no holder and reconstructs using the original
path. Durable Round2/Proof and terminal/proof-complete states clear the holder.
Inputs over the reuse eligibility bound recompute normally, not fail a new
protocol limit. Backend equations, fresh scratch handling and L1 are unchanged.

Eight additive regressions cover full real two-party proof equivalence, original
three versus continued one Round1 computation per actor, exact-origin mutations,
statement/framing mutations, consumed and poisoned states, dropping the holder,
oversize fallback and failed durable round-two persistence. The comparison uses
an isolated test-only snapshot of the same nonce-vault fixture; production cannot
export or clone these holders. Existing nonce-vault and full restart tests remain.
These new regressions are written but have not yet executed at this handoff.

## Why the restart fixture is not a swap stopwatch

`complete_native_proof_in_fixture_for_leg` deliberately drops and remounts the
bootstrap, identity and other owners for each actor tick. This repeats password
derivation and complete recovery audits, unlike the daemon's retained owners.
Those recovery checks are not removed or made cheaper by weakening custody.

The fixture now reports actual tick/mount/identity-open counts and disjoint setup,
mount, identity-open, remaining-tick, terminal-mount and terminal-audit durations.
Its report explicitly says `fixture_restart_only=true` and
`actual_daemon_latency=false`. Two cheap regressions check the accounting.

The normal daemon's full funding/claim/refund/recovery scenarios remain the
required end-to-end evidence. Neither reduced primitive counts nor the duration
of a restart-heavy fixture establishes a mainnet swap completion time.
