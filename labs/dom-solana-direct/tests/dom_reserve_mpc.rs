//! The two-party DOM reserve, end to end, with no capsule and no chain.
//!
//! This is the regression guard for a defect in `bulletproof_mpc_finalize`: it
//! proved correctly with a null extra commitment but then self-checked with
//! `bp_verify_with_extra_commit`, which refuses an empty extra commitment
//! outright. A shared output carrying no recovery capsule -- the case
//! `crates/dom-adaptor/src/bulletproof_mpc.rs` documents as supported, and the
//! case `dom_reserve` deliberately uses for native plain outputs -- therefore
//! could not be produced at all, however valid its proof was. All three live
//! scenarios died on it with
//! `Malformed("range proof extra commitment must not be empty")`.
//!
//! The decisive assertion is the last one: the finished proof must be accepted
//! by `range_proof_verify`, the plain verifier, because that is exactly the one
//! `dom-consensus` uses for an output with no capsule
//! (`crates/dom-consensus/src/transaction.rs`). A proof that only satisfied the
//! extra-commitment verifier would be a proof the node would reject.
//!
//! It needs no validator and no DOM node, so it runs in the cheap job.

use dom_solana_direct_lab::dom_reserve::{ReserveIntent, ReserveShare};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

const VALUE: u64 = 100_000_000;

fn two_party_reserve_proof() -> (dom_crypto::pedersen::Commitment, Vec<u8>) {
    let shares = [
        ReserveShare::generate(&mut OsRng).expect("a reserve share"),
        ReserveShare::generate(&mut OsRng).expect("a reserve share"),
    ];
    let intent = ReserveIntent::new(
        VALUE,
        [0x11; 32],
        [0x22; 32],
        [0x33; 32],
        [shares[0].public_key(), shares[1].public_key()],
    )
    .expect("a reserve intent");
    let proofs = [
        shares[0].prove(&intent, 0).expect("share 0 possession"),
        shares[1].prove(&intent, 1).expect("share 1 possession"),
    ];
    let plan = intent.authorize(proofs).expect("an authorized reserve");

    // One common seed, two private nonces: both parties must derive the same
    // common nonce or the aggregation does not close.
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *seed);
    let (first, first_commitment) = shares[0]
        .begin_proof(plan.clone(), 0, &seed, &mut OsRng)
        .expect("party 0 round one");
    let (second, second_commitment) = shares[1]
        .begin_proof(plan.clone(), 1, &seed, &mut OsRng)
        .expect("party 1 round one");
    drop(seed);

    let (first, first_response) = first
        .respond(&second_commitment)
        .expect("party 0 round two");
    let (second, second_response) = second
        .respond(&first_commitment)
        .expect("party 1 round two");

    let proof = first.complete(second_response).expect("party 0 finalizes");
    let mirror = second.complete(first_response).expect("party 1 finalizes");
    assert_eq!(
        proof, mirror,
        "both parties must finish on byte-identical proofs"
    );
    (plan.commitment().clone(), proof)
}

#[test]
fn a_capsuleless_two_party_reserve_proof_is_produced_and_the_node_accepts_it() {
    let (commitment, proof) = two_party_reserve_proof();
    assert!(
        dom_crypto::range_proof_verify(commitment.as_bytes(), &proof)
            .expect("the plain verifier runs"),
        "the plain verifier is the one consensus uses for an output with no \
         capsule; a proof it rejects is a proof the node rejects"
    );
}

#[test]
fn the_proof_does_not_verify_against_a_different_commitment() {
    let (_, proof) = two_party_reserve_proof();
    let (other, _) = two_party_reserve_proof();
    assert!(
        !dom_crypto::range_proof_verify(other.as_bytes(), &proof)
            .expect("the plain verifier runs"),
        "a reserve proof must not verify against another reserve's commitment"
    );
}
