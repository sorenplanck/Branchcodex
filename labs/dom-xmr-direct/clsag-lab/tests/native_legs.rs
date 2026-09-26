//! Native transaction checks on synthetic funding fixtures, not chain evidence.
#[path = "support/dom_claim.rs"]
mod dom;

use dom_scriptless_primitives::SecretScalar;
use dom_serialization::{DomDeserialize, DomSerialize};
use rand_core::OsRng;
use xmr_dleq_sigma::CrossCurveSecret252;

#[test]
fn native_dom_claim_roundtrips_validates_and_extracts_only_exact_transaction() {
    let shared = CrossCurveSecret252::generate(&mut OsRng);
    let secret = SecretScalar::from_be_bytes(shared.dom_secret_big_endian()).unwrap();
    let fixture = dom::Fixture::new();
    let point = secret.public_key().unwrap().to_compressed_bytes();
    let offer = fixture.offer(&point);
    let tx = offer.complete(&secret, &dom::context()).unwrap();
    let decoded = dom_consensus::Transaction::from_bytes(&tx.to_bytes().unwrap()).unwrap();
    dom_consensus::validate_transaction(&decoded, &dom::context()).unwrap();
    assert_eq!(
        *offer.extract(&decoded, &dom::context()).unwrap(),
        shared.dom_secret_big_endian()
    );
    // Consensus accepts a different kernel signature for the same body;
    // extraction must additionally prove that it completes THIS adaptor offer.
    let other_offer = fixture.offer(&point);
    let other_final = other_offer.complete(&secret, &dom::context()).unwrap();
    assert!(offer.extract(&other_final, &dom::context()).is_err());
    for change in 0..7 {
        let mut altered = tx.clone();
        match change {
            0 => {
                altered.inputs[0].commitment =
                    dom::Fixture::new().claim.unsigned_transaction().inputs[0]
                        .commitment
                        .clone()
            }
            1 => {
                altered.outputs[0] =
                    dom::Fixture::new().claim.unsigned_transaction().outputs[0].clone()
            }
            2 => altered.offset[0] ^= 1,
            3 => altered.kernels[0].fee = dom_core::Amount::from_noms(100_001).unwrap(),
            4 => altered.kernels[0].excess_signature[40] ^= 1,
            5 => altered.kernels.clear(),
            _ => altered.outputs[0].proof[10] ^= 1,
        }
        assert!(offer.extract(&altered, &dom::context()).is_err());
    }
    let mut wrong_chain = dom::context();
    wrong_chain.chain_id[0] ^= 1;
    assert!(offer.extract(&tx, &wrong_chain).is_err());
    assert!(offer
        .complete(
            &SecretScalar::from_be_bytes([1; 32]).unwrap(),
            &dom::context()
        )
        .is_err());
    assert_ne!(
        fixture.claim.binding().unwrap(),
        dom::Fixture::new().claim.binding().unwrap()
    );
}

#[test]
fn presigned_dom_refund_is_height_locked_and_cannot_be_rewritten_as_plain() {
    use dom_core::{BlockHeight, DomError, KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN};
    use dxp1_clsag_lab::native_dom::PreparedDomClaim;
    let mut fixture = dom::Fixture::new();
    let original_binding = fixture.claim.binding().unwrap();
    let mut unsigned = fixture.claim.unsigned_transaction().clone();
    unsigned.kernels[0].features = KERNEL_FEAT_HEIGHT_LOCKED;
    unsigned.kernels[0].lock_height = 110;
    assert!(PreparedDomClaim::new(unsigned.clone(), dom::context().chain_id).is_err());
    for height in [0, 109, 111] {
        assert!(PreparedDomClaim::new_height_locked_refund(
            unsigned.clone(),
            dom::context().chain_id,
            height
        )
        .is_err());
    }
    fixture.claim =
        PreparedDomClaim::new_height_locked_refund(unsigned, dom::context().chain_id, 110).unwrap();
    assert_ne!(fixture.claim.binding().unwrap(), original_binding);
    let secret = SecretScalar::from_be_bytes([1; 32]).unwrap();
    let offer = fixture.offer(&secret.public_key().unwrap().to_compressed_bytes());
    assert!(matches!(
        offer.complete(&secret, &dom::context()),
        Err(DomError::TemporarilyInvalid(_))
    ));
    // Prepare the full signed refund off-chain at its declared validity height.
    let mut at_expiry = dom::context();
    at_expiry.current_height = BlockHeight(110);
    let refund = offer.complete(&secret, &at_expiry).unwrap();
    let refund = dom_consensus::Transaction::from_bytes(&refund.to_bytes().unwrap()).unwrap();
    for height in [100, 109] {
        let mut context = dom::context();
        context.current_height = BlockHeight(height);
        assert!(matches!(
            dom_consensus::validate_transaction(&refund, &context),
            Err(DomError::TemporarilyInvalid(_))
        ));
    }
    for height in [110, 111] {
        let mut context = dom::context();
        context.current_height = BlockHeight(height);
        dom_consensus::validate_transaction(&refund, &context).unwrap();
    }
    let mut plain = refund.clone();
    plain.kernels[0].features = KERNEL_FEAT_PLAIN;
    plain.kernels[0].lock_height = 0;
    assert!(dom_consensus::validate_transaction(&plain, &dom::context()).is_err());
    let mut earlier = refund;
    earlier.kernels[0].lock_height = 100;
    assert!(dom_consensus::validate_transaction(&earlier, &dom::context()).is_err());
    assert!(offer.extract(&earlier, &at_expiry).is_err());
}
