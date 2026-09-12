//! Unit tests of exact key/template selection, not graph economic admission.
//! The private fixture intentionally has no BP/offer/identity authority.
use super::*;
use dom_consensus::TransactionKernel;
use dom_crypto::{pedersen::Commitment, SecretKey};

#[path = "graph_proposal_v22_tests.rs"]
mod proposal_tests;

fn graph_binding(
    material: &XmrGraphKeyMaterialV22,
) -> dom_scriptless_crypto::XmrRecoveryGraphBindingV11 {
    let point = |index: usize| material.aggregates[index].to_compressed_bytes();
    dom_scriptless_crypto::XmrRecoveryGraphBindingV11 {
        chain_id: material.chain,
        session_id: material.session,
        terms_hash: material.terms,
        funding_commitment: point(0),
        cancelled_commitment: point(1),
        refund_recipient_commitment: point(2),
        punish_recipient_commitment: point(3),
        claim_adaptor_point: point(4),
        refund_adaptor_point: material.keys[0][0].to_compressed_bytes(),
        cancel_height: 20,
        punish_height: 40,
        reveal_safety_blocks: 5,
        cancel_fee: 1,
        refund_fee: 2,
        punish_fee: 3,
    }
}

fn bound_fixture() -> Result<XmrGraphSigningKeysV22, Box<dyn std::error::Error>> {
    let (material, transactions) = fixture()?;
    let templates = material.transaction_hashes(transactions.each_ref())?;
    Ok(XmrGraphSigningKeysV22 {
        binding: graph_binding(&material),
        material,
        templates,
    })
}

fn fixture() -> Result<(XmrGraphKeyMaterialV22, [Transaction; 5]), Box<dyn std::error::Error>> {
    let keys = [0u8, 1].map(|participant| {
        [0u8, 1, 2, 3, 4].map(|stage| {
            SecretKey::from_bytes(&[3 + participant * 10 + stage; 32])
                .expect("valid deterministic scalar")
                .public_key()
        })
    });
    let aggregates = std::array::from_fn(|index| {
        dom_adaptor::aggregate_public_nonces_v1(&[keys[0][index].clone(), keys[1][index].clone()])
            .expect("distinct non-opposite keys")
    });
    let material = XmrGraphKeyMaterialV22 {
        chain: [10; 32],
        route: [13; 32],
        policy_hash: [14; 32],
        directions: [DirectionV1::Initiator, DirectionV1::Responder],
        session: [11; 32],
        terms: [12; 32],
        participants: [[1; 32], [2; 32]],
        keys,
        aggregates,
        offsets: [[0; 32]; 5],
        packets: [Vec::new(), Vec::new()],
    };
    let fee = dom_core::Amount::from_noms(1)?;
    let transactions = std::array::from_fn(|index| Transaction {
        inputs: Vec::new(),
        outputs: Vec::new(),
        kernels: vec![TransactionKernel {
            features: 0,
            fee,
            lock_height: 0,
            excess: Commitment::from_compressed_bytes(
                &material.aggregates[index].to_compressed_bytes(),
            )
            .expect("valid public point"),
            excess_signature: [0; 65],
        }],
        offset: [0; 32],
    });
    Ok((material, transactions))
}

#[test]
fn graph_keys_require_exact_route_and_native_store_scope() -> Result<(), Box<dyn std::error::Error>>
{
    let chain = dom_adaptor::TrustedChainIdV1::from_authenticated_genesis(
        0x4455_6677,
        &dom_core::Hash256::from_bytes([0x91; 32]),
    );
    let other_chain = dom_adaptor::TrustedChainIdV1::from_authenticated_genesis(
        0x4455_6677,
        &dom_core::Hash256::from_bytes([0x92; 32]),
    );
    let mut keys = bound_fixture()?;
    keys.material.chain = *chain.as_bytes();
    keys.binding.chain_id = *chain.as_bytes();
    let check = |chain, session, terms, participants, directions| {
        keys.require_scope(chain, session, terms, participants, directions)
    };
    let material = &keys.material;
    keys.require_route(material.route)?;
    assert!(keys.require_route([0; 32]).is_err());
    let mut other_route = material.route;
    other_route[0] ^= 1;
    assert!(keys.require_route(other_route).is_err());
    check(
        &chain,
        material.session,
        material.terms,
        material.participants,
        material.directions,
    )?;
    assert!(check(
        &other_chain,
        material.session,
        material.terms,
        material.participants,
        material.directions
    )
    .is_err());
    for field in 0..4 {
        let mut session = material.session;
        let mut terms = material.terms;
        let mut participants = material.participants;
        let mut directions = material.directions;
        match field {
            0 => session[0] ^= 1,
            1 => terms[0] ^= 1,
            2 => participants.swap(0, 1),
            _ => directions.swap(0, 1),
        }
        assert!(check(&chain, session, terms, participants, directions).is_err());
    }
    for index in 0..2 {
        let mut participants = material.participants;
        participants[index][0] ^= 1;
        assert!(check(
            &chain,
            material.session,
            material.terms,
            participants,
            material.directions
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn every_graph_key_requires_its_participant_stage_and_exact_template(
) -> Result<(), Box<dyn std::error::Error>> {
    let bound = bound_fixture()?;
    for stage in XmrGraphSigningStageV22::ALL {
        for participant in 0..2 {
            assert_eq!(
                bound.key(
                    stage,
                    bound.material.participants[participant],
                    bound.template_hash(stage)
                )?,
                &bound.material.keys[participant][stage as usize]
            );
            for other in XmrGraphSigningStageV22::ALL {
                if stage != other {
                    assert!(bound
                        .key(
                            stage,
                            bound.material.participants[participant],
                            bound.template_hash(other)
                        )
                        .is_err());
                }
            }
        }
        assert!(bound
            .key(stage, [99; 32], bound.template_hash(stage))
            .is_err());
        assert!(bound.key(stage, [1; 32], [0; 32]).is_err());
    }
    Ok(())
}

#[test]
fn changed_excess_offset_signature_or_kernel_count_refuses_the_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let (material, transactions) = fixture()?;
    material.transaction_hashes(transactions.each_ref())?;
    for index in 0..5 {
        for mutation in 0..5 {
            let mut changed = transactions.clone();
            match mutation {
                0 => {
                    changed[index].kernels[0].excess =
                        transactions[(index + 1) % 5].kernels[0].excess.clone()
                }
                1 => changed[index].offset[31] = 1,
                2 => changed[index].kernels[0].excess_signature[0] = 1,
                3 => changed[index].kernels.clear(),
                _ => changed[index]
                    .kernels
                    .push(transactions[index].kernels[0].clone()),
            }
            assert!(
                material.transaction_hashes(changed.each_ref()).is_err(),
                "stage {index}, mutation {mutation}"
            );
        }
    }
    Ok(())
}

#[test]
fn an_economic_template_change_cannot_reuse_the_old_key_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let (material, mut transactions) = fixture()?;
    let templates = material.transaction_hashes(transactions.each_ref())?;
    let bound = XmrGraphSigningKeysV22 {
        binding: graph_binding(&material),
        material,
        templates,
    };
    for stage in XmrGraphSigningStageV22::ALL {
        transactions[stage as usize].kernels[0].lock_height = 42;
        let changed = canonical_template_v1(&transactions[stage as usize])?.1;
        assert_ne!(changed, bound.template_hash(stage));
        assert!(bound.key(stage, [1; 32], changed).is_err());
        assert!(bound.key(stage, [2; 32], changed).is_err());
    }
    Ok(())
}
