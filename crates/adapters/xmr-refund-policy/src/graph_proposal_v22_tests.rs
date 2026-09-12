//! Exact unsigned proposal encoding only; the fixture is not a graph authority.
use super::*;

#[test]
fn proposal_is_fixed_length_and_rejects_every_byte_change_or_wrong_length(
) -> Result<(), Box<dyn std::error::Error>> {
    let proposal = bound_fixture()?.proposal()?;
    let bytes = proposal.as_bytes();
    assert_eq!(bytes.len(), 704);
    assert_eq!(&bytes[..8], b"DXGP22\0\x01");
    assert_eq!(&bytes[8..40], &[10; 32]);
    assert_eq!(&bytes[40..72], &[13; 32]);
    assert_eq!(&bytes[672..704], &[14; 32]);
    proposal.require_matches(bytes)?;
    for index in 0..bytes.len() {
        let mut changed = *bytes;
        changed[index] ^= 1;
        assert!(proposal.require_matches(&changed).is_err(), "byte {index}");
    }
    for length in 0..bytes.len() {
        assert!(proposal.require_matches(&bytes[..length]).is_err());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(proposal.require_matches(&trailing).is_err());
    assert_eq!(proposal.digest(), bound_fixture()?.proposal()?.digest());
    Ok(())
}

#[test]
fn proposal_digest_binds_every_scope_offer_template_point_and_recovery_parameter(
) -> Result<(), Box<dyn std::error::Error>> {
    let original = bound_fixture()?.proposal()?;
    // Mutate each source field, not merely its already-encoded byte: omitting a
    // field from the writer must be caught even though equality checks still work.
    for field in 0..30 {
        let mut changed = bound_fixture()?;
        match field {
            0 => changed.material.chain[0] ^= 1,
            1 => changed.material.route[0] ^= 1,
            2 => changed.material.session[0] ^= 1,
            3 => changed.material.terms[0] ^= 1,
            4..=5 => changed.material.participants[field - 4][0] ^= 1,
            6 => changed.material.directions[0] = DirectionV1::Responder,
            7 => changed.material.directions[1] = DirectionV1::Initiator,
            8..=9 => changed.material.packets[field - 8].push(1),
            10..=14 => changed.templates[field - 10][0] ^= 1,
            15 => changed.binding.funding_commitment[1] ^= 1,
            16 => changed.binding.cancelled_commitment[1] ^= 1,
            17 => changed.binding.refund_recipient_commitment[1] ^= 1,
            18 => changed.binding.punish_recipient_commitment[1] ^= 1,
            19 => changed.binding.claim_adaptor_point[1] ^= 1,
            20 => changed.binding.refund_adaptor_point[1] ^= 1,
            21 => changed.binding.cancel_height += 1,
            22 => changed.binding.punish_height += 1,
            23 => changed.binding.reveal_safety_blocks += 1,
            24 => changed.binding.cancel_fee += 1,
            25 => changed.binding.refund_fee += 1,
            26 => changed.binding.punish_fee += 1,
            27 => changed.material.policy_hash[0] ^= 1,
            28 => changed.material.participants.swap(0, 1),
            _ => changed.templates.swap(2, 4),
        }
        let proposal = changed.proposal()?;
        assert_ne!(original.digest(), proposal.digest(), "source field {field}");
        assert!(original.require_matches(proposal.as_bytes()).is_err());
    }
    Ok(())
}
