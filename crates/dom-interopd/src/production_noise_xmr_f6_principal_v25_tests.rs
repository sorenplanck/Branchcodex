//! Native original-journal provenance, without a completed C/D graph.
//! Candidates below use the permitted test seam inside the Noise boundary;
//! these are not socket/Noise handshake tests. All packet mathematics, local
//! custody, scoped retention, reopening and opaque-owner construction are real.
use super::*;
use crate::production_contracts_bootstrap::producer_v13::native_ceremony_tests::f6_source_fixture_v25::with_native_f6_source_fixture_v25;
use crate::production_f6::terms::ProductionNativeXmrDomFaceOwnerV25;

type TestResult = core::result::Result<(), Box<dyn std::error::Error>>;
const PEER_RECORD: &[u8] = b"xmr-peer-graph-offer-v25";

fn candidate(source: &ProductionNoiseGraphOfferV22) -> ProductionReceivedXmrGraphCandidateV22 {
    ProductionReceivedXmrGraphCandidateV22 {
        bytes: source.local.clone(),
    }
}

fn same_principal(
    left: &ProductionAuthenticatedXmrClaimPrincipalV25,
    right: &ProductionAuthenticatedXmrClaimPrincipalV25,
) -> TestResult {
    assert_eq!(left.route_id(), right.route_id());
    assert_eq!(left.terms(), right.terms());
    assert_eq!(left.policy(), right.policy());
    assert_eq!(left.chain(), right.chain());
    assert_eq!(left.beneficiary(), right.beneficiary());
    assert_eq!(left.participant_index(), right.participant_index());
    assert_eq!(left.direction(), right.direction());
    assert_eq!(left.offer().to_bytes()?, right.offer().to_bytes()?);
    Ok(())
}

#[test]
fn original_local_beneficiary_and_noise_peer_mint_identical_principal_owners_v25() -> TestResult {
    with_native_f6_source_fixture_v25(|fixture| {
        // Opening missing offers does not prepare a replacement wallet.
        assert!(fixture.reopen_actor(0).is_err());
        let mut alice = fixture.prepare_actor(0)?;
        let bob = fixture.prepare_actor(1)?;
        assert_eq!(
            *bob.source.native.participant_id(),
            bob.source.policy.policy().xmr_funder
        );
        assert_eq!(
            *alice.source.native.participant_id(),
            alice.source.policy.policy().dom_funder
        );
        assert!(bob
            .source
            .verify_f6_peer_principal_v25(&bob.mounted._shares[0], &candidate(&alice.source))
            .is_err());
        assert!(bob
            .source
            .reopen_f6_principal_v25(&alice.mounted._shares[0])
            .is_err());
        assert!(bob
            .source
            .reopen_f6_principal_v25(&bob.mounted._shares[1])
            .is_err());
        assert!(alice
            .source
            .reopen_f6_principal_v25(&alice.mounted._shares[0])?
            .is_none());
        let received = candidate(&bob.source);
        alice
            .source
            .verify_f6_peer_principal_v25(&alice.mounted._shares[0], &received)?;
        // Verification returns no principal token and does not publish state.
        assert!(alice.mounted._shares[0]
            .runtime_public_record_v16(PEER_RECORD)?
            .is_none());
        assert!(alice
            .source
            .reopen_f6_principal_v25(&alice.mounted._shares[0])?
            .is_none());
        let local = bob
            .source
            .reopen_f6_principal_v25(&bob.mounted._shares[0])?
            .ok_or("local principal missing")?;
        let peer =
            alice.mounted._shares[0].retain_peer_f6_principal_v25(&alice.source, &received)?;
        same_principal(&local, &peer)?;
        assert_eq!(local.beneficiary(), local.terms().dom_leg.beneficiary.0);
        assert_eq!(local.offer().kind(), XmrGraphPayoutKindV22::ClaimPrincipal);
        // No token fields are forged and no wallet revision is supplied.
        let _local_owner =
            ProductionNativeXmrDomFaceOwnerV25::from_authenticated_principal_v25(local)?;
        let _peer_owner =
            ProductionNativeXmrDomFaceOwnerV25::from_authenticated_principal_v25(peer)?;
        assert_eq!(
            alice.mounted._shares[0]
                .runtime_public_record_v16(PEER_RECORD)?
                .as_deref(),
            Some(received.bytes())
        );
        Ok(())
    })
}

#[test]
fn peer_principal_reopens_from_original_journal_without_recreating_local_material_v25() -> TestResult
{
    with_native_f6_source_fixture_v25(|fixture| {
        let mut alice = fixture.prepare_actor(0)?;
        let bob = fixture.prepare_actor(1)?;
        let received = candidate(&bob.source);
        // The generic public-record API cannot promote raw peer bytes into an
        // identity-bearing principal. Only the authenticated specialized API can.
        assert!(alice.mounted._shares[0]
            .retain_runtime_public_v16(PEER_RECORD, received.bytes())
            .is_err());
        assert!(alice.mounted._shares[0]
            .runtime_public_record_v16(PEER_RECORD)?
            .is_none());
        let original =
            alice.mounted._shares[0].retain_peer_f6_principal_v25(&alice.source, &received)?;
        let again =
            alice.mounted._shares[0].retain_peer_f6_principal_v25(&alice.source, &received)?;
        same_principal(&original, &again)?;
        let original_offer = original.offer().to_bytes()?;
        let local_packets = [alice.source.local.clone(), bob.source.local.clone()];
        assert_eq!(
            alice.mounted._shares[0]
                .runtime_public_record_v16(PEER_RECORD)?
                .as_deref(),
            Some(received.bytes())
        );
        drop((original, again, alice, bob));
        // All mounted journal/wallet owners have dropped before real reopen.
        // The bridge's reopen branch never calls wallet or proof producers.
        let alice = fixture.reopen_actor(0)?;
        let bob = fixture.reopen_actor(1)?;
        assert_eq!(alice.source.local, local_packets[0]);
        assert_eq!(bob.source.local, local_packets[1]);
        let peer = alice
            .source
            .reopen_f6_principal_v25(&alice.mounted._shares[0])?
            .ok_or("retained peer principal missing")?;
        let local = bob
            .source
            .reopen_f6_principal_v25(&bob.mounted._shares[0])?
            .ok_or("retained local principal missing")?;
        same_principal(&local, &peer)?;
        assert_eq!(peer.offer().to_bytes()?, original_offer);
        assert_eq!(
            alice.mounted._shares[0]
                .runtime_public_record_v16(PEER_RECORD)?
                .as_deref(),
            Some(received.bytes())
        );
        let _peer_owner =
            ProductionNativeXmrDomFaceOwnerV25::from_authenticated_principal_v25(peer)?;
        let _local_owner =
            ProductionNativeXmrDomFaceOwnerV25::from_authenticated_principal_v25(local)?;
        Ok(())
    })
}

/// A new mathematically valid proof from the SAME test beneficiary, not a new
/// authority. The opening belongs to Bob's synthetic fixture, never Alice.
fn alternative_valid_packet(
    source: &ProductionNoiseGraphOfferV22,
) -> core::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    use xmr_refund_policy::economic_graph::{produce_xmr_payout_value_proof_v12, XmrPayoutKindV12};
    let graph = source.decode_packet(&source.local, false)?;
    let principal = graph
        .payouts()
        .iter()
        .find(|offer| offer.kind() == XmrGraphPayoutKindV22::ClaimPrincipal)
        .ok_or("principal absent")?;
    let ownership = produce_xmr_payout_value_proof_v12(
        &source.terms,
        &source.policy,
        XmrPayoutKindV12::ClaimPrincipal,
        source.native.role(),
        source.native.trusted_chain_id(),
        &dom_adaptor::SigningShareV1::from_be_bytes([11; 32])?,
    )?;
    let alternative = XmrPolicyPayoutOfferV22::new(
        &source.terms,
        &source.policy,
        XmrGraphPayoutKindV22::ClaimPrincipal,
        principal.output().clone(),
        Some(ownership),
        source.native.trusted_chain_id(),
        source.native.role(),
    )?
    .to_bytes()?;
    let original = principal.to_bytes()?;
    assert_ne!(original, alternative);
    assert_eq!(original.len(), alternative.len());
    // Replace a unique, already decoded length-preserving public object; no
    // hand-maintained wire offsets or skipped packet validation are needed.
    let positions: Vec<_> = source
        .local
        .windows(original.len())
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == original.as_slice()).then_some(index))
        .collect();
    assert_eq!(positions.len(), 1);
    let mut bytes = source.local.clone();
    bytes[positions[0]..positions[0] + original.len()].copy_from_slice(&alternative);
    source.decode_packet(&bytes, false)?;
    Ok(bytes)
}

#[test]
fn valid_alternative_peer_proof_cannot_replace_original_retained_principal_v25() -> TestResult {
    with_native_f6_source_fixture_v25(|fixture| {
        let mut alice = fixture.prepare_actor(0)?;
        let bob = fixture.prepare_actor(1)?;
        let original = candidate(&bob.source);
        alice.mounted._shares[0].retain_peer_f6_principal_v25(&alice.source, &original)?;
        let changed = ProductionReceivedXmrGraphCandidateV22 {
            bytes: alternative_valid_packet(&bob.source)?,
        };
        // The replacement is independently valid under the exact original
        // beneficiary/terms. Its refusal therefore tests durable immutability,
        // not merely malformed or mathematically invalid packet rejection.
        alice
            .source
            .verify_f6_peer_principal_v25(&alice.mounted._shares[0], &changed)?;
        assert!(alice.mounted._shares[0]
            .retain_peer_f6_principal_v25(&alice.source, &changed)
            .is_err());
        assert_eq!(
            alice.mounted._shares[0]
                .runtime_public_record_v16(PEER_RECORD)?
                .as_deref(),
            Some(original.bytes())
        );
        let unretained_source = ProductionNoiseGraphOfferV22::new(
            bob.source.route_id,
            bob.source.terms.clone(),
            bob.source.policy.clone(),
            bob.source.native.clone(),
            changed.bytes.clone(),
        )?;
        assert!(unretained_source
            .reopen_f6_principal_v25(&bob.mounted._shares[0])
            .is_err());
        drop((alice, bob));
        let mut reopened = fixture.reopen_actor(0)?;
        assert!(reopened.mounted._shares[0]
            .retain_peer_f6_principal_v25(&reopened.source, &changed)
            .is_err());
        assert_eq!(
            reopened.mounted._shares[0]
                .runtime_public_record_v16(PEER_RECORD)?
                .as_deref(),
            Some(original.bytes())
        );
        assert!(reopened
            .source
            .reopen_f6_principal_v25(&reopened.mounted._shares[0])?
            .is_some());
        Ok(())
    })
}

#[test]
fn other_payouts_terms_and_corrupt_packets_never_publish_peer_principal_v25() -> TestResult {
    with_native_f6_source_fixture_v25(|fixture| {
        let mut alice = fixture.prepare_actor(0)?;
        let bob = fixture.prepare_actor(1)?;
        let graph = bob.source.decode_packet(&bob.source.local, false)?;
        let compensation = graph
            .payouts()
            .iter()
            .find(|offer| offer.kind() == XmrGraphPayoutKindV22::Compensation)
            .ok_or("compensation absent")?;
        compensation.verify(
            &bob.source.terms,
            &bob.source.policy,
            bob.source.native.trusted_chain_id(),
            bob.source.native.role(),
        )?;
        let mut bad = vec![
            candidate(&alice.source),
            ProductionReceivedXmrGraphCandidateV22 {
                bytes: compensation.to_bytes()?,
            },
        ];
        let principal = graph
            .payouts()
            .iter()
            .find(|offer| offer.kind() == XmrGraphPayoutKindV22::ClaimPrincipal)
            .ok_or("principal absent")?
            .to_bytes()?;
        let offset = bob
            .source
            .local
            .windows(principal.len())
            .position(|bytes| bytes == principal.as_slice())
            .ok_or("principal framing absent")?;
        let mut relabelled = bob.source.local.clone();
        // Canonical DXPO22 header is eight bytes; change only the payout kind
        // inside a genuine complete graph packet, retaining all original scope.
        relabelled[offset + 8] = XmrGraphPayoutKindV22::Compensation as u8;
        bad.push(ProductionReceivedXmrGraphCandidateV22 { bytes: relabelled });
        for mutation in 0..4 {
            let mut bytes = bob.source.local.clone();
            match mutation {
                0 => bytes[8] ^= 1, // actual route pin in the public graph framing
                1 => {
                    bytes.pop();
                }
                2 => bytes.push(0),
                _ => {
                    let end = bytes.len() - 1;
                    bytes[end] ^= 1;
                }
            }
            bad.push(ProductionReceivedXmrGraphCandidateV22 { bytes });
        }
        for rejected in bad {
            assert!(alice.mounted._shares[0]
                .retain_peer_f6_principal_v25(&alice.source, &rejected)
                .is_err());
            assert!(alice.mounted._shares[0]
                .runtime_public_record_v16(PEER_RECORD)?
                .is_none());
        }
        let mut other_terms = bob.source.terms.clone();
        other_terms.policy_version += 1;
        assert!(ProductionNoiseGraphOfferV22::new(
            bob.source.route_id,
            other_terms,
            bob.source.policy.clone(),
            bob.source.native.clone(),
            bob.source.local.clone()
        )
        .is_err());
        assert!(alice
            .source
            .reopen_f6_principal_v25(&alice.mounted._shares[0])?
            .is_none());
        // Refusals left the original scope usable for its genuine peer.
        alice.mounted._shares[0]
            .retain_peer_f6_principal_v25(&alice.source, &candidate(&bob.source))?;
        assert!(alice
            .source
            .reopen_f6_principal_v25(&alice.mounted._shares[0])?
            .is_some());
        Ok(())
    })
}
