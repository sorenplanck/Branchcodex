//! Canonical writer of the NEW pre-template authority discriminator, using
//! an authenticated native-enrollment session. Never fills the legacy pin.
use super::*;

pub(super) fn encode_enrollment_wire_v23(
    session: &crate::production_inputs::AuthenticatedXmrSessionBindingsV1,
    terms: &kaystra_core::terms::SettlementTermsV1,
    mut descriptor: ProductionUniversalLegV11,
    compensation_policy: &XmrCompensationPolicyV11,
    resources: NativeXmrBundleResourcesV23,
) -> Result<(ProductionUniversalLegV11, Vec<u8>), Box<dyn std::error::Error>> {
    let bundle = session
        .native_enrollment_bundle_v23()
        .ok_or("native enrollment public bundle is absent")?;
    let enrollment = session
        .native_enrollment_v23()
        .ok_or("native enrollment absent")?;
    if session.refund_bundle().is_some()
        || session.session_id() != terms.session_id.0
        || session.terms_digest() != terms.terms_hash()?
        || session.setup().terms_hash() != session.terms_digest()
        || session.setup().binding_hash() != enrollment.setup().binding_hash()
    {
        return Err("native enrollment session/terms mismatch".into());
    }
    let encoded = encode_xmr_enrollment_leg_authority_bundle_v23(
        terms,
        enrollment,
        bundle,
        compensation_policy,
        ProductionXmrEnrollmentLegResourcesV23 {
            local_participant_id: resources.local_participant_id,
            secret_store: resources.secret_store,
            sidecar_socket: resources.sidecar_socket,
            sidecar_timeout_ms: resources.sidecar_timeout_ms,
            private_funding: resources.private_funding.map(
                |(raw_transaction_file, max_fee_piconero)| ProductionXmrEnrollmentFundingFileV23 {
                    raw_transaction_file,
                    max_fee_piconero,
                },
            ),
            custody_directory: resources.custody_directory,
            sealing_key_file: resources.sealing_key_file,
            custody_id: resources.custody_id,
            nullifier_store: resources.nullifier_store,
        },
    )?;
    descriptor.family = ProductionChainFamilyV11::Xmr;
    descriptor.chain_id = terms.counterparty_leg.chain_id.0;
    descriptor.settlement_id = terms.settlement_id.0;
    descriptor.session_id = terms.session_id.0;
    descriptor.authority_bundle_digest = encoded.digest();
    Ok((descriptor, encoded.bytes().to_vec()))
}
