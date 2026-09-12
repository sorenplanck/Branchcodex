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
    let value = ProductionUniversalXmrEnrollmentAuthorityV23 {
        scope: None,
        validated_compensation: None,
        compensation_policy: compensation_policy.to_bytes()?,
        local_participant_id: resources.local_participant_id,
        setup_binding_hash: session.setup().binding_hash(),
        refund_point_sec1: bundle.adaptor_point_sec1().to_vec(),
        executor_profile_hash: bundle.executor_profile_hash(),
        refund_deadline: bundle.deadline(),
        refund_destination: bundle.refund_destination().to_owned(),
        secret_store: resources.secret_store,
        sidecar_socket: resources.sidecar_socket,
        sidecar_timeout_ms: resources.sidecar_timeout_ms,
        private_funding_v12: resources.private_funding.map(
            |(raw_transaction_file, max_fee_piconero)| ProductionXmrPrivateFundingConfigV12 {
                raw_transaction_file,
                max_fee_piconero,
            },
        ),
        recovery_v23: ProductionXmrRecoveryResourcesV23 {
            directory: resources.custody_directory,
            sealing_key_file: resources.sealing_key_file,
            custody_id: resources.custody_id,
            nullifier_store: resources.nullifier_store,
        },
    };
    // Same public policy/path/identity checks as real decoding, but no scope
    // token is manufactured. First-export subsequently invokes full admission.
    value.validate_public_inputs_v23(session, terms)?;
    descriptor.family = ProductionChainFamilyV11::Xmr;
    descriptor.chain_id = terms.counterparty_leg.chain_id.0;
    descriptor.settlement_id = terms.settlement_id.0;
    descriptor.session_id = terms.session_id.0;
    let wire = WireV11 {
        format: FORMAT.to_owned(),
        settlement_id: descriptor.settlement_id,
        session_id: descriptor.session_id,
        chain_id: descriptor.chain_id,
        terms_hash: terms.terms_hash()?,
        authority: WireAuthorityV11::MoneroEnrollment(value),
    };
    let bytes = serde_json::to_vec(&wire)?;
    descriptor.authority_bundle_digest = ProductionUniversalLegV11::bundle_digest(&bytes)?;
    Ok((descriptor, bytes))
}
