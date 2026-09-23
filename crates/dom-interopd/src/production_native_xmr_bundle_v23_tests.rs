//! Test-only canonical writer for an admitted native XMR daemon position.
//! Resource paths point at owners provisioned by the real session initializer;
//! this module neither creates those owners nor substitutes missing witnesses.
use super::*;
#[path = "production_native_xmr_enrollment_bundle_v23_tests.rs"]
mod enrollment_wire_v23;
#[path = "production_native_xmr_bundle_entrypoints_v23_tests.rs"]
mod entrypoints_v23;
pub(crate) use entrypoints_v23::{
    encode_native_xmr_bundle_from_plan_v23, encode_native_xmr_bundle_v23,
};

pub(crate) struct NativeXmrBundleResourcesV23 {
    pub local_participant_id: [u8; 32],
    pub secret_store: String,
    pub sidecar_socket: String,
    pub sidecar_timeout_ms: u64,
    pub custody_directory: String,
    pub sealing_key_file: String,
    pub custody_id: [u8; 32],
    pub nullifier_store: String,
    /// Only the actual XMR funder supplies its retained canonical transaction.
    pub private_funding: Option<(String, u64)>,
}

fn encode_native_xmr_wire_v23(
    session: &crate::production_inputs::AuthenticatedXmrSessionBindingsV1,
    terms: &kaystra_core::terms::SettlementTermsV1,
    mut descriptor: ProductionUniversalLegV11,
    compensation_policy: &XmrCompensationPolicyV11,
    resources: NativeXmrBundleResourcesV23,
) -> Result<(ProductionUniversalLegV11, Vec<u8>), Box<dyn std::error::Error>> {
    if session.native_enrollment_v23().is_some() {
        return enrollment_wire_v23::encode_enrollment_wire_v23(
            session,
            terms,
            descriptor,
            compensation_policy,
            resources,
        );
    }
    let refund = session
        .refund_bundle()
        .ok_or("native daemon refund proof absent")?;
    compensation_policy.validate_for(terms)?;
    if compensation_policy.bounded_availability_v23.is_none()
        || resources.custody_id == [0; 32]
        || ![
            terms.counterparty_leg.beneficiary.0,
            terms.counterparty_leg.refund_to.0,
        ]
        .contains(&resources.local_participant_id)
        || terms.counterparty_leg.beneficiary == terms.counterparty_leg.refund_to
        || resources.secret_store == resources.sidecar_socket
        || Path::new(&resources.custody_directory).components().count() != 1
    {
        return Err("native XMR planned resource/role binding".into());
    }
    for path in [
        &resources.secret_store,
        &resources.sidecar_socket,
        &resources.custody_directory,
        &resources.sealing_key_file,
        &resources.nullifier_store,
    ] {
        relative_path(path)?;
    }
    require_milliseconds(
        resources.sidecar_timeout_ms,
        crate::production_universal_leg_authority::MAX_SIDECAR_CALL_MS_V26,
    )?;
    if let Some((path, fee)) = &resources.private_funding {
        relative_path(path)?;
        if resources.local_participant_id != terms.counterparty_leg.refund_to.0
            || *fee == 0
            || u128::from(*fee) > terms.fee_limit.counterparty_max
            || path == &resources.secret_store
            || path == &resources.sidecar_socket
        {
            return Err("native XMR planned funding resource binding".into());
        }
    }
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
        authority: WireAuthorityV11::Monero(ProductionUniversalXmrAuthorityV11 {
            scope: None,
            validated_compensation: None,
            compensation_policy: compensation_policy.to_bytes()?,
            local_participant_id: resources.local_participant_id,
            setup_binding_hash: session.setup().binding_hash(),
            refund_template_hash: refund.template_hash,
            refund_point_sec1: refund.adaptor_point_sec1.to_vec(),
            secret_store: resources.secret_store,
            sidecar_socket: resources.sidecar_socket,
            sidecar_timeout_ms: resources.sidecar_timeout_ms,
            private_funding_v12: resources.private_funding.map(
                |(raw_transaction_file, max_fee_piconero)| ProductionXmrPrivateFundingConfigV12 {
                    raw_transaction_file,
                    max_fee_piconero,
                },
            ),
            recovery_v22: None,
            recovery_v23: Some(ProductionXmrRecoveryResourcesV23 {
                directory: resources.custody_directory,
                sealing_key_file: resources.sealing_key_file,
                custody_id: resources.custody_id,
                nullifier_store: resources.nullifier_store,
            }),
        }),
    };
    let bytes = serde_json::to_vec(&wire)?;
    descriptor.authority_bundle_digest = ProductionUniversalLegV11::bundle_digest(&bytes)?;
    Ok((descriptor, bytes))
}
