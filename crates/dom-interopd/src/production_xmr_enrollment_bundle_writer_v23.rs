//! Canonical public resource description for a pre-template XMR position.
//! No registration, credential, remote availability or economic grant is minted.
use super::*;
use crate::production_inputs::ProductionXmrEnrollmentBundleV23;
use kaystra_core::terms::SettlementTermsV1;
use xmr_refund_policy::NonCooperativeRefundCapability as _;
use xmr_session_init::PreparedXmrShareEnrollmentV23;

/// Existing private candidate file, supplied only by the actual XMR funder.
/// These are public references/bounds, not raw transaction bytes or a signer.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionXmrEnrollmentFundingFileV23 {
    /// Canonical state-relative location of an independently prepared candidate.
    pub raw_transaction_file: String,
    /// Nonzero fee ceiling, also bounded by the negotiated terms.
    pub max_fee_piconero: u64,
}

/// Explicit operator-owned resources. Encoding does not access or create them.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionXmrEnrollmentLegResourcesV23 {
    /// Exact beneficiary or refund participant in the frozen XMR terms.
    pub local_participant_id: [u8; 32],
    /// Existing encrypted SDK store, e.g. `custodia-xmr/secrets.sqlite`.
    pub secret_store: String,
    /// Existing independently provisioned authenticated sidecar socket.
    pub sidecar_socket: String,
    /// Nonzero timeout bounded by the existing daemon limit of 180000 ms.
    pub sidecar_timeout_ms: u64,
    /// One root-level directory name for the separate native graph archive.
    /// This is not the directory containing the encrypted enrollment databases.
    pub custody_directory: String,
    /// Existing independent recovery sealing credential file, never its bytes.
    pub sealing_key_file: String,
    /// Explicit nonzero identity of the native graph custody archive.
    pub custody_id: [u8; 32],
    /// Existing SDK nullifier database, e.g. `custodia-xmr/nullifiers.sqlite`.
    pub nullifier_store: String,
    /// Required for the XMR funder; forbidden for the claim receiver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_funding: Option<ProductionXmrEnrollmentFundingFileV23>,
}

/// Writes the exact `XMR_ENROLLMENT_V23` wire and manifest digest consumed by
/// the existing native daemon loader. Neither the prepared SDK token nor the
/// resulting bytes grant route admission, F6, signing or secret revelation.
///
/// The caller supplies existing negotiated terms, both public enrollment
/// proofs, compensation/availability policy and local resource references.
/// All cross-registry trust, actual resource opening and economic authority
/// remain with the unchanged authenticated daemon admission path.
pub fn encode_xmr_enrollment_leg_authority_bundle_v23(
    terms: &SettlementTermsV1,
    enrollment: &PreparedXmrShareEnrollmentV23,
    public_enrollment: &ProductionXmrEnrollmentBundleV23,
    compensation_policy: &XmrCompensationPolicyV11,
    resources: ProductionXmrEnrollmentLegResourcesV23,
) -> Result<ProductionLegBundleV22, Refusal> {
    // The decoder receives this metadata only after participant authentication.
    // Public callers of this writer must prove the same link explicitly; a
    // structurally decoded public bundle alone is not an authenticated session.
    let claim = public_enrollment.proof().bundle.claim;
    if claim.secp_compressed != *public_enrollment.adaptor_point_sec1()
        || xmr_refund_adaptor::DomRefundAdaptorExecutor::new(claim).profile_hash()
            != public_enrollment.executor_profile_hash()
    {
        return Err(Refusal::Conflict);
    }
    let value = ProductionUniversalXmrEnrollmentAuthorityV23 {
        scope: None,
        validated_compensation: None,
        compensation_policy: compensation_policy
            .to_bytes()
            .map_err(|_| Refusal::Conflict)?,
        local_participant_id: resources.local_participant_id,
        setup_binding_hash: enrollment.setup().binding_hash(),
        refund_point_sec1: public_enrollment.adaptor_point_sec1().to_vec(),
        executor_profile_hash: public_enrollment.executor_profile_hash(),
        refund_deadline: public_enrollment.deadline(),
        refund_destination: public_enrollment.refund_destination().to_owned(),
        secret_store: resources.secret_store,
        sidecar_socket: resources.sidecar_socket,
        sidecar_timeout_ms: resources.sidecar_timeout_ms,
        private_funding_v12: resources.private_funding.map(|candidate| {
            ProductionXmrPrivateFundingConfigV12 {
                raw_transaction_file: candidate.raw_transaction_file,
                max_fee_piconero: candidate.max_fee_piconero,
            }
        }),
        recovery_v23: ProductionXmrRecoveryResourcesV23 {
            directory: resources.custody_directory,
            sealing_key_file: resources.sealing_key_file,
            custody_id: resources.custody_id,
            nullifier_store: resources.nullifier_store,
        },
    };
    value.validate_enrollment_parameters_v23(
        terms,
        enrollment.setup(),
        enrollment,
        public_enrollment,
    )?;
    encode_wire_v22(
        &ProductionLegBundleIdentityV22 {
            settlement_id: terms.settlement_id.0,
            session_id: terms.session_id.0,
            chain_id: terms.counterparty_leg.chain_id.0,
            terms_hash: terms.terms_hash().map_err(|_| Refusal::Conflict)?,
        },
        WireAuthorityV11::MoneroEnrollment(value),
    )
}

#[cfg(test)]
#[path = "production_xmr_enrollment_bundle_writer_v23_tests.rs"]
mod tests;
