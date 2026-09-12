//! Public pre-template enrollment. This is not an executable refund policy.
use super::*;

/// Native enrollment commits U and the economic refund constraints before
/// C/D exist. No template placeholder is representable in this profile.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionXmrEnrollmentBundleV23 {
    proof: BoundCrossCurveProofV1,
    adaptor_point_sec1: [u8; 33],
    executor_profile_hash: Digest32,
    deadline: u64,
    refund_destination: String,
}

impl ProductionXmrEnrollmentBundleV23 {
    /// Structural validation only; participant admission verifies both DLEQs.
    pub fn new(
        proof: BoundCrossCurveProofV1,
        adaptor_point_sec1: [u8; 33],
        executor_profile_hash: Digest32,
        deadline: u64,
        refund_destination: String,
    ) -> Result<Self, ProductionInputErrorV1> {
        validate_xmr_destination_v10(&refund_destination)?;
        if executor_profile_hash == ZERO_DIGEST
            || deadline == 0
            || !matches!(adaptor_point_sec1[0], 2 | 3)
            || proof.bundle.proof.is_empty()
            || proof.bundle.proof.len() > xmr_dleq_sigma::MAX_PROOF_BYTES
        {
            return Err(ProductionInputErrorV1::InvalidParticipantBundle);
        }
        Ok(Self {
            proof,
            adaptor_point_sec1,
            executor_profile_hash,
            deadline,
            refund_destination,
        })
    }

    /// Authenticated public U proof, never a private share or execution grant.
    pub fn proof(&self) -> &BoundCrossCurveProofV1 {
        &self.proof
    }
    /// Exact U point to bind after native graph formation.
    pub fn adaptor_point_sec1(&self) -> &[u8; 33] {
        &self.adaptor_point_sec1
    }
    /// Refund executor negotiated before native output creation.
    pub fn executor_profile_hash(&self) -> Digest32 {
        self.executor_profile_hash
    }
    /// Numeric deadline; its unit must be authenticated from the frozen terms.
    pub fn deadline(&self) -> u64 {
        self.deadline
    }
    /// Refund recipient committed by the immutable participant bundle.
    pub fn refund_destination(&self) -> &str {
        &self.refund_destination
    }

    pub(super) fn encode_into(&self, bytes: &mut Vec<u8>) -> Result<(), ProductionInputErrorV1> {
        bytes.extend_from_slice(&self.proof.version.to_be_bytes());
        bytes.extend_from_slice(&self.proof.settlement_id);
        bytes.extend_from_slice(&self.proof.context_hash);
        bytes.push(self.proof.role);
        bytes.extend_from_slice(&self.proof.bundle.version.to_be_bytes());
        bytes.extend_from_slice(&self.proof.bundle.claim.to_canonical_bytes());
        let length = u32::try_from(self.proof.bundle.proof.len())
            .map_err(|_| ProductionInputErrorV1::InputBoundExceeded)?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&self.proof.bundle.proof);
        bytes.extend_from_slice(&self.adaptor_point_sec1);
        bytes.extend_from_slice(&self.executor_profile_hash);
        bytes.extend_from_slice(&self.deadline.to_be_bytes());
        let length = u16::try_from(self.refund_destination.len())
            .map_err(|_| ProductionInputErrorV1::InputBoundExceeded)?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(self.refund_destination.as_bytes());
        Ok(())
    }

    pub(super) fn decode_from(
        cursor: &mut InputCursorV1<'_>,
    ) -> Result<Self, ProductionInputErrorV1> {
        let version = cursor.u16()?;
        let settlement_id = cursor.take::<32>()?;
        let context_hash = cursor.take::<32>()?;
        let role = cursor.u8()?;
        let bundle_version = cursor.u16()?;
        let claim = CrossCurvePublicClaim::from_canonical_bytes(&cursor.take::<65>()?)
            .ok_or(ProductionInputErrorV1::InvalidParticipantBundle)?;
        let length = usize::try_from(u32::from_be_bytes(cursor.take::<4>()?))
            .map_err(|_| ProductionInputErrorV1::InputBoundExceeded)?;
        if length == 0 || length > xmr_dleq_sigma::MAX_PROOF_BYTES {
            return Err(ProductionInputErrorV1::InvalidParticipantBundle);
        }
        let proof = cursor.bytes(length)?.to_vec();
        let adaptor_point_sec1 = cursor.take::<33>()?;
        let executor_profile_hash = cursor.take::<32>()?;
        let deadline = u64::from_be_bytes(cursor.take::<8>()?);
        let length = usize::from(cursor.u16()?);
        if length == 0 || length > xmr_live_sidecar_api::MAX_DESTINATION_BYTES {
            return Err(ProductionInputErrorV1::InvalidParticipantBundle);
        }
        let destination = String::from_utf8(cursor.bytes(length)?.to_vec())
            .map_err(|_| ProductionInputErrorV1::NonCanonicalEncoding)?;
        Self::new(
            BoundCrossCurveProofV1 {
                version,
                settlement_id,
                context_hash,
                role,
                bundle: CrossCurveProofBytes {
                    version: bundle_version,
                    proof,
                    claim,
                },
            },
            adaptor_point_sec1,
            executor_profile_hash,
            deadline,
            destination,
        )
    }

    pub(super) fn authenticate(
        &self,
        terms: &SettlementTermsV1,
        setup: &ValidatedXmrSetup,
    ) -> Result<xmr_session_init::PreparedXmrShareEnrollmentV23, ProductionInputErrorV1> {
        use xmr_refund_policy::NonCooperativeRefundCapability as _;
        let enrollment = xmr_session_init::prepare_xmr_share_enrollment_v23(setup, &self.proof)
            .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
        if self.proof.bundle.claim.secp_compressed != self.adaptor_point_sec1
            || xmr_refund_adaptor::DomRefundAdaptorExecutor::new(self.proof.bundle.claim)
                .profile_hash()
                != self.executor_profile_hash
            || authenticate_xmr_refund_deadline_v23(terms, setup, self.deadline).is_err()
        {
            return Err(ProductionInputErrorV1::InvalidParticipantBundle);
        }
        Ok(enrollment)
    }
}
