//! Typed digest of the locally reconstructed XMR graph proposal.
//! Wire authentication is not Store admission or a funding authorization.
use super::*;

/// Exact digest length for the XMR graph commitment extension (`0x18`).
pub const XMR_GRAPH_TEMPLATE_COMMIT_PAYLOAD_LEN_V22: usize = 32;

/// Public proposal commitment. The native Store must independently reconstruct
/// the graph, verify both C/D histories and authorize the signing request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XmrGraphTemplateCommitPayloadV22 {
    proposal_digest: [u8; XMR_GRAPH_TEMPLATE_COMMIT_PAYLOAD_LEN_V22],
}

impl XmrGraphTemplateCommitPayloadV22 {
    /// Reject an empty commitment; this constructor grants no signing authority.
    pub fn new(proposal_digest: [u8; 32]) -> Result<Self, TransportError> {
        if proposal_digest == [0; 32] {
            return Err(TransportError::ZeroPayloadCommitment);
        }
        Ok(Self { proposal_digest })
    }

    /// Decode only the complete 32-byte commitment, without extensions.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, TransportError> {
        let digest = bytes
            .try_into()
            .map_err(|_| TransportError::NonCanonicalLength)?;
        Self::new(digest)
    }

    /// Domain-separated digest of the native, locally reconstructed proposal.
    pub const fn proposal_digest(&self) -> &[u8; 32] {
        &self.proposal_digest
    }

    /// Exact public wire bytes, never a transaction signature or secret.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.proposal_digest
    }
}

impl UnsignedMessageV1 {
    /// Construct an exact XMR graph commitment envelope. Identity signing must
    /// still use the Store-issued request and consume-before-export journal.
    pub fn new_xmr_graph_template_commit_v22(
        chain_id: [u8; 32],
        session_id: [u8; 32],
        sender_id: [u8; 32],
        sequence: u64,
        previous_transcript_hash: [u8; 32],
        payload: XmrGraphTemplateCommitPayloadV22,
    ) -> Result<Self, TransportError> {
        Self::new(
            MessageTypeV1::XmrGraphTemplateCommitV22,
            chain_id,
            session_id,
            sender_id,
            sequence,
            previous_transcript_hash,
            payload.into_bytes().to_vec(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xmr_graph_template_commit_v22_has_exact_nonzero_payload_and_closed_phase(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let kind = MessageTypeV1::XmrGraphTemplateCommitV22;
        assert_eq!(MessageTypeV1::try_from(0x18)?, kind);
        assert_eq!(
            MessageTypeV1::try_from(0x19),
            Err(TransportError::UnknownMessageType)
        );
        assert_eq!(kind.payload_cap(), 32);
        assert!(kind.accepts_phase(SessionPhaseV1::TemplatesCommitted));
        for phase in [
            SessionPhaseV1::Created,
            SessionPhaseV1::OutputFinalized,
            SessionPhaseV1::RefundSigning,
            SessionPhaseV1::RefundSigned,
            SessionPhaseV1::FundingAuthorized,
            SessionPhaseV1::FundingConfirmed,
            SessionPhaseV1::ClaimPrepared,
            SessionPhaseV1::Aborted,
        ] {
            assert!(!kind.accepts_phase(phase));
        }
        assert_eq!(
            XmrGraphTemplateCommitPayloadV22::new([0; 32]),
            Err(TransportError::ZeroPayloadCommitment)
        );
        for length in 0..=33 {
            let bytes = vec![7; length];
            assert_eq!(
                XmrGraphTemplateCommitPayloadV22::decode_exact(&bytes).is_ok(),
                length == 32
            );
            assert_eq!(
                UnsignedMessageV1::new(kind, [1; 32], [2; 32], [3; 32], 0, [4; 32], bytes).is_ok(),
                length == 32
            );
        }
        assert!(
            UnsignedMessageV1::new(kind, [1; 32], [2; 32], [3; 32], 0, [4; 32], vec![0; 32])
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn xmr_graph_template_commit_v22_identity_signature_binds_the_proposal(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = SecretKey::from_bytes(&[23; 32])?;
        let payload = XmrGraphTemplateCommitPayloadV22::new([5; 32])?;
        let message = SignedMessageV1::sign(
            UnsignedMessageV1::new_xmr_graph_template_commit_v22(
                [1; 32], [2; 32], [3; 32], 7, [4; 32], payload,
            )?,
            &key,
        )?;
        let decoded = SignedMessageV1::decode_exact(message.as_bytes())?;
        decoded.verify_identity(&key.public_key())?;
        assert_eq!(decoded.as_bytes(), message.as_bytes());
        assert_eq!(decoded.unsigned().payload(), payload.proposal_digest());
        // Every replacement remains structurally canonical, including changing
        // the kind to the separate 0x17 readiness message with the same length.
        for (offset, value) in [
            (6, 0x17),
            (8, 9),
            (40, 9),
            (72, 9),
            (104, 9),
            (112, 9),
            (UNSIGNED_PREFIX_LEN_V1, 9),
        ] {
            let mut changed = message.as_bytes().to_vec();
            changed[offset] = value;
            let changed = SignedMessageV1::decode_exact(&changed)?;
            assert!(
                changed.verify_identity(&key.public_key()).is_err(),
                "field {offset}"
            );
        }
        assert!(decoded
            .verify_identity(&SecretKey::from_bytes(&[24; 32])?.public_key())
            .is_err());
        Ok(())
    }
}
