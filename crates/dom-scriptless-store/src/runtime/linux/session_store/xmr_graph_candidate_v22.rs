//! Framing-only reader for retired V22 caches; no producer or graph admission.
//! Decoding and a checksum never authenticate a bilateral graph agreement.
use super::*;
pub(super) const SUFFIX: &str = ".xmr-graph-candidate-v22";
pub(super) const MAGIC: &[u8; 8] = b"DXGC22\0\x01";
const DOMAIN: &str = "DOM:unsigned-xmr-graph-candidate:v22";
pub(super) const MAX: usize = 256 * 1024;
const FIELD_LIMITS: [usize; 5] = [32768, 32768, 65536, 65536, 1024];
const HEADER: usize = 8 + 8 + 33 + 704;

/// Private, untrusted data. No authority token or private nonce is serialized.
pub(super) struct XmrGraphCandidateV22 {
    tip: u64,
    refund_point: [u8; 33],
    proposal: [u8; 704],
    // Canonical offers in terms-roster order, C/D journals, funding condition.
    fields: [Vec<u8>; 5],
}

impl XmrGraphCandidateV22 {
    /// Scope check against the owning Store, never against the candidate itself.
    pub(super) fn require_store_scope(
        &self,
        chain: &[u8; 32],
        session: [u8; 32],
        terms: [u8; 32],
    ) -> Result<(), SessionStoreError> {
        if &self.proposal[..8] != b"DXGP22\0\x01"
            || self.proposal[8..40] != chain[..]
            || self.proposal[40..72] == [0; 32]
            || self.proposal[72..104] != session
            || self.proposal[104..136] != terms
        {
            return Err(SessionStoreError::Conflict);
        }
        Ok(())
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, SessionStoreError> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&self.tip.to_le_bytes());
        bytes.extend_from_slice(&self.refund_point);
        bytes.extend_from_slice(&self.proposal);
        for (field, maximum) in self.fields.iter().zip(FIELD_LIMITS) {
            if field.is_empty() || field.len() > maximum {
                return Err(SessionStoreError::CapacityExceeded);
            }
            bytes.extend_from_slice(&(field.len() as u32).to_le_bytes());
            bytes.extend_from_slice(field);
        }
        let digest = tagged_hash(DOMAIN, &bytes);
        bytes.extend_from_slice(&digest);
        if bytes.len() > MAX {
            return Err(SessionStoreError::CapacityExceeded);
        }
        Ok(bytes)
    }

    /// Only framing/integrity: even fully rechecksummed fields remain untrusted.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < HEADER + 5 * 5 + 32
            || bytes.len() > MAX
            || bytes.get(..8) != Some(MAGIC.as_slice())
        {
            return Err(SessionStoreError::Canonical);
        }
        let body = &bytes[..bytes.len() - 32];
        if tagged_hash(DOMAIN, body) != bytes[body.len()..] {
            return Err(SessionStoreError::Canonical);
        }
        let mut position = HEADER;
        let mut fields = Vec::with_capacity(5);
        for maximum in FIELD_LIMITS {
            let length_end = position
                .checked_add(4)
                .ok_or(SessionStoreError::Canonical)?;
            let length = u32::from_le_bytes(copy_array(
                body.get(position..length_end)
                    .ok_or(SessionStoreError::Canonical)?,
            )?) as usize;
            if length == 0 || length > maximum {
                return Err(SessionStoreError::Canonical);
            }
            let end = length_end
                .checked_add(length)
                .ok_or(SessionStoreError::Canonical)?;
            fields.push(
                body.get(length_end..end)
                    .ok_or(SessionStoreError::Canonical)?
                    .to_vec(),
            );
            position = end;
        }
        if position != body.len() {
            return Err(SessionStoreError::Canonical);
        }
        let candidate = Self {
            tip: u64::from_le_bytes(copy_array(&body[8..16])?),
            refund_point: copy_array(&body[16..49])?,
            proposal: copy_array(&body[49..HEADER])?,
            fields: fields
                .try_into()
                .map_err(|_| SessionStoreError::Canonical)?,
        };
        if candidate.encode()? != bytes {
            return Err(SessionStoreError::Canonical);
        }
        Ok(candidate)
    }
}

impl ContractsSessionStoreV1 {
    pub(super) fn read_xmr_graph_candidate_v22(
        &self,
        session: [u8; 32],
    ) -> Result<XmrGraphCandidateV22, SessionStoreError> {
        let name = format!("{}{SUFFIX}", hex_lower(&session));
        let bytes = self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&name)?, MAX)
            .map_err(|error| match error {
                LinuxCapabilityError::NotFound => SessionStoreError::SessionNotFound,
                other => other.into(),
            })?;
        let candidate = XmrGraphCandidateV22::decode(&bytes)?;
        let current = self.load_session_locked(session)?;
        let roster = self.load_transport_roster(session)?;
        candidate.require_store_scope(&roster.chain_id, session, current.terms_hash())?;
        Ok(candidate)
    }

    /// Startup checks only frame/scope of this untrusted cache. Unlike key
    /// authority records, it is never used to validate signing or funding.
    pub(super) fn audit_xmr_graph_candidate_frame_v22(
        &self,
        session: [u8; 32],
    ) -> Result<(), SessionStoreError> {
        self.read_xmr_graph_candidate_v22(session).map(|_| ())
    }
}

#[cfg(test)]
pub(super) fn framing_fixture_for_test(
    chain: [u8; 32],
    session: [u8; 32],
    terms: [u8; 32],
) -> Result<Vec<u8>, SessionStoreError> {
    // Scope-valid framing only; invalid offers/journals are intentional.
    let mut proposal = [5; 704];
    proposal[..8].copy_from_slice(b"DXGP22\0\x01");
    proposal[8..40].copy_from_slice(&chain);
    proposal[72..104].copy_from_slice(&session);
    proposal[104..136].copy_from_slice(&terms);
    XmrGraphCandidateV22 {
        tip: 10,
        refund_point: [3; 33],
        proposal,
        fields: std::array::from_fn(|i| vec![i as u8 + 1; i + 1]),
    }
    .encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_framing_is_bounded_exact_and_does_not_claim_authority(
    ) -> Result<(), SessionStoreError> {
        // Deliberately not valid offers or journals: decode must not be confused
        // with reconstruction or authenticated agreement.
        let record = XmrGraphCandidateV22 {
            tip: 10,
            refund_point: [3; 33],
            proposal: [5; 704],
            fields: std::array::from_fn(|i| vec![i as u8 + 1; i + 1]),
        };
        let encoded = record.encode()?;
        assert_eq!(XmrGraphCandidateV22::decode(&encoded)?.encode()?, encoded);
        for cut in 0..encoded.len() {
            assert!(XmrGraphCandidateV22::decode(&encoded[..cut]).is_err());
        }
        for index in 0..encoded.len() {
            let mut changed = encoded.clone();
            changed[index] ^= 1;
            assert!(XmrGraphCandidateV22::decode(&changed).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(XmrGraphCandidateV22::decode(&trailing).is_err());
        for size in [0u32, 32769, u32::MAX] {
            let mut changed = encoded.clone();
            changed[HEADER..HEADER + 4].copy_from_slice(&size.to_le_bytes());
            let end = changed.len() - 32;
            let checksum = tagged_hash(DOMAIN, &changed[..end]);
            changed[end..].copy_from_slice(&checksum);
            assert!(XmrGraphCandidateV22::decode(&changed).is_err());
        }
        for index in 0..5 {
            let mut changed = XmrGraphCandidateV22::decode(&encoded)?;
            changed.fields[index] = vec![1; FIELD_LIMITS[index] + 1];
            assert!(changed.encode().is_err());
        }
        Ok(())
    }
}
