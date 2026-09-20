//! Immutable native authorization of wallet-composed signing keys.
//! Revalidates the exact BP, both 0x0b messages, wallet offers and knowledge
//! proofs. This authorizes key ancestry only; phase/funding/claim gates remain.
use super::*;
use dom_adaptor::{
    DomBootstrapBudgetV17, DomBootstrapProvenOfferV18, DomBootstrapTemplatesV17,
    VerifiedSharedOutputV1, DOM_NATIVE_BOOTSTRAP_POLICY_V17,
};
use kaystra_core::{types::TimelockSpec, SettlementTermsV1};

pub(super) const KEY_AUTH_SUFFIX_V18: &str = ".bootstrap-wallet-keys-v18";
const MAX: usize = 65536;
const MAGIC: &[u8; 8] = b"DOMBKA18";
/// The tag a caller that does not read one passes in.
const UNTAGGED_STEP_V25: &str = "retain_keys/untagged";
const DOMAIN: &str = "DOM:bootstrap-wallet-key-authority:v18";

#[path = "bootstrap_gate_v20.rs"]
mod bootstrap_gate_v20;

pub(super) struct BootstrapKeyAuthorityV18 {
    chain: [u8; 32],
    session: [u8; 32],
    terms: SettlementTermsV1,
    tip: u64,
    template_payload: [u8; 160],
    offers: [DomBootstrapProvenOfferV18; 2],
}
impl BootstrapKeyAuthorityV18 {
    fn bytes(&self) -> Result<Vec<u8>, SessionStoreError> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&self.chain);
        out.extend_from_slice(&self.session);
        out.extend_from_slice(&self.tip.to_le_bytes());
        out.extend_from_slice(&self.template_payload);
        put(
            &mut out,
            &self
                .terms
                .canonical_bytes()
                .map_err(|_| SessionStoreError::Canonical)?,
        )?;
        for offer in &self.offers {
            put(
                &mut out,
                &offer.to_bytes().map_err(|_| SessionStoreError::Canonical)?,
            )?;
        }
        let hash = tagged_hash(DOMAIN, &out);
        out.extend_from_slice(&hash);
        if out.len() > MAX {
            return Err(SessionStoreError::CapacityExceeded);
        }
        Ok(out)
    }
    fn parse(bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len() < 272
            || bytes.len() > MAX
            || bytes[..8] != *MAGIC
            || tagged_hash(DOMAIN, &bytes[..bytes.len() - 32]) != bytes[bytes.len() - 32..]
        {
            return Err(SessionStoreError::Quarantined);
        }
        let mut input = Reader {
            bytes: &bytes[..bytes.len() - 32],
            position: 8,
        };
        let chain = input.array()?;
        let session = input.array()?;
        let tip = u64::from_le_bytes(input.array()?);
        let template_payload = input.array()?;
        let terms_bytes = input.field(8192)?;
        let terms =
            SettlementTermsV1::decode(terms_bytes).map_err(|_| SessionStoreError::Canonical)?;
        if terms
            .canonical_bytes()
            .map_err(|_| SessionStoreError::Canonical)?
            != terms_bytes
        {
            return Err(SessionStoreError::Canonical);
        }
        let a = DomBootstrapProvenOfferV18::from_bytes(
            input.field(DomBootstrapProvenOfferV18::MAX_BYTES)?,
        )
        .map_err(|_| SessionStoreError::Canonical)?;
        let b = DomBootstrapProvenOfferV18::from_bytes(
            input.field(DomBootstrapProvenOfferV18::MAX_BYTES)?,
        )
        .map_err(|_| SessionStoreError::Canonical)?;
        if input.position != input.bytes.len() {
            return Err(SessionStoreError::Canonical);
        }
        let record = Self {
            chain,
            session,
            terms,
            tip,
            template_payload,
            offers: [a, b],
        };
        if record.bytes()? != bytes {
            return Err(SessionStoreError::Canonical);
        }
        Ok(record)
    }
    pub(super) fn key(
        &self,
        purpose: PurposeV1,
        id: [u8; 32],
        template: [u8; 32],
    ) -> Result<PublicKey, SessionStoreError> {
        let slot = match purpose {
            PurposeV1::Funding => 0,
            PurposeV1::ClaimAdaptor => 1,
            PurposeV1::Refund => 2,
            _ => return Err(SessionStoreError::InvalidTransition),
        };
        if self.template_payload[slot * 32..slot * 32 + 32] != template {
            return Err(SessionStoreError::Quarantined);
        }
        let offer = self
            .offers
            .iter()
            .find(|o| o.offer().participant_id == id)
            .ok_or(SessionStoreError::Quarantined)?;
        Ok(offer.offer().signing_keys[slot].clone())
    }
}

impl ContractsSessionStoreV1 {
    /// Install the public key ancestry only after bilateral template agreement.
    /// The stored proof body must remain byte-identical on every later reopen.
    /// This method does not issue a transaction or nonce authorization.
    pub fn retain_bootstrap_wallet_keys_v18(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        terms: &SettlementTermsV1,
        offers: &[DomBootstrapProvenOfferV18; 2],
        negotiated_tip: u64,
    ) -> Result<(), SessionStoreError> {
        let mut step = UNTAGGED_STEP_V25;
        self.retain_bootstrap_wallet_keys_tagged_v25(
            chain,
            session,
            terms,
            offers,
            negotiated_tip,
            &mut step,
        )
    }

    /// Exactly [`Self::retain_bootstrap_wallet_keys_v18`], reporting which
    /// closed region of the authority refused. The tag names a step, never a
    /// value, a key, a path or a participant, and grants nothing.
    pub fn retain_bootstrap_wallet_keys_tagged_v25(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        terms: &SettlementTermsV1,
        offers: &[DomBootstrapProvenOfferV18; 2],
        negotiated_tip: u64,
        step: &mut &'static str,
    ) -> Result<(), SessionStoreError> {
        let _guard = self.operation_lock()?;
        let template = self.load_template_transport_authority(session)?;
        let record = BootstrapKeyAuthorityV18 {
            chain: *chain.as_bytes(),
            session,
            terms: terms.clone(),
            tip: negotiated_tip,
            template_payload: template.template_commit_payload,
            offers: (*offers).clone(),
        };
        self.validate_bootstrap_wallet_keys_tagged_v25(&record, chain.as_bytes(), step)?;
        let bytes = record.bytes()?;
        match self.read_bootstrap_wallet_keys_v18(session) {
            Ok(old) => {
                if old.bytes()? != bytes {
                    return Err(SessionStoreError::Conflict);
                }
                return Ok(());
            }
            Err(SessionStoreError::SessionNotFound) => {}
            Err(error) => return Err(error),
        }
        *step = "retain_keys/session_phase";
        let current = self.load_session_locked(session)?;
        if current.phase() != SessionPhaseV1::TemplatesCommitted
            || current.irreversible().funding_authorized
        {
            return Err(SessionStoreError::InvalidTransition);
        }
        for purpose in [
            PurposeV1::Funding,
            PurposeV1::ClaimAdaptor,
            PurposeV1::Refund,
            PurposeV1::RefundAdaptor,
        ] {
            match self.load_signing_binding(session, purpose) {
                Ok(_) => return Err(SessionStoreError::Conflict),
                Err(SessionStoreError::SessionNotFound) => {}
                Err(error) => return Err(error),
            }
        }
        *step = "retain_keys/publish";
        let name = format!("{}{KEY_AUTH_SUFFIX_V18}", hex_lower(&session));
        publish_immutable(
            &self.rosters,
            &format!(".{name}.staging"),
            &name,
            &bytes,
            MAX,
        )?;
        let reread = self.read_bootstrap_wallet_keys_v18(session)?;
        if reread.bytes()? != bytes {
            return Err(SessionStoreError::Quarantined);
        }
        self.validate_bootstrap_wallet_keys_tagged_v25(&reread, chain.as_bytes(), step)
    }

    /// Rebuild the purpose-specific roster solely from the retained proof
    /// record and the native authenticated DSC1 identities.
    pub fn bootstrap_wallet_signing_roster_v18(
        &self,
        chain: TrustedChainIdV1,
        session: [u8; 32],
        purpose: PurposeV1,
    ) -> Result<ParticipantRosterV1, SessionStoreError> {
        let _guard = self.operation_lock()?;
        let record = self.read_bootstrap_wallet_keys_v18(session)?;
        self.validate_bootstrap_wallet_keys_v18(&record, chain.as_bytes())?;
        let transport = self.load_transport_roster(session)?;
        let template = template_hash_for_purpose(&record.template_payload, purpose);
        let mut participants = Vec::new();
        for entry in transport.participants {
            participants.push(
                ParticipantIdentityV1::new(
                    &chain,
                    entry.identity_key,
                    record.key(purpose, entry.participant_id, template)?,
                    entry.direction,
                )
                .map_err(|_| SessionStoreError::Canonical)?,
            );
        }
        ParticipantRosterV1::new(participants).map_err(|_| SessionStoreError::Canonical)
    }

    pub(super) fn read_bootstrap_wallet_keys_v18(
        &self,
        session: [u8; 32],
    ) -> Result<BootstrapKeyAuthorityV18, SessionStoreError> {
        let name = format!("{}{KEY_AUTH_SUFFIX_V18}", hex_lower(&session));
        let bytes = self
            .rosters
            .read_bounded_file(&ValidatedComponent::registered(&name)?, MAX)?;
        let record = BootstrapKeyAuthorityV18::parse(&bytes)?;
        if record.session != session {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(record)
    }

    pub(super) fn optional_bootstrap_wallet_keys_v18(
        &self,
        chain: &TrustedChainIdV1,
        session: [u8; 32],
    ) -> Result<Option<BootstrapKeyAuthorityV18>, SessionStoreError> {
        self.optional_bootstrap_wallet_keys_frozen_v18(chain.as_bytes(), session)
    }

    pub(super) fn optional_bootstrap_wallet_keys_frozen_v18(
        &self,
        chain: &[u8; 32],
        session: [u8; 32],
    ) -> Result<Option<BootstrapKeyAuthorityV18>, SessionStoreError> {
        let record = match self.read_bootstrap_wallet_keys_v18(session) {
            Ok(record) => record,
            Err(SessionStoreError::SessionNotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        self.validate_bootstrap_wallet_keys_v18(&record, chain)?;
        Ok(Some(record))
    }

    pub(super) fn audit_bootstrap_wallet_keys_v18(
        &self,
        session: [u8; 32],
    ) -> Result<(), SessionStoreError> {
        let record = self.read_bootstrap_wallet_keys_v18(session)?;
        let roster = self.load_transport_roster(session)?;
        self.validate_bootstrap_wallet_keys_v18(&record, &roster.chain_id)
    }

    fn validate_bootstrap_wallet_keys_v18(
        &self,
        record: &BootstrapKeyAuthorityV18,
        chain: &[u8; 32],
    ) -> Result<(), SessionStoreError> {
        let mut step = UNTAGGED_STEP_V25;
        self.validate_bootstrap_wallet_keys_tagged_v25(record, chain, &mut step)
    }

    fn validate_bootstrap_wallet_keys_tagged_v25(
        &self,
        record: &BootstrapKeyAuthorityV18,
        chain: &[u8; 32],
        step: &mut &'static str,
    ) -> Result<(), SessionStoreError> {
        self.reconstruct_bootstrap_wallet_templates_v20(record, chain, step)
            .map(|_| ())
    }

    fn reconstruct_bootstrap_wallet_templates_v20(
        &self,
        record: &BootstrapKeyAuthorityV18,
        chain: &[u8; 32],
        step: &mut &'static str,
    ) -> Result<DomBootstrapTemplatesV17, SessionStoreError> {
        *step = "retain_keys/terms";
        let current = self.load_session_locked(record.session)?;
        let terms = &record.terms;
        let terms_hash = terms
            .terms_hash()
            .map_err(|_| SessionStoreError::Canonical)?;
        if record.chain != *chain
            || terms.policy_version != DOM_NATIVE_BOOTSTRAP_POLICY_V17
            || terms.dom_leg.mechanism != kaystra_core::types::LockMechanism::DomAdaptor2of2
            || terms.session_id.0 != record.session
            || terms.dom_leg.chain_id.0 != record.chain
            || terms_hash != current.terms_hash()
        {
            return Err(SessionStoreError::Quarantined);
        }
        *step = "retain_keys/transport_identity";
        let roster = self.load_transport_roster(record.session)?;
        let identities = self.load_transport_identity_binding(record.session)?;
        require_transport_identity_binding(&roster, &identities)?;
        *step = "retain_keys/early_authority";
        let early = self.load_early_transport_authority(record.session)?;
        let initial = self.load_session_revision(record.session, 0)?;
        self.require_live_early_transport_authority(&early, &initial, &roster)?;
        *step = "retain_keys/bp_authority";
        let bp = self.load_bp_transport_authority(record.session)?;
        let bp_start = self.load_session_revision(record.session, bp.round_start_revision)?;
        self.require_live_bp_transport_authority(&bp, &early, &bp_start, &roster)?;
        *step = "retain_keys/template_authority";
        let template = self.load_template_transport_authority(record.session)?;
        let template_start =
            self.load_session_revision(record.session, template.round_start_revision)?;
        self.require_live_template_transport_authority(&template, &bp, &template_start, &roster)?;
        *step = "retain_keys/template_prefix";
        if record.template_payload != template.template_commit_payload
            || self.audit_operational_template_transport_prefix(
                record.session,
                &current,
                &roster,
                &template,
            )? != 2
            || roster.participants.len() != 2
            || terms.roster.map(|p| p.0).as_slice() != bp.statement.participant_ids()
        {
            return Err(SessionStoreError::Quarantined);
        }
        *step = "retain_keys/offer_binding";
        for (index, offer) in record.offers.iter().enumerate() {
            if offer.offer().terms_hash != terms_hash
                || offer.offer().session_id != record.session
                || offer.offer().participant_id != roster.participants[index].participant_id
            {
                return Err(SessionStoreError::Quarantined);
            }
            offer
                .verify_against_frozen_chain_v18(
                    chain,
                    bp.statement.participant_ids(),
                    roster.participants[index].direction,
                    index as u16,
                )
                .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        }
        *step = "retain_keys/bp_continuation";
        let verifier = DomCollaborativeRangeProofV1::new(
            &bp.statement,
            bp.recovery_capsule.as_bytes().to_vec(),
        )
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let final_bp = self
            .audit_operational_bp_continuation(
                record.session,
                &template_start,
                &roster,
                &bp.statement,
                &verifier,
            )?
            .into_final_proof()?
            .into_proof();
        let commitment = bp.statement.aggregate_commitment().to_compressed_bytes();
        let output = dom_consensus::TransactionOutput::with_recovery_capsule(
            dom_crypto::pedersen::Commitment::from_compressed_bytes(&commitment)
                .map_err(|_| SessionStoreError::Canonical)?,
            final_bp.as_bytes().to_vec(),
            &bp.recovery_capsule,
        )
        .map_err(|_| SessionStoreError::Canonical)?;
        let shared = VerifiedSharedOutputV1::from_retained_output_v14(&output, &commitment)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        *step = "retain_keys/budget";
        let budget = DomBootstrapBudgetV17::new(terms.dom_leg.amount, terms.fee_limit.dom_max)
            .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        let funder = terms
            .roster
            .iter()
            .position(|p| *p == terms.dom_leg.refund_to)
            .ok_or(SessionStoreError::Canonical)?;
        if terms.roster[1 - funder] != terms.dom_leg.beneficiary {
            return Err(SessionStoreError::Canonical);
        }
        let height = match terms.dom_leg.deadline {
            TimelockSpec::BlockHeight { value } => value,
            _ => return Err(SessionStoreError::Canonical),
        };
        *step = "retain_keys/assemble";
        let templates = DomBootstrapTemplatesV17::assemble(
            budget,
            &bp.statement,
            &shared,
            terms_hash,
            &[
                record.offers[0].offer().clone(),
                record.offers[1].offer().clone(),
            ],
            funder,
            height,
            record.tip,
        )
        .map_err(|_| SessionStoreError::InvalidDomTransaction)?;
        *step = "retain_keys/payload";
        if operational_template_commit_payload_v1(
            templates.funding.transaction_template(),
            templates.claim.transaction_template(),
            templates.refund.transaction_template(),
            &bp.statement,
        )? != record.template_payload
        {
            return Err(SessionStoreError::Quarantined);
        }
        Ok(templates)
    }
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), SessionStoreError> {
    let len = u32::try_from(bytes.len()).map_err(|_| SessionStoreError::CapacityExceeded)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], SessionStoreError> {
        let end = self
            .position
            .checked_add(size)
            .ok_or(SessionStoreError::Canonical)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(SessionStoreError::Canonical)?;
        self.position = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], SessionStoreError> {
        self.take(N)?
            .try_into()
            .map_err(|_| SessionStoreError::Canonical)
    }
    fn field(&mut self, maximum: usize) -> Result<&'a [u8], SessionStoreError> {
        let size = u32::from_le_bytes(self.array()?) as usize;
        if size == 0 || size > maximum {
            return Err(SessionStoreError::Canonical);
        }
        self.take(size)
    }
}
