//! Native one-participant shared-output bootstrap before bilateral artifact signing.
//!
//! This owns the real encrypted shared-blinding vault and an independent
//! immutable production journal. Peer commitments are roster-authenticated and
//! durable before any local decoy reveal can leave this owner. It never derives
//! a private share from the legacy public bootstrap artifact.

use btc_crypto::SecpContext;
use dom_actuator::DomSessionBindingV1;
use dom_adaptor::{
    combine_decoy_capsule_v1, contribute_vault_backed_blinding_share_v1,
    resume_vault_backed_blinding_share_after_restart_v1, DecoyCommitmentV1, DecoyContributionV1,
    DecoyRevealV1, DirectionV1, PendingSharedBlindingBindingV1, RestartedSessionBlindingShareV1,
    SessionBlindingShareCapabilityV1, SharedBlindingRestartRequestV1, SharedBlindingVaultError,
    TrustedChainIdV1,
};
use dom_crypto::{recovery::RecoveryCapsule, PublicKey};
use dom_scriptless_store::{ContractsNonceVaultV1, InventoryError};
use relay::SenderRoleV1;
use store::Store;
use zeroize::Zeroizing;

use crate::production_inputs::ProductionRosterLegV1;

const NS: &[u8] = b"dom.shared.bootstrap.v12";
const COMMIT_UNSIGNED: usize = 8 + 32 + 32 + 33 + 32;
const COMMIT_BYTES: usize = COMMIT_UNSIGNED + 64;
const REVEAL_UNSIGNED: usize = 8 + 32 + 32 + 32 + 92;
const REVEAL_BYTES: usize = REVEAL_UNSIGNED + 64;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionDomSharedBootstrapErrorV12 {
    #[error("native DOM bootstrap scope or roster mismatch")]
    Binding,
    #[error("DOM shared contribution cryptographic validation failed")]
    Crypto,
    #[error("retained DOM shared contribution authority is unavailable")]
    Vault,
    #[error("DOM bootstrap journal is missing, conflicting or unavailable")]
    Journal,
    #[error("the peer commitment has not been durably authenticated")]
    AwaitingPeerCommitment,
}

/// The sole owner of one participant's real pending or capsule-bound share.
pub(crate) struct ProductionDomSharedBootstrapV12 {
    chain: TrustedChainIdV1,
    binding: DomSessionBindingV1,
    roster: ProductionRosterLegV1,
    scope: [u8; 32],
    local: usize,
    vault: ContractsNonceVaultV1,
    journal: Store,
    share: RestartedSessionBlindingShareV1,
    secp: SecpContext,
}

/// Native completed bootstrap material. No secret scalar or seed is exported.
pub(crate) struct ProductionBoundDomSharedOutputV12 {
    shared_bindings: [dom_adaptor::SharedBlindingBindingV1; 2],
    pub(crate) vault: Option<ContractsNonceVaultV1>,
    // Funding never consumes the retained SharedOutput/BP owner on native XMR.
    pub(crate) funding_vault_v23: Option<ContractsNonceVaultV1>,
    // Claim has a separate nonce domain and durable provisioning journal.
    pub(crate) claim_vault_v23: Option<ContractsNonceVaultV1>,
    pub(crate) journal: Store,
    pub(crate) capability: SessionBlindingShareCapabilityV1,
    pub(crate) capsule: RecoveryCapsule,
    pub(crate) funding_share_v18: Option<dom_actuator::DomParticipantSigningShareV1>,
    pub(crate) claim_share_v18: Option<dom_actuator::DomParticipantSigningShareV1>,
    pub(crate) refund_share_v18: Option<dom_actuator::DomParticipantSigningShareV1>,
    pub(crate) xmr_graph_shares_v22: Option<dom_actuator::DomXmrGraphSigningSharesV22>,
    pub(crate) funding_signer_v20:
        Option<dom_actuator::RetainedParticipantVaultSignerV12<ContractsNonceVaultV1>>,
    pub(crate) refund_signer_v18:
        Option<dom_actuator::RetainedParticipantVaultSignerV12<ContractsNonceVaultV1>>,
}

impl ProductionDomSharedBootstrapV12 {
    /// Recover the exact share or create one only when the native vault proves
    /// exact absence and the independent production journal is wholly empty.
    /// A retained public commitment with a missing private share is a refusal.
    pub(crate) fn open(
        vault: ContractsNonceVaultV1,
        journal: Store,
        binding: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        roster: ProductionRosterLegV1,
    ) -> Result<Self, ProductionDomSharedBootstrapErrorV12> {
        Self::open_with_creation(vault, journal, binding, chain, roster, true)
    }

    /// Reopen-only path: no missing contribution may ever be regenerated,
    /// even if a damaged or rolled-back private journal appears empty.
    pub(crate) fn open_retained(
        vault: ContractsNonceVaultV1,
        journal: Store,
        binding: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        roster: ProductionRosterLegV1,
    ) -> Result<Self, ProductionDomSharedBootstrapErrorV12> {
        Self::open_with_creation(vault, journal, binding, chain, roster, false)
    }

    fn open_with_creation(
        mut vault: ContractsNonceVaultV1,
        mut journal: Store,
        binding: DomSessionBindingV1,
        chain: TrustedChainIdV1,
        roster: ProductionRosterLegV1,
        allow_create: bool,
    ) -> Result<Self, ProductionDomSharedBootstrapErrorV12> {
        use ProductionDomSharedBootstrapErrorV12 as Error;
        journal
            .require_production_binding(shared_bootstrap_journal_binding_v12(binding, &roster)?)
            .map_err(|_| Error::Journal)?;
        let limits =
            store::ProductionAuditLimitsV1::new(20, 131072, 32768).map_err(|_| Error::Journal)?;
        let snapshot = journal
            .production_audit_snapshot(limits)
            .map_err(|_| Error::Journal)?;
        if !snapshot.revisions().is_empty()
            || !snapshot.journal().is_empty()
            || snapshot.opaque_records().iter().any(|row| {
                row.namespace() != NS
                    || !matches!(
                        row.key(),
                        b"local-commit"
                            | b"peer-commit"
                            | b"local-reveal"
                            | b"peer-reveal"
                            | b"dsc1-reveal-v16"
                            | b"bp-start-v16"
                            | b"relay-expiry-v16"
                            | b"wallet-offer-v17"
                            | b"peer-wallet-offer-v17"
                            | b"wallet-key-proofs-v18"
                            | b"peer-wallet-key-proofs-v18"
                            | b"xmr-payout-principal-v22"
                            | b"xmr-payout-change-v22"
                            | b"xmr-payout-refund-v22"
                            | b"xmr-payout-compensation-v22"
                            | b"xmr-graph-keys-v22"
                            | b"xmr-graph-proofs-v22"
                            | b"xmr-funding-offer-v22"
                            | b"xmr-graph-offer-v22"
                            | b"xmr-peer-graph-offer-v25"
                    )
                    || !runtime_public_length_valid(row.key(), row.value().len())
            })
        {
            return Err(Error::Journal);
        }
        let local = usize::from(binding.participant().protocol_index());
        if chain.as_bytes() != &binding.chain_id()
            || roster.session_id != binding.session_id()
            || roster.roster_snapshot == [0; 32]
            || roster.members[0].participant_id >= roster.members[1].participant_id
            || roster.members[0].xonly_key == roster.members[1].xonly_key
            || local > 1
            || roster.members[local].participant_id.0 != binding.participant().participant_id()
            || !matches!(
                (roster.members[0].role, roster.members[1].role),
                (SenderRoleV1::Initiator, SenderRoleV1::Solver)
                    | (SenderRoleV1::Solver, SenderRoleV1::Initiator)
            )
        {
            return Err(Error::Binding);
        }
        let role = match roster.members[local].role {
            SenderRoleV1::Initiator => DirectionV1::Initiator,
            SenderRoleV1::Solver => DirectionV1::Responder,
            SenderRoleV1::Observer => return Err(Error::Binding),
        };
        let ids = roster.members.map(|member| member.participant_id.0);
        let request = SharedBlindingRestartRequestV1::new(
            &chain,
            binding.session_id(),
            &ids,
            role,
            local as u16,
            binding.terms_digest(),
        )
        .map_err(|_| Error::Binding)?;
        let share = match resume_vault_backed_blinding_share_after_restart_v1(request, &mut vault) {
            Ok(share) => share,
            Err(SharedBlindingVaultError::Vault(InventoryError::NoMatchingSharedBlinding))
                if allow_create =>
            {
                journal
                    .require_empty_production()
                    .map_err(|_| Error::Journal)?;
                RestartedSessionBlindingShareV1::Pending(
                    contribute_vault_backed_blinding_share_v1(
                        &chain,
                        binding.session_id(),
                        &ids,
                        role,
                        local as u16,
                        binding.terms_digest(),
                        &mut vault,
                    )
                    .map_err(|_| Error::Vault)?,
                )
            }
            Err(_) => return Err(Error::Vault),
        };
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::getrandom(seed.as_mut()).map_err(|_| Error::Crypto)?;
        let secp = SecpContext::new(&seed);
        let scope = bootstrap_scope(binding, &roster);
        let owner = Self {
            chain,
            binding,
            roster,
            scope,
            local,
            vault,
            journal,
            share,
            secp,
        };
        owner.require_native_binding()?;
        if owner.read(b"local-commit")?.is_some() {
            owner.require_local_commit()?;
        }
        if owner.read(b"peer-commit")?.is_some() {
            owner.require_local_commit()?;
            owner.require_peer_commit()?;
        }
        if let Some(reveal) = owner.read(b"local-reveal")? {
            owner.require_peer_commit()?;
            owner.verify_reveal(&reveal, local, &owner.require_local_commit()?)?;
            if reveal[104..196] != owner.contribution()?.into_reveal().to_bytes() {
                return Err(Error::Journal);
            }
        }
        if let Some(reveal) = owner.read(b"peer-reveal")? {
            if owner.read(b"local-reveal")?.is_none() {
                return Err(Error::Journal);
            }
            owner.verify_reveal(&reveal, 1 - local, &owner.require_peer_commit()?)?;
        }
        Ok(owner)
    }

    /// Persist and return the exact signed local public commitment. Repeated
    /// calls return the retained signature bytes, not a freshly signed variant.
    pub(crate) fn local_commit(
        &mut self,
        relay_secret: &[u8; 32],
    ) -> Result<Vec<u8>, ProductionDomSharedBootstrapErrorV12> {
        let unsigned = self.local_commit_unsigned()?;
        if let Some(existing) = self.read(b"local-commit")? {
            self.verify_commit(&existing, self.local)?;
            if existing[..COMMIT_UNSIGNED] != unsigned {
                return Err(ProductionDomSharedBootstrapErrorV12::Journal);
            }
            return Ok(existing);
        }
        let signed = self.sign(unsigned, relay_secret)?;
        self.persist(b"local-commit", &signed)?;
        Ok(signed)
    }

    /// Authenticate the peer's exact identity and context, then durably pin its
    /// commitment. Changing any signed byte on a repeated call is a conflict.
    pub(crate) fn accept_peer_commit(
        &mut self,
        signed: &[u8],
    ) -> Result<(), ProductionDomSharedBootstrapErrorV12> {
        self.require_local_commit()?;
        self.verify_commit(signed, 1 - self.local)?;
        self.persist(b"peer-commit", signed)
    }

    /// The decoy contribution can leave only after the peer commitment is
    /// authenticated from the retained journal. This is not the swap secret.
    pub(crate) fn local_reveal(
        &mut self,
        relay_secret: &[u8; 32],
    ) -> Result<Vec<u8>, ProductionDomSharedBootstrapErrorV12> {
        let local_commit = self.require_local_commit()?;
        self.require_peer_commit()?;
        let mut unsigned = Vec::with_capacity(REVEAL_UNSIGNED);
        unsigned.extend_from_slice(b"DOMSRV12");
        unsigned.extend_from_slice(&self.scope);
        unsigned.extend_from_slice(&self.binding.participant().participant_id());
        unsigned.extend_from_slice(&digest(
            b"DOM/SHARED-BOOTSTRAP/COMMIT/V12\0",
            &local_commit[..COMMIT_UNSIGNED],
        ));
        unsigned.extend_from_slice(&self.contribution()?.into_reveal().to_bytes());
        if let Some(existing) = self.read(b"local-reveal")? {
            self.verify_reveal(&existing, self.local, &local_commit)?;
            if existing[..REVEAL_UNSIGNED] != unsigned {
                return Err(ProductionDomSharedBootstrapErrorV12::Journal);
            }
            return Ok(existing);
        }
        let signed = self.sign(unsigned, relay_secret)?;
        self.persist(b"local-reveal", &signed)?;
        Ok(signed)
    }

    /// Verify and retain the peer reveal, bind the real encrypted share to the
    /// exact native capsule, and return the opaque shared-output capability.
    pub(crate) fn finish(
        mut self,
        peer_reveal: &[u8],
    ) -> Result<ProductionBoundDomSharedOutputV12, ProductionDomSharedBootstrapErrorV12> {
        use ProductionDomSharedBootstrapErrorV12 as Error;
        let peer_commit = self.require_peer_commit()?;
        let local_commit = self.require_local_commit()?;
        let local_reveal = self.read(b"local-reveal")?.ok_or(Error::Journal)?;
        self.verify_reveal(&local_reveal, self.local, &local_commit)?;
        if local_reveal[104..196] != self.contribution()?.into_reveal().to_bytes() {
            return Err(Error::Journal);
        }
        self.verify_reveal(peer_reveal, 1 - self.local, &peer_commit)?;
        let local = DecoyRevealV1::from_bytes(
            local_reveal[104..196]
                .try_into()
                .map_err(|_| Error::Binding)?,
        );
        let peer = DecoyRevealV1::from_bytes(
            peer_reveal[104..196]
                .try_into()
                .map_err(|_| Error::Binding)?,
        );
        let peer_commitment = DecoyCommitmentV1::from_bytes(
            peer_commit[105..137]
                .try_into()
                .map_err(|_| Error::Binding)?,
        );
        let capsule =
            combine_decoy_capsule_v1(&local, &peer, &peer_commitment).map_err(|_| Error::Crypto)?;
        // Both points originate in the exact roster-authenticated commitments.
        // Preserve that provenance for the later C/D value-proof driver.
        let commits = if self.local == 0 {
            [&local_commit, &peer_commit]
        } else {
            [&peer_commit, &local_commit]
        };
        let ids = self.roster.members.map(|member| member.participant_id.0);
        let chain = self.chain;
        let mut public = Vec::with_capacity(2);
        for (index, commit) in commits.iter().enumerate() {
            let point =
                PublicKey::from_compressed_bytes(&commit[72..105]).map_err(|_| Error::Crypto)?;
            let direction = match self.roster.members[index].role {
                SenderRoleV1::Initiator => DirectionV1::Initiator,
                SenderRoleV1::Solver => DirectionV1::Responder,
                SenderRoleV1::Observer => return Err(Error::Binding),
            };
            let pending = PendingSharedBlindingBindingV1::new(
                &chain,
                self.binding.session_id(),
                &ids,
                direction,
                index as u16,
                self.binding.terms_digest(),
                point,
            )
            .map_err(|_| Error::Binding)?;
            public.push(dom_adaptor::SharedBlindingBindingV1::bind_recovery_capsule(
                &pending, &capsule,
            ));
        }
        let shared_bindings: [dom_adaptor::SharedBlindingBindingV1; 2] =
            public.try_into().map_err(|_| Error::Binding)?;
        self.persist(b"peer-reveal", peer_reveal)?;
        let capability = match self.share {
            RestartedSessionBlindingShareV1::Pending(pending) => pending
                .bind_recovery_capsule_restartable_v1(&capsule, &mut self.vault)
                .map_err(|_| Error::Vault)?,
            RestartedSessionBlindingShareV1::Bound {
                capability,
                capsule: retained,
            } => {
                if retained.as_bytes() != capsule.as_bytes() {
                    return Err(Error::Journal);
                }
                capability
            }
        };
        if capability.binding() != &shared_bindings[self.local] {
            return Err(Error::Binding);
        }
        Ok(ProductionBoundDomSharedOutputV12 {
            shared_bindings,
            vault: Some(self.vault),
            funding_vault_v23: None,
            claim_vault_v23: None,
            journal: self.journal,
            capability,
            capsule,
            funding_share_v18: None,
            claim_share_v18: None,
            refund_share_v18: None,
            xmr_graph_shares_v22: None,
            refund_signer_v18: None,
            funding_signer_v20: None,
        })
    }

    /// Complete a prior crash cut after the peer reveal was durably retained.
    pub(crate) fn finish_retained(
        self,
    ) -> Result<ProductionBoundDomSharedOutputV12, ProductionDomSharedBootstrapErrorV12> {
        let peer = self
            .read(b"peer-reveal")?
            .ok_or(ProductionDomSharedBootstrapErrorV12::Journal)?;
        self.finish(&peer)
    }

    fn pending_binding(&self) -> &PendingSharedBlindingBindingV1 {
        match &self.share {
            RestartedSessionBlindingShareV1::Pending(capability) => capability.binding(),
            RestartedSessionBlindingShareV1::Bound { capability, .. } => {
                capability.binding().pending_binding()
            }
        }
    }

    fn require_native_binding(&self) -> Result<(), ProductionDomSharedBootstrapErrorV12> {
        let native = self.pending_binding();
        if native.session_id() != &self.binding.session_id()
            || native.chain_id() != &self.binding.chain_id()
            || native.terms_hash() != &self.binding.terms_digest()
            || native.participant_id() != &self.binding.participant().participant_id()
            || native.participant_index() != self.local as u16
            || native.roster() != self.roster.members.map(|member| member.participant_id.0)
        {
            return Err(ProductionDomSharedBootstrapErrorV12::Binding);
        }
        Ok(())
    }

    fn contribution(&self) -> Result<DecoyContributionV1, ProductionDomSharedBootstrapErrorV12> {
        self.require_native_binding()?;
        match &self.share {
            RestartedSessionBlindingShareV1::Pending(capability) => {
                capability.derive_decoy_contribution_v1()
            }
            RestartedSessionBlindingShareV1::Bound { capability, .. } => {
                capability.derive_decoy_contribution_v1()
            }
        }
        .map_err(|_| ProductionDomSharedBootstrapErrorV12::Crypto)
    }

    fn local_commit_unsigned(&self) -> Result<Vec<u8>, ProductionDomSharedBootstrapErrorV12> {
        let mut unsigned = Vec::with_capacity(COMMIT_UNSIGNED);
        unsigned.extend_from_slice(b"DOMSCM12");
        unsigned.extend_from_slice(&self.scope);
        unsigned.extend_from_slice(&self.binding.participant().participant_id());
        unsigned.extend_from_slice(&self.pending_binding().share_point().to_compressed_bytes());
        unsigned.extend_from_slice(&self.contribution()?.commitment().to_bytes());
        Ok(unsigned)
    }

    fn sign(
        &self,
        mut unsigned: Vec<u8>,
        secret: &[u8; 32],
    ) -> Result<Vec<u8>, ProductionDomSharedBootstrapErrorV12> {
        let mut aux = Zeroizing::new([0; 32]);
        getrandom::getrandom(aux.as_mut())
            .map_err(|_| ProductionDomSharedBootstrapErrorV12::Crypto)?;
        let hash = digest(b"DOM/SHARED-BOOTSTRAP/SIGNATURE/V12\0", &unsigned);
        let (signature, key) = self
            .secp
            .sign_bip340(secret, &hash, &aux)
            .map_err(|_| ProductionDomSharedBootstrapErrorV12::Crypto)?;
        if key != self.roster.members[self.local].xonly_key {
            return Err(ProductionDomSharedBootstrapErrorV12::Binding);
        }
        unsigned.extend_from_slice(&signature);
        Ok(unsigned)
    }

    fn verify_commit(
        &self,
        bytes: &[u8],
        participant: usize,
    ) -> Result<(), ProductionDomSharedBootstrapErrorV12> {
        if bytes.len() != COMMIT_BYTES || &bytes[..8] != b"DOMSCM12" {
            return Err(ProductionDomSharedBootstrapErrorV12::Binding);
        }
        let point: [u8; 33] = bytes[72..105]
            .try_into()
            .map_err(|_| ProductionDomSharedBootstrapErrorV12::Binding)?;
        PublicKey::from_compressed_bytes(&point)
            .map_err(|_| ProductionDomSharedBootstrapErrorV12::Crypto)?;
        if participant != self.local
            && point == self.pending_binding().share_point().to_compressed_bytes()
        {
            return Err(ProductionDomSharedBootstrapErrorV12::Binding);
        }
        self.verify_signature(bytes, COMMIT_UNSIGNED, participant)
    }

    fn verify_reveal(
        &self,
        bytes: &[u8],
        participant: usize,
        commit: &[u8],
    ) -> Result<(), ProductionDomSharedBootstrapErrorV12> {
        if bytes.len() != REVEAL_BYTES
            || &bytes[..8] != b"DOMSRV12"
            || bytes[72..104]
                != digest(
                    b"DOM/SHARED-BOOTSTRAP/COMMIT/V12\0",
                    &commit[..COMMIT_UNSIGNED],
                )
        {
            return Err(ProductionDomSharedBootstrapErrorV12::Binding);
        }
        self.verify_signature(bytes, REVEAL_UNSIGNED, participant)
    }

    fn verify_signature(
        &self,
        bytes: &[u8],
        unsigned_len: usize,
        participant: usize,
    ) -> Result<(), ProductionDomSharedBootstrapErrorV12> {
        if bytes[8..40] != self.scope
            || bytes[40..72] != self.roster.members[participant].participant_id.0
        {
            return Err(ProductionDomSharedBootstrapErrorV12::Binding);
        }
        let signature: [u8; 64] = bytes[unsigned_len..]
            .try_into()
            .map_err(|_| ProductionDomSharedBootstrapErrorV12::Binding)?;
        self.secp
            .verify_bip340(
                &self.roster.members[participant].xonly_key,
                &digest(
                    b"DOM/SHARED-BOOTSTRAP/SIGNATURE/V12\0",
                    &bytes[..unsigned_len],
                ),
                &signature,
            )
            .map_err(|_| ProductionDomSharedBootstrapErrorV12::Crypto)
    }

    fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ProductionDomSharedBootstrapErrorV12> {
        self.journal
            .opaque(NS, key)
            .map_err(|_| ProductionDomSharedBootstrapErrorV12::Journal)
    }

    fn persist(
        &mut self,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<(), ProductionDomSharedBootstrapErrorV12> {
        self.journal
            .put_opaque(NS, key, bytes)
            .map_err(|_| ProductionDomSharedBootstrapErrorV12::Journal)?;
        if self.read(key)?.as_deref() != Some(bytes) {
            return Err(ProductionDomSharedBootstrapErrorV12::Journal);
        }
        Ok(())
    }

    fn require_local_commit(&self) -> Result<Vec<u8>, ProductionDomSharedBootstrapErrorV12> {
        let bytes = self
            .read(b"local-commit")?
            .ok_or(ProductionDomSharedBootstrapErrorV12::Journal)?;
        self.verify_commit(&bytes, self.local)?;
        if bytes[..COMMIT_UNSIGNED] != self.local_commit_unsigned()? {
            return Err(ProductionDomSharedBootstrapErrorV12::Journal);
        }
        Ok(bytes)
    }

    fn require_peer_commit(&self) -> Result<Vec<u8>, ProductionDomSharedBootstrapErrorV12> {
        let bytes = self
            .read(b"peer-commit")?
            .ok_or(ProductionDomSharedBootstrapErrorV12::AwaitingPeerCommitment)?;
        self.verify_commit(&bytes, 1 - self.local)?;
        Ok(bytes)
    }
}

/// Public neutral-store binding selected by the production provisioning root.
pub(crate) fn shared_bootstrap_journal_binding_v12(
    binding: DomSessionBindingV1,
    roster: &ProductionRosterLegV1,
) -> Result<store::ProductionStoreBindingV1, ProductionDomSharedBootstrapErrorV12> {
    let mut bytes = bootstrap_scope(binding, roster).to_vec();
    bytes.extend_from_slice(&binding.participant().participant_id());
    store::ProductionStoreBindingV1::new(digest(b"DOM/SHARED-BOOTSTRAP/JOURNAL/V12\0", &bytes))
        .map_err(|_| ProductionDomSharedBootstrapErrorV12::Binding)
}

pub(crate) fn bootstrap_scope(
    binding: DomSessionBindingV1,
    roster: &ProductionRosterLegV1,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    for value in [
        binding.route_id(),
        binding.session_id(),
        binding.chain_id(),
        binding.genesis_hash(),
        binding.terms_digest(),
        binding.profile_digest(),
        binding.deployment_digest(),
        binding.asset_binding_digest(),
        roster.roster_snapshot,
    ] {
        bytes.extend_from_slice(&value);
    }
    bytes.extend_from_slice(&binding.registry_epoch().to_be_bytes());
    bytes.extend_from_slice(&roster.policy_version.to_be_bytes());
    for member in roster.members {
        bytes.extend_from_slice(&member.participant_id.0);
        bytes.extend_from_slice(&member.xonly_key);
        bytes.push(match member.role {
            SenderRoleV1::Initiator => 1,
            SenderRoleV1::Solver => 2,
            SenderRoleV1::Observer => 3,
        });
    }
    digest(b"DOM/SHARED-BOOTSTRAP/SCOPE/V12\0", &bytes)
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    use blake2::{digest::consts::U32, Digest};
    let mut hash = blake2::Blake2b::<U32>::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

impl ProductionBoundDomSharedOutputV12 {
    /// Public bindings reconstructed only after both signed native commitments
    /// and their capsule reveals have been authenticated.
    pub(crate) fn shared_bindings_v22(&self) -> &[dom_adaptor::SharedBlindingBindingV1; 2] {
        &self.shared_bindings
    }
    pub(crate) fn runtime_public_record_v16(
        &self,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, ProductionDomSharedBootstrapErrorV12> {
        if !matches!(
            key,
            b"dsc1-reveal-v16"
                | b"bp-start-v16"
                | b"relay-expiry-v16"
                | b"wallet-offer-v17"
                | b"peer-wallet-offer-v17"
                | b"wallet-key-proofs-v18"
                | b"peer-wallet-key-proofs-v18"
                | b"xmr-payout-principal-v22"
                | b"xmr-payout-change-v22"
                | b"xmr-payout-refund-v22"
                | b"xmr-payout-compensation-v22"
                | b"xmr-graph-keys-v22"
                | b"xmr-graph-proofs-v22"
                | b"xmr-funding-offer-v22"
                | b"xmr-graph-offer-v22"
                | b"xmr-peer-graph-offer-v25"
        ) {
            return Err(ProductionDomSharedBootstrapErrorV12::Binding);
        }
        let retained = self
            .journal
            .opaque(NS, key)
            .map_err(|_| ProductionDomSharedBootstrapErrorV12::Journal)?;
        if retained
            .as_ref()
            .is_some_and(|bytes| !runtime_public_length_valid(key, bytes.len()))
        {
            return Err(ProductionDomSharedBootstrapErrorV12::Journal);
        }
        Ok(retained)
    }
    pub(crate) fn retain_runtime_public_v16(
        &mut self,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<(), ProductionDomSharedBootstrapErrorV12> {
        // Peer evidence has a dedicated authenticated ingress below. Generic
        // public-record writes must not manufacture peer identity provenance.
        if key == b"xmr-peer-graph-offer-v25" || !runtime_public_length_valid(key, bytes.len()) {
            return Err(ProductionDomSharedBootstrapErrorV12::Binding);
        }
        if let Some(old) = self.runtime_public_record_v16(key)? {
            if old != bytes {
                return Err(ProductionDomSharedBootstrapErrorV12::Journal);
            }
            return Ok(());
        }
        self.journal
            .put_opaque(NS, key, bytes)
            .map_err(|_| ProductionDomSharedBootstrapErrorV12::Journal)?;
        if self.runtime_public_record_v16(key)?.as_deref() != Some(bytes) {
            return Err(ProductionDomSharedBootstrapErrorV12::Journal);
        }
        Ok(())
    }

    /// Authenticate the peer beneficiary's exact public graph, retain it in
    /// this original journal, and only then release its principal proof token.
    /// Missing state is not reconstructed by copying another actor's custody.
    pub(crate) fn retain_peer_f6_principal_v25(
        &mut self,
        source: &crate::production_noise_relay::ProductionNoiseGraphOfferV22,
        candidate: &crate::production_noise_relay::ProductionReceivedXmrGraphCandidateV22,
    ) -> Result<
        crate::production_noise_relay::ProductionAuthenticatedXmrClaimPrincipalV25,
        ProductionDomSharedBootstrapErrorV12,
    > {
        use ProductionDomSharedBootstrapErrorV12 as Error;
        source
            .verify_f6_peer_principal_v25(self, candidate)
            .map_err(|_| Error::Binding)?;
        let key = b"xmr-peer-graph-offer-v25";
        if !runtime_public_length_valid(key, candidate.bytes().len()) {
            return Err(Error::Binding);
        }
        if let Some(old) = self.runtime_public_record_v16(key)? {
            if old != candidate.bytes() {
                return Err(Error::Journal);
            }
        } else {
            self.journal
                .put_opaque_if_absent(NS, key, candidate.bytes())
                .map_err(|_| Error::Journal)?;
        }
        if self.runtime_public_record_v16(key)?.as_deref() != Some(candidate.bytes()) {
            return Err(Error::Journal);
        }
        source
            .reopen_f6_principal_v25(self)
            .map_err(|_| Error::Binding)?
            .ok_or(Error::Journal)
    }
}

fn runtime_public_length_valid(key: &[u8], length: usize) -> bool {
    if key == b"xmr-graph-proofs-v22" {
        return length
            == xmr_refund_policy::graph_key_proofs_v22::XmrGraphKeyProofScopeV22::ENCODED_LEN;
    }
    if key == b"xmr-graph-keys-v22" {
        return length == 32;
    }
    length > 0 && length <= runtime_public_limit(key)
}

#[cfg(test)]
mod runtime_public_length_tests {
    use super::*;

    #[test]
    fn graph_commitment_requires_exact_length_and_payouts_remain_bounded() {
        for length in [0, 1, 31, 33, 2048, 4096, usize::MAX] {
            assert!(!runtime_public_length_valid(b"xmr-graph-keys-v22", length));
        }
        assert!(runtime_public_length_valid(b"xmr-graph-keys-v22", 32));
        let proof_length =
            xmr_refund_policy::graph_key_proofs_v22::XmrGraphKeyProofScopeV22::ENCODED_LEN;
        assert!(runtime_public_length_valid(
            b"xmr-graph-proofs-v22",
            proof_length
        ));
        for length in [0, 32, proof_length - 1, proof_length + 1, usize::MAX] {
            assert!(!runtime_public_length_valid(
                b"xmr-graph-proofs-v22",
                length
            ));
        }
        for key in [
            b"xmr-payout-principal-v22".as_slice(),
            b"xmr-payout-change-v22".as_slice(),
            b"xmr-payout-refund-v22".as_slice(),
            b"xmr-payout-compensation-v22".as_slice(),
        ] {
            let limit = runtime_public_limit(key);
            assert!(!runtime_public_length_valid(key, 0));
            assert!(runtime_public_length_valid(key, limit));
            assert!(!runtime_public_length_valid(key, limit + 1));
            assert!(!runtime_public_length_valid(key, usize::MAX));
        }
    }
}

fn runtime_public_limit(key: &[u8]) -> usize {
    if matches!(key, b"xmr-graph-offer-v22" | b"xmr-peer-graph-offer-v25") {
        return xmr_refund_policy::graph_offer_v22::XmrGraphOfferV22::MAX_BYTES;
    }
    if key == b"xmr-funding-offer-v22" {
        return xmr_refund_policy::funding_offer_v22::XmrFundingOfferV22::MAX_BYTES;
    }
    if matches!(
        key,
        b"xmr-payout-principal-v22"
            | b"xmr-payout-change-v22"
            | b"xmr-payout-refund-v22"
            | b"xmr-payout-compensation-v22"
    ) {
        return xmr_refund_policy::payout_offer_v22::XmrPolicyPayoutOfferV22::MAX_BYTES;
    }
    if matches!(
        key,
        b"wallet-key-proofs-v18" | b"peer-wallet-key-proofs-v18"
    ) {
        dom_adaptor::DomBootstrapProvenOfferV18::MAX_BYTES
    } else if matches!(key, b"wallet-offer-v17" | b"peer-wallet-offer-v17") {
        dom_adaptor::DomBootstrapOfferV17::MAX_BYTES
    } else {
        2048
    }
}

/// Public scope for the independently initialized XMR cancellation output D.
/// Construction pins the validated policy to the parent deployment and roster;
/// creating or reopening private material still uses the native vault journal.
pub(crate) struct ProductionXmrCancelledBootstrapScopeV22 {
    binding: DomSessionBindingV1,
    roster: ProductionRosterLegV1,
}

impl ProductionXmrCancelledBootstrapScopeV22 {
    pub(crate) fn new(
        parent: DomSessionBindingV1,
        mut roster: ProductionRosterLegV1,
        policy: &xmr_refund_policy::compensation::ValidatedXmrCompensationPolicyV11,
    ) -> Result<Self, ProductionDomSharedBootstrapErrorV12> {
        use ProductionDomSharedBootstrapErrorV12 as Error;
        let economic = policy.policy();
        let ids = roster.members.map(|member| member.participant_id.0);
        if economic.dom_chain_id != parent.chain_id()
            || economic.session_id != parent.session_id()
            || policy.terms_hash() != &parent.terms_digest()
            || roster.session_id != parent.session_id()
            || ids[0] >= ids[1]
            || !ids.contains(&economic.dom_funder)
            || !ids.contains(&economic.xmr_funder)
            || economic.dom_funder == economic.xmr_funder
            || ids[usize::from(parent.participant().protocol_index())]
                != parent.participant().participant_id()
        {
            return Err(Error::Binding);
        }
        let binding = parent
            .for_xmr_cancelled_output_v22()
            .map_err(|_| Error::Binding)?;
        if binding.session_id()
            != xmr_refund_policy::graph_builder::xmr_cancelled_output_session_v12(policy)
        {
            return Err(Error::Binding);
        }
        // Keep the authenticated parent roster snapshot and member identities.
        // The derived session is separately committed in the bootstrap scope.
        roster.session_id = binding.session_id();
        Ok(Self { binding, roster })
    }

    pub(crate) const fn binding(&self) -> DomSessionBindingV1 {
        self.binding
    }

    pub(crate) fn journal_binding(
        &self,
    ) -> Result<store::ProductionStoreBindingV1, ProductionDomSharedBootstrapErrorV12> {
        shared_bootstrap_journal_binding_v12(self.binding, &self.roster)
    }

    /// Fresh provisioning; missing private material is allowed only if the
    /// native D journal is empty. A C journal is refused before vault mutation.
    pub(crate) fn open(
        self,
        vault: ContractsNonceVaultV1,
        journal: Store,
        chain: TrustedChainIdV1,
    ) -> Result<ProductionDomSharedBootstrapV12, ProductionDomSharedBootstrapErrorV12> {
        ProductionDomSharedBootstrapV12::open(vault, journal, self.binding, chain, self.roster)
    }

    /// Restart never creates a replacement share for a missing D contribution.
    pub(crate) fn open_retained(
        self,
        vault: ContractsNonceVaultV1,
        journal: Store,
        chain: TrustedChainIdV1,
    ) -> Result<ProductionDomSharedBootstrapV12, ProductionDomSharedBootstrapErrorV12> {
        ProductionDomSharedBootstrapV12::open_retained(
            vault,
            journal,
            self.binding,
            chain,
            self.roster,
        )
    }
}
