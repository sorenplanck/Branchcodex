//! Concrete Solana observation; terminal escrows never count as live funding.

use chain_profile::{ChainKindV1, SolanaNetworkV1};
use deployment_registry::{AssetRepresentationV1, ResolvedSolanaDeploymentV1};
use kaystra_core::terms::SettlementTermsV1;
use sha2::{Digest, Sha256};
use solana_escrow_wire::{EscrowStateV1, EscrowStatus};
use solana_evidence::SolanaEvidenceBodyV1;
use solana_observer::{ObservationKind, ObserverError, SolanaSettlementObserver};
use solana_profile::{
    revalidate_setup_for_chain_profile_v25, validate_setup, SolanaAdapterProfileV1, SolanaAssetV1,
    SolanaNetwork, ValidatedSolanaSetup,
};
use solana_rpc::{HttpSolanaRpc, RpcError, SolanaRpc};
use solana_rpc_pool::SolanaRpcPool;
use solana_types::{Commitment, SolanaSignature};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Instant,
};

use super::{
    ExternalFundingEvidenceV11, F7ExternalFamilyV11, F7FamilyAuthorityErrorV11 as Error,
    F7FundingIdV11,
};

/// Exact, still-funded Solana escrow observed through concrete HTTP quorum.
/// This prerequisite contains no signing authority and no serialized constructor.
pub struct VerifiedSolanaFundingV11 {
    pub(super) evidence: ExternalFundingEvidenceV11,
}

impl VerifiedSolanaFundingV11 {
    /// Complete read-only family, immutable terms and canonical snapshot facts.
    pub const fn facts(&self) -> &ExternalFundingEvidenceV11 {
        &self.evidence
    }
    /// Complete native 64-byte funding signature; never a truncated hash.
    pub const fn funding_id(&self) -> &F7FundingIdV11 {
        &self.evidence.funding_id
    }
    /// Canonical blockhash at the successful funding slot.
    pub const fn block_hash(&self) -> &[u8; 32] {
        &self.evidence.block_hash
    }
    /// Native funding slot.
    pub const fn slot(&self) -> u64 {
        self.evidence.position
    }
    /// Commitment to full native evidence and the stable current state quorum.
    pub const fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence.evidence_digest
    }
}

/// Bound observer with authenticated cluster genesis and live-state checks.
pub struct SolanaFundingAuthorityV11 {
    observer: SolanaSettlementObserver<HttpSolanaRpc>,
    pool: SolanaRpcPool<HttpSolanaRpc>,
    setup: ValidatedSolanaSetup,
    terms: SettlementTermsV1,
    genesis: [u8; 32],
}

impl SolanaFundingAuthorityV11 {
    /// Construct only the selected Solana clients and bind their exact setup.
    ///
    /// Requires a strict configured majority and immutable program attestation.
    /// A registry chain or asset cannot be relabelled as another cluster.
    /// The existing registry capability identifies native SOL, so this factory
    /// rejects SPL setups until an authenticated SPL asset capability exists.
    pub fn new(
        deployment: &ResolvedSolanaDeploymentV1,
        terms: &SettlementTermsV1,
        setup: &ValidatedSolanaSetup,
        profile: SolanaAdapterProfileV1,
        endpoints: &[String],
    ) -> Result<Self, Error> {
        if endpoints.is_empty()
            || endpoints.len() > 32
            || endpoints.len() != usize::from(profile.rpc_node_count)
            || usize::from(profile.rpc_quorum) <= endpoints.len() / 2
            || usize::from(profile.rpc_quorum) > endpoints.len()
            || endpoints.iter().any(|url| url.is_empty())
            || endpoints.iter().collect::<BTreeSet<_>>().len() != endpoints.len()
            || !profile.require_immutable_program
            || terms.counterparty_leg.chain_id != deployment.asset_binding().chain_id
            || terms.counterparty_leg.asset_id != deployment.asset_binding().asset_id
            || terms.counterparty_leg.finality != deployment.profile().finality
            || deployment.asset_binding().representation != AssetRepresentationV1::Native
            || setup.asset() != SolanaAssetV1::NativeSol
            || deployment.deployment().genesis_hash == [0; 32]
        {
            return Err(Error::Binding);
        }
        require_registry_program(
            deployment.profile().kind,
            profile.network,
            profile.program_id.0,
            setup.program_data_hash(),
        )?;
        // A frozen V1 setup pins the operational adapter hash; a V25 setup pins
        // the registry chain-profile digest and pays proven accounts. The two
        // hashes are distinct domains, so exactly one rule can ever accept.
        let verified = if terms.counterparty_leg.adapter_profile_hash == profile.profile_hash() {
            validate_setup(&profile, terms, setup.binding().clone())
        } else {
            revalidate_setup_for_chain_profile_v25(&profile, terms, setup, deployment.profile())
        }
        .map_err(|_| Error::Binding)?;
        if verified.binding_hash() != setup.binding_hash() {
            return Err(Error::Binding);
        }
        let nodes = endpoints
            .iter()
            .map(|endpoint| {
                HttpSolanaRpc::new(
                    endpoint.clone(),
                    profile.max_signed_transaction_bytes as usize,
                )
                .map(Arc::new)
                .map_err(map_rpc)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pool = SolanaRpcPool::new(nodes, usize::from(profile.rpc_quorum))
            .map_err(|_| Error::Binding)?;
        let observer = SolanaSettlementObserver::new(
            pool.clone(),
            verified.clone(),
            profile,
            terms.counterparty_leg.finality.min_confirmations,
        )
        .map_err(map_observer)?;
        Ok(Self {
            observer,
            pool,
            setup: verified,
            terms: terms.clone(),
            genesis: deployment.deployment().genesis_hash,
        })
    }

    /// Observe one exact signature with native finalized evidence and an
    /// unchanged, still-Funded escrow snapshot around native verification.
    ///
    /// Unknown transactions produce `Ok(None)`. A swapped returned signature,
    /// malformed response or contradictory inclusion is a hard error even when
    /// another quorum member reports absence. Deadlines still require a fresh
    /// native clock in the final F7 signing decision; this is funding evidence.
    pub fn observe(
        &self,
        signature: SolanaSignature,
    ) -> Result<Option<VerifiedSolanaFundingV11>, Error> {
        if signature.0 == [0; 64] {
            return Err(Error::Binding);
        }
        let before = match self.snapshot(signature)? {
            Some(value) => value,
            None => return Ok(None),
        };
        let native = self
            .observer
            .observe(signature, ObservationKind::Funding)
            .map_err(map_observer)?;
        let SolanaEvidenceBodyV1::Funding(funding) = &native.body else {
            return Err(Error::InvalidEvidence);
        };
        if funding.signature != signature
            || funding.slot != before.slot
            || funding.blockhash.0 != before.block_hash
            || funding.settlement_id != self.setup.settlement_id()
            || funding.terms_hash != self.setup.terms_hash()
            || funding.state_hash != before.state_hash
            || funding.vault_hash != before.vault_hash
            || funding.program_data_hash != self.setup.program_data_hash()
        {
            return Err(Error::InvalidEvidence);
        }
        let after = self.snapshot(signature)?.ok_or(Error::WindowClosed)?;
        if after.tip < before.tip
            || after.slot != before.slot
            || after.block_hash != before.block_hash
            || after.transaction_hash != before.transaction_hash
            || after.state_hash != before.state_hash
            || after.vault_hash != before.vault_hash
        {
            return Err(Error::WindowClosed);
        }
        self.require_canonical_anchor(before.tip, before.tip_hash)?;
        let depth = after
            .tip
            .checked_sub(after.slot)
            .and_then(|d| d.checked_add(1))
            .ok_or(Error::InvalidEvidence)?;
        if depth < u64::from(self.terms.counterparty_leg.finality.min_confirmations) {
            return Err(Error::InsufficientFinality);
        }
        let mut digest = Sha256::new();
        digest.update(b"DOM-INTEROP/F7-SOLANA-FUNDING/V11\0");
        digest.update(self.genesis);
        digest.update(native.encode().map_err(|_| Error::InvalidEvidence)?);
        digest.update(before.digest());
        digest.update(after.digest());
        Ok(Some(VerifiedSolanaFundingV11 {
            evidence: ExternalFundingEvidenceV11 {
                family: F7ExternalFamilyV11::Solana,
                settlement_id: self.setup.settlement_id(),
                terms_hash: self.setup.terms_hash(),
                chain_registry_id: self.terms.counterparty_leg.chain_id.0,
                funding_id: F7FundingIdV11::SolanaSignature(signature.0),
                block_hash: before.block_hash,
                position: before.slot,
                observed_tip_hash: after.tip_hash,
                observed_tip_position: after.tip,
                confirmations: u32::try_from(depth).map_err(|_| Error::Bounds)?,
                evidence_digest: digest.finalize().into(),
                observed_at: Instant::now(),
            },
        }))
    }

    fn snapshot(&self, signature: SolanaSignature) -> Result<Option<Snapshot>, Error> {
        let tip = self.finalized_tip()?;
        let mut absent = 0usize;
        let mut votes: BTreeMap<[u8; 32], (usize, Snapshot)> = BTreeMap::new();
        for node in self.pool.nodes() {
            match self.node_snapshot(node, signature, tip) {
                Ok(None) => absent += 1,
                Ok(Some(value)) => {
                    let entry = votes.entry(value.digest()).or_insert((0, value));
                    entry.0 += 1;
                }
                Err(Error::Unavailable) => {}
                Err(error) => return Err(error),
            }
        }
        let mut present = votes
            .into_values()
            .filter(|(count, _)| *count >= self.pool.quorum());
        let first = present.next();
        if present.next().is_some() || (first.is_some() && absent >= self.pool.quorum()) {
            return Err(Error::InvalidEvidence);
        }
        match first {
            Some((_, snapshot)) => Ok(Some(snapshot)),
            None if absent >= self.pool.quorum() => Ok(None),
            None => Err(Error::Unavailable),
        }
    }

    fn finalized_tip(&self) -> Result<u64, Error> {
        let mut tips = Vec::new();
        for node in self.pool.nodes() {
            match node.genesis_hash().map_err(map_rpc) {
                Ok(genesis) if genesis.0 == self.genesis => {}
                Ok(_) => return Err(Error::InvalidEvidence),
                Err(Error::Unavailable) => continue,
                Err(error) => return Err(error),
            }
            match node.get_slot(Commitment::Finalized).map_err(map_rpc) {
                Ok(tip) => tips.push(tip),
                Err(Error::Unavailable) => {}
                Err(error) => return Err(error),
            }
        }
        if tips.len() < self.pool.quorum() {
            return Err(Error::Unavailable);
        }
        tips.sort_unstable();
        Ok(tips[tips.len() - self.pool.quorum()])
    }

    fn require_canonical_anchor(&self, slot: u64, expected: [u8; 32]) -> Result<(), Error> {
        let mut votes = 0;
        for node in self.pool.nodes() {
            match node.get_block_anchor(slot).map_err(map_rpc) {
                Ok(Some(anchor)) if anchor.slot == slot && anchor.blockhash.0 == expected => {
                    votes += 1
                }
                Ok(Some(_)) => return Err(Error::InvalidEvidence),
                Ok(None) | Err(Error::Unavailable) => {}
                Err(error) => return Err(error),
            }
        }
        if votes < self.pool.quorum() {
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    fn node_snapshot(
        &self,
        node: &HttpSolanaRpc,
        signature: SolanaSignature,
        tip: u64,
    ) -> Result<Option<Snapshot>, Error> {
        if node.genesis_hash().map_err(map_rpc)?.0 != self.genesis {
            return Err(Error::InvalidEvidence);
        }
        // Always fetch both identity-bearing results before handling absence.
        let transaction = node
            .get_transaction(signature, Commitment::Finalized)
            .map_err(map_rpc)?;
        let status = node.get_signature_status(signature).map_err(map_rpc)?;
        if transaction
            .as_ref()
            .is_some_and(|tx| tx.signature != signature)
        {
            return Err(Error::InvalidEvidence);
        }
        let (transaction, status) = match (transaction, status) {
            (None, None) => return Ok(None),
            (None, Some(status))
                if status.confirmation != Commitment::Finalized && !status.failed =>
            {
                return Ok(None);
            }
            (Some(transaction), Some(status)) => (transaction, status),
            _ => return Err(Error::InvalidEvidence),
        };
        if transaction.slot != status.slot || !transaction.success || status.failed {
            return Err(Error::InvalidEvidence);
        }
        if status.confirmation != Commitment::Finalized {
            return Err(Error::InsufficientFinality);
        }
        if tip < status.slot {
            return Err(Error::InvalidEvidence);
        }
        let node_tip = node.get_slot(Commitment::Finalized).map_err(map_rpc)?;
        if node_tip < tip || node_tip - tip > 64 {
            return Err(Error::Unavailable);
        }
        let tip_anchor = node
            .get_block_anchor(tip)
            .map_err(map_rpc)?
            .ok_or(Error::Unavailable)?;
        let block = node
            .get_block_anchor(status.slot)
            .map_err(map_rpc)?
            .ok_or(Error::Unavailable)?;
        if tip_anchor.slot != tip
            || block.slot != status.slot
            || tip_anchor.blockhash.0 == [0; 32]
            || block.blockhash.0 == [0; 32]
        {
            return Err(Error::InvalidEvidence);
        }
        let state_account = node
            .get_account(self.setup.state_pda(), Commitment::Finalized)
            .map_err(map_rpc)?
            .ok_or(Error::InvalidEvidence)?;
        let vault = node
            .get_account(self.setup.vault_pda(), Commitment::Finalized)
            .map_err(map_rpc)?
            .ok_or(Error::InvalidEvidence)?;
        let state =
            EscrowStateV1::decode(&state_account.data).map_err(|_| Error::InvalidEvidence)?;
        require_live_status(state.status, state.revealed_secret_be)?;
        if state_account.owner != self.setup.program_id()
            || state_account.executable
            || state.settlement_id != self.setup.settlement_id()
            || state.terms_hash != self.setup.terms_hash()
            || state.setup_id != self.setup.setup_id()
        {
            return Err(Error::InvalidEvidence);
        }
        if state_account.context_slot < tip
            || vault.context_slot < tip
            || state_account.context_slot - tip > 64
            || vault.context_slot - tip > 64
        {
            return Err(Error::Unavailable);
        }
        // Native observer separately validates every state field, rent/token
        // ownership, asset, amount and code attestation against these hashes.
        let mut state_hash = Sha256::new();
        state_hash.update(b"DOM-INTEROP/SOLANA-ESCROW-STATE/V1\0");
        state_hash.update(&state_account.data);
        if node.get_block_anchor(tip).map_err(map_rpc)? != Some(tip_anchor) {
            return Err(Error::Unavailable);
        }
        Ok(Some(Snapshot {
            tip,
            tip_hash: tip_anchor.blockhash.0,
            slot: status.slot,
            block_hash: block.blockhash.0,
            transaction_hash: transaction.commitment_hash(),
            state_hash: state_hash.finalize().into(),
            vault_hash: vault.commitment_hash(),
        }))
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Snapshot {
    tip: u64,
    tip_hash: [u8; 32],
    slot: u64,
    block_hash: [u8; 32],
    transaction_hash: [u8; 32],
    state_hash: [u8; 32],
    vault_hash: [u8; 32],
}

impl Snapshot {
    fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"DOM-INTEROP/F7-SOLANA-SNAPSHOT/V11\0");
        hash.update(self.tip.to_be_bytes());
        hash.update(self.tip_hash);
        hash.update(self.slot.to_be_bytes());
        hash.update(self.block_hash);
        hash.update(self.transaction_hash);
        hash.update(self.state_hash);
        hash.update(self.vault_hash);
        hash.finalize().into()
    }
}

fn require_live_status(status: EscrowStatus, secret: [u8; 32]) -> Result<(), Error> {
    if status != EscrowStatus::Funded || secret != [0; 32] {
        return Err(Error::InvalidEvidence);
    }
    Ok(())
}

fn require_registry_program(
    kind: ChainKindV1,
    network: SolanaNetwork,
    program: [u8; 32],
    code_hash: [u8; 32],
) -> Result<(), Error> {
    let expected_network = match network {
        SolanaNetwork::Devnet => SolanaNetworkV1::Devnet,
        SolanaNetwork::Testnet => SolanaNetworkV1::Testnet,
        SolanaNetwork::LocalValidator => SolanaNetworkV1::LocalValidator,
    };
    match kind {
        ChainKindV1::Solana {
            network,
            escrow_program,
            program_data_hash,
        } if network == expected_network
            && escrow_program == program
            && program_data_hash == code_hash =>
        {
            Ok(())
        }
        _ => Err(Error::Binding),
    }
}

fn map_rpc(error: RpcError) -> Error {
    match error {
        RpcError::Unavailable | RpcError::Remote | RpcError::NotFound => Error::Unavailable,
        RpcError::InvalidResponse => Error::InvalidEvidence,
        RpcError::BoundsExceeded => Error::Bounds,
    }
}

fn map_observer(error: ObserverError) -> Error {
    match error {
        ObserverError::Quorum => Error::Unavailable,
        ObserverError::NotFinalized | ObserverError::InsufficientDepth => {
            Error::InsufficientFinality
        }
        _ => Error::InvalidEvidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_terminal_escrows_cannot_be_funding_authority() {
        assert!(require_live_status(EscrowStatus::Funded, [0; 32]).is_ok());
        assert!(require_live_status(EscrowStatus::Claimed, [0; 32]).is_err());
        assert!(require_live_status(EscrowStatus::Refunded, [0; 32]).is_err());
        assert!(require_live_status(EscrowStatus::Funded, [1; 32]).is_err());
    }

    #[test]
    fn snapshot_hash_binds_funding_and_both_current_accounts() {
        let original = Snapshot {
            tip: 300,
            tip_hash: [1; 32],
            slot: 270,
            block_hash: [2; 32],
            transaction_hash: [3; 32],
            state_hash: [4; 32],
            vault_hash: [5; 32],
        };
        let digest = original.digest();
        let mut changed = original.clone();
        changed.vault_hash[0] ^= 1;
        assert_ne!(digest, changed.digest());
        let mut changed = original.clone();
        changed.state_hash[0] ^= 1;
        assert_ne!(digest, changed.digest());
        let mut changed = original;
        changed.transaction_hash[0] ^= 1;
        assert_ne!(digest, changed.digest());
    }

    #[test]
    fn native_setup_cannot_override_the_registry_program_code_or_network() {
        let kind = ChainKindV1::Solana {
            network: SolanaNetworkV1::Devnet,
            escrow_program: [1; 32],
            program_data_hash: [2; 32],
        };
        assert!(require_registry_program(kind, SolanaNetwork::Devnet, [1; 32], [2; 32]).is_ok());
        assert!(require_registry_program(kind, SolanaNetwork::Testnet, [1; 32], [2; 32]).is_err());
        assert!(require_registry_program(kind, SolanaNetwork::Devnet, [3; 32], [2; 32]).is_err());
        assert!(require_registry_program(kind, SolanaNetwork::Devnet, [1; 32], [3; 32]).is_err());
    }
}
