//! Concrete EVM funding observation with an exact transaction and live lock.
//!
//! This token is an observation prerequisite, never a signing capability.
//! Receipt inclusion, deployment attestation and finalized ancestry use the
//! native adapter. `lockOf` is additionally read at an exact canonical head:
//! a historical `LockOpened` event cannot authorize an already settled lock.

use adapter_evm::{
    abi::{selector, word_address, word_u64},
    adaptor_address, derive_binding, derive_lock_id,
    rpc::{hex_bytes, hex_bytes32, hex_of, hex_quantity, EthClient, HttpJsonRpc},
    EvidenceKind, EvmAdapter, EvmAdapterConfig, JsonRpc, LockTerms,
};
use counterparty_api::{AdapterError, VerifiedOutcome};
use deployment_registry::ResolvedEvmDeploymentV1;
use kaystra_core::{
    terms::SettlementTermsV1,
    types::{LockMechanism, TimelockSpec},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Instant;

use super::{
    ExternalFundingEvidenceV11, F7ExternalFamilyV11, F7FamilyAuthorityErrorV11, F7FundingIdV11,
};

/// Native-adapter verified funding and a still-open exact EVM lock.
///
/// There is no decoder or public constructor from an evidence blob. Reobserve
/// immediately before using this prerequisite in a final authorization.
pub struct VerifiedEvmFundingV11 {
    pub(super) evidence: ExternalFundingEvidenceV11,
}

impl VerifiedEvmFundingV11 {
    /// Complete read-only family, immutable terms and canonical snapshot facts.
    pub const fn facts(&self) -> &ExternalFundingEvidenceV11 {
        &self.evidence
    }
    /// Exact native funding transaction identity.
    pub const fn funding_id(&self) -> &F7FundingIdV11 {
        &self.evidence.funding_id
    }
    /// Exact finalized funding block.
    pub const fn block_hash(&self) -> &[u8; 32] {
        &self.evidence.block_hash
    }
    /// Funding block number.
    pub const fn block_height(&self) -> u64 {
        self.evidence.position
    }
    /// Commitment to the complete native observation and live lock checks.
    pub const fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence.evidence_digest
    }
}

/// Read-only authority owning concrete HTTP transports for one selected chain.
pub struct EvmFundingAuthorityV11 {
    adapter: EvmAdapter<HttpJsonRpc>,
    rpc: HttpJsonRpc,
    config: EvmAdapterConfig,
    terms: SettlementTermsV1,
    lock_terms: LockTerms,
    lock_id: [u8; 32],
    genesis_hash: [u8; 32],
}

impl EvmFundingAuthorityV11 {
    /// Bind exact frozen terms to a deployment from the authenticated registry.
    ///
    /// Both internal transports use the same URL; callers cannot substitute a
    /// generic RPC implementation that manufactures native adapter evidence.
    pub fn new(
        deployment: &ResolvedEvmDeploymentV1,
        terms: &SettlementTermsV1,
        endpoint: &str,
        timeout_seconds: u64,
    ) -> Result<Self, F7FamilyAuthorityErrorV11> {
        if endpoint.is_empty() || timeout_seconds == 0 || timeout_seconds > 120 {
            return Err(F7FamilyAuthorityErrorV11::Bounds);
        }
        let config = deployment.adapter_config();
        let lock_terms = bind_terms(deployment, terms)?;
        let binding =
            derive_binding(config.chain_id, &config.contract, &lock_terms).map_err(map_adapter)?;
        let lock_id = derive_lock_id(&binding, &config.funder).map_err(map_adapter)?;
        let adapter = EvmAdapter::new(config, HttpJsonRpc::new(endpoint, timeout_seconds))
            .map_err(map_adapter)?;
        adapter.track_lock(&lock_terms).map_err(map_adapter)?;
        Ok(Self {
            adapter,
            rpc: HttpJsonRpc::new(endpoint, timeout_seconds),
            config,
            terms: terms.clone(),
            lock_terms,
            lock_id,
            genesis_hash: deployment.deployment().genesis_hash,
        })
    }

    /// Observe the requested funding transaction, with a positive remaining
    /// claim window measured against the latest block's native timestamp.
    ///
    /// A genuinely unknown receipt returns `Ok(None)`. A response carrying a
    /// different transaction hash is a hard error, including when another
    /// response is absent. The token never substitutes a different funding tx.
    pub fn observe(
        &self,
        requested_txid: [u8; 32],
        minimum_remaining_seconds: u64,
    ) -> Result<Option<VerifiedEvmFundingV11>, F7FamilyAuthorityErrorV11> {
        if requested_txid == [0; 32] || minimum_remaining_seconds == 0 {
            return Err(F7FamilyAuthorityErrorV11::Binding);
        }
        self.adapter.preflight().map_err(map_adapter)?;
        let client = EthClient::new(&self.rpc);
        let genesis = client
            .block_by_number(0)
            .map_err(map_adapter)?
            .ok_or(F7FamilyAuthorityErrorV11::Unavailable)?;
        if genesis.hash != self.genesis_hash {
            return Err(F7FamilyAuthorityErrorV11::InvalidEvidence);
        }
        let receipt = client.receipt(&requested_txid).map_err(map_adapter)?;
        let transaction = client.transaction(&requested_txid).map_err(map_adapter)?;
        if !require_requested_identity(
            requested_txid,
            receipt.as_ref().map(|value| value.tx_hash),
            transaction.as_ref().map(|value| value.hash),
        )? {
            // An unmined transaction is a legitimate absence of funding.
            return Ok(None);
        }
        let evidence = self
            .adapter
            .collect_evidence(&self.lock_id, EvidenceKind::Funded)
            .map_err(map_adapter)?;
        if evidence.tx_hash != requested_txid || evidence.terms != self.lock_terms {
            return Err(F7FamilyAuthorityErrorV11::InvalidEvidence);
        }
        let encoded = evidence.encode();
        match self
            .adapter
            .verify_evidence_for_lock(&encoded, &self.lock_id)
            .map_err(map_adapter)?
        {
            VerifiedOutcome::Funded { height } if height == evidence.block_number => {}
            _ => return Err(F7FamilyAuthorityErrorV11::InvalidEvidence),
        }
        let head = self
            .adapter
            .finalized_head_checked()
            .map_err(|_| F7FamilyAuthorityErrorV11::Unavailable)?;
        if head.height != evidence.finalized_height || head.hash != evidence.finalized_block_hash {
            return Err(F7FamilyAuthorityErrorV11::Unavailable);
        }
        let depth = head
            .height
            .checked_sub(evidence.block_number)
            .and_then(|n| n.checked_add(1))
            .ok_or(F7FamilyAuthorityErrorV11::InvalidEvidence)?;
        if depth < u64::from(self.terms.counterparty_leg.finality.min_confirmations) {
            return Err(F7FamilyAuthorityErrorV11::InsufficientFinality);
        }
        self.require_open_at(head.hash)?;
        let latest = self.latest_clock()?;
        if latest.0 < head.height {
            return Err(F7FamilyAuthorityErrorV11::InvalidEvidence);
        }
        self.require_open_at(latest.1)?;
        if latest
            .2
            .checked_add(minimum_remaining_seconds)
            .map_or(true, |last| last >= self.lock_terms.deadline)
        {
            return Err(F7FamilyAuthorityErrorV11::WindowClosed);
        }
        if self.latest_clock()? != latest
            || self
                .adapter
                .finalized_head_checked()
                .map_err(|_| F7FamilyAuthorityErrorV11::Unavailable)?
                != head
        {
            return Err(F7FamilyAuthorityErrorV11::Unavailable);
        }
        let mut digest = Sha256::new();
        digest.update(b"DOM-INTEROP/F7-EVM-OBSERVATION/V11\0");
        digest.update(self.terms.settlement_id.0);
        digest.update(&encoded);
        digest.update(latest.1);
        digest.update(latest.2.to_be_bytes());
        digest.update(minimum_remaining_seconds.to_be_bytes());
        Ok(Some(VerifiedEvmFundingV11 {
            evidence: ExternalFundingEvidenceV11 {
                family: F7ExternalFamilyV11::Evm,
                settlement_id: self.terms.settlement_id.0,
                terms_hash: self.lock_terms.terms_hash,
                chain_registry_id: self.terms.counterparty_leg.chain_id.0,
                funding_id: F7FundingIdV11::Hash32(requested_txid),
                block_hash: evidence.block_hash,
                position: evidence.block_number,
                observed_tip_hash: head.hash,
                observed_tip_position: head.height,
                confirmations: u32::try_from(depth)
                    .map_err(|_| F7FamilyAuthorityErrorV11::Bounds)?,
                evidence_digest: digest.finalize().into(),
                observed_at: Instant::now(),
            },
        }))
    }

    fn require_open_at(&self, block_hash: [u8; 32]) -> Result<(), F7FamilyAuthorityErrorV11> {
        let mut calldata = selector("lockOf(bytes32)").to_vec();
        calldata.extend_from_slice(&self.lock_id);
        let answer = self
            .rpc
            .call(
                "eth_call",
                json!([
                    {"to":hex_of(&self.config.contract),"data":hex_of(&calldata)},
                    {"blockHash":hex_of(&block_hash),"requireCanonical":true}
                ]),
            )
            .map_err(map_adapter)?;
        let bytes = hex_bytes(&answer, 256).map_err(map_adapter)?;
        require_open_lock(&bytes, &self.config, &self.lock_terms)
    }

    fn latest_clock(&self) -> Result<(u64, [u8; 32], u64), F7FamilyAuthorityErrorV11> {
        let value = self
            .rpc
            .call("eth_getBlockByNumber", json!(["latest", false]))
            .map_err(map_adapter)?;
        if value.is_null() {
            return Err(F7FamilyAuthorityErrorV11::Unavailable);
        }
        let field = |name| {
            value
                .get(name)
                .ok_or(F7FamilyAuthorityErrorV11::InvalidEvidence)
        };
        Ok((
            hex_quantity(field("number")?).map_err(map_adapter)?,
            hex_bytes32(field("hash")?).map_err(map_adapter)?,
            hex_quantity(field("timestamp")?).map_err(map_adapter)?,
        ))
    }
}

fn bind_terms(
    deployment: &ResolvedEvmDeploymentV1,
    terms: &SettlementTermsV1,
) -> Result<LockTerms, F7FamilyAuthorityErrorV11> {
    let terms_hash = terms
        .terms_hash()
        .map_err(|_| F7FamilyAuthorityErrorV11::Binding)?;
    let cfg = deployment.adapter_config();
    cfg.validate().map_err(map_adapter)?;
    if cfg.terms_hash != terms_hash
        || cfg.session_id != terms.session_id.0
        || cfg.dom_chain_id != terms.dom_leg.chain_id.0
        || terms.counterparty_leg.chain_id != deployment.asset_binding().chain_id
        || terms.counterparty_leg.asset_id != deployment.asset_binding().asset_id
        || terms.counterparty_leg.adapter_profile_hash != deployment.profile_digest()
        || terms.counterparty_leg.mechanism != LockMechanism::ConditionLock
        || terms.settlement_id.0 == [0; 32]
    {
        return Err(F7FamilyAuthorityErrorV11::Binding);
    }
    let deadline = match terms.counterparty_leg.deadline {
        TimelockSpec::TimestampSeconds { value } if value != 0 => value,
        _ => return Err(F7FamilyAuthorityErrorV11::Binding),
    };
    let mut amount = [0; 32];
    amount[16..].copy_from_slice(&terms.counterparty_leg.amount.to_be_bytes());
    Ok(LockTerms {
        dom_chain_id: cfg.dom_chain_id,
        direction: cfg.direction.as_u8(),
        session_id: cfg.session_id,
        terms_hash,
        participants_hash: cfg.participants_hash,
        asset: cfg.asset,
        amount,
        beneficiary: cfg.beneficiary,
        adaptor_address: adaptor_address(&terms.adaptor_point_sec1).map_err(map_adapter)?,
        deadline,
    })
}

fn require_open_lock(
    bytes: &[u8],
    cfg: &EvmAdapterConfig,
    terms: &LockTerms,
) -> Result<(), F7FamilyAuthorityErrorV11> {
    let binding = derive_binding(cfg.chain_id, &cfg.contract, terms).map_err(map_adapter)?;
    let expected = [
        word_address(cfg.funder),
        word_address(terms.beneficiary),
        word_address(terms.adaptor_address),
        word_address(terms.asset),
        terms.amount,
        word_u64(terms.deadline),
        binding,
        [0; 32],
    ];
    if bytes.len() != expected.len() * 32
        || !bytes
            .chunks_exact(32)
            .zip(expected)
            .all(|(actual, wanted)| actual == wanted)
    {
        return Err(F7FamilyAuthorityErrorV11::InvalidEvidence);
    }
    Ok(())
}

fn require_requested_identity(
    requested: [u8; 32],
    receipt: Option<[u8; 32]>,
    transaction: Option<[u8; 32]>,
) -> Result<bool, F7FamilyAuthorityErrorV11> {
    if receipt.is_some_and(|value| value != requested)
        || transaction.is_some_and(|value| value != requested)
        || (receipt.is_some() && transaction.is_none())
    {
        return Err(F7FamilyAuthorityErrorV11::InvalidEvidence);
    }
    Ok(receipt.is_some())
}

fn map_adapter(error: AdapterError) -> F7FamilyAuthorityErrorV11 {
    match error {
        AdapterError::AdapterUnavailable => F7FamilyAuthorityErrorV11::Unavailable,
        AdapterError::BoundsExceeded => F7FamilyAuthorityErrorV11::Bounds,
        _ => F7FamilyAuthorityErrorV11::InvalidEvidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_fixture() -> (EvmAdapterConfig, LockTerms) {
        let cfg = EvmAdapterConfig {
            chain_id: 31337,
            contract: [0xc0; 20],
            expected_code_hash: [0xc1; 32],
            dom_chain_id: [1; 32],
            direction: adapter_evm::Direction::DomToEvm,
            session_id: [2; 32],
            terms_hash: [3; 32],
            participants_hash: [4; 32],
            asset: [0; 20],
            beneficiary: [0xbe; 20],
            funder: [0xf0; 20],
            start_block: 0,
            page_size: 8,
            max_reorg_depth: 32,
            gas_limit_hint: 300_000,
        };
        let terms = LockTerms {
            dom_chain_id: cfg.dom_chain_id,
            direction: cfg.direction.as_u8(),
            session_id: cfg.session_id,
            terms_hash: cfg.terms_hash,
            participants_hash: cfg.participants_hash,
            asset: cfg.asset,
            amount: adapter_evm::abi::word_u128(1_000),
            beneficiary: cfg.beneficiary,
            adaptor_address: [0x66; 20],
            deadline: 1_800_000_000,
        };
        (cfg, terms)
    }

    #[test]
    fn open_lock_requires_all_eight_exact_abi_words() -> Result<(), F7FamilyAuthorityErrorV11> {
        let (cfg, terms) = native_fixture();
        let binding = derive_binding(cfg.chain_id, &cfg.contract, &terms).map_err(map_adapter)?;
        let words = [
            word_address(cfg.funder),
            word_address(terms.beneficiary),
            word_address(terms.adaptor_address),
            word_address(terms.asset),
            terms.amount,
            word_u64(terms.deadline),
            binding,
            [0; 32],
        ];
        let canonical: Vec<u8> = words.into_iter().flatten().collect();
        assert!(require_open_lock(&canonical, &cfg, &terms).is_ok());
        for index in 0..canonical.len() {
            let mut changed = canonical.clone();
            changed[index] ^= 1;
            assert!(require_open_lock(&changed, &cfg, &terms).is_err());
        }
        assert!(require_open_lock(&canonical[..255], &cfg, &terms).is_err());
        let mut trailing = canonical;
        trailing.push(0);
        assert!(require_open_lock(&trailing, &cfg, &terms).is_err());
        Ok(())
    }

    #[test]
    fn missing_receipt_is_distinct_from_a_substituted_identity() {
        let requested = [1; 32];
        let swapped = [2; 32];
        assert_eq!(require_requested_identity(requested, None, None), Ok(false));
        assert_eq!(
            require_requested_identity(requested, None, Some(requested)),
            Ok(false)
        );
        assert_eq!(
            require_requested_identity(requested, Some(requested), Some(requested)),
            Ok(true)
        );
        assert!(require_requested_identity(requested, None, Some(swapped)).is_err());
        assert!(require_requested_identity(requested, Some(swapped), None).is_err());
        assert!(require_requested_identity(requested, Some(requested), None).is_err());
    }
}
