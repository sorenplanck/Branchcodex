//! Exact XMR funding through concrete quorum HTTP and authenticated UDS ports.

use super::{
    ExternalFundingEvidenceV11, F7ExternalFamilyV11, F7FamilyAuthorityErrorV11 as Error,
    F7FundingIdV11,
};
use deployment_registry::ResolvedMoneroDeploymentV1;
use kaystra_core::{types::LockMechanism, SettlementTermsV1};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, time::Instant};
use xmr_live_sidecar_api::{SecretScalarBytes, VerifyFundingRequestV2, API_VERSION_V2};
use xmr_live_sidecar_uds_client::BlockingUdsSidecarPort;
use xmr_observer::{
    confirmation_status, HttpXmrRpc, XmrObserverError, XmrRpcPool, XmrTransactionStatus,
};
use xmr_secret_store::{EncryptedSqliteSecretStore, SecretMaterialStore, SecretStoreError};
use xmr_setup_profile::{ValidatedXmrSetup, XmrAdapterProfileV1, XmrNetwork};
use xmr_spend_port::{FundingVerifyPort, SpendPortError};

/// Complete immutable XMR funding inputs. No supplied event or RPC trait can
/// stand in for the actual HTTP quorum and permissioned sidecar.
pub struct XmrFundingObservationRequestV11<'a> {
    /// Exact native signed settlement terms.
    pub terms: &'a SettlementTermsV1,
    /// DLEQ-verified shared destination and exact funding transaction.
    pub setup: &'a ValidatedXmrSetup,
    /// Complete profile committed by those terms.
    pub profile: &'a XmrAdapterProfileV1,
    /// Signed registry deployment fixing the exact network genesis and asset.
    pub deployment: &'a ResolvedMoneroDeploymentV1,
    /// Independent daemon URLs; count and quorum come from the frozen profile.
    pub daemon_urls: &'a [String],
}

/// Fresh concrete verification of the exact XMR output and canonical location.
/// No public constructor, codec, Clone or Debug; this is still only funding
/// evidence. DOM recovery and same-Store authorization remain mandatory.
pub struct VerifiedXmrFundingV11 {
    pub(super) evidence: ExternalFundingEvidenceV11,
    pub(super) setup_binding_hash: [u8; 32],
    pub(super) output_index: u32,
    dom_chain_id_v22: [u8; 32],
    session_id_v22: [u8; 32],
    genesis_hash_v22: [u8; 32],
    amount_piconero_v22: u64,
    observation_sources_v23: [u8; 32],
}

impl VerifiedXmrFundingV11 {
    /// Read-only complete family and canonical snapshot binding.
    pub const fn facts(&self) -> &ExternalFundingEvidenceV11 {
        &self.evidence
    }
    /// Digest of the exact DLEQ-verified shared destination setup.
    pub const fn setup_binding_hash(&self) -> &[u8; 32] {
        &self.setup_binding_hash
    }
    /// Exact output/event position authenticated by the funding view scan.
    pub const fn output_index(&self) -> u32 {
        self.output_index
    }
    /// Exact Monero funding transaction hash, never a caller-labelled txid.
    pub const fn funding_id(&self) -> &F7FundingIdV11 {
        &self.evidence.funding_id
    }
    /// Exact canonical funding block.
    pub const fn block_hash(&self) -> &[u8; 32] {
        &self.evidence.block_hash
    }
    /// Canonical funding height.
    pub const fn block_height(&self) -> u64 {
        self.evidence.position
    }
    /// Confirmation depth proven by stable quorum reads.
    pub const fn confirmations(&self) -> u32 {
        self.evidence.confirmations
    }
    /// Commitment to immutable setup, output and complete observation facts.
    pub const fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence.evidence_digest
    }
}

/// Verify the exact funded shared destination without reconstructing a spend
/// key or sending any spend share. The sidecar receives only the retained view
/// scalar. Both quorum snapshots must agree across the sidecar operation.
pub async fn verify_xmr_funding_v11(
    request: XmrFundingObservationRequestV11<'_>,
    sidecar: &mut BlockingUdsSidecarPort,
    secrets: &EncryptedSqliteSecretStore,
) -> Result<VerifiedXmrFundingV11, Error> {
    validate_request(&request)?;
    let profile = request.profile;
    let network = match profile.network {
        XmrNetwork::Mainnet => xmr_observer::XmrNetwork::Mainnet,
        XmrNetwork::Stagenet => xmr_observer::XmrNetwork::Stagenet,
        XmrNetwork::Testnet => xmr_observer::XmrNetwork::Testnet,
    };
    let nodes = request
        .daemon_urls
        .iter()
        .map(|url| HttpXmrRpc::new(url.clone()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_observer)?;
    let pool =
        XmrRpcPool::new(nodes, network, usize::from(profile.rpc_quorum)).map_err(map_observer)?;
    if pool.block_hash(0).await.map_err(map_observer)?
        != request.deployment.deployment().genesis_hash
    {
        return Err(Error::Binding);
    }
    let setup = request.setup;
    let terms = request.terms;
    let before = confirmation_status(&pool, setup.funding_tx_hash())
        .await
        .map_err(map_observer)?;
    let height = match before.status {
        XmrTransactionStatus::Unseen => return Err(Error::FundingAbsent),
        XmrTransactionStatus::InPool => return Err(Error::InsufficientFinality),
        XmrTransactionStatus::InBlock { block_height } => block_height,
    };
    if !before.is_final(u64::from(terms.counterparty_leg.finality.min_confirmations)) {
        return Err(Error::InsufficientFinality);
    }
    let block_hash = before.inclusion_block_hash.ok_or(Error::InvalidEvidence)?;
    let confirmations = u32::try_from(before.confirmations).map_err(|_| Error::Bounds)?;
    let nonce = funding_nonce(
        setup.settlement_id(),
        setup.terms_hash(),
        setup.binding_hash(),
        setup.funding_tx_hash(),
        block_hash,
        before.canonical_tip.hash,
    );
    let material = secrets
        .load(&setup.settlement_id(), &setup.terms_hash())
        .map_err(map_secret)?;
    let response = material
        .expose(|_, view| {
            sidecar.verify_funding(VerifyFundingRequestV2 {
                api_version: API_VERSION_V2,
                request_nonce: nonce,
                settlement_id: setup.settlement_id(),
                funding_tx_hash: setup.funding_tx_hash(),
                expected_amount_piconero: setup.expected_amount_piconero(),
                expected_spend_public_key: setup.combined_spend_public_key(),
                view_scalar: SecretScalarBytes::new(*view),
                auth_tag: [0; 32],
            })
        })
        .map_err(|error| match error {
            SpendPortError::Retryable => Error::Unavailable,
            SpendPortError::Rejected => Error::InvalidEvidence,
        })?;
    drop(material);
    // The concrete UDS client already performs validate_for and authenticates
    // peer credentials. Keep exact public echoes checked at this boundary too.
    if response.api_version != API_VERSION_V2
        || response.request_nonce != nonce
        || response.funding_tx_hash != setup.funding_tx_hash()
        || response.received_amount_piconero != setup.expected_amount_piconero()
        || !response.spendable
    {
        return Err(Error::InvalidEvidence);
    }
    let after = confirmation_status(&pool, setup.funding_tx_hash())
        .await
        .map_err(map_observer)?;
    if before != after {
        // A changing snapshot requires another fresh read; it does not prove
        // that the signed claim/refund window has elapsed.
        return Err(Error::Unavailable);
    }
    let mut digest = Sha256::new();
    digest.update(b"DOM-INTEROP/F7-XMR-FUNDING/V11\0");
    digest.update(nonce);
    digest.update(terms.counterparty_leg.chain_id.0);
    digest.update(setup.combined_spend_public_key());
    digest.update(response.event_index.to_be_bytes());
    digest.update(response.received_amount_piconero.to_be_bytes());
    digest.update(height.to_be_bytes());
    digest.update(before.canonical_tip.height.to_be_bytes());
    digest.update(confirmations.to_be_bytes());
    Ok(VerifiedXmrFundingV11 {
        evidence: ExternalFundingEvidenceV11 {
            family: F7ExternalFamilyV11::Monero,
            settlement_id: setup.settlement_id(),
            terms_hash: setup.terms_hash(),
            chain_registry_id: terms.counterparty_leg.chain_id.0,
            funding_id: F7FundingIdV11::Hash32(setup.funding_tx_hash()),
            block_hash,
            position: height,
            observed_tip_hash: before.canonical_tip.hash,
            observed_tip_position: before.canonical_tip.height,
            confirmations,
            evidence_digest: digest.finalize().into(),
            observed_at: Instant::now(),
        },
        setup_binding_hash: setup.binding_hash(),
        output_index: response.event_index,
        dom_chain_id_v22: terms.dom_leg.chain_id.0,
        session_id_v22: terms.session_id.0,
        genesis_hash_v22: request.deployment.deployment().genesis_hash,
        amount_piconero_v22: response.received_amount_piconero,
        observation_sources_v23: observation_sources_v23(request.daemon_urls),
    })
}

// Bind the two-phase promotion to the exact selected observation endpoints.
// Length prefixes prevent URL concatenation ambiguity; order stays exact.
fn observation_sources_v23(urls: &[String]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"DOM-INTEROP/F7-XMR-OBSERVATION-SOURCES/V23\0");
    digest.update((urls.len() as u64).to_be_bytes());
    for url in urls {
        digest.update((url.len() as u64).to_be_bytes());
        digest.update(url.as_bytes());
    }
    digest.finalize().into()
}

/// Revalidate an opaque observation before synchronous DOM promotion.
/// This function cannot manufacture funding evidence or renew its timestamp.
pub(super) fn require_funding_request_v23(
    request: &XmrFundingObservationRequestV11<'_>,
    funding: &VerifiedXmrFundingV11,
) -> Result<(), Error> {
    validate_request(request)?;
    let terms = request.terms;
    let setup = request.setup;
    let facts = funding.facts();
    if facts.family != F7ExternalFamilyV11::Monero
        || facts.settlement_id != terms.settlement_id.0
        || facts.terms_hash != setup.terms_hash()
        || facts.chain_registry_id != terms.counterparty_leg.chain_id.0
        || facts.funding_id != F7FundingIdV11::Hash32(setup.funding_tx_hash())
        || funding.setup_binding_hash != setup.binding_hash()
        || funding.dom_chain_id_v22 != terms.dom_leg.chain_id.0
        || funding.session_id_v22 != terms.session_id.0
        || funding.genesis_hash_v22 != request.deployment.deployment().genesis_hash
        || funding.amount_piconero_v22 != setup.expected_amount_piconero()
        || funding.observation_sources_v23 != observation_sources_v23(request.daemon_urls)
        || facts.confirmations < terms.counterparty_leg.finality.min_confirmations
    {
        return Err(Error::Binding);
    }
    if facts.age() > std::time::Duration::from_secs(60) {
        return Err(Error::WindowClosed);
    }
    Ok(())
}

fn validate_request(request: &XmrFundingObservationRequestV11<'_>) -> Result<(), Error> {
    let terms = request.terms;
    let setup = request.setup;
    let profile = request.profile;
    let deployment = request.deployment;
    terms.validate().map_err(|_| Error::Binding)?;
    xmr_setup_profile::require_setup_chain_profile_v24(terms, profile, setup, deployment.profile())
        .map_err(|_| Error::Binding)?;
    if terms.counterparty_leg.mechanism != LockMechanism::CrossCurveSharedSpend
        || terms.dom_leg.mechanism != LockMechanism::DomAdaptor2of2
        || terms.settlement_id.0 != setup.settlement_id()
        || terms.terms_hash().map_err(|_| Error::Binding)? != setup.terms_hash()
        || terms.counterparty_leg.adapter_profile_hash != deployment.profile_digest()
        || terms.counterparty_leg.amount != u128::from(setup.expected_amount_piconero())
        || terms.adaptor_point_sec1 != setup.claim().secp_compressed
        || setup.funding_tx_hash() == [0; 32]
        || profile.sidecar_api_version != API_VERSION_V2
        || deployment.profile().chain_id != terms.counterparty_leg.chain_id
        || deployment.profile().finality != terms.counterparty_leg.finality
        || deployment.asset_binding().asset_id != terms.counterparty_leg.asset_id
        || deployment.asset_binding().chain_id != terms.counterparty_leg.chain_id
    {
        return Err(Error::Binding);
    }
    let admitted_network = match deployment.profile().kind {
        chain_profile::ChainKindV1::Monero {
            network: chain_profile::MoneroNetworkV1::Mainnet,
        } => XmrNetwork::Mainnet,
        chain_profile::ChainKindV1::Monero {
            network: chain_profile::MoneroNetworkV1::Stagenet,
        } => XmrNetwork::Stagenet,
        chain_profile::ChainKindV1::Monero {
            network: chain_profile::MoneroNetworkV1::Testnet,
        } => XmrNetwork::Testnet,
        _ => return Err(Error::Binding),
    };
    if admitted_network != profile.network {
        return Err(Error::Binding);
    }
    validate_urls(
        request.daemon_urls,
        usize::from(profile.rpc_node_count),
        usize::from(profile.rpc_quorum),
    )
}

fn validate_urls(urls: &[String], count: usize, quorum: usize) -> Result<(), Error> {
    if count == 0 || count > 16 || urls.len() != count || quorum <= count / 2 || quorum > count {
        return Err(Error::Binding);
    }
    let mut unique = BTreeSet::new();
    for url in urls {
        let normalized = url.trim_end_matches('/');
        if url.trim() != url
            || normalized.is_empty()
            || !(normalized.starts_with("http://") || normalized.starts_with("https://"))
            || !unique.insert(normalized)
        {
            return Err(Error::Binding);
        }
    }
    Ok(())
}

fn funding_nonce(
    settlement: [u8; 32],
    terms: [u8; 32],
    setup: [u8; 32],
    txid: [u8; 32],
    block: [u8; 32],
    tip: [u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DOM-INTEROP/F7-XMR-VIEW-REQUEST/V11\0");
    for field in [settlement, terms, setup, txid, block, tip] {
        hash.update(field);
    }
    hash.finalize().into()
}

fn map_observer(error: XmrObserverError) -> Error {
    match error {
        XmrObserverError::RpcTransport | XmrObserverError::NotSynchronized => Error::Unavailable,
        XmrObserverError::StaleTip => Error::Unavailable,
        XmrObserverError::InvalidQuorum { .. } | XmrObserverError::WrongNetwork => Error::Binding,
        _ => Error::InvalidEvidence,
    }
}

fn map_secret(error: SecretStoreError) -> Error {
    match error {
        SecretStoreError::NotFound | SecretStoreError::Unavailable => Error::Unavailable,
        _ => Error::InvalidEvidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn xmr_nonce_binds_every_public_request_and_chain_snapshot_field() {
        let original = [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]];
        let hash = |f: [[u8; 32]; 6]| funding_nonce(f[0], f[1], f[2], f[3], f[4], f[5]);
        for index in 0..6 {
            let mut changed = original;
            changed[index][0] ^= 1;
            assert_ne!(hash(changed), hash(original));
        }
    }
    #[test]
    fn xmr_promotion_sources_bind_endpoint_count_order_and_boundaries() {
        let original = vec!["http://a".into(), "http://bc".into()];
        let digest = observation_sources_v23(&original);
        for changed in [
            vec!["http://a".into()],
            vec!["http://bc".into(), "http://a".into()],
            vec!["http://ab".into(), "http://c".into()],
            vec!["http://a".into(), "http://substituted".into()],
        ] {
            assert_ne!(digest, observation_sources_v23(&changed));
        }
        assert_eq!(digest, observation_sources_v23(&original));
    }
    #[test]
    fn xmr_duplicate_daemon_urls_do_not_count_as_independent_votes() {
        let urls = vec![
            "http://127.0.0.1:18081".into(),
            "http://127.0.0.1:18081/".into(),
        ];
        assert_eq!(validate_urls(&urls, 2, 2), Err(Error::Binding));
        assert_eq!(
            validate_urls(
                &["http://a".into(), "http://b".into(), "http://c".into()],
                3,
                1
            ),
            Err(Error::Binding)
        );
    }
    #[test]
    fn xmr_malformed_and_absent_custody_errors_remain_distinct() {
        assert_eq!(
            map_observer(XmrObserverError::MalformedResponse),
            Error::InvalidEvidence
        );
        assert_eq!(
            map_observer(XmrObserverError::RpcTransport),
            Error::Unavailable
        );
        assert_eq!(map_secret(SecretStoreError::NotFound), Error::Unavailable);
        assert_eq!(
            map_secret(SecretStoreError::AuthenticationFailed),
            Error::InvalidEvidence
        );
    }
}
