//! Read-only projection of the already finalized Mainnet identity envelope.
//! No mining, admission, fork choice, genesis construction, or store writes.
use super::*;

impl EmbeddedWalletCoreApi {
    /// Project one stored canonical entry under the caller's chain lock.
    /// Mainnet height zero has no economic body and must not be decoded as a
    /// legacy Block or assigned fabricated coinbase metadata.
    pub(crate) fn load_scan_projection_locked(
        chain: &dom_chain::ChainState,
        identity: &ChainIdentity,
        height: u64,
        filters: Option<&HashSet<[u8; 33]>>,
    ) -> Result<Option<ScanBlock>, WalletCoreError> {
        if height != 0 || chain.network_magic != dom_core::NETWORK_MAGIC_MAINNET {
            return Self::load_canonical_block_locked(chain, height)?
                .map(|(hash, block)| Self::project_block(identity, hash, block, filters))
                .transpose();
        }
        let Some(hash) = Self::block_hash_at_locked(chain, height)? else {
            return Ok(None);
        };
        let expected = dom_core::startup_genesis_hash_for_network_magic(chain.network_magic)
            .map_err(|error| WalletCoreError::NodeNotReady(error.to_string()))?;
        if hash != *expected.as_bytes()
            || identity.network != CoreNetwork::Mainnet
            || identity.network_magic != chain.network_magic
            || identity.genesis_hash != hash
            || identity.chain_id
                != *dom_consensus::derive_chain_id(chain.network_magic, &expected).as_bytes()
        {
            return Err(WalletCoreError::CanonicalGap(
                "Mainnet genesis identity mismatch".into(),
            ));
        }
        let body = chain
            .store
            .get_block_body(&hash)
            .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?
            .ok_or_else(|| WalletCoreError::CanonicalGap("Mainnet genesis body missing".into()))?;
        let genesis = dom_chain::validate_mainnet_genesis_identity(&body)
            .map_err(|error| WalletCoreError::CanonicalGap(error.to_string()))?;
        let canonical = genesis
            .to_canonical_bytes()
            .map_err(|error| WalletCoreError::CanonicalGap(error.to_string()))?;
        let identifier = genesis
            .identity_hash()
            .map_err(|error| WalletCoreError::CanonicalGap(error.to_string()))?;
        let stored_header = chain
            .store
            .get_block_header(&hash)
            .map_err(|error| WalletCoreError::InternalFailure(error.to_string()))?
            .ok_or_else(|| {
                WalletCoreError::CanonicalGap("Mainnet genesis header missing".into())
            })?;
        if canonical != body
            || identifier.as_bytes() != &hash
            || stored_header.as_slice() != genesis.header_bytes()
        {
            return Err(WalletCoreError::CanonicalGap(
                "Mainnet genesis header/body mismatch".into(),
            ));
        }
        let header = dom_consensus::BlockHeader::from_bytes(genesis.header_bytes())
            .map_err(|error| WalletCoreError::CanonicalGap(error.to_string()))?;
        if header.height.0 != 0 || header.prev_hash != Hash256::ZERO {
            return Err(WalletCoreError::CanonicalGap(
                "Mainnet genesis ancestry mismatch".into(),
            ));
        }
        Ok(Some(ScanBlock {
            height: 0,
            block_hash: hash,
            previous_block_hash: [0; 32],
            canonical_header_bytes: stored_header,
            timestamp: header.timestamp.0,
            canonical_marker: hash,
            outputs: Vec::new(),
            inputs: Vec::new(),
            kernels: Vec::new(),
            transactions: Vec::new(),
            coinbase: None,
            total_fees_noms: 0,
            protocol_version: header.version,
            range_proof_serialization_version: identity.range_proof_serialization_version,
        }))
    }
}
