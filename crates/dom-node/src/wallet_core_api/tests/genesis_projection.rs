//! Exercise only the stored Mainnet identity's read projections. No node run,
//! listeners, seed discovery, mining loop, transaction submission, or fork choice.

use super::*;
use crate::node_handle::NodeHandleImpl;
use dom_rpc::NodeHandle;

async fn mainnet_with_stored_genesis(name: &str) -> Arc<DomNode> {
    let mut config = test_config(name);
    config.network = Network::Mainnet;
    assert!(!config.mine);
    assert!(config.disable_dns_seeds);
    assert!(config.dns_seeds.is_empty());
    assert!(config.seed_peers.is_empty());
    assert_eq!(config.min_outbound, 0);
    assert!(config.rpc_listen_addr.is_none());
    assert!(config.metrics_listen_addr.is_none());
    let node = Arc::new(
        DomNode::init_with_map_size(config, 16 * 1024 * 1024)
            .expect("initialize offline Mainnet node"),
    );
    // Existing production persistence path, not a manually fabricated LMDB row.
    crate::miner::create_genesis_block(Arc::clone(&node))
        .await
        .expect("persist the existing canonical genesis identity");
    node
}

fn require_empty_genesis(block: &ScanBlock, canonical: &dom_chain::CanonicalGenesis) {
    assert_eq!(block.height, 0);
    assert_eq!(&block.block_hash, canonical.hash.as_bytes());
    assert_eq!(block.canonical_marker, block.block_hash);
    assert_eq!(block.previous_block_hash, [0; 32]);
    assert_eq!(block.canonical_header_bytes, canonical.header_bytes);
    assert!(block.coinbase.is_none());
    assert!(block.outputs.is_empty());
    assert!(block.inputs.is_empty());
    assert!(block.kernels.is_empty());
    assert!(block.transactions.is_empty());
    assert_eq!(block.total_fees_noms, 0);
    let header = dom_consensus::BlockHeader::from_bytes(&canonical.header_bytes)
        .expect("canonical rooted genesis header");
    assert_eq!(block.timestamp, header.timestamp.0);
    assert_eq!(block.protocol_version, header.version);
    assert_eq!(
        block.range_proof_serialization_version,
        dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION
    );
}

#[tokio::test]
async fn stored_mainnet_genesis_is_identical_in_wallet_and_full_rpc_scanners() {
    let node = mainnet_with_stored_genesis("mainnet-genesis-projection").await;
    let api = EmbeddedWalletCoreApi::new(Arc::clone(&node));
    let identity = api.chain_identity().expect("real node identity");
    assert_eq!(identity.network, CoreNetwork::Mainnet);
    assert_eq!(identity.network_magic, dom_core::NETWORK_MAGIC_MAINNET);
    let canonical = dom_chain::build_canonical_genesis(identity.network_magic, &identity.chain_id)
        .expect("existing canonical genesis");
    assert!(canonical.block.is_none());
    assert_eq!(&identity.genesis_hash, canonical.hash.as_bytes());
    assert_eq!(identity.current_tip.height, 0);
    assert_eq!(identity.current_tip.hash, identity.genesis_hash);

    let wallet_page = api
        .scan_range(ScanRequest {
            network: identity.network,
            chain_id: identity.chain_id,
            start: ScanStart::Height(0),
            max_blocks: 1,
            stop_height: Some(0),
            commitment_filters: Vec::new(),
        })
        .expect("wallet scanner reads identity envelope without legacy Block decoding");
    assert_eq!(wallet_page.blocks.len(), 1);
    require_empty_genesis(&wallet_page.blocks[0], &canonical);
    assert!(wallet_page.continuation.is_none());

    let handle = NodeHandleImpl(Arc::clone(&node));
    let rpc_page = handle
        .scan_chain_full_v1(dom_rpc::FullScanRequestV1 {
            schema_version: dom_rpc::FULL_SCAN_SCHEMA_VERSION_V1,
            network_magic: identity.network_magic,
            chain_id: identity.chain_id,
            start_height: 0,
            max_blocks: 1,
            anchor: None,
        })
        .expect("full RPC scanner uses the same canonical read projection");
    assert_eq!(rpc_page.blocks.len(), 1);
    require_empty_genesis(&rpc_page.blocks[0], &canonical);
    assert_eq!(rpc_page.blocks, wallet_page.blocks);
    assert!(rpc_page.continuation.is_none());

    // At the tip there is no advertised next page. A caller retaining the
    // observed genesis anchor can still resume at height one without a gap.
    let anchor = BlockRef {
        height: 0,
        hash: identity.genesis_hash,
    };
    let cursor = WalletScanCursor::new(identity.network, identity.chain_id, 1, anchor);
    api.validate_cursor(cursor)
        .expect("genesis-anchored cursor");
    let resumed = api
        .scan_range(ScanRequest {
            network: identity.network,
            chain_id: identity.chain_id,
            start: ScanStart::Cursor(cursor),
            max_blocks: 1,
            stop_height: None,
            commitment_filters: Vec::new(),
        })
        .expect("wallet resumes just beyond genesis");
    assert!(resumed.blocks.is_empty());
    assert!(resumed.continuation.is_none());
    let next = handle
        .scan_chain_full_v1(dom_rpc::FullScanRequestV1 {
            schema_version: dom_rpc::FULL_SCAN_SCHEMA_VERSION_V1,
            network_magic: identity.network_magic,
            chain_id: identity.chain_id,
            start_height: 1,
            max_blocks: 1,
            anchor: Some(dom_rpc::FullScanAnchorV1 {
                height: 0,
                block_hash: identity.genesis_hash,
            }),
        })
        .expect("full RPC resumes with the same anchor");
    assert!(next.blocks.is_empty());
    assert!(next.continuation.is_none());

    let mut wrong_anchor = identity.genesis_hash;
    wrong_anchor[0] ^= 1;
    assert!(handle
        .scan_chain_full_v1(dom_rpc::FullScanRequestV1 {
            schema_version: dom_rpc::FULL_SCAN_SCHEMA_VERSION_V1,
            network_magic: identity.network_magic,
            chain_id: identity.chain_id,
            start_height: 1,
            max_blocks: 1,
            anchor: Some(dom_rpc::FullScanAnchorV1 {
                height: 0,
                block_hash: wrong_anchor
            }),
        })
        .is_err());
}

#[tokio::test]
async fn genesis_projection_rejects_substituted_identity_without_mutating_storage() {
    let node = mainnet_with_stored_genesis("mainnet-genesis-projection-identity").await;
    let api = EmbeddedWalletCoreApi::new(Arc::clone(&node));
    for mutation in 0..4 {
        let mut identity = api.chain_identity().expect("actual node identity");
        match mutation {
            0 => identity.genesis_hash[0] ^= 1,
            1 => identity.chain_id[0] ^= 1,
            2 => identity.network = CoreNetwork::Regtest,
            _ => identity.network_magic = dom_core::NETWORK_MAGIC_TESTNET,
        }
        let chain = node.chain.try_lock().expect("read-only chain lock");
        assert!(matches!(
            EmbeddedWalletCoreApi::load_scan_projection_locked(&chain, &identity, 0, None),
            Err(WalletCoreError::CanonicalGap(_))
        ));
    }
    // The negative inputs were supplied only to the read helper; the authentic
    // persisted identity remains readable and no replacement DB was created.
    let identity = api.chain_identity().expect("unchanged real identity");
    let chain = node.chain.try_lock().expect("read-only chain lock");
    assert!(
        EmbeddedWalletCoreApi::load_scan_projection_locked(&chain, &identity, 0, None)
            .expect("authentic projection still succeeds")
            .is_some()
    );
}
