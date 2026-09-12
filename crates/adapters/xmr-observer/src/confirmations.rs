//! Quorum-backed transaction confirmations.

use crate::{
    relative_confirmations, XmrConfirmationStatus, XmrObserverError, XmrRpc, XmrRpcPool,
    XmrTransactionStatus,
};

/// Resolves transaction status against a separately agreed canonical tip.
pub async fn confirmation_status<R: XmrRpc>(
    pool: &XmrRpcPool<R>,
    tx_hash: [u8; 32],
) -> Result<XmrConfirmationStatus, XmrObserverError> {
    if tx_hash == [0; 32] {
        return Err(XmrObserverError::MalformedResponse);
    }
    let canonical_tip = pool.canonical_tip().await?;
    let status = pool.transaction_status(tx_hash).await?;
    let observation = match status {
        XmrTransactionStatus::Unseen | XmrTransactionStatus::InPool => XmrConfirmationStatus {
            status,
            inclusion_block_hash: None,
            confirmations: 0,
            canonical_tip,
        },
        XmrTransactionStatus::InBlock { block_height } => {
            let confirmations = relative_confirmations(block_height, canonical_tip.height)
                .ok_or(XmrObserverError::StaleTip)?;
            let inclusion_block_hash = pool.block_hash(block_height).await?;
            XmrConfirmationStatus {
                status,
                inclusion_block_hash: Some(inclusion_block_hash),
                confirmations,
                canonical_tip,
            }
        }
    };
    // The first tip, requested transaction and inclusion hash must all remain
    // canonical across the read. A moving/reorganizing snapshot is retried;
    // it must not turn into finality for data assembled across two forks.
    if pool.transaction_status(tx_hash).await? != status {
        return Err(XmrObserverError::StaleTip);
    }
    if let (XmrTransactionStatus::InBlock { block_height }, Some(block_hash)) =
        (status, observation.inclusion_block_hash)
    {
        if pool.block_hash(block_height).await? != block_hash {
            return Err(XmrObserverError::StaleTip);
        }
    }
    if pool.canonical_tip().await? != canonical_tip {
        return Err(XmrObserverError::StaleTip);
    }
    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeObservation, XmrNetwork};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Node {
        // 0 stable inclusion, 1 changed status, 2 changed block, 3 changed tip,
        // 4 stable explicit absence, 5 unavailable, 6 malformed.
        mode: u8,
        statuses: AtomicUsize,
        blocks: AtomicUsize,
        tips: AtomicUsize,
    }
    impl Node {
        fn new(mode: u8) -> Self {
            Self {
                mode,
                statuses: AtomicUsize::new(0),
                blocks: AtomicUsize::new(0),
                tips: AtomicUsize::new(0),
            }
        }
    }
    impl XmrRpc for Node {
        async fn observe_tip(
            &self,
            network: XmrNetwork,
        ) -> Result<NodeObservation, XmrObserverError> {
            if self.mode == 5 {
                return Err(XmrObserverError::RpcTransport);
            }
            let call = self.tips.fetch_add(1, Ordering::SeqCst);
            Ok(NodeObservation {
                node: "fixture".into(),
                network,
                synchronized: true,
                tip_height: 110,
                target_height: 111,
                top_hash: if self.mode == 3 && call > 0 {
                    [9; 32]
                } else {
                    [8; 32]
                },
            })
        }
        async fn transaction_status(
            &self,
            _: [u8; 32],
        ) -> Result<XmrTransactionStatus, XmrObserverError> {
            if self.mode == 5 {
                return Err(XmrObserverError::RpcTransport);
            }
            if self.mode == 6 {
                return Err(XmrObserverError::MalformedResponse);
            }
            let call = self.statuses.fetch_add(1, Ordering::SeqCst);
            if self.mode == 4 || self.mode == 1 && call > 0 {
                Ok(XmrTransactionStatus::Unseen)
            } else {
                Ok(XmrTransactionStatus::InBlock { block_height: 100 })
            }
        }
        async fn block_hash(&self, _: u64) -> Result<[u8; 32], XmrObserverError> {
            if self.mode == 5 {
                return Err(XmrObserverError::RpcTransport);
            }
            let call = self.blocks.fetch_add(1, Ordering::SeqCst);
            Ok(if self.mode == 2 && call > 0 {
                [7; 32]
            } else {
                [6; 32]
            })
        }
    }
    fn pool(modes: &[u8], required: usize) -> XmrRpcPool<Node> {
        XmrRpcPool::new(
            modes.iter().map(|mode| Node::new(*mode)).collect(),
            XmrNetwork::Testnet,
            required,
        )
        .expect("configured fixture")
    }
    #[tokio::test]
    async fn v11_changed_location_block_or_tip_cannot_mint_finality() {
        for mode in [1, 2, 3] {
            assert_eq!(
                confirmation_status(&pool(&[mode; 3], 2), [1; 32]).await,
                Err(XmrObserverError::StaleTip)
            );
        }
    }
    #[tokio::test]
    async fn v11_stable_snapshot_confirms_exact_depth_and_stable_absence_remains_absent() {
        let status = confirmation_status(&pool(&[0, 0, 5], 2), [1; 32])
            .await
            .expect("finality");
        assert_eq!(status.confirmations, 11);
        assert!(status.is_final(11));
        assert!(!status.is_final(12));
        assert!(!status.is_final(0));
        let absent = confirmation_status(&pool(&[4, 4, 5], 2), [1; 32])
            .await
            .expect("absence");
        assert_eq!(absent.status, XmrTransactionStatus::Unseen);
        assert!(!absent.is_final(1));
        assert_eq!(
            confirmation_status(&pool(&[4, 4, 6], 2), [1; 32]).await,
            Err(XmrObserverError::MalformedResponse)
        );
    }
    #[test]
    fn v11_confirmation_arithmetic_and_quorum_bounds_are_checked() {
        assert_eq!(relative_confirmations(0, u64::MAX), None);
        assert_eq!(relative_confirmations(101, 100), None);
        assert_eq!(relative_confirmations(100, 100), Some(1));
        for (nodes, required) in [(0, 0), (3, 1), (4, 2), (2, 3), (17, 9)] {
            assert!(XmrRpcPool::new(
                (0..nodes).map(|_| Node::new(0)).collect(),
                XmrNetwork::Testnet,
                required
            )
            .is_err());
        }
    }
}
