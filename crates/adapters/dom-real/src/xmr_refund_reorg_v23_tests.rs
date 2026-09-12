//! Pure parser/fork boundary regressions. These do not replace the real
//! daemon scenarios or assert RPC authentication from synthetic block maps.
use super::*;

fn block(height: u64) -> [u8; 32] {
    [height.to_le_bytes()[0].wrapping_add(1); 32]
}

fn checkpoint() -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.push(3);
    for value in [
        [21; 32],
        [22; 32],
        [23; 32],
        [24; 32],
        [25; 32],
        [26; 32],
        [27; 32],
        block(18),
        block(20),
    ] {
        bytes.extend_from_slice(&value);
    }
    for value in [18u64, 20] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    for value in [0u32, 3, 3, 6] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    for height in 14u64..=20 {
        bytes.extend_from_slice(&height.to_be_bytes());
        bytes.extend_from_slice(&block(height));
    }
    seal(&mut bytes);
    bytes
}
fn seal(bytes: &mut Vec<u8>) {
    let digest = digest_parts(b"DOM-INTEROP/XMR-RECOVERY-FINALITY/V11\0", &[bytes]);
    bytes.extend_from_slice(&digest);
}
fn alter(mut bytes: Vec<u8>, offset: usize, value: u8) -> Vec<u8> {
    bytes.truncate(bytes.len() - 32);
    bytes[offset] = value;
    seal(&mut bytes);
    bytes
}
fn fork() -> BTreeMap<u64, [u8; 32]> {
    (14..=20)
        .map(|h| {
            (
                h,
                if h <= 17 {
                    block(h)
                } else {
                    [100 + h as u8; 32]
                },
            )
        })
        .collect()
}

#[test]
fn native_refund_checkpoint_exact_layout_and_ancestry_v23() -> Result<(), RealDomError> {
    let bytes = checkpoint();
    let parsed = decode_native_refund_v23(&bytes)?;
    assert_eq!(parsed.session, [22; 32]);
    assert_eq!(parsed.transaction, [27; 32]);
    assert_eq!(parsed.tail.len(), 7);
    assert_eq!(parsed.tail[0], (14, block(14)));
    assert_eq!(parsed.evidence, bytes[bytes.len() - 32..]);
    Ok(())
}

#[test]
fn native_refund_checkpoint_refuses_wrong_kind_digest_trailing_and_truncation_v23() {
    assert!(decode_native_refund_v23(&alter(checkpoint(), MAGIC.len(), 4)).is_err());
    let mut corrupt = checkpoint();
    corrupt[20] ^= 1;
    assert!(decode_native_refund_v23(&corrupt).is_err());
    let mut extra = checkpoint();
    extra.push(0);
    assert!(decode_native_refund_v23(&extra).is_err());
    for length in [0, 11, PREFIX, PREFIX + 40, checkpoint().len() - 1] {
        assert!(decode_native_refund_v23(&checkpoint()[..length]).is_err());
    }
}

#[test]
fn native_refund_checkpoint_refuses_discontinuous_tail_wrong_block_and_weak_policy_v23() {
    // Recompute the audit digest: malformed authenticated structure must still
    // be rejected, not merely caught as an accidental byte corruption.
    assert!(decode_native_refund_v23(&alter(checkpoint(), PREFIX + 7, 13)).is_err());
    assert!(decode_native_refund_v23(&alter(checkpoint(), PREFIX + 4 * 40 + 8, 99)).is_err());
    // minimum=7 > maximum=6, and declared depth=3.
    assert!(decode_native_refund_v23(&alter(checkpoint(), PREFIX - 5, 7)).is_err());
}

#[test]
fn native_refund_fork_proves_exact_removed_tail_and_original_identity_v23(
) -> Result<(), RealDomError> {
    let proof = prove_native_refund_fork_v23(
        decode_native_refund_v23(&checkpoint())?,
        &fork(),
        20,
        [120; 32],
        None,
    )?;
    assert_eq!(proof.common_ancestor_height(), 17);
    assert_eq!(proof.removed_depth(), 3);
    assert_eq!(proof.transaction_hash(), [27; 32]);
    assert_eq!(proof.prior_block_hash(), block(18));
    assert_eq!(proof.minimum_confirmations(), 3);
    assert_eq!(proof.max_reorg_depth(), 6);
    assert!(proof.require_recent_v23().is_ok());
    Ok(())
}

#[test]
fn native_refund_fork_refuses_deep_or_unproved_ancestor_v23() -> Result<(), RealDomError> {
    let no_ancestor = (14..=20).map(|h| (h, [100 + h as u8; 32])).collect();
    assert!(matches!(
        prove_native_refund_fork_v23(
            decode_native_refund_v23(&checkpoint())?,
            &no_ancestor,
            20,
            [120; 32],
            None
        ),
        Err(RealDomError::ReorgBeyondPolicy)
    ));
    Ok(())
}

#[test]
fn native_refund_fork_still_canonical_or_depth_loss_is_not_invalidation_v23(
) -> Result<(), RealDomError> {
    let same = (14..=20).map(|h| (h, block(h))).collect();
    assert!(matches!(
        prove_native_refund_fork_v23(
            decode_native_refund_v23(&checkpoint())?,
            &same,
            20,
            block(20),
            Some((18, block(18)))
        ),
        Err(RealDomError::TransactionStillCanonical)
    ));
    assert!(matches!(
        prove_native_refund_fork_v23(
            decode_native_refund_v23(&checkpoint())?,
            &same,
            19,
            block(19),
            Some((18, block(18)))
        ),
        Err(RealDomError::InsufficientConfirmations)
    ));
    assert!(matches!(
        prove_native_refund_fork_v23(
            decode_native_refund_v23(&checkpoint())?,
            &same,
            20,
            block(20),
            None
        ),
        Err(RealDomError::InvalidEvidence)
    ));
    Ok(())
}

#[test]
fn native_refund_reinclusion_is_distinct_from_absence_and_replay_stable_v23(
) -> Result<(), RealDomError> {
    let make = |location| {
        prove_native_refund_fork_v23(
            decode_native_refund_v23(&checkpoint())?,
            &fork(),
            20,
            [120; 32],
            location,
        )
    };
    let removed = make(None)?;
    let included = make(Some((19, [119; 32])))?;
    assert_ne!(removed.evidence_digest(), included.evidence_digest());
    assert_eq!(
        included.evidence_digest(),
        make(Some((19, [119; 32])))?.evidence_digest()
    );
    Ok(())
}

#[test]
fn native_refund_fork_token_expires_without_sleep_v23() -> Result<(), RealDomError> {
    let mut proof = prove_native_refund_fork_v23(
        decode_native_refund_v23(&checkpoint())?,
        &fork(),
        20,
        [120; 32],
        None,
    )?;
    proof.observed_at = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(31))
        .ok_or(RealDomError::BoundsExceeded)?;
    assert!(matches!(
        proof.require_recent_v23(),
        Err(RealDomError::Chain(
            ChainAdapterError::TemporarilyUnavailable
        ))
    ));
    Ok(())
}

#[test]
fn native_graph_progress_retains_only_bounded_scopes_and_never_shares_prefix_v23(
) -> Result<(), RealDomError> {
    let mut cache = BTreeMap::new();
    let mut progress = NativeGraphScanProgressV23::default();
    progress.state.append(0, [1; 32], 8)?;
    for key in 1..=8 {
        retain_native_graph_progress_v23(&mut cache, [key; 32], &progress, None);
        assert!(cache.len() <= 4);
    }
    assert!(!cache.contains_key(&[1; 32]));
    assert_eq!(cache[&[8; 32]].state.next_height, 1);
    assert!(!cache.contains_key(&[9; 32]));
    Ok(())
}

#[test]
fn native_graph_progress_resets_anchor_fork_discards_corruption_and_keeps_timeout_v23(
) -> Result<(), RealDomError> {
    let mut cache = BTreeMap::new();
    let mut progress = NativeGraphScanProgressV23::default();
    progress.state.append(0, [1; 32], 8)?;
    let timeout = RealDomError::Chain(ChainAdapterError::TemporarilyUnavailable);
    retain_native_graph_progress_v23(&mut cache, [1; 32], &progress, Some(&timeout));
    assert_eq!(cache[&[1; 32]].state.next_height, 1);
    let fork = RealDomError::Chain(ChainAdapterError::ReorgDetected);
    retain_native_graph_progress_v23(&mut cache, [1; 32], &progress, Some(&fork));
    assert_eq!(cache[&[1; 32]].state.next_height, 0);
    assert!(cache[&[1; 32]].blocks.is_empty());
    retain_native_graph_progress_v23(
        &mut cache,
        [1; 32],
        &progress,
        Some(&RealDomError::InvalidEvidence),
    );
    assert!(!cache.contains_key(&[1; 32]));
    Ok(())
}
