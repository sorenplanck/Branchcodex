//! Actual RPC checkpoint collection. A hash links the complete observed walk;
//! it is not an independent consensus or proof-of-work verifier.
use super::*;
use blake2::digest::{Update, VariableOutput};
use xmr_rpc_broadcast_blocking::{BlockingMoneroDaemonReaderV1, MoneroTimeHeaderV23};

const MAX_HISTORY: u64 = 4096;

pub(super) fn require_loopback(address: SocketAddr) -> Result<()> {
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("time observer requires numeric loopback endpoints".into());
    }
    Ok(())
}

pub(super) fn dom(
    client: &DomHttpChainAdapterV1,
    binding: CheckpointBindingV2,
    limits: RouteTimePolicyLimitsV2,
) -> Result<CanonicalCheckpointObservationV2> {
    let mut cursor = ScriptlessScanCursorV1::genesis();
    let mut blocks = Vec::new();
    let mut tip = None;
    loop {
        let page = client.scan_page(cursor, 64)?;
        let identity = (page.identity.tip_height, page.identity.tip_hash);
        if identity.0 == 0
            || identity.0 > MAX_HISTORY
            || tip.is_some_and(|previous| previous != identity)
        {
            return Err("DOM time snapshot empty, changed, or oversized".into());
        }
        tip = Some(identity);
        if page.blocks.is_empty() {
            return Err("DOM time walk made no progress".into());
        }
        blocks.extend(page.blocks);
        cursor = page.next_cursor;
        if page.reached_snapshot_tip {
            break;
        }
        if cursor.next_height > MAX_HISTORY {
            return Err("DOM time scan bound".into());
        }
    }
    let (tip_height, tip_hash) = tip.ok_or("DOM time tip absent")?;
    if blocks.first().map(|block| block.block_hash) != Some(binding.genesis_hash())
        || blocks.last().map(|block| (block.height, block.block_hash))
            != Some((tip_height, tip_hash))
    {
        return Err("DOM time walk does not reach the pinned genesis and tip".into());
    }
    // Read back the tip under a fresh snapshot; stale concatenated pages
    // cannot be signed if the authoritative RPC changed during collection.
    let tip_page = client.scan_page(
        ScriptlessScanCursorV1 {
            next_height: tip_height,
            anchor_hash: Some(blocks[blocks.len() - 2].block_hash),
        },
        1,
    )?;
    if tip_page.identity.tip_height != tip_height || tip_page.identity.tip_hash != tip_hash {
        return Err("DOM time tip changed after observation".into());
    }
    let anchor_height = anchor_height(tip_height, binding)?;
    let anchor = blocks
        .iter()
        .find(|block| block.height == anchor_height)
        .ok_or("DOM time anchor absent")?;
    let mut hash = blake2::Blake2bVar::new(32)?;
    hash.update(b"DOM-INTEROP/TIME/DOM-RPC-WALK/V23\0");
    hash.update(&binding.chain_id().0);
    for block in &blocks {
        hash.update(&block.height.to_be_bytes());
        hash.update(&block.block_hash);
        hash.update(&block.previous_block_hash);
        hash.update(&(u32::try_from(block.canonical_header_bytes.len())?).to_be_bytes());
        hash.update(&block.canonical_header_bytes);
    }
    let mut digest = [0; 32];
    hash.finalize_variable(&mut digest)?;
    observation(
        anchor_height,
        anchor.block_hash,
        anchor.previous_block_hash,
        anchor.timestamp,
        tip_height,
        tip_hash,
        digest,
        limits,
    )
}

pub(super) fn monero(
    addresses: &[SocketAddr],
    binding: CheckpointBindingV2,
    limits: RouteTimePolicyLimitsV2,
    quorum: u16,
) -> Result<CanonicalCheckpointObservationV2> {
    if !crate::production_xmr_quorum::valid_quorum_v5(addresses.len(), usize::from(quorum)) {
        return Err("time observer invalid negotiated XMR quorum".into());
    }
    let mut distinct_ports = std::collections::BTreeSet::new();
    for address in addresses {
        require_loopback(*address)?;
        if !distinct_ports.insert(address.port()) {
            return Err("time observer duplicate XMR voter".into());
        }
    }
    let mut groups: Vec<(Vec<MoneroTimeHeaderV23>, usize)> = Vec::new();
    for address in addresses {
        let reader = BlockingMoneroDaemonReaderV1::new(format!("http://{address}"))?;
        let Ok(headers) = monero_walk(&reader, binding.genesis_hash()) else {
            continue;
        };
        if let Some((_, votes)) = groups.iter_mut().find(|(known, _)| *known == headers) {
            *votes += 1;
        } else {
            groups.push((headers, 1));
        }
    }
    let mut accepted = groups
        .into_iter()
        .filter(|(_, votes)| *votes >= usize::from(quorum));
    let (headers, _) = accepted.next().ok_or("no canonical XMR time quorum")?;
    if accepted.next().is_some() {
        return Err("contradictory XMR time quorums".into());
    }
    let tip = headers.last().ok_or("XMR time tip absent")?;
    let height = anchor_height(tip.height, binding)?;
    let anchor = headers
        .iter()
        .find(|header| header.height == height)
        .ok_or("XMR time anchor absent")?;
    let mut hash = blake2::Blake2bVar::new(32)?;
    hash.update(b"DOM-INTEROP/TIME/XMR-RPC-WALK/V23\0");
    hash.update(&binding.chain_id().0);
    hash.update(&binding.genesis_hash());
    for header in &headers {
        hash.update(&header.height.to_be_bytes());
        hash.update(&header.hash);
        hash.update(&header.parent);
        hash.update(&header.timestamp.to_be_bytes());
    }
    let mut digest = [0; 32];
    hash.finalize_variable(&mut digest)?;
    observation(
        height,
        anchor.hash,
        anchor.parent,
        anchor.timestamp,
        tip.height,
        tip.hash,
        digest,
        limits,
    )
}

fn monero_walk(
    reader: &BlockingMoneroDaemonReaderV1,
    genesis: [u8; 32],
) -> Result<Vec<MoneroTimeHeaderV23>> {
    let height = reader
        .daemon_height()?
        .checked_sub(1)
        .ok_or("XMR empty height")?;
    if height == 0 || height > MAX_HISTORY || reader.block_hash_at(0)? != genesis {
        return Err("XMR time genesis/height mismatch".into());
    }
    let mut headers = Vec::new();
    let mut previous = genesis;
    for current in 1..=height {
        let header = reader.time_header_at_v23(current)?;
        if header.parent != previous {
            return Err("XMR time chain discontinuity".into());
        }
        previous = header.hash;
        headers.push(header);
    }
    if reader.daemon_height()? != height + 1
        || reader.block_hash_at(height)? != previous
        || reader.block_hash_at(0)? != genesis
    {
        return Err("XMR time snapshot changed".into());
    }
    Ok(headers)
}

fn anchor_height(tip: u64, binding: CheckpointBindingV2) -> Result<u64> {
    let depth = u64::from(binding.finality().min_confirmations)
        .checked_sub(1)
        .ok_or("zero time confirmations")?;
    let anchor = tip
        .checked_sub(depth)
        .ok_or("insufficient time confirmations")?;
    if anchor == 0 {
        return Err("genesis is not a time anchor".into());
    }
    Ok(anchor)
}

fn observation(
    height: u64,
    hash: [u8; 32],
    parent: [u8; 32],
    timestamp: u64,
    tip: u64,
    tip_hash: [u8; 32],
    digest: [u8; 32],
    limits: RouteTimePolicyLimitsV2,
) -> Result<CanonicalCheckpointObservationV2> {
    // Use the entire signed uncertainty budget, not an exact wall-clock claim.
    let half = limits.max_anchor_interval_width_seconds / 2;
    let lower = timestamp
        .checked_sub(half)
        .ok_or("time interval underflow")?;
    let upper = timestamp
        .checked_add(half)
        .ok_or("time interval overflow")?;
    Ok(CanonicalCheckpointObservationV2::new(
        CanonicalAnchorObservationV2::new(height, hash, parent),
        CanonicalTimeRangeV2::new(lower, upper),
        CanonicalTipObservationV2::new(tip, tip_hash, digest),
    ))
}
