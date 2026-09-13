//! Cheap producer/reader compatibility tests, without a sidecar or ceremony.
//! The synthetic raw bytes here exercise the descriptor codec ONLY. They are
//! not an ownership proof, a real XMR transaction, or a funding capability.
use super::*;
use crate::production_xmr_inventory_v23::{
    read_inventory_descriptor_v24, NativeF6XmrInventoryExpectedV23, PublicInventoryEvidenceV24,
};
use std::os::unix::fs::PermissionsExt as _;

fn descriptor() -> NativeInventoryDescriptorV23 {
    NativeInventoryDescriptorV23 {
        network_id: [1; 32],
        route_id: [2; 32],
        sessions: [[3; 32], [4; 32]],
        terms: [[5; 32], [6; 32]],
        authority_id: [7; 32],
        genesis: crate::production_xmr_remote_sweep_v23::MONERO_MAINNET_GENESIS_V23,
        tx_hash: [9; 32],
        spend_public: [10; 32],
        amount_piconero: 123_456,
        max_fee_piconero: 10_000,
        output_index: 0x01020304,
        destination: "synthetic-public-inventory-codec-only".into(),
        raw: Zeroizing::new(vec![12; 400]),
    }
}

fn private_directory() -> Result<tempfile::TempDir> {
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

fn expected(value: &NativeInventoryDescriptorV23) -> NativeF6XmrInventoryExpectedV23 {
    NativeF6XmrInventoryExpectedV23 {
        network_id: value.network_id,
        route_id: value.route_id,
        sessions: value.sessions,
        terms: value.terms,
        authority_id: value.authority_id,
        genesis: value.genesis,
        chain_id: [11; 32],
        asset_id: [12; 32],
        amount_piconero: value.amount_piconero,
        max_fee_piconero: value.max_fee_piconero,
        min_confirmations: 10,
        route_funding_tx_hashes: vec![[13; 32], [14; 32]],
        max_age_seconds: 60,
    }
}

// Independent reference for the existing length-delimited BLAKE2b domains.
fn reference_digest(domain: &[u8], parts: &[&[u8]]) -> Result<[u8; 32]> {
    use blake2::digest::{Update as _, VariableOutput as _};
    let mut hash = blake2::Blake2bVar::new(32)?;
    hash.update(domain);
    for part in parts {
        hash.update(&u64::try_from(part.len())?.to_be_bytes());
        hash.update(part);
    }
    let mut output = [0; 32];
    hash.finalize_variable(&mut output)?;
    Ok(output)
}

fn legacy_fixture_bytes(value: &NativeInventoryDescriptorV23) -> Result<Vec<u8>> {
    let mut bytes = b"XMRINV23".to_vec();
    bytes.extend_from_slice(&23u16.to_le_bytes());
    for field in [
        value.network_id,
        value.route_id,
        value.sessions[0],
        value.sessions[1],
        value.terms[0],
        value.terms[1],
        value.authority_id,
        value.tx_hash,
        value.spend_public,
    ] {
        bytes.extend_from_slice(&field);
    }
    bytes.extend_from_slice(&value.amount_piconero.to_le_bytes());
    bytes.extend_from_slice(&value.max_fee_piconero.to_le_bytes());
    bytes.extend_from_slice(&u16::try_from(value.destination.len())?.to_le_bytes());
    bytes.extend_from_slice(&u32::try_from(value.raw.len())?.to_le_bytes());
    bytes.extend_from_slice(value.destination.as_bytes());
    bytes.extend_from_slice(&value.raw);
    let checksum = reference_digest(b"DOM/NATIVE-F6/XMR-INVENTORY-DESCRIPTOR/V23\0", &[&bytes])?;
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

#[test]
fn fixture_descriptor_roundtrips_through_production_reader_v24() -> Result<()> {
    let directory = private_directory()?;
    let path = directory.path().join(NATIVE_XMR_INVENTORY_DESCRIPTOR_V23);
    let value = descriptor();
    publish_inventory_descriptor_v23(&path, &value)?;
    let bytes = std::fs::read(&path)?;
    assert_eq!(&bytes[..10], b"XMRINV23\0\x17");
    assert_eq!(&bytes[234..266], &value.genesis);
    assert_eq!(&bytes[346..350], &value.output_index.to_be_bytes());
    let read = read_inventory_descriptor_v24(directory.path())?;
    read.require_expected(&expected(&value))?;
    assert_eq!(read.encode()?, bytes);
    assert_eq!(read_inventory_descriptor_v23(&path)?.encode()?, bytes);
    assert_eq!(
        inventory_custody_ids_v23(&read)?,
        inventory_custody_ids_v23(&value)?
    );
    assert_eq!(std::fs::read_dir(directory.path())?.count(), 1);
    // The reader neither creates a Store nor rewrites the descriptor.
    assert_eq!(std::fs::read(&path)?, bytes);
    Ok(())
}

#[test]
fn production_reader_refuses_legacy_mutated_and_nonprivate_inventory_v24() -> Result<()> {
    let directory = private_directory()?;
    let path = directory.path().join(NATIVE_XMR_INVENTORY_DESCRIPTOR_V23);
    let value = descriptor();
    publish_inventory_descriptor_v23(&path, &value)?;
    let canonical = value.encode()?;
    let legacy = legacy_fixture_bytes(&value)?;
    assert_ne!(&legacy[8..10], &canonical[8..10]);
    std::fs::write(&path, &legacy)?;
    assert!(read_inventory_descriptor_v24(directory.path()).is_err());
    // A version-only repair cannot turn the old layout/domain into production.
    let mut legacy_version_repaired = legacy;
    legacy_version_repaired[8..10].copy_from_slice(&23u16.to_be_bytes());
    std::fs::write(&path, legacy_version_repaired)?;
    assert!(read_inventory_descriptor_v24(directory.path()).is_err());
    for position in [8, 10, 42, 234, 266, 330, 338, 346, 350, canonical.len() - 1] {
        let mut mutated = canonical.clone();
        mutated[position] ^= 1;
        std::fs::write(&path, mutated)?;
        assert!(read_inventory_descriptor_v24(directory.path()).is_err());
    }
    let mut trailing = canonical.clone();
    trailing.push(0);
    std::fs::write(&path, trailing)?;
    assert!(read_inventory_descriptor_v24(directory.path()).is_err());
    std::fs::write(&path, &canonical)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    assert!(read_inventory_descriptor_v24(directory.path()).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    assert_eq!(
        read_inventory_descriptor_v24(directory.path())?.encode()?,
        canonical
    );
    assert_eq!(std::fs::read_dir(directory.path())?.count(), 1);
    Ok(())
}

#[test]
fn inventory_fixture_scope_refuses_relabelled_source_v24() -> Result<()> {
    assert_eq!(inventory_fee_cap_v24([10_000, 7_000])?, 7_000);
    assert_eq!(inventory_fee_cap_v24([7_000, 10_000])?, 7_000);
    assert_eq!(inventory_fee_cap_v24([10_000, 10_000])?, 10_000);
    assert!(inventory_fee_cap_v24([0, 10_000]).is_err());
    assert!(inventory_fee_cap_v24([10_000, 0]).is_err());
    let value = descriptor();
    value.require_expected(&expected(&value))?;
    for field in 0..16 {
        let mut scope = expected(&value);
        match field {
            0 => scope.network_id[0] ^= 1,
            1 => scope.route_id[0] ^= 1,
            2 => scope.sessions[0][0] ^= 1,
            3 => scope.sessions[1][0] ^= 1,
            4 => scope.terms[0][0] ^= 1,
            5 => scope.terms[1][0] ^= 1,
            6 => scope.authority_id[0] ^= 1,
            7 => scope.genesis[0] ^= 1,
            8 => scope.amount_piconero += 1,
            9 => scope.max_fee_piconero -= 1,
            10 => scope.min_confirmations = 0,
            11 => scope.max_age_seconds = 0,
            12 => scope.route_funding_tx_hashes[0] = value.tx_hash,
            13 => scope.route_funding_tx_hashes.clear(),
            14 => scope.chain_id = [0; 32],
            _ => scope.asset_id = [0; 32],
        }
        assert!(value.require_expected(&scope).is_err());
    }
    Ok(())
}

#[test]
fn inventory_custody_derivation_binds_genesis_and_output_index_v24() -> Result<()> {
    let value = descriptor();
    let original = inventory_custody_ids_v23(&value)?;
    let legacy_record = reference_digest(
        b"DOM/NATIVE-F6/XMR-INVENTORY-CUSTODY-RECORD/V23\0",
        &[
            &value.network_id,
            &value.route_id,
            &value.sessions[0],
            &value.sessions[1],
            &value.tx_hash,
        ],
    )?;
    assert_ne!(original.0, legacy_record);
    let mut changed_genesis = descriptor();
    changed_genesis.genesis[0] ^= 1;
    let genesis_ids = inventory_custody_ids_v23(&changed_genesis)?;
    assert_eq!(original.0, genesis_ids.0);
    assert_ne!(original.1, genesis_ids.1);
    let mut changed_index = descriptor();
    changed_index.output_index += 1;
    let index_ids = inventory_custody_ids_v23(&changed_index)?;
    assert_ne!(original.0, index_ids.0);
    assert_ne!(original.1, index_ids.1);
    Ok(())
}

fn evidence() -> PublicInventoryEvidenceV24 {
    PublicInventoryEvidenceV24 {
        network_id: [1; 32],
        route_id: [2; 32],
        sessions: [[3; 32], [4; 32]],
        terms: [[5; 32], [6; 32]],
        genesis: [7; 32],
        tx_hash: [8; 32],
        raw_fingerprint: [9; 32],
        output_index: 10,
        output_key: [11; 32],
        key_image: [12; 32],
        amount_piconero: 13,
        fee_piconero: 14,
        height: 15,
        block_hash: [16; 32],
    }
}

#[test]
fn inventory_public_evidence_keeps_production_domain_and_all_operands_v24() -> Result<()> {
    let value = evidence();
    let original = value.digest()?;
    // Pin the pre-refactor production domain, field order and integer framing.
    let reference = reference_digest(
        b"DOM/PRODUCTION/XMR-INVENTORY-EVIDENCE/V23\0",
        &[
            &[1; 32],
            &[2; 32],
            &[3; 32],
            &[4; 32],
            &[5; 32],
            &[6; 32],
            &[7; 32],
            &[8; 32],
            &[9; 32],
            &10u32.to_be_bytes(),
            &[11; 32],
            &[12; 32],
            &13u64.to_be_bytes(),
            &14u64.to_be_bytes(),
            &15u64.to_be_bytes(),
            &[16; 32],
        ],
    )?;
    assert_eq!(original, reference);
    for field in 0..16 {
        let mut changed = evidence();
        match field {
            0 => changed.network_id[0] ^= 1,
            1 => changed.route_id[0] ^= 1,
            2 => changed.sessions[0][0] ^= 1,
            3 => changed.sessions[1][0] ^= 1,
            4 => changed.terms[0][0] ^= 1,
            5 => changed.terms[1][0] ^= 1,
            6 => changed.genesis[0] ^= 1,
            7 => changed.tx_hash[0] ^= 1,
            8 => changed.raw_fingerprint[0] ^= 1,
            9 => changed.output_index += 1,
            10 => changed.output_key[0] ^= 1,
            11 => changed.key_image[0] ^= 1,
            12 => changed.amount_piconero += 1,
            13 => changed.fee_piconero += 1,
            14 => changed.height += 1,
            _ => changed.block_hash[0] ^= 1,
        }
        assert_ne!(changed.digest()?, original);
    }
    Ok(())
}
