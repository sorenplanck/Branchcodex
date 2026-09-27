//! Finalized attestation of an immutable upgradeable Solana program.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use solana_rpc::SolanaRpc;
use solana_rpc_pool::{QuorumError, SolanaRpcPool};
use solana_types::{Commitment, SolanaPubkey, BPF_LOADER_UPGRADEABLE_ID};

pub const PROGRAM_METADATA_LEN: usize = 36;
pub const PROGRAM_DATA_METADATA_LEN: usize = 45;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramAttestation {
    pub program_id: SolanaPubkey,
    pub program_data_address: SolanaPubkey,
    pub deployment_slot: u64,
    pub code_hash: [u8; 32],
    pub observed_context_slot: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestationError {
    #[error("RPC quorum failed")]
    Quorum,
    #[error("program account is not a valid upgradeable-loader program")]
    InvalidProgram,
    #[error("program still has an upgrade authority")]
    UpgradeAuthorityPresent,
    #[error("program code hash differs from frozen profile")]
    CodeHashMismatch,
}

pub fn code_hash(code: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"DOM-INTEROP/SOLANA-PROGRAM-DATA/V1\0");
    hasher.update((code.len() as u64).to_be_bytes());
    hasher.update(code);
    hasher.finalize().into()
}

pub fn attest_immutable_program<R: SolanaRpc>(
    pool: &SolanaRpcPool<R>,
    program_id: SolanaPubkey,
    expected_code_hash: [u8; 32],
) -> Result<ProgramAttestation, AttestationError> {
    let program = pool
        .account(program_id, Commitment::Finalized)
        .map_err(|_| AttestationError::Quorum)?
        .ok_or(AttestationError::InvalidProgram)?;
    if !program.executable
        || program.owner != BPF_LOADER_UPGRADEABLE_ID
        || program.data.len() < PROGRAM_METADATA_LEN
        || u32::from_le_bytes(
            program.data[..4]
                .try_into()
                .map_err(|_| AttestationError::InvalidProgram)?,
        ) != 2
    {
        return Err(AttestationError::InvalidProgram);
    }
    let mut address = [0u8; 32];
    address.copy_from_slice(&program.data[4..36]);
    let program_data_address = SolanaPubkey(address);
    let program_data = pool
        .account(program_data_address, Commitment::Finalized)
        .map_err(|_| AttestationError::Quorum)?
        .ok_or(AttestationError::InvalidProgram)?;
    if program_data.owner != BPF_LOADER_UPGRADEABLE_ID
        || program_data.executable
        || program_data.data.len() < PROGRAM_DATA_METADATA_LEN
        || u32::from_le_bytes(
            program_data.data[..4]
                .try_into()
                .map_err(|_| AttestationError::InvalidProgram)?,
        ) != 3
    {
        return Err(AttestationError::InvalidProgram);
    }
    let deployment_slot = u64::from_le_bytes(
        program_data.data[4..12]
            .try_into()
            .map_err(|_| AttestationError::InvalidProgram)?,
    );
    // bincode `Option<Pubkey>`: 0 = None, 1 = Some followed by 32 bytes. A zero
    // tag is the whole statement that no upgrade can be authorized, and it is
    // the only part of this field the loader defines after a revocation.
    if program_data.data[12] != 0 {
        return Err(AttestationError::UpgradeAuthorityPresent);
    }
    // The 32 bytes after the tag are NOT required to be zero, and requiring it
    // rejected every genuinely revoked program. `SetAuthority` serializes
    // `ProgramData { slot, upgrade_authority_address: None }` with bincode, which
    // writes thirteen bytes and stops; the reserved region keeps whatever was
    // written there last, which is the revoked authority's own key. Measured on
    // agave 2.1.11: a program loaded with authority
    // 6nSgiDWFfyGdhPEQLmNfgYEDCeWWgi3QVCHiKcqCPGeC and then finalized has tag 0
    // followed by 55ee9cdf6e6db6484bba024856eecbb9199ef9ee1bd2e2ad77016d1862114769
    // -- that authority, base58-decoded, still sitting in the reserved bytes.
    //
    // Nothing is weakened by not reading them: with a zero tag the loader never
    // interprets that region, so its contents cannot authorize anything. What the
    // loader does guarantee, and what this function relies on, is that the region
    // is a fixed 45 bytes for either variant, so the program's code always begins
    // at PROGRAM_DATA_METADATA_LEN. That was measured on the same program: the
    // account is exactly 45 + 171056 bytes and the code region equals the built
    // object byte for byte.
    let actual = code_hash(&program_data.data[PROGRAM_DATA_METADATA_LEN..]);
    if expected_code_hash == [0; 32] || actual != expected_code_hash {
        return Err(AttestationError::CodeHashMismatch);
    }
    Ok(ProgramAttestation {
        program_id,
        program_data_address,
        deployment_slot,
        code_hash: actual,
        observed_context_slot: program.context_slot.min(program_data.context_slot),
    })
}

impl From<QuorumError> for AttestationError {
    fn from(_: QuorumError) -> Self {
        Self::Quorum
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use solana_rpc::RpcError;
    use solana_types::{SolanaAccountSnapshot, SolanaHash, SolanaSignature, SolanaSignatureStatus, SolanaTransactionRecord};
    use std::sync::Arc;

    const CODE: &[u8] = b"not a real program, but exactly these bytes";

    /// Answers `get_account` from a fixed pair and refuses everything else: this
    /// crate reads accounts and nothing more, and a mock that quietly answered
    /// other questions would hide that.
    struct TwoAccounts {
        program: (SolanaPubkey, SolanaAccountSnapshot),
        program_data: (SolanaPubkey, SolanaAccountSnapshot),
    }

    impl SolanaRpc for TwoAccounts {
        fn get_slot(&self, _: Commitment) -> Result<u64, RpcError> {
            Err(RpcError::Unavailable)
        }
        fn get_block_height(&self, _: Commitment) -> Result<u64, RpcError> {
            Err(RpcError::Unavailable)
        }
        fn get_block_anchor(&self, _: u64) -> Result<Option<solana_types::SolanaBlockAnchor>, RpcError> {
            Err(RpcError::Unavailable)
        }
        fn get_account(
            &self,
            key: SolanaPubkey,
            _: Commitment,
        ) -> Result<Option<SolanaAccountSnapshot>, RpcError> {
            if key == self.program.0 {
                Ok(Some(self.program.1.clone()))
            } else if key == self.program_data.0 {
                Ok(Some(self.program_data.1.clone()))
            } else {
                Ok(None)
            }
        }
        fn get_signature_status(
            &self,
            _: SolanaSignature,
        ) -> Result<Option<SolanaSignatureStatus>, RpcError> {
            Err(RpcError::Unavailable)
        }
        fn get_transaction(
            &self,
            _: SolanaSignature,
            _: Commitment,
        ) -> Result<Option<SolanaTransactionRecord>, RpcError> {
            Err(RpcError::Unavailable)
        }
        fn get_latest_blockhash(&self) -> Result<SolanaHash, RpcError> {
            Err(RpcError::Unavailable)
        }
        fn get_latest_blockhash_with_validity(&self) -> Result<(SolanaHash, u64), RpcError> {
            Err(RpcError::Unavailable)
        }
        fn send_transaction(&self, _: &[u8]) -> Result<SolanaSignature, RpcError> {
            Err(RpcError::Unavailable)
        }
    }

    /// `reserved` is what the loader leaves in the 32 bytes after a `None` tag.
    fn cluster(authority_tag: u8, reserved: [u8; 32]) -> (SolanaPubkey, SolanaRpcPool<TwoAccounts>) {
        let program_id = SolanaPubkey([7; 32]);
        let program_data_address = SolanaPubkey([9; 32]);
        let mut program = vec![0u8; PROGRAM_METADATA_LEN];
        program[..4].copy_from_slice(&2u32.to_le_bytes());
        program[4..36].copy_from_slice(&program_data_address.0);
        let mut data = vec![0u8; PROGRAM_DATA_METADATA_LEN];
        data[..4].copy_from_slice(&3u32.to_le_bytes());
        data[4..12].copy_from_slice(&11u64.to_le_bytes());
        data[12] = authority_tag;
        data[13..PROGRAM_DATA_METADATA_LEN].copy_from_slice(&reserved);
        data.extend_from_slice(CODE);
        let nodes = TwoAccounts {
            program: (
                program_id,
                SolanaAccountSnapshot {
                    context_slot: 20,
                    lamports: 1,
                    owner: BPF_LOADER_UPGRADEABLE_ID,
                    executable: true,
                    rent_epoch: 0,
                    data: program,
                },
            ),
            program_data: (
                program_data_address,
                SolanaAccountSnapshot {
                    context_slot: 21,
                    lamports: 1,
                    owner: BPF_LOADER_UPGRADEABLE_ID,
                    executable: false,
                    rent_epoch: 0,
                    data,
                },
            ),
        };
        (
            program_id,
            SolanaRpcPool::new(vec![Arc::new(nodes)], 1).expect("a single-node pool"),
        )
    }

    #[test]
    fn a_revoked_program_attests_although_the_old_authority_remains_in_the_reserved_bytes() {
        // Exactly the shape measured on agave 2.1.11 after
        // `program set-upgrade-authority --final`: tag 0, old key still present.
        let stale = [
            0x55, 0xee, 0x9c, 0xdf, 0x6e, 0x6d, 0xb6, 0x48, 0x4b, 0xba, 0x02, 0x48, 0x56, 0xee,
            0xcb, 0xb9, 0x19, 0x9e, 0xf9, 0xee, 0x1b, 0xd2, 0xe2, 0xad, 0x77, 0x01, 0x6d, 0x18,
            0x62, 0x11, 0x47, 0x69,
        ];
        let (program_id, pool) = cluster(0, stale);
        let attested = attest_immutable_program(&pool, program_id, code_hash(CODE))
            .expect("a revoked program attests");
        assert_eq!(attested.code_hash, code_hash(CODE));
        assert_eq!(attested.deployment_slot, 11);
        assert_eq!(attested.observed_context_slot, 20);
    }

    #[test]
    fn an_all_zero_reserved_region_also_attests() {
        let (program_id, pool) = cluster(0, [0; 32]);
        attest_immutable_program(&pool, program_id, code_hash(CODE))
            .expect("an absent authority with a zeroed region attests");
    }

    #[test]
    fn a_program_that_still_has_an_authority_is_refused() {
        let (program_id, pool) = cluster(1, [3; 32]);
        assert_eq!(
            attest_immutable_program(&pool, program_id, code_hash(CODE)),
            Err(AttestationError::UpgradeAuthorityPresent)
        );
    }

    #[test]
    fn different_code_is_refused_and_a_zero_expectation_never_passes() {
        let (program_id, pool) = cluster(0, [0; 32]);
        assert_eq!(
            attest_immutable_program(&pool, program_id, code_hash(b"other bytes")),
            Err(AttestationError::CodeHashMismatch)
        );
        assert_eq!(
            attest_immutable_program(&pool, program_id, [0; 32]),
            Err(AttestationError::CodeHashMismatch)
        );
    }
}
