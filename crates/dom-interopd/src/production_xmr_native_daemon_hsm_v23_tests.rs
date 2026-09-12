//! Real Unix-socket signer owners for the native daemon scenario.
//! Requests use the production MAC/statement codec; no reservation is minted
//! here. The requesting F6 owner must already have its durable reservation.
use crate::production_f6_factory::{
    native_daemon_export_v23::NativeF6SignerEndpointV23, ProductionF6HsmSigningRequestV7,
    ProductionF6HsmSigningResponseV7,
};
use btc_crypto::SecpContext;
use f6_engine::candidate_book::BondReservationAttestationRequestV2;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy)]
pub(crate) struct NativeF6HsmScopeV23 {
    pub network_id: [u8; 32],
    pub composition_id: [u8; 32],
    pub position: rfq::v2::SettlementPositionV2,
    pub solver: kaystra_core::types::ParticipantId,
    pub bond_policy_hash: [u8; 32],
    pub registry_digest: [u8; 32],
    pub registry_epoch: u64,
    pub bond_asset_binding_digest: [u8; 32],
    pub required_collateral: u128,
    pub expires_at_seconds: u64,
}

pub(crate) struct NativeF6HsmOwnerV23 {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<std::result::Result<(), String>>>,
    pub descriptor: NativeF6SignerEndpointV23,
}

impl NativeF6HsmOwnerV23 {
    pub(crate) fn bind(
        root: &Path,
        index: u16,
        independent_authority_id: [u8; 32],
        secret: Zeroizing<[u8; 32]>,
        credential: Zeroizing<[u8; 32]>,
        scope: NativeF6HsmScopeV23,
    ) -> Result<Self> {
        if !root.is_absolute()
            || root.canonicalize()? != root
            || independent_authority_id == [0; 32]
            || *credential == [0; 32]
        {
            return Err("native HSM owner scope".into());
        }
        let secp = SecpContext::new(&[0x59; 32]);
        let public = secp.xonly_public_key(&secret)?;
        let endpoint = root.join(format!("bond-{index}.sock"));
        let journal = root.join(format!("bond-{index}-journal"));
        std::fs::create_dir(&journal)?;
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o700))?;
        let listener = UnixListener::bind(&endpoint)?;
        std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        File::open(root)?.sync_all()?;
        let uid = std::fs::symlink_metadata(&endpoint)?.uid();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            let secp = SecpContext::new(&[0x59; 32]);
            let mut last = BTreeMap::<[u8; 32], (u64, [u8; 32])>::new();
            while !worker_stop.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(error) => return Err(error.to_string()),
                };
                let serve = || -> Result<()> {
                    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                    let mut header = [0; 112];
                    stream.read_exact(&mut header)?;
                    let length = usize::try_from(u32::from_be_bytes(header[108..112].try_into()?))?;
                    if length == 0 || length > 4096 {
                        return Err("native HSM request bound".into());
                    }
                    let mut bytes = Zeroizing::new(Vec::from(header));
                    bytes.resize(112 + length + 32, 0);
                    stream.read_exact(&mut bytes[112..])?;
                    let request = ProductionF6HsmSigningRequestV7::decode_and_authenticate(
                        &bytes,
                        &credential,
                        index,
                        public,
                    )
                    .map_err(|_| "native HSM request authentication")?;
                    let statement = request.attestation().request();
                    scope.require(&statement)?;
                    let digest = request.attestation_digest();
                    match last.get(&statement.reservation_id) {
                        Some((sequence, previous))
                            if *sequence == statement.sequence && *previous == digest => {}
                        Some((sequence, previous))
                            if sequence.checked_add(1) == Some(statement.sequence)
                                && *previous == statement.previous_attestation_digest => {}
                        None if statement.sequence == 1
                            && statement.previous_attestation_digest == [0; 32] => {}
                        _ => return Err("native HSM reservation history".into()),
                    }
                    let signature = secp.sign_bip340(&secret, &digest, &[0x5a; 32])?.0;
                    let response = ProductionF6HsmSigningResponseV7::new(&request, signature)
                        .canonical_bytes();
                    let name = format!(
                        "{}-{}",
                        hex::encode(statement.reservation_id),
                        statement.sequence
                    );
                    let path = journal.join(name);
                    let mut durable = Vec::from(request.attestation().canonical_bytes()?);
                    durable.extend_from_slice(&response);
                    match OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&path)
                    {
                        Ok(mut file) => {
                            file.write_all(&durable)?;
                            file.sync_all()?;
                            File::open(&journal)?.sync_all()?;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                            if std::fs::read(&path)? != durable {
                                return Err("native HSM journal conflict".into());
                            }
                        }
                        Err(error) => return Err(error.into()),
                    }
                    last.insert(statement.reservation_id, (statement.sequence, digest));
                    stream.write_all(&response)?;
                    stream.flush()?;
                    Ok(())
                };
                // Refusal closes this request, never signs alternate bytes.
                let mut serve = serve;
                let _ = serve();
            }
            Ok(())
        });
        Ok(Self {
            stop,
            worker: Some(worker),
            descriptor: NativeF6SignerEndpointV23 {
                independent_authority_id,
                signer_index: index,
                signer_public_key: public,
                endpoint_uid: uid,
                endpoint,
            },
        })
    }
}

impl NativeF6HsmScopeV23 {
    fn require(&self, value: &BondReservationAttestationRequestV2) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if value.network_id != self.network_id
            || value.composition_id != self.composition_id
            || value.position != self.position
            || value.solver != self.solver
            || value.bond_policy_hash != self.bond_policy_hash
            || value.registry_digest != self.registry_digest
            || value.registry_epoch != self.registry_epoch
            || value.bond_asset_binding_digest != self.bond_asset_binding_digest
            || value.required_collateral != self.required_collateral
            || value.reserved_collateral < self.required_collateral
            || value.observed_at_seconds > now
            || value.valid_until_seconds <= now
            || value.valid_until_seconds > self.expires_at_seconds
        {
            return Err("native HSM policy refused".into());
        }
        Ok(())
    }
}

impl Drop for NativeF6HsmOwnerV23 {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
