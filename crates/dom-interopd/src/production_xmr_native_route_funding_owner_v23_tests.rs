//! One real GPL producer, two route funding candidates plus one independently
//! keyed solver-inventory output, one common XMR RPC history, and four separately
//! credentialed actor sidecars. Nothing is broadcast.
use super::*;

fn inventory_custody_digest_v23(domain: &[u8], parts: &[&[u8]]) -> Result<[u8; 32]> {
    use blake2::digest::{Update, VariableOutput};
    let mut hash = blake2::Blake2bVar::new(32)?;
    hash.update(domain);
    for part in parts {
        hash.update(&u64::try_from(part.len())?.to_be_bytes());
        hash.update(part);
    }
    let mut value = [0; 32];
    hash.finalize_variable(&mut value)?;
    if value == [0; 32] {
        return Err("solver inventory zero custody digest".into());
    }
    Ok(value)
}

pub(crate) const NATIVE_XMR_INVENTORY_DESCRIPTOR_V23: &str =
    "native-xmr-inventory-authority-v23.bin";
const INVENTORY_DESCRIPTOR_MAGIC_V23: &[u8; 8] = b"XMRINV23";
const INVENTORY_DESCRIPTOR_PREFIX_V23: usize = 320;
const INVENTORY_DESCRIPTOR_MAX_V23: usize =
    INVENTORY_DESCRIPTOR_PREFIX_V23 + 256 + xmr_raw_tx_verify::MAX_VERIFIED_RAW_TX_BYTES + 32;

struct NativeInventoryDescriptorV23 {
    network: [u8; 32],
    route: [u8; 32],
    sessions: [[u8; 32]; 2],
    terms: [[u8; 32]; 2],
    authority_id: [u8; 32],
    tx_hash: [u8; 32],
    spend_public: [u8; 32],
    amount_piconero: u64,
    max_fee_piconero: u64,
    destination: String,
    raw: Zeroizing<Vec<u8>>,
}

impl NativeInventoryDescriptorV23 {
    fn encode(&self) -> Result<Vec<u8>> {
        if [
            self.network,
            self.route,
            self.sessions[0],
            self.sessions[1],
            self.terms[0],
            self.terms[1],
            self.authority_id,
            self.tx_hash,
            self.spend_public,
        ]
        .contains(&[0; 32])
            || self.sessions[0] == self.sessions[1]
            || self.terms[0] == self.terms[1]
            || self.amount_piconero == 0
            || self.max_fee_piconero == 0
            || self.destination.is_empty()
            || self.destination.len() > 256
            || !self.destination.is_ascii()
            || self.raw.is_empty()
            || self.raw.len() > xmr_raw_tx_verify::MAX_VERIFIED_RAW_TX_BYTES
        {
            return Err("solver inventory descriptor bounds".into());
        }
        let mut bytes = Vec::with_capacity(
            INVENTORY_DESCRIPTOR_PREFIX_V23 + self.destination.len() + self.raw.len() + 32,
        );
        bytes.extend_from_slice(INVENTORY_DESCRIPTOR_MAGIC_V23);
        bytes.extend_from_slice(&23_u16.to_le_bytes());
        for field in [
            self.network,
            self.route,
            self.sessions[0],
            self.sessions[1],
            self.terms[0],
            self.terms[1],
            self.authority_id,
            self.tx_hash,
            self.spend_public,
        ] {
            bytes.extend_from_slice(&field);
        }
        bytes.extend_from_slice(&self.amount_piconero.to_le_bytes());
        bytes.extend_from_slice(&self.max_fee_piconero.to_le_bytes());
        bytes.extend_from_slice(&u16::try_from(self.destination.len())?.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(self.raw.len())?.to_le_bytes());
        bytes.extend_from_slice(self.destination.as_bytes());
        bytes.extend_from_slice(&self.raw);
        let checksum = inventory_custody_digest_v23(
            b"DOM/NATIVE-F6/XMR-INVENTORY-DESCRIPTOR/V23\0",
            &[&bytes],
        )?;
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < INVENTORY_DESCRIPTOR_PREFIX_V23 + 32
            || bytes.len() > INVENTORY_DESCRIPTOR_MAX_V23
            || bytes.get(..8) != Some(INVENTORY_DESCRIPTOR_MAGIC_V23.as_slice())
            || bytes.get(8..10) != Some(23_u16.to_le_bytes().as_slice())
        {
            return Err("solver inventory descriptor framing".into());
        }
        let mut at = 10usize;
        let mut field = || -> Result<[u8; 32]> {
            let end = at
                .checked_add(32)
                .ok_or("solver inventory descriptor overflow")?;
            let value = bytes
                .get(at..end)
                .ok_or("solver inventory descriptor field")?
                .try_into()?;
            at = end;
            Ok(value)
        };
        let network = field()?;
        let route = field()?;
        let sessions = [field()?, field()?];
        let terms = [field()?, field()?];
        let authority_id = field()?;
        let tx_hash = field()?;
        let spend_public = field()?;
        let amount_piconero = u64::from_le_bytes(
            bytes
                .get(at..at + 8)
                .ok_or("solver inventory amount")?
                .try_into()?,
        );
        let max_fee_piconero = u64::from_le_bytes(
            bytes
                .get(at + 8..at + 16)
                .ok_or("solver inventory fee")?
                .try_into()?,
        );
        let destination_len = usize::from(u16::from_le_bytes(
            bytes
                .get(at + 16..at + 18)
                .ok_or("solver inventory destination length")?
                .try_into()?,
        ));
        let raw_len = usize::try_from(u32::from_le_bytes(
            bytes
                .get(at + 18..at + 22)
                .ok_or("solver inventory raw length")?
                .try_into()?,
        ))?;
        at = at
            .checked_add(22)
            .ok_or("solver inventory descriptor overflow")?;
        let payload_end = at
            .checked_add(destination_len)
            .and_then(|value| value.checked_add(raw_len))
            .ok_or("solver inventory descriptor overflow")?;
        if payload_end.checked_add(32) != Some(bytes.len()) {
            return Err("solver inventory descriptor trailing bytes".into());
        }
        let expected = inventory_custody_digest_v23(
            b"DOM/NATIVE-F6/XMR-INVENTORY-DESCRIPTOR/V23\0",
            &[&bytes[..payload_end]],
        )?;
        if bytes[payload_end..] != expected {
            return Err("solver inventory descriptor checksum".into());
        }
        let destination_end = at + destination_len;
        let value = Self {
            network,
            route,
            sessions,
            terms,
            authority_id,
            tx_hash,
            spend_public,
            amount_piconero,
            max_fee_piconero,
            destination: std::str::from_utf8(&bytes[at..destination_end])?.to_owned(),
            raw: Zeroizing::new(bytes[destination_end..payload_end].to_vec()),
        };
        if value.encode()? != bytes {
            return Err("solver inventory descriptor noncanonical".into());
        }
        Ok(value)
    }
}

fn inventory_custody_ids_v23(
    descriptor: &NativeInventoryDescriptorV23,
) -> Result<([u8; 32], [u8; 32])> {
    let record_id = inventory_custody_digest_v23(
        b"DOM/NATIVE-F6/XMR-INVENTORY-CUSTODY-RECORD/V23\0",
        &[
            &descriptor.network,
            &descriptor.route,
            &descriptor.sessions[0],
            &descriptor.sessions[1],
            &descriptor.tx_hash,
        ],
    )?;
    let binding = inventory_custody_digest_v23(
        b"DOM/NATIVE-F6/XMR-INVENTORY-CUSTODY-BINDING/V23\0",
        &[
            &descriptor.network,
            &descriptor.route,
            &descriptor.sessions[0],
            &descriptor.sessions[1],
            &descriptor.terms[0],
            &descriptor.terms[1],
            &descriptor.authority_id,
            &descriptor.tx_hash,
            &descriptor.spend_public,
            &descriptor.amount_piconero.to_be_bytes(),
            &descriptor.max_fee_piconero.to_be_bytes(),
            descriptor.destination.as_bytes(),
        ],
    )?;
    Ok((record_id, binding))
}

fn publish_inventory_descriptor_v23(
    path: &Path,
    descriptor: &NativeInventoryDescriptorV23,
) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let parent = path.parent().ok_or("solver inventory descriptor parent")?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if !path.is_absolute()
        || std::fs::canonicalize(parent)? != parent
        || !parent_metadata.is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != rustix::process::getuid().as_raw()
        || parent_metadata.mode() & 0o077 != 0
        || path.file_name().and_then(std::ffi::OsStr::to_str)
            != Some(NATIVE_XMR_INVENTORY_DESCRIPTOR_V23)
    {
        return Err("solver inventory descriptor state-dir refused".into());
    }
    let bytes = descriptor.encode()?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn read_inventory_descriptor_v23(path: &Path) -> Result<NativeInventoryDescriptorV23> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || std::fs::canonicalize(path)? != path
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || usize::try_from(metadata.len())? > INVENTORY_DESCRIPTOR_MAX_V23
        || path.file_name().and_then(std::ffi::OsStr::to_str)
            != Some(NATIVE_XMR_INVENTORY_DESCRIPTOR_V23)
    {
        return Err("solver inventory descriptor file refused".into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len())?);
    std::fs::File::open(path)?
        .take(u64::try_from(INVENTORY_DESCRIPTOR_MAX_V23 + 1)?)
        .read_to_end(&mut bytes)?;
    if bytes.len() != usize::try_from(metadata.len())? {
        return Err("solver inventory descriptor changed during read".into());
    }
    NativeInventoryDescriptorV23::decode(&bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteEnvelopeV23 {
    schema: String,
    scope: String,
    legs: [Envelope; 2],
    solver_inventory: Envelope,
}

pub(crate) struct RouteFundingOwnerV23 {
    sidecars: [[PeerSidecarOwnerV23; 2]; 2],
    helper: ProcessOwner,
    envelopes: [Envelope; 2],
    hashes: [[u8; 32]; 2],
    inventory_source: Option<NativeMainnetXmrInventorySourceV23>,
}

/// Private owner of a solver wallet output which is deliberately distinct
/// from both route funding candidates. It can only be consumed by the
/// mandatory F6 observer and never exports either wallet scalar.
pub(crate) struct NativeMainnetXmrInventorySourceV23 {
    raw: Zeroizing<Vec<u8>>,
    tx_hash: [u8; 32],
    amount_piconero: u64,
    max_fee_piconero: u64,
    destination: String,
    spend_public: [u8; 32],
    auth: [Zeroizing<[u8; 32]>; 2],
    authority_id: [u8; 32],
    pending_material: Option<xmr_secret_store::XmrSecretMaterial>,
    custody: Option<NativeInventoryCustodyV23>,
    custody_scope: Option<([u8; 32], [u8; 32], [[u8; 32]; 2], [[u8; 32]; 2])>,
}

/// Opaque handle to the existing encrypted enrollment Store. The inventory
/// scalars are loaded under route-bound AEAD associated data only while used;
/// neither scalar, the Store master key nor a plaintext path is exported.
struct NativeInventoryCustodyV23 {
    store: xmr_secret_store::EncryptedSqliteSecretStore,
    record_id: [u8; 32],
    binding: [u8; 32],
}

impl NativeMainnetXmrInventorySourceV23 {
    pub(crate) fn tx_hash(&self) -> [u8; 32] {
        self.tx_hash
    }
    pub(crate) fn amount_piconero(&self) -> u64 {
        self.amount_piconero
    }
    pub(crate) fn max_fee_piconero(&self) -> u64 {
        self.max_fee_piconero
    }
    pub(crate) fn destination(&self) -> &str {
        &self.destination
    }
    pub(crate) fn authority_id(&self) -> [u8; 32] {
        self.authority_id
    }

    pub(crate) fn require_custody_scope_v23(
        &self,
        network: [u8; 32],
        route: [u8; 32],
        sessions: [[u8; 32]; 2],
        terms: [[u8; 32]; 2],
    ) -> Result<()> {
        if self.custody_scope != Some((network, route, sessions, terms)) {
            return Err("solver inventory restored custody scope mismatch".into());
        }
        Ok(())
    }

    /// Reconstruct from a bounded public descriptor and an already-authenticated
    /// existing encrypted Store. No missing row, file or credential is created.
    pub(crate) fn reopen_from_state_dir_v23(
        descriptor_path: &Path,
        store: xmr_secret_store::EncryptedSqliteSecretStore,
        auth: [Zeroizing<[u8; 32]>; 2],
    ) -> Result<Self> {
        use xmr_secret_store::SecretMaterialStore;
        let descriptor = read_inventory_descriptor_v23(descriptor_path)?;
        let (record_id, binding) = inventory_custody_ids_v23(&descriptor)?;
        let material = store.load(&record_id, &binding)?;
        material.expose(|spend, view| -> Result<()> {
            if xmr_crypto::XmrSpendShare::from_canonical_bytes(*spend)?.public_share()?
                != descriptor.spend_public
                || xmr_raw_tx_verify::standard_funding_address_v12(
                    1,
                    descriptor.spend_public,
                    view,
                )? != descriptor.destination
            {
                return Err("solver inventory restored public wallet mismatch".into());
            }
            let owned = xmr_raw_tx_verify::derive_owned_funding_key_image_v23(
                &descriptor.raw,
                descriptor.tx_hash,
                spend,
                view,
                descriptor.amount_piconero,
                descriptor.max_fee_piconero,
            )?;
            if owned.funding().transaction().tx_hash != descriptor.tx_hash
                || owned.funding().amount_piconero() != descriptor.amount_piconero
                || owned.funding().fee_piconero() > descriptor.max_fee_piconero
            {
                return Err("solver inventory restored outpoint/economics mismatch".into());
            }
            Ok(())
        })?;
        Ok(Self {
            raw: descriptor.raw,
            tx_hash: descriptor.tx_hash,
            amount_piconero: descriptor.amount_piconero,
            max_fee_piconero: descriptor.max_fee_piconero,
            destination: descriptor.destination,
            spend_public: descriptor.spend_public,
            auth,
            authority_id: descriptor.authority_id,
            pending_material: None,
            custody: Some(NativeInventoryCustodyV23 {
                store,
                record_id,
                binding,
            }),
            custody_scope: Some((
                descriptor.network,
                descriptor.route,
                descriptor.sessions,
                descriptor.terms,
            )),
        })
    }

    fn load_custodied_material_v23(&self) -> Result<xmr_secret_store::XmrSecretMaterial> {
        use xmr_secret_store::SecretMaterialStore;
        let custody = self
            .custody
            .as_ref()
            .ok_or("solver inventory durable custody absent")?;
        Ok(custody.store.load(&custody.record_id, &custody.binding)?)
    }

    pub(crate) fn derive_owned_key_image_v23(
        &self,
    ) -> Result<xmr_raw_tx_verify::VerifiedOwnedFundingKeyImageV23> {
        let material = self.load_custodied_material_v23()?;
        material.expose(|spend, view| -> Result<_> {
            if xmr_crypto::XmrSpendShare::from_canonical_bytes(*spend)?.public_share()?
                != self.spend_public
            {
                return Err("solver inventory spend key owner mismatch".into());
            }
            Ok(xmr_raw_tx_verify::derive_owned_funding_key_image_v23(
                &self.raw,
                self.tx_hash,
                spend,
                view,
                self.amount_piconero,
                self.max_fee_piconero,
            )?)
        })
    }
    pub(crate) fn verify_sidecar_v23(
        &self,
        actor: usize,
        socket: PathBuf,
        nonce: [u8; 32],
        session: [u8; 32],
    ) -> Result<xmr_live_sidecar_api::VerifyFundingResponseV2> {
        use xmr_spend_port::FundingVerifyPort;
        let auth = self.auth.get(actor).ok_or("solver inventory actor")?;
        let mut sidecar = xmr_live_sidecar_uds_client::BlockingUdsSidecarPort::with_timeout(
            socket,
            xmr_sidecar_auth::SidecarAuthKey::new(**auth)?,
            std::time::Duration::from_secs(30),
        )?;
        let material = self.load_custodied_material_v23()?;
        material.expose(|_, view| {
            Ok(
                sidecar.verify_funding(xmr_live_sidecar_api::VerifyFundingRequestV2 {
                    api_version: xmr_live_sidecar_api::API_VERSION_V2,
                    request_nonce: nonce,
                    settlement_id: session,
                    funding_tx_hash: self.tx_hash,
                    expected_amount_piconero: self.amount_piconero,
                    expected_spend_public_key: self.spend_public,
                    view_scalar: xmr_live_sidecar_api::SecretScalarBytes::new(*view),
                    auth_tag: [0; 32],
                })?,
            )
        })
    }
    pub(crate) fn expected_destination_v23(&self) -> Result<String> {
        let material = self.load_custodied_material_v23()?;
        material.expose(|_, view| {
            Ok(xmr_raw_tx_verify::standard_funding_address_v12(
                1,
                self.spend_public,
                view,
            )?)
        })
    }

    fn persist_custody_v23(
        &mut self,
        network: [u8; 32],
        route: [u8; 32],
        sessions: [[u8; 32]; 2],
        terms: [[u8; 32]; 2],
        descriptor_path: &Path,
        persist: impl FnOnce(
            [u8; 32],
            [u8; 32],
            &xmr_secret_store::XmrSecretMaterial,
        ) -> Result<xmr_secret_store::EncryptedSqliteSecretStore>,
    ) -> Result<()> {
        if self.custody.is_some()
            || self.pending_material.is_none()
            || [network, route, sessions[0], sessions[1], terms[0], terms[1]].contains(&[0; 32])
            || sessions[0] == sessions[1]
            || terms[0] == terms[1]
        {
            return Err("solver inventory custody scope or state mismatch".into());
        }
        let descriptor = NativeInventoryDescriptorV23 {
            network,
            route,
            sessions,
            terms,
            authority_id: self.authority_id,
            tx_hash: self.tx_hash,
            spend_public: self.spend_public,
            amount_piconero: self.amount_piconero,
            max_fee_piconero: self.max_fee_piconero,
            destination: self.destination.clone(),
            raw: Zeroizing::new(self.raw.to_vec()),
        };
        let (record_id, binding) = inventory_custody_ids_v23(&descriptor)?;
        let pending = self
            .pending_material
            .as_ref()
            .ok_or("solver inventory pending custody absent")?;
        let store = persist(record_id, binding, pending)?;
        use xmr_secret_store::SecretMaterialStore;
        let restored = store.load(&record_id, &binding)?;
        restored.expose(|spend, view| -> Result<()> {
            if xmr_crypto::XmrSpendShare::from_canonical_bytes(*spend)?.public_share()?
                != self.spend_public
                || xmr_raw_tx_verify::standard_funding_address_v12(1, self.spend_public, view)?
                    != self.destination
            {
                return Err("solver inventory restored custody disagrees".into());
            }
            Ok(())
        })?;
        publish_inventory_descriptor_v23(descriptor_path, &descriptor)?;
        self.custody = Some(NativeInventoryCustodyV23 {
            store,
            record_id,
            binding,
        });
        self.custody_scope = Some((network, route, sessions, terms));
        drop(self.pending_material.take());
        Ok(())
    }
}

impl Configuration {
    pub(crate) fn start_mainnet_route_v23(
        &self,
        spends: [[u8; 32]; 2],
        amounts: [u64; 2],
        fees: [u64; 2],
        work: [&Path; 2],
        auth: &[[Zeroizing<[u8; 32]>; 2]; 2],
        inventory_authority_id: [u8; 32],
    ) -> Result<RouteFundingOwnerV23> {
        if spends[0] == spends[1] || spends.contains(&[0; 32]) || inventory_authority_id == [0; 32]
        {
            return Err("route funding requires distinct combined spend keys".into());
        }
        let mut rng = rand::thread_rng();
        let inventory_spend = xmr_dleq_sigma::CrossCurveSecret252::generate(&mut rng);
        let inventory_view = xmr_dleq_sigma::CrossCurveSecret252::generate(&mut rng);
        let spend_scalar = Zeroizing::new(inventory_spend.xmr_share_little_endian());
        let view_scalar = Zeroizing::new(inventory_view.xmr_share_little_endian());
        let spend_public = inventory_spend.public_claim()?.ed_compressed;
        let view_public = inventory_view.public_claim()?.ed_compressed;
        if spends.contains(&spend_public) || spend_public == view_public {
            return Err("solver inventory wallet key collision".into());
        }
        let inventory_amount = amounts[0]
            .checked_add(amounts[1])
            .ok_or("solver inventory amount overflow")?;
        let inventory_fee = fees.into_iter().max().ok_or("solver inventory fee")?;
        let child = Command::new(&self.helper)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut helper = ProcessOwner { child, input: None };
        helper.input = Some(helper.child.stdin.take().ok_or("route helper stdin")?);
        let stdout = helper.child.stdout.take().ok_or("route helper stdout")?;
        let request = serde_json::json!({
            "schema":"DOM-XMR-OFFLINE-FUNDING-REQUEST-V23", "network_tag":1,
            "combined_spend_public_key":hex::encode(spends[0]),"amount_piconero":amounts[0],
            "max_fee_piconero":fees[0],
            "route_peer":{"combined_spend_public_key":hex::encode(spends[1]),
                "amount_piconero":amounts[1],"max_fee_piconero":fees[1],
                "solver_inventory":{"spend_public_key":hex::encode(spend_public),
                    "view_public_key":hex::encode(view_public),
                    "amount_piconero":inventory_amount,"max_fee_piconero":inventory_fee}},
        });
        let input = helper.input.as_mut().ok_or("route helper input missing")?;
        serde_json::to_writer(&mut *input, &request)?;
        input.write_all(b"\n")?;
        input.flush()?;
        let (send, receive) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = BufReader::new(stdout)
                .take((MAX_ENVELOPE * 3 + 1) as u64)
                .read_until(b'\n', &mut bytes)
                .map(|_| bytes)
                .map_err(|_| "route envelope read");
            let _ = send.send(result);
        });
        let bytes = match receive.recv_timeout(Duration::from_secs(120)) {
            Ok(result) => result?,
            Err(_) => {
                let _ = helper.child.kill();
                let _ = helper.child.wait();
                let _ = reader.join();
                return Err("route helper envelope timeout".into());
            }
        };
        reader.join().map_err(|_| "route envelope reader panic")?;
        if bytes.len() > MAX_ENVELOPE * 3 || !bytes.ends_with(b"\n") {
            return Err("route envelope bound".into());
        }
        let value: RouteEnvelopeV23 = serde_json::from_slice(&bytes)?;
        if value.schema != "DOM-XMR-OFFLINE-ROUTE-FUNDING-V23"
            || value.scope != "local-route-only-no-chain-funding"
            || value.legs[0].daemon_urls != value.legs[1].daemon_urls
            || value.legs[0].daemon_urls != value.solver_inventory.daemon_urls
            || value.legs[0].daemon_urls.len() != 2
        {
            return Err("route helper changed shared-history scope".into());
        }
        let mut ports = std::collections::BTreeSet::new();
        for url in &value.legs[0].daemon_urls {
            let address = url
                .strip_prefix("http://")
                .ok_or("route RPC scheme")?
                .parse::<std::net::SocketAddr>()?;
            if !address.ip().is_loopback() || address.port() == 0 || !ports.insert(address.port()) {
                return Err("route RPC voters must be distinct numeric loopback".into());
            }
        }
        let mut hashes = [[0; 32]; 2];
        let mut view = Zeroizing::new([0; 32]);
        view[0] = 13;
        for position in 0..2 {
            let envelope = &value.legs[position];
            hashes[position] = hex::decode(&envelope.funding_tx_hash)?
                .try_into()
                .map_err(|_| "route funding hash length")?;
            if envelope.schema != "DOM-XMR-OFFLINE-FUNDING-V23"
                || envelope.scope != "local-component-only-no-chain-funding"
                || envelope.combined_spend_public_key != hex::encode(spends[position])
                || envelope.amount_piconero != amounts[position]
                || envelope.destination
                    != xmr_raw_tx_verify::standard_funding_address_v12(1, spends[position], &view)?
            {
                return Err("route funding public binding mismatch".into());
            }
            xmr_rpc_broadcast_blocking::PreparedPrivateFundingV12::import(
                hex::decode(&envelope.canonical_transaction)?,
                hashes[position],
                spends[position],
                &view,
                amounts[position],
                fees[position],
            )?;
        }
        if hashes[0] == hashes[1] {
            return Err("route funding hashes alias".into());
        }
        let inventory_hash: [u8; 32] = hex::decode(&value.solver_inventory.funding_tx_hash)?
            .try_into()
            .map_err(|_| "solver inventory hash length")?;
        let inventory_raw =
            Zeroizing::new(hex::decode(&value.solver_inventory.canonical_transaction)?);
        let inventory_verified = xmr_raw_tx_verify::verify_exact_raw_funding_v12(
            &inventory_raw,
            inventory_hash,
            spend_public,
            &view_scalar,
            inventory_amount,
            inventory_fee,
        )?;
        if hashes.contains(&inventory_hash)
            || value.solver_inventory.schema != "DOM-XMR-OFFLINE-FUNDING-V23"
            || value.solver_inventory.scope != "local-component-only-no-chain-funding"
            || value.solver_inventory.combined_spend_public_key != hex::encode(spend_public)
            || value.solver_inventory.view_public_key != hex::encode(view_public)
            || value.solver_inventory.amount_piconero != inventory_amount
            || value.solver_inventory.destination
                != xmr_raw_tx_verify::standard_funding_address_v12(1, spend_public, &view_scalar)?
            || inventory_verified.transaction().tx_hash != inventory_hash
        {
            return Err("solver inventory public/provenance binding mismatch".into());
        }
        let mut sidecars = Vec::with_capacity(2);
        for position in 0..2 {
            let mut actors = Vec::with_capacity(2);
            for actor in 0..2 {
                actors.push(self.start_peer_sidecar_for_urls_v23(
                    &value.legs[position].daemon_urls,
                    work[actor],
                    *auth[position][actor],
                )?);
            }
            sidecars.push(actors.try_into().map_err(|_| "two route sidecar actors")?);
        }
        Ok(RouteFundingOwnerV23 {
            sidecars: sidecars.try_into().map_err(|_| "two sidecar positions")?,
            helper,
            envelopes: value.legs,
            hashes,
            inventory_source: Some(NativeMainnetXmrInventorySourceV23 {
                raw: inventory_raw,
                tx_hash: inventory_hash,
                amount_piconero: inventory_amount,
                max_fee_piconero: inventory_fee,
                destination: value.solver_inventory.destination,
                spend_public,
                auth: std::array::from_fn(|actor| Zeroizing::new(*auth[0][actor])),
                authority_id: inventory_authority_id,
                pending_material: Some(xmr_secret_store::XmrSecretMaterial::new(
                    *spend_scalar,
                    *view_scalar,
                )?),
                custody: None,
                custody_scope: None,
            }),
        })
    }
}

impl RouteFundingOwnerV23 {
    pub(crate) fn inventory_authority_id_v23(&self) -> Result<[u8; 32]> {
        self.inventory_source
            .as_ref()
            .map(NativeMainnetXmrInventorySourceV23::authority_id)
            .ok_or_else(|| "solver inventory source absent".into())
    }

    /// Persist the independent wallet scalars into the already-authenticated
    /// enrollment Store. The closure returns only an opaque opened Store;
    /// plaintext material is dropped immediately after an authenticated reload.
    pub(crate) fn persist_inventory_source_v23(
        &mut self,
        network: [u8; 32],
        route: [u8; 32],
        sessions: [[u8; 32]; 2],
        terms: [[u8; 32]; 2],
        descriptor_path: &Path,
        persist: impl FnOnce(
            [u8; 32],
            [u8; 32],
            &xmr_secret_store::XmrSecretMaterial,
        ) -> Result<xmr_secret_store::EncryptedSqliteSecretStore>,
    ) -> Result<()> {
        self.inventory_source
            .as_mut()
            .ok_or("solver inventory source absent")?
            .persist_custody_v23(network, route, sessions, terms, descriptor_path, persist)
    }

    /// Moves the sole unrelated solver-wallet owner into the mandatory F6
    /// observer. Missing durable custody is terminal; no ephemeral-key fallback
    /// or fresh-wallet reconstruction is permitted after a restart.
    pub(crate) fn take_inventory_source_v23(
        &mut self,
    ) -> Result<NativeMainnetXmrInventorySourceV23> {
        let ready = self
            .inventory_source
            .as_ref()
            .is_some_and(|source| source.custody.is_some() && source.pending_material.is_none());
        if !ready {
            return Err("solver inventory durable custody is not ready".into());
        }
        self.inventory_source
            .take()
            .ok_or_else(|| "solver inventory source already consumed".into())
    }

    pub(crate) fn hash(&self, position: usize) -> Result<[u8; 32]> {
        self.hashes
            .get(position)
            .copied()
            .ok_or_else(|| "route position".into())
    }
    pub(crate) fn destination(&self, position: usize) -> Result<String> {
        Ok(self
            .envelopes
            .get(position)
            .ok_or("route position")?
            .destination
            .clone())
    }
    pub(crate) fn raw(&self, position: usize) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(hex::decode(
            &self
                .envelopes
                .get(position)
                .ok_or("route position")?
                .canonical_transaction,
        )?))
    }
    pub(crate) fn urls(&self) -> &[String] {
        &self.envelopes[0].daemon_urls
    }
    pub(crate) fn socket(&self, position: usize, actor: usize) -> Result<PathBuf> {
        Ok(self
            .sidecars
            .get(position)
            .and_then(|actors| actors.get(actor))
            .ok_or("route sidecar index")?
            .socket())
    }
    pub(crate) fn require_alive(&mut self) -> Result<()> {
        if self.helper.child.try_wait()?.is_some() {
            return Err("route helper exited".into());
        }
        for sidecar in self.sidecars.iter_mut().flatten() {
            sidecar.require_alive()?;
        }
        Ok(())
    }
}
