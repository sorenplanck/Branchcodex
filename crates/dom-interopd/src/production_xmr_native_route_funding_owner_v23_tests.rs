//! One real GPL producer, two route funding candidates plus one independently
//! keyed solver-inventory output, one common XMR RPC history, and four separately
//! credentialed actor sidecars. Nothing is forwarded to a live chain. The
//! explicit mutable mode accepts daemon submissions into a private local pool;
//! initial route candidates are neither submitted nor confirmed for the daemon.
use super::*;

#[path = "production_xmr_native_route_control_v23_tests.rs"]
mod control_v23;
pub(crate) use control_v23::NativeXmrHistoryStatusV23;

// The real daemon and this fixture must share one descriptor codec, custody
// associated-data derivation and bounded reader. This data is not authority.
pub(crate) use crate::production_xmr_inventory_v23::NATIVE_XMR_INVENTORY_DESCRIPTOR_V23;
use crate::production_xmr_inventory_v23::{
    custody_ids as inventory_custody_ids_v23, DescriptorV23 as NativeInventoryDescriptorV23,
};

#[path = "production_xmr_native_inventory_fixture_compat_v24_tests.rs"]
mod inventory_fixture_compat_v24;

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
        || path.file_name().and_then(std::ffi::OsStr::to_str)
            != Some(NATIVE_XMR_INVENTORY_DESCRIPTOR_V23)
    {
        return Err("solver inventory descriptor file refused".into());
    }
    Ok(
        crate::production_xmr_inventory_v23::read_inventory_descriptor_v24(
            path.parent().ok_or("solver inventory descriptor parent")?,
        )?,
    )
}

fn inventory_fee_cap_v24(fees: [u64; 2]) -> Result<u64> {
    if fees.contains(&0) {
        return Err("solver inventory fee cap absent".into());
    }
    // The same inventory funds both legs; neither negotiated cap may grow.
    Ok(fees[0].min(fees[1]))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteEnvelopeV23 {
    schema: String,
    scope: String,
    legs: [Envelope; 2],
    solver_inventory: Envelope,
    #[serde(default)]
    funding_state_v23: Option<String>,
    #[serde(default)]
    source_outputs_v23: Option<[RouteSourceOutputV23; 3]>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteSourceOutputV23 {
    position: String,
    tx_hash: String,
    block_height: u64,
    global_output_index: u64,
    amount_piconero: u64,
    public_key: String,
    commitment: String,
}

fn check_route_sources_v23(
    state: Option<&str>,
    sources: Option<&[RouteSourceOutputV23; 3]>,
    mutable: bool,
    amounts: [u64; 3],
    candidates: [[u8; 32]; 3],
) -> Result<()> {
    if !mutable {
        if state.is_some() || sources.is_some() {
            return Err("immutable route unexpectedly exposes mutable funding state".into());
        }
        return Ok(());
    }
    if state != Some("unconfirmed-route-candidates-inventory-confirmed") {
        return Err("mutable route candidates must start unconfirmed".into());
    }
    let sources = sources.ok_or("mutable route source metadata missing")?;
    let mut identities = std::collections::BTreeSet::new();
    for (index, source) in sources.iter().enumerate() {
        let canonical = |text: &str| -> Result<[u8; 32]> {
            let bytes: [u8; 32] = hex::decode(text)?
                .try_into()
                .map_err(|_| "route source field length")?;
            if bytes == [0; 32] || hex::encode(bytes) != text {
                return Err("route source field is not canonical".into());
            }
            Ok(bytes)
        };
        let tx_hash = canonical(&source.tx_hash)?;
        canonical(&source.public_key)?;
        canonical(&source.commitment)?;
        if source.position != ["upstream", "downstream", "inventory"][index]
            || source.block_height != index as u64 + 1
            || source.global_output_index != index as u64 * 8
            || source.amount_piconero
                != amounts[index]
                    .checked_add(1_000_000_000)
                    .ok_or("route source amount overflow")?
            || candidates.contains(&tx_hash)
            || !identities.insert(tx_hash)
        {
            return Err("mutable route source scope or identity mismatch".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod source_metadata_tests_v23 {
    use super::*;

    fn sources() -> [RouteSourceOutputV23; 3] {
        std::array::from_fn(|index| RouteSourceOutputV23 {
            position: ["upstream", "downstream", "inventory"][index].into(),
            tx_hash: hex::encode([index as u8 + 4; 32]),
            block_height: index as u64 + 1,
            global_output_index: index as u64 * 8,
            amount_piconero: 1_000_000_010,
            public_key: hex::encode([7; 32]),
            commitment: hex::encode([8; 32]),
        })
    }

    #[test]
    fn route_source_metadata_cannot_preconfirm_or_alias_funding_candidates() {
        let state = Some("unconfirmed-route-candidates-inventory-confirmed");
        let candidates = [[1; 32], [2; 32], [3; 32]];
        assert!(
            check_route_sources_v23(state, Some(&sources()), true, [10; 3], candidates).is_ok()
        );
        assert!(check_route_sources_v23(None, None, false, [10; 3], candidates).is_ok());
        assert!(
            check_route_sources_v23(state, Some(&sources()), false, [10; 3], candidates).is_err()
        );
        assert!(
            check_route_sources_v23(None, Some(&sources()), true, [10; 3], candidates).is_err()
        );
        assert!(check_route_sources_v23(state, None, true, [10; 3], candidates).is_err());
        assert!(check_route_sources_v23(
            Some("confirmed"),
            Some(&sources()),
            true,
            [10; 3],
            candidates
        )
        .is_err());
        for mutation in 0..9 {
            let mut values = sources();
            match mutation {
                0 => values[0].tx_hash = hex::encode(candidates[0]),
                1 => values[1].tx_hash = values[0].tx_hash.clone(),
                2 => values[0].block_height = 100,
                3 => values[0].global_output_index = 1,
                4 => values[0].amount_piconero += 1,
                5 => values[0].position = "downstream".into(),
                6 => values[0].public_key = "AA".repeat(32),
                7 => values[0].commitment = "00".repeat(32),
                _ => values.swap(0, 1),
            }
            assert!(
                check_route_sources_v23(state, Some(&values), true, [10; 3], candidates).is_err()
            );
        }
    }
}

pub(crate) struct RouteFundingOwnerV23 {
    sidecars: [[PeerSidecarOwnerV23; 2]; 2],
    helper: ProcessOwner,
    control: Option<control_v23::RouteFixtureControlV23>,
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
                || owned.funding().output_index() != descriptor.output_index
                || owned.funding().amount_piconero() != descriptor.amount_piconero
                || owned.funding().fee_piconero() > descriptor.max_fee_piconero
                || descriptor.genesis
                    != crate::production_xmr_remote_sweep_v23::MONERO_MAINNET_GENESIS_V23
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
                descriptor.network_id,
                descriptor.route_id,
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
        let pending = self
            .pending_material
            .as_ref()
            .ok_or("solver inventory pending custody absent")?;
        // The index comes from the exact independently owned raw output, not
        // from a fixture default or a route funding candidate.
        let output_index = pending.expose(|spend, view| -> Result<u32> {
            Ok(xmr_raw_tx_verify::derive_owned_funding_key_image_v23(
                &self.raw,
                self.tx_hash,
                spend,
                view,
                self.amount_piconero,
                self.max_fee_piconero,
            )?
            .funding()
            .output_index())
        })?;
        let descriptor = NativeInventoryDescriptorV23 {
            network_id: network,
            route_id: route,
            sessions,
            terms,
            authority_id: self.authority_id,
            genesis: crate::production_xmr_remote_sweep_v23::MONERO_MAINNET_GENESIS_V23,
            tx_hash: self.tx_hash,
            spend_public: self.spend_public,
            amount_piconero: self.amount_piconero,
            max_fee_piconero: self.max_fee_piconero,
            output_index,
            destination: self.destination.clone(),
            raw: Zeroizing::new(self.raw.to_vec()),
        };
        let (record_id, binding) = inventory_custody_ids_v23(&descriptor)?;
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
        self.start_route_with_control_v23(
            spends,
            amounts,
            fees,
            work,
            auth,
            inventory_authority_id,
            false,
        )
    }

    pub(crate) fn start_mutable_mainnet_route_v23(
        &self,
        spends: [[u8; 32]; 2],
        amounts: [u64; 2],
        fees: [u64; 2],
        work: [&Path; 2],
        auth: &[[Zeroizing<[u8; 32]>; 2]; 2],
        inventory_authority_id: [u8; 32],
    ) -> Result<RouteFundingOwnerV23> {
        self.start_route_with_control_v23(
            spends,
            amounts,
            fees,
            work,
            auth,
            inventory_authority_id,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_route_with_control_v23(
        &self,
        spends: [[u8; 32]; 2],
        amounts: [u64; 2],
        fees: [u64; 2],
        work: [&Path; 2],
        auth: &[[Zeroizing<[u8; 32]>; 2]; 2],
        inventory_authority_id: [u8; 32],
        mutable: bool,
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
        let inventory_fee = inventory_fee_cap_v24(fees)?;
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
                "mutable_scenario_v23":mutable,
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
            let mut source = BufReader::new(stdout);
            let mut first = true;
            loop {
                let limit = if first { MAX_ENVELOPE * 3 } else { 65_536 };
                let mut bytes = Vec::new();
                let result = source
                    .by_ref()
                    .take((limit + 1) as u64)
                    .read_until(b'\n', &mut bytes)
                    .map_err(|_| "route helper reply read")
                    .and_then(|count| {
                        if count == 0 || count > limit || !bytes.ends_with(b"\n") {
                            Err("route helper reply framing")
                        } else {
                            Ok(bytes)
                        }
                    });
                let failed = result.is_err();
                if send.send(result).is_err() || failed || !mutable {
                    break;
                }
                first = false;
            }
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
        let mut control = if mutable {
            Some(control_v23::RouteFixtureControlV23::new(receive, reader))
        } else {
            reader.join().map_err(|_| "route envelope reader panic")?;
            None
        };
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
        check_route_sources_v23(
            value.funding_state_v23.as_deref(),
            value.source_outputs_v23.as_ref(),
            mutable,
            [amounts[0], amounts[1], inventory_amount],
            [hashes[0], hashes[1], inventory_hash],
        )?;
        if let Some(control) = &mut control {
            let status =
                control.status(helper.input.as_mut().ok_or("route helper input absent")?)?;
            if status.tip_height != 200
                || !status.pool_tx_hashes.is_empty()
                || status.transactions.len() != 1
                || status.transactions[0].tx_hash != inventory_hash
                || status.transactions[0].block_height != 102
            {
                return Err(
                    "mutable route must retain only inventory, with both route candidates absent"
                        .into(),
                );
            }
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
            control,
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
    pub(crate) fn with_stopped_sidecar_v24<T>(
        &mut self,
        position: usize,
        actor: usize,
        operation: impl FnOnce(&Path) -> Result<T>,
    ) -> Result<T> {
        self.require_alive()?;
        let result = self
            .sidecars
            .get_mut(position)
            .and_then(|actors| actors.get_mut(actor))
            .ok_or("route sidecar index")?
            .with_stopped_v24(operation);
        match result {
            Ok(value) => {
                self.require_alive()?;
                Ok(value)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn history_status_v23(&mut self) -> Result<NativeXmrHistoryStatusV23> {
        self.require_alive()?;
        self.control
            .as_mut()
            .ok_or("immutable XMR history has no control channel")?
            .status(
                self.helper
                    .input
                    .as_mut()
                    .ok_or("route helper input absent")?,
            )
    }

    pub(crate) fn advance_history_v23(
        &mut self,
        height: u64,
        timestamp: u64,
        include: &[[u8; 32]],
    ) -> Result<NativeXmrHistoryStatusV23> {
        self.require_alive()?;
        self.control
            .as_mut()
            .ok_or("immutable XMR history cannot advance")?
            .advance(
                self.helper
                    .input
                    .as_mut()
                    .ok_or("route helper input absent")?,
                height,
                timestamp,
                include,
            )
    }

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
