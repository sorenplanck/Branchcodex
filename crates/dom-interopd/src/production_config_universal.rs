//! V11 separates the common DOM/Relay bootstrap from two external resource sets.
//! It reuses the byte-frozen V6 common graph, never V7's mandatory Bitcoin owner.
use super::*;
use serde::{Deserialize, Serialize};

/// Universal provisioning manifest, independent of the V10 EVM+BTC family.
pub const PRODUCTION_CREATE_CONFIG_FILE_V11: &str = "bootstrap-create-v11.conf";
/// Universal recovery manifest. Recovery never substitutes the create document.
pub const PRODUCTION_REOPEN_CONFIG_FILE_V11: &str = "bootstrap-reopen-v11.conf";
pub(super) const HEADER_V11: &str = "DOM-INTEROPD-BOOTSTRAP-V11";
pub(super) const MAX_BYTES_V11: u64 = 64 * 1024;
const MAX_LEG_BUNDLE_BYTES: u64 = 1024 * 1024;

/// Family of one external position. DOM is the shared center, not a variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductionChainFamilyV11 {
    /// Bitcoin node, participant and prebroadcast owner.
    Btc,
    /// EVM node, signer and actuator owner.
    Evm,
    /// Solana pool, signers and escrow owner.
    Sol,
    /// Monero observer, sidecar and encrypted share owners.
    Xmr,
}

/// Public references for exactly one independently provisioned external leg.
/// The bundle contains the family's native public authority inputs; its digest
/// authenticates bytes, not chain facts or the signer's ability to execute.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionUniversalLegV11 {
    /// Family required for this position alone.
    pub family: ProductionChainFamilyV11,
    /// Exact settlement bound by this position.
    pub settlement_id: [u8; 32],
    /// Exact signing session bound by this position.
    pub session_id: [u8; 32],
    /// External network selected by the authenticated registry.
    pub chain_id: [u8; 32],
    /// This leg's own durable actuator database, even for a same-family pair.
    pub actuator_store: String,
    /// Existing public family-specific authority bundle, relative to state_dir.
    pub authority_bundle: String,
    /// Domain-separated digest of that exact bounded bundle.
    pub authority_bundle_digest: [u8; 32],
}

/// The universal additions to a V6 common DOM/Relay graph. No BTC or EVM
/// credential, deployment, policy or prebroadcast field is mandatory here.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionUniversalBootstrapFieldsV11 {
    /// The seven ordered F6 V8 references.
    pub f6_paths: [String; PRODUCTION_F6_PATH_ROLE_COUNT_V8],
    /// The signed F6 bundle commitment, verified again by its concrete owner.
    pub f6_authority_bundle_digest: [u8; 32],
    /// Static generation of the refund-arming authority.
    pub refund_arming_authority_epoch: u64,
    /// Upstream and downstream remote Relay database identities.
    pub remote_relay_database_ids: [[u8; 32]; 2],
    /// Upstream and downstream resources, in that exact order.
    pub legs: [ProductionUniversalLegV11; 2],
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct ProductionUniversalBootstrapV11 {
    pub(super) common: ProductionBootstrapConfigV1,
    pub(super) fields: ProductionUniversalBootstrapFieldsV11,
    pub(super) f6_paths: ProductionF6PathReferencesV8,
    common_hex: [String; 2],
    fields_hex: String,
}

impl ProductionBootstrapConfigV1 {
    /// Authenticated remote Relay database identities without requiring an
    /// unrelated EVM fee policy. Position order is upstream, downstream.
    pub fn remote_relay_database_ids(&self) -> Option<[[u8; 32]; 2]> {
        if let Some(fields) = self.universal_v11() {
            return Some(fields.remote_relay_database_ids);
        }
        self.operational_policies_v10().map(|policy| {
            [
                policy.upstream_remote_relay_database_id(),
                policy.downstream_remote_relay_database_id(),
            ]
        })
    }

    /// Build a V11 bootstrap from the complete common V6 graph and the two
    /// independent resource descriptions. V7--V10 inputs are rejected: their
    /// mandatory single Bitcoin owner must not leak into this family.
    pub fn from_common_v6_and_legs_v11(
        common: ProductionBootstrapConfigV1,
        fields: ProductionUniversalBootstrapFieldsV11,
    ) -> Result<Self, ProductionConfigErrorV1> {
        if common.family() != ProductionBootstrapFamilyV1::V6 {
            return Err(ProductionConfigErrorV1::InvalidPublicBinding);
        }
        let common_pins = common.pins();
        let [upstream, downstream] = &fields.legs;
        if fields.f6_authority_bundle_digest == ZERO_DIGEST
            || fields.refund_arming_authority_epoch == 0
            || fields.remote_relay_database_ids.contains(&ZERO_DIGEST)
            || fields.remote_relay_database_ids[0] == fields.remote_relay_database_ids[1]
            || upstream.settlement_id == downstream.settlement_id
            || upstream.session_id == downstream.session_id
        {
            return Err(ProductionConfigErrorV1::InvalidPublicBinding);
        }
        let relay = common
            .relay_authority_pins_v6()
            .ok_or(ProductionConfigErrorV1::InvalidPublicBinding)?;
        let contracts = common
            .contracts_bootstrap_pins_v5()
            .ok_or(ProductionConfigErrorV1::InvalidPublicBinding)?;
        for id in fields.remote_relay_database_ids {
            if route_pin_digests(common_pins).contains(&id)
                || relay.authority_ids().contains(&id)
                || [
                    contracts.commit_stage_digest(),
                    contracts.reveal_stage_digest(),
                    fields.f6_authority_bundle_digest,
                ]
                .contains(&id)
            {
                return Err(ProductionConfigErrorV1::InvalidPublicBinding);
            }
        }
        // Preserve path isolation across both positions and the common graph.
        let mut paths = common.paths.paths.to_vec();
        for path in [
            common.contracts_transport_identity_store(),
            common.contracts_budget_policy(),
            common.contracts_bootstrap(),
        ] {
            paths.push(
                path.ok_or(ProductionConfigErrorV1::InvalidPathReference)?
                    .to_str()
                    .ok_or(ProductionConfigErrorV1::InvalidPathReference)?
                    .to_owned(),
            );
        }
        paths.extend_from_slice(
            &common
                .f6_paths_v4()
                .ok_or(ProductionConfigErrorV1::InvalidPathReference)?
                .paths,
        );
        paths.extend_from_slice(&fields.f6_paths);
        for leg in &fields.legs {
            if [
                leg.settlement_id,
                leg.session_id,
                leg.chain_id,
                leg.authority_bundle_digest,
            ]
            .contains(&ZERO_DIGEST)
                || leg.settlement_id == leg.session_id
            {
                return Err(ProductionConfigErrorV1::InvalidPublicBinding);
            }
            paths.push(leg.actuator_store.clone());
            paths.push(leg.authority_bundle.clone());
        }
        validate_path_set(&paths)?;
        let f6_paths = ProductionF6PathReferencesV8::from_ordered(fields.f6_paths.clone())?;
        let fields_hex = hex_bytes(
            &serde_json::to_vec(&fields)
                .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)?,
        );
        let mut create_common = common.clone();
        create_common.mode = ProductionBootstrapModeV1::Create;
        let mut reopen_common = common.clone();
        reopen_common.mode = ProductionBootstrapModeV1::ReopenExisting;
        let common_hex = [
            hex_bytes(&create_common.canonical_bytes()?),
            hex_bytes(&reopen_common.canonical_bytes()?),
        ];
        let result = Self {
            mode: common.mode,
            pins: common.pins,
            bounds: common.bounds,
            paths: common.paths.clone(),
            extras: ProductionFamilyExtrasV1::V11(Box::new(ProductionUniversalBootstrapV11 {
                common,
                fields,
                f6_paths,
                common_hex,
                fields_hex,
            })),
        };
        // Refuse oversized envelopes at construction as well as decoding.
        let _ = result.canonical_bytes()?;
        Ok(result)
    }

    /// Strict V11 decoder; old manifest families are never inferred or accepted.
    pub fn decode_canonical_v11_for_mode(
        bytes: &[u8],
        mode: ProductionBootstrapModeV1,
    ) -> Result<Self, ProductionConfigErrorV1> {
        decode(bytes, mode)
    }

    /// Universal resources, or None for the byte-frozen legacy families.
    pub const fn universal_v11(&self) -> Option<&ProductionUniversalBootstrapFieldsV11> {
        match &self.extras {
            ProductionFamilyExtrasV1::V11(value) => Some(&value.fields),
            _ => None,
        }
    }
}

impl ProductionUniversalBootstrapV11 {
    pub(super) fn canonical_body(&self, mode: ProductionBootstrapModeV1) -> String {
        let mut body = String::new();
        body.push_str(HEADER_V11);
        body.push('\n');
        push_reference(&mut body, "mode", mode.as_str());
        let index = match mode {
            ProductionBootstrapModeV1::Create => 0,
            ProductionBootstrapModeV1::ReopenExisting => 1,
        };
        push_reference(&mut body, "common_v6", &self.common_hex[index]);
        push_reference(&mut body, "universal", &self.fields_hex);
        body
    }

    pub(super) fn encode(
        &self,
        mode: ProductionBootstrapModeV1,
    ) -> Result<Vec<u8>, ProductionConfigErrorV1> {
        let mut body = self.canonical_body(mode);
        let digest = config_digest(body.as_bytes())?;
        push_reference(&mut body, "config_digest", &encode_hex(&digest));
        body.push_str(END_V1);
        body.push('\n');
        if body.len() as u64 > MAX_BYTES_V11 {
            return Err(ProductionConfigErrorV1::OversizeConfig);
        }
        Ok(body.into_bytes())
    }
}

pub(super) fn decode(
    bytes: &[u8],
    expected_mode: ProductionBootstrapModeV1,
) -> Result<ProductionBootstrapConfigV1, ProductionConfigErrorV1> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_BYTES_V11 {
        return Err(ProductionConfigErrorV1::OversizeConfig);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
    if !text.ends_with('\n') {
        return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
    }
    let lines: Vec<_> = text[..text.len() - 1].split('\n').collect();
    if lines.len() != 6 || lines[0] != HEADER_V11 || lines[5] != END_V1 {
        return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
    }
    let mut cursor = 1;
    let mode = ProductionBootstrapModeV1::parse(take_value(&lines, &mut cursor, "mode")?)?;
    if mode != expected_mode {
        return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
    }
    let base = unhex(take_value(&lines, &mut cursor, "common_v6")?)?;
    let fields = unhex(take_value(&lines, &mut cursor, "universal")?)?;
    let _supplied_digest = take_digest(&lines, &mut cursor, "config_digest")?;
    let common = ProductionBootstrapConfigV1::decode_canonical_v6_for_mode(&base, mode)?;
    let fields = serde_json::from_slice(&fields)
        .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
    let config = ProductionBootstrapConfigV1::from_common_v6_and_legs_v11(common, fields)?;
    if config.canonical_bytes()?.as_slice() != bytes {
        return Err(ProductionConfigErrorV1::IntegrityMismatch);
    }
    Ok(config)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 15) as usize] as char);
    }
    result
}
fn unhex(value: &str) -> Result<Vec<u8>, ProductionConfigErrorV1> {
    if value.is_empty() || value.len() % 2 != 0 {
        return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

impl ProductionUniversalLegV11 {
    /// Domain-separated public bundle digest used by preparation and reopening.
    pub fn bundle_digest(bytes: &[u8]) -> Result<[u8; 32], ProductionConfigErrorV1> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_LEG_BUNDLE_BYTES {
            return Err(ProductionConfigErrorV1::InvalidPublicBinding);
        }
        let mut hasher =
            Blake2bVar::new(32).map_err(|_| ProductionConfigErrorV1::InvalidPublicBinding)?;
        hasher.update(b"DOM-INTEROPD/UNIVERSAL-LEG-BUNDLE/V11\0");
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        let mut digest = [0; 32];
        hasher
            .finalize_variable(&mut digest)
            .map_err(|_| ProductionConfigErrorV1::InvalidPublicBinding)?;
        Ok(digest)
    }

    /// Load and authenticate the exact owner-only public authority bundle.
    /// The caller must then use the selected family's semantic decoder.
    pub fn read_bundle(
        &self,
        layout: &ValidatedProductionLayoutV1,
    ) -> Result<Vec<u8>, ProductionConfigErrorV1> {
        validate_relative_path(&self.authority_bundle)?;
        let path = layout.state_dir().join(&self.authority_bundle);
        validate_parent_chain(layout.state_dir(), &path)?;
        let bytes = read_owner_file_bounded(
            &path,
            MAX_LEG_BUNDLE_BYTES,
            ProductionConfigErrorV1::InputArtifactUnavailable,
        )?;
        if Self::bundle_digest(&bytes)? != self.authority_bundle_digest {
            return Err(ProductionConfigErrorV1::IntegrityMismatch);
        }
        Ok(bytes)
    }
}

/// Load the universal companions and common layout. Only the selected two
/// external stores are required. This function opens no node, signer or wallet.
/// Create refuses existing actuator files; restart requires those exact files.
pub fn load_production_bootstrap_v11(
    state_dir: &Path,
    mode: ProductionBootstrapModeV1,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &state,
        PRODUCTION_CREATE_CONFIG_FILE_V11,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V11,
    )?;
    let reopen = load_manifest(
        &state,
        PRODUCTION_REOPEN_CONFIG_FILE_V11,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V11,
    )?;
    if !create.equivalent_except_mode(&reopen) {
        return Err(ProductionConfigErrorV1::CompanionMismatch);
    }
    let config = match mode {
        ProductionBootstrapModeV1::Create => create,
        ProductionBootstrapModeV1::ReopenExisting => reopen,
    };
    let creating = mode == ProductionBootstrapModeV1::Create;
    let layout = resolve_and_validate_layout(&state, &config, creating)?;
    let fields = config
        .universal_v11()
        .ok_or(ProductionConfigErrorV1::InvalidPublicBinding)?;
    for leg in &fields.legs {
        let path = state.join(&leg.actuator_store);
        validate_parent_chain(&state, &path)?;
        if creating {
            require_managed_file_absent(&path)?;
        } else {
            validate_owner_file(&path, ProductionConfigErrorV1::RecoveryStateUnavailable)?;
        }
        let _ = leg.read_bundle(&layout)?;
    }
    Ok(ValidatedProductionBootstrapV1 { config, layout })
}

impl ProductionUniversalBootstrapFieldsV11 {
    /// Exact public resources for one external route position.
    pub const fn leg(&self, leg: LegIdV1) -> &ProductionUniversalLegV11 {
        &self.legs[match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        }]
    }

    /// Required credential/client families in their authenticated order.
    pub const fn families(&self) -> [ProductionChainFamilyV11; 2] {
        [self.legs[0].family, self.legs[1].family]
    }
}

impl ValidatedProductionBootstrapV1 {
    /// Cross-check every selected resource against registry-authenticated
    /// admission before consuming credentials or opening clients/signers.
    /// Public configuration cannot select another family, session or network.
    #[cfg(feature = "production")]
    pub(crate) fn require_universal_admission_v11(
        &self,
        inputs: &crate::production_inputs::AuthenticatedProductionInputsV1,
    ) -> Result<[ProductionChainFamilyV11; 2], ProductionConfigErrorV1> {
        use settlement_coordinator::SettlementFaceV1;
        let fields = self
            .config
            .universal_v11()
            .ok_or(ProductionConfigErrorV1::InvalidPublicBinding)?;
        let topology =
            crate::production_route_topology::ProductionRouteTopologyV4::authenticate(inputs)
                .map_err(|_| ProductionConfigErrorV1::InvalidPublicBinding)?;
        if topology.route_id != self.config.pins().route_id
            || topology.registry_digest != self.config.pins().registry_manifest_digest
        {
            return Err(ProductionConfigErrorV1::InvalidPublicBinding);
        }
        for (index, leg) in [LegIdV1::Upstream, LegIdV1::Downstream]
            .into_iter()
            .enumerate()
        {
            let resources = fields.leg(leg);
            let admitted = topology.legs[index];
            let terms = match leg {
                LegIdV1::Upstream => inputs.composition().upstream(),
                LegIdV1::Downstream => inputs.composition().downstream(),
            };
            let family = match admitted.face {
                SettlementFaceV1::Bitcoin => ProductionChainFamilyV11::Btc,
                SettlementFaceV1::Evm => ProductionChainFamilyV11::Evm,
                SettlementFaceV1::Solana => ProductionChainFamilyV11::Sol,
                SettlementFaceV1::Monero => ProductionChainFamilyV11::Xmr,
                SettlementFaceV1::Dom => return Err(ProductionConfigErrorV1::InvalidPublicBinding),
            };
            if resources.family != family
                || resources.chain_id != admitted.chain_id
                || resources.settlement_id != admitted.settlement_id
                || resources.session_id != terms.session_id.0
            {
                return Err(ProductionConfigErrorV1::InvalidPublicBinding);
            }
        }
        Ok(fields.families())
    }

    /// Exact selected actuator path; no legacy BTC/EVM leaf is substituted.
    /// The loader already checked its parent chain and lifecycle state.
    pub fn universal_actuator_path_v11(
        &self,
        leg: LegIdV1,
    ) -> Result<PathBuf, ProductionConfigErrorV1> {
        let fields = self
            .config
            .universal_v11()
            .ok_or(ProductionConfigErrorV1::InvalidPublicBinding)?;
        Ok(self
            .layout
            .state_dir()
            .join(&fields.leg(leg).actuator_store))
    }
}

/// V11 binds the historical journal's two external slots to route positions.
/// The numeric journal format remains unchanged, but its full binding commits
/// to the V11 manifests, including each position's actual family and path.
/// These labels do not authorize opening an EVM or Bitcoin resource.
#[cfg(feature = "production")]
pub(crate) const fn universal_actuator_stage_v11(leg: LegIdV1) -> ProductionProvisioningStageV1 {
    match leg {
        LegIdV1::Upstream => ProductionProvisioningStageV1::EvmActuatorStore,
        LegIdV1::Downstream => ProductionProvisioningStageV1::BitcoinActuatorStore,
    }
}

#[cfg(feature = "production")]
fn companions(
    state: &Path,
) -> Result<(ProductionBootstrapConfigV1, ProductionBootstrapConfigV1), ProductionConfigErrorV1> {
    let create = load_manifest(
        state,
        PRODUCTION_CREATE_CONFIG_FILE_V11,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V11,
    )?;
    let reopen = load_manifest(
        state,
        PRODUCTION_REOPEN_CONFIG_FILE_V11,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V11,
    )?;
    if !create.equivalent_except_mode(&reopen) {
        return Err(ProductionConfigErrorV1::CompanionMismatch);
    }
    Ok((create, reopen))
}

/// Reconstruct the exact pair-bound journal identity. The currently loaded
/// mode is compared as well, so rewriting both manifests after admission is
/// refused instead of silently changing the process's provisioning authority.
#[cfg(feature = "production")]
pub(crate) fn provisioning_binding_for_v11_bootstrap(
    bootstrap: &ValidatedProductionBootstrapV1,
) -> Result<[u8; 32], ProductionConfigErrorV1> {
    if bootstrap.config.family() != ProductionBootstrapFamilyV1::V11 {
        return Err(ProductionConfigErrorV1::ProvisioningJournalRefused);
    }
    let (create, reopen) = companions(bootstrap.layout.state_dir())?;
    let selected = match bootstrap.config.mode() {
        ProductionBootstrapModeV1::Create => &create,
        ProductionBootstrapModeV1::ReopenExisting => &reopen,
    };
    if selected != &bootstrap.config {
        return Err(ProductionConfigErrorV1::IntegrityMismatch);
    }
    provisioning_binding_for_configs(&create, &reopen)
}

/// Resume only a journal-authenticated creation prefix. Every external store
/// is checked against its own position's durable stage. A missing complete
/// store, an unstarted pre-existing store, or another route's journal refuses.
#[cfg(feature = "production")]
pub(crate) fn load_production_create_or_resume_bootstrap_v11(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let state = validate_state_dir(state_dir)?;
    let (create, reopen) = companions(&state)?;
    let binding = provisioning_binding_for_configs(&create, &reopen)?;
    let layout = match DurableProductionProvisioningJournalV1::open(&state, binding) {
        Ok(journal) => {
            let layout = resolve_and_validate_layout_for_provisioning(&state, &create, &journal)?;
            let fields = create
                .universal_v11()
                .ok_or(ProductionConfigErrorV1::InvalidPublicBinding)?;
            for leg in [LegIdV1::Upstream, LegIdV1::Downstream] {
                let resources = fields.leg(leg);
                let path = state.join(&resources.actuator_store);
                validate_parent_chain(&state, &path)?;
                let stage = journal
                    .stage_state(universal_actuator_stage_v11(leg))
                    .map_err(|_| ProductionConfigErrorV1::ProvisioningJournalRefused)?;
                validate_managed_path_for_provisioning(
                    &path,
                    ProductionPathKindV1::ManagedFile,
                    stage,
                )?;
                let _ = resources.read_bundle(&layout)?;
            }
            layout
        }
        Err(ProductionProvisioningErrorV1::NotFound) => {
            let bootstrap =
                load_production_bootstrap_v11(&state, ProductionBootstrapModeV1::Create)?;
            // A second manifest read cannot replace the already-bound pair.
            if bootstrap.config != create {
                return Err(ProductionConfigErrorV1::IntegrityMismatch);
            }
            require_absent(
                &state.join(ROUTE_SECRET_VAULT_ROOT_NAME_V1),
                ProductionConfigErrorV1::StateAlreadyPresent,
            )?;
            bootstrap.layout
        }
        Err(_) => return Err(ProductionConfigErrorV1::ProvisioningJournalRefused),
    };
    Ok(ValidatedProductionBootstrapV1 {
        config: create,
        layout,
    })
}
