//! Breaks the manifest/admission cycle without constructing an admission token.
//! A planning context produces public artifacts; the actual production loader
//! then authenticates them and journals its own native creation prefix.
use super::*;
use crate::production_config::{
    load_production_create_or_resume_bootstrap_v11, production_f6_authority_bundle_digest_v8,
    provisioning_binding_for_v11_bootstrap, ProductionBootstrapConfigV1, ProductionBootstrapModeV1,
    ProductionUniversalBootstrapFieldsV11, ProductionUniversalLegV11,
    PRODUCTION_CREATE_CONFIG_FILE_V11, PRODUCTION_REOPEN_CONFIG_FILE_V11,
};
use crate::production_f6_factory::{
    native_daemon_export_v23::ExportedNativeDaemonV23, AuthenticatedProductionF6AuthorityBundleV7,
};
use zeroize::Zeroizing;

impl NativeDaemonPlanningContextV23 {
    pub(crate) fn export_first(
        self,
        common: [ProductionBootstrapConfigV1; 2],
        mut fields: ProductionUniversalBootstrapFieldsV11,
        f6_bundle: &[u8],
        leg_bundles: [&[u8]; 2],
        stdin_v4: Zeroizing<Vec<u8>>,
        now_seconds: u64,
    ) -> Result<ExportedNativeDaemonV23> {
        // XMR-planned contexts still select exactly [Xmr; 2] here.
        let families = self.families_v25();
        crate::production_node::ProductionSecretsV4::read(stdin_v4.as_slice())?
            .into_parts(families)?;
        let [create, reopen] = common;
        if create.mode() != ProductionBootstrapModeV1::Create
            || reopen.mode() != ProductionBootstrapModeV1::ReopenExisting
            || now_seconds < self.composition.time_proof_validated_at_seconds()
        {
            return Err("native first-export mode or clock".into());
        }
        for config in [&create, &reopen] {
            let pins = config.pins();
            if pins.network_id != self.rosters.network_id()
                || pins.route_id != self.admission.route_id()
                || pins.registry_manifest_digest != self.registry.manifest_digest()
                || pins.registry_minimum_epoch > self.registry.epoch()
                || pins.registry_authority_set_digest
                    != self.authorities.registry.authority_set_digest()?
                || pins.time_policy_authority_set_digest != self.policy_authority_digest
                || pins.time_evidence_authority_set_digest != self.evidence_authority_digest
                || pins.upstream_terms_digest != self.composition.upstream().terms_hash()?
                || pins.downstream_terms_digest != self.composition.downstream().terms_hash()?
                || pins.route_scope_digest != self.composition.route_scope_digest()
                || pins.participant_bindings_digest != self.participants.bundle_digest()?
                || pins.relay_binding_digest != self.rosters.bundle_digest()?
            {
                return Err("native first-export changed authenticated pins".into());
            }
            let stages = config
                .contracts_bootstrap_pins_v5()
                .ok_or("native first-export contracts pins")?;
            validate_contracts_bootstrap_stage_pins_v5(
                *self.contracts.commit_stage_digest(),
                *self.contracts.reveal_stage_digest(),
                stages,
            )?;
        }
        fields.f6_authority_bundle_digest = production_f6_authority_bundle_digest_v8(f6_bundle)?;
        for (index, terms) in [self.composition.upstream(), self.composition.downstream()]
            .into_iter()
            .enumerate()
        {
            fields.legs[index] = ProductionUniversalLegV11 {
                family: families[index],
                settlement_id: terms.settlement_id.0,
                session_id: terms.session_id.0,
                chain_id: terms.counterparty_leg.chain_id.0,
                authority_bundle_digest: ProductionUniversalLegV11::bundle_digest(
                    leg_bundles[index],
                )?,
                ..fields.legs[index].clone()
            };
        }
        let create =
            ProductionBootstrapConfigV1::from_common_v6_and_legs_v11(create, fields.clone())?;
        let reopen =
            ProductionBootstrapConfigV1::from_common_v6_and_legs_v11(reopen, fields.clone())?;
        let create_bytes = create.canonical_bytes()?;
        let reopen_bytes = reopen.canonical_bytes()?;
        for (leg, bytes) in fields.legs.iter().zip(leg_bundles) {
            publish(&self.root, &leg.authority_bundle, bytes)?;
        }
        publish(&self.root, &fields.f6_paths[6], f6_bundle)?;
        publish(&self.root, PRODUCTION_CREATE_CONFIG_FILE_V11, &create_bytes)?;
        publish(&self.root, PRODUCTION_REOPEN_CONFIG_FILE_V11, &reopen_bytes)?;

        // Creation is not faked or pre-completed. Native journals own every
        // loader mutation and the daemon resumes this exact prefix via --create.
        // Failures preserve the private fixture for diagnosis, never fallback.
        let bootstrap = load_production_create_or_resume_bootstrap_v11(&self.root)?;
        let binding = provisioning_binding_for_v11_bootstrap(&bootstrap)?;
        let mut journal =
            DurableProductionProvisioningJournalV1::open_or_create_after_absence_check(
                &self.root, binding,
            )?;
        let authenticated = load_authenticated_production_inputs_with_provisioning_v1(
            &bootstrap,
            now_seconds,
            &mut journal,
        )?;
        bootstrap.require_universal_admission_v11(&authenticated)?;
        if authenticated.composition().binding_digest() != self.composition.binding_digest()
            || authenticated.admission().frozen_bindings() != self.admission.frozen_bindings()
        {
            return Err("native first-export recomposed another route".into());
        }
        AuthenticatedProductionF6AuthorityBundleV7::decode_and_authenticate(
            f6_bundle,
            &authenticated,
        )?;
        for (index, leg) in [LegIdV1::Upstream, LegIdV1::Downstream]
            .into_iter()
            .enumerate()
        {
            crate::production_universal_leg_authority::ProductionUniversalLegAuthorityV11::decode(
                leg_bundles[index],
                &fields.legs[index],
                &authenticated,
                leg,
            )?;
        }
        drop(authenticated);
        drop(journal);
        use blake2::digest::Update as _;
        use blake2::digest::VariableOutput as _;
        let mut hash = blake2::Blake2bVar::new(32)?;
        hash.update(b"DOM-INTEROP/TEST/DAEMON-EXPORT/V23\0");
        hash.update(&create_bytes);
        hash.update(&reopen_bytes);
        let mut config_digest = [0; 32];
        hash.finalize_variable(&mut config_digest)?;
        Ok(ExportedNativeDaemonV23 {
            state_dir: self.root,
            stdin_v4,
            route_id: self.admission.route_id(),
            config_digest,
        })
    }
}
