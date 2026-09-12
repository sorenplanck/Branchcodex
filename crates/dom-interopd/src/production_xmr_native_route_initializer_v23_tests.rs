//! Two real XMR sessions for the new daemon scenario, before C/D signing.
//! One route T is borrowed by both initializations. Each position has its own
//! U, payout wallet, encrypted database keys, directories and nullifier store.
//! No private key is recovered from public bytes or an existing database.
use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[path = "production_xmr_native_enrollment_fixture_v23.rs"]
mod enrollment_v23;
pub(crate) use enrollment_v23::{NativeXmrEnrolledFixtureV23, NativeXmrEnrollmentPlanV23};

pub(crate) struct NativeXmrRouteSecretsV23 {
    claim: CrossCurveSecret252,
    refunds: [CrossCurveSecret252; 2],
    profile: XmrAdapterProfileV1,
    fee_cap: u64,
    payouts: [NativeClaimPayoutV23; 2],
    master_keys: [[Zeroizing<[u8; 32]>; 2]; 2],
}

pub(crate) struct NativeXmrPlannedLegV23 {
    pub refund_template_hash: [u8; 32],
    /// Hash derived from that position's actual offline funding bytes; this
    /// is a setup identity, not proof that funding was accepted or confirmed.
    pub funding_tx_hash: [u8; 32],
    pub funding_destination: String,
}

impl NativeXmrRouteSecretsV23 {
    pub(crate) fn new(
        profile: XmrAdapterProfileV1,
        fee_cap: u64,
        master_keys: [[Zeroizing<[u8; 32]>; 2]; 2],
    ) -> Result<Self> {
        if !matches!(
            profile.network,
            xmr_setup_profile::XmrNetwork::Mainnet | xmr_setup_profile::XmrNetwork::Stagenet
        ) || fee_cap == 0
            || fee_cap > 1_000_000
        {
            return Err("native route initializer profile or fee cap".into());
        }
        let keys: Vec<_> = master_keys.iter().flat_map(|pair| pair.iter()).collect();
        for (index, key) in keys.iter().enumerate() {
            if key.as_slice().iter().all(|byte| *byte == 0)
                || keys[..index]
                    .iter()
                    .any(|other| other.as_slice() == key.as_slice())
            {
                return Err("native route database keys must be independent".into());
            }
        }
        let mut rng = rand::thread_rng();
        let claim = CrossCurveSecret252::generate(&mut rng);
        let refunds = std::array::from_fn(|_| CrossCurveSecret252::generate(&mut rng));
        let claims = [
            claim.public_claim()?,
            refunds[0].public_claim()?,
            refunds[1].public_claim()?,
        ];
        if claims[0] == claims[1] || claims[0] == claims[2] || claims[1] == claims[2] {
            return Err("native route independent U generation".into());
        }
        Ok(Self {
            claim,
            refunds,
            profile,
            fee_cap,
            master_keys,
            payouts: [
                NativeClaimPayoutV23::new_for_network_v23(fee_cap, 0, profile.network)?,
                NativeClaimPayoutV23::new_for_network_v23(fee_cap, 1, profile.network)?,
            ],
        })
    }

    pub(crate) fn configure_registry(
        &self,
        manifest: &mut deployment_registry::RegistryManifestV1,
        mut terms: [&mut SettlementTermsV1; 2],
    ) -> Result<()> {
        for terms in &mut terms {
            terms.counterparty_leg.amount = 1_000_000_000;
            terms.fee_limit.counterparty_max = u128::from(self.fee_cap);
        }
        let [upstream, downstream] = terms;
        registry_v23::configure_network(
            manifest,
            [&mut *upstream, &mut *downstream],
            self.profile.network,
        )?;
        self.configure_terms(0, upstream)?;
        self.configure_terms(1, downstream)?;
        for chain in &mut manifest.chains {
            if let deployment_registry::ChainDeploymentV1::Monero(deployment) =
                &mut chain.deployment
            {
                deployment.max_fee_piconero = self.fee_cap;
            }
        }
        manifest.validate()?;
        Ok(())
    }

    pub(crate) fn configure_terms(
        &self,
        position: usize,
        terms: &mut SettlementTermsV1,
    ) -> Result<()> {
        self.refunds.get(position).ok_or("native route position")?;
        terms.adaptor_point_sec1 = self.claim.public_claim()?.secp_compressed;
        terms.counterparty_leg.amount = 1_000_000_000;
        terms.fee_limit.counterparty_max = u128::from(self.fee_cap);
        terms.counterparty_leg.adapter_profile_hash = self.profile.profile_hash();
        terms.validate()?;
        Ok(())
    }

    pub(crate) fn refund_point(&self, position: usize) -> Result<[u8; 33]> {
        Ok(self
            .refunds
            .get(position)
            .ok_or("native route position")?
            .public_claim()?
            .secp_compressed)
    }

    pub(crate) fn combined_spend_public_key(&self, position: usize) -> Result<[u8; 32]> {
        Ok(xmr_crypto::combine_public_shares(
            self.claim.public_claim()?.ed_compressed,
            self.refunds
                .get(position)
                .ok_or("native route position")?
                .public_claim()?
                .ed_compressed,
        )?)
    }

    /// All four private roots must already be provisioned owner-only and
    /// disjoint. Existing session databases are never reopened as creation.
    pub(crate) fn initialize(
        self,
        terms: [&SettlementTermsV1; 2],
        planned: [NativeXmrPlannedLegV23; 2],
        actors: [[[u8; 32]; 2]; 2],
        roots: [[&Path; 2]; 2],
    ) -> Result<[NativeXmrCustodyFixtureV23; 2]> {
        if terms[0].session_id == terms[1].session_id
            || terms[0].settlement_id == terms[1].settlement_id
            || planned[0].funding_tx_hash == planned[1].funding_tx_hash
        {
            return Err("native route position scope collision".into());
        }
        for (index, terms) in terms.iter().enumerate() {
            terms.validate()?;
            if terms.adaptor_point_sec1 != self.claim.public_claim()?.secp_compressed
                || terms.counterparty_leg.adapter_profile_hash != self.profile.profile_hash()
                || planned[index].refund_template_hash == [0; 32]
                || planned[index].funding_tx_hash == [0; 32]
                || planned[index].funding_destination.is_empty()
            {
                return Err("native route public initialization scope".into());
            }
        }
        let flat: Vec<_> = roots.iter().flat_map(|pair| pair.iter()).copied().collect();
        for (index, path) in flat.iter().enumerate() {
            let metadata = std::fs::symlink_metadata(path)?;
            if !path.is_absolute()
                || std::fs::canonicalize(path)?.as_path() != *path
                || !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != rustix::process::getuid().as_raw()
                || metadata.permissions().mode() & 0o077 != 0
                || flat[..index]
                    .iter()
                    .any(|other| path.starts_with(other) || other.starts_with(path))
            {
                return Err("native route private roots are not independent".into());
            }
            if std::fs::read_dir(path)?.next().is_some() {
                return Err(
                    "native route refuses nonempty initializer roots, including SQLite sidecars"
                        .into(),
                );
            }
            for name in [
                "native-xmr-secrets-v23.sqlite",
                "native-xmr-nullifiers-v23.sqlite",
            ] {
                match std::fs::symlink_metadata(path.join(name)) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => {
                        return Err(
                            "native route refuses existing database or missing metadata".into()
                        )
                    }
                }
            }
        }
        for (index, terms) in terms.iter().enumerate() {
            if actors[index][0] == actors[index][1]
                || actors[index].iter().any(|actor| {
                    ![
                        terms.dom_leg.refund_to.0,
                        terms.counterparty_leg.refund_to.0,
                    ]
                    .contains(actor)
                })
            {
                return Err("native route actor role binding".into());
            }
        }
        let Self {
            claim,
            refunds,
            profile,
            payouts,
            master_keys,
            ..
        } = self;
        let mut result = Vec::with_capacity(2);
        for (index, ((planned, payout), keys)) in planned
            .into_iter()
            .zip(payouts)
            .zip(master_keys)
            .enumerate()
        {
            result.push(
                NativeXmrInitializerV23 {
                    claim: &claim,
                    refund: &refunds[index],
                    profile: profile.clone(),
                    claim_payout_v23: Some(payout),
                    master_keys_v23: keys,
                }
                .initialize_custody(
                    terms[index],
                    planned.refund_template_hash,
                    planned.funding_tx_hash,
                    planned.funding_destination,
                    actors[index],
                    roots[index],
                )?,
            );
        }
        result
            .try_into()
            .map_err(|_| "native route requires exactly two initialized positions".into())
    }
}
