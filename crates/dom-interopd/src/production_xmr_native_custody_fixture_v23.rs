//! Test-only native T/U custody. No public secret getter, fabricated DLEQ,
//! claimed chain payment or production-admission token.
use kaystra_core::{terms::SettlementTermsV1, types::TimelockSpec};
use std::path::Path;
use xmr_dleq_nullifier_store::DleqNullifierStore;
use xmr_dleq_sigma::{BoundCrossCurveProofV1, CrossCurveSecret252};
use xmr_refund_adaptor::DomRefundAdaptorExecutor;
use xmr_refund_policy::{
    NonCooperativeRefundCapability, ValidatedRefundPolicy, XmrRefundArtifactV1, XmrRefundModeV1,
};
use xmr_secret_store::{EncryptedSqliteSecretStore, SecretStoreMasterKey};
use xmr_session_init::{XmrLocalSessionSecretsV11, XmrLocalShareRoleV11};
use xmr_setup_profile::{
    ValidatedXmrSetup, XmrAdapterProfileV1, XmrProofContextV1, XmrSetupBindingV1,
};
use zeroize::Zeroizing;

#[path = "production_xmr_native_claim_exposure_v23_tests.rs"]
mod claim_exposure_v23;
#[path = "production_xmr_native_claim_payout_v23_tests.rs"]
mod claim_payout_v23;
#[path = "production_xmr_native_claim_sweep_v23_tests.rs"]
mod claim_sweep_v23;
#[path = "production_xmr_native_refund_sweep_v23_tests.rs"]
mod refund_sweep_v23;
use claim_payout_v23::NativeClaimPayoutV23;
#[path = "production_xmr_native_claim_extraction_v23_tests.rs"]
mod claim_extraction_v23;
#[path = "production_xmr_native_custody_observation_v23_tests.rs"]
mod observation_v23;
#[path = "production_xmr_native_participant_export_v23_tests.rs"]
mod participant_export_v23;
#[path = "production_xmr_native_route_initializer_v23_tests.rs"]
mod route_initializer_v23;
pub(crate) use route_initializer_v23::{
    NativeXmrEnrolledFixtureV23, NativeXmrEnrollmentPlanV23, NativeXmrPlannedLegV23,
    NativeXmrRouteSecretsV23,
};
#[path = "production_xmr_native_registry_fixture_v23.rs"]
mod registry_v23;

type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) struct NativeXmrSecretsFixtureV23 {
    claim: CrossCurveSecret252,
    refund: CrossCurveSecret252,
    profile: XmrAdapterProfileV1,
    funding_fee_cap_v23: Option<u64>,
    claim_payout_v23: Option<NativeClaimPayoutV23>,
}

impl NativeXmrSecretsFixtureV23 {
    pub(crate) fn new(profile: XmrAdapterProfileV1) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            claim: CrossCurveSecret252::generate(&mut rng),
            refund: CrossCurveSecret252::generate(&mut rng),
            profile,
            funding_fee_cap_v23: None,
            claim_payout_v23: None,
        }
    }

    /// Separate observer scenario only; must be selected before terms/registry/C/D.
    pub(crate) fn with_funding_fee_cap_v23(mut self, cap: u64) -> Result<Self> {
        if cap == 0 || cap > 1_000_000 {
            return Err("offline funding fee cap bound".into());
        }
        self.funding_fee_cap_v23 = Some(cap);
        Ok(self)
    }

    /// Freeze the distinct local payout wallet before starting either graph leg.
    pub(crate) fn with_claim_payout_v23(mut self) -> Result<Self> {
        if self.profile.network != xmr_setup_profile::XmrNetwork::Stagenet {
            return Err("offline payout requires Stagenet".into());
        }
        self.claim_payout_v23 = Some(NativeClaimPayoutV23::new(
            self.funding_fee_cap_v23
                .ok_or("freeze fee cap before payout")?,
        )?);
        Ok(self)
    }

    pub(crate) fn configure_registry(
        &self,
        manifest: &mut deployment_registry::RegistryManifestV1,
        mut terms: [&mut SettlementTermsV1; 2],
    ) -> Result<()> {
        if self.profile.network != xmr_setup_profile::XmrNetwork::Stagenet {
            return Err("native registry fixture supports only ratified stagenet".into());
        }
        if self.claim_payout_v23.is_some() {
            for terms in &mut terms {
                terms.counterparty_leg.amount = 1_000_000_000;
            }
        }
        if let Some(cap) = self.funding_fee_cap_v23 {
            for terms in &mut terms {
                terms.fee_limit.counterparty_max = u128::from(cap);
            }
        }
        registry_v23::configure(manifest, terms)?;
        if let Some(cap) = self.funding_fee_cap_v23 {
            for chain in &mut manifest.chains {
                if let deployment_registry::ChainDeploymentV1::Monero(deployment) =
                    &mut chain.deployment
                {
                    deployment.max_fee_piconero = cap;
                }
            }
            manifest.validate()?;
        }
        Ok(())
    }

    // Must precede terms hashing, C/D construction and the bilateral proposal.
    pub(crate) fn configure_terms(&self, terms: &mut SettlementTermsV1) -> Result<()> {
        terms.adaptor_point_sec1 = self.claim.public_claim()?.secp_compressed;
        if self.claim_payout_v23.is_some() {
            // New offline payout scenario only: 0.001 XMR, exceeding the
            // separately frozen 10,000-piconero fee cap without fee scaling.
            terms.counterparty_leg.amount = 1_000_000_000;
        }
        if let Some(cap) = self.funding_fee_cap_v23 {
            terms.fee_limit.counterparty_max = u128::from(cap);
        }
        terms.counterparty_leg.adapter_profile_hash = self.profile.profile_hash();
        terms.validate()?;
        Ok(())
    }

    pub(crate) fn combined_spend_public_key_v23(&self) -> Result<[u8; 32]> {
        Ok(xmr_crypto::combine_public_shares(
            self.claim.public_claim()?.ed_compressed,
            self.refund.public_claim()?.ed_compressed,
        )?)
    }

    pub(crate) fn refund_point(&self) -> Result<[u8; 33]> {
        Ok(self.refund.public_claim()?.secp_compressed)
    }

    pub(crate) fn initialize_custody(
        self,
        terms: &SettlementTermsV1,
        refund_template_hash: [u8; 32],
        planned_funding_hash: [u8; 32],
        destination: String,
        actors: [[u8; 32]; 2],
        roots: [&Path; 2],
    ) -> Result<NativeXmrCustodyFixtureV23> {
        let Self {
            claim,
            refund,
            profile,
            claim_payout_v23,
            ..
        } = self;
        NativeXmrInitializerV23 {
            claim: &claim,
            refund: &refund,
            profile,
            claim_payout_v23,
            master_keys_v23: [Zeroizing::new([0xd1; 32]), Zeroizing::new([0xd2; 32])],
        }
        .initialize_custody(
            terms,
            refund_template_hash,
            planned_funding_hash,
            destination,
            actors,
            roots,
        )
    }
}

struct NativeXmrInitializerV23<'a> {
    claim: &'a CrossCurveSecret252,
    refund: &'a CrossCurveSecret252,
    profile: XmrAdapterProfileV1,
    claim_payout_v23: Option<NativeClaimPayoutV23>,
    master_keys_v23: [Zeroizing<[u8; 32]>; 2],
}

impl NativeXmrInitializerV23<'_> {
    /// The caller supplies the scenario's actual planned XMR funding artifact
    /// identity/destination, not a payment observation. This creates no funding proof.
    pub(crate) fn initialize_custody(
        self,
        terms: &SettlementTermsV1,
        refund_template_hash: [u8; 32],
        planned_funding_hash: [u8; 32],
        destination: String,
        actors: [[u8; 32]; 2],
        roots: [&Path; 2],
    ) -> Result<NativeXmrCustodyFixtureV23> {
        use xmr_dleq_sigma::{prove_bound, ROLE_XMR_REFUND_SHARE, ROLE_XMR_SHARED_SPEND};
        let claim = self.claim.public_claim()?;
        let refund_claim = self.refund.public_claim()?;
        if terms.adaptor_point_sec1 != claim.secp_compressed
            || terms.counterparty_leg.adapter_profile_hash != self.profile.profile_hash()
            || claim == refund_claim
            || actors[0] == actors[1]
            || refund_template_hash == [0; 32]
            || planned_funding_hash == [0; 32]
            || destination.is_empty()
        {
            return Err("native XMR fixture scope mismatch".into());
        }
        let context = xmr_setup_profile::proof_context_hash(
            &self.profile,
            &XmrProofContextV1 {
                settlement_id: terms.settlement_id.0,
                chain_id: terms.counterparty_leg.chain_id.0,
                asset_id: terms.counterparty_leg.asset_id.0,
                amount_piconero: terms.counterparty_leg.amount,
                min_confirmations: terms.counterparty_leg.finality.min_confirmations,
                max_reorg_depth: terms.counterparty_leg.finality.max_reorg_depth,
            },
        )?;
        let mut rng = rand::thread_rng();
        let claim_proof = prove_bound(
            &self.claim,
            terms.settlement_id.0,
            context,
            ROLE_XMR_SHARED_SPEND,
            &mut rng,
        )?;
        let refund_proof = prove_bound(
            &self.refund,
            terms.settlement_id.0,
            context,
            ROLE_XMR_REFUND_SHARE,
            &mut rng,
        )?;
        let public_binding_v23 = XmrSetupBindingV1 {
            settlement_id: terms.settlement_id.0,
            terms_hash: terms.terms_hash()?,
            dleq: claim_proof,
            funding_tx_hash: planned_funding_hash,
            expected_amount_piconero: u64::try_from(terms.counterparty_leg.amount)?,
            destination: match self.claim_payout_v23.as_ref() {
                Some(payout) => {
                    if payout.address() == destination {
                        return Err("payout equals shared funding address".into());
                    }
                    payout.address().to_owned()
                }
                None => destination,
            },
            combined_spend_public_key: xmr_crypto::combine_public_shares(
                claim.ed_compressed,
                refund_claim.ed_compressed,
            )?,
        };
        let setup = xmr_setup_profile::validate_setup(
            terms,
            &self.profile,
            public_binding_v23.clone(),
            None,
        )?;
        let executor = DomRefundAdaptorExecutor::new(refund_claim);
        let deadline = match terms.counterparty_leg.deadline {
            TimelockSpec::BlockHeight { value } => value,
            _ => return Err("native XMR fixture requires a Monero height deadline".into()),
        };
        let public_refund_artifact_v23 = XmrRefundArtifactV1 {
            template_hash: refund_template_hash,
            adaptor_point_sec1: refund_claim.secp_compressed,
            executor_profile_hash: executor.profile_hash(),
            deadline,
        };
        let refund_policy = xmr_refund_policy::admit_refund_policy(
            terms,
            self.profile.network,
            XmrRefundModeV1::AdaptorRefundRequired,
            Some(public_refund_artifact_v23),
            None,
            Some(&executor),
        )?;
        let mut owners = Vec::with_capacity(2);
        for (actor, master_key_v23) in self.master_keys_v23.into_iter().enumerate() {
            let (role, secret) = if actors[actor] == terms.dom_leg.refund_to.0 {
                (XmrLocalShareRoleV11::ClaimReceiver, &self.refund)
            } else if actors[actor] == terms.counterparty_leg.refund_to.0 {
                (XmrLocalShareRoleV11::RefundReceiver, &self.claim)
            } else {
                return Err("native XMR fixture actor has no economic role".into());
            };
            let secrets = EncryptedSqliteSecretStore::open(
                &roots[actor].join("native-xmr-secrets-v23.sqlite"),
                SecretStoreMasterKey::new(*master_key_v23)?,
            )?;
            let nullifiers =
                DleqNullifierStore::open(&roots[actor].join("native-xmr-nullifiers-v23.sqlite"))?;
            let mut view = [0; 32];
            view[0] = 13;
            xmr_session_init::initialize_session_for_role_v11(
                &setup,
                &secrets,
                &nullifiers,
                &refund_policy,
                &refund_proof,
                XmrLocalSessionSecretsV11 {
                    role,
                    spend_share: Zeroizing::new(secret.xmr_share_little_endian()),
                    view_key: Zeroizing::new(view),
                },
                &mut rng,
            )?;
            owners.push(NativeXmrActorCustodyV23 {
                secrets,
                nullifiers,
                role,
                master_key_v23,
            });
        }
        Ok(NativeXmrCustodyFixtureV23 {
            profile: self.profile,
            claim_payout_v23: self.claim_payout_v23,
            setup,
            public_binding_v23,
            public_refund_artifact_v23,
            refund_policy,
            refund_proof,
            actors: owners
                .try_into()
                .map_err(|_| "two native XMR actors required")?,
        })
    }
}

struct NativeXmrActorCustodyV23 {
    secrets: EncryptedSqliteSecretStore,
    nullifiers: DleqNullifierStore,
    role: XmrLocalShareRoleV11,
    master_key_v23: Zeroizing<[u8; 32]>,
}

pub(crate) struct NativeXmrCustodyFixtureV23 {
    profile: XmrAdapterProfileV1,
    claim_payout_v23: Option<NativeClaimPayoutV23>,
    setup: ValidatedXmrSetup,
    public_binding_v23: XmrSetupBindingV1,
    public_refund_artifact_v23: XmrRefundArtifactV1,
    refund_policy: ValidatedRefundPolicy,
    refund_proof: BoundCrossCurveProofV1,
    actors: [NativeXmrActorCustodyV23; 2],
}

impl NativeXmrCustodyFixtureV23 {
    /// Consume every old DB owner before reopening existing rows; no initialize fallback.
    pub(crate) fn reopen(self, roots: [&Path; 2]) -> Result<Self> {
        let Self {
            profile,
            claim_payout_v23,
            setup,
            public_binding_v23,
            public_refund_artifact_v23,
            refund_policy,
            refund_proof,
            actors,
        } = self;
        let retained = actors.map(|actor| {
            let NativeXmrActorCustodyV23 {
                secrets,
                nullifiers,
                role,
                master_key_v23,
            } = actor;
            drop(secrets);
            drop(nullifiers);
            (role, master_key_v23)
        });
        let mut owners = Vec::with_capacity(2);
        for (actor, (role, master_key_v23)) in retained.into_iter().enumerate() {
            let secrets = EncryptedSqliteSecretStore::open_existing(
                &roots[actor].join("native-xmr-secrets-v23.sqlite"),
                SecretStoreMasterKey::new(*master_key_v23)?,
            )?;
            let nullifiers = DleqNullifierStore::open_existing(
                &roots[actor].join("native-xmr-nullifiers-v23.sqlite"),
            )?;
            xmr_session_init::resume_session_for_role_v11(
                &setup,
                &secrets,
                &nullifiers,
                &refund_policy,
                &refund_proof,
                role,
            )?;
            owners.push(NativeXmrActorCustodyV23 {
                secrets,
                nullifiers,
                role,
                master_key_v23,
            });
        }
        Ok(Self {
            profile,
            claim_payout_v23,
            setup,
            public_binding_v23,
            public_refund_artifact_v23,
            refund_policy,
            refund_proof,
            actors: owners
                .try_into()
                .map_err(|_| "two reopened native owners required")?,
        })
    }

    pub(crate) fn profile(&self) -> &XmrAdapterProfileV1 {
        &self.profile
    }

    pub(crate) fn setup(&self) -> &ValidatedXmrSetup {
        &self.setup
    }
    pub(crate) fn refund_policy(&self) -> &ValidatedRefundPolicy {
        &self.refund_policy
    }
    pub(crate) fn refund_proof(&self) -> &BoundCrossCurveProofV1 {
        &self.refund_proof
    }

    pub(crate) fn complete_private_refund(
        &self,
        actor: usize,
        graph: &dom_scriptless_crypto::VerifiedXmrRecoveryGraphV11,
    ) -> Result<dom_scriptless_crypto::PrivateXmrRefundTransactionV11> {
        let owner = self.actors.get(actor).ok_or("unknown native XMR actor")?;
        if owner.role != XmrLocalShareRoleV11::ClaimReceiver {
            return Err("native XMR actor does not own private U".into());
        }
        xmr_session_init::resume_session_for_role_v11(
            &self.setup,
            &owner.secrets,
            &owner.nullifiers,
            &self.refund_policy,
            &self.refund_proof,
            owner.role,
        )?;
        Ok(xmr_session_init::complete_private_dom_refund_v12(
            &self.setup,
            &owner.secrets,
            &owner.nullifiers,
            &self.refund_policy,
            &self.refund_proof,
            graph,
        )?)
    }
}
