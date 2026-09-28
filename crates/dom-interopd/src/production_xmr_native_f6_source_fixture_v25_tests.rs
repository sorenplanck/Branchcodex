//! Test-only bridge to the original small ceremony and wallet producers.
//! No completed C/D Bulletproof graph, transaction signature or F7 authority is
//! made. Only the caller's real provenance checks may produce an F6 terms owner.
use super::*;
use crate::production_noise_relay::ProductionNoiseGraphOfferV22;
use dom_actuator::{
    DomActuatorStoreV1, DomParticipantWalletV1, DomWalletAuthorityBindingV1, DomWalletSessionLegV1,
    DomXmrGraphSharesRequestV22, DomXmrPayoutKindV22 as Payout, DomXmrPayoutProofRequestV22,
};
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_wallet2::{BlockRef, Network, OutputOrigin, StoredOutput, WalletV2State};

type Result<T> = core::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) struct NativeF6SourceFixtureV25 {
    original: Fixture,
    artifact: Vec<u8>,
}

pub(crate) struct NativeF6SourceActorV25 {
    pub(crate) mounted: Box<MountedBootstrapV13>,
    pub(crate) source: ProductionNoiseGraphOfferV22,
}

pub(crate) fn with_native_f6_source_fixture_v25(
    check: impl FnOnce(&NativeF6SourceFixtureV25) -> Result<()>,
) -> Result<()> {
    let original = xmr_graph_wallet_tests::configure_wallet_fixture_v23(
        fixture_with_xmr(true),
        true,
        |_, _| {},
    );
    let (original, artifact) = complete_fixture(original);
    check(&NativeF6SourceFixtureV25 { original, artifact })
}

impl NativeF6SourceFixtureV25 {
    fn mount(&self, actor: usize) -> Result<(Box<MountedBootstrapV13>, Plan, Context)> {
        let plan_path = self
            .original
            .plan
            .get(actor)
            .ok_or("invalid fixture actor")?;
        let plan: Plan = serde_json::from_slice(&std::fs::read(plan_path)?)?;
        let secp = SecpContext::new(&[13; 32]);
        let context = load_context(&plan, &secp, true)?;
        let verified = authenticate_against_expected_v1(
            &self.artifact,
            &context.expected,
            &context.rosters,
            &secp,
        )?;
        let bindings = [0, 1].map(|leg| {
            let position = context.rosters.legs()[leg]
                .members
                .iter()
                .position(|member| member.participant_id.0 == plan.local_participant_id)
                .expect("original participant in original roster");
            context.bindings[leg][position]
        });
        let mounted = resume_completed_bootstrap_v13(
            &self.original.work[actor].join(ARTIFACT),
            &verified,
            bindings,
            &plan.identity_store,
            b"test-passphrase-v13",
        )?
        .ok_or("original completed bootstrap must reopen")?;
        Ok((mounted, plan, context))
    }

    /// Reopen only original journals; missing public material is an error,
    /// never permission to recreate the wallet or rerun any prover.
    pub(crate) fn reopen_actor(&self, actor: usize) -> Result<NativeF6SourceActorV25> {
        let (mounted, plan, context) = self.mount(actor)?;
        let terms = SettlementTermsV1::decode(&std::fs::read(&plan.terms_files[0])?)?;
        let material = &mounted._shares[0];
        let packet = material
            .runtime_public_record_v16(b"xmr-graph-offer-v22")?
            .ok_or("original local offer missing")?;
        let source = ProductionNoiseGraphOfferV22::new(
            plan.route_id,
            terms,
            context.xmr_policies[0]
                .clone()
                .ok_or("XMR policy missing")?,
            material.capability.binding().clone(),
            packet,
        )?;
        Ok(NativeF6SourceActorV25 { mounted, source })
    }

    /// Create each participant's own wallet exactly once, using that actor's
    /// original C/D shares and the same real producers used by the daemon.
    pub(crate) fn prepare_actor(&self, actor: usize) -> Result<NativeF6SourceActorV25> {
        let (mut mounted, plan, context) = self.mount(actor)?;
        let bindings = [0, 1].map(|leg| {
            let index = usize::from(
                mounted._shares[leg]
                    .capability
                    .binding()
                    .participant_index(),
            );
            context.bindings[leg][index]
        });
        let terms = SettlementTermsV1::decode(&std::fs::read(&plan.terms_files[0])?)?;
        let policy = context.xmr_policies[0]
            .as_ref()
            .ok_or("XMR policy missing")?;
        let funds = plan.local_participant_id == policy.policy().dom_funder;
        let kinds = if funds {
            [Payout::ClaimChange, Payout::Refund]
        } else {
            [Payout::ClaimPrincipal, Payout::Compensation]
        };
        let wallet_path = self.original.work[actor].join("f6-source-wallet.v3");
        let store_path = self.original.work[actor].join("f6-source-actuator.sqlite");
        if wallet_path.exists() || store_path.exists() {
            return Err("fixture owner already initialized; use reopen_actor".into());
        }
        let mut state = WalletV2State::new(Network::Mainnet, bindings[0].chain_id());
        state.meta.last_reconciled_tip = 10;
        for kind in kinds {
            let (_, commitment, value) = kind.policy_payout(policy);
            let tag = match kind {
                Payout::ClaimPrincipal => 11,
                Payout::ClaimChange => 12,
                Payout::Refund => 13,
                Payout::Compensation => 14,
            };
            state.outputs.insert(StoredOutput::new_unconfirmed(
                commitment,
                value,
                [tag; 32],
                OutputOrigin::ReceiveSlate,
                false,
                None,
                1,
            ))?;
        }
        if funds {
            // Only synthetic wallet inventory, not canonical chain evidence.
            let blind = BlindingFactor::from_bytes([31; 32])?;
            let mut input = StoredOutput::new_unconfirmed(
                *Commitment::commit(3_000_000, &blind).as_bytes(),
                3_000_000,
                *blind.as_bytes(),
                OutputOrigin::ReceiveSlate,
                false,
                None,
                1,
            );
            input.confirm(
                BlockRef {
                    height: 2,
                    hash: [32; 32],
                },
                2,
            )?;
            state.outputs.insert(input)?;
        }
        dom_wallet2::save_wallet_state(&state, &wallet_path, "f6-source-wallet-test")?;
        std::fs::set_permissions(&wallet_path, std::fs::Permissions::from_mode(0o600))?;
        let mut store = DomActuatorStoreV1::create(&store_path)?;
        let lease = store.acquire_lease(
            plan.local_participant_id,
            [141 + actor as u8; 32],
            1_000,
            10_000,
        )?;
        for binding in bindings {
            store.bind_session(lease, binding, 1_000)?;
        }
        let mut wallet = DomParticipantWalletV1::open_existing(
            &wallet_path,
            zeroize::Zeroizing::new("f6-source-wallet-test".into()),
            DomWalletAuthorityBindingV1::new(bindings[0], bindings[1])?,
        )?;
        let c = &mut mounted._shares[0];
        let d = mounted._cancelled_shares[0]
            .as_ref()
            .ok_or("original D missing")?;
        for kind in kinds {
            let key: &[u8] = match kind {
                Payout::ClaimPrincipal => b"xmr-payout-principal-v22",
                Payout::ClaimChange => b"xmr-payout-change-v22",
                Payout::Refund => b"xmr-payout-refund-v22",
                Payout::Compensation => b"xmr-payout-compensation-v22",
            };
            let offer = wallet
                .session(DomWalletSessionLegV1::Upstream)?
                .prepare_xmr_payout_proof_v22(
                    &mut store,
                    lease,
                    DomXmrPayoutProofRequestV22 {
                        terms: &terms,
                        policy,
                        kind,
                        shared: &c.capability,
                        retained: None,
                        now_unix_ms: 1_001,
                    },
                )?;
            c.retain_runtime_public_v16(key, &offer.to_bytes()?)?;
        }
        let shares = wallet
            .session(DomWalletSessionLegV1::Upstream)?
            .prepare_xmr_graph_shares_v22(
                &mut store,
                lease,
                DomXmrGraphSharesRequestV22 {
                    terms: &terms,
                    policy,
                    collateral: &c.capability,
                    cancelled: &d.capability,
                    now_unix_ms: 1_001,
                },
            )?;
        let funding = wallet
            .session(DomWalletSessionLegV1::Upstream)?
            .prepare_xmr_funding_offer_v22(&mut store, lease, &terms, policy, None, 1_001)?;
        c.retain_runtime_public_v16(b"xmr-funding-offer-v22", &funding.to_bytes()?)?;
        c.retain_runtime_public_v16(b"xmr-graph-keys-v22", &shares.public_commitment_v22())?;
        c.retain_runtime_public_v16(
            b"xmr-graph-proofs-v22",
            &shares.prove_public_commitment_v22(None)?,
        )?;
        let packet = crate::production_xmr_graph_offer_v22::retain_local_graph_offer_v22(
            c,
            &shares,
            bindings[0],
            &terms,
            policy,
        )?;
        let source = ProductionNoiseGraphOfferV22::new(
            plan.route_id,
            terms,
            policy.clone(),
            c.capability.binding().clone(),
            packet,
        )?;
        Ok(NativeF6SourceActorV25 { mounted, source })
    }
}
