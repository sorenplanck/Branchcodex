//! One DOM<->Solana leg, in both claim orders, with DOM as the hub.
//!
//! This module freezes the public facts of a leg and derives everything else
//! from them: the settlement terms, the escrow setup, the four escrow
//! instructions and the condition both chains share. It holds no secret except
//! through [`EstablishedLegV1`], and it never submits anything — delivery is
//! `crate::cluster` and the DOM side is `crate::native_dom` plus
//! `crate::dom_joint`.
//!
//! Both directions use the SAME escrow and the SAME DOM kernel. What changes is
//! which leg publishes the secret first, and therefore which deadline is
//! derived from the other:
//!
//! ```text
//! SOL -> DOM (ClaimOrderV1::DomFirst)
//!   the DOM claim is completed with the secret and reveals it in the kernel's
//!   excess signature; the counterparty extracts it and claims the escrow.
//!
//! DOM -> SOL (ClaimOrderV1::SolanaFirst)
//!   the escrow claim carries the secret in its instruction data and stores it
//!   in the escrow state; the DOM side reads it and completes the DOM claim.
//! ```
//!
//! In neither direction does value move between two counterparty chains: a
//! BTC<->SOL settlement is two legs, BTC<->DOM and DOM<->SOL, and this module
//! is only ever the second of them.
//!
//! Both assets the escrow supports are settled here: native SOL and a legacy SPL
//! token. The asset is part of the frozen plan -- it enters the DLEQ proof context
//! and the setup binding -- so the two sides cannot disagree about it, and the
//! token accounts a token settlement needs are part of the same plan rather than
//! arguments a caller may forget. A plan whose asset and token accounts disagree
//! is refused before anything is signed.

use dom_core::{BlockHeight, Timestamp};
use kaystra_core::{
    terms::SettlementTermsV1,
    types::{
        AssetId, ChainId, FeeLimitV1, FinalityPolicyV1, IntentHash, LegRole, LegTermsV1,
        LockMechanism, ParticipantId, RecoveryPolicyV1, SessionId, SettlementId, SolverId,
        TimelockSpec,
    },
};
use sha2::{Digest, Sha256};
use solana_escrow_wire::{EscrowStateV1, EscrowStatus};
use solana_profile::{
    proof_context_hash, setup_id, validate_setup_with_profile_digest, SolanaAdapterProfileV1,
    SolanaAssetV1,
    SolanaProofContextV1, SolanaSetupBindingV1, ValidatedSolanaSetup,
};
use solana_route_secret::{verify_counterparty_bundle, SolanaRouteSecret};
use solana_secret_store::WitnessMaterialStore;
use solana_session_init::{
    finalize_session_with_profile_digest, persist_route_witness, prepare_route_secret,
    resume_session_with_profile_digest,
    InitializedSolanaSession,
};
use solana_setup_store::SolanaSetupStore;
use solana_types::{SolanaInstruction, SolanaPubkey};
use xmr_dleq_sigma::BoundCrossCurveProofV1;
use zeroize::Zeroizing;

use crate::{
    condition::{ConditionError, ConditionLockV1, ConditionOpeningV1},
    time_bounds::{
        AssumedDomAnchor, AssumedLegDelaysV1, ClaimOrderV1, DomClockNetwork, LegScheduleV1,
        ScheduleAnchorV1, TimingError,
    },
};

/// Domain tag for the DOM leg's adapter profile hash. The DOM leg of these
/// terms is served by this laboratory, not by a registered adapter profile, and
/// saying so in the hash keeps it from being mistaken for one.
const DOM_LEG_PROFILE_DOMAIN: &[u8] = b"DOM-SOLANA-DIRECT-LAB/dom-leg-profile/v1\0";

#[derive(Debug, thiserror::Error)]
pub enum LegError {
    #[error("leg schedule: {0:?}")]
    Timing(TimingError),
    #[error("leg condition: {0}")]
    Condition(#[from] ConditionError),
    #[error("settlement terms: {0}")]
    Terms(#[from] kaystra_core::terms::TermsError),
    #[error("escrow setup: {0}")]
    Setup(#[from] solana_profile::SetupError),
    #[error("route secret: {0}")]
    RouteSecret(#[from] solana_route_secret::RouteSecretError),
    #[error("session initialization: {0}")]
    Session(#[from] solana_session_init::SessionInitError),
    #[error("setup store: {0}")]
    Store(String),
    #[error("escrow instruction: {0}")]
    Client(#[from] solana_program_client::ClientError),
    #[error("escrow wire: {0}")]
    Wire(String),
    #[error("the escrow state does not belong to this leg")]
    ForeignEscrowState,
    #[error("the escrow has not revealed a secret")]
    NoRevealedSecret,
    #[error("the opening belongs to a different condition")]
    ForeignOpening,
    #[error("a token settlement needs all three token accounts, a native one needs none")]
    TokenAccountsMismatch,
    #[error("witness storage: {0}")]
    Witness(#[from] solana_secret_store::SecretStoreError),
    #[error("no setup is registered for this settlement")]
    UnknownSettlement,
}

impl From<TimingError> for LegError {
    fn from(error: TimingError) -> Self {
        Self::Timing(error)
    }
}

/// Every public fact of a leg, agreed before anything is funded.
///
/// `dom_*` fields describe the DOM leg; the rest describe the Solana leg.
/// `cluster_genesis` is the cluster's own genesis hash, read from the node, and
/// it is what makes the DLEQ proof context specific to this cluster: the same
/// terms against a different cluster produce a different context hash and the
/// counterparty's bundle stops verifying.
#[derive(Clone, Debug)]
pub struct LegPlanInputV1 {
    pub settlement_id: [u8; 32],
    pub session_id: [u8; 32],
    pub intent_hash: [u8; 32],
    pub solver_id: [u8; 32],
    // ── DOM leg ─────────────────────────────────────────────────────────────
    pub dom_chain_id: [u8; 32],
    pub dom_asset_id: [u8; 32],
    pub dom_amount_noms: u64,
    pub dom_beneficiary: ParticipantId,
    pub dom_refund_to: ParticipantId,
    pub dom_finality: FinalityPolicyV1,
    pub dom_fee_max: u64,
    /// Digest the counterparty leg's `adapter_profile_hash` must carry.
    ///
    /// `None` means the adapter profile's own hash, which is what a standalone leg
    /// uses. A route admitted by `dom-interopd` must carry the AUTHENTICATED
    /// registry's chain-profile digest instead: `admission`,
    /// `route_time_anchor::counterparty_binding` and the ratified Monero boundary all
    /// compare this field with that value, so a leg that insists on the adapter's own
    /// hash cannot be part of an admitted route. The adapter profile's identity is
    /// unaffected either way -- `proof_context_hash` binds it inside the DLEQ context.
    pub counterparty_profile_digest: Option<[u8; 32]>,
    /// Digest of the adapter profile that interprets the DOM leg.
    ///
    /// A route provisioned against a daemon must pass the digest its registry
    /// derives; a standalone laboratory passes
    /// [`LegPlanInputV1::derived_dom_leg_profile_hash`]. It is an input rather than a
    /// derivation because only the first of those two is authority.
    pub dom_leg_profile_hash: [u8; 32],
    // ── Solana leg ──────────────────────────────────────────────────────────
    pub cluster_genesis: [u8; 32],
    pub solana_asset_id: [u8; 32],
    /// Which asset the escrow holds. Frozen into the proof context and the setup.
    pub asset: SolanaAssetV1,
    /// Amount in the asset's smallest unit: lamports for SOL, base units for a
    /// token, where the mint's decimals decide what a base unit means.
    pub lamports: u64,
    pub funder: SolanaPubkey,
    pub beneficiary: SolanaPubkey,
    pub refund_recipient: SolanaPubkey,
    /// Token accounts, required exactly when the asset is a token. The escrow's
    /// terminal transfer refuses a destination whose owner is not the recipient
    /// the terms froze, so these are accounts owned by the roles above.
    pub funder_token_account: Option<SolanaPubkey>,
    pub beneficiary_token_account: Option<SolanaPubkey>,
    pub refund_token_account: Option<SolanaPubkey>,
    pub solana_finality: FinalityPolicyV1,
    pub solana_fee_max: u64,
    pub program_data_hash: [u8; 32],
    // ── schedule ────────────────────────────────────────────────────────────
    pub anchor: AssumedDomAnchor,
    pub now: Timestamp,
    pub network: DomClockNetwork,
    pub validator_clock_ahead_secs: u64,
    pub delays: AssumedLegDelaysV1,
    pub chosen_deadline: ScheduleAnchorV1,
    pub evidence_retention_blocks: u64,
    pub policy_version: u32,
}

impl LegPlanInputV1 {
    /// The value this laboratory uses when no deployment names one.
    ///
    /// The DOM leg's adapter profile hash is a DEPLOYMENT fact, not something a leg
    /// may invent: a daemon route derives it from its authenticated registry with
    /// `route_time_anchor::resolved_dom_profile_digest_v1`, and refuses terms that
    /// carry anything else. This laboratory has no registry, so it derives a stable
    /// value from the DOM chain and asset instead -- which is why the field is an
    /// input now and this function only supplies the default for a caller that has
    /// nothing better.
    pub fn derived_dom_leg_profile_hash(dom_chain_id: [u8; 32], dom_asset_id: [u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(DOM_LEG_PROFILE_DOMAIN);
        hasher.update(dom_chain_id);
        hasher.update(dom_asset_id);
        hasher.finalize().into()
    }

    /// The digest the counterparty leg's `adapter_profile_hash` carries, and the digest
    /// every validation of this leg checks it against. One function, so the terms and
    /// the validation cannot disagree.
    fn expected_profile_digest(&self, profile: &SolanaAdapterProfileV1) -> [u8; 32] {
        self.counterparty_profile_digest
            .unwrap_or_else(|| profile.profile_hash())
    }

    fn roster(&self) -> [ParticipantId; 2] {
        let mut roster = [self.dom_beneficiary, self.dom_refund_to];
        roster.sort();
        roster
    }

    fn proof_context(&self, schedule: &LegScheduleV1) -> SolanaProofContextV1 {
        SolanaProofContextV1 {
            settlement_id: self.settlement_id,
            chain_id: self.cluster_genesis,
            asset_id: self.solana_asset_id,
            amount: u128::from(self.lamports),
            beneficiary: self.beneficiary.0,
            refund_to: self.refund_recipient.0,
            refund_after_unix: schedule.escrow_refund_after.0,
            min_confirmations: self.solana_finality.min_confirmations,
            max_reorg_depth: self.solana_finality.max_reorg_depth,
            asset: self.asset,
            funder: self.funder,
        }
    }

    /// A token settlement needs all three token accounts and a native one needs
    /// none. Refusing the mixed shapes here means no instruction builder has to
    /// decide what a missing account meant.
    fn validate_token_accounts(&self) -> Result<(), LegError> {
        let accounts = [
            self.funder_token_account,
            self.beneficiary_token_account,
            self.refund_token_account,
        ];
        let present = accounts.iter().filter(|slot| slot.is_some()).count();
        let required = match self.asset {
            SolanaAssetV1::NativeSol => 0,
            SolanaAssetV1::LegacySpl { .. } => accounts.len(),
        };
        if present != required {
            return Err(LegError::TokenAccountsMismatch);
        }
        Ok(())
    }

    /// The frozen terms. `adaptor_point_sec1` is the condition's secp256k1
    /// face, so the terms cannot be built before the condition exists, and the
    /// condition cannot be proved before the schedule fixes the escrow
    /// deadline: the order of these three steps is forced.
    fn terms(&self, schedule: &LegScheduleV1, adaptor_point_sec1: [u8; 33]) -> SettlementTermsV1 {
        SettlementTermsV1 {
            settlement_id: SettlementId(self.settlement_id),
            session_id: SessionId(self.session_id),
            intent_hash: IntentHash(self.intent_hash),
            solver_id: SolverId(self.solver_id),
            roster: self.roster(),
            dom_leg: LegTermsV1 {
                role: LegRole::Dom,
                chain_id: ChainId(self.dom_chain_id),
                asset_id: AssetId(self.dom_asset_id),
                amount: u128::from(self.dom_amount_noms),
                beneficiary: self.dom_beneficiary,
                refund_to: self.dom_refund_to,
                mechanism: LockMechanism::DomAdaptor2of2,
                deadline: TimelockSpec::BlockHeight {
                    value: schedule.dom_refund_height.0,
                },
                finality: self.dom_finality,
                adapter_profile_hash: self.dom_leg_profile_hash,
            },
            counterparty_leg: LegTermsV1 {
                role: LegRole::Counterparty,
                chain_id: ChainId(self.cluster_genesis),
                asset_id: AssetId(self.solana_asset_id),
                amount: u128::from(self.lamports),
                beneficiary: ParticipantId(self.beneficiary.0),
                refund_to: ParticipantId(self.refund_recipient.0),
                mechanism: LockMechanism::CrossCurveConditionLock,
                deadline: TimelockSpec::TimestampSeconds {
                    value: schedule.escrow_refund_after.0,
                },
                finality: self.solana_finality,
                adapter_profile_hash: [0; 32], // replaced below with the real profile hash
            },
            adaptor_point_sec1,
            fee_limit: FeeLimitV1 {
                // The terms carry fee ceilings as u128; the input keeps them in
                // each chain's own smallest unit, which is u64 on both.
                dom_max: u128::from(self.dom_fee_max),
                counterparty_max: u128::from(self.solana_fee_max),
            },
            recovery: RecoveryPolicyV1 {
                refund_before_funding: true,
                evidence_retention_blocks: self.evidence_retention_blocks,
            },
            assurance_policy_hash: None,
            policy_version: self.policy_version,
            metadata: Vec::new(),
        }
    }
}

/// A leg whose public side is fully derived and checked. Both participants hold
/// one of these; only one of them also holds the secret.
///
/// Not `Clone`: one leg is one settlement, and a second copy of it would be a
/// second view that could drift from the first.
pub struct SolanaLegV1 {
    profile: SolanaAdapterProfileV1,
    terms: SettlementTermsV1,
    schedule: LegScheduleV1,
    lock: ConditionLockV1,
    setup: ValidatedSolanaSetup,
    funder_token_account: Option<SolanaPubkey>,
    beneficiary_token_account: Option<SolanaPubkey>,
    refund_token_account: Option<SolanaPubkey>,
}

impl core::fmt::Debug for SolanaLegV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SolanaLegV1")
            .field("order", &self.schedule.order)
            .field("dom_refund_height", &self.schedule.dom_refund_height)
            .field("escrow_refund_after", &self.schedule.escrow_refund_after)
            .field("state_pda", &self.setup.state_pda())
            .finish_non_exhaustive()
    }
}

impl SolanaLegV1 {
    pub fn order(&self) -> ClaimOrderV1 {
        self.schedule.order
    }

    pub fn schedule(&self) -> &LegScheduleV1 {
        &self.schedule
    }

    pub fn dom_refund_height(&self) -> BlockHeight {
        self.schedule.dom_refund_height
    }

    pub fn escrow_refund_after(&self) -> Timestamp {
        self.schedule.escrow_refund_after
    }

    pub fn terms(&self) -> &SettlementTermsV1 {
        &self.terms
    }

    pub fn lock(&self) -> &ConditionLockV1 {
        &self.lock
    }

    pub fn setup(&self) -> &ValidatedSolanaSetup {
        &self.setup
    }

    pub fn profile(&self) -> &SolanaAdapterProfileV1 {
        &self.profile
    }

    /// The side that does NOT hold the secret: rebuild every derived value from
    /// the same public input plus the counterparty's DLEQ proof, and refuse
    /// anything that does not reproduce exactly. Nothing received over the wire
    /// is trusted beyond the proof itself, and the proof is verified against a
    /// context hash computed here.
    pub fn accept(
        input: &LegPlanInputV1,
        profile: &SolanaAdapterProfileV1,
        proof: BoundCrossCurveProofV1,
        store: &SolanaSetupStore,
    ) -> Result<Self, LegError> {
        input.validate_token_accounts()?;
        let schedule = LegScheduleV1::plan(
            &input.anchor,
            input.chosen_deadline,
            input.now,
            input.network,
            input.validator_clock_ahead_secs,
            input.delays,
        )?;
        let context = input.proof_context(&schedule);
        let context_hash = proof_context_hash(profile, &context)?;
        let claim = verify_counterparty_bundle(&proof, &input.settlement_id, &context_hash)?;
        let lock = ConditionLockV1::from_verified_claim(claim)?;
        let terms = Self::frozen_terms(input, profile, &schedule, lock.dom_adaptor_point())?;
        let setup = Self::derive_setup(input, profile, &terms, proof)?;
        store
            .register(setup.binding())
            .map_err(|error| LegError::Store(error.to_string()))?;
        Ok(Self {
            profile: *profile,
            terms,
            schedule,
            lock,
            setup,
            funder_token_account: input.funder_token_account,
            beneficiary_token_account: input.beneficiary_token_account,
            refund_token_account: input.refund_token_account,
        })
    }

    /// The side that holds the secret: generate the condition, freeze the terms
    /// around it and register the setup through the adapter's own session
    /// initialization, which re-verifies the bundle and the adaptor point.
    pub fn establish(
        input: &LegPlanInputV1,
        profile: &SolanaAdapterProfileV1,
        store: &SolanaSetupStore,
        rng: &mut (impl rand::CryptoRng + rand::RngCore),
    ) -> Result<EstablishedLegV1, LegError> {
        input.validate_token_accounts()?;
        let schedule = LegScheduleV1::plan(
            &input.anchor,
            input.chosen_deadline,
            input.now,
            input.network,
            input.validator_clock_ahead_secs,
            input.delays,
        )?;
        let context = input.proof_context(&schedule);
        let route: SolanaRouteSecret = prepare_route_secret(profile, &context, rng)?;
        let context_hash = proof_context_hash(profile, &context)?;
        let claim = verify_counterparty_bundle(route.proof(), &input.settlement_id, &context_hash)?;
        let lock = ConditionLockV1::from_verified_claim(claim)?;
        let terms = Self::frozen_terms(input, profile, &schedule, lock.dom_adaptor_point())?;
        let proof = route.proof().clone();
        let session = finalize_session_with_profile_digest(
            profile,
            &terms,
            input.asset,
            input.funder,
            input.program_data_hash,
            route,
            store,
            input.expected_profile_digest(profile),
        )?;
        // Two independent derivations of the same setup: the adapter's own
        // `finalize_session` and this module's. They must agree on the setup
        // id, which covers every field the escrow will store, and a mismatch
        // means one of the two is wrong — so neither is trusted alone.
        let derived = Self::derive_setup(input, profile, &terms, proof)?;
        if derived.setup_id() != session.setup().setup_id()
            || derived.binding_hash() != session.setup().binding_hash()
        {
            return Err(LegError::Setup(solana_profile::SetupError::BindingMismatch));
        }
        let leg = Self {
            profile: *profile,
            terms,
            schedule,
            lock,
            setup: derived,
            funder_token_account: input.funder_token_account,
            beneficiary_token_account: input.beneficiary_token_account,
            refund_token_account: input.refund_token_account,
        };
        Ok(EstablishedLegV1 { leg, session })
    }

    /// The terms, with the counterparty leg's adapter profile hash filled in
    /// from the profile itself and the whole structure validated.
    pub fn frozen_terms(
        input: &LegPlanInputV1,
        profile: &SolanaAdapterProfileV1,
        schedule: &LegScheduleV1,
        adaptor_point_sec1: [u8; 33],
    ) -> Result<SettlementTermsV1, LegError> {
        let mut terms = input.terms(schedule, adaptor_point_sec1);
        terms.counterparty_leg.adapter_profile_hash = input.expected_profile_digest(profile);
        terms.validate()?;
        Ok(terms)
    }

    fn derive_setup(
        input: &LegPlanInputV1,
        profile: &SolanaAdapterProfileV1,
        terms: &SettlementTermsV1,
        proof: BoundCrossCurveProofV1,
    ) -> Result<ValidatedSolanaSetup, LegError> {
        let pdas = solana_pda::derive_escrow_pdas(profile.program_id, input.settlement_id)
            .map_err(|_| LegError::Setup(solana_profile::SetupError::BindingMismatch))?;
        // A token escrow holds its balance in a token account, a native one in a
        // lamport account, and they are different PDAs under different seeds.
        let (vault_pda, vault_bump) = match input.asset {
            SolanaAssetV1::NativeSol => (pdas.native_vault, pdas.native_vault_bump),
            SolanaAssetV1::LegacySpl { .. } => (pdas.token_vault, pdas.token_vault_bump),
        };
        let mut binding = SolanaSetupBindingV1 {
            settlement_id: input.settlement_id,
            terms_hash: terms.terms_hash()?,
            dleq: proof,
            program_id: profile.program_id,
            state_pda: pdas.state,
            vault_pda,
            vault_authority: pdas.vault_authority,
            state_bump: pdas.state_bump,
            vault_bump,
            authority_bump: pdas.vault_authority_bump,
            asset: input.asset,
            funder: input.funder,
            recipient: input.beneficiary,
            refund_recipient: input.refund_recipient,
            amount: input.lamports,
            refund_after_unix: i64::try_from(
                terms_deadline_seconds(terms).ok_or(LegError::Setup(
                    solana_profile::SetupError::BindingMismatch,
                ))?,
            )
            .map_err(|_| LegError::Setup(solana_profile::SetupError::BoundsExceeded))?,
            program_data_hash: input.program_data_hash,
            setup_id: [0; 32],
        };
        binding.setup_id = setup_id(&binding)?;
        Ok(validate_setup_with_profile_digest(
            profile,
            terms,
            binding,
            input.expected_profile_digest(profile),
        )?)
    }

    // ── the four escrow instructions ────────────────────────────────────────

    /// Create the state PDA and the vault, recording both faces of the
    /// condition and the frozen deadline. Signed by the funder.
    pub fn initialize_instruction(&self) -> SolanaInstruction {
        solana_program_client::initialize(&self.setup)
    }

    /// Deposit exactly `amount`. Signed by the funder. For a token asset the
    /// source is the funder's own token account, carried in the plan.
    pub fn fund_instruction(&self) -> Result<SolanaInstruction, LegError> {
        Ok(solana_program_client::fund(
            &self.setup,
            self.funder_token_account,
        )?)
    }

    /// Transfer to the beneficiary against the revealed scalar. No signature
    /// authorizes this: the opening does, which is why the opening is checked
    /// against both faces before it ever reaches here.
    pub fn claim_instruction(
        &self,
        opening: &ConditionOpeningV1,
    ) -> Result<SolanaInstruction, LegError> {
        if opening.lock() != &self.lock {
            return Err(LegError::ForeignOpening);
        }
        Ok(solana_program_client::claim(
            &self.setup,
            opening.escrow_claim_bytes(),
            self.beneficiary_token_account,
        )?)
    }

    /// Transfer back to the refund recipient after the frozen deadline.
    pub fn refund_instruction(&self) -> Result<SolanaInstruction, LegError> {
        Ok(solana_program_client::refund(
            &self.setup,
            self.refund_token_account,
        )?)
    }

    // ── observation ─────────────────────────────────────────────────────────

    /// Decode the escrow state account and refuse one that is not this leg's.
    pub fn read_escrow_state(&self, account_data: &[u8]) -> Result<EscrowStateV1, LegError> {
        let state =
            EscrowStateV1::decode(account_data).map_err(|e| LegError::Wire(e.to_string()))?;
        if state.settlement_id != self.setup.settlement_id()
            || state.setup_id != self.setup.setup_id()
            || state.terms_hash != self.setup.terms_hash()
            || state.dom_adaptor_point != self.lock.dom_adaptor_point()
            || state.claim_point_ed25519 != self.lock.solana_claim_point()
            || state.amount != self.setup.amount()
            || state.refund_after_unix != self.setup.refund_after_unix()
        {
            return Err(LegError::ForeignEscrowState);
        }
        Ok(state)
    }

    /// DOM <- SOL reveal: take the opening from a claimed escrow state. The
    /// state is the durable record, so this works after the claim transaction
    /// has been pruned from the node's transaction history.
    pub fn opening_from_escrow_state(
        &self,
        account_data: &[u8],
    ) -> Result<ConditionOpeningV1, LegError> {
        let state = self.read_escrow_state(account_data)?;
        if state.status != EscrowStatus::Claimed || state.revealed_secret_be == [0; 32] {
            return Err(LegError::NoRevealedSecret);
        }
        Ok(self
            .lock
            .open(Zeroizing::new(state.revealed_secret_be))?)
    }

    /// DOM <- SOL reveal, from the claim transaction's instruction data. Same
    /// opening, read from the transaction instead of the account.
    pub fn opening_from_escrow_claim_data(
        &self,
        instruction_data: &[u8],
    ) -> Result<ConditionOpeningV1, LegError> {
        Ok(self.lock.open_from_escrow_claim_data(instruction_data)?)
    }

    /// SOL <- DOM reveal: take the opening from the DOM claim this leg's
    /// counterparty published. The DOM side extracts the scalar with
    /// `DomClaimOffer::extract`; this only re-checks it against both faces so
    /// that a wrong extraction never becomes an escrow claim.
    pub fn opening_from_dom_secret(
        &self,
        extracted_big_endian: Zeroizing<[u8; 32]>,
    ) -> Result<ConditionOpeningV1, LegError> {
        Ok(self.lock.open(extracted_big_endian)?)
    }
}

fn terms_deadline_seconds(terms: &SettlementTermsV1) -> Option<u64> {
    match terms.counterparty_leg.deadline {
        TimelockSpec::TimestampSeconds { value } => Some(value),
        _ => None,
    }
}

/// A leg plus the secret that opens its condition.
pub struct EstablishedLegV1 {
    leg: SolanaLegV1,
    session: InitializedSolanaSession,
}

impl core::fmt::Debug for EstablishedLegV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EstablishedLegV1")
            .field("leg", &self.leg)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl EstablishedLegV1 {
    pub fn leg(&self) -> &SolanaLegV1 {
        &self.leg
    }

    /// Persist the witness, encrypted, so a restart can rebuild this session.
    ///
    /// Both durable halves must exist for that: the registered public binding,
    /// which `establish` wrote, and this witness. With only the first, a restarted
    /// leg knows what it agreed to and cannot act on it -- the settlement would
    /// have to wait out its timelock instead of completing.
    pub fn persist_witness<S: WitnessMaterialStore>(
        &self,
        witness_store: &S,
        rng: &mut (impl rand::CryptoRng + rand::RngCore),
    ) -> Result<(), LegError> {
        Ok(persist_route_witness(&self.session, witness_store, rng)?)
    }

    /// Rebuild a leg and its session after a restart, from the registered binding
    /// and the encrypted witness.
    ///
    /// Nothing is trusted because it was stored. The schedule is re-derived from
    /// the same public input, the condition is taken from the DLEQ the binding
    /// carries and verified against a context hash computed here, the terms are
    /// rebuilt around it, and `resume_session` re-validates the binding under that
    /// profile and those terms and refuses a witness that does not reproduce the
    /// registered public claim. The setup is then derived independently once more
    /// and must agree with the resumed one.
    pub fn resume<S: WitnessMaterialStore>(
        input: &LegPlanInputV1,
        profile: &SolanaAdapterProfileV1,
        setup_store: &SolanaSetupStore,
        witness_store: &S,
        rng: &mut (impl rand::CryptoRng + rand::RngCore),
    ) -> Result<Self, LegError> {
        let schedule = LegScheduleV1::plan(
            &input.anchor,
            input.chosen_deadline,
            input.now,
            input.network,
            input.validator_clock_ahead_secs,
            input.delays,
        )?;
        let binding = setup_store
            .load(&input.settlement_id)
            .map_err(|error| LegError::Store(error.to_string()))?
            .ok_or(LegError::UnknownSettlement)?;
        let proof = binding.dleq.clone();
        let context = input.proof_context(&schedule);
        let context_hash = proof_context_hash(profile, &context)?;
        let claim = verify_counterparty_bundle(&proof, &input.settlement_id, &context_hash)?;
        let lock = ConditionLockV1::from_verified_claim(claim)?;
        let terms = SolanaLegV1::frozen_terms(input, profile, &schedule, lock.dom_adaptor_point())?;
        let session = resume_session_with_profile_digest(
            profile,
            &terms,
            setup_store,
            witness_store,
            rng,
            input.expected_profile_digest(profile),
        )?;
        let derived = SolanaLegV1::derive_setup(input, profile, &terms, proof)?;
        if derived.setup_id() != session.setup().setup_id()
            || derived.binding_hash() != session.setup().binding_hash()
        {
            return Err(LegError::Setup(solana_profile::SetupError::BindingMismatch));
        }
        Ok(Self {
            leg: SolanaLegV1 {
                profile: *profile,
                terms,
                schedule,
                lock,
                setup: derived,
                funder_token_account: input.funder_token_account,
                beneficiary_token_account: input.beneficiary_token_account,
                refund_token_account: input.refund_token_account,
            },
            session,
        })
    }

    /// The public proof to hand the counterparty. It carries no secret and it
    /// is the only thing the counterparty needs in order to run `accept`.
    pub fn proof(&self) -> BoundCrossCurveProofV1 {
        self.session.with_route_secret(|route| route.proof().clone())
    }

    /// The checked opening. Producing it costs two scalar multiplications and
    /// refuses a secret that does not open both faces, which is the last place
    /// a wrong witness can be caught before it is published on a chain.
    pub fn opening(&self) -> Result<ConditionOpeningV1, LegError> {
        let big_endian = self.session.with_route_secret(|route| {
            route.with_revealed_dom_secret(|secret| Zeroizing::new(secret.expose_scalar_bytes()))
        });
        Ok(self.leg.lock.open(big_endian)?)
    }
}
