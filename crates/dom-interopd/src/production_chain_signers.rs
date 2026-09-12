//! Strict production ownership of the route's participant signing authorities.
//!
//! Stage 8 owns one physical DOM wallet, two independently bound DOM nonce
//! stores and zero, one or two Bitcoin participant authorities. The V1 entrypoint
//! preserves its original single-Bitcoin layout; V6 binds each selected leg separately.  Relay secrets are
//! borrowed only long enough to identify the same participant in both frozen
//! roster snapshots.  No path, scalar, wallet plaintext or generic signer is
//! returned from this module.

use std::path::{Path, PathBuf};

use adapter_btc::roster::BitcoinSignerRoleV1;
use blake2::{digest::consts::U32, Blake2b, Digest as _};
use btc_actuator::{
    BitcoinParticipantClaimAuthorityRequestV1, BitcoinParticipantClaimAuthorityV1,
    BitcoinParticipantNonceVaultV1, BitcoinParticipantRoleV1,
};
use btc_crypto::SecpContext;
use btc_vault::BitcoinNonceSealKeyV1;
use dom_actuator::{
    DomParticipantV1, DomParticipantWalletSessionV1, DomParticipantWalletV1, DomSessionBindingV1,
    DomWalletAuthorityBindingV1, DomWalletSessionLegV1,
};
use dom_vault::DurableNonceVault;
use kaystra_core::{terms::SettlementTermsV1, types::ParticipantId};
use relay::SenderRoleV1;
use route_executor::LegIdV1;
use store::{ProductionStoreBindingV1, Store};
use zeroize::Zeroizing;

use crate::production_config::{
    ProductionBootstrapModeV1, ProductionPathRoleV1, ProductionRoutePinsV1,
    ValidatedProductionBootstrapV1,
};
use crate::production_inputs::{
    AuthenticatedProductionInputsV1, ProductionRosterLegV1, ProductionRoutePositionV1,
};
use crate::production_provisioning::{
    DurableProductionProvisioningJournalV1, ProductionProvisioningStageStateV1,
    ProductionProvisioningStageV1,
};

type Digest32 = [u8; 32];

const MATCH_CONTEXT_SEED_V1: [u8; 32] = [0xC8; 32];
const DOM_STATE_BINDING_DOMAIN_V1: &[u8] = b"DOM-INTEROPD/PRODUCTION-DOM-PARTICIPANT-STATE/V1\0";
const CHAIN_SIGNER_BINDING_DOMAIN_V1: &[u8] =
    b"DOM-INTEROPD/PRODUCTION-CHAIN-SIGNER-AUTHORITIES/V1\0";
const BITCOIN_NONCE_SEAL_KEY_DOMAIN_V1: &[u8] =
    b"DOM-INTEROPD/PRODUCTION-BITCOIN-NONCE-SEAL-KEY/V1\0";

/// Secret-bearing inputs consumed or borrowed while Stage 8 is provisioned.
///
/// Relay secrets remain owned by the later Relay stage.  The wallet passphrase
/// and Bitcoin participant secret move into their sole physical authorities.
pub(crate) struct ProductionChainSignerProvisioningRequestV1<'authority> {
    pub(crate) bootstrap: &'authority ValidatedProductionBootstrapV1,
    pub(crate) inputs: &'authority AuthenticatedProductionInputsV1,
    pub(crate) journal: &'authority mut DurableProductionProvisioningJournalV1,
    pub(crate) upstream_relay_signing_secret: &'authority [u8; 32],
    pub(crate) downstream_relay_signing_secret: &'authority [u8; 32],
    pub(crate) dom_wallet_passphrase: Zeroizing<String>,
    pub(crate) bitcoin_participant_secret: Zeroizing<[u8; 32]>,
}

/// Redacted refusal from strict participant-authority provisioning.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProductionChainSignerErrorV1 {
    #[error("authenticated chain-signer binding is inconsistent")]
    InvalidBinding,
    #[error("local participant credential is not uniquely roster-bound")]
    ParticipantCredentialRefused,
    #[error("chain-signer provisioning journal is inconsistent")]
    ProvisioningRefused,
    #[error("DOM participant state authority is unavailable")]
    DomStateRefused,
    #[error("DOM participant wallet authority is unavailable")]
    DomWalletRefused,
    #[error("Bitcoin participant authority is unavailable")]
    BitcoinAuthorityRefused,
}

/// Sole owner of all route-local participant signing authorities.
///
/// The value has no `Clone`, codec or generic signing method.  Later concrete
/// child authorities may borrow only the typed per-leg views below.
pub(crate) struct ProductionChainSignerAuthoritiesV1 {
    participant_id: ParticipantId,
    relay_role: SenderRoleV1,
    upstream_relay_xonly: Digest32,
    downstream_relay_xonly: Digest32,
    upstream: ProductionDomLegAuthorityV1,
    downstream: ProductionDomLegAuthorityV1,
    dom_wallet: DomParticipantWalletV1,
    bitcoin: [Option<ProductionBitcoinLegAuthorityV6>; 2],
    binding_digest: Digest32,
}

impl core::fmt::Debug for ProductionChainSignerAuthoritiesV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionChainSignerAuthoritiesV1([authority redacted])")
    }
}

struct ProductionBitcoinLegAuthorityV6 {
    authority: BitcoinParticipantClaimAuthorityV1,
    state: BitcoinParticipantNonceVaultV1,
    seal_key: BitcoinNonceSealKeyV1,
}

/// The two credentials are positional and consumed independently. None is
/// required for a non-Bitcoin leg; an extra credential is refused.
pub(crate) struct ProductionChainSignerProvisioningRequestV6<'a> {
    pub(crate) bootstrap: &'a ValidatedProductionBootstrapV1,
    pub(crate) inputs: &'a AuthenticatedProductionInputsV1,
    pub(crate) journal: &'a mut DurableProductionProvisioningJournalV1,
    pub(crate) upstream_relay_signing_secret: &'a [u8; 32],
    pub(crate) downstream_relay_signing_secret: &'a [u8; 32],
    pub(crate) dom_wallet_passphrase: Zeroizing<String>,
    pub(crate) bitcoin_participant_secrets: [Option<Zeroizing<[u8; 32]>>; 2],
}

struct ProductionDomLegAuthorityV1 {
    binding: DomSessionBindingV1,
    state_binding_digest: Digest32,
    nonce_vault: DurableNonceVault,
}

/// Temporary, exact DOM participant authority for one route leg.
///
/// This crate-private composition seam keeps the session binding adjacent to
/// both secret-bearing owners.  It cannot outlive the aggregate owner and it
/// cannot be constructed by a caller.
pub(crate) struct ProductionDomParticipantAuthorityV1<'authority> {
    binding: DomSessionBindingV1,
    nonce_vault: &'authority mut DurableNonceVault,
    wallet: DomParticipantWalletSessionV1<'authority>,
}

impl<'authority> ProductionDomParticipantAuthorityV1<'authority> {
    #[expect(
        dead_code,
        reason = "bitcoin claim path frozen until the authenticated M8 round"
    )]
    pub(crate) const fn binding(&self) -> DomSessionBindingV1 {
        self.binding
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "bitcoin claim path frozen until the authenticated M8 round"
        )
    )]
    pub(crate) fn nonce_vault(&mut self) -> &mut DurableNonceVault {
        self.nonce_vault
    }

    pub(crate) fn wallet(&mut self) -> &mut DomParticipantWalletSessionV1<'authority> {
        &mut self.wallet
    }
}

/// Temporary Bitcoin participant authority paired with its sole nonce store.
pub(crate) struct ProductionBitcoinParticipantAuthorityV1<'authority> {
    leg: LegIdV1,
    authority: &'authority BitcoinParticipantClaimAuthorityV1,
    state: &'authority mut BitcoinParticipantNonceVaultV1,
    nonce_seal_key: &'authority BitcoinNonceSealKeyV1,
}

impl ProductionBitcoinParticipantAuthorityV1<'_> {
    pub(crate) const fn leg(&self) -> LegIdV1 {
        self.leg
    }

    pub(crate) const fn authority(&self) -> &BitcoinParticipantClaimAuthorityV1 {
        self.authority
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "bitcoin claim path frozen until the authenticated M8 round"
        )
    )]
    pub(crate) fn state(&mut self) -> &mut BitcoinParticipantNonceVaultV1 {
        self.state
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "bitcoin claim path frozen until the authenticated M8 round"
        )
    )]
    pub(crate) const fn nonce_seal_key(&self) -> &BitcoinNonceSealKeyV1 {
        self.nonce_seal_key
    }
}

/// One independently revalidated F7/M.8 invocation for the retained signer.
/// Transport orchestration must supply a fresh local capability on each call;
/// no raw caller-created timing window is accepted at this boundary.
pub(crate) struct ProductionBitcoinClaimInvocationV3<'a> {
    pub(crate) authorization: crate::production_f7_m8::ProductionLocalBitcoinM8AuthorizationV2,
    pub(crate) scope: &'a btc_actuator::BitcoinActuationScopeV1,
    pub(crate) session: &'a btc_actuator::BitcoinClaimSessionV1,
    pub(crate) now_ms: u64,
}

/// Completed round minted only by aggregation through the retained local key
/// and nonce vault. It has no codec, key getter or caller-shaped constructor.
pub(crate) struct ProductionBitcoinCompletedClaimV3 {
    leg: LegIdV1,
    session: btc_actuator::BitcoinClaimSessionV1,
    pre_signature: btc_actuator::BitcoinPreSignatureV1,
}

impl ProductionBitcoinCompletedClaimV3 {
    pub(crate) fn into_prepared_materialization_v11(
        self,
        binding: &crate::production_child_btc::ProductionBitcoinClaimBindingV11,
    ) -> Result<
        crate::production_child_btc::ProductionBitcoinClaimMaterializationAuthorityV1,
        settlement_coordinator::ChildAuthorityRefusalV1,
    > {
        crate::production_child_btc::ProductionBitcoinClaimMaterializationAuthorityV1::bind_prepared_v11(
            binding, self.leg, self.session, self.pre_signature,
        )
    }

    pub(crate) fn into_materialization(
        self,
        inputs: &AuthenticatedProductionInputsV1,
        role_plan: &route_composer::ComposedFinalClaimRolePlanV1,
        upstream_scope: &route_composer::FinalClaimSecretSourceScopeV1,
        downstream_scope: &route_composer::FinalClaimSecretSourceScopeV1,
    ) -> Result<
        crate::production_child_btc::ProductionBitcoinClaimMaterializationAuthorityV1,
        settlement_coordinator::ChildAuthorityRefusalV1,
    > {
        crate::production_child_btc::ProductionBitcoinClaimMaterializationAuthorityV1::bind(
            inputs,
            role_plan,
            upstream_scope,
            downstream_scope,
            self.leg,
            self.session,
            self.pre_signature,
        )
    }
}

impl ProductionBitcoinParticipantAuthorityV1<'_> {
    fn claim_context_v3<'a>(
        &'a mut self,
        invocation: ProductionBitcoinClaimInvocationV3<'a>,
    ) -> Result<btc_actuator::BitcoinClaimSigningContextV1<'a>, btc_actuator::BitcoinActuatorErrorV1>
    {
        let authorization = invocation
            .authorization
            .consume_for(self)
            .map_err(|_| btc_actuator::BitcoinActuatorErrorV1::ClaimAuthorityMismatch)?;
        Ok(btc_actuator::BitcoinClaimSigningContextV1 {
            scope: invocation.scope,
            authority: self.authority,
            session: invocation.session,
            authorization,
            seal_key: self.nonce_seal_key,
            participant_state: self.state,
            now_ms: invocation.now_ms,
        })
    }

    pub(crate) fn expose_claim_v3(
        &mut self,
        actuator: &mut btc_actuator::DurableBitcoinActuatorV1,
        invocation: ProductionBitcoinClaimInvocationV3<'_>,
    ) -> Result<btc_actuator::BitcoinClaimMessageV3, btc_actuator::BitcoinActuatorErrorV1> {
        actuator.expose_claim_message_v3(self.claim_context_v3(invocation)?)
    }

    pub(crate) fn produce_claim_v3(
        &mut self,
        actuator: &mut btc_actuator::DurableBitcoinActuatorV1,
        invocation: ProductionBitcoinClaimInvocationV3<'_>,
        peer_nonce: &btc_actuator::BitcoinClaimMessageV3,
    ) -> Result<btc_actuator::BitcoinClaimMessageV3, btc_actuator::BitcoinActuatorErrorV1> {
        actuator.produce_claim_message_v3(self.claim_context_v3(invocation)?, peer_nonce)
    }

    pub(crate) fn aggregate_claim_v3(
        &mut self,
        actuator: &mut btc_actuator::DurableBitcoinActuatorV1,
        invocation: ProductionBitcoinClaimInvocationV3<'_>,
        peer_nonce: &btc_actuator::BitcoinClaimMessageV3,
        peer_partial: &btc_actuator::BitcoinClaimMessageV3,
    ) -> Result<ProductionBitcoinCompletedClaimV3, btc_actuator::BitcoinActuatorErrorV1> {
        let leg = self.leg;
        let session = invocation.session.clone();
        let pre_signature = actuator.aggregate_claim_messages_v3(
            self.claim_context_v3(invocation)?,
            peer_nonce,
            peer_partial,
        )?;
        Ok(ProductionBitcoinCompletedClaimV3 {
            leg,
            session,
            pre_signature,
        })
    }
}

/// Drives the V6 exchange through the retained Stage-8 participant and its
/// actual actuator. Every phase calls the local F7 refresh closure anew.
struct ProductionBitcoinRoundSignerV6<'a, 'owner, F> {
    participant: &'a mut ProductionBitcoinParticipantAuthorityV1<'owner>,
    actuator: &'a mut btc_actuator::DurableBitcoinActuatorV1,
    scope: &'a btc_actuator::BitcoinActuationScopeV1,
    session: &'a btc_actuator::BitcoinClaimSessionV1,
    refresh: F,
}
impl<F> btc_actuator::BitcoinClaimSigningPortV6 for ProductionBitcoinRoundSignerV6<'_, '_, F>
where
    F: FnMut(
        &ProductionBitcoinParticipantAuthorityV1<'_>,
    ) -> Result<
        (
            crate::production_f7_m8::ProductionLocalBitcoinM8AuthorizationV2,
            u64,
        ),
        btc_actuator::BitcoinActuatorErrorV1,
    >,
{
    type Completion = ProductionBitcoinCompletedClaimV3;
    fn expose_nonce(
        &mut self,
    ) -> Result<btc_actuator::BitcoinClaimMessageV3, btc_actuator::BitcoinActuatorErrorV1> {
        let (authorization, now_ms) = (self.refresh)(self.participant)?;
        self.participant.expose_claim_v3(
            self.actuator,
            ProductionBitcoinClaimInvocationV3 {
                authorization,
                now_ms,
                scope: self.scope,
                session: self.session,
            },
        )
    }
    fn produce_partial(
        &mut self,
        peer_nonce: &btc_actuator::BitcoinClaimMessageV3,
    ) -> Result<btc_actuator::BitcoinClaimMessageV3, btc_actuator::BitcoinActuatorErrorV1> {
        let (authorization, now_ms) = (self.refresh)(self.participant)?;
        self.participant.produce_claim_v3(
            self.actuator,
            ProductionBitcoinClaimInvocationV3 {
                authorization,
                now_ms,
                scope: self.scope,
                session: self.session,
            },
            peer_nonce,
        )
    }
    fn complete(
        &mut self,
        peer_nonce: &btc_actuator::BitcoinClaimMessageV3,
        peer_partial: &btc_actuator::BitcoinClaimMessageV3,
    ) -> Result<Self::Completion, btc_actuator::BitcoinActuatorErrorV1> {
        let (authorization, now_ms) = (self.refresh)(self.participant)?;
        self.participant.aggregate_claim_v3(
            self.actuator,
            ProductionBitcoinClaimInvocationV3 {
                authorization,
                now_ms,
                scope: self.scope,
                session: self.session,
            },
            peer_nonce,
            peer_partial,
        )
    }
}
impl ProductionBitcoinParticipantAuthorityV1<'_> {
    pub(crate) fn drive_claim_v6<F>(
        &mut self,
        actuator: &mut btc_actuator::DurableBitcoinActuatorV1,
        scope: &btc_actuator::BitcoinActuationScopeV1,
        session: &btc_actuator::BitcoinClaimSessionV1,
        refresh: F,
        transport: &mut dyn btc_actuator::BitcoinClaimTransportV6,
    ) -> Result<ProductionBitcoinCompletedClaimV3, btc_actuator::BitcoinClaimDriverErrorV6>
    where
        F: FnMut(
            &ProductionBitcoinParticipantAuthorityV1<'_>,
        ) -> Result<
            (
                crate::production_f7_m8::ProductionLocalBitcoinM8AuthorizationV2,
                u64,
            ),
            btc_actuator::BitcoinActuatorErrorV1,
        >,
    {
        btc_actuator::drive_bitcoin_claim_v6(
            &mut ProductionBitcoinRoundSignerV6 {
                participant: self,
                actuator,
                scope,
                session,
                refresh,
            },
            transport,
        )
    }
}

impl ProductionChainSignerAuthoritiesV1 {
    pub(crate) const fn participant_id(&self) -> ParticipantId {
        self.participant_id
    }

    pub(crate) const fn relay_role(&self) -> SenderRoleV1 {
        self.relay_role
    }

    #[expect(
        dead_code,
        reason = "bitcoin claim path frozen until the authenticated M8 round"
    )]
    pub(crate) const fn binding_digest(&self) -> Digest32 {
        self.binding_digest
    }

    pub(crate) fn bitcoin_leg(&self) -> Result<LegIdV1, ProductionChainSignerErrorV1> {
        match (&self.bitcoin[0], &self.bitcoin[1]) {
            (Some(_), None) => Ok(LegIdV1::Upstream),
            (None, Some(_)) => Ok(LegIdV1::Downstream),
            _ => Err(ProductionChainSignerErrorV1::InvalidBinding),
        }
    }

    pub(crate) const fn relay_xonly_key(&self, leg: LegIdV1) -> Digest32 {
        match leg {
            LegIdV1::Upstream => self.upstream_relay_xonly,
            LegIdV1::Downstream => self.downstream_relay_xonly,
        }
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "bitcoin claim path frozen until the authenticated M8 round"
        )
    )]
    pub(crate) const fn dom_state_binding_digest(&self, leg: LegIdV1) -> Digest32 {
        match leg {
            LegIdV1::Upstream => self.upstream.state_binding_digest,
            LegIdV1::Downstream => self.downstream.state_binding_digest,
        }
    }

    pub(crate) const fn dom_binding(&self, leg: LegIdV1) -> DomSessionBindingV1 {
        match leg {
            LegIdV1::Upstream => self.upstream.binding,
            LegIdV1::Downstream => self.downstream.binding,
        }
    }

    pub(crate) fn dom_authority(
        &mut self,
        leg: LegIdV1,
    ) -> Result<ProductionDomParticipantAuthorityV1<'_>, ProductionChainSignerErrorV1> {
        match leg {
            LegIdV1::Upstream => {
                let wallet = self
                    .dom_wallet
                    .session(DomWalletSessionLegV1::Upstream)
                    .map_err(|_| ProductionChainSignerErrorV1::DomWalletRefused)?;
                Ok(ProductionDomParticipantAuthorityV1 {
                    binding: self.upstream.binding,
                    nonce_vault: &mut self.upstream.nonce_vault,
                    wallet,
                })
            }
            LegIdV1::Downstream => {
                let wallet = self
                    .dom_wallet
                    .session(DomWalletSessionLegV1::Downstream)
                    .map_err(|_| ProductionChainSignerErrorV1::DomWalletRefused)?;
                Ok(ProductionDomParticipantAuthorityV1 {
                    binding: self.downstream.binding,
                    nonce_vault: &mut self.downstream.nonce_vault,
                    wallet,
                })
            }
        }
    }

    pub(crate) fn bitcoin_authority(
        &mut self,
        leg: LegIdV1,
    ) -> Result<ProductionBitcoinParticipantAuthorityV1<'_>, ProductionChainSignerErrorV1> {
        let owner = self.bitcoin[usize::from(leg_tag(leg) - 1)]
            .as_mut()
            .ok_or(ProductionChainSignerErrorV1::InvalidBinding)?;
        Ok(ProductionBitcoinParticipantAuthorityV1 {
            leg,
            authority: &owner.authority,
            state: &mut owner.state,
            nonce_seal_key: &owner.seal_key,
        })
    }
}

#[derive(Clone, Copy)]
struct LocalRelayLegIdentityV1 {
    position: ProductionRoutePositionV1,
    participant_id: ParticipantId,
    protocol_index: u8,
    role: SenderRoleV1,
    xonly_key: Digest32,
    roster_snapshot: Digest32,
}

#[derive(Clone, Copy)]
struct LocalRelayIdentityV1 {
    participant_id: ParticipantId,
    role: SenderRoleV1,
    upstream: LocalRelayLegIdentityV1,
    downstream: LocalRelayLegIdentityV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityOpenModeV1 {
    Create,
    ResumeCreate,
    OpenExistingEmpty,
    OpenExisting,
}

/// Provision or reopen the complete Stage 8 signer authority.
pub(crate) fn provision_production_chain_signers_v1(
    request: ProductionChainSignerProvisioningRequestV1<'_>,
) -> Result<ProductionChainSignerAuthoritiesV1, ProductionChainSignerErrorV1> {
    let ProductionChainSignerProvisioningRequestV1 {
        bootstrap,
        inputs,
        journal,
        upstream_relay_signing_secret,
        downstream_relay_signing_secret,
        dom_wallet_passphrase,
        bitcoin_participant_secret,
    } = request;
    let (leg, _) = sole_bitcoin_binding(inputs)?;
    let mut secrets = [None, None];
    secrets[usize::from(leg_tag(leg) - 1)] = Some(bitcoin_participant_secret);
    provision_chain_signers_v6(
        ProductionChainSignerProvisioningRequestV6 {
            bootstrap,
            inputs,
            journal,
            upstream_relay_signing_secret,
            downstream_relay_signing_secret,
            dom_wallet_passphrase,
            bitcoin_participant_secrets: secrets,
        },
        true,
    )
}

/// Generalized Stage-8 entrypoint consumed by the V11 composition root.
/// The historical V10 wrapper keeps its original single-Bitcoin layout.
pub(crate) fn provision_production_chain_signers_v6(
    request: ProductionChainSignerProvisioningRequestV6<'_>,
) -> Result<ProductionChainSignerAuthoritiesV1, ProductionChainSignerErrorV1> {
    provision_chain_signers_v6(request, false)
}

fn provision_chain_signers_v6(
    request: ProductionChainSignerProvisioningRequestV6<'_>,
    legacy: bool,
) -> Result<ProductionChainSignerAuthoritiesV1, ProductionChainSignerErrorV1> {
    let ProductionChainSignerProvisioningRequestV6 {
        bootstrap,
        inputs,
        journal,
        upstream_relay_signing_secret,
        downstream_relay_signing_secret,
        dom_wallet_passphrase,
        mut bitcoin_participant_secrets,
    } = request;
    let selected = [
        inputs.bitcoin_session(LegIdV1::Upstream).is_some(),
        inputs.bitcoin_session(LegIdV1::Downstream).is_some(),
    ];
    require_bitcoin_credentials_v6(selected, &bitcoin_participant_secrets)?;
    let open_mode = stage_open_mode(bootstrap, journal)?;
    let pins = bootstrap.config().pins();
    let secp = SecpContext::new(&MATCH_CONTEXT_SEED_V1);
    let rosters = inputs.roster_bundle();
    if rosters.route_id() != pins.route_id || rosters.network_id() != pins.network_id {
        return Err(ProductionChainSignerErrorV1::InvalidBinding);
    }
    let upstream_identity =
        resolve_local_relay_identity(&secp, &rosters.legs()[0], upstream_relay_signing_secret)?;
    let downstream_identity =
        resolve_local_relay_identity(&secp, &rosters.legs()[1], downstream_relay_signing_secret)?;
    let local = require_same_local_participant(upstream_identity, downstream_identity)?;
    crosscheck_relay_registry(inputs, local.upstream)?;
    crosscheck_relay_registry(inputs, local.downstream)?;

    let dom_deployment = inputs
        .admission()
        .dom_deployment_capability()
        .map_err(|_| ProductionChainSignerErrorV1::InvalidBinding)?;
    let upstream_binding =
        dom_session_binding(inputs, LegIdV1::Upstream, local.upstream, dom_deployment)?;
    let downstream_binding = dom_session_binding(
        inputs,
        LegIdV1::Downstream,
        local.downstream,
        dom_deployment,
    )?;
    let wallet_binding = DomWalletAuthorityBindingV1::new(upstream_binding, downstream_binding)
        .map_err(|_| ProductionChainSignerErrorV1::InvalidBinding)?;

    let upstream_state_binding = dom_state_binding_digest(
        pins,
        local.upstream,
        upstream_binding,
        wallet_binding.digest(),
    );
    let downstream_state_binding = dom_state_binding_digest(
        pins,
        local.downstream,
        downstream_binding,
        wallet_binding.digest(),
    );
    if upstream_state_binding == downstream_state_binding {
        return Err(ProductionChainSignerErrorV1::InvalidBinding);
    }
    // All roster/key bindings are checked before opening the first nonce store.
    let mut pending = [None, None];
    for (index, leg) in [LegIdV1::Upstream, LegIdV1::Downstream]
        .into_iter()
        .enumerate()
    {
        let Some(binding) = inputs.bitcoin_session(leg) else {
            continue;
        };
        validate_bitcoin_binding(inputs, pins, leg, binding)?;
        let participant = binding
            .roster()
            .participants()
            .iter()
            .find(|p| p.participant_id == local.participant_id.0)
            .ok_or(ProductionChainSignerErrorV1::InvalidBinding)?;
        let role = match participant.role {
            BitcoinSignerRoleV1::Maker => BitcoinParticipantRoleV1::Maker,
            BitcoinSignerRoleV1::Taker => BitcoinParticipantRoleV1::Taker,
        };
        let mut secret = bitcoin_participant_secrets[index]
            .take()
            .ok_or(ProductionChainSignerErrorV1::InvalidBinding)?;
        let seal_key = BitcoinNonceSealKeyV1::new(derive_bitcoin_nonce_seal_key_v1(
            &secret,
            pins.route_id,
            binding.terms_digest(),
            local.participant_id,
            leg,
            role,
        ))
        .map_err(|_| ProductionChainSignerErrorV1::BitcoinAuthorityRefused)?;
        let authority = BitcoinParticipantClaimAuthorityV1::authorize_local_key(
            BitcoinParticipantClaimAuthorityRequestV1 {
                deployment: binding.deployment(),
                route_id: pins.route_id,
                terms_digest: binding.terms_digest(),
                participant_id: local.participant_id.0,
                role,
                expected_public_key: participant.compressed_key,
            },
            &mut secret,
        )
        .map_err(|_| ProductionChainSignerErrorV1::BitcoinAuthorityRefused)?;
        pending[index] = Some((authority, seal_key));
    }
    let mut authority_paths = Vec::new();
    for (index, present) in selected.into_iter().enumerate() {
        if present {
            authority_paths.push(if legacy {
                bootstrap
                    .layout()
                    .path(ProductionPathRoleV1::BitcoinParticipantState)
                    .to_owned()
            } else {
                bootstrap.layout().state_dir().join(if index == 0 {
                    "bitcoin-upstream-participant.sqlite3"
                } else {
                    "bitcoin-downstream-participant.sqlite3"
                })
            });
        }
    }
    if !legacy {
        // Every manifest reference is already lexical-canonical under the
        // canonical state root. Compare names without touching an unselected
        // chain's parent directory: a SOL/XMR route does not own that resource.
        // Reserve inactive names as well, so a later configuration cannot
        // reinterpret a Bitcoin nonce vault as an actuator or input artifact.
        let mut configured_paths: Vec<PathBuf> = ProductionPathRoleV1::ALL
            .into_iter()
            .map(|role| bootstrap.layout().path(role).to_owned())
            .collect();
        for path in [
            bootstrap.layout().contracts_transport_identity_store(),
            bootstrap.layout().contracts_budget_policy(),
            bootstrap.layout().contracts_bootstrap(),
            bootstrap.layout().refund_arming_database(),
        ] {
            if let Some(path) = path {
                configured_paths.push(path.to_owned());
            }
        }
        for role in crate::production_config::ProductionF6PathRoleV4::ALL {
            if let Some(path) = bootstrap.layout().f6_path_v4(role) {
                configured_paths.push(path.to_owned());
            }
        }
        for role in crate::production_config::ProductionF6PathRoleV8::ALL {
            if let Some(path) = bootstrap.layout().f6_path_v8(role) {
                configured_paths.push(path.to_owned());
            }
        }
        if let Some(fields) = bootstrap.config().universal_v11() {
            for resources in &fields.legs {
                configured_paths.push(
                    bootstrap
                        .layout()
                        .state_dir()
                        .join(&resources.actuator_store),
                );
                configured_paths.push(
                    bootstrap
                        .layout()
                        .state_dir()
                        .join(&resources.authority_bundle),
                );
            }
        }
        for path in &authority_paths {
            for other in &configured_paths {
                if path.starts_with(other) || other.starts_with(path) {
                    return Err(ProductionChainSignerErrorV1::InvalidBinding);
                }
            }
        }
    }
    authority_paths.push(
        bootstrap
            .layout()
            .path(ProductionPathRoleV1::DomUpstreamParticipantState)
            .to_owned(),
    );
    authority_paths.push(
        bootstrap
            .layout()
            .path(ProductionPathRoleV1::DomDownstreamParticipantState)
            .to_owned(),
    );
    require_distinct_authority_paths_v6(&authority_paths)?;
    let path_refs: Vec<_> = authority_paths.iter().map(PathBuf::as_path).collect();
    let modes = ordered_authority_modes_v6(&path_refs, open_mode)?;
    let mut cursor = 0;
    let mut bitcoin = [None, None];
    for (index, entry) in pending.into_iter().enumerate() {
        if let Some((authority, seal_key)) = entry {
            let state = open_bitcoin_participant_state(
                &authority_paths[cursor],
                &authority,
                modes[cursor],
            )?;
            if state.authority_digest() != authority.authority_digest() {
                return Err(ProductionChainSignerErrorV1::BitcoinAuthorityRefused);
            }
            bitcoin[index] = Some(ProductionBitcoinLegAuthorityV6 {
                authority,
                state,
                seal_key,
            });
            cursor += 1;
        }
    }
    let upstream_vault = open_dom_nonce_vault(
        &authority_paths[cursor],
        upstream_state_binding,
        modes[cursor],
    )?;
    let downstream_vault = open_dom_nonce_vault(
        &authority_paths[cursor + 1],
        downstream_state_binding,
        modes[cursor + 1],
    )?;

    let dom_wallet = DomParticipantWalletV1::open_existing(
        bootstrap.layout().path(ProductionPathRoleV1::DomWallet),
        dom_wallet_passphrase,
        wallet_binding,
    )
    .map_err(|_| ProductionChainSignerErrorV1::DomWalletRefused)?;
    if dom_wallet.authority_binding() != wallet_binding {
        return Err(ProductionChainSignerErrorV1::DomWalletRefused);
    }

    let binding_digest = if legacy {
        let (bitcoin_leg, _) = sole_bitcoin_binding(inputs)?;
        let owner = bitcoin[usize::from(leg_tag(bitcoin_leg) - 1)]
            .as_ref()
            .ok_or(ProductionChainSignerErrorV1::InvalidBinding)?;
        chain_signer_binding_digest(ChainSignerBindingMaterialV1 {
            pins,
            participant_id: local.participant_id,
            role: local.role,
            upstream_xonly: local.upstream.xonly_key,
            downstream_xonly: local.downstream.xonly_key,
            upstream_state_binding,
            downstream_state_binding,
            wallet_binding: wallet_binding.digest(),
            bitcoin_leg,
            bitcoin_authority: owner.authority.authority_digest(),
            bitcoin_nonce_seal_key_id: *owner.seal_key.key_id(),
        })
    } else {
        let mut h = Blake2b::<U32>::new();
        h.update(b"DOM-INTEROPD/PRODUCTION-CHAIN-SIGNER-AUTHORITIES/V6\0");
        hash_route_pins(&mut h, pins);
        h.update(local.participant_id.0);
        h.update([sender_role_tag(local.role)]);
        h.update(local.upstream.xonly_key);
        h.update(local.downstream.xonly_key);
        h.update(upstream_state_binding);
        h.update(downstream_state_binding);
        h.update(wallet_binding.digest());
        for (index, owner) in bitcoin.iter().enumerate() {
            h.update([index as u8 + 1, u8::from(owner.is_some())]);
            if let Some(owner) = owner {
                h.update(owner.authority.authority_digest());
                h.update(owner.seal_key.key_id());
            }
        }
        h.finalize().into()
    };
    if binding_digest == [0; 32] {
        return Err(ProductionChainSignerErrorV1::InvalidBinding);
    }
    if open_mode != AuthorityOpenModeV1::OpenExisting {
        journal
            .complete(ProductionProvisioningStageV1::ChainSignerAuthorities)
            .map_err(|_| ProductionChainSignerErrorV1::ProvisioningRefused)?;
    }

    Ok(ProductionChainSignerAuthoritiesV1 {
        participant_id: local.participant_id,
        relay_role: local.role,
        upstream_relay_xonly: local.upstream.xonly_key,
        downstream_relay_xonly: local.downstream.xonly_key,
        upstream: ProductionDomLegAuthorityV1 {
            binding: upstream_binding,
            state_binding_digest: upstream_state_binding,
            nonce_vault: upstream_vault,
        },
        downstream: ProductionDomLegAuthorityV1 {
            binding: downstream_binding,
            state_binding_digest: downstream_state_binding,
            nonce_vault: downstream_vault,
        },
        dom_wallet,
        bitcoin,
        binding_digest,
    })
}

fn stage_open_mode(
    bootstrap: &ValidatedProductionBootstrapV1,
    journal: &mut DurableProductionProvisioningJournalV1,
) -> Result<AuthorityOpenModeV1, ProductionChainSignerErrorV1> {
    let stage = ProductionProvisioningStageV1::ChainSignerAuthorities;
    let prior = journal
        .stage_state(stage)
        .map_err(|_| ProductionChainSignerErrorV1::ProvisioningRefused)?;
    match bootstrap.config().mode() {
        ProductionBootstrapModeV1::Create => {
            let begun = journal
                .begin(stage)
                .map_err(|_| ProductionChainSignerErrorV1::ProvisioningRefused)?;
            match (prior, begun) {
                (
                    ProductionProvisioningStageStateV1::Absent,
                    ProductionProvisioningStageStateV1::Started,
                ) => Ok(AuthorityOpenModeV1::Create),
                (
                    ProductionProvisioningStageStateV1::Started,
                    ProductionProvisioningStageStateV1::Started,
                ) => Ok(AuthorityOpenModeV1::ResumeCreate),
                (
                    ProductionProvisioningStageStateV1::Complete,
                    ProductionProvisioningStageStateV1::Complete,
                ) => Ok(AuthorityOpenModeV1::OpenExisting),
                _ => Err(ProductionChainSignerErrorV1::ProvisioningRefused),
            }
        }
        ProductionBootstrapModeV1::ReopenExisting => {
            if prior == ProductionProvisioningStageStateV1::Complete {
                Ok(AuthorityOpenModeV1::OpenExisting)
            } else {
                Err(ProductionChainSignerErrorV1::ProvisioningRefused)
            }
        }
    }
}

fn resolve_local_relay_identity(
    secp: &SecpContext,
    leg: &ProductionRosterLegV1,
    secret: &[u8; 32],
) -> Result<LocalRelayLegIdentityV1, ProductionChainSignerErrorV1> {
    let xonly_key = secp
        .xonly_public_key(secret)
        .map_err(|_| ProductionChainSignerErrorV1::ParticipantCredentialRefused)?;
    let mut matches = leg
        .members
        .iter()
        .enumerate()
        .filter(|(_, member)| member.xonly_key == xonly_key);
    let (index, member) = matches
        .next()
        .ok_or(ProductionChainSignerErrorV1::ParticipantCredentialRefused)?;
    if matches.next().is_some() {
        return Err(ProductionChainSignerErrorV1::ParticipantCredentialRefused);
    }
    if matches!(member.role, SenderRoleV1::Observer) {
        return Err(ProductionChainSignerErrorV1::ParticipantCredentialRefused);
    }
    let protocol_index = u8::try_from(index)
        .map_err(|_| ProductionChainSignerErrorV1::ParticipantCredentialRefused)?;
    Ok(LocalRelayLegIdentityV1 {
        position: leg.position,
        participant_id: member.participant_id,
        protocol_index,
        role: member.role,
        xonly_key,
        roster_snapshot: leg.roster_snapshot,
    })
}

fn require_same_local_participant(
    upstream: LocalRelayLegIdentityV1,
    downstream: LocalRelayLegIdentityV1,
) -> Result<LocalRelayIdentityV1, ProductionChainSignerErrorV1> {
    if upstream.position != ProductionRoutePositionV1::Upstream
        || downstream.position != ProductionRoutePositionV1::Downstream
        || upstream.participant_id != downstream.participant_id
        || upstream.role != downstream.role
        || upstream.xonly_key == downstream.xonly_key
    {
        return Err(ProductionChainSignerErrorV1::ParticipantCredentialRefused);
    }
    Ok(LocalRelayIdentityV1 {
        participant_id: upstream.participant_id,
        role: upstream.role,
        upstream,
        downstream,
    })
}

fn crosscheck_relay_registry(
    inputs: &AuthenticatedProductionInputsV1,
    identity: LocalRelayLegIdentityV1,
) -> Result<(), ProductionChainSignerErrorV1> {
    let member = inputs
        .roster_registry()
        .snapshot(&identity.roster_snapshot)
        .and_then(|snapshot| snapshot.member(&identity.participant_id))
        .ok_or(ProductionChainSignerErrorV1::InvalidBinding)?;
    if member.xonly_key != identity.xonly_key || member.role != identity.role {
        return Err(ProductionChainSignerErrorV1::InvalidBinding);
    }
    Ok(())
}

fn dom_session_binding(
    inputs: &AuthenticatedProductionInputsV1,
    leg: LegIdV1,
    local: LocalRelayLegIdentityV1,
    deployment: deployment_registry::ResolvedDomDeploymentV1,
) -> Result<DomSessionBindingV1, ProductionChainSignerErrorV1> {
    let terms = terms_for_leg(inputs, leg);
    if terms.roster[usize::from(local.protocol_index)] != local.participant_id {
        return Err(ProductionChainSignerErrorV1::InvalidBinding);
    }
    let participant = DomParticipantV1::new(local.participant_id.0, local.protocol_index)
        .map_err(|_| ProductionChainSignerErrorV1::InvalidBinding)?;
    let terms_digest = terms
        .terms_hash()
        .map_err(|_| ProductionChainSignerErrorV1::InvalidBinding)?;
    DomSessionBindingV1::from_resolved_deployment(
        inputs.admission().route_id(),
        terms.session_id.0,
        participant,
        terms_digest,
        deployment,
    )
    .map_err(|_| ProductionChainSignerErrorV1::InvalidBinding)
}

fn terms_for_leg(inputs: &AuthenticatedProductionInputsV1, leg: LegIdV1) -> &SettlementTermsV1 {
    match leg {
        LegIdV1::Upstream => inputs.composition().upstream(),
        LegIdV1::Downstream => inputs.composition().downstream(),
    }
}

fn sole_bitcoin_binding(
    inputs: &AuthenticatedProductionInputsV1,
) -> Result<
    (
        LegIdV1,
        &crate::production_inputs::AuthenticatedBitcoinParticipantBindingsV1,
    ),
    ProductionChainSignerErrorV1,
> {
    match (
        inputs.bitcoin_session(LegIdV1::Upstream),
        inputs.bitcoin_session(LegIdV1::Downstream),
    ) {
        (Some(binding), None) => Ok((LegIdV1::Upstream, binding)),
        (None, Some(binding)) => Ok((LegIdV1::Downstream, binding)),
        _ => Err(ProductionChainSignerErrorV1::InvalidBinding),
    }
}

fn validate_bitcoin_binding(
    inputs: &AuthenticatedProductionInputsV1,
    pins: ProductionRoutePinsV1,
    leg: LegIdV1,
    binding: &crate::production_inputs::AuthenticatedBitcoinParticipantBindingsV1,
) -> Result<(), ProductionChainSignerErrorV1> {
    let terms = terms_for_leg(inputs, leg);
    let expected_position = match leg {
        LegIdV1::Upstream => ProductionRoutePositionV1::Upstream,
        LegIdV1::Downstream => ProductionRoutePositionV1::Downstream,
    };
    let terms_digest = terms
        .terms_hash()
        .map_err(|_| ProductionChainSignerErrorV1::InvalidBinding)?;
    if binding.position() != expected_position
        || binding.network_id() != pins.network_id
        || binding.route_id() != pins.route_id
        || binding.session_id() != terms.session_id.0
        || binding.terms_digest() != terms_digest
        || binding.deployment().registry_digest() != pins.registry_manifest_digest
        || binding.deployment().registry_epoch() < pins.registry_minimum_epoch
        || binding.deployment().profile().chain_id != terms.counterparty_leg.chain_id
        || binding.deployment().profile_digest() != terms.counterparty_leg.adapter_profile_hash
        || [
            binding.roster().participants()[0].participant_id,
            binding.roster().participants()[1].participant_id,
        ] != terms.roster.map(|participant| participant.0)
    {
        return Err(ProductionChainSignerErrorV1::InvalidBinding);
    }
    Ok(())
}

fn open_dom_nonce_vault(
    path: &Path,
    binding_digest: Digest32,
    mode: AuthorityOpenModeV1,
) -> Result<DurableNonceVault, ProductionChainSignerErrorV1> {
    let binding = ProductionStoreBindingV1::new(binding_digest)
        .map_err(|_| ProductionChainSignerErrorV1::DomStateRefused)?;
    let mut store = match mode {
        AuthorityOpenModeV1::Create => Store::create_production(path, binding),
        AuthorityOpenModeV1::ResumeCreate => Store::resume_create_production(path, binding),
        AuthorityOpenModeV1::OpenExistingEmpty | AuthorityOpenModeV1::OpenExisting => {
            Store::open_production(path, binding)
        }
    }
    .map_err(|_| ProductionChainSignerErrorV1::DomStateRefused)?;
    if mode == AuthorityOpenModeV1::OpenExistingEmpty {
        store
            .require_empty_production()
            .map_err(|_| ProductionChainSignerErrorV1::DomStateRefused)?;
    }
    DurableNonceVault::open_production(store)
        .map_err(|_| ProductionChainSignerErrorV1::DomStateRefused)
}

fn open_bitcoin_participant_state(
    path: &Path,
    authority: &BitcoinParticipantClaimAuthorityV1,
    mode: AuthorityOpenModeV1,
) -> Result<BitcoinParticipantNonceVaultV1, ProductionChainSignerErrorV1> {
    let state = match mode {
        AuthorityOpenModeV1::Create => BitcoinParticipantNonceVaultV1::create(path, authority),
        AuthorityOpenModeV1::ResumeCreate => {
            BitcoinParticipantNonceVaultV1::resume_create_production(path, authority)
        }
        AuthorityOpenModeV1::OpenExistingEmpty | AuthorityOpenModeV1::OpenExisting => {
            BitcoinParticipantNonceVaultV1::open_existing(path, authority)
        }
    }
    .map_err(|_| ProductionChainSignerErrorV1::BitcoinAuthorityRefused)?;
    if mode == AuthorityOpenModeV1::OpenExistingEmpty {
        state
            .require_empty_production()
            .map_err(|_| ProductionChainSignerErrorV1::BitcoinAuthorityRefused)?;
    }
    Ok(state)
}

#[cfg(test)]
fn ordered_authority_open_modes(
    paths: [&Path; 3],
    stage_mode: AuthorityOpenModeV1,
) -> Result<[AuthorityOpenModeV1; 3], ProductionChainSignerErrorV1> {
    ordered_authority_modes_v6(&paths, stage_mode)?
        .try_into()
        .map_err(|_| ProductionChainSignerErrorV1::ProvisioningRefused)
}

fn ordered_authority_modes_v6(
    paths: &[&Path],
    stage_mode: AuthorityOpenModeV1,
) -> Result<Vec<AuthorityOpenModeV1>, ProductionChainSignerErrorV1> {
    if !(2..=4).contains(&paths.len()) {
        return Err(ProductionChainSignerErrorV1::InvalidBinding);
    }
    if stage_mode != AuthorityOpenModeV1::ResumeCreate {
        return Ok(vec![stage_mode; paths.len()]);
    }
    let mut prefix = 0;
    let mut absent_seen = false;
    for path in paths {
        let database = path_present(path)?;
        let lock = path_present(&lock_path(path))?;
        if (database && !lock) || (lock && absent_seen) {
            return Err(ProductionChainSignerErrorV1::ProvisioningRefused);
        }
        if lock {
            prefix += 1;
        } else {
            absent_seen = true;
        }
    }
    Ok((0..paths.len())
        .map(|i| {
            if i >= prefix {
                AuthorityOpenModeV1::Create
            } else if i + 1 == prefix {
                AuthorityOpenModeV1::ResumeCreate
            } else {
                AuthorityOpenModeV1::OpenExistingEmpty
            }
        })
        .collect())
}

fn require_bitcoin_credentials_v6(
    selected: [bool; 2],
    credentials: &[Option<Zeroizing<[u8; 32]>>; 2],
) -> Result<(), ProductionChainSignerErrorV1> {
    for index in 0..2 {
        if selected[index] != credentials[index].is_some()
            || credentials[index]
                .as_ref()
                .is_some_and(|key| key.as_slice() == [0; 32])
        {
            return Err(ProductionChainSignerErrorV1::InvalidBinding);
        }
    }
    Ok(())
}

fn require_distinct_authority_paths_v6(
    paths: &[PathBuf],
) -> Result<(), ProductionChainSignerErrorV1> {
    use std::os::unix::fs::MetadataExt;
    let mut names = Vec::new();
    let mut files = Vec::new();
    for path in paths {
        let parent = path
            .parent()
            .ok_or(ProductionChainSignerErrorV1::InvalidBinding)?;
        let name = parent
            .canonicalize()
            .map_err(|_| ProductionChainSignerErrorV1::ProvisioningRefused)?
            .join(
                path.file_name()
                    .ok_or(ProductionChainSignerErrorV1::InvalidBinding)?,
            );
        if names.contains(&name) {
            return Err(ProductionChainSignerErrorV1::InvalidBinding);
        }
        names.push(name);
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                if !meta.is_file() || meta.file_type().is_symlink() || meta.nlink() != 1 {
                    return Err(ProductionChainSignerErrorV1::InvalidBinding);
                }
                let identity = (meta.dev(), meta.ino());
                if files.contains(&identity) {
                    return Err(ProductionChainSignerErrorV1::InvalidBinding);
                }
                files.push(identity);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ProductionChainSignerErrorV1::ProvisioningRefused),
        }
    }
    Ok(())
}

fn path_present(path: &Path) -> Result<bool, ProductionChainSignerErrorV1> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ProductionChainSignerErrorV1::ProvisioningRefused),
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

fn dom_state_binding_digest(
    pins: ProductionRoutePinsV1,
    local: LocalRelayLegIdentityV1,
    binding: DomSessionBindingV1,
    wallet_binding_digest: Digest32,
) -> Digest32 {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(DOM_STATE_BINDING_DOMAIN_V1);
    hash_route_pins(&mut hasher, pins);
    hasher.update([position_tag(local.position)]);
    hasher.update(local.participant_id.0);
    hasher.update([local.protocol_index]);
    hasher.update([sender_role_tag(local.role)]);
    hasher.update(local.xonly_key);
    hasher.update(local.roster_snapshot);
    hash_dom_binding(&mut hasher, binding);
    hasher.update(wallet_binding_digest);
    hasher.finalize().into()
}

fn hash_dom_binding(hasher: &mut Blake2b<U32>, binding: DomSessionBindingV1) {
    let identity = binding.runtime_identity();
    hasher.update(binding.route_id());
    hasher.update(binding.session_id());
    hasher.update(binding.participant().participant_id());
    hasher.update([binding.participant().protocol_index()]);
    hasher.update(binding.chain_id());
    hasher.update(binding.genesis_hash());
    hasher.update(identity.network.label().as_bytes());
    hasher.update(identity.network_magic.to_be_bytes());
    hasher.update(identity.protocol_version.to_be_bytes());
    hasher.update([identity.range_proof_serialization_version]);
    hasher.update(binding.terms_digest());
    hasher.update(binding.profile_digest());
    hasher.update(binding.deployment_digest());
    hasher.update(binding.asset_binding_digest());
    hasher.update(binding.registry_epoch().to_be_bytes());
    hasher.update(binding.min_confirmations().to_be_bytes());
    hasher.update(binding.max_reorg_depth().to_be_bytes());
}

struct ChainSignerBindingMaterialV1 {
    pins: ProductionRoutePinsV1,
    participant_id: ParticipantId,
    role: SenderRoleV1,
    upstream_xonly: Digest32,
    downstream_xonly: Digest32,
    upstream_state_binding: Digest32,
    downstream_state_binding: Digest32,
    wallet_binding: Digest32,
    bitcoin_leg: LegIdV1,
    bitcoin_authority: Digest32,
    bitcoin_nonce_seal_key_id: Digest32,
}

fn chain_signer_binding_digest(material: ChainSignerBindingMaterialV1) -> Digest32 {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(CHAIN_SIGNER_BINDING_DOMAIN_V1);
    hash_route_pins(&mut hasher, material.pins);
    hasher.update(material.participant_id.0);
    hasher.update([sender_role_tag(material.role)]);
    hasher.update(material.upstream_xonly);
    hasher.update(material.downstream_xonly);
    hasher.update(material.upstream_state_binding);
    hasher.update(material.downstream_state_binding);
    hasher.update(material.wallet_binding);
    hasher.update([leg_tag(material.bitcoin_leg)]);
    hasher.update(material.bitcoin_authority);
    hasher.update(material.bitcoin_nonce_seal_key_id);
    hasher.finalize().into()
}

fn derive_bitcoin_nonce_seal_key_v1(
    participant_secret: &[u8; 32],
    route_id: Digest32,
    terms_digest: Digest32,
    participant_id: ParticipantId,
    leg: LegIdV1,
    role: BitcoinParticipantRoleV1,
) -> Digest32 {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(BITCOIN_NONCE_SEAL_KEY_DOMAIN_V1);
    hasher.update(route_id);
    hasher.update(terms_digest);
    hasher.update(participant_id.0);
    hasher.update([leg_tag(leg)]);
    hasher.update([match role {
        BitcoinParticipantRoleV1::Maker => 1,
        BitcoinParticipantRoleV1::Taker => 2,
    }]);
    hasher.update(participant_secret);
    hasher.finalize().into()
}

fn hash_route_pins(hasher: &mut Blake2b<U32>, pins: ProductionRoutePinsV1) {
    hasher.update(pins.network_id);
    hasher.update(pins.route_id);
    hasher.update(pins.registry_manifest_digest);
    hasher.update(pins.registry_minimum_epoch.to_be_bytes());
    hasher.update(pins.registry_authority_set_digest);
    hasher.update(pins.time_policy_authority_set_digest);
    hasher.update(pins.time_evidence_authority_set_digest);
    hasher.update(pins.upstream_terms_digest);
    hasher.update(pins.downstream_terms_digest);
    hasher.update(pins.route_scope_digest);
    hasher.update(pins.participant_bindings_digest);
    hasher.update(pins.relay_binding_digest);
    hasher.update(pins.time_policy_digest);
    hasher.update(pins.time_evidence_digest);
    hasher.update(pins.process_owner_id);
    hasher.update(pins.coordinator_id);
    hasher.update(pins.coordinator_plan_authority_id);
    hasher.update(pins.actuator_bindings_digest);
    hasher.update(pins.solver_inventory_binding_digest);
}

const fn position_tag(position: ProductionRoutePositionV1) -> u8 {
    match position {
        ProductionRoutePositionV1::Upstream => 1,
        ProductionRoutePositionV1::Downstream => 2,
    }
}

const fn leg_tag(leg: LegIdV1) -> u8 {
    match leg {
        LegIdV1::Upstream => 1,
        LegIdV1::Downstream => 2,
    }
}

const fn sender_role_tag(role: SenderRoleV1) -> u8 {
    match role {
        SenderRoleV1::Initiator => 1,
        SenderRoleV1::Solver => 2,
        SenderRoleV1::Observer => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_inputs::{ProductionRosterLegV1, ProductionRosterMemberV1};

    const PARTICIPANT_A: ParticipantId = ParticipantId([0x11; 32]);
    const PARTICIPANT_B: ParticipantId = ParticipantId([0x22; 32]);
    const UPSTREAM_SECRET: [u8; 32] = [0x31; 32];
    const DOWNSTREAM_SECRET: [u8; 32] = [0x32; 32];

    fn roster_leg(
        secp: &SecpContext,
        position: ProductionRoutePositionV1,
        local_secret: &[u8; 32],
        local_participant: ParticipantId,
        local_role: SenderRoleV1,
    ) -> ProductionRosterLegV1 {
        let local_key = secp
            .xonly_public_key(local_secret)
            .expect("valid local key");
        let other_secret = if local_secret == &UPSTREAM_SECRET {
            [0x41; 32]
        } else {
            [0x42; 32]
        };
        let other_key = secp
            .xonly_public_key(&other_secret)
            .expect("valid other key");
        let other_participant = if local_participant == PARTICIPANT_A {
            PARTICIPANT_B
        } else {
            PARTICIPANT_A
        };
        let other_role = match local_role {
            SenderRoleV1::Initiator => SenderRoleV1::Solver,
            SenderRoleV1::Solver => SenderRoleV1::Initiator,
            SenderRoleV1::Observer => SenderRoleV1::Initiator,
        };
        let mut members = [
            ProductionRosterMemberV1 {
                participant_id: local_participant,
                xonly_key: local_key,
                role: local_role,
            },
            ProductionRosterMemberV1 {
                participant_id: other_participant,
                xonly_key: other_key,
                role: other_role,
            },
        ];
        members.sort_by_key(|member| member.participant_id);
        ProductionRosterLegV1 {
            position,
            session_id: [position_tag(position); 32],
            roster_snapshot: [position_tag(position) + 2; 32],
            policy_version: 1,
            members,
        }
    }

    #[test]
    fn v6_credential_shape_covers_all_sixteen_pairs_without_extra_bitcoin_keys() {
        for first in 0..4 {
            for second in 0..4 {
                let selected = [first == 0, second == 0];
                let credentials = selected.map(|yes| yes.then(|| Zeroizing::new([7; 32])));
                assert!(require_bitcoin_credentials_v6(selected, &credentials).is_ok());
                for index in 0..2 {
                    let mut changed = selected.map(|yes| yes.then(|| Zeroizing::new([7; 32])));
                    changed[index] = if changed[index].is_some() {
                        None
                    } else {
                        Some(Zeroizing::new([8; 32]))
                    };
                    assert!(require_bitcoin_credentials_v6(selected, &changed).is_err());
                }
            }
        }
        assert!(require_bitcoin_credentials_v6(
            [true, false],
            &[Some(Zeroizing::new([0; 32])), None]
        )
        .is_err());
    }

    #[test]
    fn v6_every_two_three_and_four_store_crash_prefix_resumes_only_its_last_owner() {
        for count in 2..=4 {
            for prefix in 0..=count {
                let dir = tempfile::tempdir().expect("state directory");
                let paths: Vec<_> = (0..count)
                    .map(|i| dir.path().join(format!("authority-{i}.sqlite3")))
                    .collect();
                for path in paths.iter().take(prefix) {
                    std::fs::File::create(lock_path(path)).expect("published prefix");
                }
                let refs: Vec<_> = paths.iter().map(PathBuf::as_path).collect();
                let modes = ordered_authority_modes_v6(&refs, AuthorityOpenModeV1::ResumeCreate)
                    .expect("valid prefix");
                for (index, mode) in modes.into_iter().enumerate() {
                    assert_eq!(
                        mode,
                        if index >= prefix {
                            AuthorityOpenModeV1::Create
                        } else if index + 1 == prefix {
                            AuthorityOpenModeV1::ResumeCreate
                        } else {
                            AuthorityOpenModeV1::OpenExistingEmpty
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn v6_nonce_authority_paths_refuse_aliases_before_any_store_is_opened() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("directory");
        let a = dir.path().join("a.sqlite3");
        let b = dir.path().join("b.sqlite3");
        assert!(require_distinct_authority_paths_v6(&[a.clone(), b.clone()]).is_ok());
        assert!(require_distinct_authority_paths_v6(&[a.clone(), a.clone()]).is_err());
        std::fs::write(&a, b"existing").expect("file");
        std::fs::hard_link(&a, &b).expect("hardlink");
        assert!(require_distinct_authority_paths_v6(&[a.clone(), b.clone()]).is_err());
        std::fs::remove_file(&b).expect("remove alias");
        symlink(&a, &b).expect("symbolic alias");
        assert!(require_distinct_authority_paths_v6(&[a, b]).is_err());
    }

    #[test]
    fn relay_secrets_resolve_only_the_exact_roster_member() {
        let secp = SecpContext::new(&MATCH_CONTEXT_SEED_V1);
        let leg = roster_leg(
            &secp,
            ProductionRoutePositionV1::Upstream,
            &UPSTREAM_SECRET,
            PARTICIPANT_A,
            SenderRoleV1::Initiator,
        );
        let resolved = resolve_local_relay_identity(&secp, &leg, &UPSTREAM_SECRET)
            .expect("exact member resolves");
        assert_eq!(resolved.participant_id, PARTICIPANT_A);
        assert_eq!(resolved.role, SenderRoleV1::Initiator);
        assert_eq!(
            leg.members[usize::from(resolved.protocol_index)].xonly_key,
            resolved.xonly_key
        );
        assert!(matches!(
            resolve_local_relay_identity(&secp, &leg, &[0x77; 32]),
            Err(ProductionChainSignerErrorV1::ParticipantCredentialRefused)
        ));
    }

    #[test]
    fn cross_leg_participant_role_and_secret_reuse_are_refused() {
        let secp = SecpContext::new(&MATCH_CONTEXT_SEED_V1);
        let upstream = resolve_local_relay_identity(
            &secp,
            &roster_leg(
                &secp,
                ProductionRoutePositionV1::Upstream,
                &UPSTREAM_SECRET,
                PARTICIPANT_A,
                SenderRoleV1::Initiator,
            ),
            &UPSTREAM_SECRET,
        )
        .expect("upstream identity");
        let downstream = resolve_local_relay_identity(
            &secp,
            &roster_leg(
                &secp,
                ProductionRoutePositionV1::Downstream,
                &DOWNSTREAM_SECRET,
                PARTICIPANT_A,
                SenderRoleV1::Initiator,
            ),
            &DOWNSTREAM_SECRET,
        )
        .expect("downstream identity");
        require_same_local_participant(upstream, downstream).expect("same owner accepted");

        let foreign_participant = resolve_local_relay_identity(
            &secp,
            &roster_leg(
                &secp,
                ProductionRoutePositionV1::Downstream,
                &DOWNSTREAM_SECRET,
                PARTICIPANT_B,
                SenderRoleV1::Initiator,
            ),
            &DOWNSTREAM_SECRET,
        )
        .expect("foreign participant resolves in its own leg");
        assert!(require_same_local_participant(upstream, foreign_participant).is_err());

        let foreign_role = resolve_local_relay_identity(
            &secp,
            &roster_leg(
                &secp,
                ProductionRoutePositionV1::Downstream,
                &DOWNSTREAM_SECRET,
                PARTICIPANT_A,
                SenderRoleV1::Solver,
            ),
            &DOWNSTREAM_SECRET,
        )
        .expect("foreign role resolves in its own leg");
        assert!(require_same_local_participant(upstream, foreign_role).is_err());

        let reused_secret = LocalRelayLegIdentityV1 {
            xonly_key: upstream.xonly_key,
            ..downstream
        };
        assert!(require_same_local_participant(upstream, reused_secret).is_err());
    }

    #[test]
    fn stage_binding_changes_for_leg_key_role_and_authority() {
        let pins = ProductionRoutePinsV1 {
            network_id: [1; 32],
            route_id: [2; 32],
            registry_manifest_digest: [3; 32],
            registry_minimum_epoch: 1,
            registry_authority_set_digest: [4; 32],
            time_policy_authority_set_digest: [5; 32],
            time_evidence_authority_set_digest: [6; 32],
            upstream_terms_digest: [7; 32],
            downstream_terms_digest: [8; 32],
            route_scope_digest: [9; 32],
            participant_bindings_digest: [10; 32],
            relay_binding_digest: [11; 32],
            time_policy_digest: [12; 32],
            time_evidence_digest: [13; 32],
            process_owner_id: [14; 32],
            coordinator_id: [15; 32],
            coordinator_plan_authority_id: [16; 32],
            actuator_bindings_digest: [17; 32],
            solver_inventory_binding_digest: [18; 32],
        };
        let material = |role, bitcoin_leg, bitcoin_authority| ChainSignerBindingMaterialV1 {
            pins,
            participant_id: PARTICIPANT_A,
            role,
            upstream_xonly: [0x21; 32],
            downstream_xonly: [0x22; 32],
            upstream_state_binding: [0x23; 32],
            downstream_state_binding: [0x24; 32],
            wallet_binding: [0x25; 32],
            bitcoin_leg,
            bitcoin_authority,
            bitcoin_nonce_seal_key_id: [0x28; 32],
        };
        let base = chain_signer_binding_digest(material(
            SenderRoleV1::Initiator,
            LegIdV1::Downstream,
            [0x26; 32],
        ));
        assert_ne!(
            base,
            chain_signer_binding_digest(material(
                SenderRoleV1::Solver,
                LegIdV1::Downstream,
                [0x26; 32],
            ))
        );
        assert_ne!(
            base,
            chain_signer_binding_digest(material(
                SenderRoleV1::Initiator,
                LegIdV1::Upstream,
                [0x26; 32],
            ))
        );
        assert_ne!(
            base,
            chain_signer_binding_digest(material(
                SenderRoleV1::Initiator,
                LegIdV1::Downstream,
                [0x27; 32],
            ))
        );
        let mut changed_owner = material(SenderRoleV1::Initiator, LegIdV1::Downstream, [0x26; 32]);
        changed_owner.pins.process_owner_id = [0x91; 32];
        assert_ne!(base, chain_signer_binding_digest(changed_owner));
        let mut changed_seal_key =
            material(SenderRoleV1::Initiator, LegIdV1::Downstream, [0x26; 32]);
        changed_seal_key.bitcoin_nonce_seal_key_id = [0x92; 32];
        assert_ne!(base, chain_signer_binding_digest(changed_seal_key));
    }

    #[test]
    fn bitcoin_nonce_seal_derivation_is_stable_and_scope_separated() {
        let derive = |route_id, terms_digest, participant_id, leg, role| {
            derive_bitcoin_nonce_seal_key_v1(
                &[0xA7; 32],
                route_id,
                terms_digest,
                participant_id,
                leg,
                role,
            )
        };
        let base = derive(
            [0x31; 32],
            [0x32; 32],
            PARTICIPANT_A,
            LegIdV1::Downstream,
            BitcoinParticipantRoleV1::Maker,
        );
        assert_ne!(base, [0; 32]);
        assert_eq!(
            base,
            derive(
                [0x31; 32],
                [0x32; 32],
                PARTICIPANT_A,
                LegIdV1::Downstream,
                BitcoinParticipantRoleV1::Maker,
            )
        );
        for changed in [
            derive(
                [0x41; 32],
                [0x32; 32],
                PARTICIPANT_A,
                LegIdV1::Downstream,
                BitcoinParticipantRoleV1::Maker,
            ),
            derive(
                [0x31; 32],
                [0x42; 32],
                PARTICIPANT_A,
                LegIdV1::Downstream,
                BitcoinParticipantRoleV1::Maker,
            ),
            derive(
                [0x31; 32],
                [0x32; 32],
                PARTICIPANT_B,
                LegIdV1::Downstream,
                BitcoinParticipantRoleV1::Maker,
            ),
            derive(
                [0x31; 32],
                [0x32; 32],
                PARTICIPANT_A,
                LegIdV1::Upstream,
                BitcoinParticipantRoleV1::Maker,
            ),
            derive(
                [0x31; 32],
                [0x32; 32],
                PARTICIPANT_A,
                LegIdV1::Downstream,
                BitcoinParticipantRoleV1::Taker,
            ),
        ] {
            assert_ne!(base, changed);
        }
        assert!(BitcoinNonceSealKeyV1::new(base).is_ok());
    }

    #[test]
    fn resume_accepts_only_the_ordered_authority_crash_prefix() {
        let directory = tempfile::tempdir().expect("temporary authority root");
        let bitcoin = directory.path().join("bitcoin.sqlite3");
        let upstream = directory.path().join("dom-upstream.sqlite3");
        let downstream = directory.path().join("dom-downstream.sqlite3");
        let paths = [bitcoin.as_path(), upstream.as_path(), downstream.as_path()];

        assert_eq!(
            ordered_authority_open_modes(paths, AuthorityOpenModeV1::ResumeCreate)
                .expect("empty prefix"),
            [AuthorityOpenModeV1::Create; 3]
        );
        std::fs::File::create(lock_path(&bitcoin)).expect("Bitcoin lock prefix");
        assert_eq!(
            ordered_authority_open_modes(paths, AuthorityOpenModeV1::ResumeCreate)
                .expect("Bitcoin partial prefix"),
            [
                AuthorityOpenModeV1::ResumeCreate,
                AuthorityOpenModeV1::Create,
                AuthorityOpenModeV1::Create,
            ]
        );
        std::fs::File::create(&bitcoin).expect("Bitcoin database prefix");
        std::fs::File::create(lock_path(&upstream)).expect("upstream lock prefix");
        assert_eq!(
            ordered_authority_open_modes(paths, AuthorityOpenModeV1::ResumeCreate)
                .expect("second authority partial prefix"),
            [
                AuthorityOpenModeV1::OpenExistingEmpty,
                AuthorityOpenModeV1::ResumeCreate,
                AuthorityOpenModeV1::Create,
            ]
        );
        std::fs::File::create(lock_path(&downstream)).expect("downstream lock prefix");
        assert_eq!(
            ordered_authority_open_modes(paths, AuthorityOpenModeV1::ResumeCreate)
                .expect("third authority partial prefix"),
            [
                AuthorityOpenModeV1::OpenExistingEmpty,
                AuthorityOpenModeV1::OpenExistingEmpty,
                AuthorityOpenModeV1::ResumeCreate,
            ]
        );
    }

    #[test]
    fn resume_refuses_database_without_lock_and_gapped_prefix() {
        let database_only = tempfile::tempdir().expect("database-only root");
        let paths = [
            database_only.path().join("bitcoin.sqlite3"),
            database_only.path().join("dom-upstream.sqlite3"),
            database_only.path().join("dom-downstream.sqlite3"),
        ];
        std::fs::File::create(&paths[0]).expect("orphan database");
        assert_eq!(
            ordered_authority_open_modes(
                [paths[0].as_path(), paths[1].as_path(), paths[2].as_path()],
                AuthorityOpenModeV1::ResumeCreate,
            ),
            Err(ProductionChainSignerErrorV1::ProvisioningRefused)
        );

        let gapped = tempfile::tempdir().expect("gapped root");
        let paths = [
            gapped.path().join("bitcoin.sqlite3"),
            gapped.path().join("dom-upstream.sqlite3"),
            gapped.path().join("dom-downstream.sqlite3"),
        ];
        std::fs::File::create(lock_path(&paths[1])).expect("out-of-order upstream lock");
        assert_eq!(
            ordered_authority_open_modes(
                [paths[0].as_path(), paths[1].as_path(), paths[2].as_path()],
                AuthorityOpenModeV1::ResumeCreate,
            ),
            Err(ProductionChainSignerErrorV1::ProvisioningRefused)
        );
    }
}
