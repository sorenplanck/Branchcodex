//! Durable production Relay worker for one participant and one route.
//!
//! The worker composes the already-hardened sender outbox, recipient inbox,
//! V2 frame reassembler and Contracts session store.  It deliberately does
//! not infer a Contracts successor from an opaque DSC1 payload.  New messages
//! are admitted only through Store-issued, phase-specific capabilities;
//! already-journaled messages may use the Store's derived redelivery path.

use dom_scriptless_store::PreparedF7FinalClaimIngressV15;

use std::{
    path::{Path, PathBuf},
    rc::Rc,
};

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use dom_scriptless_store::{
    CommittedOutboundDsc1V1, ContractsSessionStoreV1, DurableTransportOutcomeV1,
    DurableTransportReceiptV1, PreparedEarlyTransportAuthorityV1,
    PreparedF7ClaimPreSignatureTransportV12, PreparedOperationalBpTransportAuthorityV1,
    PreparedOperationalFinalClaimIngressAuthorityV2,
    PreparedOperationalFinalRefundTransportAuthorityV1, PreparedOperationalM8FundingGateV2,
    PreparedOperationalSigningTransportAuthorityV1,
    PreparedOperationalTemplateTransportAuthorityV1, PreparedOperationalXmrFundingGateV12,
    PreparedPostAnchorClaimPreSignatureTransportAuthorityV1,
    PreparedPostAnchorClaimPreSignatureTransportAuthorityV2, SessionPhaseV1, SessionStoreError,
};
use dom_scriptless_transport::{MessageTypeV1, SignedMessageV1};
use kaystra_core::types::Digest32;
use relay::auth::{message_type, RosterRegistryV1};
use relay::{ParticipantId, SenderRoleV1, TimelockSpec};
use route_executor::LegIdV1;
use route_transport::{
    ContractsRouteDeliveryV1, ContractsTransportPortV1, DurableFrameReassemblerConfigV2,
    DurableFrameReassemblerErrorV2, DurableFrameReassemblerStatsV2, DurableFrameReassemblerV2,
    DurableInboxConfigV1, DurableInboxError, DurableInboxIngestReportV1, DurableInboxStatsV1,
    DurableOutboundEnvelopeV1, DurablePayloadCommitV1, DurablePayloadDispositionV1,
    DurableProductionCreationStateV1, DurableQuarantineAuthorityV1,
    DurableQuarantineResolutionErrorV1, DurableQuarantineResolutionReportV1, DurableRelayInboxV1,
    DurableRelaySenderConfigV1, DurableRelaySenderErrorV1, DurableRelaySenderStatsV1,
    DurableRelaySenderV1, F6AppliedReplayErrorV1, F6AppliedReplayReportV1, F6DispatchErrorV1,
    F6DispatchReportV1, F6PayloadDeliveryV1, F6TransportPortV1, FramedContractsTransportErrorV2,
    FramedContractsTransportV2, RelayQueueV1, RelaySubmitQueueV1, RouteApplicationDispositionV2,
    RouteDispatchErrorV1, RouteDispatchReportV1,
};

use crate::production_config::ProductionRelayAuthorityPinsV6;
use crate::production_f6_lifecycle::{ProductionF6LifecycleErrorV2, ProductionF6LifecyclePortV2};

const RECEIPT_DOMAIN: &[u8] = b"DOM-INTEROP/CONTRACTS-RELAY-RECEIPT/V1\0";
const FAILED_CLOSED_RECEIPT_DOMAIN: &[u8] = b"DOM-INTEROP/CONTRACTS-RELAY-FAILED-CLOSED/V1\0";
const ZERO_DIGEST: Digest32 = [0; 32];

#[cfg(test)]
#[path = "relay_worker_terminal_refund_v24_tests.rs"]
mod terminal_refund_v24_tests;

/// Owner-only directories used by the three independent Relay authorities.
pub struct RelayWorkerPathsV1 {
    sender_root: PathBuf,
    inbox_root: PathBuf,
    frame_reassembly_root: PathBuf,
}

impl core::fmt::Debug for RelayWorkerPathsV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RelayWorkerPathsV1")
            .field("sender_root", &"[redacted]")
            .field("inbox_root", &"[redacted]")
            .field("frame_reassembly_root", &"[redacted]")
            .finish()
    }
}

impl RelayWorkerPathsV1 {
    /// Binds explicit roots.  Each underlying authority independently checks
    /// canonicality, owner, mode, link count and process exclusivity.
    pub fn new(
        sender_root: impl Into<PathBuf>,
        inbox_root: impl Into<PathBuf>,
        frame_reassembly_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            sender_root: sender_root.into(),
            inbox_root: inbox_root.into(),
            frame_reassembly_root: frame_reassembly_root.into(),
        }
    }

    /// Sender/outbox root.
    pub fn sender_root(&self) -> &Path {
        &self.sender_root
    }

    /// Recipient inbox root.
    pub fn inbox_root(&self) -> &Path {
        &self.inbox_root
    }

    /// V2 frame-reassembly root.
    pub fn frame_reassembly_root(&self) -> &Path {
        &self.frame_reassembly_root
    }
}

/// Frozen identities, wire binding and hard bounds for one Relay worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayWorkerConfigV1 {
    sender: DurableRelaySenderConfigV1,
    inbox: DurableInboxConfigV1,
    frames: DurableFrameReassemblerConfigV2,
    production_v6_bound: bool,
}

impl RelayWorkerConfigV1 {
    /// Cross-checks the three authorities before any path is opened.
    pub fn new(
        sender: DurableRelaySenderConfigV1,
        inbox: DurableInboxConfigV1,
        frames: DurableFrameReassemblerConfigV2,
    ) -> Result<Self, RelayWorkerOpenErrorV1> {
        let wire = sender.wire_context();
        if inbox.wire_context() != wire
            || frames.wire_context() != wire
            || sender.sender_id() != inbox.recipient_id()
            || sender.sender_id() != frames.recipient_id()
        {
            return Err(RelayWorkerOpenErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            sender,
            inbox,
            frames,
            production_v6_bound: false,
        })
    }

    /// Constructs the production worker config only when every Relay store
    /// identity and bound matches the official V6 manifest for this leg.
    pub fn new_production_v6(
        sender: DurableRelaySenderConfigV1,
        inbox: DurableInboxConfigV1,
        frames: DurableFrameReassemblerConfigV2,
        relay_pins: ProductionRelayAuthorityPinsV6,
        leg: LegIdV1,
    ) -> Result<Self, RelayWorkerOpenErrorV1> {
        let authority_ids = [
            relay_pins.relay_database_id,
            relay_pins.upstream_sender_store_id,
            relay_pins.upstream_inbox_id,
            relay_pins.upstream_reassembler_id,
            relay_pins.downstream_sender_store_id,
            relay_pins.downstream_inbox_id,
            relay_pins.downstream_reassembler_id,
        ];
        let ids_are_distinct = authority_ids
            .iter()
            .enumerate()
            .all(|(index, id)| id != &ZERO_DIGEST && !authority_ids[..index].contains(id));
        let (sender_store_id, inbox_id, reassembler_id) = match leg {
            LegIdV1::Upstream => (
                relay_pins.upstream_sender_store_id,
                relay_pins.upstream_inbox_id,
                relay_pins.upstream_reassembler_id,
            ),
            LegIdV1::Downstream => (
                relay_pins.downstream_sender_store_id,
                relay_pins.downstream_inbox_id,
                relay_pins.downstream_reassembler_id,
            ),
        };
        if !ids_are_distinct
            || !(1..=65_536).contains(&relay_pins.relay_max_envelopes)
            || !(1..=65_536).contains(&relay_pins.sender_max_envelopes)
            || !(1..=65_536).contains(&relay_pins.inbox_max_entries)
            || !(1..=256).contains(&relay_pins.frame_max_messages)
            || !(16_385..=67_108_864).contains(&relay_pins.frame_max_active_bytes)
            || !(1..=8_448).contains(&relay_pins.frame_max_active_chunks)
            || sender.sender_store_id() != &sender_store_id
            || inbox.inbox_id() != &inbox_id
            || inbox.expected_relay_database_id() != &relay_pins.relay_database_id
            || frames.reassembler_id() != &reassembler_id
            || sender.max_envelopes() != relay_pins.sender_max_envelopes
            || inbox.max_entries() != relay_pins.inbox_max_entries
            || frames.max_messages() != relay_pins.frame_max_messages
            || frames.max_active_bytes() != relay_pins.frame_max_active_bytes
            || frames.max_active_chunks() != relay_pins.frame_max_active_chunks
        {
            return Err(RelayWorkerOpenErrorV1::InvalidConfiguration);
        }
        let mut config = Self::new(sender, inbox, frames)?;
        config.production_v6_bound = true;
        Ok(config)
    }

    /// Shared frozen route wire context.
    pub const fn wire_context(&self) -> route_transport::RouteWireContextV1 {
        self.sender.wire_context()
    }

    /// Local participant owning the sender and recipient stores.
    pub const fn local_participant(&self) -> ParticipantId {
        self.sender.sender_id()
    }

    /// Remote participant addressed by the outbound flow.
    pub const fn remote_participant(&self) -> ParticipantId {
        self.sender.recipient_id()
    }

    /// V6-pinned production Relay database identity accepted by the inbox.
    pub const fn relay_database_id(&self) -> &Digest32 {
        self.inbox.expected_relay_database_id()
    }

    pub(crate) const fn is_production_v6_bound(&self) -> bool {
        self.production_v6_bound
    }

    pub(crate) const fn relay_signer_xonly(&self) -> &[u8; 32] {
        self.sender.signer_xonly()
    }

    pub(crate) const fn relay_sender_role(&self) -> SenderRoleV1 {
        self.sender.sender_role()
    }
}

/// Process-only Contracts ingress authority.
///
/// It has no codec, `Clone`, `Copy`, equality or debug surface.  The only
/// constructors consume opaque handles issued by `ContractsSessionStoreV1`.
/// A worker reopened after a crash must reissue the handle from the same
/// authenticated Store records.
pub struct PreparedContractsIngressV1 {
    inner: PreparedContractsIngressKindV1,
}

enum PreparedContractsIngressKindV1 {
    XmrGraphCommitV23(dom_scriptless_store::PreparedXmrGraphCommitIngressV23),
    XmrGraphSigningV23(dom_scriptless_store::PreparedXmrGraphSigningIngressV23),
    Early(PreparedEarlyTransportAuthorityV1),
    OperationalBp(PreparedOperationalBpTransportAuthorityV1),
    OperationalTemplate(PreparedOperationalTemplateTransportAuthorityV1),
    OperationalSigning(PreparedOperationalSigningTransportAuthorityV1),
    OperationalFinalRefund(PreparedOperationalFinalRefundTransportAuthorityV1),
    PostAnchorClaimPreSignature(Box<PreparedPostAnchorClaimPreSignatureTransportAuthorityV1>),
    PostAnchorClaimPreSignatureV2(Box<PreparedPostAnchorClaimPreSignatureTransportAuthorityV2>),
    ReadyToFundV2(PreparedOperationalM8FundingGateV2),
    UniversalReadyToFundV12(PreparedOperationalXmrFundingGateV12),
    UniversalClaimPreSignatureV12(Box<PreparedF7ClaimPreSignatureTransportV12>),
    FinalClaimIngressV2(Box<PreparedOperationalFinalClaimIngressAuthorityV2>),
    UniversalFinalClaimV15(Box<PreparedF7FinalClaimIngressV15>),
}

impl PreparedContractsIngressV1 {
    pub fn xmr_graph_signing_v23(
        authority: dom_scriptless_store::PreparedXmrGraphSigningIngressV23,
    ) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::XmrGraphSigningV23(authority),
        }
    }
    pub fn xmr_graph_commit_v23(
        authority: dom_scriptless_store::PreparedXmrGraphCommitIngressV23,
    ) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::XmrGraphCommitV23(authority),
        }
    }
    /// Receiver ingress issued only after a native universal claim observation.
    pub fn universal_final_claim_v15(authority: PreparedF7FinalClaimIngressV15) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::UniversalFinalClaimV15(Box::new(authority)),
        }
    }

    /// Authorizes only the prepared DSC1 `Offer`, `Accept`, `ShareCommit` and
    /// `ShareReveal` state machine owned by the Store.
    pub fn early(authority: PreparedEarlyTransportAuthorityV1) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::Early(authority),
        }
    }

    /// Authorizes only the prepared operational Bulletproof transport rounds
    /// from `BpCommonCommitment` through `BpFinalProof` (`0x05`–`0x0a`).
    pub fn operational_bp(authority: PreparedOperationalBpTransportAuthorityV1) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::OperationalBp(authority),
        }
    }

    /// Authorizes only the two prepared operational `TxTemplateCommit`
    /// messages (`0x0b`) over the Store-frozen canonical templates.
    pub fn operational_template(
        authority: PreparedOperationalTemplateTransportAuthorityV1,
    ) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::OperationalTemplate(authority),
        }
    }

    /// Authorizes only one Store-frozen operational signing round across
    /// nonce commitments, nonce reveals and partial signatures (`0x0c`–`0x0e`).
    pub fn operational_signing(authority: PreparedOperationalSigningTransportAuthorityV1) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::OperationalSigning(authority),
        }
    }

    /// Authorizes only the exact Store-derived, fully signed operational
    /// Refund transaction (`FinalRefund`, `0x10`).
    pub fn operational_final_refund(
        authority: PreparedOperationalFinalRefundTransportAuthorityV1,
    ) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::OperationalFinalRefund(authority),
        }
    }

    /// Authorizes only the Store-frozen post-anchor Claim adaptor
    /// pre-signature transport edge (`0x0f`).
    pub fn post_anchor_claim_pre_signature(
        authority: PreparedPostAnchorClaimPreSignatureTransportAuthorityV1,
    ) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(Box::new(authority)),
        }
    }

    /// Authorizes only the Store-frozen V2 post-anchor Claim adaptor
    /// pre-signature transport edge (`0x0f`).
    ///
    /// This is the productive constructor. The V1 form above remains available
    /// solely for legacy evidence-only recovery: its Store entrypoints refuse
    /// the ratified production profile.
    pub fn post_anchor_claim_pre_signature_v2(
        authority: PreparedPostAnchorClaimPreSignatureTransportAuthorityV2,
    ) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(Box::new(
                authority,
            )),
        }
    }

    /// Authorizes only the next Store-derived M.8 `ReadyToFund` vote.
    pub fn ready_to_fund_v2(authority: PreparedOperationalM8FundingGateV2) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::ReadyToFundV2(authority),
        }
    }

    /// Installs only the next native F7 V12 readiness vote (`0x17`).
    /// The capability retains the exact selected-family recovery gate.
    pub fn universal_ready_to_fund_v12(authority: PreparedOperationalXmrFundingGateV12) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::UniversalReadyToFundV12(authority),
        }
    }

    /// Returns the linear V12 F7 gate after bilateral readiness is durable.
    pub fn into_universal_ready_to_fund_v12(
        self,
    ) -> Result<PreparedOperationalXmrFundingGateV12, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::UniversalReadyToFundV12(authority) => Ok(authority),
            inner => Err(Box::new(Self { inner })),
        }
    }

    /// Installs the exact native F7 V12 post-anchor pre-signature (`0x0f`).
    pub fn universal_claim_pre_signature_v12(
        authority: PreparedF7ClaimPreSignatureTransportV12,
    ) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::UniversalClaimPreSignatureV12(Box::new(
                authority,
            )),
        }
    }

    /// Returns the native V12 pre-signature authority without cloning it.
    pub fn into_universal_claim_pre_signature_v12(
        self,
    ) -> Result<PreparedF7ClaimPreSignatureTransportV12, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::UniversalClaimPreSignatureV12(authority) => {
                Ok(*authority)
            }
            inner => Err(Box::new(Self { inner })),
        }
    }

    /// Authorizes only the reception of the counterparty's exact FinalClaim
    /// (`0x12`).
    ///
    /// The boxed capability is the Store's *ingress* authority, minted from
    /// the durable FinalClaim observation record; it is deliberately not the
    /// transport authority of the same phase, which is the emitter-side
    /// capability minted from the admission record and consumed by
    /// `prepare_final_claim_dsc1_signing_request_v2`.  Installing the emitter
    /// capability here would compile and then never accept a real `0x12`,
    /// because the Store's accept entrypoint takes the ingress form.
    ///
    /// This variant is reception-only.  A locally owned FinalClaim leaves
    /// through [`DurableRelayWorkerV1::stage_store_outbound_dsc1`] like every
    /// other Store-committed outbound DSC1 object, never through an installed
    /// ingress capability.
    pub fn final_claim_ingress_v2(
        authority: PreparedOperationalFinalClaimIngressAuthorityV2,
    ) -> Self {
        Self {
            inner: PreparedContractsIngressKindV1::FinalClaimIngressV2(Box::new(authority)),
        }
    }

    /// Recovers the linear M.8 gate after the Relay votes have been accepted,
    /// so the composition root can consume it at the funding boundary.
    ///
    /// Every authority for another phase is returned unchanged in `Err`; no
    /// capability is cloned, serialized or silently discarded.
    pub fn into_ready_to_fund_v2(self) -> Result<PreparedOperationalM8FundingGateV2, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::ReadyToFundV2(authority) => Ok(authority),
            inner @ (PreparedContractsIngressKindV1::XmrGraphSigningV23(_)
            | PreparedContractsIngressKindV1::XmrGraphCommitV23(_)
            | PreparedContractsIngressKindV1::Early(_)
            | PreparedContractsIngressKindV1::OperationalBp(_)
            | PreparedContractsIngressKindV1::OperationalTemplate(_)
            | PreparedContractsIngressKindV1::OperationalSigning(_)
            | PreparedContractsIngressKindV1::OperationalFinalRefund(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(_)
            | PreparedContractsIngressKindV1::UniversalReadyToFundV12(_)
            | PreparedContractsIngressKindV1::UniversalClaimPreSignatureV12(_)
            | PreparedContractsIngressKindV1::FinalClaimIngressV2(_)
            | PreparedContractsIngressKindV1::UniversalFinalClaimV15(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }

    /// Recovers an early-phase authority without exposing any capability's
    /// representation. Authorities for other phases are returned unchanged in
    /// `Err`.
    pub fn into_early(self) -> Result<PreparedEarlyTransportAuthorityV1, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::Early(authority) => Ok(authority),
            inner @ (PreparedContractsIngressKindV1::XmrGraphSigningV23(_)
            | PreparedContractsIngressKindV1::XmrGraphCommitV23(_)
            | PreparedContractsIngressKindV1::OperationalBp(_)
            | PreparedContractsIngressKindV1::OperationalTemplate(_)
            | PreparedContractsIngressKindV1::OperationalSigning(_)
            | PreparedContractsIngressKindV1::OperationalFinalRefund(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(_)
            | PreparedContractsIngressKindV1::ReadyToFundV2(_)
            | PreparedContractsIngressKindV1::UniversalReadyToFundV12(_)
            | PreparedContractsIngressKindV1::UniversalClaimPreSignatureV12(_)
            | PreparedContractsIngressKindV1::FinalClaimIngressV2(_)
            | PreparedContractsIngressKindV1::UniversalFinalClaimV15(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }

    /// Recovers the operational Bulletproof authority without exposing its
    /// representation.  Authorities for other phases are returned unchanged
    /// in `Err`.
    pub fn into_operational_bp(
        self,
    ) -> Result<PreparedOperationalBpTransportAuthorityV1, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::OperationalBp(authority) => Ok(authority),
            inner @ (PreparedContractsIngressKindV1::XmrGraphSigningV23(_)
            | PreparedContractsIngressKindV1::XmrGraphCommitV23(_)
            | PreparedContractsIngressKindV1::Early(_)
            | PreparedContractsIngressKindV1::OperationalTemplate(_)
            | PreparedContractsIngressKindV1::OperationalSigning(_)
            | PreparedContractsIngressKindV1::OperationalFinalRefund(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(_)
            | PreparedContractsIngressKindV1::ReadyToFundV2(_)
            | PreparedContractsIngressKindV1::UniversalReadyToFundV12(_)
            | PreparedContractsIngressKindV1::UniversalClaimPreSignatureV12(_)
            | PreparedContractsIngressKindV1::FinalClaimIngressV2(_)
            | PreparedContractsIngressKindV1::UniversalFinalClaimV15(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }

    /// Recovers the operational template authority without exposing its
    /// representation. Authorities for other phases are returned unchanged
    /// in `Err`.
    pub fn into_operational_template(
        self,
    ) -> Result<PreparedOperationalTemplateTransportAuthorityV1, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::OperationalTemplate(authority) => Ok(authority),
            inner @ (PreparedContractsIngressKindV1::XmrGraphSigningV23(_)
            | PreparedContractsIngressKindV1::XmrGraphCommitV23(_)
            | PreparedContractsIngressKindV1::Early(_)
            | PreparedContractsIngressKindV1::OperationalBp(_)
            | PreparedContractsIngressKindV1::OperationalSigning(_)
            | PreparedContractsIngressKindV1::OperationalFinalRefund(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(_)
            | PreparedContractsIngressKindV1::ReadyToFundV2(_)
            | PreparedContractsIngressKindV1::UniversalReadyToFundV12(_)
            | PreparedContractsIngressKindV1::UniversalClaimPreSignatureV12(_)
            | PreparedContractsIngressKindV1::FinalClaimIngressV2(_)
            | PreparedContractsIngressKindV1::UniversalFinalClaimV15(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }

    /// Recovers the operational signing authority without exposing its
    /// representation. Authorities for other phases are returned unchanged
    /// in `Err`.
    pub fn into_operational_signing(
        self,
    ) -> Result<PreparedOperationalSigningTransportAuthorityV1, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::OperationalSigning(authority) => Ok(authority),
            inner @ (PreparedContractsIngressKindV1::XmrGraphSigningV23(_)
            | PreparedContractsIngressKindV1::XmrGraphCommitV23(_)
            | PreparedContractsIngressKindV1::Early(_)
            | PreparedContractsIngressKindV1::OperationalBp(_)
            | PreparedContractsIngressKindV1::OperationalTemplate(_)
            | PreparedContractsIngressKindV1::OperationalFinalRefund(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(_)
            | PreparedContractsIngressKindV1::ReadyToFundV2(_)
            | PreparedContractsIngressKindV1::UniversalReadyToFundV12(_)
            | PreparedContractsIngressKindV1::UniversalClaimPreSignatureV12(_)
            | PreparedContractsIngressKindV1::FinalClaimIngressV2(_)
            | PreparedContractsIngressKindV1::UniversalFinalClaimV15(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }

    /// Recovers the exact final Refund authority without exposing its
    /// representation. Authorities for other phases are returned unchanged in
    /// `Err`.
    pub fn into_operational_final_refund(
        self,
    ) -> Result<PreparedOperationalFinalRefundTransportAuthorityV1, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::OperationalFinalRefund(authority) => Ok(authority),
            inner @ (PreparedContractsIngressKindV1::XmrGraphSigningV23(_)
            | PreparedContractsIngressKindV1::XmrGraphCommitV23(_)
            | PreparedContractsIngressKindV1::Early(_)
            | PreparedContractsIngressKindV1::OperationalBp(_)
            | PreparedContractsIngressKindV1::OperationalTemplate(_)
            | PreparedContractsIngressKindV1::OperationalSigning(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(_)
            | PreparedContractsIngressKindV1::ReadyToFundV2(_)
            | PreparedContractsIngressKindV1::UniversalReadyToFundV12(_)
            | PreparedContractsIngressKindV1::UniversalClaimPreSignatureV12(_)
            | PreparedContractsIngressKindV1::FinalClaimIngressV2(_)
            | PreparedContractsIngressKindV1::UniversalFinalClaimV15(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }

    /// Recovers the post-anchor Claim pre-signature authority without
    /// exposing its representation. Authorities for other phases are returned
    /// unchanged in `Err`.
    pub fn into_post_anchor_claim_pre_signature(
        self,
    ) -> Result<PreparedPostAnchorClaimPreSignatureTransportAuthorityV1, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(authority) => {
                Ok(*authority)
            }
            inner @ (PreparedContractsIngressKindV1::XmrGraphSigningV23(_)
            | PreparedContractsIngressKindV1::XmrGraphCommitV23(_)
            | PreparedContractsIngressKindV1::Early(_)
            | PreparedContractsIngressKindV1::OperationalBp(_)
            | PreparedContractsIngressKindV1::OperationalTemplate(_)
            | PreparedContractsIngressKindV1::OperationalSigning(_)
            | PreparedContractsIngressKindV1::OperationalFinalRefund(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(_)
            | PreparedContractsIngressKindV1::ReadyToFundV2(_)
            | PreparedContractsIngressKindV1::UniversalReadyToFundV12(_)
            | PreparedContractsIngressKindV1::UniversalClaimPreSignatureV12(_)
            | PreparedContractsIngressKindV1::FinalClaimIngressV2(_)
            | PreparedContractsIngressKindV1::UniversalFinalClaimV15(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }

    /// Recovers the V2 post-anchor Claim pre-signature authority without
    /// exposing its representation. Authorities for other phases are returned
    /// unchanged in `Err`.
    pub fn into_post_anchor_claim_pre_signature_v2(
        self,
    ) -> Result<PreparedPostAnchorClaimPreSignatureTransportAuthorityV2, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(authority) => {
                Ok(*authority)
            }
            inner @ (PreparedContractsIngressKindV1::XmrGraphSigningV23(_)
            | PreparedContractsIngressKindV1::XmrGraphCommitV23(_)
            | PreparedContractsIngressKindV1::Early(_)
            | PreparedContractsIngressKindV1::OperationalBp(_)
            | PreparedContractsIngressKindV1::OperationalTemplate(_)
            | PreparedContractsIngressKindV1::OperationalSigning(_)
            | PreparedContractsIngressKindV1::OperationalFinalRefund(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(_)
            | PreparedContractsIngressKindV1::ReadyToFundV2(_)
            | PreparedContractsIngressKindV1::UniversalReadyToFundV12(_)
            | PreparedContractsIngressKindV1::UniversalClaimPreSignatureV12(_)
            | PreparedContractsIngressKindV1::FinalClaimIngressV2(_)
            | PreparedContractsIngressKindV1::UniversalFinalClaimV15(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }

    /// Recovers the FinalClaim ingress authority without exposing its
    /// representation. Authorities for other phases are returned unchanged in
    /// `Err`.
    pub fn into_final_claim_ingress_v2(
        self,
    ) -> Result<PreparedOperationalFinalClaimIngressAuthorityV2, Box<Self>> {
        match self.inner {
            PreparedContractsIngressKindV1::FinalClaimIngressV2(authority) => Ok(*authority),
            inner @ (PreparedContractsIngressKindV1::XmrGraphSigningV23(_)
            | PreparedContractsIngressKindV1::XmrGraphCommitV23(_)
            | PreparedContractsIngressKindV1::UniversalFinalClaimV15(_)
            | PreparedContractsIngressKindV1::Early(_)
            | PreparedContractsIngressKindV1::OperationalBp(_)
            | PreparedContractsIngressKindV1::OperationalTemplate(_)
            | PreparedContractsIngressKindV1::OperationalSigning(_)
            | PreparedContractsIngressKindV1::OperationalFinalRefund(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(_)
            | PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(_)
            | PreparedContractsIngressKindV1::ReadyToFundV2(_)
            | PreparedContractsIngressKindV1::UniversalReadyToFundV12(_)
            | PreparedContractsIngressKindV1::UniversalClaimPreSignatureV12(_)) => {
                Err(Box::new(Self { inner }))
            }
        }
    }
}

/// Redacted construction/reopen failures.
#[derive(Debug, thiserror::Error)]
pub enum RelayWorkerOpenErrorV1 {
    /// Component identities, roles, wire contexts or roster facts diverge.
    #[error("invalid Relay worker configuration")]
    InvalidConfiguration,
    /// The sender/outbox authority refused creation or reopen.
    #[error("Relay sender authority: {0}")]
    Sender(#[from] DurableRelaySenderErrorV1),
    /// The recipient inbox authority refused creation or reopen.
    #[error("Relay inbox authority: {0}")]
    Inbox(#[from] DurableInboxError),
    /// The V2 reassembly authority refused creation or reopen.
    #[error("Relay frame authority: {0}")]
    Frames(#[from] DurableFrameReassemblerErrorV2),
    /// The Contracts Store could not authenticate the bound session.
    #[error("Contracts session authority: {0}")]
    Contracts(#[from] SessionStoreError),
    /// Operating-system entropy was unavailable for secp context hardening.
    #[error("operating-system entropy unavailable")]
    EntropyUnavailable,
}

/// Refusals at the strict Relay-to-Contracts boundary.
#[derive(Debug, thiserror::Error)]
pub enum ContractsRelayIngressErrorV1 {
    /// The single-threaded Contracts/Relay owner is already serving another
    /// operation; callers must retry without opening another worker.
    #[error("Contracts Relay owner is busy")]
    OwnerBusy,
    /// The Store refused, quarantined or could not authenticate the operation.
    #[error("Contracts Store refused Relay ingress: {0}")]
    Store(#[from] SessionStoreError),
    /// No Store-issued authority exists for this unseen message phase.
    #[error("unseen DSC1 message has no prepared Contracts authority")]
    UnpreparedMessage,
    /// The final claim receiver persisted its observation, but the ingress
    /// authority that accepts the sender's final claim lives only in this
    /// relay's memory and is installed by the next native round. Keep the
    /// message pending until then: a fresh process after reopen, or a relay
    /// turn ahead of that round, must not fail closed on a claim it will
    /// accept moments later.
    #[error("F7 final claim is awaiting its ingress handoff")]
    AwaitingFinalClaimIngressHandoffV29,
    /// The peer's authenticated first funding edge arrived in the same Relay
    /// batch that completed bilateral readiness. Keep it pending until the
    /// native owner observes the chain and installs its linear authority.
    #[error("native XMR funding commitment is awaiting its signing handoff")]
    AwaitingNativeXmrFundingHandoffV25,
    /// Authenticated first readiness vote awaits the local native gate. No ACK.
    #[error("native XMR readiness is awaiting local gate construction")]
    AwaitingNativeXmrReadinessGateV25,
    /// Exact native claim verified, but chain observation has not committed.
    /// Relay keeps this row pending; this is never an acceptance receipt.
    #[error("verified final claim is awaiting its canonical chain observation")]
    AwaitingFinalClaimObservationV16,
    /// Authenticated first template commitment precedes the local wallet
    /// construction data. The inbox retains it without an acceptance receipt.
    #[error("template commitment is awaiting local wallet construction data")]
    AwaitingTemplateConstructionV17,
    /// A checked refund edge arrived in the batch that completed its prior
    /// phase. Keep it pending until the native bootstrap owner installs ingress.
    #[error("refund edge is awaiting the native bootstrap ingress handoff")]
    AwaitingBootstrapRefundHandoffV18,
    /// The signed native refund request remains in the inbox until this
    /// participant independently observes public U and binds its transport.
    #[error("native XMR refund is awaiting the local public-U transport scope")]
    AwaitingNativeXmrRefundTransportV23,
    /// A capability belongs to a different session or Store state.
    #[error("prepared Contracts ingress authority does not match this route")]
    WrongAuthority,
    /// A linear capability is already installed and must first be taken.
    #[error("a prepared Contracts ingress authority is already installed")]
    AuthorityAlreadyInstalled,
    /// A nonzero durable receipt could not be constructed.
    #[error("Contracts Store returned an invalid durable ingress receipt")]
    InvalidReceipt,
    /// The inner DSC1 envelope is malformed or not canonically encoded.
    #[error("Relay payload is not a canonical signed DSC1 envelope")]
    InvalidDsc1,
    /// The authenticated outer Relay sender differs from the inner DSC1 signer.
    #[error("outer Relay sender does not match the inner DSC1 sender")]
    SenderMismatch,
}

fn require_xmr_claim_response_payload_v24(
    kind: dom_scriptless_transport::MessageTypeV1,
    payload: &[u8],
) -> Result<(), RelayWorkerOutboundErrorV1> {
    if kind != dom_scriptless_transport::MessageTypeV1::XmrRemoteSweepResponseV23
        || xmr_remote_sweep_wire::RemoteSweepResponseV23::decode_exact(payload)
            .map_err(|_| RelayWorkerOutboundErrorV1::InvalidDsc1)?
            .action()
            != xmr_remote_sweep_wire::RemoteSweepActionV23::Claim
    {
        return Err(RelayWorkerOutboundErrorV1::WrongDsc1Scope);
    }
    Ok(())
}

#[cfg(test)]
mod claim_publication_type_tests_v24 {
    use super::*;

    #[test]
    fn claim_publication_accepts_claim_framing_but_refuses_refund_framing() {
        use xmr_remote_sweep_wire::*;
        // Canonical public framing only, never a crypto/funding authority.
        for action in [RemoteSweepActionV23::Claim, RemoteSweepActionV23::Refund] {
            let bytes = RemoteSweepResponseV23::new(RemoteSweepResponseInputV23 {
                request_digest: [1; 32],
                request_message_digest: [2; 32],
                signer_funding_evidence_digest: [3; 32],
                network_genesis: [4; 32],
                route_id: [5; 32],
                session_id: [6; 32],
                settlement_id: [7; 32],
                terms_digest: [8; 32],
                registry_digest: [9; 32],
                profile_digest: [10; 32],
                deployment_digest: [11; 32],
                effect_id: [12; 32],
                semantic_digest: [13; 32],
                transaction_hash: [14; 32],
                key_image: [15; 32],
                funded_amount_piconero: 100,
                fee_piconero: 1,
                fencing_epoch: 1,
                action,
                leg: RemoteSweepLegV23::Upstream,
                raw_transaction: vec![0x7a; 64],
                input_spend_proof: [0x31; INPUT_SPEND_PROOF_BYTES_V23],
                payout_proofs: vec![RemoteTxKeyDerivationProofV23::decode(
                    &[0x41; TX_KEY_DERIVATION_PROOF_BYTES_V23],
                )
                .unwrap()],
                ring_members: (0..16)
                    .map(|i| RemoteRingMemberV23 {
                        global_index: i + 1,
                        key: [i as u8 + 1; 32],
                        commitment: [i as u8 + 33; 32],
                    })
                    .collect(),
            })
            .unwrap()
            .encode()
            .unwrap();
            assert_eq!(
                require_xmr_claim_response_payload_v24(
                    MessageTypeV1::XmrRemoteSweepResponseV23,
                    &bytes
                )
                .is_ok(),
                action == RemoteSweepActionV23::Claim
            );
        }
    }

    #[test]
    fn claim_publication_never_admits_request_or_other_dsc1_types() {
        for tag in 1..=0x19 {
            if let Ok(kind) = MessageTypeV1::try_from(tag) {
                assert!(matches!(
                    require_xmr_claim_response_payload_v24(kind, &[]),
                    Err(RelayWorkerOutboundErrorV1::WrongDsc1Scope)
                ));
            }
        }
        assert!(matches!(
            require_xmr_claim_response_payload_v24(MessageTypeV1::XmrRemoteSweepResponseV23, &[],),
            Err(RelayWorkerOutboundErrorV1::InvalidDsc1)
        ));
    }
}

/// Redacted outbound worker failures.
#[derive(Debug, thiserror::Error)]
pub enum RelayWorkerOutboundErrorV1 {
    /// The single-threaded Contracts/Relay owner is already serving another
    /// operation; callers must retry through the same retained worker.
    #[error("Contracts Relay owner is busy")]
    OwnerBusy,
    /// Operating-system entropy was unavailable for BIP340 auxiliary input.
    #[error("operating-system entropy unavailable")]
    EntropyUnavailable,
    /// The durable sender refused preparation, submit, ACK or retained state.
    #[error("Relay sender authority: {0}")]
    Sender(#[from] DurableRelaySenderErrorV1),
    /// The shared Contracts Store rejected, quarantined or could not
    /// reauthenticate the Store-issued outbound handle.
    #[error("Contracts Store refused outbound Relay staging")]
    StoreRejected,
    /// The proposed inner payload is not one exact canonical DSC1 envelope.
    #[error("outbound DSC1 is not canonically encoded")]
    InvalidDsc1,
    /// The inner sender/session differs from the worker's frozen addressed flow.
    #[error("outbound DSC1 does not belong to this Relay sender")]
    WrongDsc1Scope,
}

/// A complete inbound step failed.  Accepted outer envelopes remain durable;
/// the first uncommitted downstream row remains pending for exact redelivery.
#[derive(Debug, thiserror::Error)]
pub enum RelayWorkerInboundErrorV1<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Mailbox authentication or inbox persistence failed.
    #[error("Relay inbox ingest: {0}")]
    Ingest(#[from] DurableInboxError),
    /// The shared F6 authority refused its next pending object.
    #[error("Relay F6 dispatch: {0}")]
    F6(#[source] F6DispatchErrorV1<E>),
    /// Frame reassembly or the Contracts Store refused its next pending DSC1.
    #[error("Relay Contracts dispatch: {0}")]
    Contracts(
        #[source]
        RouteDispatchErrorV1<FramedContractsTransportErrorV2<ContractsRelayIngressErrorV1>>,
    ),
}

/// Secret-free Contracts head information suitable for health reporting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContractsSessionStatusV1 {
    /// Current durable revision.
    pub revision: u64,
    /// Current authenticated phase.
    pub phase: SessionPhaseV1,
}

/// Closed F6 kinds that share the outbound checkpoint with DSC1 traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayF6MessageKindV1 {
    /// RFQ emitted by the initiator.
    Rfq,
    /// Quote emitted by a solver.
    Quote,
    /// Quote acceptance emitted by the initiator.
    Acceptance,
    /// Deterministic selection emitted by the initiator.
    Selection,
}

impl RelayF6MessageKindV1 {
    const fn wire_kind(self) -> u16 {
        match self {
            Self::Rfq => message_type::RFQ,
            Self::Quote => message_type::QUOTE,
            Self::Acceptance => message_type::ACCEPTANCE,
            Self::Selection => message_type::SELECTION,
        }
    }
}

/// Secret-free evidence that an exact outbound envelope is already durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedRelayOutboundV1 {
    /// Ratified Relay kind.
    pub message_type: u16,
    /// Shared-flow sequence.
    pub sequence: u64,
    /// Digest of the exact retained signed envelope.
    pub envelope_digest: Digest32,
    /// Frame index for V2, absent for F6 and direct route messages.
    pub frame_index: Option<u16>,
    /// Total V2 frame count when framed.
    pub frame_count: Option<u16>,
}

/// Result of one outbound step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayOutboundStepV1 {
    /// No exact envelope is currently staged.  A Store application may still
    /// require re-staging to prepare its next reserved frame or reconcile its
    /// final durable ACK.
    Idle,
    /// One exact ACK and the advanced shared checkpoint are durable.
    Acked {
        /// Ratified Relay kind.
        message_type: u16,
        /// Frame index for V2, if this ACK belongs to a frame.
        frame_index: Option<u16>,
        /// Sequence that will be used by the next F6 or route envelope.
        next_sequence: u64,
        /// Digest acknowledged by the Relay.
        envelope_digest: Digest32,
    },
}

/// Result of dispatching the already-durable shared inbox in protocol order.
#[derive(Debug)]
pub struct RelayInboundDispatchReportV1 {
    /// F6 objects consumed before the currently eligible route segment.
    pub f6: F6DispatchReportV1,
    /// Direct envelopes or authenticated frames consumed by Contracts.
    pub contracts: RouteDispatchReportV1,
    /// Counters after both downstream authorities returned durable receipts.
    pub inbox: DurableInboxStatsV1,
    /// Bounded V2 reassembly counters after the step.
    pub frames: DurableFrameReassemblerStatsV2,
}

/// Full mailbox pull plus ordered downstream-dispatch report.
#[derive(Debug)]
pub struct RelayInboundPollReportV1 {
    /// Outer envelopes authenticated and committed before dispatch.
    pub ingest: DurableInboxIngestReportV1,
    /// Shared-order downstream results.
    pub dispatch: RelayInboundDispatchReportV1,
}

/// Explicit fail-closed F6 boundary for a composition that has not installed
/// its real RFQ/solver authority.  A pending F6 row blocks later route traffic
/// in the same flow instead of being skipped.
#[derive(Default)]
pub struct UnavailableF6AuthorityV1;

impl core::fmt::Debug for UnavailableF6AuthorityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("UnavailableF6AuthorityV1").finish()
    }
}

/// Named fail-closed error from [`UnavailableF6AuthorityV1`].
#[derive(Debug, thiserror::Error)]
#[error("no production F6 authority is installed")]
pub struct UnavailableF6AuthorityErrorV1;

impl F6TransportPortV1 for UnavailableF6AuthorityV1 {
    type Error = UnavailableF6AuthorityErrorV1;

    fn accept_f6(
        &mut self,
        _delivery: F6PayloadDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error> {
        Err(UnavailableF6AuthorityErrorV1)
    }
}

struct ContractsStoreTransportPortV1 {
    store: Rc<ContractsSessionStoreV1>,
    session_id: Digest32,
    /// Participant this worker signs as, taken from the route configuration.
    /// It is never supplied by a caller at install time, so an installed
    /// capability cannot name its own recipient.
    local_participant: ParticipantId,
    /// The single counterparty this route addresses, from the same frozen
    /// configuration.
    remote_participant: ParticipantId,
    authority: Option<PreparedContractsIngressV1>,
    // Monotonic for this worker opening: terminal draining cannot restore a
    // prepared signing/F7 ingress or dispatch any other economic message.
    terminal_refund_only_v24: bool,
}

// Test-only construction of the REAL downstream port for native graph tests.
// No injected receipt, phase, signature or Store implementation is accepted.
#[cfg(test)]
pub(crate) fn native_refund_transport_test_port_v24(
    store: Rc<ContractsSessionStoreV1>,
    session: Digest32,
    local: ParticipantId,
    remote: ParticipantId,
) -> Result<impl ContractsTransportPortV1<Error = ContractsRelayIngressErrorV1>, SessionStoreError>
{
    ContractsStoreTransportPortV1::new(store, session, local, remote)
}

impl ContractsStoreTransportPortV1 {
    fn new(
        store: Rc<ContractsSessionStoreV1>,
        session_id: Digest32,
        local_participant: ParticipantId,
        remote_participant: ParticipantId,
    ) -> Result<Self, SessionStoreError> {
        store.load_session(session_id)?;
        Ok(Self {
            store,
            session_id,
            local_participant,
            remote_participant,
            authority: None,
            terminal_refund_only_v24: false,
        })
    }

    fn install(
        &mut self,
        authority: PreparedContractsIngressV1,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        if self.terminal_refund_only_v24 {
            return Err(ContractsRelayIngressErrorV1::WrongAuthority);
        }
        if self.authority.is_some() {
            return Err(ContractsRelayIngressErrorV1::AuthorityAlreadyInstalled);
        }
        match &authority.inner {
            PreparedContractsIngressKindV1::XmrGraphSigningV23(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::XmrGraphCommitV23(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::Early(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::OperationalBp(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::OperationalTemplate(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::OperationalSigning(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::OperationalFinalRefund(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::UniversalFinalClaimV15(prepared) => {
                if prepared.session_id() != &self.session_id
                    || ParticipantId(*prepared.receiver_id()) != self.local_participant
                    || ParticipantId(*prepared.sender_id()) != self.remote_participant
                {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::FinalClaimIngressV2(prepared) => {
                // Three predicates, all against facts frozen before this call:
                // the session comes from the store opening, and the two
                // participants from the route configuration.  The Store has
                // already bound the identities into the capability; this is
                // the worker refusing a capability issued for another session
                // or another pair, so a misrouted `0x12` fails here and not
                // one layer down.
                if prepared.session_id() != &self.session_id
                    || ParticipantId(*prepared.final_claim_receiver_id()) != self.local_participant
                    || ParticipantId(*prepared.dom_claim_sender_id()) != self.remote_participant
                {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::UniversalClaimPreSignatureV12(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
            }
            PreparedContractsIngressKindV1::UniversalReadyToFundV12(prepared) => {
                if prepared.session_id() != &self.session_id {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
                match self
                    .store
                    .prepare_next_operational_xmr_ready_to_fund_vote_v12(prepared)?
                {
                    Some(vote) if vote.session_id() != self.session_id => {
                        return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                    }
                    Some(_) => {}
                    None => return Err(ContractsRelayIngressErrorV1::UnpreparedMessage),
                }
            }
            PreparedContractsIngressKindV1::ReadyToFundV2(prepared) => {
                match self
                    .store
                    .prepare_next_operational_m8_ready_to_fund_vote_v2(prepared)?
                {
                    Some(vote) if vote.session_id() != self.session_id => {
                        return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                    }
                    Some(_) => {}
                    // Both votes already durable means Relay ingress has no
                    // remaining work.  The caller must retain/take the gate
                    // for funding instead of installing a no-op authority.
                    None => return Err(ContractsRelayIngressErrorV1::UnpreparedMessage),
                }
            }
        }
        self.authority = Some(authority);
        Ok(())
    }

    fn take_authority(&mut self) -> Option<PreparedContractsIngressV1> {
        self.authority.take()
    }

    // A dedicated ownership transition, deliberately outside the general
    // refresh whitelist. The native gate proves the final refund predecessor.
    fn install_f7_readiness_v19(
        &mut self,
        gate: dom_scriptless_store::PreparedF7FundingGateV12,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        use PreparedContractsIngressKindV1 as Kind;
        if gate.session_id() != &self.session_id {
            return Err(ContractsRelayIngressErrorV1::WrongAuthority);
        }
        if self
            .store
            .prepare_next_operational_xmr_ready_to_fund_vote_v12(&gate)?
            .is_none()
        {
            return Err(ContractsRelayIngressErrorV1::UnpreparedMessage);
        }
        match self.authority.as_ref().map(|value| &value.inner) {
            Some(Kind::UniversalReadyToFundV12(existing)) => {
                if existing.session_id() != gate.session_id()
                    || existing.ready_to_fund_vote_payload() != gate.ready_to_fund_vote_payload()
                {
                    return Err(ContractsRelayIngressErrorV1::WrongAuthority);
                }
                // Keep the originally installed linear owner.
                return Ok(());
            }
            Some(Kind::XmrGraphSigningV23(previous)) => {
                self.store
                    .require_xmr_bounded_ready_handoff_v23(previous, &gate)?;
            }
            None | Some(Kind::OperationalFinalRefund(_)) => {}
            _ => return Err(ContractsRelayIngressErrorV1::AuthorityAlreadyInstalled),
        }
        let previous = self.authority.take();
        if let Err(error) = self.install(PreparedContractsIngressV1::universal_ready_to_fund_v12(
            gate,
        )) {
            self.authority = previous;
            return Err(error);
        }
        Ok(())
    }

    fn finish_f7_readiness_v19(&mut self) -> Result<(), ContractsRelayIngressErrorV1> {
        let Some(PreparedContractsIngressV1 {
            inner: PreparedContractsIngressKindV1::UniversalReadyToFundV12(gate),
        }) = self.authority.as_ref()
        else {
            // A later signing/claim owner must never be discarded by a tick
            // which is merely observing completed readiness.
            return Ok(());
        };
        if self
            .store
            .prepare_next_operational_xmr_ready_to_fund_vote_v12(gate)?
            .is_some()
        {
            return Err(ContractsRelayIngressErrorV1::UnpreparedMessage);
        }
        self.authority.take();
        Ok(())
    }

    fn handoff_funding_signing_v20(
        &mut self,
        authority: dom_scriptless_store::PreparedOperationalSigningTransportAuthorityV1,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        use PreparedContractsIngressKindV1 as Kind;
        if authority.session_id() != &self.session_id
            || authority.purpose() != dom_adaptor::PurposeV1::Funding
        {
            return Err(ContractsRelayIngressErrorV1::WrongAuthority);
        }
        match self.authority.as_ref().map(|value| &value.inner) {
            None | Some(Kind::OperationalFinalRefund(_)) => {}
            Some(Kind::OperationalSigning(old))
                if old.purpose() == authority.purpose()
                    && old.session_id() == authority.session_id() =>
            {
                return Ok(())
            }
            Some(Kind::UniversalReadyToFundV12(gate)) => {
                if self
                    .store
                    .prepare_next_operational_xmr_ready_to_fund_vote_v12(gate)?
                    .is_some()
                {
                    return Err(ContractsRelayIngressErrorV1::UnpreparedMessage);
                }
            }
            _ => return Err(ContractsRelayIngressErrorV1::AuthorityAlreadyInstalled),
        }
        let previous = self.authority.take();
        if let Err(error) = self.install(PreparedContractsIngressV1::operational_signing(authority))
        {
            self.authority = previous;
            return Err(error);
        }
        Ok(())
    }

    fn finish_funding_signing_v20(
        &mut self,
        chain: dom_adaptor::TrustedChainIdV1,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        let Some(PreparedContractsIngressV1 {
            inner: PreparedContractsIngressKindV1::OperationalSigning(authority),
        }) = self.authority.as_ref()
        else {
            return Ok(());
        };
        if authority.purpose() != dom_adaptor::PurposeV1::Funding {
            return Ok(());
        }
        let head = self.store.load_session(self.session_id)?;
        if head.phase() != dom_scriptless_store::SessionPhaseV1::FundingBroadcast {
            return Err(ContractsRelayIngressErrorV1::UnpreparedMessage);
        }
        // Native committed bytes, not a phase flag, authorize this handoff.
        let gate = self
            .store
            .resume_f7_funding_gate_v12(chain, self.session_id)?;
        let _funding = self.store.resume_f7_committed_funding_v12(&gate)?;
        self.authority.take();
        Ok(())
    }

    // Both handoffs require a new native capability before the old owner is
    // touched. They do not extend the generic refresh path to signing gates.
    fn handoff_claim_signing_v19(
        &mut self,
        authority: dom_scriptless_store::PreparedOperationalSigningTransportAuthorityV1,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        use PreparedContractsIngressKindV1 as Kind;
        if authority.session_id() != &self.session_id
            || authority.purpose() != dom_adaptor::PurposeV1::ClaimAdaptor
        {
            return Err(ContractsRelayIngressErrorV1::WrongAuthority);
        }
        match self.authority.as_ref().map(|value| &value.inner) {
            None | Some(Kind::OperationalFinalRefund(_)) => {}
            Some(Kind::OperationalSigning(old))
                if old.session_id() == authority.session_id()
                    && old.purpose() == authority.purpose() =>
            {
                return Ok(())
            }
            Some(Kind::UniversalReadyToFundV12(gate)) => {
                if self
                    .store
                    .prepare_next_operational_xmr_ready_to_fund_vote_v12(gate)?
                    .is_some()
                {
                    return Err(ContractsRelayIngressErrorV1::UnpreparedMessage);
                }
            }
            Some(Kind::ReadyToFundV2(gate)) => {
                if self
                    .store
                    .prepare_next_operational_m8_ready_to_fund_vote_v2(gate)?
                    .is_some()
                {
                    return Err(ContractsRelayIngressErrorV1::UnpreparedMessage);
                }
            }
            _ => return Err(ContractsRelayIngressErrorV1::AuthorityAlreadyInstalled),
        }
        let previous = self.authority.take();
        if let Err(error) = self.install(PreparedContractsIngressV1::operational_signing(authority))
        {
            self.authority = previous;
            return Err(error);
        }
        Ok(())
    }

    fn handoff_m8_final_claim_v22(
        &mut self,
        authority: dom_scriptless_store::PreparedOperationalFinalClaimIngressAuthorityV2,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        use PreparedContractsIngressKindV1 as Kind;
        if authority.session_id() != &self.session_id
            || ParticipantId(*authority.final_claim_receiver_id()) != self.local_participant
            || ParticipantId(*authority.dom_claim_sender_id()) != self.remote_participant
        {
            return Err(ContractsRelayIngressErrorV1::WrongAuthority);
        }
        match self.authority.as_ref().map(|value| &value.inner) {
            None
            | Some(Kind::PostAnchorClaimPreSignatureV2(_))
            | Some(Kind::FinalClaimIngressV2(_)) => {}
            Some(Kind::OperationalSigning(old))
                if old.purpose() == dom_adaptor::PurposeV1::ClaimAdaptor => {}
            _ => return Err(ContractsRelayIngressErrorV1::AuthorityAlreadyInstalled),
        }
        let previous = self.authority.take();
        if let Err(error) = self.install(PreparedContractsIngressV1::final_claim_ingress_v2(
            authority,
        )) {
            self.authority = previous;
            return Err(error);
        }
        Ok(())
    }

    fn handoff_f7_final_claim_v19(
        &mut self,
        authority: dom_scriptless_store::PreparedF7FinalClaimIngressV15,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        use PreparedContractsIngressKindV1 as Kind;
        if authority.session_id() != &self.session_id
            || ParticipantId(*authority.receiver_id()) != self.local_participant
            || ParticipantId(*authority.sender_id()) != self.remote_participant
        {
            return Err(ContractsRelayIngressErrorV1::WrongAuthority);
        }
        // This native receiver capability requires the exact accepted 0x0f
        // AND the durably recorded canonical claim observation. Consequently
        // it proves completion of an old claim-signing/pre-signature ingress.
        match self.authority.as_ref().map(|value| &value.inner) {
            None
            | Some(Kind::OperationalFinalRefund(_))
            | Some(Kind::UniversalClaimPreSignatureV12(_))
            | Some(Kind::UniversalFinalClaimV15(_)) => {}
            Some(Kind::OperationalSigning(old))
                if old.purpose() == dom_adaptor::PurposeV1::ClaimAdaptor => {}
            _ => return Err(ContractsRelayIngressErrorV1::AuthorityAlreadyInstalled),
        }
        let previous = self.authority.take();
        if let Err(error) = self.install(PreparedContractsIngressV1::universal_final_claim_v15(
            authority,
        )) {
            self.authority = previous;
            return Err(error);
        }
        Ok(())
    }

    // Only reconstructible transport capabilities may be refreshed. Funding
    // votes and signing gates are linear and must still be explicitly taken
    // and consumed by their owner. Validate first; restore on any refusal.
    fn refresh_reissued_v16(
        &mut self,
        authority: PreparedContractsIngressV1,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        use PreparedContractsIngressKindV1 as Kind;
        let old_allowed = matches!(
            (&self.authority, &authority.inner),
            (
                None,
                Kind::Early(_) | Kind::OperationalBp(_) | Kind::UniversalFinalClaimV15(_)
            ) | (
                Some(PreparedContractsIngressV1 {
                    inner: Kind::Early(_)
                }),
                Kind::Early(_) | Kind::OperationalBp(_)
            ) | (
                Some(PreparedContractsIngressV1 {
                    inner: Kind::OperationalBp(_)
                }),
                Kind::OperationalBp(_)
            ) | (
                Some(PreparedContractsIngressV1 {
                    inner: Kind::UniversalFinalClaimV15(_)
                }),
                Kind::UniversalFinalClaimV15(_)
            )
        );
        // All of these handles are reissued from immutable native records.
        // Only ordinary Refund may occupy the signing position. Linear F7,
        // M.8 and claim permits are outside this replacement path.
        let bootstrap_rank = |kind: &Kind| -> Option<u8> {
            match kind {
                Kind::Early(_) => Some(0),
                Kind::OperationalBp(_) => Some(1),
                Kind::OperationalTemplate(_) => Some(2),
                Kind::OperationalSigning(prepared)
                    if prepared.purpose() == dom_adaptor::PurposeV1::Refund =>
                {
                    Some(3)
                }
                Kind::OperationalFinalRefund(_) => Some(4),
                _ => None,
            }
        };
        let bootstrap_allowed = match (self.authority.as_ref(), bootstrap_rank(&authority.inner)) {
            (None, Some(_)) => true,
            (Some(old), Some(next)) => {
                bootstrap_rank(&old.inner).is_some_and(|previous| next >= previous)
            }
            _ => false,
        };
        // A Store-issued graph handle proves C/D reconstruction; it may replace
        // only the completed BP receiver or an earlier instance of itself.
        let graph_allowed = matches!(
            (
                self.authority.as_ref().map(|old| &old.inner),
                &authority.inner
            ),
            (
                None | Some(Kind::OperationalBp(_)) | Some(Kind::XmrGraphCommitV23(_)),
                Kind::XmrGraphCommitV23(_)
            )
        );
        let graph_signing_allowed = matches!(
            (
                self.authority.as_ref().map(|old| &old.inner),
                &authority.inner
            ),
            (
                None | Some(Kind::OperationalBp(_))
                    | Some(Kind::XmrGraphCommitV23(_))
                    | Some(Kind::XmrGraphSigningV23(_)),
                Kind::XmrGraphSigningV23(_)
            )
        );
        let allowed = old_allowed || bootstrap_allowed || graph_allowed || graph_signing_allowed;
        if !allowed {
            return Err(ContractsRelayIngressErrorV1::AuthorityAlreadyInstalled);
        }
        let previous = self.authority.take();
        if let Err(error) = self.install(authority) {
            self.authority = previous;
            return Err(error);
        }
        Ok(())
    }

    fn session_status(&self) -> Result<ContractsSessionStatusV1, SessionStoreError> {
        let current = self.store.load_session(self.session_id)?;
        Ok(ContractsSessionStatusV1 {
            revision: current.revision(),
            phase: current.phase(),
        })
    }

    fn terminal_commit(
        &self,
        duplicate: bool,
    ) -> Result<Option<DurablePayloadCommitV1>, ContractsRelayIngressErrorV1> {
        let current = self.store.load_session(self.session_id)?;
        if current.phase() != SessionPhaseV1::FailedClosed {
            return Ok(None);
        }
        let receipt = digest_parts(
            FAILED_CLOSED_RECEIPT_DOMAIN,
            &[&self.session_id, current.digest()],
        )?;
        DurablePayloadCommitV1::new(
            DurablePayloadDispositionV1::FailedClosed,
            receipt,
            duplicate,
        )
        .map(Some)
        .map_err(|_| ContractsRelayIngressErrorV1::InvalidReceipt)
    }

    fn map_outcome(
        &self,
        outcome: DurableTransportOutcomeV1,
    ) -> Result<DurablePayloadCommitV1, ContractsRelayIngressErrorV1> {
        match outcome {
            DurableTransportOutcomeV1::Accepted(receipt) => {
                let digest = accepted_receipt_digest(self.session_id, receipt)?;
                DurablePayloadCommitV1::new(
                    DurablePayloadDispositionV1::Applied,
                    digest,
                    receipt.duplicate,
                )
                .map_err(|_| ContractsRelayIngressErrorV1::InvalidReceipt)
            }
            DurableTransportOutcomeV1::EquivocationPersisted => self
                .terminal_commit(false)?
                .ok_or(ContractsRelayIngressErrorV1::InvalidReceipt),
        }
    }

    fn accept_unseen(
        &self,
        signed_dsc1: &[u8],
    ) -> Result<DurablePayloadCommitV1, ContractsRelayIngressErrorV1> {
        let Some(authority) = self.authority.as_ref() else {
            return self
                .terminal_commit(true)?
                .ok_or(ContractsRelayIngressErrorV1::UnpreparedMessage);
        };
        let accepted = match &authority.inner {
            PreparedContractsIngressKindV1::XmrGraphSigningV23(prepared) => {
                if self
                    .store
                    .xmr_readiness_awaits_gate_v25(prepared, signed_dsc1)?
                {
                    return Err(ContractsRelayIngressErrorV1::AwaitingNativeXmrReadinessGateV25);
                }
                self.store
                    .accept_xmr_graph_signing_ingress_v23(prepared, signed_dsc1)
            }
            PreparedContractsIngressKindV1::XmrGraphCommitV23(prepared) => self
                .store
                .accept_xmr_graph_commit_ingress_v23(prepared, signed_dsc1),
            PreparedContractsIngressKindV1::Early(prepared) => self
                .store
                .accept_prepared_early_transport_message(prepared, signed_dsc1),
            PreparedContractsIngressKindV1::OperationalBp(prepared) => self
                .store
                .accept_prepared_operational_bp_transport_message(prepared, signed_dsc1),
            PreparedContractsIngressKindV1::OperationalTemplate(prepared) => self
                .store
                .accept_prepared_operational_template_transport_message(prepared, signed_dsc1),
            PreparedContractsIngressKindV1::OperationalSigning(prepared) => self
                .store
                .accept_prepared_operational_signing_transport_message(prepared, signed_dsc1),
            PreparedContractsIngressKindV1::OperationalFinalRefund(prepared) => self
                .store
                .accept_prepared_operational_final_refund_transport_message(prepared, signed_dsc1),
            PreparedContractsIngressKindV1::PostAnchorClaimPreSignature(prepared) => self
                .store
                .accept_prepared_post_anchor_dom_claim_pre_signature_transport_message(
                    prepared,
                    signed_dsc1,
                ),
            PreparedContractsIngressKindV1::PostAnchorClaimPreSignatureV2(prepared) => self
                .store
                .accept_prepared_post_anchor_dom_claim_pre_signature_transport_message_v2(
                    prepared,
                    signed_dsc1,
                ),
            PreparedContractsIngressKindV1::UniversalFinalClaimV15(prepared) => self
                .store
                .accept_prepared_f7_final_claim_transport_v15(prepared, signed_dsc1),
            PreparedContractsIngressKindV1::FinalClaimIngressV2(prepared) => self
                .store
                .accept_prepared_operational_final_claim_transport_message_v2(
                    prepared,
                    signed_dsc1,
                ),
            PreparedContractsIngressKindV1::UniversalClaimPreSignatureV12(prepared) => {
                self.store
                    .accept_prepared_f7_claim_pre_signature_transport_v12(prepared, signed_dsc1)?;
                let replay = self.store.accept_transport_message_derived(signed_dsc1)?;
                let receipt = first_delivery_receipt_from_prepared_readback(replay)
                    .map_err(ContractsRelayIngressErrorV1::Store)?;
                return self.map_accepted_receipt(receipt, false);
            }
            PreparedContractsIngressKindV1::UniversalReadyToFundV12(prepared) => {
                let vote = self
                    .store
                    .prepare_next_operational_xmr_ready_to_fund_vote_v12(prepared)?
                    .ok_or(ContractsRelayIngressErrorV1::UnpreparedMessage)?;
                self.store
                    .accept_prepared_operational_xmr_ready_to_fund_vote_v12(
                        prepared,
                        vote,
                        signed_dsc1,
                    )?;
                // Only the phase-specific native gate may create this row.
                // The generic path below reads its exact committed receipt.
                let replay = self.store.accept_transport_message_derived(signed_dsc1)?;
                let receipt = first_delivery_receipt_from_prepared_readback(replay)
                    .map_err(ContractsRelayIngressErrorV1::Store)?;
                return self.map_accepted_receipt(receipt, false);
            }
            PreparedContractsIngressKindV1::ReadyToFundV2(prepared) => {
                let vote = self
                    .store
                    .prepare_next_operational_m8_ready_to_fund_vote_v2(prepared)?
                    .ok_or(ContractsRelayIngressErrorV1::UnpreparedMessage)?;
                self.store
                    .accept_prepared_operational_m8_ready_to_fund_vote_v2(
                        prepared,
                        vote,
                        signed_dsc1,
                    )?;
                // The purpose-specific Store method above owns semantic
                // validation and the first durable transition, but returns
                // `()`.  The generic derived entrypoint is then safe only as
                // an exact-redelivery readback: it retrieves the authenticated
                // receipt from the just-retained row.  It must report a
                // duplicate; the worker clears that flag for this first outer
                // delivery before committing its inbox row.
                let replay = self.store.accept_transport_message_derived(signed_dsc1)?;
                let receipt = first_delivery_receipt_from_prepared_readback(replay)
                    .map_err(ContractsRelayIngressErrorV1::Store)?;
                return self.map_accepted_receipt(receipt, false);
            }
        };
        match accepted {
            Ok(outcome) => self.map_outcome(outcome),
            Err(error) => self
                .terminal_commit(true)?
                .ok_or(ContractsRelayIngressErrorV1::Store(error)),
        }
    }

    fn map_accepted_receipt(
        &self,
        receipt: DurableTransportReceiptV1,
        duplicate: bool,
    ) -> Result<DurablePayloadCommitV1, ContractsRelayIngressErrorV1> {
        let digest = accepted_receipt_digest(self.session_id, receipt)?;
        DurablePayloadCommitV1::new(DurablePayloadDispositionV1::Applied, digest, duplicate)
            .map_err(|_| ContractsRelayIngressErrorV1::InvalidReceipt)
    }
}

fn require_public_refund_payload_v24(
    kind: MessageTypeV1,
    payload: &[u8],
) -> Result<(), ContractsRelayIngressErrorV1> {
    use xmr_remote_sweep_wire::{
        RemoteSweepActionV23, RemoteSweepRequestV23, RemoteSweepResponseV23,
    };
    let action = match kind {
        MessageTypeV1::XmrRemoteSweepRequestV23 => {
            RemoteSweepRequestV23::decode_exact(payload).map(|request| request.action)
        }
        MessageTypeV1::XmrRemoteSweepResponseV23 => {
            RemoteSweepResponseV23::decode_exact(payload).map(|response| response.action())
        }
        _ => return Err(ContractsRelayIngressErrorV1::UnpreparedMessage),
    }
    .map_err(|_| ContractsRelayIngressErrorV1::InvalidDsc1)?;
    if action != RemoteSweepActionV23::Refund {
        return Err(ContractsRelayIngressErrorV1::UnpreparedMessage);
    }
    // This filter grants nothing: the original Store transition below still
    // authenticates signature, phase, pairing, economic scope and uniqueness.
    Ok(())
}

impl ContractsTransportPortV1 for ContractsStoreTransportPortV1 {
    type Error = ContractsRelayIngressErrorV1;

    fn accept_signed_dsc1(
        &mut self,
        delivery: ContractsRouteDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error> {
        let parsed = SignedMessageV1::decode_exact(delivery.signed_dsc1())
            .map_err(|_| ContractsRelayIngressErrorV1::InvalidDsc1)?;
        if ParticipantId(*parsed.unsigned().sender_id()) != delivery.sender_id() {
            return Err(ContractsRelayIngressErrorV1::SenderMismatch);
        }
        if self.terminal_refund_only_v24 {
            require_public_refund_payload_v24(
                parsed.unsigned().kind(),
                parsed.unsigned().payload(),
            )?;
        }
        let was_failed_closed =
            self.store.load_session(self.session_id)?.phase() == SessionPhaseV1::FailedClosed;
        // XMR remote sweep messages have a dedicated Store transition that
        // authenticates role, pairing, live phase and economic uniqueness.
        // Persist through that narrow API first; the generic call below is
        // only the canonical duplicate/readback used to mint the Relay
        // receipt, never the signing witness consumed by the responder.
        let typed_xmr = match parsed.unsigned().kind() {
            MessageTypeV1::XmrRemoteSweepRequestV23 => self
                .store
                .accept_xmr_remote_sweep_request_transport_message(delivery.signed_dsc1())
                .map(|accepted| drop(accepted)),
            MessageTypeV1::XmrRemoteSweepResponseV23 => self
                .store
                .accept_xmr_remote_sweep_response_transport_message(delivery.signed_dsc1())
                .map(|accepted| drop(accepted)),
            _ => Ok(()),
        };
        if matches!(
            parsed.unsigned().kind(),
            MessageTypeV1::XmrRemoteSweepRequestV23 | MessageTypeV1::XmrRemoteSweepResponseV23
        ) {
            if let Err(error) = typed_xmr {
                if matches!(error, SessionStoreError::NativeXmrRefundTransportPendingV23) {
                    return Err(ContractsRelayIngressErrorV1::AwaitingNativeXmrRefundTransportV23);
                }
                return self
                    .terminal_commit(true)?
                    .ok_or(ContractsRelayIngressErrorV1::Store(error));
            }
            return match self
                .store
                .accept_transport_message_derived(delivery.signed_dsc1())
            {
                Ok(outcome) => {
                    let receipt = first_delivery_receipt_from_prepared_readback(outcome)
                        .map_err(ContractsRelayIngressErrorV1::Store)?;
                    self.map_accepted_receipt(receipt, false)
                }
                Err(error) => self
                    .terminal_commit(true)?
                    .ok_or(ContractsRelayIngressErrorV1::Store(error)),
            };
        }
        // DIAG(temporary): the ready-to-fund vote is the one message whose
        // semantic acceptance lives behind the generic derived entry point.
        // Name the branch that consumed it and the session revision on both
        // sides of the call: a vote that is acknowledged without advancing the
        // recipient's revision is the deadlock this run keeps reproducing.
        let ready_vote_v25 = parsed.unsigned().kind() as u8 == 0x17;
        let rev_before_v25 = if ready_vote_v25 {
            self.store.load_session(self.session_id).map(|s| s.revision()).ok()
        } else {
            None
        };
        let diag_v25 = |branch: &str, worker: &Self| {
            if let Some(before) = rev_before_v25 {
                let after = worker.store.load_session(worker.session_id).map(|s| s.revision()).ok();
                eprintln!(
                    "DOM_READY_APPLY_V25 branch={branch} rev_before={before} rev_after={after:?}"
                );
            }
        };
        match self
            .store
            .accept_transport_message_derived(delivery.signed_dsc1())
        {
            Ok(DurableTransportOutcomeV1::EquivocationPersisted) if was_failed_closed => self
                .terminal_commit(true)?
                .ok_or(ContractsRelayIngressErrorV1::InvalidReceipt),
            Ok(outcome) => {
                diag_v25("derived", self);
                self.map_outcome(outcome)
            }
            Err(SessionStoreError::InvalidTransition) => {
                let stale_refund_ingress = matches!(
                    (&self.authority, parsed.unsigned().kind() as u8),
                    (
                        Some(PreparedContractsIngressV1 {
                            inner: PreparedContractsIngressKindV1::OperationalTemplate(_)
                        }),
                        0x0c
                    ) | (
                        Some(PreparedContractsIngressV1 {
                            inner: PreparedContractsIngressKindV1::OperationalSigning(_)
                        }),
                        0x10
                    )
                );
                if stale_refund_ingress
                    && self.store.bootstrap_refund_awaits_handoff_v18(
                        self.session_id,
                        delivery.signed_dsc1(),
                    )?
                {
                    return Err(ContractsRelayIngressErrorV1::AwaitingBootstrapRefundHandoffV18);
                }
                if self.store.template_commit_awaits_construction_v17(
                    self.session_id,
                    delivery.signed_dsc1(),
                )? {
                    return Err(ContractsRelayIngressErrorV1::AwaitingTemplateConstructionV17);
                }
                if self.store.f7_final_claim_awaits_observation_v16(
                    self.session_id,
                    self.local_participant.0,
                    delivery.signed_dsc1(),
                )? {
                    return Err(ContractsRelayIngressErrorV1::AwaitingFinalClaimObservationV16);
                }
                if !matches!(
                    self.authority.as_ref().map(|value| &value.inner),
                    Some(PreparedContractsIngressKindV1::UniversalFinalClaimV15(_))
                ) && self.store.f7_final_claim_awaits_ingress_handoff_v29(
                    self.session_id,
                    self.local_participant.0,
                    delivery.signed_dsc1(),
                )? {
                    return Err(ContractsRelayIngressErrorV1::AwaitingFinalClaimIngressHandoffV29);
                }
                if self.store.xmr_funding_commitment_awaits_handoff_v25(
                    self.session_id,
                    delivery.signed_dsc1(),
                )? {
                    return Err(ContractsRelayIngressErrorV1::AwaitingNativeXmrFundingHandoffV25);
                }
                let outcome = self.accept_unseen(delivery.signed_dsc1());
                diag_v25("unseen", self);
                outcome
            }
            Err(error) => {
                diag_v25("store_error", self);
                self.terminal_commit(true)?
                    .ok_or(ContractsRelayIngressErrorV1::Store(error))
            }
        }
    }
}

/// Productive, durable Relay worker for one local participant and route.
///
/// `F` is the real F6 persistence authority.  Deployments that have not wired
/// it may explicitly select [`UnavailableF6AuthorityV1`], which blocks rather
/// than skips F6.  The Contracts authority is fixed to the real
/// `ContractsSessionStoreV1` and cannot be replaced by a caller-shaped port.
pub struct DurableRelayWorkerV1<F>
where
    F: F6TransportPortV1,
{
    sender: DurableRelaySenderV1,
    inbox: DurableRelayInboxV1,
    contracts: FramedContractsTransportV2<ContractsStoreTransportPortV1>,
    rosters: RosterRegistryV1,
    f6: F,
}

impl<F> core::fmt::Debug for DurableRelayWorkerV1<F>
where
    F: F6TransportPortV1,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DurableRelayWorkerV1")
            .field("sender", &self.sender)
            .field("inbox", &self.inbox)
            .field("contracts", &"[redacted]")
            .field("f6", &"[redacted]")
            .finish()
    }
}

impl<F> DurableRelayWorkerV1<F>
where
    F: F6TransportPortV1,
{
    /// Creates the three durable Relay authorities around the single shared
    /// opening of a production Contracts Store.  Partial creation remains on
    /// disk and is never silently replaced by a fresh store.
    pub fn create(
        paths: &RelayWorkerPathsV1,
        config: RelayWorkerConfigV1,
        contracts_store: Rc<ContractsSessionStoreV1>,
        rosters: RosterRegistryV1,
        f6: F,
        signing_secret: [u8; 32],
    ) -> Result<Self, RelayWorkerOpenErrorV1> {
        validate_roster(&config, &rosters)?;
        let contracts = ContractsStoreTransportPortV1::new(
            contracts_store,
            config.wire_context().session_id,
            config.local_participant(),
            config.remote_participant(),
        )?;
        let sender = DurableRelaySenderV1::create(
            paths.sender_root(),
            config.sender,
            signing_secret,
            os_random_32().map_err(|_| RelayWorkerOpenErrorV1::EntropyUnavailable)?,
        )?;
        let inbox = DurableRelayInboxV1::create(paths.inbox_root(), config.inbox, &rosters)?;
        let frames =
            DurableFrameReassemblerV2::create(paths.frame_reassembly_root(), config.frames)?;
        Ok(Self {
            sender,
            inbox,
            contracts: FramedContractsTransportV2::new(frames, contracts),
            rosters,
            f6,
        })
    }

    /// Completes a Stage-11 production create after a crash at any of the
    /// three Relay authority boundaries. Each underlying resume accepts only
    /// its exact pristine creation prefix; an authority that has accepted or
    /// emitted economic traffic cannot be reclassified as provisioning.
    ///
    /// The caller supplies the same single `Rc` opening owned by
    /// `ProductionContractsV1`; this method never opens, clones, or replaces a
    /// Contracts Store.
    pub fn resume_create_production(
        paths: &RelayWorkerPathsV1,
        config: RelayWorkerConfigV1,
        contracts_store: Rc<ContractsSessionStoreV1>,
        rosters: RosterRegistryV1,
        f6: F,
        signing_secret: [u8; 32],
    ) -> Result<Self, RelayWorkerOpenErrorV1> {
        validate_roster(&config, &rosters)?;
        let sender_state =
            DurableRelaySenderV1::production_creation_state(paths.sender_root(), config.sender)?;
        let inbox_state =
            DurableRelayInboxV1::production_creation_state(paths.inbox_root(), config.inbox)?;
        let frame_state = DurableFrameReassemblerV2::production_creation_state(
            paths.frame_reassembly_root(),
            config.frames,
        )?;
        if (inbox_state != DurableProductionCreationStateV1::Missing
            && sender_state != DurableProductionCreationStateV1::InitializedPristine)
            || (frame_state != DurableProductionCreationStateV1::Missing
                && inbox_state != DurableProductionCreationStateV1::InitializedPristine)
        {
            return Err(RelayWorkerOpenErrorV1::InvalidConfiguration);
        }
        let contracts = ContractsStoreTransportPortV1::new(
            contracts_store,
            config.wire_context().session_id,
            config.local_participant(),
            config.remote_participant(),
        )?;
        let sender = DurableRelaySenderV1::resume_create_production(
            paths.sender_root(),
            config.sender,
            signing_secret,
            os_random_32().map_err(|_| RelayWorkerOpenErrorV1::EntropyUnavailable)?,
        )?;
        let inbox = DurableRelayInboxV1::resume_create_production(
            paths.inbox_root(),
            config.inbox,
            &rosters,
        )?;
        let frames = DurableFrameReassemblerV2::resume_create_production(
            paths.frame_reassembly_root(),
            config.frames,
        )?;
        Ok(Self {
            sender,
            inbox,
            contracts: FramedContractsTransportV2::new(frames, contracts),
            rosters,
            f6,
        })
    }

    /// Reopens the exact three Relay stores around the single shared Contracts
    /// Store opening.  No missing database is created and no schema migration
    /// or capability reissuance happens implicitly.
    pub fn open_existing(
        paths: &RelayWorkerPathsV1,
        config: RelayWorkerConfigV1,
        contracts_store: Rc<ContractsSessionStoreV1>,
        rosters: RosterRegistryV1,
        f6: F,
        signing_secret: [u8; 32],
    ) -> Result<Self, RelayWorkerOpenErrorV1> {
        validate_roster(&config, &rosters)?;
        let contracts = ContractsStoreTransportPortV1::new(
            contracts_store,
            config.wire_context().session_id,
            config.local_participant(),
            config.remote_participant(),
        )?;
        let sender = DurableRelaySenderV1::open_existing(
            paths.sender_root(),
            config.sender,
            signing_secret,
            os_random_32().map_err(|_| RelayWorkerOpenErrorV1::EntropyUnavailable)?,
        )?;
        let inbox = DurableRelayInboxV1::open(paths.inbox_root(), config.inbox, &rosters)?;
        let frames = DurableFrameReassemblerV2::open(paths.frame_reassembly_root(), config.frames)?;
        Ok(Self {
            sender,
            inbox,
            contracts: FramedContractsTransportV2::new(frames, contracts),
            rosters,
            f6,
        })
    }

    /// Installs one process-only Store-issued ingress capability.  This covers
    /// the early rounds, operational Bulletproof/template/signing rounds, the
    /// exact final Refund, the V2 post-anchor Claim pre-signature edge (or its
    /// legacy V1 recovery form), or the M.8 vote gate.
    /// An existing linear capability must first be taken; unsupported phases
    /// remain closed.
    pub fn install_contracts_ingress(
        &mut self,
        authority: PreparedContractsIngressV1,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        self.contracts.contracts_mut().install(authority)
    }

    pub(crate) fn install_f7_readiness_v19(
        &mut self,
        gate: dom_scriptless_store::PreparedF7FundingGateV12,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        self.contracts
            .contracts_mut()
            .install_f7_readiness_v19(gate)
    }

    pub(crate) fn finish_f7_readiness_v19(&mut self) -> Result<(), ContractsRelayIngressErrorV1> {
        self.contracts.contracts_mut().finish_f7_readiness_v19()
    }

    pub(crate) fn handoff_funding_signing_v20(
        &mut self,
        authority: dom_scriptless_store::PreparedOperationalSigningTransportAuthorityV1,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        self.contracts
            .contracts_mut()
            .handoff_funding_signing_v20(authority)
    }

    pub(crate) fn finish_funding_signing_v20(
        &mut self,
        chain: dom_adaptor::TrustedChainIdV1,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        self.contracts
            .contracts_mut()
            .finish_funding_signing_v20(chain)
    }

    pub(crate) fn handoff_claim_signing_v19(
        &mut self,
        authority: dom_scriptless_store::PreparedOperationalSigningTransportAuthorityV1,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        self.contracts
            .contracts_mut()
            .handoff_claim_signing_v19(authority)
    }

    pub(crate) fn handoff_m8_final_claim_v22(
        &mut self,
        authority: dom_scriptless_store::PreparedOperationalFinalClaimIngressAuthorityV2,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        self.contracts
            .contracts_mut()
            .handoff_m8_final_claim_v22(authority)
    }

    pub(crate) fn handoff_f7_final_claim_v19(
        &mut self,
        authority: dom_scriptless_store::PreparedF7FinalClaimIngressV15,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        self.contracts
            .contracts_mut()
            .handoff_f7_final_claim_v19(authority)
    }

    /// Takes the process-local capability without cloning or discarding it.
    ///
    /// This is required after both M.8 votes so the caller can unwrap the same
    /// linear gate with [`PreparedContractsIngressV1::into_ready_to_fund_v2`] and
    /// consume it at the Store's funding-authorization boundary.  It also
    /// permits restart-safe reissue of early, Bulletproof, template, signing,
    /// final Refund or post-anchor Claim pre-signature (V1 or V2) authorities.
    /// With no installed capability, unseen DSC1 messages remain fail-closed.
    pub fn take_contracts_ingress(&mut self) -> Option<PreparedContractsIngressV1> {
        self.contracts.contracts_mut().take_authority()
    }

    /// Refresh only native early/BP or receiver observation capabilities.
    /// Other linear gates are never discarded by this operation.
    pub fn refresh_reissued_contracts_ingress_v16(
        &mut self,
        authority: PreparedContractsIngressV1,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        self.contracts
            .contracts_mut()
            .refresh_reissued_v16(authority)
    }

    /// Returns only the secret-free authenticated Contracts head.
    ///
    /// The underlying Store is intentionally not exposed: its APIs mutate via
    /// shared references, so returning `&ContractsSessionStoreV1` would bypass
    /// the worker's phase authority and inbox ordering.
    pub fn contracts_session_status(
        &mut self,
    ) -> Result<ContractsSessionStatusV1, SessionStoreError> {
        self.contracts.contracts_mut().session_status()
    }

    /// Persists one F6 envelope before any Relay submission.
    pub fn prepare_f6(
        &mut self,
        kind: RelayF6MessageKindV1,
        payload: &[u8],
        expiry: TimelockSpec,
    ) -> Result<PreparedRelayOutboundV1, RelayWorkerOutboundErrorV1> {
        let pending = self.sender.prepare_message(
            kind.wire_kind(),
            payload,
            expiry,
            os_random_32().map_err(|_| RelayWorkerOutboundErrorV1::EntropyUnavailable)?,
        )?;
        Ok(prepared_report(&pending))
    }

    /// Returns true when an RFQ envelope was ever prepared by this durable
    /// sender (still pending or already handed to the Relay). The initiator's
    /// RFQ is deterministic for the route, so crash recovery must not prepare
    /// a second RFQ envelope with a fresh expiry.
    pub fn f6_rfq_already_prepared_v25(&mut self) -> Result<bool, RelayWorkerOutboundErrorV1> {
        Ok(self
            .sender
            .kind_ever_prepared_v25(message_type::RFQ)
            .map_err(RelayWorkerOutboundErrorV1::from)?)
    }

    /// Applies the initiator's own deterministic RFQ to the local F6 port.
    ///
    /// F6 is a replicated machine: the same RFQ object the initiator submits
    /// over the Relay must also activate the initiator's own F6 authority.
    /// This method only forwards a kind-restricted local delivery into the
    /// same `accept_f6` boundary used by network traffic — the port itself
    /// re-authenticates the payload against its pinned bindings, and the
    /// F6 lifecycle authority is never exposed to the caller. The delivery
    /// digest is derived deterministically from the exact payload bytes so
    /// crash-recovery redelivery presents the same evidence.
    pub fn accept_local_initiator_rfq_v25(
        &mut self,
        payload: &[u8],
    ) -> Result<DurablePayloadCommitV1, F::Error> {
        let mut hasher = Blake2bVar::new(32).expect("BLAKE2b-256 output length is valid");
        hasher.update(b"DOM-INTEROP/F6/LOCAL-INITIATOR-RFQ/V25\0");
        hasher.update(payload);
        let mut digest: Digest32 = ZERO_DIGEST;
        hasher
            .finalize_variable(&mut digest)
            .expect("BLAKE2b-256 output length is valid");
        let sender_id = self.contracts.contracts_mut().local_participant;
        let delivery = F6PayloadDeliveryV1::local_initiator_rfq_v25(sender_id, digest, payload);
        self.f6.accept_f6(delivery)
    }

    /// Returns true when the exact Store-owned DSC1 application is already
    /// durable in the route sender and still waiting for Relay ACK. Crash
    /// recovery must wait in that state instead of preparing the same
    /// application again with a fresh expiry.
    pub(crate) fn store_outbound_dsc1_pending_v24(
        &mut self,
        outbound: &CommittedOutboundDsc1V1,
    ) -> Result<bool, RelayWorkerOutboundErrorV1> {
        let store = Rc::clone(&self.contracts.contracts_mut().store);
        store
            .revalidate_committed_outbound_dsc1(outbound)
            .map_err(|_| RelayWorkerOutboundErrorV1::StoreRejected)?;

        Ok(self
            .sender
            .pending_envelope()?
            .is_some_and(|pending| pending.application_id() == Some(outbound.application_id())))
    }

    /// Stages or reconciles one DSC1 object already signed and committed by
    /// the same physical Contracts Store opening embedded in this worker.
    ///
    /// The opaque handle is reauthenticated before its exact signed bytes are
    /// decoded and cross-checked against both the handle and the worker's
    /// frozen sender/session. The bytes then enter only the durable Route
    /// application V2 API under the Store-minted application identifier.
    /// `AlreadyAcked` is returned only after the Store has durably recorded
    /// the completed Relay handoff. A pending handle is deliberately not
    /// returned: crash recovery reissues it from the same Store journal.
    pub fn stage_store_outbound_dsc1(
        &mut self,
        outbound: CommittedOutboundDsc1V1,
        expiry: TimelockSpec,
    ) -> Result<RouteApplicationDispositionV2, RelayWorkerOutboundErrorV1> {
        self.stage_store_outbound_dsc1_inner_v24(outbound, expiry, None)
    }

    /// Stage only an authenticated Claim 0x1a, with a same-custody veto at the
    /// sender's SQLite persistence boundary. No other DSC1 action may enter.
    pub(crate) fn stage_xmr_claim_response_guarded_v24(
        &mut self,
        outbound: CommittedOutboundDsc1V1,
        expiry: TimelockSpec,
        before_publication: &mut dyn FnMut() -> bool,
    ) -> Result<RouteApplicationDispositionV2, RelayWorkerOutboundErrorV1> {
        self.stage_store_outbound_dsc1_inner_v24(outbound, expiry, Some(before_publication))
    }

    fn stage_store_outbound_dsc1_inner_v24(
        &mut self,
        outbound: CommittedOutboundDsc1V1,
        expiry: TimelockSpec,
        mut before_publication: Option<&mut dyn FnMut() -> bool>,
    ) -> Result<RouteApplicationDispositionV2, RelayWorkerOutboundErrorV1> {
        let store = Rc::clone(&self.contracts.contracts_mut().store);
        store
            .revalidate_committed_outbound_dsc1(&outbound)
            .map_err(|_| RelayWorkerOutboundErrorV1::StoreRejected)?;

        let parsed = SignedMessageV1::decode_exact(outbound.signed_bytes())
            .map_err(|_| RelayWorkerOutboundErrorV1::InvalidDsc1)?;
        if before_publication.is_some() {
            require_xmr_claim_response_payload_v24(
                parsed.unsigned().kind(),
                parsed.unsigned().payload(),
            )?;
        }
        let checkpoint = self.sender.checkpoint()?;
        if parsed.unsigned().session_id() != outbound.session_id()
            || parsed.unsigned().sender_id() != outbound.sender_id()
            || parsed.unsigned().sequence() != outbound.sequence()
            || parsed.digest() != outbound.message_digest()
            || ParticipantId(*outbound.sender_id()) != checkpoint.sender_id()
            || parsed.unsigned().session_id() != &checkpoint.wire_context().session_id
        {
            return Err(RelayWorkerOutboundErrorV1::WrongDsc1Scope);
        }
        let aux = os_random_32().map_err(|_| RelayWorkerOutboundErrorV1::EntropyUnavailable)?;
        let disposition = match before_publication.as_mut() {
            Some(guard) => self.sender.prepare_xmr_claim_application_guarded_v24(
                *outbound.application_id(),
                outbound.signed_bytes(),
                expiry,
                aux,
                *guard,
            ),
            None => self.sender.prepare_route_application(
                *outbound.application_id(),
                outbound.signed_bytes(),
                expiry,
                aux,
            ),
        }?;
        if disposition.status().application_id() != outbound.application_id() {
            return Err(RelayWorkerOutboundErrorV1::WrongDsc1Scope);
        }
        match disposition {
            RouteApplicationDispositionV2::Pending(_) => Ok(disposition),
            RouteApplicationDispositionV2::AlreadyAcked(_) => {
                store
                    .complete_outbound_dsc1_relay_handoff(outbound)
                    .map_err(|_| RelayWorkerOutboundErrorV1::StoreRejected)?;
                Ok(disposition)
            }
        }
    }

    /// Submits at most one exact durable envelope.  Lost or inconsistent ACKs
    /// leave it pending byte-identically.  If an application-managed V2 frame
    /// was just acknowledged, the next frame is persisted only by repeating
    /// [`Self::stage_store_outbound_dsc1`] with the Store-recovered handle;
    /// this method never enters the legacy caller-shaped frame path.
    pub fn submit_outbound_once<Q: RelaySubmitQueueV1>(
        &mut self,
        queue: &mut Q,
    ) -> Result<RelayOutboundStepV1, RelayWorkerOutboundErrorV1> {
        if self.sender.pending_envelope()?.is_none() {
            return Ok(RelayOutboundStepV1::Idle);
        }
        let committed = self.sender.submit_pending(queue)?;
        Ok(RelayOutboundStepV1::Acked {
            message_type: committed.message_type(),
            frame_index: committed.frame_index(),
            next_sequence: committed.checkpoint().next_sequence(),
            envelope_digest: committed.ack().digest,
        })
    }

    /// Flush only an existing Store-committed public refund response. A
    /// different pending application is refused, never skipped or replaced.
    pub(crate) fn submit_terminal_refund_outbound_v24<Q: RelaySubmitQueueV1>(
        &mut self,
        queue: &mut Q,
        now: TimelockSpec,
    ) -> Result<RelayOutboundStepV1, RelayWorkerOutboundErrorV1> {
        let pending = self.sender.pending_envelope()?;
        let frames = self.sender.frame_transfer_status()?.is_some();
        let contracts = self.contracts.contracts_mut();
        let store = Rc::clone(&contracts.store);
        let session = contracts.session_id;
        let retained = store
            .resume_outbound_dsc1(session)
            .map_err(|_| RelayWorkerOutboundErrorV1::StoreRejected)?;
        let retained = match retained {
            dom_scriptless_store::OutboundDsc1RecoveryV1::None if pending.is_none() && !frames => {
                return Ok(RelayOutboundStepV1::Idle);
            }
            dom_scriptless_store::OutboundDsc1RecoveryV1::SigningRequest(request)
                if pending.is_none()
                    && !frames
                    && request.message_type() == 0x1a
                    && require_public_refund_payload_v24(
                        MessageTypeV1::XmrRemoteSweepResponseV23,
                        request.payload(),
                    )
                    .is_ok() =>
            {
                // The public publisher, not this transport-only method, must
                // finish authenticating/signing the retained DSC1 envelope.
                return Ok(RelayOutboundStepV1::Idle);
            }
            dom_scriptless_store::OutboundDsc1RecoveryV1::Committed(retained) => retained,
            _ => return Err(RelayWorkerOutboundErrorV1::StoreRejected),
        };
        let message = SignedMessageV1::decode_exact(retained.signed_bytes())
            .map_err(|_| RelayWorkerOutboundErrorV1::InvalidDsc1)?;
        if pending
            .as_ref()
            .is_some_and(|pending| pending.application_id() != Some(retained.application_id()))
            || message.unsigned().kind() != MessageTypeV1::XmrRemoteSweepResponseV23
            || require_public_refund_payload_v24(
                message.unsigned().kind(),
                message.unsigned().payload(),
            )
            .is_err()
        {
            return Err(RelayWorkerOutboundErrorV1::WrongDsc1Scope);
        }
        if self
            .sender
            .route_application_status(*retained.application_id())?
            .is_none()
        {
            // Crash after Store commit but before first Relay staging. Only
            // the publisher can select the initial transport expiry.
            return if pending.is_none() && !frames {
                Ok(RelayOutboundStepV1::Idle)
            } else {
                Err(RelayWorkerOutboundErrorV1::WrongDsc1Scope)
            };
        }
        // Existing application only: the sender reuses its ORIGINAL expiry
        // and prepares the next frame, or completes the Store's final ACK
        // handoff. `now` cannot create or renew availability on this branch.
        let application_id = *retained.application_id();
        let message_digest = *retained.message_digest();
        self.stage_store_outbound_dsc1(*retained, now)?;
        let submitted = self.submit_outbound_once(queue)?;
        if matches!(submitted, RelayOutboundStepV1::Acked { .. }) {
            let dom_scriptless_store::OutboundDsc1RecoveryV1::Committed(retained) = store
                .resume_outbound_dsc1(session)
                .map_err(|_| RelayWorkerOutboundErrorV1::StoreRejected)?
            else {
                return Err(RelayWorkerOutboundErrorV1::StoreRejected);
            };
            if retained.application_id() != &application_id
                || retained.message_digest() != &message_digest
            {
                return Err(RelayWorkerOutboundErrorV1::WrongDsc1Scope);
            }
            // Prepare only the next ORIGINAL frame, or finish the Store
            // handoff immediately after the final durable ACK.
            self.stage_store_outbound_dsc1(*retained, now)?;
        }
        Ok(submitted)
    }

    pub(crate) fn terminal_refund_frames_pending_v24(
        &mut self,
    ) -> Result<bool, RelayWorkerOutboundErrorV1> {
        let contracts = self.contracts.contracts_mut();
        let retained = contracts
            .store
            .resume_outbound_dsc1(contracts.session_id)
            .map_err(|_| RelayWorkerOutboundErrorV1::StoreRejected)?;
        let retained_refund = match retained {
            dom_scriptless_store::OutboundDsc1RecoveryV1::None => false,
            dom_scriptless_store::OutboundDsc1RecoveryV1::SigningRequest(request) => {
                if request.message_type() != 0x1a
                    || require_public_refund_payload_v24(
                        MessageTypeV1::XmrRemoteSweepResponseV23,
                        request.payload(),
                    )
                    .is_err()
                {
                    return Err(RelayWorkerOutboundErrorV1::WrongDsc1Scope);
                }
                true
            }
            dom_scriptless_store::OutboundDsc1RecoveryV1::Committed(retained) => {
                let message = SignedMessageV1::decode_exact(retained.signed_bytes())
                    .map_err(|_| RelayWorkerOutboundErrorV1::InvalidDsc1)?;
                if message.unsigned().kind() != MessageTypeV1::XmrRemoteSweepResponseV23
                    || require_public_refund_payload_v24(
                        message.unsigned().kind(),
                        message.unsigned().payload(),
                    )
                    .is_err()
                {
                    return Err(RelayWorkerOutboundErrorV1::WrongDsc1Scope);
                }
                true
            }
        };
        Ok(self.sender.pending_envelope()?.is_some()
            || self.sender.frame_transfer_status()?.is_some()
            || retained_refund)
    }

    /// Pulls and authenticates the mailbox through the one durable transcript,
    /// without dispatching any downstream payload.
    pub fn ingest_mailbox(
        &mut self,
        queue: &mut relay::production::ProductionRelayV1,
        now: TimelockSpec,
    ) -> Result<DurableInboxIngestReportV1, DurableInboxError> {
        self.inbox.ingest(queue, &self.rosters, now)
    }

    /// Compatibility-only full-mailbox harness. Production callers must use
    /// [`Self::ingest_mailbox`] so retained history is never materialized.
    pub fn ingest_mailbox_ephemeral_v1<Q: RelayQueueV1>(
        &mut self,
        queue: &Q,
        now: TimelockSpec,
    ) -> Result<DurableInboxIngestReportV1, DurableInboxError> {
        self.inbox.ingest_ephemeral_v1(queue, &self.rosters, now)
    }

    /// Dispatches the already-durable inbox in shared F6/route order.  F6 is
    /// attempted first; the inbox itself prevents either class from jumping a
    /// still-pending predecessor in the other class.
    pub fn dispatch_inbound(
        &mut self,
    ) -> Result<RelayInboundDispatchReportV1, RelayWorkerInboundErrorV1<F::Error>> {
        let f6 = self
            .inbox
            .dispatch_f6(&mut self.f6)
            .map_err(RelayWorkerInboundErrorV1::F6)?;
        let contracts = self
            .inbox
            .dispatch_routes(&mut self.contracts)
            .map_err(RelayWorkerInboundErrorV1::Contracts)?;
        let inbox = self.inbox.stats()?;
        let frames = self.contracts.stats().map_err(|error| {
            RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
                FramedContractsTransportErrorV2::Reassembly(error),
            ))
        })?;
        Ok(RelayInboundDispatchReportV1 {
            f6,
            contracts,
            inbox,
            frames,
        })
    }

    /// Resolves one quarantined Relay envelope only through the caller's
    /// explicit durable quarantine authority. The worker supplies its frozen
    /// roster and never manufactures a release or successful reprocess.
    pub fn resolve_quarantine<A: DurableQuarantineAuthorityV1>(
        &mut self,
        ordinal: u64,
        now: TimelockSpec,
        authority: &mut A,
    ) -> Result<DurableQuarantineResolutionReportV1, DurableQuarantineResolutionErrorV1<A::Error>>
    {
        self.inbox
            .resolve_quarantine(ordinal, &self.rosters, now, authority)
    }

    /// Executes one mailbox pull followed by the ordered downstream step.
    pub fn poll_inbound(
        &mut self,
        queue: &mut relay::production::ProductionRelayV1,
        now: TimelockSpec,
    ) -> Result<RelayInboundPollReportV1, RelayWorkerInboundErrorV1<F::Error>> {
        let ingest = self.ingest_mailbox(queue, now)?;
        let dispatch = self.dispatch_inbound()?;
        Ok(RelayInboundPollReportV1 { ingest, dispatch })
    }

    /// Preserve the same authenticated inbox, frame reassembler and sequence
    /// ordering, but never dispatch F6 or a non-refund Contracts operation.
    /// An earlier F6/other route row remains pending; it cannot be jumped.
    pub(crate) fn poll_terminal_refund_inbound_v24(
        &mut self,
        queue: &mut relay::production::ProductionRelayV1,
        now: TimelockSpec,
    ) -> Result<(), RelayWorkerInboundErrorV1<F::Error>> {
        let contracts = self.contracts.contracts_mut();
        contracts.terminal_refund_only_v24 = true;
        contracts.authority.take();
        self.ingest_mailbox(queue, now)?;
        self.inbox
            .dispatch_routes(&mut self.contracts)
            .map_err(RelayWorkerInboundErrorV1::Contracts)?;
        Ok(())
    }

    /// Compatibility-only poll for in-memory V1 harnesses.
    pub fn poll_inbound_ephemeral_v1<Q: RelayQueueV1>(
        &mut self,
        queue: &Q,
        now: TimelockSpec,
    ) -> Result<RelayInboundPollReportV1, RelayWorkerInboundErrorV1<F::Error>> {
        let ingest = self.ingest_mailbox_ephemeral_v1(queue, now)?;
        let dispatch = self.dispatch_inbound()?;
        Ok(RelayInboundPollReportV1 { ingest, dispatch })
    }

    /// Secret-free sender/outbox counters.
    pub fn sender_stats(&self) -> Result<DurableRelaySenderStatsV1, DurableRelaySenderErrorV1> {
        self.sender.stats()
    }

    /// Secret-free inbox counters.
    pub fn inbox_stats(&self) -> Result<DurableInboxStatsV1, DurableInboxError> {
        self.inbox.stats()
    }

    /// Durable timestamp rollback floor retained by this worker's sole inbox.
    pub(crate) fn retained_timestamp_floor(&self) -> Result<Option<u64>, DurableInboxError> {
        self.inbox.retained_timestamp_floor()
    }

    /// Bounded V2 frame counters.
    pub fn frame_stats(
        &self,
    ) -> Result<DurableFrameReassemblerStatsV2, DurableFrameReassemblerErrorV2> {
        self.contracts.stats()
    }
}

impl DurableRelayWorkerV1<ProductionF6LifecyclePortV2> {
    /// Reauthenticates every retained applied F6 row against the exact
    /// production lifecycle before this reopened worker may dispatch pending
    /// F6 traffic.
    ///
    /// This deliberately exposes neither the inbox nor a mutable lifecycle
    /// reference. The retained inbox is replayed read-only by the lifecycle's
    /// purpose-specific recovery boundary; any divergent receipt, corrupted
    /// row, transplanted position or unavailable downstream authority leaves
    /// the lifecycle in `RecoveryRequired`.
    pub(crate) fn recover_production_f6_applied_history(
        &mut self,
    ) -> Result<F6AppliedReplayReportV1, F6AppliedReplayErrorV1<ProductionF6LifecycleErrorV2>> {
        self.f6.recover_applied_history(&self.inbox)
    }
}

fn validate_roster(
    config: &RelayWorkerConfigV1,
    rosters: &RosterRegistryV1,
) -> Result<(), RelayWorkerOpenErrorV1> {
    let Some(snapshot) = rosters.snapshot(&config.wire_context().roster_snapshot) else {
        return Err(RelayWorkerOpenErrorV1::InvalidConfiguration);
    };
    let Some(local) = snapshot.member(&config.local_participant()) else {
        return Err(RelayWorkerOpenErrorV1::InvalidConfiguration);
    };
    if local.role != config.sender.sender_role()
        || local.xonly_key != *config.sender.signer_xonly()
        || snapshot.member(&config.remote_participant()).is_none()
    {
        return Err(RelayWorkerOpenErrorV1::InvalidConfiguration);
    }
    Ok(())
}

fn prepared_report(pending: &DurableOutboundEnvelopeV1) -> PreparedRelayOutboundV1 {
    PreparedRelayOutboundV1 {
        message_type: pending.message_type(),
        sequence: pending.sequence(),
        envelope_digest: *pending.envelope_digest(),
        frame_index: pending.frame_index(),
        frame_count: pending.frame_count(),
    }
}

fn accepted_receipt_digest(
    session_id: Digest32,
    receipt: DurableTransportReceiptV1,
) -> Result<Digest32, ContractsRelayIngressErrorV1> {
    let sequence = receipt.sequence.to_be_bytes();
    let message_type = [receipt.message_type];
    digest_parts(
        RECEIPT_DOMAIN,
        &[
            &session_id,
            &receipt.message_digest,
            &receipt.transcript_hash,
            &sequence,
            &message_type,
        ],
    )
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, ContractsRelayIngressErrorV1> {
    let mut hasher =
        Blake2bVar::new(32).map_err(|_| ContractsRelayIngressErrorV1::InvalidReceipt)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut digest = [0; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| ContractsRelayIngressErrorV1::InvalidReceipt)?;
    if digest == ZERO_DIGEST {
        return Err(ContractsRelayIngressErrorV1::InvalidReceipt);
    }
    Ok(digest)
}

fn os_random_32() -> Result<[u8; 32], getrandom::Error> {
    let mut bytes = [0; 32];
    getrandom::getrandom(&mut bytes)?;
    Ok(bytes)
}

fn first_delivery_receipt_from_prepared_readback(
    outcome: DurableTransportOutcomeV1,
) -> Result<DurableTransportReceiptV1, SessionStoreError> {
    match outcome {
        DurableTransportOutcomeV1::Accepted(receipt) if receipt.duplicate => Ok(receipt),
        DurableTransportOutcomeV1::Accepted(_)
        | DurableTransportOutcomeV1::EquivocationPersisted => Err(SessionStoreError::Quarantined),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_f6_recovery_surface_is_concrete_and_does_not_expose_authorities() {
        let _recover: fn(
            &mut DurableRelayWorkerV1<ProductionF6LifecyclePortV2>,
        ) -> Result<
            F6AppliedReplayReportV1,
            F6AppliedReplayErrorV1<ProductionF6LifecycleErrorV2>,
        > = DurableRelayWorkerV1::<
            ProductionF6LifecyclePortV2,
        >::recover_production_f6_applied_history;

        let source = include_str!("relay_worker.rs");
        assert!(!source.contains(&["pub fn ", "f6_mut"].concat()));
        assert!(!source.contains(&["pub(crate) fn ", "f6_mut"].concat()));
    }

    #[test]
    fn post_anchor_claim_pre_signature_ingress_has_a_linear_typed_surface() {
        let _constructor: fn(
            PreparedPostAnchorClaimPreSignatureTransportAuthorityV1,
        ) -> PreparedContractsIngressV1 =
            PreparedContractsIngressV1::post_anchor_claim_pre_signature;
        let _extractor: fn(
            PreparedContractsIngressV1,
        ) -> Result<
            PreparedPostAnchorClaimPreSignatureTransportAuthorityV1,
            Box<PreparedContractsIngressV1>,
        > = PreparedContractsIngressV1::into_post_anchor_claim_pre_signature;
    }

    #[test]
    fn post_anchor_claim_pre_signature_v2_ingress_has_a_linear_typed_surface() {
        let _constructor: fn(
            PreparedPostAnchorClaimPreSignatureTransportAuthorityV2,
        ) -> PreparedContractsIngressV1 =
            PreparedContractsIngressV1::post_anchor_claim_pre_signature_v2;
        let _extractor: fn(
            PreparedContractsIngressV1,
        ) -> Result<
            PreparedPostAnchorClaimPreSignatureTransportAuthorityV2,
            Box<PreparedContractsIngressV1>,
        > = PreparedContractsIngressV1::into_post_anchor_claim_pre_signature_v2;
    }

    #[test]
    fn operational_final_refund_ingress_has_a_linear_typed_surface() {
        let _constructor: fn(
            PreparedOperationalFinalRefundTransportAuthorityV1,
        ) -> PreparedContractsIngressV1 = PreparedContractsIngressV1::operational_final_refund;
        let _extractor: fn(
            PreparedContractsIngressV1,
        ) -> Result<
            PreparedOperationalFinalRefundTransportAuthorityV1,
            Box<PreparedContractsIngressV1>,
        > = PreparedContractsIngressV1::into_operational_final_refund;
    }

    /// The FinalClaim ingress variant must name the *ingress* authority on
    /// both sides of the linear surface.
    ///
    /// This is the discriminating half of the test: the emitter-side
    /// `PreparedOperationalFinalClaimTransportAuthorityV2` is a distinct type,
    /// so if the variant were ever retyped to carry it, these two coercions
    /// stop compiling.  A variant carrying the emitter capability would
    /// otherwise build cleanly and refuse every real `0x12` at run time.
    #[test]
    fn final_claim_ingress_v2_has_a_linear_typed_surface() {
        let _constructor: fn(
            PreparedOperationalFinalClaimIngressAuthorityV2,
        ) -> PreparedContractsIngressV1 = PreparedContractsIngressV1::final_claim_ingress_v2;
        let _extractor: fn(
            PreparedContractsIngressV1,
        ) -> Result<
            PreparedOperationalFinalClaimIngressAuthorityV2,
            Box<PreparedContractsIngressV1>,
        > = PreparedContractsIngressV1::into_final_claim_ingress_v2;
    }

    #[test]
    fn prepared_m8_readback_must_be_the_exact_durable_duplicate() {
        let duplicate = DurableTransportReceiptV1 {
            message_digest: [0x11; 32],
            transcript_hash: [0x22; 32],
            sequence: 7,
            message_type: 0x11,
            duplicate: true,
        };
        assert_eq!(
            first_delivery_receipt_from_prepared_readback(DurableTransportOutcomeV1::Accepted(
                duplicate
            ))
            .expect("prepared Store transition must be readable as an exact duplicate"),
            duplicate
        );

        let impossible_first = DurableTransportReceiptV1 {
            duplicate: false,
            ..duplicate
        };
        assert!(matches!(
            first_delivery_receipt_from_prepared_readback(DurableTransportOutcomeV1::Accepted(
                impossible_first
            )),
            Err(SessionStoreError::Quarantined)
        ));
        assert!(matches!(
            first_delivery_receipt_from_prepared_readback(
                DurableTransportOutcomeV1::EquivocationPersisted
            ),
            Err(SessionStoreError::Quarantined)
        ));
    }
}

#[cfg(test)]
#[path = "production_xmr_readiness_handoff_v25_tests.rs"]
mod readiness_gate_v25_tests;
