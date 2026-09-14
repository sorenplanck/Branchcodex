//! Closed diagnostic projection only. Never formats an original error, reads
//! its source chain, changes retry classification, or authorizes a transition.
use super::*;
use crate::production_contracts::{
    ProductionBootstrapRuntimeErrorV16, ProductionContractsOutboundErrorV1,
    ProductionF7ReadinessErrorV19,
};
use crate::production_dom_shared_bootstrap_v12::ProductionDomSharedBootstrapErrorV12;
use crate::production_f6::ProductionF6ErrorV2;
use crate::production_f6_lifecycle::ProductionPendingAuthorityV1;
use crate::relay_worker::ContractsRelayIngressErrorV1;
use dom_scriptless_store::SessionStoreError;
use route_transport::{F6DispatchErrorV1, FramedContractsTransportErrorV2, RouteDispatchErrorV1};

macro_rules! closed_tags {
    ($name:ident { $($variant:ident => $tag:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum $name { $($variant),+ }
        impl $name {
            const ALL: &'static [Self] = &[$(Self::$variant),+];
            const fn code(self) -> &'static str {
                match self { $(Self::$variant => $tag),+ }
            }
        }
    };
}

closed_tags!(Stage {
    Composite => "composite", Bootstrap => "bootstrap", F7 => "f7_readiness",
    LocalBootstrap => "local_bootstrap", GraphCandidate => "graph_candidate",
    PostExchangeBootstrap => "post_exchange_bootstrap",
    Outbound => "outbound", Network => "network", Noise => "noise",
    NetworkConfiguration => "network_configuration", Inbound => "inbound",
    InboundF6 => "inbound_f6", CancelledInbound => "cancelled_inbound",
    RecoverySigningInbound => "recovery_signing_inbound", Activation => "f6_activation",
    Route => "route", Control => "control",
});

closed_tags!(Cause {
    InvalidConfiguration => "invalid_configuration", Clock => "clock_unavailable",
    Binding => "binding", Crypto => "crypto", Vault => "vault", Expired => "expired",
    Mailbox => "mailbox", XmrGraph => "xmr_recovery_graph_required",
    JournalBinding => "journal_binding", JournalCrypto => "journal_crypto",
    JournalVault => "journal_vault", Journal => "journal_unavailable",
    PeerCommitment => "awaiting_peer_commitment",
    StoreFilesystem => "store_filesystem", StoreBusy => "store_busy",
    StoreConflict => "store_conflict", StoreCanonical => "store_canonical",
    StorePolicy => "store_policy_profile", StoreQuarantined => "store_quarantined",
    StoreDomTransaction => "store_dom_transaction", StoreMissing => "store_session_missing",
    StoreTransition => "store_invalid_transition", StoreFunding => "store_funding_unavailable",
    StoreRefundPending => "store_native_refund_pending",
    StoreClaimSigning => "store_claim_signing_unavailable",
    StoreLegacy => "store_legacy_recovery_only", StoreCapacity => "store_capacity",
    StoreRandom => "store_randomness",
    OwnerBusy => "owner_busy", Identity => "identity_refused", Sender => "sender_refused",
    Entropy => "entropy_unavailable", StoreRejected => "store_rejected",
    InvalidDsc1 => "invalid_dsc1", WrongDsc1Scope => "wrong_dsc1_scope",
    Unprepared => "unprepared_message", ClaimObservation => "awaiting_claim_observation",
    Templates => "awaiting_template_construction", RefundHandoff => "awaiting_refund_handoff",
    NativeRefund => "awaiting_native_refund_transport", WrongAuthority => "wrong_authority",
    AlreadyInstalled => "authority_already_installed", Receipt => "invalid_receipt",
    SenderMismatch => "sender_mismatch", Inbox => "inbox_refused", Framing => "framing_refused",
    Connect => "connect_unavailable", Listen => "listen_unavailable",
    AcceptDeadline => "accept_deadline", AuthenticatedExchange => "authenticated_exchange_failed",
    Channel => "channel_unavailable", DurableRelay => "durable_relay_unavailable",
    Protocol => "protocol_refused", Peer => "peer_refused",
    ConfigUnavailable => "configuration_unavailable", ConfigEncoding => "configuration_encoding",
    ConfigLink => "configuration_link", ConfigPeer => "configuration_peer_binding",
    F6Binding => "binding_invalid", F6PendingRfq => "pending_rfq_invalid",
    F6ActivationUnavailable => "activation_unavailable", F6Recovery => "recovery_required",
    F6Payload => "payload_invalid", F6Role => "role_refused", F6Journal => "binding_unavailable",
    F6Inventory => "inventory_unavailable", F6Status => "status_unavailable",
    F6AttestationUnavailable => "attestation_unavailable", F6Attestation => "attestation_invalid",
    F6Time => "time_unavailable", F6TermsUnavailable => "terms_unavailable",
    F6Terms => "terms_invalid", F6Terminal => "terminal_unavailable", F6Receipt => "receipt_unavailable",
    PendingActivation => "awaiting_activation", PendingRfq => "awaiting_authenticated_rfq",
    PendingStatus => "awaiting_solver_status", PendingTime => "awaiting_time_evidence",
    PendingBond => "awaiting_bond_attestation", PendingTerms => "awaiting_adapter_terms",
    PendingClaimPlan => "awaiting_claim_role_plan", PendingEvmAccount => "awaiting_evm_account",
    Driver => "driver_refused", Supervisor => "supervisor_refused",
    SecretRetirement => "secret_retirement_refused", Control => "control_unavailable",
});

/// Secret-free, bounded projection of one concrete composite failure.
/// Construction is private; text decoding cannot create an execution authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionCompositeFailureV25 {
    stage: Stage,
    cause: Cause,
}

impl ProductionCompositeFailureV25 {
    pub(crate) const fn stage_code(self) -> &'static str {
        self.stage.code()
    }
    pub(crate) const fn cause_code(self) -> &'static str {
        self.cause.code()
    }

    /// Exact ASCII diagnostic, not a substring, error-source parser, or log
    /// sanitizer. Only combinations emitted by the typed projection qualify.
    pub(crate) fn classify_exact_display_v25(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > 96 {
            return None;
        }
        let separator = bytes.iter().position(|byte| *byte == b'/')?;
        let stage = Stage::ALL
            .iter()
            .copied()
            .find(|stage| stage.code().as_bytes() == &bytes[..separator])?;
        let cause = Cause::ALL
            .iter()
            .copied()
            .find(|cause| cause.code().as_bytes() == &bytes[separator + 1..])?;
        permitted(stage, cause).then_some(Self { stage, cause })
    }
}

impl core::fmt::Display for ProductionCompositeFailureV25 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}/{}", self.stage_code(), self.cause_code())
    }
}

fn store_cause(error: &SessionStoreError) -> Cause {
    use SessionStoreError as E;
    match error {
        E::Filesystem => Cause::StoreFilesystem,
        E::StoreBusy => Cause::StoreBusy,
        E::Conflict => Cause::StoreConflict,
        E::Canonical => Cause::StoreCanonical,
        E::PolicyProfile => Cause::StorePolicy,
        E::Quarantined => Cause::StoreQuarantined,
        E::InvalidDomTransaction => Cause::StoreDomTransaction,
        E::SessionNotFound => Cause::StoreMissing,
        E::InvalidTransition => Cause::StoreTransition,
        E::FundingAuthorityUnavailable => Cause::StoreFunding,
        E::NativeXmrRefundTransportPendingV23 => Cause::StoreRefundPending,
        E::ClaimSigningAuthorityUnavailable => Cause::StoreClaimSigning,
        E::LegacyV1RecoveryOnly => Cause::StoreLegacy,
        E::CapacityExceeded => Cause::StoreCapacity,
        E::RandomFailure => Cause::StoreRandom,
    }
}

fn outbound(error: &RelayWorkerOutboundErrorV1) -> Cause {
    use RelayWorkerOutboundErrorV1 as E;
    match error {
        E::OwnerBusy => Cause::OwnerBusy,
        E::EntropyUnavailable => Cause::Entropy,
        E::Sender(_) => Cause::Sender,
        E::StoreRejected => Cause::StoreRejected,
        E::InvalidDsc1 => Cause::InvalidDsc1,
        E::WrongDsc1Scope => Cause::WrongDsc1Scope,
    }
}

fn contracts_outbound(error: &ProductionContractsOutboundErrorV1) -> Cause {
    match error {
        ProductionContractsOutboundErrorV1::Identity(_) => Cause::Identity,
        ProductionContractsOutboundErrorV1::Store(error) => store_cause(error),
        ProductionContractsOutboundErrorV1::Relay(error) => outbound(error),
        ProductionContractsOutboundErrorV1::OwnerBusy => Cause::OwnerBusy,
    }
}

fn ingress(error: &ContractsRelayIngressErrorV1) -> Cause {
    use ContractsRelayIngressErrorV1 as E;
    match error {
        E::OwnerBusy => Cause::OwnerBusy,
        E::Store(error) => store_cause(error),
        E::UnpreparedMessage => Cause::Unprepared,
        E::AwaitingFinalClaimObservationV16 => Cause::ClaimObservation,
        E::AwaitingTemplateConstructionV17 => Cause::Templates,
        E::AwaitingBootstrapRefundHandoffV18 => Cause::RefundHandoff,
        E::AwaitingNativeXmrRefundTransportV23 => Cause::NativeRefund,
        E::WrongAuthority => Cause::WrongAuthority,
        E::AuthorityAlreadyInstalled => Cause::AlreadyInstalled,
        E::InvalidReceipt => Cause::Receipt,
        E::InvalidDsc1 => Cause::InvalidDsc1,
        E::SenderMismatch => Cause::SenderMismatch,
    }
}

fn pending(error: &ProductionPendingAuthorityV1) -> Cause {
    use ProductionPendingAuthorityV1 as E;
    match error {
        E::F6Activation { .. } => Cause::PendingActivation,
        E::AuthenticatedRfq { .. } => Cause::PendingRfq,
        E::SolverStatusEvidence => Cause::PendingStatus,
        E::PreF6TimeEvidence { .. } => Cause::PendingTime,
        E::BondAttestationSigners { .. } => Cause::PendingBond,
        E::AdapterTerms { .. } => Cause::PendingTerms,
        E::ComposedFinalClaimRolePlan => Cause::PendingClaimPlan,
        E::RemoteEvmAccount => Cause::PendingEvmAccount,
    }
}

fn f6(error: &ProductionF6LifecycleErrorV2) -> Cause {
    use ProductionF6LifecycleErrorV2 as E;
    match error {
        E::InvalidBinding => Cause::F6Binding,
        E::InvalidPendingRfq => Cause::F6PendingRfq,
        E::Awaiting(error) => pending(error),
        E::ActivationUnavailable => Cause::F6ActivationUnavailable,
        E::RecoveryRequired => Cause::F6Recovery,
        E::Active(error) => match error {
            ProductionF6ErrorV2::InvalidBinding => Cause::F6Binding,
            ProductionF6ErrorV2::InvalidPayload => Cause::F6Payload,
            ProductionF6ErrorV2::WrongRole => Cause::F6Role,
            ProductionF6ErrorV2::Binding => Cause::F6Journal,
            ProductionF6ErrorV2::Inventory => Cause::F6Inventory,
            ProductionF6ErrorV2::StatusUnavailable => Cause::F6Status,
            ProductionF6ErrorV2::CandidateAttestationUnavailable => Cause::F6AttestationUnavailable,
            ProductionF6ErrorV2::InvalidCandidateAttestation => Cause::F6Attestation,
            ProductionF6ErrorV2::TimeUnavailable => Cause::F6Time,
            ProductionF6ErrorV2::TermsUnavailable => Cause::F6TermsUnavailable,
            ProductionF6ErrorV2::InvalidTerms => Cause::F6Terms,
            ProductionF6ErrorV2::TerminalUnavailable => Cause::F6Terminal,
            ProductionF6ErrorV2::Receipt => Cause::F6Receipt,
            ProductionF6ErrorV2::ClockUnavailable => Cause::Clock,
        },
    }
}

fn poll<E: std::error::Error + Send + Sync + 'static>(
    error: &ProductionContractsPollErrorV1<E>,
    classify_f6: impl FnOnce(&E) -> Cause,
) -> Cause {
    match error {
        ProductionContractsPollErrorV1::OwnerBusy => Cause::OwnerBusy,
        ProductionContractsPollErrorV1::Worker(error) => match error {
            RelayWorkerInboundErrorV1::Ingest(_) => Cause::Inbox,
            RelayWorkerInboundErrorV1::F6(F6DispatchErrorV1::Inbox(_)) => Cause::Inbox,
            RelayWorkerInboundErrorV1::F6(F6DispatchErrorV1::F6(error)) => classify_f6(error),
            RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Inbox(_)) => Cause::Inbox,
            RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(error)) => {
                match error {
                    FramedContractsTransportErrorV2::Reassembly(_) => Cause::Framing,
                    FramedContractsTransportErrorV2::Contracts(error) => ingress(error),
                }
            }
        },
    }
}

impl ProductionCompositeLoopErrorV1 {
    pub(crate) fn failure_v25(&self) -> ProductionCompositeFailureV25 {
        use ProductionCompositeLoopErrorV1 as E;
        let (stage, cause) = match self {
            E::InvalidConfiguration => (Stage::Composite, Cause::InvalidConfiguration),
            E::ClockUnavailable => (Stage::Composite, Cause::Clock),
            E::Bootstrap(error) | E::BootstrapAtV25 { error, .. } => (
                match self {
                    E::BootstrapAtV25 { context, .. } => match context {
                        ProductionCompositeBootstrapContextV25::LocalBootstrap => {
                            Stage::LocalBootstrap
                        }
                        ProductionCompositeBootstrapContextV25::GraphCandidate => {
                            Stage::GraphCandidate
                        }
                        ProductionCompositeBootstrapContextV25::PostExchangeBootstrap => {
                            Stage::PostExchangeBootstrap
                        }
                    },
                    _ => Stage::Bootstrap,
                },
                match error {
                    ProductionBootstrapRuntimeErrorV16::Binding => Cause::Binding,
                    ProductionBootstrapRuntimeErrorV16::Crypto => Cause::Crypto,
                    ProductionBootstrapRuntimeErrorV16::Vault => Cause::Vault,
                    ProductionBootstrapRuntimeErrorV16::Expired => Cause::Expired,
                    ProductionBootstrapRuntimeErrorV16::Store(error) => store_cause(error),
                    ProductionBootstrapRuntimeErrorV16::Journal(error) => match error {
                        ProductionDomSharedBootstrapErrorV12::Binding => Cause::JournalBinding,
                        ProductionDomSharedBootstrapErrorV12::Crypto => Cause::JournalCrypto,
                        ProductionDomSharedBootstrapErrorV12::Vault => Cause::JournalVault,
                        ProductionDomSharedBootstrapErrorV12::Journal => Cause::Journal,
                        ProductionDomSharedBootstrapErrorV12::AwaitingPeerCommitment => {
                            Cause::PeerCommitment
                        }
                    },
                    ProductionBootstrapRuntimeErrorV16::Outbound(error) => {
                        contracts_outbound(error)
                    }
                    ProductionBootstrapRuntimeErrorV16::Ingress(error) => ingress(error),
                    ProductionBootstrapRuntimeErrorV16::Mailbox => Cause::Mailbox,
                    ProductionBootstrapRuntimeErrorV16::XmrRecoveryGraphRequired => Cause::XmrGraph,
                    // Tolerated by the composite loop (the candidate is
                    // re-received once the local surfaces exist); if it ever
                    // reaches a failure report it reads as the binding stage
                    // it guards.
                    ProductionBootstrapRuntimeErrorV16::AwaitingGraphCandidateSurfacesV25 => {
                        Cause::Binding
                    }
                },
            ),
            E::F7Readiness(error) => (
                Stage::F7,
                match error {
                    ProductionF7ReadinessErrorV19::Store(error) => store_cause(error),
                    ProductionF7ReadinessErrorV19::Ingress(error) => ingress(error),
                    ProductionF7ReadinessErrorV19::Outbound(error) => contracts_outbound(error),
                    ProductionF7ReadinessErrorV19::Clock => Cause::Clock,
                },
            ),
            E::Outbound(error) => (Stage::Outbound, outbound(error)),
            E::Network(error) => (
                Stage::Network,
                match error {
                    ProductionRelayNetworkRuntimeErrorV1::InvalidConfiguration => {
                        Cause::InvalidConfiguration
                    }
                    ProductionRelayNetworkRuntimeErrorV1::ConnectUnavailable => Cause::Connect,
                    ProductionRelayNetworkRuntimeErrorV1::ListenUnavailable => Cause::Listen,
                    ProductionRelayNetworkRuntimeErrorV1::AcceptDeadlineElapsed => {
                        Cause::AcceptDeadline
                    }
                    ProductionRelayNetworkRuntimeErrorV1::AuthenticatedExchangeFailed => {
                        Cause::AuthenticatedExchange
                    }
                    ProductionRelayNetworkRuntimeErrorV1::ChannelUnavailable => Cause::Channel,
                    ProductionRelayNetworkRuntimeErrorV1::DurableRelayUnavailable => {
                        Cause::DurableRelay
                    }
                },
            ),
            E::Noise(error) => (
                Stage::Noise,
                match error {
                    ProductionNoiseRelayErrorV1::InvalidConfiguration => {
                        Cause::InvalidConfiguration
                    }
                    ProductionNoiseRelayErrorV1::IdentityAuthenticationFailed => Cause::Identity,
                    ProductionNoiseRelayErrorV1::ChannelUnavailable => Cause::Channel,
                    ProductionNoiseRelayErrorV1::DurableRelayUnavailable => Cause::DurableRelay,
                    ProductionNoiseRelayErrorV1::ProtocolRefused => Cause::Protocol,
                    ProductionNoiseRelayErrorV1::PeerRefused => Cause::Peer,
                },
            ),
            E::NetworkConfiguration(error) => (
                Stage::NetworkConfiguration,
                match error {
                    ProductionRelayNetworkConfigErrorV1::Unavailable => Cause::ConfigUnavailable,
                    ProductionRelayNetworkConfigErrorV1::InvalidEncoding => Cause::ConfigEncoding,
                    ProductionRelayNetworkConfigErrorV1::InvalidLink => Cause::ConfigLink,
                    ProductionRelayNetworkConfigErrorV1::PeerBindingMismatch => Cause::ConfigPeer,
                },
            ),
            E::Inbound(error) => {
                let stage = if matches!(
                    error,
                    ProductionContractsPollErrorV1::Worker(RelayWorkerInboundErrorV1::F6(_))
                ) {
                    Stage::InboundF6
                } else {
                    Stage::Inbound
                };
                (stage, poll(error, f6))
            }
            E::CancelledInbound(error) => (
                Stage::CancelledInbound,
                poll(error, |_| Cause::F6ActivationUnavailable),
            ),
            E::RecoverySigningInbound(error) => (
                Stage::RecoverySigningInbound,
                poll(error, |_| Cause::F6ActivationUnavailable),
            ),
            E::Activation(error) => (
                Stage::Activation,
                match error {
                    ProductionF6ActivationRefusalV2::Awaiting(error) => pending(error),
                    ProductionF6ActivationRefusalV2::InvalidBinding => Cause::F6Binding,
                    ProductionF6ActivationRefusalV2::Unavailable => Cause::F6ActivationUnavailable,
                },
            ),
            E::Route(error) => (
                Stage::Route,
                match error {
                    RouteRuntimeErrorV1::InvalidConfiguration => Cause::InvalidConfiguration,
                    RouteRuntimeErrorV1::Driver(_) => Cause::Driver,
                    RouteRuntimeErrorV1::Supervisor(_) => Cause::Supervisor,
                    RouteRuntimeErrorV1::Control(_) => Cause::Control,
                    RouteRuntimeErrorV1::SecretRetirement(_) => Cause::SecretRetirement,
                },
            ),
            E::Control(RouteRunControlErrorV1::Unavailable) => (Stage::Control, Cause::Control),
        };
        ProductionCompositeFailureV25 { stage, cause }
    }
}

fn permitted(stage: Stage, cause: Cause) -> bool {
    use Cause as C;
    let store = matches!(
        cause,
        C::StoreFilesystem
            | C::StoreBusy
            | C::StoreConflict
            | C::StoreCanonical
            | C::StorePolicy
            | C::StoreQuarantined
            | C::StoreDomTransaction
            | C::StoreMissing
            | C::StoreTransition
            | C::StoreFunding
            | C::StoreRefundPending
            | C::StoreClaimSigning
            | C::StoreLegacy
            | C::StoreCapacity
            | C::StoreRandom
    );
    let outbound = matches!(
        cause,
        C::OwnerBusy
            | C::Entropy
            | C::Sender
            | C::StoreRejected
            | C::InvalidDsc1
            | C::WrongDsc1Scope
    );
    let ingress = store
        || matches!(
            cause,
            C::OwnerBusy
                | C::Unprepared
                | C::ClaimObservation
                | C::Templates
                | C::RefundHandoff
                | C::NativeRefund
                | C::WrongAuthority
                | C::AlreadyInstalled
                | C::Receipt
                | C::InvalidDsc1
                | C::SenderMismatch
        );
    let pending = matches!(
        cause,
        C::PendingActivation
            | C::PendingRfq
            | C::PendingStatus
            | C::PendingTime
            | C::PendingBond
            | C::PendingTerms
            | C::PendingClaimPlan
            | C::PendingEvmAccount
    );
    match stage {
        Stage::Composite => matches!(cause, C::InvalidConfiguration | C::Clock),
        Stage::Bootstrap
        | Stage::LocalBootstrap
        | Stage::GraphCandidate
        | Stage::PostExchangeBootstrap => {
            ingress
                || outbound
                || matches!(
                    cause,
                    C::Identity
                        | C::Binding
                        | C::Crypto
                        | C::Vault
                        | C::Expired
                        | C::Mailbox
                        | C::XmrGraph
                        | C::JournalBinding
                        | C::JournalCrypto
                        | C::JournalVault
                        | C::Journal
                        | C::PeerCommitment
                )
        }
        Stage::F7 => ingress || outbound || matches!(cause, C::Identity | C::Clock),
        Stage::Outbound => outbound,
        Stage::Network => matches!(
            cause,
            C::InvalidConfiguration
                | C::Connect
                | C::Listen
                | C::AcceptDeadline
                | C::AuthenticatedExchange
                | C::Channel
                | C::DurableRelay
        ),
        Stage::Noise => matches!(
            cause,
            C::InvalidConfiguration
                | C::Identity
                | C::Channel
                | C::DurableRelay
                | C::Protocol
                | C::Peer
        ),
        Stage::NetworkConfiguration => matches!(
            cause,
            C::ConfigUnavailable | C::ConfigEncoding | C::ConfigLink | C::ConfigPeer
        ),
        Stage::Inbound => ingress || matches!(cause, C::Inbox | C::Framing),
        Stage::CancelledInbound | Stage::RecoverySigningInbound => {
            ingress || matches!(cause, C::Inbox | C::Framing | C::F6ActivationUnavailable)
        }
        Stage::InboundF6 => {
            pending
                || matches!(
                    cause,
                    C::Inbox
                        | C::F6Binding
                        | C::F6PendingRfq
                        | C::F6ActivationUnavailable
                        | C::F6Recovery
                        | C::F6Payload
                        | C::F6Role
                        | C::F6Journal
                        | C::F6Inventory
                        | C::F6Status
                        | C::F6AttestationUnavailable
                        | C::F6Attestation
                        | C::F6Time
                        | C::F6TermsUnavailable
                        | C::F6Terms
                        | C::F6Terminal
                        | C::F6Receipt
                        | C::Clock
                )
        }
        Stage::Activation => pending || matches!(cause, C::F6Binding | C::F6ActivationUnavailable),
        Stage::Route => matches!(
            cause,
            C::InvalidConfiguration | C::Driver | C::Supervisor | C::Control | C::SecretRetirement
        ),
        Stage::Control => cause == C::Control,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_projection(error: ProductionCompositeLoopErrorV1, expected: &str) {
        let diagnostic = error.failure_v25();
        assert_eq!(diagnostic.to_string(), expected);
        assert_eq!(
            ProductionCompositeFailureV25::classify_exact_display_v25(expected.as_bytes()),
            Some(diagnostic)
        );
        assert!(!is_peer_temporarily_unavailable_v23(&error));
    }

    #[test]
    fn composite_failure_v25_preserves_bootstrap_store_and_ingress_causes() {
        for (error, expected) in [
            (SessionStoreError::Filesystem, "bootstrap/store_filesystem"),
            (SessionStoreError::StoreBusy, "bootstrap/store_busy"),
            (SessionStoreError::Conflict, "bootstrap/store_conflict"),
            (SessionStoreError::Canonical, "bootstrap/store_canonical"),
            (
                SessionStoreError::PolicyProfile,
                "bootstrap/store_policy_profile",
            ),
            (
                SessionStoreError::Quarantined,
                "bootstrap/store_quarantined",
            ),
            (
                SessionStoreError::InvalidDomTransaction,
                "bootstrap/store_dom_transaction",
            ),
            (
                SessionStoreError::SessionNotFound,
                "bootstrap/store_session_missing",
            ),
            (
                SessionStoreError::InvalidTransition,
                "bootstrap/store_invalid_transition",
            ),
            (
                SessionStoreError::FundingAuthorityUnavailable,
                "bootstrap/store_funding_unavailable",
            ),
            (
                SessionStoreError::NativeXmrRefundTransportPendingV23,
                "bootstrap/store_native_refund_pending",
            ),
            (
                SessionStoreError::ClaimSigningAuthorityUnavailable,
                "bootstrap/store_claim_signing_unavailable",
            ),
            (
                SessionStoreError::LegacyV1RecoveryOnly,
                "bootstrap/store_legacy_recovery_only",
            ),
            (
                SessionStoreError::CapacityExceeded,
                "bootstrap/store_capacity",
            ),
            (
                SessionStoreError::RandomFailure,
                "bootstrap/store_randomness",
            ),
        ] {
            assert_projection(
                ProductionCompositeLoopErrorV1::Bootstrap(
                    ProductionBootstrapRuntimeErrorV16::Store(error),
                ),
                expected,
            );
        }
        assert_projection(
            ProductionCompositeLoopErrorV1::Bootstrap(ProductionBootstrapRuntimeErrorV16::Vault),
            "bootstrap/vault",
        );
        assert_projection(
            ProductionCompositeLoopErrorV1::Bootstrap(ProductionBootstrapRuntimeErrorV16::Ingress(
                ContractsRelayIngressErrorV1::UnpreparedMessage,
            )),
            "bootstrap/unprepared_message",
        );
        assert_projection(
            ProductionCompositeLoopErrorV1::F7Readiness(ProductionF7ReadinessErrorV19::Store(
                SessionStoreError::FundingAuthorityUnavailable,
            )),
            "f7_readiness/store_funding_unavailable",
        );
    }

    #[test]
    fn composite_failure_v25_bootstrap_contexts_preserve_cause_and_terminal_class() {
        for (context, stage) in [
            (
                ProductionCompositeBootstrapContextV25::LocalBootstrap,
                "local_bootstrap",
            ),
            (
                ProductionCompositeBootstrapContextV25::GraphCandidate,
                "graph_candidate",
            ),
            (
                ProductionCompositeBootstrapContextV25::PostExchangeBootstrap,
                "post_exchange_bootstrap",
            ),
        ] {
            for (error, cause) in [
                (ProductionBootstrapRuntimeErrorV16::Binding, "binding"),
                (
                    ProductionBootstrapRuntimeErrorV16::Store(SessionStoreError::Quarantined),
                    "store_quarantined",
                ),
            ] {
                let error = ProductionCompositeLoopErrorV1::BootstrapAtV25 { context, error };
                assert!(!is_f6_activation_awaiting(&error));
                assert!(!is_template_construction_awaiting_v17(&error));
                assert!(!is_claim_finality_awaiting_v16(&error));
                assert!(!is_terminal_refund_transport_awaiting_v24(&error));
                assert_projection(error, &format!("{stage}/{cause}"));
            }
        }
    }

    #[test]
    fn composite_failure_v25_preserves_f6_and_noise_without_changing_refusal() {
        let error = ProductionF6LifecycleErrorV2::Active(ProductionF6ErrorV2::InvalidTerms);
        let error = RelayWorkerInboundErrorV1::F6(F6DispatchErrorV1::F6(error));
        assert_projection(
            ProductionCompositeLoopErrorV1::Inbound(ProductionContractsPollErrorV1::Worker(error)),
            "inbound_f6/terms_invalid",
        );
        assert_projection(
            map_noise_error(ProductionNoiseRelayErrorV1::IdentityAuthenticationFailed),
            "noise/identity_refused",
        );
        assert_projection(
            map_network_config_error(ProductionRelayNetworkConfigErrorV1::PeerBindingMismatch),
            "network_configuration/configuration_peer_binding",
        );
        // Projection does not turn a retryable network outage into an error
        // policy decision: the original predicate still owns that decision.
        let error = ProductionCompositeLoopErrorV1::Network(
            ProductionRelayNetworkRuntimeErrorV1::ConnectUnavailable,
        );
        assert!(is_peer_temporarily_unavailable_v23(&error));
        assert_eq!(
            error.failure_v25().to_string(),
            "network/connect_unavailable"
        );
        assert!(is_peer_temporarily_unavailable_v23(&error));
    }

    #[test]
    fn composite_failure_v25_exact_decoder_refuses_foreign_and_injected_text() {
        for text in [
            "",
            "bootstrap/store_quarantined\n",
            " bootstrap/store_quarantined",
            "bootstrap/store_quarantined/extra",
            "prefix bootstrap/store_quarantined",
            "bootstrap/secret-value",
            "noise/store_quarantined",
            "control/terms_invalid",
            "bootstrap/store_quarantined\0",
            "BOOTSTRAP/store_quarantined",
        ] {
            assert_eq!(
                ProductionCompositeFailureV25::classify_exact_display_v25(text.as_bytes()),
                None
            );
        }
        assert_eq!(
            ProductionCompositeFailureV25::classify_exact_display_v25(&[0xff, b'/', 0xff]),
            None
        );
        assert_eq!(
            ProductionCompositeFailureV25::classify_exact_display_v25(&[b'a'; 97]),
            None
        );
        for stage in Stage::ALL {
            for cause in Cause::ALL {
                let candidate = ProductionCompositeFailureV25 {
                    stage: *stage,
                    cause: *cause,
                };
                let text = candidate.to_string();
                assert_eq!(
                    ProductionCompositeFailureV25::classify_exact_display_v25(text.as_bytes()),
                    permitted(*stage, *cause).then_some(candidate)
                );
                assert!(text.len() <= 96);
                assert!(text.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || byte == b'_'
                    || byte == b'/'));
            }
        }
    }

    #[test]
    fn composite_failure_v25_never_formats_generic_error_payload() {
        struct NeverFormat;
        impl core::fmt::Debug for NeverFormat {
            fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                panic!("source Debug must not run")
            }
        }
        impl core::fmt::Display for NeverFormat {
            fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                panic!("source Display must not run")
            }
        }
        impl std::error::Error for NeverFormat {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                panic!("source traversal must not run")
            }
        }
        let error = ProductionContractsPollErrorV1::Worker(RelayWorkerInboundErrorV1::F6(
            F6DispatchErrorV1::F6(NeverFormat),
        ));
        assert_eq!(
            poll(&error, |_| Cause::F6ActivationUnavailable),
            Cause::F6ActivationUnavailable
        );
    }
}
