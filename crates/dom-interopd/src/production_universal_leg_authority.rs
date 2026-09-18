//! Public provisioning for one selected external chain. JSON authenticates
//! configuration bytes only; native admission still supplies every settlement,
//! deployment and cryptographic setup. These helpers mint neither F7 evidence
//! nor a broadcast/claim/refund authorization.

#[path = "production_universal_xmr_enrollment_authority_v23.rs"]
mod xmr_enrollment_authority_v23;
pub(crate) use xmr_enrollment_authority_v23::{
    ProductionOpenedXmrEnrollmentV23, ProductionUniversalXmrEnrollmentAuthorityV23,
    ProductionXmrEnrolledFundingV23,
};

#[path = "production_xmr_enrollment_bundle_writer_v23.rs"]
mod xmr_enrollment_bundle_writer_v23;
pub use xmr_enrollment_bundle_writer_v23::{
    encode_xmr_enrollment_leg_authority_bundle_v23, ProductionXmrEnrollmentFundingFileV23,
    ProductionXmrEnrollmentLegResourcesV23,
};

#[cfg(test)]
#[path = "production_native_xmr_bundle_v23_tests.rs"]
pub(crate) mod native_bundle_v23;

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use evm_actuator::{EvmFeesV1, EvmSignerRoleV1};
use route_executor::LegIdV1;
use serde::{Deserialize, Serialize};
use settlement_coordinator::ChildAuthorityRefusalV1 as Refusal;
use solana_types::SolanaPubkey;
use xmr_live_sidecar_uds_client::BlockingUdsSidecarPort;
use xmr_refund_policy::compensation::{
    ValidatedXmrCompensationPolicyV11, XmrCompensationPolicyV11,
};
use xmr_secret_store::{EncryptedSqliteSecretStore, SecretStoreMasterKey};
use xmr_sidecar_auth::SidecarAuthKey;
use zeroize::Zeroizing;

use crate::production_child_solana::ScopedSolanaSignerV1;
use crate::production_config::{ProductionChainFamilyV11, ProductionUniversalLegV11};
use crate::production_evm_remote_signer::{
    ProductionEvmRemoteSignerBindingV1, ProductionEvmRemoteSignerPinsV1,
};
use crate::production_evm_signer::{
    ProductionEvmLocalCredentialV1, ProductionEvmSignerBindingV1, ProductionEvmSignerPinsV1,
    ProductionScopedEip1559SignerV1,
};
use crate::production_inputs::AuthenticatedProductionInputsV1;
use crate::production_solana_signer::{
    validate_token_accounts_v7, ProductionSolanaLocalSignerV7, ProductionSolanaSignerBindingV7,
    ProductionSolanaSignerRoleV7, ProductionSolanaTokenAccountsV7, ProductionSolanaUnixSignerV7,
};
use crate::production_xmr_sweep::ProductionXmrRefundRevealSourceV11;
use crate::production_xmr_sweep::ProductionXmrSweepAuthorityV10;

/// Startup path classification, not a filesystem creation capability.
/// Only the authenticated V23 archive directory may legitimately be absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProductionResourceLeafV23 {
    Existing,
    NativeXmrGraphCustodyDirectory,
}

const FORMAT: &str = "DOM-INTEROPD-LEG-AUTHORITY-V11";
const MAX_BYTES: usize = 1024 * 1024;

struct LegScopeV11 {
    route_id: [u8; 32],
    composition_digest: [u8; 32],
    settlement_id: [u8; 32],
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    leg: LegIdV1,
}

impl LegScopeV11 {
    fn require(
        &self,
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
    ) -> Result<(), Refusal> {
        let terms = match leg {
            LegIdV1::Upstream => inputs.composition().upstream(),
            LegIdV1::Downstream => inputs.composition().downstream(),
        };
        if leg != self.leg
            || self.route_id != inputs.admission().route_id()
            || self.composition_digest != inputs.composition().binding_digest()
            || self.settlement_id != terms.settlement_id.0
            || self.session_id != terms.session_id.0
            || self.terms_hash != terms.terms_hash().map_err(|_| Refusal::Conflict)?
        {
            return Err(Refusal::Conflict);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireV11 {
    format: String,
    settlement_id: [u8; 32],
    session_id: [u8; 32],
    chain_id: [u8; 32],
    terms_hash: [u8; 32],
    authority: WireAuthorityV11,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "family", content = "parameters", deny_unknown_fields)]
enum WireAuthorityV11 {
    #[serde(rename = "EVM")]
    Evm(ProductionUniversalEvmAuthorityV11),
    #[serde(rename = "SOL")]
    Solana(ProductionUniversalSolanaAuthorityV11),
    #[serde(rename = "XMR")]
    Monero(ProductionUniversalXmrAuthorityV11),
    #[serde(rename = "XMR_ENROLLMENT_V23")]
    MoneroEnrollment(ProductionUniversalXmrEnrollmentAuthorityV23),
}

/// Closed selected-family value. Bitcoin retains its native participant and
/// prebroadcast bundle; it must never be decoded as an EVM/SOL/XMR signer.
pub(crate) enum ProductionUniversalLegAuthorityV11 {
    Evm(ProductionUniversalEvmAuthorityV11),
    Solana(ProductionUniversalSolanaAuthorityV11),
    Monero(ProductionUniversalXmrAuthorityV11),
    MoneroEnrollment(ProductionUniversalXmrEnrollmentAuthorityV23),
}

impl ProductionUniversalLegAuthorityV11 {
    /// Requires canonical JSON, the manifest's exact byte digest, and the
    /// admitted settlement in this particular position. A copied sibling's
    /// bundle cannot pass merely because the two positions use the same chain.
    pub(crate) fn decode(
        bytes: &[u8],
        descriptor: &ProductionUniversalLegV11,
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
    ) -> Result<Self, Refusal> {
        if bytes.is_empty()
            || bytes.len() > MAX_BYTES
            || ProductionUniversalLegV11::bundle_digest(bytes).map_err(|_| Refusal::Conflict)?
                != descriptor.authority_bundle_digest
        {
            return Err(Refusal::Conflict);
        }
        let wire: WireV11 = serde_json::from_slice(bytes).map_err(|_| Refusal::Conflict)?;
        if serde_json::to_vec(&wire).map_err(|_| Refusal::Conflict)? != bytes {
            return Err(Refusal::Conflict);
        }
        let terms = match leg {
            LegIdV1::Upstream => inputs.composition().upstream(),
            LegIdV1::Downstream => inputs.composition().downstream(),
        };
        if wire.format != FORMAT
            || wire.settlement_id != descriptor.settlement_id
            || wire.session_id != descriptor.session_id
            || wire.chain_id != descriptor.chain_id
            || wire.settlement_id != terms.settlement_id.0
            || wire.session_id != terms.session_id.0
            || wire.chain_id != terms.counterparty_leg.chain_id.0
            || wire.terms_hash != terms.terms_hash().map_err(|_| Refusal::Conflict)?
        {
            return Err(Refusal::Conflict);
        }
        let scope = LegScopeV11 {
            route_id: inputs.admission().route_id(),
            composition_digest: inputs.composition().binding_digest(),
            settlement_id: wire.settlement_id,
            session_id: wire.session_id,
            terms_hash: wire.terms_hash,
            leg,
        };
        match (descriptor.family, wire.authority) {
            (ProductionChainFamilyV11::Evm, WireAuthorityV11::Evm(mut value)) => {
                value.scope = Some(scope);
                value.fees(inputs, leg)?;
                Ok(Self::Evm(value))
            }
            (ProductionChainFamilyV11::Sol, WireAuthorityV11::Solana(mut value)) => {
                let session = inputs.solana_session(leg).ok_or(Refusal::Conflict)?;
                validate_token_accounts_v7(session.setup(), value.accounts())?;
                relative_path(&value.peer_socket)?;
                require_milliseconds(value.peer_timeout_ms, 60_000)?;
                if session.setup().funder() == session.setup().recipient() {
                    return Err(Refusal::Conflict);
                }
                value.scope = Some(scope);
                Ok(Self::Solana(value))
            }
            (ProductionChainFamilyV11::Xmr, WireAuthorityV11::Monero(mut value)) => {
                let session = inputs.monero_session(leg).ok_or(Refusal::Conflict)?;
                let refund = session.refund_bundle().ok_or(Refusal::Conflict)?;
                relative_path(&value.secret_store)?;
                relative_path(&value.sidecar_socket)?;
                require_milliseconds(value.sidecar_timeout_ms, 180_000)?;
                if value.secret_store == value.sidecar_socket
                    || value.setup_binding_hash != session.setup().binding_hash()
                    || value.refund_template_hash != refund.template_hash
                    || value.refund_point_sec1.as_slice() != refund.adaptor_point_sec1
                    || ![
                        terms.counterparty_leg.beneficiary.0,
                        terms.counterparty_leg.refund_to.0,
                    ]
                    .contains(&value.local_participant_id)
                    || terms.counterparty_leg.beneficiary == terms.counterparty_leg.refund_to
                {
                    return Err(Refusal::Conflict);
                }
                value.validated_compensation = Some(
                    XmrCompensationPolicyV11::from_bytes(&value.compensation_policy)
                        .map_err(|_| Refusal::Conflict)?
                        .validate_for(terms)
                        .map_err(|_| Refusal::Conflict)?,
                );
                if let Some(candidate) = &value.private_funding_v12 {
                    relative_path(&candidate.raw_transaction_file)?;
                    if value.local_participant_id != terms.counterparty_leg.refund_to.0
                        || candidate.max_fee_piconero == 0
                        || u128::from(candidate.max_fee_piconero) > terms.fee_limit.counterparty_max
                        || candidate.raw_transaction_file == value.secret_store
                        || candidate.raw_transaction_file == value.sidecar_socket
                    {
                        return Err(Refusal::Conflict);
                    }
                }
                if let Some(recovery) = &value.recovery_v23 {
                    if value.recovery_v22.is_some()
                        || recovery.custody_id == [0; 32]
                        || value
                            .validated_compensation
                            .as_ref()
                            .ok_or(Refusal::Conflict)?
                            .policy()
                            .bounded_availability_v23
                            .is_none()
                    {
                        return Err(Refusal::Conflict);
                    }
                    relative_path(&recovery.directory)?;
                    relative_path(&recovery.sealing_key_file)?;
                    relative_path(&recovery.nullifier_store)?;
                    if Path::new(&recovery.directory).components().count() != 1 {
                        return Err(Refusal::Conflict);
                    }
                }
                if let Some(recovery) = &value.recovery_v22 {
                    relative_path(&recovery.directory)?;
                    relative_path(&recovery.sealing_key_file)?;
                    if Path::new(&recovery.directory).components().count() != 1 {
                        return Err(Refusal::Conflict);
                    }
                }
                value.scope = Some(scope);
                Ok(Self::Monero(value))
            }
            (ProductionChainFamilyV11::Xmr, WireAuthorityV11::MoneroEnrollment(mut value)) => {
                value.admit(inputs, leg, scope)?;
                Ok(Self::MoneroEnrollment(value))
            }
            _ => Err(Refusal::Conflict),
        }
    }

    /// Additional resources the root must include in its cross-position path
    /// isolation check before opening any owner. Paths are state-dir relative.
    pub(crate) fn resource_paths(&self) -> Vec<(&str, ProductionResourceLeafV23)> {
        use ProductionResourceLeafV23::{Existing, NativeXmrGraphCustodyDirectory};
        match self {
            Self::MoneroEnrollment(value) => value.resource_paths_v23(),
            Self::Evm(_) => Vec::new(),
            Self::Solana(value) => vec![(value.peer_socket.as_str(), Existing)],
            Self::Monero(value) => {
                let mut paths = vec![
                    (value.secret_store.as_str(), Existing),
                    (value.sidecar_socket.as_str(), Existing),
                ];
                if let Some(candidate) = &value.private_funding_v12 {
                    paths.push((candidate.raw_transaction_file.as_str(), Existing));
                }
                if let Some(recovery) = &value.recovery_v22 {
                    paths.push((recovery.directory.as_str(), Existing));
                    paths.push((recovery.sealing_key_file.as_str(), Existing));
                }
                if let Some(recovery) = &value.recovery_v23 {
                    paths.push((recovery.directory.as_str(), NativeXmrGraphCustodyDirectory));
                    paths.push((recovery.sealing_key_file.as_str(), Existing));
                    paths.push((recovery.nullifier_store.as_str(), Existing));
                }
                paths
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProductionUniversalEvmAuthorityV11 {
    #[serde(skip)]
    scope: Option<LegScopeV11>,
    // Canonical decimal strings preserve the complete uint128 range without
    // relying on a JSON consumer's floating-point number representation.
    max_fee_per_gas: String,
    max_priority_fee_per_gas: String,
    observation_valid_for_ms: u64,
    remote_custody_lease_duration_ms: u64,
}

pub(crate) struct ProductionUniversalEvmSignerPairV11 {
    pub(crate) local_signer: ProductionScopedEip1559SignerV1,
    pub(crate) remote_signer: ProductionEvmRemoteSignerBindingV1,
    pub(crate) fees: EvmFeesV1,
    pub(crate) observation_valid_for_ms: u64,
    pub(crate) remote_custody_lease_duration_ms: u64,
    pub(crate) local_participant_id: [u8; 32],
}

impl ProductionUniversalEvmAuthorityV11 {
    fn fees(
        &self,
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
    ) -> Result<EvmFeesV1, Refusal> {
        self.scope
            .as_ref()
            .ok_or(Refusal::Conflict)?
            .require(inputs, leg)?;
        let session = inputs.evm_session(leg).ok_or(Refusal::Conflict)?;
        let deployment = inputs
            .admission()
            .evm_deployment_capability(leg, session)
            .map_err(|_| Refusal::Conflict)?;
        let fee = canonical_u128(&self.max_fee_per_gas)?;
        let priority = canonical_u128(&self.max_priority_fee_per_gas)?;
        if fee > deployment.deployment().max_fee_per_gas
            || priority > deployment.deployment().max_priority_fee_per_gas
        {
            return Err(Refusal::Conflict);
        }
        require_milliseconds(self.observation_valid_for_ms, 60_000)?;
        require_milliseconds(self.remote_custody_lease_duration_ms, 3_600_000)?;
        EvmFeesV1::new(fee, priority).map_err(|_| Refusal::Conflict)
    }

    /// Binds exactly this leg, even if its sibling is also EVM. Only one local
    /// account is imported; the complementary account stays a Contracts/Relay
    /// request capability and never becomes a local signing handle.
    pub(crate) fn bind_signers(
        self,
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
        signing: Zeroizing<[u8; 32]>,
        owner_id: [u8; 32],
    ) -> Result<ProductionUniversalEvmSignerPairV11, Refusal> {
        let fees = self.fees(inputs, leg)?;
        let session = inputs.evm_session(leg).ok_or(Refusal::Conflict)?;
        let deployment = inputs
            .admission()
            .evm_deployment_capability(leg, session)
            .map_err(|_| Refusal::Conflict)?;
        let adapter = deployment.adapter_config();
        let credential =
            ProductionEvmLocalCredentialV1::import(signing).map_err(|_| Refusal::Conflict)?;
        let account = credential.account();
        let (local_role, remote_role) =
            match (account == adapter.funder, account == adapter.beneficiary) {
                (true, false) => (EvmSignerRoleV1::Funder, EvmSignerRoleV1::Beneficiary),
                (false, true) => (EvmSignerRoleV1::Beneficiary, EvmSignerRoleV1::Funder),
                _ => return Err(Refusal::Conflict),
            };
        let binding = ProductionEvmSignerBindingV1::new(ProductionEvmSignerPinsV1 {
            route_id: inputs.admission().route_id(),
            registry_digest: deployment.registry_digest(),
            profile_digest: deployment.profile_digest(),
            asset_binding_digest: deployment.asset_binding_digest(),
            deployment_digest: deployment.deployment().deployment_digest,
            terms_digest: session.settlement_terms_digest(),
            chain_id: adapter.chain_id,
            contract: adapter.contract,
            account,
            role: local_role,
        })
        .map_err(|_| Refusal::Conflict)?;
        let terms = match leg {
            LegIdV1::Upstream => inputs.composition().upstream(),
            LegIdV1::Downstream => inputs.composition().downstream(),
        };
        let (requester_id, signer_id) = match local_role {
            EvmSignerRoleV1::Funder => (
                terms.counterparty_leg.refund_to.0,
                terms.counterparty_leg.beneficiary.0,
            ),
            EvmSignerRoleV1::Beneficiary => (
                terms.counterparty_leg.beneficiary.0,
                terms.counterparty_leg.refund_to.0,
            ),
        };
        let remote_account = match remote_role {
            EvmSignerRoleV1::Funder => adapter.funder,
            EvmSignerRoleV1::Beneficiary => adapter.beneficiary,
        };
        let remote_signer =
            ProductionEvmRemoteSignerBindingV1::new(ProductionEvmRemoteSignerPinsV1 {
                route_id: inputs.admission().route_id(),
                session_id: terms.session_id.0,
                settlement_id: terms.settlement_id.0,
                terms_digest: session.settlement_terms_digest(),
                registry_digest: deployment.registry_digest(),
                profile_digest: deployment.profile_digest(),
                deployment_digest: deployment.deployment().deployment_digest,
                composition_digest: inputs.composition().binding_digest(),
                chain_id: adapter.chain_id,
                contract: adapter.contract,
                signer_account: remote_account,
                role: remote_role,
                requester_id,
                signer_id,
                owner_id,
            })?;
        Ok(ProductionUniversalEvmSignerPairV11 {
            local_signer: credential.bind(binding).map_err(|_| Refusal::Conflict)?,
            remote_signer,
            fees,
            observation_valid_for_ms: self.observation_valid_for_ms,
            remote_custody_lease_duration_ms: self.remote_custody_lease_duration_ms,
            local_participant_id: requester_id,
        })
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SolanaRoleV11 {
    Funder,
    Beneficiary,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenAccountsV11 {
    source: [u8; 32],
    recipient: [u8; 32],
    refund: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProductionUniversalSolanaAuthorityV11 {
    #[serde(skip)]
    scope: Option<LegScopeV11>,
    local_role: SolanaRoleV11,
    token_accounts: Option<TokenAccountsV11>,
    peer_socket: String,
    peer_timeout_ms: u64,
}

pub(crate) struct ProductionUniversalSolanaSignerPairV11 {
    pub(crate) funder: Box<dyn ScopedSolanaSignerV1>,
    pub(crate) beneficiary: Box<dyn ScopedSolanaSignerV1>,
    pub(crate) token_accounts: Option<ProductionSolanaTokenAccountsV7>,
    local_participant_id: [u8; 32],
}

impl ProductionUniversalSolanaSignerPairV11 {
    pub(crate) const fn local_participant_id(&self) -> [u8; 32] {
        self.local_participant_id
    }
}

impl ProductionUniversalSolanaAuthorityV11 {
    fn accounts(&self) -> Option<ProductionSolanaTokenAccountsV7> {
        self.token_accounts
            .map(|a| ProductionSolanaTokenAccountsV7 {
                source: SolanaPubkey(a.source),
                recipient: SolanaPubkey(a.recipient),
                refund: SolanaPubkey(a.refund),
            })
    }

    /// V7 authenticates the returned signature against the exact admitted
    /// Ed25519 account and rebuilt message. Its frozen protocol has no HMAC
    /// handshake: V4's reserved peer_auth field is wiped here, never sent or
    /// represented as a transport authentication guarantee.
    pub(crate) fn bind_signers(
        self,
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
        state_dir: &Path,
        seed: Zeroizing<[u8; 32]>,
        peer_auth: Zeroizing<[u8; 32]>,
    ) -> Result<ProductionUniversalSolanaSignerPairV11, Refusal> {
        self.scope
            .as_ref()
            .ok_or(Refusal::Conflict)?
            .require(inputs, leg)?;
        if *peer_auth == [0; 32] || *peer_auth == *seed {
            return Err(Refusal::Conflict);
        }
        drop(peer_auth);
        let session = inputs.solana_session(leg).ok_or(Refusal::Conflict)?;
        let terms = match leg {
            LegIdV1::Upstream => inputs.composition().upstream(),
            LegIdV1::Downstream => inputs.composition().downstream(),
        };
        let local_participant_id = match self.local_role {
            SolanaRoleV11::Funder => terms.counterparty_leg.refund_to.0,
            SolanaRoleV11::Beneficiary => terms.counterparty_leg.beneficiary.0,
        };
        let accounts = self.accounts();
        let (local_role, peer_role) = match self.local_role {
            SolanaRoleV11::Funder => (
                ProductionSolanaSignerRoleV7::Funder,
                ProductionSolanaSignerRoleV7::Beneficiary,
            ),
            SolanaRoleV11::Beneficiary => (
                ProductionSolanaSignerRoleV7::Beneficiary,
                ProductionSolanaSignerRoleV7::Funder,
            ),
        };
        let local = ProductionSolanaLocalSignerV7::new(
            ProductionSolanaSignerBindingV7::authenticate(session, local_role, accounts)?,
            seed,
        )?;
        let peer_binding =
            ProductionSolanaSignerBindingV7::authenticate(session, peer_role, accounts)?;
        let path = existing_resource(state_dir, &self.peer_socket, true)?;
        let socket = connect_unix_bounded(&path)?;
        let peer = ProductionSolanaUnixSignerV7::new(
            peer_binding,
            socket,
            require_milliseconds(self.peer_timeout_ms, 60_000)?,
        )?;
        let (funder, beneficiary): (Box<dyn ScopedSolanaSignerV1>, Box<dyn ScopedSolanaSignerV1>) =
            match self.local_role {
                SolanaRoleV11::Funder => (Box::new(local), Box::new(peer)),
                SolanaRoleV11::Beneficiary => (Box::new(peer), Box::new(local)),
            };
        Ok(ProductionUniversalSolanaSignerPairV11 {
            funder,
            beneficiary,
            token_accounts: accounts,
            local_participant_id,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProductionUniversalXmrAuthorityV11 {
    #[serde(skip)]
    scope: Option<LegScopeV11>,
    #[serde(skip)]
    validated_compensation: Option<ValidatedXmrCompensationPolicyV11>,
    // Exact native canonical bytes. Its digest must already be present in
    // the bilateral terms; an operator cannot upgrade old terms unilaterally.
    compensation_policy: Vec<u8>,
    local_participant_id: [u8; 32],
    setup_binding_hash: [u8; 32],
    refund_template_hash: [u8; 32],
    refund_point_sec1: Vec<u8>,
    secret_store: String,
    sidecar_socket: String,
    sidecar_timeout_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_funding_v12: Option<ProductionXmrPrivateFundingConfigV12>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_v22: Option<ProductionXmrRecoveryResourcesV22>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_v23: Option<ProductionXmrRecoveryResourcesV23>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionXmrRecoveryResourcesV23 {
    directory: String,
    sealing_key_file: String,
    custody_id: [u8; 32],
    nullifier_store: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionXmrRecoveryResourcesV22 {
    directory: String,
    sealing_key_file: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionXmrPrivateFundingConfigV12 {
    raw_transaction_file: String,
    max_fee_piconero: u64,
}

impl ProductionUniversalXmrAuthorityV11 {
    /// Open the provisioned independent recovery key without exporting it or
    /// deriving it from either protocol witness. The graph scope comes from Store.
    pub(crate) fn recovery_resources_v22(
        &self,
        state_dir: &Path,
        local_store_key: &[u8; 32],
        sidecar_key: &[u8; 32],
    ) -> Result<
        (
            cap_std::fs::Dir,
            String,
            dom_scriptless_crypto::XmrRecoverySealKeyV11,
        ),
        Refusal,
    > {
        let config = self.recovery_v22.as_ref().ok_or(Refusal::Conflict)?;
        Self::open_recovery_resources_v23(
            state_dir,
            &config.directory,
            &config.sealing_key_file,
            local_store_key,
            sidecar_key,
        )
    }

    fn open_recovery_resources_v23(
        state_dir: &Path,
        directory: &str,
        sealing_key_file: &str,
        local_store_key: &[u8; 32],
        sidecar_key: &[u8; 32],
    ) -> Result<
        (
            cap_std::fs::Dir,
            String,
            dom_scriptless_crypto::XmrRecoverySealKeyV11,
        ),
        Refusal,
    > {
        use std::io::Read;
        relative_path(directory)?;
        if Path::new(directory).components().count() != 1 {
            return Err(Refusal::Conflict);
        }
        let path = existing_resource(state_dir, sealing_key_file, false)?;
        let before = std::fs::symlink_metadata(&path).map_err(|_| Refusal::Unavailable)?;
        let fd = rustix::fs::open(
            &path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| Refusal::Unavailable)?;
        let mut file = std::fs::File::from(fd);
        let actual = file.metadata().map_err(|_| Refusal::Unavailable)?;
        if actual.dev() != before.dev()
            || actual.ino() != before.ino()
            || actual.len() != 32
            || actual.nlink() != 1
            || !actual.is_file()
            || actual.mode() & 0o077 != 0
        {
            return Err(Refusal::Conflict);
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        file.read_exact(&mut bytes[..])
            .map_err(|_| Refusal::Unavailable)?;
        if &*bytes == local_store_key || &*bytes == sidecar_key {
            return Err(Refusal::Conflict);
        }
        let after = std::fs::symlink_metadata(&path).map_err(|_| Refusal::Unavailable)?;
        if after.dev() != actual.dev()
            || after.ino() != actual.ino()
            || after.len() != 32
            || after.nlink() != 1
            || after.uid() != actual.uid()
            || after.mode() != actual.mode()
        {
            return Err(Refusal::Conflict);
        }
        let key = dom_scriptless_crypto::XmrRecoverySealKeyV11::from_bytes(bytes)
            .map_err(|_| Refusal::Conflict)?;
        let parent = cap_std::fs::Dir::open_ambient_dir(state_dir, cap_std::ambient_authority())
            .map_err(|_| Refusal::Unavailable)?;
        Ok((parent, directory.to_owned(), key))
    }

    pub(crate) fn uses_graph_custody_v23(&self) -> bool {
        self.recovery_v23.is_some()
    }

    /// Open provisioned resources only. Missing registry/key is never initialized.
    pub(crate) fn graph_custody_resources_v23(
        &self,
        state_dir: &Path,
        local_store_key: &[u8; 32],
        sidecar_key: &[u8; 32],
    ) -> Result<
        (
            crate::production_contracts::ProductionXmrGraphCustodyResourcesV23,
            std::rc::Rc<xmr_dleq_nullifier_store::DleqNullifierStore>,
        ),
        Refusal,
    > {
        let config = self.recovery_v23.as_ref().ok_or(Refusal::Conflict)?;
        if self.recovery_v22.is_some()
            || config.custody_id == [0; 32]
            || self
                .validated_compensation
                .as_ref()
                .ok_or(Refusal::Conflict)?
                .policy()
                .bounded_availability_v23
                .is_none()
        {
            return Err(Refusal::Conflict);
        }
        let (parent, directory_name, key) = Self::open_recovery_resources_v23(
            state_dir,
            &config.directory,
            &config.sealing_key_file,
            local_store_key,
            sidecar_key,
        )?;
        let path = existing_resource(state_dir, &config.nullifier_store, false)?;
        let before = std::fs::symlink_metadata(&path).map_err(|_| Refusal::Unavailable)?;
        if before.nlink() != 1 {
            return Err(Refusal::Conflict);
        }
        let nullifiers = xmr_dleq_nullifier_store::DleqNullifierStore::open_existing(&path)
            .map_err(|_| Refusal::Conflict)?;
        let after = std::fs::symlink_metadata(&path).map_err(|_| Refusal::Unavailable)?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.uid() != after.uid()
            || before.mode() != after.mode()
            || after.nlink() != 1
        {
            return Err(Refusal::Conflict);
        }
        Ok((
            crate::production_contracts::ProductionXmrGraphCustodyResourcesV23 {
                parent,
                directory_name,
                custody_id: config.custody_id,
                key,
            },
            std::rc::Rc::new(nullifiers),
        ))
    }

    /// Build the real sweep before graph signing has produced its durable
    /// recovery owner. The deferred source has no execution authority.
    pub(crate) fn open_sweep_v23(
        mut self,
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
        state_dir: &Path,
        local_key: Zeroizing<[u8; 32]>,
        sidecar_auth: Zeroizing<[u8; 32]>,
        recovery: std::rc::Rc<crate::production_xmr_sweep::ProductionXmrDeferredRecoveryV23>,
    ) -> Result<ProductionXmrSweepAuthorityV10, Refusal> {
        self.scope
            .as_ref()
            .ok_or(Refusal::Conflict)?
            .require(inputs, leg)?;
        if !self.uses_graph_custody_v23() {
            return Err(Refusal::Conflict);
        }
        let terms = match leg {
            LegIdV1::Upstream => inputs.composition().upstream(),
            LegIdV1::Downstream => inputs.composition().downstream(),
        };
        let source = if self.local_participant_id == terms.counterparty_leg.refund_to.0 {
            if self.private_funding_v12.is_none() {
                return Err(Refusal::Conflict);
            }
            Some(ProductionXmrRefundRevealSourceV11::RecoveryDeferredV23(
                recovery,
            ))
        } else if self.local_participant_id == terms.counterparty_leg.beneficiary.0 {
            if self.private_funding_v12.is_some() {
                return Err(Refusal::Conflict);
            }
            None
        } else {
            return Err(Refusal::Conflict);
        };
        let candidate = self.private_funding_v12.take();
        let sweep = self.open_sweep(inputs, leg, state_dir, local_key, sidecar_auth, source)?;
        if let Some(candidate) = candidate {
            sweep.attach_private_funding_v12(
                state_dir,
                &candidate.raw_transaction_file,
                candidate.max_fee_piconero,
            )
        } else {
            Ok(sweep)
        }
    }

    /// Bind the admitted local role to the concrete same-Store recovery driver.
    /// The U owner never receives an extra refund source; the T owner obtains
    /// U only from the native canonical DOM refund observed by that driver.
    pub(crate) fn open_sweep_v12(
        mut self,
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
        state_dir: &Path,
        local_key: Zeroizing<[u8; 32]>,
        sidecar_auth: Zeroizing<[u8; 32]>,
        recovery: std::rc::Rc<
            crate::production_xmr_recovery_driver_v12::ProductionXmrRecoveryDriverV12,
        >,
    ) -> Result<ProductionXmrSweepAuthorityV10, Refusal> {
        self.scope
            .as_ref()
            .ok_or(Refusal::Conflict)?
            .require(inputs, leg)?;
        let terms = match leg {
            LegIdV1::Upstream => inputs.composition().upstream(),
            LegIdV1::Downstream => inputs.composition().downstream(),
        };
        recovery.require_attachment(terms.terms_hash().map_err(|_| Refusal::Conflict)?)?;
        let source = if self.local_participant_id == terms.counterparty_leg.refund_to.0 {
            if self.private_funding_v12.is_none() {
                return Err(Refusal::Conflict);
            }
            Some(ProductionXmrRefundRevealSourceV11::RecoveryV12(recovery))
        } else if self.local_participant_id == terms.counterparty_leg.beneficiary.0 {
            if self.private_funding_v12.is_some() {
                return Err(Refusal::Conflict);
            }
            None
        } else {
            return Err(Refusal::Conflict);
        };
        let candidate = self.private_funding_v12.take();
        let sweep = self.open_sweep(inputs, leg, state_dir, local_key, sidecar_auth, source)?;
        if let Some(candidate) = candidate {
            sweep.attach_private_funding_v12(
                state_dir,
                &candidate.raw_transaction_file,
                candidate.max_fee_piconero,
            )
        } else {
            Ok(sweep)
        }
    }

    /// One existing encrypted local share is mandatory even during daemon
    /// creation: provisioning of T/U belongs to the session initializer. An
    /// absent database or row is never replaced by an empty one on restart.
    /// The refund source must be the root's same physical Contracts owner.
    pub(crate) fn open_sweep(
        self,
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
        state_dir: &Path,
        local_store: Zeroizing<[u8; 32]>,
        sidecar_auth: Zeroizing<[u8; 32]>,
        refund_source: Option<ProductionXmrRefundRevealSourceV11>,
    ) -> Result<ProductionXmrSweepAuthorityV10, Refusal> {
        self.scope
            .as_ref()
            .ok_or(Refusal::Conflict)?
            .require(inputs, leg)?;
        self.compensation_policy()?;
        // A V12 private candidate cannot silently fall back to legacy external
        // funding verification. Only open_sweep_v12 consumes that capability.
        if self.private_funding_v12.is_some() {
            return Err(Refusal::Conflict);
        }
        if *local_store == *sidecar_auth {
            return Err(Refusal::Conflict);
        }
        let secrets_path = existing_resource(state_dir, &self.secret_store, false)?;
        let sidecar_path = existing_resource(state_dir, &self.sidecar_socket, true)?;
        let secrets = EncryptedSqliteSecretStore::open_existing(
            secrets_path,
            SecretStoreMasterKey::new(*local_store).map_err(|_| Refusal::Conflict)?,
        )
        .map_err(|error| match error {
            xmr_secret_store::SecretStoreError::Unavailable => Refusal::Unavailable,
            _ => Refusal::Conflict,
        })?;
        let sidecar = BlockingUdsSidecarPort::with_timeout(
            sidecar_path,
            SidecarAuthKey::new(*sidecar_auth).map_err(|_| Refusal::Conflict)?,
            require_milliseconds(self.sidecar_timeout_ms, 180_000)?,
        )
        .map_err(|_| Refusal::Conflict)?;
        ProductionXmrSweepAuthorityV10::authenticate(
            inputs,
            leg,
            self.local_participant_id,
            secrets,
            sidecar,
            refund_source,
        )
    }

    pub(crate) const fn local_participant_id(&self) -> [u8; 32] {
        self.local_participant_id
    }

    pub(crate) fn compensation_policy(
        &self,
    ) -> Result<&ValidatedXmrCompensationPolicyV11, Refusal> {
        self.validated_compensation
            .as_ref()
            .ok_or(Refusal::Conflict)
    }
}

fn canonical_u128(text: &str) -> Result<u128, Refusal> {
    let value = text.parse::<u128>().map_err(|_| Refusal::Conflict)?;
    if value.to_string() != text {
        return Err(Refusal::Conflict);
    }
    Ok(value)
}

fn require_milliseconds(value: u64, maximum: u64) -> Result<Duration, Refusal> {
    if value == 0 || value > maximum {
        return Err(Refusal::Conflict);
    }
    Ok(Duration::from_millis(value))
}

fn relative_path(value: &str) -> Result<(), Refusal> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4096
        || value.contains('\0')
        || value.contains('\\')
        || path.is_absolute()
        || !path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
        || path
            .components()
            .map(|part| part.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/")
            != value
    {
        return Err(Refusal::Conflict);
    }
    Ok(())
}

/// The already-validated state root supplies the expected owner. Every child
/// parent must retain that ownership and owner-only permissions; symlinks and
/// an unexpected regular-file/socket type are hard conflicts.
pub(crate) fn existing_resource(
    state_dir: &Path,
    relative: &str,
    socket: bool,
) -> Result<PathBuf, Refusal> {
    relative_path(relative)?;
    let root = std::fs::symlink_metadata(state_dir).map_err(|_| Refusal::Unavailable)?;
    if !root.is_dir() || root.file_type().is_symlink() || root.permissions().mode() & 0o077 != 0 {
        return Err(Refusal::Conflict);
    }
    let owner = root.uid();
    let mut path = state_dir.to_owned();
    let components: Vec<_> = Path::new(relative).components().collect();
    for (index, component) in components.iter().enumerate() {
        path.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| Refusal::Unavailable)?;
        let final_component = index + 1 == components.len();
        let expected_type = if !final_component {
            metadata.is_dir()
        } else if socket {
            metadata.file_type().is_socket()
        } else {
            metadata.is_file()
        };
        if !expected_type
            || metadata.file_type().is_symlink()
            || metadata.uid() != owner
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(Refusal::Conflict);
        }
    }
    Ok(path)
}

pub(crate) fn connect_unix_bounded(path: &Path) -> Result<UnixStream, Refusal> {
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};
    use std::os::fd::AsRawFd;
    let address = UnixAddr::new(path).map_err(|_| Refusal::Conflict)?;
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(|_| Refusal::Unavailable)?;
    // A full Unix backlog reports EAGAIN; release this socket and allow a
    // bounded retry instead of blocking daemon initialization indefinitely.
    connect(fd.as_raw_fd(), &address).map_err(|_| Refusal::Unavailable)?;
    let stream = UnixStream::from(fd);
    stream
        .set_nonblocking(false)
        .map_err(|_| Refusal::Unavailable)?;
    Ok(stream)
}

/// The identity every leg authority bundle repeats from its manifest entry.
///
/// The decoder rejects a bundle whose identity disagrees with the descriptor
/// *or* with the admitted terms, so a bundle copied from the sibling position
/// cannot pass merely because both legs use the same chain. Repeating the
/// identity here is what makes that check possible.
pub struct ProductionLegBundleIdentityV22 {
    /// Settlement bound by this position.
    pub settlement_id: [u8; 32],
    /// Signing session bound by this position.
    pub session_id: [u8; 32],
    /// External network selected by the authenticated registry.
    pub chain_id: [u8; 32],
    /// Digest of the terms this position settles under.
    pub terms_hash: [u8; 32],
}

/// The EVM position's own policy values, in the units the decoder reads.
pub struct ProductionEvmLegBundleParametersV22 {
    /// Canonical decimal `u128`; no leading zero, no sign, no separator.
    pub max_fee_per_gas: String,
    /// Canonical decimal `u128`, bounded by the deployment at load.
    pub max_priority_fee_per_gas: String,
    /// Non-zero, at most 60_000.
    pub observation_valid_for_ms: u64,
    /// Non-zero, at most 3_600_000.
    pub remote_custody_lease_duration_ms: u64,
}

/// One encoded leg authority bundle and the digest its manifest entry pins.
pub struct ProductionLegBundleV22 {
    bytes: Vec<u8>,
    digest: [u8; 32],
}

impl ProductionLegBundleV22 {
    /// Bytes to write at the descriptor's `authority_bundle` path, mode 0600.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Value to place in the descriptor's `authority_bundle_digest`.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Encodes one EVM leg authority bundle.
///
/// The decoder requires `serde_json::to_vec(&wire) == bytes`, so the bytes
/// must come from the same serializer over the same type. That is why this
/// writer lives beside `WireV11` and builds it directly instead of restating
/// the schema: a second description of the same wire is a second thing to
/// keep in step, and the failure would be a daemon that refuses its own
/// generated bundle at startup with nothing but `Conflict` to show for it.
///
/// The checks applied here are exactly the ones that do not need the
/// authenticated inputs: the decimal strings must be canonical and the two
/// millisecond bounds must hold. Everything cross-checked against the
/// registry, the admitted deployment and the terms stays with the decoder,
/// which is the only place that holds those authorities.
pub fn encode_evm_leg_authority_bundle_v22(
    identity: &ProductionLegBundleIdentityV22,
    parameters: ProductionEvmLegBundleParametersV22,
) -> Result<ProductionLegBundleV22, Refusal> {
    canonical_u128(&parameters.max_fee_per_gas)?;
    canonical_u128(&parameters.max_priority_fee_per_gas)?;
    require_milliseconds(parameters.observation_valid_for_ms, 60_000)?;
    require_milliseconds(parameters.remote_custody_lease_duration_ms, 3_600_000)?;
    encode_wire_v22(
        identity,
        WireAuthorityV11::Evm(ProductionUniversalEvmAuthorityV11 {
            scope: None,
            max_fee_per_gas: parameters.max_fee_per_gas,
            max_priority_fee_per_gas: parameters.max_priority_fee_per_gas,
            observation_valid_for_ms: parameters.observation_valid_for_ms,
            remote_custody_lease_duration_ms: parameters.remote_custody_lease_duration_ms,
        }),
    )
}

/// Which of the two escrow keys this daemon signs with locally; the other one
/// is served by the peer signer on `peer_socket`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionSolanaLegRoleV25 {
    /// Initializes and funds the escrow.
    Funder,
    /// Claims the escrow with the revealed secret.
    Beneficiary,
}

/// Explicit legacy SPL token accounts. Native SOL takes none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionSolanaLegTokenAccountsV25 {
    /// Funder's source token account.
    pub source: [u8; 32],
    /// Beneficiary's destination token account.
    pub recipient: [u8; 32],
    /// Funder's refund token account.
    pub refund: [u8; 32],
}

/// The Solana position's own local values, in the units the decoder reads.
pub struct ProductionSolanaLegBundleParametersV25 {
    /// The key this daemon holds; the peer socket serves the other one.
    pub local_role: ProductionSolanaLegRoleV25,
    /// `None` for native SOL; all three accounts for legacy SPL.
    pub token_accounts: Option<ProductionSolanaLegTokenAccountsV25>,
    /// Normal relative path inside the state directory.
    pub peer_socket: String,
    /// Non-zero, at most 60_000.
    pub peer_timeout_ms: u64,
}

/// Encodes one Solana leg authority bundle.
///
/// Same reasoning as the EVM writer: the decoder requires the bytes to
/// re-serialize to themselves, so they are produced from `WireV11` here rather
/// than from a second description of the schema. Only the checks that stand
/// without the authenticated inputs are applied: the socket path, the timeout
/// bound, and non-zero token accounts. Whether the asset admits token accounts
/// at all, whether one of them is the vault PDA, and whether funder and
/// recipient differ are judged by the decoder against the admitted setup.
pub fn encode_solana_leg_authority_bundle_v25(
    identity: &ProductionLegBundleIdentityV22,
    parameters: ProductionSolanaLegBundleParametersV25,
) -> Result<ProductionLegBundleV22, Refusal> {
    relative_path(&parameters.peer_socket)?;
    require_milliseconds(parameters.peer_timeout_ms, 60_000)?;
    if let Some(accounts) = parameters.token_accounts {
        if [accounts.source, accounts.recipient, accounts.refund].contains(&[0; 32]) {
            return Err(Refusal::Conflict);
        }
    }
    encode_wire_v22(
        identity,
        WireAuthorityV11::Solana(ProductionUniversalSolanaAuthorityV11 {
            scope: None,
            local_role: match parameters.local_role {
                ProductionSolanaLegRoleV25::Funder => SolanaRoleV11::Funder,
                ProductionSolanaLegRoleV25::Beneficiary => SolanaRoleV11::Beneficiary,
            },
            token_accounts: parameters.token_accounts.map(|accounts| TokenAccountsV11 {
                source: accounts.source,
                recipient: accounts.recipient,
                refund: accounts.refund,
            }),
            peer_socket: parameters.peer_socket,
            peer_timeout_ms: parameters.peer_timeout_ms,
        }),
    )
}

fn encode_wire_v22(
    identity: &ProductionLegBundleIdentityV22,
    authority: WireAuthorityV11,
) -> Result<ProductionLegBundleV22, Refusal> {
    let wire = WireV11 {
        format: FORMAT.to_owned(),
        settlement_id: identity.settlement_id,
        session_id: identity.session_id,
        chain_id: identity.chain_id,
        terms_hash: identity.terms_hash,
        authority,
    };
    let bytes = serde_json::to_vec(&wire).map_err(|_| Refusal::Conflict)?;
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(Refusal::Conflict);
    }
    let digest = ProductionUniversalLegV11::bundle_digest(&bytes).map_err(|_| Refusal::Conflict)?;
    Ok(ProductionLegBundleV22 { bytes, digest })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn identity() -> ProductionLegBundleIdentityV22 {
        ProductionLegBundleIdentityV22 {
            settlement_id: [11; 32],
            session_id: [12; 32],
            chain_id: [13; 32],
            terms_hash: [14; 32],
        }
    }

    fn evm_parameters() -> ProductionEvmLegBundleParametersV22 {
        ProductionEvmLegBundleParametersV22 {
            max_fee_per_gas: "30000000000".to_owned(),
            max_priority_fee_per_gas: "1500000000".to_owned(),
            observation_valid_for_ms: 45_000,
            remote_custody_lease_duration_ms: 600_000,
        }
    }

    fn solana_parameters() -> ProductionSolanaLegBundleParametersV25 {
        ProductionSolanaLegBundleParametersV25 {
            local_role: ProductionSolanaLegRoleV25::Funder,
            token_accounts: None,
            peer_socket: "sol-peer-0.sock".to_owned(),
            peer_timeout_ms: 30_000,
        }
    }

    /// The Solana bytes must re-serialize to themselves, carry the identity
    /// unchanged and spell the role exactly as the decoder's enum does.
    #[test]
    fn encoded_solana_bundle_satisfies_the_decoder_checks_that_stand_alone() {
        let identity = identity();
        let bundle = encode_solana_leg_authority_bundle_v25(&identity, solana_parameters())
            .expect("valid parameters");
        let wire: WireV11 = serde_json::from_slice(bundle.bytes()).expect("decodes");
        assert_eq!(serde_json::to_vec(&wire).expect("re-encodes"), bundle.bytes());
        assert_eq!(wire.format, FORMAT);
        assert_eq!(wire.settlement_id, identity.settlement_id);
        assert_eq!(wire.session_id, identity.session_id);
        assert_eq!(wire.chain_id, identity.chain_id);
        assert_eq!(wire.terms_hash, identity.terms_hash);
        assert_eq!(
            bundle.digest(),
            ProductionUniversalLegV11::bundle_digest(bundle.bytes()).expect("digest")
        );
        match wire.authority {
            WireAuthorityV11::Solana(value) => {
                assert!(matches!(value.local_role, SolanaRoleV11::Funder));
                assert!(value.token_accounts.is_none());
                assert_eq!(value.peer_socket, "sol-peer-0.sock");
                assert_eq!(value.peer_timeout_ms, 30_000);
            }
            _ => panic!("the Solana writer must produce the SOL authority"),
        }
        let text = std::str::from_utf8(bundle.bytes()).expect("utf8");
        assert!(text.ends_with(
            "\"authority\":{\"family\":\"SOL\",\"parameters\":{\"local_role\":\"funder\",\
             \"token_accounts\":null,\"peer_socket\":\"sol-peer-0.sock\",\"peer_timeout_ms\":30000}}}"
        ));
        let beneficiary = encode_solana_leg_authority_bundle_v25(
            &identity,
            ProductionSolanaLegBundleParametersV25 {
                local_role: ProductionSolanaLegRoleV25::Beneficiary,
                ..solana_parameters()
            },
        )
        .expect("encodes");
        assert_ne!(beneficiary.digest(), bundle.digest());
    }

    #[test]
    fn the_solana_writer_refuses_what_it_can_judge_without_the_admitted_inputs() {
        let refused = |parameters| {
            matches!(
                encode_solana_leg_authority_bundle_v25(&identity(), parameters),
                Err(Refusal::Conflict)
            )
        };
        for socket in ["", "/abs/sol.sock", "../sol.sock", "a//sol.sock", "a\\sol.sock"] {
            assert!(refused(ProductionSolanaLegBundleParametersV25 {
                peer_socket: socket.to_owned(),
                ..solana_parameters()
            }));
        }
        for timeout in [0, 60_001] {
            assert!(refused(ProductionSolanaLegBundleParametersV25 {
                peer_timeout_ms: timeout,
                ..solana_parameters()
            }));
        }
        assert!(refused(ProductionSolanaLegBundleParametersV25 {
            token_accounts: Some(ProductionSolanaLegTokenAccountsV25 {
                source: [1; 32],
                recipient: [0; 32],
                refund: [3; 32],
            }),
            ..solana_parameters()
        }));
        assert!(encode_solana_leg_authority_bundle_v25(
            &identity(),
            ProductionSolanaLegBundleParametersV25 {
                token_accounts: Some(ProductionSolanaLegTokenAccountsV25 {
                    source: [1; 32],
                    recipient: [2; 32],
                    refund: [3; 32],
                }),
                peer_timeout_ms: 60_000,
                ..solana_parameters()
            }
        )
        .is_ok());
    }

    /// The encoder's output must satisfy every decoder check that does not
    /// need the authenticated inputs: the format string, byte canonicality,
    /// the size bound, and the identity carried back unchanged.
    #[test]
    fn encoded_evm_bundle_satisfies_the_decoder_checks_that_stand_alone() {
        let identity = identity();
        let bundle = encode_evm_leg_authority_bundle_v22(&identity, evm_parameters())
            .expect("canonical parameters");
        let wire: WireV11 = serde_json::from_slice(bundle.bytes()).expect("decodes");
        assert_eq!(
            serde_json::to_vec(&wire).expect("re-encodes"),
            bundle.bytes(),
            "the decoder refuses any bundle that does not re-serialize to itself"
        );
        assert_eq!(wire.format, FORMAT);
        assert_eq!(wire.settlement_id, identity.settlement_id);
        assert_eq!(wire.session_id, identity.session_id);
        assert_eq!(wire.chain_id, identity.chain_id);
        assert_eq!(wire.terms_hash, identity.terms_hash);
        assert!(!bundle.bytes().is_empty() && bundle.bytes().len() <= MAX_BYTES);
        assert!(matches!(wire.authority, WireAuthorityV11::Evm(_)));
    }

    /// The manifest pins the digest of the exact bytes, so the value this
    /// writer reports and the value the loader recomputes must be the same
    /// function of the same bytes -- and any edit must break it.
    #[test]
    fn the_reported_digest_is_the_digest_the_loader_recomputes() {
        let bundle =
            encode_evm_leg_authority_bundle_v22(&identity(), evm_parameters()).expect("encodes");
        assert_eq!(
            bundle.digest(),
            ProductionUniversalLegV11::bundle_digest(bundle.bytes()).expect("digest")
        );
        let mut edited = bundle.bytes().to_vec();
        let last = edited.len() - 2;
        edited[last] ^= 0x01;
        assert_ne!(
            ProductionUniversalLegV11::bundle_digest(&edited).expect("digest"),
            bundle.digest()
        );
    }

    /// A bundle that encodes and is refused at startup with nothing but
    /// `Conflict` is the worst outcome for an operator, so the values the
    /// writer can judge on its own are judged here.
    #[test]
    fn the_writer_refuses_what_it_can_judge_without_the_admitted_inputs() {
        let refused = |parameters| {
            matches!(
                encode_evm_leg_authority_bundle_v22(&identity(), parameters),
                Err(Refusal::Conflict)
            )
        };
        assert!(refused(ProductionEvmLegBundleParametersV22 {
            max_fee_per_gas: "030000000000".to_owned(),
            ..evm_parameters()
        }));
        assert!(refused(ProductionEvmLegBundleParametersV22 {
            max_priority_fee_per_gas: "0x1".to_owned(),
            ..evm_parameters()
        }));
        assert!(refused(ProductionEvmLegBundleParametersV22 {
            observation_valid_for_ms: 0,
            ..evm_parameters()
        }));
        assert!(refused(ProductionEvmLegBundleParametersV22 {
            observation_valid_for_ms: 60_001,
            ..evm_parameters()
        }));
        assert!(refused(ProductionEvmLegBundleParametersV22 {
            remote_custody_lease_duration_ms: 3_600_001,
            ..evm_parameters()
        }));
        assert!(encode_evm_leg_authority_bundle_v22(
            &identity(),
            ProductionEvmLegBundleParametersV22 {
                observation_valid_for_ms: 60_000,
                remote_custody_lease_duration_ms: 3_600_000,
                ..evm_parameters()
            }
        )
        .is_ok());
    }

    /// Two positions that differ only in identity must not produce the same
    /// bytes, or a bundle copied across positions would pass its digest pin.
    #[test]
    fn each_position_gets_its_own_bytes_and_its_own_digest() {
        let upstream =
            encode_evm_leg_authority_bundle_v22(&identity(), evm_parameters()).expect("encodes");
        let downstream = encode_evm_leg_authority_bundle_v22(
            &ProductionLegBundleIdentityV22 {
                session_id: [22; 32],
                ..identity()
            },
            evm_parameters(),
        )
        .expect("encodes");
        assert_ne!(upstream.bytes(), downstream.bytes());
        assert_ne!(upstream.digest(), downstream.digest());
    }

    #[test]
    fn v11_selected_share_resource_resume_never_creates_missing_or_follows_symlinks() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            existing_resource(root.path(), "absent.sqlite", false),
            Err(Refusal::Unavailable)
        ));
        assert!(!root.path().join("absent.sqlite").exists());
        std::fs::write(root.path().join("existing.sqlite"), b"retained").unwrap();
        std::fs::set_permissions(
            root.path().join("existing.sqlite"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(existing_resource(root.path(), "existing.sqlite", false).is_ok());
        symlink(
            root.path().join("existing.sqlite"),
            root.path().join("alias.sqlite"),
        )
        .unwrap();
        assert!(matches!(
            existing_resource(root.path(), "alias.sqlite", false),
            Err(Refusal::Conflict)
        ));
        assert!(matches!(
            existing_resource(root.path(), "existing.sqlite", true),
            Err(Refusal::Conflict)
        ));
    }

    #[test]
    fn v11_selected_resource_refs_and_json_numbers_have_one_spelling() {
        for bad in ["", "./key", "a//b", "a/../b", "/tmp/key", "a/", "a\\b"] {
            assert!(relative_path(bad).is_err());
        }
        for bad in [
            "01",
            "+1",
            " 1",
            "1.0",
            "-1",
            "340282366920938463463374607431768211456",
        ] {
            assert!(canonical_u128(bad).is_err());
        }
        assert_eq!(
            canonical_u128("340282366920938463463374607431768211455"),
            Ok(u128::MAX)
        );
    }
}
#[cfg(test)]
mod retired_consensus_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn retired_xmr_consensus_configuration_is_rejected_not_ignored() {
        let baseline = json!({
            "compensation_policy": [],
            "local_participant_id": vec![1u8; 32],
            "setup_binding_hash": vec![2u8; 32],
            "refund_template_hash": vec![3u8; 32],
            "refund_point_sec1": vec![2u8; 33],
            "secret_store": "xmr.sqlite",
            "sidecar_socket": "sidecar.sock",
            "sidecar_timeout_ms": 1000
        });
        // Shape-only fixture, not authenticated production admission.
        assert!(
            serde_json::from_value::<ProductionUniversalXmrAuthorityV11>(baseline.clone()).is_ok()
        );
        for value in [json!({}), serde_json::Value::Null] {
            let mut retired = baseline.clone();
            retired["funding_intent_v22"] = value;
            assert!(serde_json::from_value::<ProductionUniversalXmrAuthorityV11>(retired).is_err());
        }
        let resources = json!({"directory": "recovery", "sealing_key_file": "recovery.key"});
        assert!(
            serde_json::from_value::<ProductionXmrRecoveryResourcesV22>(resources.clone()).is_ok()
        );
        for value in [json!("certificate.bin"), serde_json::Value::Null] {
            let mut retired = resources.clone();
            retired["certificate_file"] = value;
            assert!(serde_json::from_value::<ProductionXmrRecoveryResourcesV22>(retired).is_err());
        }
    }
}
