//! Pre-funding initialization of restart-safe local XMR secrets.

#![forbid(unsafe_code)]

mod enrollment_v23;
pub use enrollment_v23::{
    initialize_enrolled_session_for_role_v23, prepare_xmr_share_enrollment_v23,
    resume_enrolled_session_for_role_v23, PreparedXmrShareEnrollmentV23,
};

use rand::{CryptoRng, RngCore};
use xmr_crypto::{combine_public_shares, XmrPrivateViewKey, XmrSpendShare};
use xmr_dleq_nullifier_store::{DleqNullifierStore, NullifierError, RegistrationOutcome};
use xmr_dleq_sigma::{
    verify_bound, BoundCrossCurveProofV1, CrossCurveSecret252, ROLE_XMR_REFUND_SHARE,
};
use xmr_refund_policy::{RefundPolicyError, ValidatedRefundPolicy, XmrRefundModeV1};
use xmr_secret_store::{SecretMaterialStore, SecretStoreError, XmrSecretMaterial};
use xmr_setup_profile::ValidatedXmrSetup;
use zeroize::Zeroizing;

/// Session-initialization failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionInitError {
    /// Native graph or private refund differs from the authenticated setup.
    #[error("invalid native DOM/XMR recovery graph")]
    InvalidRecoveryGraph,
    /// The refund-share proof does not authenticate this setup and role.
    #[error("invalid XMR refund-share proof")]
    InvalidRefundProof,
    /// Local scalar/public-key material is invalid.
    #[error("invalid local XMR key material")]
    InvalidKeyMaterial,
    /// Local + DLEQ-certified remote share differs from frozen setup.
    #[error("combined XMR spend public key mismatch")]
    CombinedPublicKeyMismatch,
    /// Encrypted secret storage failed.
    #[error("XMR secret storage failed: {0}")]
    Store(#[from] SecretStoreError),
    /// One-shot DLEQ registration failed.
    #[error("DLEQ nullifier registration failed: {0}")]
    Nullifier(#[from] NullifierError),
    /// The refund path was not admitted before funding.
    #[error("XMR refund policy failed: {0}")]
    Refund(#[from] RefundPolicyError),
}

/// Builds validated local material without mutation. Public entry points
/// authenticate policy and register the claim separately before insertion.
fn prepare_claim_receiver_material(
    setup: &ValidatedXmrSetup,
    local_spend_share_le: [u8; 32],
    private_view_key_le: [u8; 32],
) -> Result<XmrSecretMaterial, SessionInitError> {
    let local_share = XmrSpendShare::from_canonical_bytes(local_spend_share_le)
        .map_err(|_| SessionInitError::InvalidKeyMaterial)?;
    let view_key = XmrPrivateViewKey::from_canonical_bytes(private_view_key_le)
        .map_err(|_| SessionInitError::InvalidKeyMaterial)?;
    let local_public = local_share
        .public_share()
        .map_err(|_| SessionInitError::InvalidKeyMaterial)?;
    let combined = combine_public_shares(local_public, setup.claim().ed_compressed)
        .map_err(|_| SessionInitError::InvalidKeyMaterial)?;
    if combined != setup.combined_spend_public_key() {
        return Err(SessionInitError::CombinedPublicKeyMismatch);
    }
    let material = local_share
        .expose(|local| view_key.expose(|view| XmrSecretMaterial::new(*local, *view)))
        .map_err(SessionInitError::Store)?;
    Ok(material)
}

/// Outcome of guarded, restart-safe pre-funding initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardedSessionInitialization {
    /// Whether the DLEQ claim was newly inserted or replayed identically.
    pub nullifier: RegistrationOutcome,
}

/// Preferred pre-funding entry point.
///
/// It refuses to store usable local XMR secrets until the refund policy is
/// validated and the DLEQ public claim is durably registered one-shot.
pub fn initialize_session_guarded<S: SecretMaterialStore>(
    setup: &ValidatedXmrSetup,
    store: &S,
    nullifiers: &DleqNullifierStore,
    refund_policy: &ValidatedRefundPolicy,
    local_spend_share_le: [u8; 32],
    private_view_key_le: [u8; 32],
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<GuardedSessionInitialization, SessionInitError> {
    refund_policy.require_scope(&setup.settlement_id(), &setup.terms_hash())?;
    let material =
        prepare_claim_receiver_material(setup, local_spend_share_le, private_view_key_le)?;
    if refund_policy.mode() == XmrRefundModeV1::AdaptorRefundRequired {
        // This legacy entry point initializes the claim receiver's U only.
        // Matching T + U to the deposit is insufficient if the admitted DOM
        // refund uses a different U. Prove the local scalar's other public
        // representation before registering or retaining it.
        let refund = CrossCurveSecret252::from_little_endian(local_spend_share_le)
            .map_err(|_| SessionInitError::InvalidKeyMaterial)?;
        let claim = refund
            .public_claim()
            .map_err(|_| SessionInitError::InvalidKeyMaterial)?;
        refund_policy.require_refund_point(&claim.secp_compressed)?;
    }
    let nullifier =
        nullifiers.register(setup.settlement_id(), setup.binding_hash(), &setup.claim())?;
    store.insert(setup.settlement_id(), setup.terms_hash(), &material, rng)?;
    Ok(GuardedSessionInitialization { nullifier })
}

/// Which ONE share belongs in this participant's encrypted store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XmrLocalShareRoleV11 {
    /// DOM funder / XMR beneficiary owns U and waits for a DOM claim exposing T.
    ClaimReceiver,
    /// XMR funder owns T and waits for a DOM refund exposing U.
    RefundReceiver,
}

/// One participant's private material. No formatter or serializer is provided.
pub struct XmrLocalSessionSecretsV11 {
    /// Participant's economic role, verified against the corresponding proof.
    pub role: XmrLocalShareRoleV11,
    /// A single canonical local spend share, never the combined spend key.
    pub spend_share: Zeroizing<[u8; 32]>,
    /// Canonical private view key for scanning the shared deposit.
    pub view_key: Zeroizing<[u8; 32]>,
}

/// Initialize either economic role with verified T/U separation and exact
/// policy/setup bindings. Validates all public and private inputs before any
/// mutation. Registration and insertion are independently durable/idempotent:
/// after a crash between them, replay with the same material completes custody.
/// This prepares local custody; it does not grant funding or prove that a
/// counterparty will publish a revealing refund.
pub fn initialize_session_for_role_v11<S: SecretMaterialStore>(
    setup: &ValidatedXmrSetup,
    store: &S,
    nullifiers: &DleqNullifierStore,
    refund_policy: &ValidatedRefundPolicy,
    refund_proof: &BoundCrossCurveProofV1,
    local: XmrLocalSessionSecretsV11,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<GuardedSessionInitialization, SessionInitError> {
    let expected = expected_local_share(setup, refund_policy, refund_proof, local.role)?;
    let material = XmrSecretMaterial::new(*local.spend_share, *local.view_key)?;
    require_local_material(&material, expected)?;
    let nullifier =
        nullifiers.register(setup.settlement_id(), setup.binding_hash(), &setup.claim())?;
    store.insert(setup.settlement_id(), setup.terms_hash(), &material, rng)?;
    Ok(GuardedSessionInitialization { nullifier })
}

/// Resume only: authenticates retained custody without accepting fresh secrets,
/// generating keys, registering a missing claim, or inserting a secret row.
/// A caller resuming after funding must use this path, not initialization replay.
/// Initialization replay remains available only for a pre-funding crash cut.
pub fn resume_session_for_role_v11<S: SecretMaterialStore>(
    setup: &ValidatedXmrSetup,
    store: &S,
    nullifiers: &DleqNullifierStore,
    refund_policy: &ValidatedRefundPolicy,
    refund_proof: &BoundCrossCurveProofV1,
    role: XmrLocalShareRoleV11,
) -> Result<(), SessionInitError> {
    let expected = expected_local_share(setup, refund_policy, refund_proof, role)?;
    nullifiers.require_registered(setup.settlement_id(), setup.binding_hash(), &setup.claim())?;
    let material = store.load(&setup.settlement_id(), &setup.terms_hash())?;
    require_local_material(&material, expected)
}

/// Complete the cooperative DOM refund exclusively from the U owner's
/// existing encrypted share. This creates a private transaction for custody;
/// it never emits a scalar, sends FinalRefund 0x10 or grants broadcast rights.
/// A missing row/nullifier is an error, never a request to regenerate secrets.
pub fn complete_private_dom_refund_v12<S: SecretMaterialStore>(
    setup: &ValidatedXmrSetup,
    store: &S,
    nullifiers: &DleqNullifierStore,
    refund_policy: &ValidatedRefundPolicy,
    refund_proof: &BoundCrossCurveProofV1,
    graph: &dom_scriptless_crypto::VerifiedXmrRecoveryGraphV11,
) -> Result<dom_scriptless_crypto::PrivateXmrRefundTransactionV11, SessionInitError> {
    let expected = expected_local_share(
        setup,
        refund_policy,
        refund_proof,
        XmrLocalShareRoleV11::ClaimReceiver,
    )?;
    let binding = graph.binding();
    if binding.terms_hash != setup.terms_hash()
        || binding.claim_adaptor_point != setup.claim().secp_compressed
    {
        return Err(SessionInitError::InvalidRecoveryGraph);
    }
    refund_policy.require_refund_point(&binding.refund_adaptor_point)?;
    nullifiers.require_registered(setup.settlement_id(), setup.binding_hash(), &setup.claim())?;
    let material = store.load(&setup.settlement_id(), &setup.terms_hash())?;
    require_local_material(&material, expected)?;
    material.expose(|spend, _view| {
        let local = CrossCurveSecret252::from_little_endian(*spend)
            .map_err(|_| SessionInitError::InvalidKeyMaterial)?;
        let public = local
            .public_claim()
            .map_err(|_| SessionInitError::InvalidKeyMaterial)?;
        if public.secp_compressed != binding.refund_adaptor_point
            || public.ed_compressed != expected
        {
            return Err(SessionInitError::InvalidRecoveryGraph);
        }
        let bytes = Zeroizing::new(local.dom_secret_big_endian());
        let witness = dom_adaptor::AdaptorSecret::from_be_bytes(*bytes)
            .map_err(|_| SessionInitError::InvalidKeyMaterial)?;
        graph
            .complete_private_refund(&witness)
            .map_err(|_| SessionInitError::InvalidRecoveryGraph)
    })
}

fn expected_local_share(
    setup: &ValidatedXmrSetup,
    refund_policy: &ValidatedRefundPolicy,
    refund_proof: &BoundCrossCurveProofV1,
    role: XmrLocalShareRoleV11,
) -> Result<[u8; 32], SessionInitError> {
    refund_policy.require_scope(&setup.settlement_id(), &setup.terms_hash())?;
    let refund = verify_bound(
        refund_proof,
        &setup.settlement_id(),
        setup.proof_context_hash(),
        ROLE_XMR_REFUND_SHARE,
    )
    .map_err(|_| SessionInitError::InvalidRefundProof)?;
    refund_policy.require_refund_point(&refund.secp_compressed)?;
    if refund.ed_compressed == setup.claim().ed_compressed
        || refund.secp_compressed == setup.claim().secp_compressed
        || combine_public_shares(setup.claim().ed_compressed, refund.ed_compressed)
            .map_err(|_| SessionInitError::InvalidKeyMaterial)?
            != setup.combined_spend_public_key()
    {
        return Err(SessionInitError::CombinedPublicKeyMismatch);
    }
    Ok(match role {
        XmrLocalShareRoleV11::ClaimReceiver => refund.ed_compressed,
        XmrLocalShareRoleV11::RefundReceiver => setup.claim().ed_compressed,
    })
}

fn require_local_material(
    material: &XmrSecretMaterial,
    expected: [u8; 32],
) -> Result<(), SessionInitError> {
    material.expose(|spend, view| {
        let share = XmrSpendShare::from_canonical_bytes(*spend)
            .map_err(|_| SessionInitError::InvalidKeyMaterial)?;
        let _view = XmrPrivateViewKey::from_canonical_bytes(*view)
            .map_err(|_| SessionInitError::InvalidKeyMaterial)?;
        if share
            .public_share()
            .map_err(|_| SessionInitError::InvalidKeyMaterial)?
            != expected
        {
            return Err(SessionInitError::InvalidKeyMaterial);
        }
        Ok(())
    })
}
