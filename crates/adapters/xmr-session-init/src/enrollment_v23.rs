//! Non-economic enrollment before the DOM refund template exists.
//!
//! This module deliberately cannot issue a refund-policy token. Its output is
//! accepted only by the local share initialization/readback functions below;
//! execution still requires the separate authenticated graph/custody/F7 path.
use super::*;

/// Authenticated public T/U enrollment, with no refund template or economic
/// authorization. Not serializable, clonable, or convertible into a validated
/// refund policy, funding grant, sweep capability, or secret-bearing handle.
pub struct PreparedXmrShareEnrollmentV23 {
    setup: ValidatedXmrSetup,
    refund: xmr_dleq_sigma::CrossCurvePublicClaim,
}

impl PreparedXmrShareEnrollmentV23 {
    /// Public setup whose claim proof and economic bindings were validated.
    /// A setup identifies a planned deposit; it does not prove its payment.
    pub fn setup(&self) -> &ValidatedXmrSetup {
        &self.setup
    }

    /// Verify public scope again without reading, exporting, or modifying
    /// custody. A later template-binding layer must additionally authenticate
    /// its native graph and bilateral commitment; this check cannot replace it.
    pub fn require_setup(
        &self,
        setup: &ValidatedXmrSetup,
        refund_proof: &BoundCrossCurveProofV1,
    ) -> Result<(), SessionInitError> {
        let checked = prepare_xmr_share_enrollment_v23(setup, refund_proof)?;
        if checked.setup.binding_hash() != self.setup.binding_hash()
            || checked.setup.settlement_id() != self.setup.settlement_id()
            || checked.setup.terms_hash() != self.setup.terms_hash()
            || checked.refund != self.refund
        {
            return Err(SessionInitError::InvalidRefundProof);
        }
        Ok(())
    }

    fn local_public_share(&self, role: XmrLocalShareRoleV11) -> [u8; 32] {
        match role {
            XmrLocalShareRoleV11::ClaimReceiver => self.refund.ed_compressed,
            XmrLocalShareRoleV11::RefundReceiver => self.setup.claim().ed_compressed,
        }
    }
}

/// Authenticate enrollment from an already validated setup and the real
/// role-2 proof. No DOM refund-template hash is accepted or invented here.
/// All public checks precede any database operation. This does not assert that
/// a refund is executable, authorize funding, or authorize secret revelation.
pub fn prepare_xmr_share_enrollment_v23(
    setup: &ValidatedXmrSetup,
    refund_proof: &BoundCrossCurveProofV1,
) -> Result<PreparedXmrShareEnrollmentV23, SessionInitError> {
    let refund = verify_bound(
        refund_proof,
        &setup.settlement_id(),
        setup.proof_context_hash(),
        ROLE_XMR_REFUND_SHARE,
    )
    .map_err(|_| SessionInitError::InvalidRefundProof)?;
    if refund.ed_compressed == setup.claim().ed_compressed
        || refund.secp_compressed == setup.claim().secp_compressed
        || combine_public_shares(setup.claim().ed_compressed, refund.ed_compressed)
            .map_err(|_| SessionInitError::InvalidKeyMaterial)?
            != setup.combined_spend_public_key()
    {
        return Err(SessionInitError::CombinedPublicKeyMismatch);
    }
    Ok(PreparedXmrShareEnrollmentV23 {
        setup: setup.clone(),
        refund,
    })
}

/// Retain ONE local share under authenticated enrollment, before template
/// binding. Uses the existing encrypted row and durable nullifier registration
/// formats; a complete identical enrollment replays without rewriting either.
/// A partial row/registration pair fails closed rather than recreating custody.
/// This function never opens a database, returns a secret, or issues a policy.
/// A daemon reopening an established session must use the read-only resume
/// function instead; callers remain responsible for their creation journal.
pub fn initialize_enrolled_session_for_role_v23<S: SecretMaterialStore>(
    enrollment: &PreparedXmrShareEnrollmentV23,
    store: &S,
    nullifiers: &DleqNullifierStore,
    local: XmrLocalSessionSecretsV11,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<GuardedSessionInitialization, SessionInitError> {
    let material = XmrSecretMaterial::new(*local.spend_share, *local.view_key)?;
    require_local_material(&material, enrollment.local_public_share(local.role))?;
    let setup = &enrollment.setup;
    let registered =
        nullifiers.require_registered(setup.settlement_id(), setup.binding_hash(), &setup.claim());
    match store.load(&setup.settlement_id(), &setup.terms_hash()) {
        Ok(existing) => {
            registered?;
            require_local_material(&existing, enrollment.local_public_share(local.role))?;
            if !existing.expose(|spend, view| {
                material.expose(|expected_spend, expected_view| {
                    spend == expected_spend && view == expected_view
                })
            }) {
                return Err(SessionInitError::Store(SecretStoreError::Conflict));
            }
            // A replay must not even generate a new encryption nonce.
            Ok(GuardedSessionInitialization {
                nullifier: RegistrationOutcome::Idempotent,
            })
        }
        Err(SecretStoreError::NotFound) => {
            match registered {
                Err(NullifierError::NotFound) => {}
                Err(error) => return Err(error.into()),
                Ok(()) => return Err(SessionInitError::Store(SecretStoreError::NotFound)),
            }
            let nullifier =
                nullifiers.register(setup.settlement_id(), setup.binding_hash(), &setup.claim())?;
            if nullifier != RegistrationOutcome::Inserted {
                // Another initializer (or a partial prior attempt) owns this
                // registration. This call cannot recreate its missing row.
                return Err(SessionInitError::Store(SecretStoreError::Conflict));
            }
            store.insert(setup.settlement_id(), setup.terms_hash(), &material, rng)?;
            Ok(GuardedSessionInitialization { nullifier })
        }
        Err(error) => Err(error.into()),
    }
}

/// Authenticate existing enrollment custody only. Missing/corrupt rows or
/// missing/conflicting registrations are errors: never create, register,
/// replace a database, renew an execution grant, or export secret material.
pub fn resume_enrolled_session_for_role_v23<S: SecretMaterialStore>(
    enrollment: &PreparedXmrShareEnrollmentV23,
    store: &S,
    nullifiers: &DleqNullifierStore,
    role: XmrLocalShareRoleV11,
) -> Result<(), SessionInitError> {
    let setup = &enrollment.setup;
    nullifiers.require_registered(setup.settlement_id(), setup.binding_hash(), &setup.claim())?;
    let material = store.load(&setup.settlement_id(), &setup.terms_hash())?;
    require_local_material(&material, enrollment.local_public_share(role))
}
