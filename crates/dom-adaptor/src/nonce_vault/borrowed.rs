//! Exclusive borrowed access to a retained native nonce vault.
//!
//! Every operation delegates to the original owner, retaining its exact opaque
//! associated types and its persistence, witness and purpose checks. No permit
//! is created or decoded at this boundary.

use super::*;

impl<Vault: NonceVaultV1> NonceVaultV1 for &mut Vault {
    type Error = Vault::Error;
    type ReservationHandle = Vault::ReservationHandle;
    type ReservationSnapshot = Vault::ReservationSnapshot;
    type DerivationAttemptPermit = Vault::DerivationAttemptPermit;
    type InitialSecretOpenPermit = Vault::InitialSecretOpenPermit;
    type StageComputationPermit = Vault::StageComputationPermit;
    type ArtifactPersistencePermit = Vault::ArtifactPersistencePermit;
    type PersistedExposureHandle = Vault::PersistedExposureHandle;
    type ExposurePermit = Vault::ExposurePermit;
    type ExportedArtifact = Vault::ExportedArtifact;
    type RecoveredSpentArtifact = Vault::RecoveredSpentArtifact;

    fn claim_fresh_reservation(
        &mut self,
        request: crate::FreshReservationRequestV1,
    ) -> core::result::Result<Self::ReservationHandle, Self::Error> {
        (**self).claim_fresh_reservation(request)
    }

    fn resume_claimed_reservation(
        &mut self,
        request: crate::ReservationResumeRequestV1,
    ) -> core::result::Result<ReservationResumeResultV1<Self::ReservationHandle>, Self::Error> {
        (**self).resume_claimed_reservation(request)
    }

    fn snapshot_reservation(
        &mut self,
        reservation: &Self::ReservationHandle,
    ) -> core::result::Result<Self::ReservationSnapshot, Self::Error> {
        (**self).snapshot_reservation(reservation)
    }

    fn begin_nonce_derivation(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        request: crate::NonceDerivationRequestV1,
    ) -> core::result::Result<Self::DerivationAttemptPermit, Self::Error> {
        (**self).begin_nonce_derivation(reservation, request)
    }

    fn seal_derived_secret(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        attempt: Self::DerivationAttemptPermit,
        secret: crate::NonceSecretTransferV1,
        seal_capability: crate::VaultSecretSealCapabilityV1,
    ) -> core::result::Result<Self::InitialSecretOpenPermit, Self::Error> {
        (**self).seal_derived_secret(reservation, attempt, secret, seal_capability)
    }

    fn open_sealed_secret_for_commitment(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        permit: Self::InitialSecretOpenPermit,
        import_capability: crate::VaultSecretImportCapabilityV1,
    ) -> core::result::Result<
        (
            crate::NonceSecretTransferV1,
            Self::ArtifactPersistencePermit,
        ),
        Self::Error,
    > {
        (**self).open_sealed_secret_for_commitment(reservation, permit, import_capability)
    }

    fn begin_stage_computation(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        request: crate::StageComputationRequestV1,
    ) -> core::result::Result<Self::StageComputationPermit, Self::Error> {
        (**self).begin_stage_computation(reservation, request)
    }

    fn open_secret_for_stage(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        permit: Self::StageComputationPermit,
        import_capability: crate::VaultSecretImportCapabilityV1,
    ) -> core::result::Result<
        (
            crate::NonceSecretTransferV1,
            Self::ArtifactPersistencePermit,
        ),
        Self::Error,
    > {
        (**self).open_secret_for_stage(reservation, permit, import_capability)
    }

    fn persist_computed_artifact(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        permit: Self::ArtifactPersistencePermit,
        artifact: PreparedExposureV1,
    ) -> core::result::Result<Self::PersistedExposureHandle, Self::Error> {
        (**self).persist_computed_artifact(reservation, permit, artifact)
    }

    fn authorize_persisted_exposure(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        persisted: Self::PersistedExposureHandle,
    ) -> core::result::Result<Self::ExposurePermit, Self::Error> {
        (**self).authorize_persisted_exposure(reservation, persisted)
    }

    fn export(
        &mut self,
        permit: Self::ExposurePermit,
    ) -> core::result::Result<Self::ExportedArtifact, Self::Error> {
        (**self).export(permit)
    }

    fn recover_spent_artifact(
        &mut self,
        authorization: &crate::ValidatedResendAuthorizationV1,
    ) -> core::result::Result<Self::RecoveredSpentArtifact, Self::Error> {
        (**self).recover_spent_artifact(authorization)
    }

    fn resend_exported(
        &mut self,
        request: ResendRequestV1,
    ) -> core::result::Result<Self::ExportedArtifact, Self::Error> {
        (**self).resend_exported(request)
    }

    fn cancel_reservation(
        &mut self,
        reservation: Self::ReservationHandle,
    ) -> core::result::Result<TerminalReservationV1, Self::Error> {
        (**self).cancel_reservation(reservation)
    }

    fn restore_state(&self) -> RestoreState {
        (**self).restore_state()
    }
}

impl<Vault: RestartArtifactRecoveryVaultV1> RestartArtifactRecoveryVaultV1 for &mut Vault {
    fn recover_spent_artifact_for_restart(
        &mut self,
        request: &RestartArtifactRecoveryRequestV1,
    ) -> core::result::Result<Self::RecoveredSpentArtifact, Self::Error> {
        (**self).recover_spent_artifact_for_restart(request)
    }
}
