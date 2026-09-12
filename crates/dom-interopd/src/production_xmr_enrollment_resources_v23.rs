//! Single opening of enrolled private resources, before any executable sweep.
use super::*;

pub(crate) struct ProductionOpenedXmrEnrollmentV23 {
    pub(crate) enrolled: crate::production_xmr_sweep::ProductionXmrEnrolledResourcesV23,
    pub(crate) archive: crate::production_contracts::ProductionXmrGraphCustodyResourcesV23,
    pub(crate) private_funding: Option<ProductionXmrEnrolledFundingV23>,
}

/// The already-admitted candidate location, not a funding permission. Applied
/// only to a real activated sweep, whose existing attachment code rechecks the
/// exact setup transaction/amount and bounded fee before retaining its bytes.
pub(crate) struct ProductionXmrEnrolledFundingV23 {
    state_dir: PathBuf,
    candidate: ProductionXmrPrivateFundingConfigV12,
}

impl ProductionXmrEnrolledFundingV23 {
    pub(crate) fn attach(
        self,
        sweep: ProductionXmrSweepAuthorityV10,
    ) -> Result<ProductionXmrSweepAuthorityV10, Refusal> {
        sweep.attach_private_funding_v12(
            &self.state_dir,
            &self.candidate.raw_transaction_file,
            self.candidate.max_fee_piconero,
        )
    }
}

impl ProductionUniversalXmrEnrollmentAuthorityV23 {
    pub(crate) fn local_participant_id(&self) -> [u8; 32] {
        self.local_participant_id
    }

    pub(crate) fn compensation_policy(
        &self,
    ) -> Result<&ValidatedXmrCompensationPolicyV11, Refusal> {
        self.validated_compensation
            .as_ref()
            .ok_or(Refusal::Conflict)
    }

    /// Consumes the admitted owner. Opens existing private DBs once and moves
    /// them into enrollment custody; no template, policy grant or sweep is
    /// synthesized. The archive parent/key are separate, with no second
    /// nullifier database opening hidden in a legacy recovery helper.
    pub(crate) fn open_enrolled_resources_v23(
        self,
        inputs: &AuthenticatedProductionInputsV1,
        leg: LegIdV1,
        state_dir: &Path,
        local_key: Zeroizing<[u8; 32]>,
        sidecar_auth: Zeroizing<[u8; 32]>,
    ) -> Result<ProductionOpenedXmrEnrollmentV23, Refusal> {
        self.scope
            .as_ref()
            .ok_or(Refusal::Conflict)?
            .require(inputs, leg)?;
        let session = inputs.monero_session(leg).ok_or(Refusal::Conflict)?;
        let terms = match leg {
            LegIdV1::Upstream => inputs.composition().upstream(),
            LegIdV1::Downstream => inputs.composition().downstream(),
        };
        let policy = self.validate_public_inputs_v23(session, terms)?;
        if self.validated_compensation.as_ref() != Some(&policy)
            || *local_key == [0; 32]
            || *sidecar_auth == [0; 32]
            || *local_key == *sidecar_auth
        {
            return Err(Refusal::Conflict);
        }
        let (parent, directory_name, key) =
            ProductionUniversalXmrAuthorityV11::open_recovery_resources_v23(
                state_dir,
                &self.recovery_v23.directory,
                &self.recovery_v23.sealing_key_file,
                &local_key,
                &sidecar_auth,
            )?;
        let secret_path = existing_resource(state_dir, &self.secret_store, false)?;
        let nullifier_path =
            existing_resource(state_dir, &self.recovery_v23.nullifier_store, false)?;
        let sidecar_path = existing_resource(state_dir, &self.sidecar_socket, true)?;
        let secret_before = private_file_identity(&secret_path)?;
        let nullifier_before = private_file_identity(&nullifier_path)?;
        if (secret_before.dev(), secret_before.ino())
            == (nullifier_before.dev(), nullifier_before.ino())
        {
            return Err(Refusal::Conflict);
        }
        let secrets = EncryptedSqliteSecretStore::open_existing(
            &secret_path,
            SecretStoreMasterKey::new(*local_key).map_err(|_| Refusal::Conflict)?,
        )
        .map_err(|error| match error {
            xmr_secret_store::SecretStoreError::Unavailable => Refusal::Unavailable,
            _ => Refusal::Conflict,
        })?;
        let nullifiers =
            xmr_dleq_nullifier_store::DleqNullifierStore::open_existing(&nullifier_path)
                .map_err(|_| Refusal::Conflict)?;
        require_same_private_file(&secret_path, &secret_before)?;
        require_same_private_file(&nullifier_path, &nullifier_before)?;
        let sidecar = BlockingUdsSidecarPort::with_timeout(
            sidecar_path,
            SidecarAuthKey::new(*sidecar_auth).map_err(|_| Refusal::Conflict)?,
            require_milliseconds(self.sidecar_timeout_ms, 180_000)?,
        )
        .map_err(|_| Refusal::Conflict)?;
        let enrolled =
            crate::production_xmr_sweep::ProductionXmrEnrolledResourcesV23::authenticate(
                inputs,
                leg,
                self.local_participant_id,
                secrets,
                nullifiers,
                sidecar,
            )?;
        Ok(ProductionOpenedXmrEnrollmentV23 {
            enrolled,
            archive: crate::production_contracts::ProductionXmrGraphCustodyResourcesV23 {
                parent,
                directory_name,
                custody_id: self.recovery_v23.custody_id,
                key,
            },
            private_funding: self.private_funding_v12.map(|candidate| {
                ProductionXmrEnrolledFundingV23 {
                    state_dir: state_dir.to_owned(),
                    candidate,
                }
            }),
        })
    }
}

fn private_file_identity(path: &Path) -> Result<std::fs::Metadata, Refusal> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| Refusal::Unavailable)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(Refusal::Conflict);
    }
    Ok(metadata)
}

fn require_same_private_file(path: &Path, before: &std::fs::Metadata) -> Result<(), Refusal> {
    let after = private_file_identity(path)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
        || before.mode() != after.mode()
    {
        return Err(Refusal::Conflict);
    }
    Ok(())
}
