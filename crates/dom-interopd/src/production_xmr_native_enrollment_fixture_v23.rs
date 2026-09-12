//! Pre-C/D custody only. This owner has no refund policy or template pin and
//! cannot be passed to the executable-custody/funding fixture continuations.
use super::*;

pub(crate) struct NativeXmrEnrollmentPlanV23 {
    pub funding_tx_hash: [u8; 32],
    pub funding_destination: String,
}

pub(crate) struct NativeXmrEnrolledFixtureV23 {
    enrollment: xmr_session_init::PreparedXmrShareEnrollmentV23,
    profile: XmrAdapterProfileV1,
    public_binding: XmrSetupBindingV1,
    refund_proof: BoundCrossCurveProofV1,
    payout: NativeClaimPayoutV23,
    actors: [NativeXmrActorCustodyV23; 2],
}

impl NativeXmrEnrolledFixtureV23 {
    /// Public profile only; no private share or store handle escapes.
    pub(crate) fn profile(&self) -> &XmrAdapterProfileV1 {
        &self.profile
    }
    pub(crate) fn setup(&self) -> &ValidatedXmrSetup {
        self.enrollment.setup()
    }

    /// Insert one route-bound auxiliary wallet into the solver actor's
    /// existing encrypted Store, then reopen that exact Store with its retained
    /// external master credential. Absence/corruption cannot create a new DB.
    pub(crate) fn persist_inventory_material_v23(
        &self,
        actor: usize,
        path: &Path,
        record_id: [u8; 32],
        binding: [u8; 32],
        material: &xmr_secret_store::XmrSecretMaterial,
    ) -> Result<EncryptedSqliteSecretStore> {
        use xmr_secret_store::SecretMaterialStore;
        if record_id == [0; 32] || binding == [0; 32] {
            return Err("solver inventory custody identifiers are zero".into());
        }
        let owner = self
            .actors
            .get(actor)
            .ok_or("solver inventory custody actor")?;
        let expected = path
            .parent()
            .ok_or("solver inventory custody parent")?
            .join("native-xmr-secrets-v23.sqlite");
        if expected != path {
            return Err("solver inventory custody path mismatch".into());
        }
        owner
            .secrets
            .insert(record_id, binding, material, &mut rand::thread_rng())?;
        let reopened = EncryptedSqliteSecretStore::open_existing(
            path,
            SecretStoreMasterKey::new(*owner.master_key_v23)?,
        )?;
        // Authentication of this exact row is part of publication, not deferred
        // until F6. The returned handle never exposes the master credential.
        reopened.load(&record_id, &binding)?;
        Ok(reopened)
    }

    /// Export only public enrollment metadata for the real participant
    /// admission. No synthetic refund template, executable policy, or grant.
    pub(crate) fn participant_setup_v23(
        &self,
        position: crate::production_inputs::ProductionRoutePositionV1,
        terms: &SettlementTermsV1,
    ) -> Result<crate::production_inputs::ProductionXmrLegSetupV1> {
        let setup = xmr_setup_profile::validate_setup(
            terms,
            &self.profile,
            self.public_binding.clone(),
            None,
        )?;
        self.enrollment.require_setup(&setup, &self.refund_proof)?;
        let public = xmr_dleq_sigma::verify_bound(
            &self.refund_proof,
            &setup.settlement_id(),
            setup.proof_context_hash(),
            xmr_dleq_sigma::ROLE_XMR_REFUND_SHARE,
        )?;
        let deadline = match terms.counterparty_leg.deadline {
            TimelockSpec::BlockHeight { value } => value,
            _ => return Err("native enrollment requires an XMR block-height deadline".into()),
        };
        let bundle = crate::production_inputs::ProductionXmrEnrollmentBundleV23::new(
            self.refund_proof.clone(),
            public.secp_compressed,
            DomRefundAdaptorExecutor::new(public).profile_hash(),
            deadline,
            self.payout.refund_address().to_owned(),
        )?;
        Ok(crate::production_inputs::ProductionXmrLegSetupV1::new(
            position,
            self.profile.clone(),
            self.public_binding.clone(),
        )?
        .with_native_enrollment_v23(bundle)?)
    }

    /// Close every original handle before reopening the same physical stores.
    /// No initialize fallback or missing-row reconstruction on this path.
    pub(crate) fn reopen(self, roots: [&Path; 2]) -> Result<Self> {
        let Self {
            enrollment,
            profile,
            public_binding,
            refund_proof,
            payout,
            actors,
        } = self;
        let retained = actors.map(|actor| {
            let NativeXmrActorCustodyV23 {
                secrets,
                nullifiers,
                role,
                master_key_v23,
            } = actor;
            drop(secrets);
            drop(nullifiers);
            (role, master_key_v23)
        });
        let mut opened = Vec::with_capacity(2);
        for (index, (role, master_key_v23)) in retained.into_iter().enumerate() {
            let secrets = EncryptedSqliteSecretStore::open_existing(
                &roots[index].join("native-xmr-secrets-v23.sqlite"),
                SecretStoreMasterKey::new(*master_key_v23)?,
            )?;
            let nullifiers = DleqNullifierStore::open_existing(
                &roots[index].join("native-xmr-nullifiers-v23.sqlite"),
            )?;
            xmr_session_init::resume_enrolled_session_for_role_v23(
                &enrollment,
                &secrets,
                &nullifiers,
                role,
            )?;
            opened.push(NativeXmrActorCustodyV23 {
                secrets,
                nullifiers,
                role,
                master_key_v23,
            });
        }
        Ok(Self {
            enrollment,
            profile,
            public_binding,
            refund_proof,
            payout,
            actors: opened
                .try_into()
                .map_err(|_| "two enrollment actors required")?,
        })
    }
}

impl NativeXmrRouteSecretsV23 {
    /// First creation before C/D: four disjoint empty private roots, one route
    /// T and independent U/database/payout owners. No DOM template is needed.
    pub(crate) fn enroll(
        self,
        terms: [&SettlementTermsV1; 2],
        planned: [NativeXmrEnrollmentPlanV23; 2],
        actors: [[[u8; 32]; 2]; 2],
        roots: [[&Path; 2]; 2],
    ) -> Result<[NativeXmrEnrolledFixtureV23; 2]> {
        if terms[0].session_id == terms[1].session_id
            || terms[0].settlement_id == terms[1].settlement_id
            || planned[0].funding_tx_hash == planned[1].funding_tx_hash
        {
            return Err("native enrollment route scope collision".into());
        }
        for (index, terms) in terms.iter().enumerate() {
            terms.validate()?;
            if terms.adaptor_point_sec1 != self.claim.public_claim()?.secp_compressed
                || terms.counterparty_leg.adapter_profile_hash != self.profile.profile_hash()
                || planned[index].funding_tx_hash == [0; 32]
                || planned[index].funding_destination.is_empty()
                || actors[index][0] == actors[index][1]
                || actors[index].iter().any(|actor| {
                    ![
                        terms.dom_leg.refund_to.0,
                        terms.counterparty_leg.refund_to.0,
                    ]
                    .contains(actor)
                })
            {
                return Err("native enrollment public or actor scope mismatch".into());
            }
        }
        let flat: Vec<_> = roots.iter().flat_map(|pair| pair.iter()).copied().collect();
        for (index, path) in flat.iter().enumerate() {
            let metadata = std::fs::symlink_metadata(path)?;
            if !path.is_absolute()
                || std::fs::canonicalize(path)?.as_path() != *path
                || !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != rustix::process::getuid().as_raw()
                || metadata.permissions().mode() & 0o077 != 0
                || flat[..index]
                    .iter()
                    .any(|other| path.starts_with(other) || other.starts_with(path))
                || std::fs::read_dir(path)?.next().is_some()
            {
                return Err("native enrollment roots must be empty, private and disjoint".into());
            }
        }
        let Self {
            claim,
            refunds,
            profile,
            payouts,
            master_keys,
            ..
        } = self;
        let mut enrolled = Vec::with_capacity(2);
        for (index, ((plan, payout), keys)) in planned
            .into_iter()
            .zip(payouts)
            .zip(master_keys)
            .enumerate()
        {
            enrolled.push(
                NativeXmrInitializerV23 {
                    claim: &claim,
                    refund: &refunds[index],
                    profile: profile.clone(),
                    claim_payout_v23: Some(payout),
                    master_keys_v23: keys,
                }
                .initialize_enrollment(
                    terms[index],
                    plan,
                    actors[index],
                    roots[index],
                )?,
            );
        }
        enrolled
            .try_into()
            .map_err(|_| "two native enrollment positions required".into())
    }
}

impl NativeXmrInitializerV23<'_> {
    fn initialize_enrollment(
        self,
        terms: &SettlementTermsV1,
        plan: NativeXmrEnrollmentPlanV23,
        actors: [[u8; 32]; 2],
        roots: [&Path; 2],
    ) -> Result<NativeXmrEnrolledFixtureV23> {
        let payout = self
            .claim_payout_v23
            .ok_or("native enrollment requires an independent payout")?;
        if payout.address() == plan.funding_destination {
            return Err("native enrollment payout aliases funding".into());
        }
        let context = xmr_setup_profile::proof_context_hash(
            &self.profile,
            &XmrProofContextV1 {
                settlement_id: terms.settlement_id.0,
                chain_id: terms.counterparty_leg.chain_id.0,
                asset_id: terms.counterparty_leg.asset_id.0,
                amount_piconero: terms.counterparty_leg.amount,
                min_confirmations: terms.counterparty_leg.finality.min_confirmations,
                max_reorg_depth: terms.counterparty_leg.finality.max_reorg_depth,
            },
        )?;
        let mut rng = rand::thread_rng();
        let claim_proof = xmr_dleq_sigma::prove_bound(
            self.claim,
            terms.settlement_id.0,
            context,
            xmr_dleq_sigma::ROLE_XMR_SHARED_SPEND,
            &mut rng,
        )?;
        let refund_proof = xmr_dleq_sigma::prove_bound(
            self.refund,
            terms.settlement_id.0,
            context,
            xmr_dleq_sigma::ROLE_XMR_REFUND_SHARE,
            &mut rng,
        )?;
        let public_binding = XmrSetupBindingV1 {
            settlement_id: terms.settlement_id.0,
            terms_hash: terms.terms_hash()?,
            dleq: claim_proof,
            funding_tx_hash: plan.funding_tx_hash,
            expected_amount_piconero: u64::try_from(terms.counterparty_leg.amount)?,
            destination: payout.address().to_owned(),
            combined_spend_public_key: xmr_crypto::combine_public_shares(
                self.claim.public_claim()?.ed_compressed,
                self.refund.public_claim()?.ed_compressed,
            )?,
        };
        let setup =
            xmr_setup_profile::validate_setup(terms, &self.profile, public_binding.clone(), None)?;
        let enrollment = xmr_session_init::prepare_xmr_share_enrollment_v23(&setup, &refund_proof)?;
        let mut owners = Vec::with_capacity(2);
        for (index, master_key_v23) in self.master_keys_v23.into_iter().enumerate() {
            let (role, secret) = if actors[index] == terms.dom_leg.refund_to.0 {
                (XmrLocalShareRoleV11::ClaimReceiver, self.refund)
            } else if actors[index] == terms.counterparty_leg.refund_to.0 {
                (XmrLocalShareRoleV11::RefundReceiver, self.claim)
            } else {
                return Err("native enrollment local actor has no role".into());
            };
            let secrets = EncryptedSqliteSecretStore::open(
                &roots[index].join("native-xmr-secrets-v23.sqlite"),
                SecretStoreMasterKey::new(*master_key_v23)?,
            )?;
            let nullifiers =
                DleqNullifierStore::open(&roots[index].join("native-xmr-nullifiers-v23.sqlite"))?;
            // Same fixture view-key convention as the real offline producer;
            // this key is never an execution authority or a spend share.
            let mut view = [0; 32];
            view[0] = 13;
            xmr_session_init::initialize_enrolled_session_for_role_v23(
                &enrollment,
                &secrets,
                &nullifiers,
                XmrLocalSessionSecretsV11 {
                    role,
                    spend_share: Zeroizing::new(secret.xmr_share_little_endian()),
                    view_key: Zeroizing::new(view),
                },
                &mut rng,
            )?;
            owners.push(NativeXmrActorCustodyV23 {
                secrets,
                nullifiers,
                role,
                master_key_v23,
            });
        }
        Ok(NativeXmrEnrolledFixtureV23 {
            enrollment,
            profile: self.profile,
            public_binding,
            refund_proof,
            payout,
            actors: owners
                .try_into()
                .map_err(|_| "two enrollment actors required")?,
        })
    }
}
