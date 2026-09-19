//! Public, two-phase F6 artifact preparation. This module grants NO authority.
//!
//! Registry roots and route pins are supplied, not trusted by this encoder.
//! Finalization checks signatures against those supplied roots, while the
//! daemon's unchanged decoder alone checks its actual trust anchor, admitted
//! composition, rosters and native enrollment. No private key, HSM credential,
//! inventory lease, third-party attestation or mutable store is created here.
use super::*;
use kaystra_core::terms::SettlementTermsV1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum F6ArtifactWriteErrorV23 {
    InvalidInput,
    InvalidSignature,
}

impl core::fmt::Display for F6ArtifactWriteErrorV23 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid public F6 artifact input",
            Self::InvalidSignature => "invalid supplied-root F6 artifact signature",
        })
    }
}

impl std::error::Error for F6ArtifactWriteErrorV23 {}

type Result<T> = std::result::Result<T, F6ArtifactWriteErrorV23>;

/// These pins must subsequently match the daemon's independent admission.
pub struct UntrustedF6RoutePinsV23 {
    pub network_id: Digest32,
    pub route_id: Digest32,
    pub composition_digest: Digest32,
    pub route_scope_digest: Digest32,
    pub registry_digest: Digest32,
    pub registry_epoch: u64,
    pub profile_bundle_digest: Digest32,
}

/// Public endpoint information only. The owner retains its signing key and
/// provides the separate authenticated socket credential to the daemon.
pub struct PublicF6SignerEndpointV23 {
    pub independent_authority_id: Digest32,
    pub signer_index: u16,
    pub signer_public_key: [u8; 32],
    pub endpoint_uid: u32,
    pub endpoint: PathBuf,
}

pub enum PublicF6ClaimProfileV23 {
    /// DOMF6A07: already-bound templates and secret-source scopes.
    Bound {
        role_plan: ComposedFinalClaimRolePlanV1,
        sources: [FinalClaimSecretSourceScopeV1; 2],
    },
    /// DOMF6A23: public role enrollment only, never an executable claim plan.
    /// Templates must later originate from the actual bilateral native Store.
    NativeEnrollment {
        upstream: SettlementTermsV1,
        downstream: SettlementTermsV1,
    },
    /// DOMF6A25: Solana role enrollment. The downstream claim template later
    /// originates from the actual bilateral native Store, as for XMR.
    SolanaEnrollment {
        upstream: SettlementTermsV1,
        downstream: SettlementTermsV1,
    },
}

/// Every economic value and authority is explicit; there are no defaults.
pub struct PublicF6ArtifactInputsV23 {
    pub route: UntrustedF6RoutePinsV23,
    pub solver: ParticipantId,
    pub inventory_binding_digest: Digest32,
    pub bond_policy_hash: Digest32,
    pub bond_asset_binding_digest: Digest32,
    pub required_collateral: u128,
    pub status_max_lifetime_seconds: u64,
    pub pre_f6_limits: PreF6TimePolicyLimitsV2,
    pub supplied_registry_roots: AuthoritySetV1,
    pub bond_authorities: AuthoritySetV1,
    pub status_authorities: AuthoritySetV1,
    pub reserved_relay_keys: Vec<[u8; 32]>,
    pub reserved_participant_keys: Vec<[u8; 32]>,
    pub reserved_chain_keys: Vec<[u8; 32]>,
    pub signers: [Vec<PublicF6SignerEndpointV23>; 2],
    pub claim_profile: PublicF6ClaimProfileV23,
}

/// Immutable public signing request, deliberately not an Authenticated bundle.
/// The registry owners sign `signing_digest()` externally. Final output is
/// still untrusted input to the production daemon, not a capability.
pub struct PreparedUntrustedF6ArtifactV23 {
    prefix: Vec<u8>,
    digest: Digest32,
    supplied_roots: AuthoritySetV1,
}

impl PreparedUntrustedF6ArtifactV23 {
    pub fn prepare(input: PublicF6ArtifactInputsV23, secp: &SecpContext) -> Result<Self> {
        validate_public_input(&input, secp)?;
        let (magic, version, domain) = match &input.claim_profile {
            PublicF6ClaimProfileV23::Bound { .. } => {
                (BUNDLE_MAGIC_V7, BUNDLE_VERSION_V7, BUNDLE_DOMAIN_V7)
            }
            PublicF6ClaimProfileV23::NativeEnrollment { .. } => (
                claim_enrollment_v23::MAGIC_V23,
                claim_enrollment_v23::VERSION_V23,
                claim_enrollment_v23::DOMAIN_V23,
            ),
            PublicF6ClaimProfileV23::SolanaEnrollment { .. } => (
                claim_enrollment_v23::MAGIC_SOL_V25,
                claim_enrollment_v23::VERSION_SOL_V25,
                claim_enrollment_v23::DOMAIN_SOL_V25,
            ),
        };
        let mut prefix = Vec::new();
        prefix.extend_from_slice(magic);
        prefix.extend_from_slice(&version.to_be_bytes());
        prefix.extend_from_slice(&0_u16.to_be_bytes());
        for digest in [
            input.route.network_id,
            input.route.route_id,
            input.route.composition_digest,
            input.route.route_scope_digest,
            input.route.registry_digest,
        ] {
            prefix.extend_from_slice(&digest);
        }
        prefix.extend_from_slice(&input.route.registry_epoch.to_be_bytes());
        for digest in [
            input.route.profile_bundle_digest,
            input.solver.0,
            input.inventory_binding_digest,
            input.bond_policy_hash,
            input.bond_asset_binding_digest,
        ] {
            prefix.extend_from_slice(&digest);
        }
        prefix.extend_from_slice(&input.required_collateral.to_be_bytes());
        for number in [
            input.status_max_lifetime_seconds,
            input.pre_f6_limits.valid_from_seconds,
            input.pre_f6_limits.expires_at_seconds,
            input.pre_f6_limits.max_evidence_age_seconds,
        ] {
            prefix.extend_from_slice(&number.to_be_bytes());
        }
        for authorities in [&input.bond_authorities, &input.status_authorities] {
            append_sized(
                &mut prefix,
                &authorities.canonical_bytes().map_err(invalid)?,
                MAX_AUTHORITY_BYTES_V7,
            )?;
        }
        for keys in [
            &input.reserved_relay_keys,
            &input.reserved_participant_keys,
            &input.reserved_chain_keys,
        ] {
            prefix.extend_from_slice(&(keys.len() as u16).to_be_bytes());
            for key in keys {
                prefix.extend_from_slice(key);
            }
        }
        for signers in &input.signers {
            prefix.extend_from_slice(&(signers.len() as u16).to_be_bytes());
            for signer in signers {
                prefix.extend_from_slice(&signer.independent_authority_id);
                prefix.extend_from_slice(&signer.signer_index.to_be_bytes());
                prefix.extend_from_slice(&signer.signer_public_key);
                prefix.extend_from_slice(&signer.endpoint_uid.to_be_bytes());
                append_sized(
                    &mut prefix,
                    signer
                        .endpoint
                        .to_str()
                        .ok_or(F6ArtifactWriteErrorV23::InvalidInput)?
                        .as_bytes(),
                    MAX_ENDPOINT_BYTES_V7,
                )?;
            }
        }
        match &input.claim_profile {
            PublicF6ClaimProfileV23::Bound { role_plan, sources } => {
                prefix.extend_from_slice(&role_plan.canonical_bytes());
                for source in sources {
                    prefix.extend_from_slice(&source.canonical_bytes());
                }
            }
            PublicF6ClaimProfileV23::NativeEnrollment {
                upstream,
                downstream,
            } => {
                prefix.extend_from_slice(&public_enrollment_bytes(upstream, downstream)?);
            }
            PublicF6ClaimProfileV23::SolanaEnrollment {
                upstream,
                downstream,
            } => {
                // Same encoder the daemon rederives from its admitted
                // composition; public terms only, no admission implied.
                prefix.extend_from_slice(
                    claim_enrollment_v23::SolClaimEnrollmentV25::from_terms(upstream, downstream)
                        .map_err(|_| F6ArtifactWriteErrorV23::InvalidInput)?
                        .bytes(),
                );
            }
        }
        // Reserve enough room for every supplied root signature before anyone
        // signs, so finalization cannot create a decoder-oversized artifact.
        if prefix.len() + 2 + 66 * input.supplied_registry_roots.xonly_keys().len()
            > MAX_BUNDLE_BYTES_V7
        {
            return Err(F6ArtifactWriteErrorV23::InvalidInput);
        }
        let digest = digest_parts(&[domain, &prefix]).map_err(invalid)?;
        Ok(Self {
            prefix,
            digest,
            supplied_roots: input.supplied_registry_roots,
        })
    }

    pub fn canonical_signing_prefix(&self) -> &[u8] {
        &self.prefix
    }

    pub const fn signing_digest(&self) -> Digest32 {
        self.digest
    }

    pub fn finalize(self, signatures: &[(u16, [u8; 64])], secp: &SecpContext) -> Result<Vec<u8>> {
        if signatures.len() > MAX_SIGNERS_V7 {
            return Err(F6ArtifactWriteErrorV23::InvalidSignature);
        }
        let mut suffix = Vec::new();
        suffix.extend_from_slice(&(signatures.len() as u16).to_be_bytes());
        for (index, signature) in signatures {
            suffix.extend_from_slice(&index.to_be_bytes());
            suffix.extend_from_slice(signature);
        }
        let mut reader = BundleReaderV7::new(&suffix);
        verify_bundle_signatures(&mut reader, &self.prefix, &self.supplied_roots, secp)
            .map_err(|_| F6ArtifactWriteErrorV23::InvalidSignature)?;
        reader
            .finish()
            .map_err(|_| F6ArtifactWriteErrorV23::InvalidSignature)?;
        let mut bytes = self.prefix;
        bytes.extend_from_slice(&suffix);
        Ok(bytes)
    }
}

fn invalid(_: impl core::fmt::Debug) -> F6ArtifactWriteErrorV23 {
    F6ArtifactWriteErrorV23::InvalidInput
}

fn append_sized(bytes: &mut Vec<u8>, value: &[u8], maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum {
        return Err(F6ArtifactWriteErrorV23::InvalidInput);
    }
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn validate_public_input(input: &PublicF6ArtifactInputsV23, secp: &SecpContext) -> Result<()> {
    let route = &input.route;
    if [
        route.network_id,
        route.route_id,
        route.composition_digest,
        route.route_scope_digest,
        route.registry_digest,
        route.profile_bundle_digest,
        input.solver.0,
        input.inventory_binding_digest,
        input.bond_policy_hash,
        input.bond_asset_binding_digest,
    ]
    .contains(&ZERO_DIGEST)
        || route.registry_epoch == 0
        || input.required_collateral == 0
        || input.status_max_lifetime_seconds == 0
        || input.pre_f6_limits.valid_from_seconds >= input.pre_f6_limits.expires_at_seconds
        || input.pre_f6_limits.max_evidence_age_seconds == 0
        || input.bond_authorities.threshold() < 2
        || input.status_authorities.threshold() < 2
        || input.supplied_registry_roots.xonly_keys().len() > MAX_SIGNERS_V7
    {
        return Err(F6ArtifactWriteErrorV23::InvalidInput);
    }
    input
        .supplied_registry_roots
        .validate_with_context(secp)
        .map_err(invalid)?;
    bond_reservation_authority_set_digest_v2(&input.bond_authorities, secp).map_err(invalid)?;
    candidate_status_authority_set_digest_v2(&input.status_authorities, secp).map_err(invalid)?;
    for keys in [
        &input.reserved_relay_keys,
        &input.reserved_participant_keys,
        &input.reserved_chain_keys,
    ] {
        if keys.is_empty()
            || keys.len() > MAX_SIGNERS_V7
            || keys.contains(&ZERO_DIGEST)
            || keys.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(F6ArtifactWriteErrorV23::InvalidInput);
        }
    }
    ProductionF6ReservedSignerKeysV2::new(
        input.reserved_relay_keys.clone(),
        input.reserved_participant_keys.clone(),
        input.reserved_chain_keys.clone(),
    )
    .map_err(invalid)?;
    let reserved: BTreeSet<_> = input
        .reserved_relay_keys
        .iter()
        .chain(&input.reserved_participant_keys)
        .chain(&input.reserved_chain_keys)
        .copied()
        .collect();
    let bond: BTreeSet<_> = input
        .bond_authorities
        .xonly_keys()
        .iter()
        .copied()
        .collect();
    if input
        .status_authorities
        .xonly_keys()
        .iter()
        .any(|key| bond.contains(key))
        || input
            .bond_authorities
            .xonly_keys()
            .iter()
            .chain(input.status_authorities.xonly_keys())
            .any(|key| reserved.contains(key))
        || input
            .supplied_registry_roots
            .xonly_keys()
            .iter()
            .any(|key| !input.reserved_chain_keys.contains(key))
    {
        return Err(F6ArtifactWriteErrorV23::InvalidInput);
    }
    for signers in &input.signers {
        if !(2..=MAX_SIGNERS_V7).contains(&signers.len()) {
            return Err(F6ArtifactWriteErrorV23::InvalidInput);
        }
        let descriptors: Vec<_> = signers
            .iter()
            .map(|s| ProductionF6BondSignerDescriptorV7 {
                independent_authority_id: s.independent_authority_id,
                signer_index: s.signer_index,
                signer_public_key: s.signer_public_key,
                endpoint_uid: s.endpoint_uid,
                endpoint: s.endpoint.clone(),
            })
            .collect();
        validate_signer_descriptors(&input.bond_authorities, &descriptors).map_err(invalid)?;
        for signer in signers {
            let text = signer
                .endpoint
                .to_str()
                .ok_or(F6ArtifactWriteErrorV23::InvalidInput)?;
            if text.is_empty()
                || text.len() > MAX_ENDPOINT_BYTES_V7
                || !signer.endpoint.is_absolute()
                || !lexically_normal(&signer.endpoint)
                || text
                    .bytes()
                    .any(|byte| byte == 0 || byte.is_ascii_control())
            {
                return Err(F6ArtifactWriteErrorV23::InvalidInput);
            }
        }
    }
    match &input.claim_profile {
        PublicF6ClaimProfileV23::Bound { role_plan, sources } => {
            let profile = ClaimPlanProfileV23::Bound {
                role_plan: role_plan.clone(),
                upstream: sources[0].clone(),
                downstream: sources[1].clone(),
            };
            profile
                .validate_scope(
                    route.route_id,
                    route.route_scope_digest,
                    route.composition_digest,
                )
                .map_err(invalid)?;
        }
        PublicF6ClaimProfileV23::SolanaEnrollment { upstream, downstream } => {
            claim_enrollment_v23::validate_solana_enrollment_terms_v25(upstream, downstream)
                .map_err(invalid)?;
        }
        PublicF6ClaimProfileV23::NativeEnrollment { .. } => {}
    }
    Ok(())
}

/// Encode public terms only. This deliberately does not claim these terms
/// have passed route admission; the daemon rederives all 322 bytes from its
/// authenticated composition before accepting an enrollment profile.
fn public_enrollment_bytes(
    upstream: &SettlementTermsV1,
    downstream: &SettlementTermsV1,
) -> Result<[u8; 322]> {
    if upstream.session_id == downstream.session_id
        || upstream.settlement_id == downstream.settlement_id
        || upstream.adaptor_point_sec1 != downstream.adaptor_point_sec1
    {
        return Err(F6ArtifactWriteErrorV23::InvalidInput);
    }
    let mut bytes = [0; 322];
    for (index, terms) in [upstream, downstream].into_iter().enumerate() {
        terms.validate().map_err(invalid)?;
        let owner = terms.counterparty_leg.refund_to;
        let claimer = terms.dom_leg.refund_to;
        if owner == claimer || !terms.roster.contains(&owner) || !terms.roster.contains(&claimer) {
            return Err(F6ArtifactWriteErrorV23::InvalidInput);
        }
        let start = index * 161;
        bytes[start..start + 32].copy_from_slice(&terms.terms_hash().map_err(invalid)?);
        bytes[start + 32..start + 64].copy_from_slice(&downstream.dom_leg.beneficiary.0);
        bytes[start + 64..start + 96].copy_from_slice(&owner.0);
        bytes[start + 96..start + 128].copy_from_slice(&claimer.0);
        bytes[start + 128..start + 161].copy_from_slice(&terms.adaptor_point_sec1);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_key(secp: &SecpContext, value: u8) -> [u8; 32] {
        secp.sign_bip340(&[value; 32], &[1; 32], &[2; 32])
            .unwrap()
            .1
    }

    fn input(secp: &SecpContext) -> PublicF6ArtifactInputsV23 {
        let bytes = hex::decode(
            include_str!("../../kaystra-core/fixtures/terms-v1/valid-minimal.hex").trim(),
        )
        .unwrap();
        let upstream = SettlementTermsV1::decode(&bytes).unwrap();
        let mut downstream = upstream.clone();
        downstream.session_id.0[0] ^= 1;
        downstream.settlement_id.0[0] ^= 1;
        let roots = vec![public_key(secp, 10), public_key(secp, 11)];
        let bond = vec![public_key(secp, 12), public_key(secp, 13)];
        let signers = std::array::from_fn(|leg| {
            bond.iter()
                .enumerate()
                .map(|(index, key)| PublicF6SignerEndpointV23 {
                    independent_authority_id: [20 + index as u8; 32],
                    signer_index: index as u16,
                    signer_public_key: *key,
                    endpoint_uid: 1000,
                    endpoint: PathBuf::from(format!("/provided/leg-{leg}/signer-{index}.sock")),
                })
                .collect()
        });
        let mut chain = roots.clone();
        chain.sort();
        PublicF6ArtifactInputsV23 {
            route: UntrustedF6RoutePinsV23 {
                network_id: [1; 32],
                route_id: [2; 32],
                composition_digest: [3; 32],
                route_scope_digest: [4; 32],
                registry_digest: [5; 32],
                registry_epoch: 1,
                profile_bundle_digest: [6; 32],
            },
            solver: ParticipantId([7; 32]),
            inventory_binding_digest: [8; 32],
            bond_policy_hash: [9; 32],
            bond_asset_binding_digest: [10; 32],
            required_collateral: 100,
            status_max_lifetime_seconds: 30,
            pre_f6_limits: PreF6TimePolicyLimitsV2 {
                valid_from_seconds: 100,
                expires_at_seconds: 200,
                max_evidence_age_seconds: 10,
            },
            supplied_registry_roots: AuthoritySetV1::new(2, roots).unwrap(),
            bond_authorities: AuthoritySetV1::new(2, bond).unwrap(),
            status_authorities: AuthoritySetV1::new(
                2,
                vec![public_key(secp, 14), public_key(secp, 15)],
            )
            .unwrap(),
            reserved_relay_keys: vec![public_key(secp, 16)],
            reserved_participant_keys: vec![public_key(secp, 17)],
            reserved_chain_keys: chain,
            signers,
            claim_profile: PublicF6ClaimProfileV23::NativeEnrollment {
                upstream,
                downstream,
            },
        }
    }

    fn signatures(secp: &SecpContext, digest: Digest32) -> [(u16, [u8; 64]); 2] {
        [0, 1].map(|index| {
            (
                index,
                secp.sign_bip340(&[10 + index as u8; 32], &digest, &[30; 32])
                    .unwrap()
                    .0,
            )
        })
    }

    #[test]
    fn public_f6_two_phase_encoding_uses_exact_production_codecs() {
        let secp = SecpContext::new(&[31; 32]);
        let first = PreparedUntrustedF6ArtifactV23::prepare(input(&secp), &secp).unwrap();
        let second = PreparedUntrustedF6ArtifactV23::prepare(input(&secp), &secp).unwrap();
        assert_eq!(
            first.canonical_signing_prefix(),
            second.canonical_signing_prefix()
        );
        assert_eq!(
            first.signing_digest(),
            digest_parts(&[
                claim_enrollment_v23::DOMAIN_V23,
                first.canonical_signing_prefix()
            ])
            .unwrap()
        );
        let signed = signatures(&secp, first.signing_digest());
        let length = first.canonical_signing_prefix().len();
        let bytes = first.finalize(&signed, &secp).unwrap();
        let mut reader = BundleReaderV7::new(&bytes);
        assert_eq!(
            &reader.take::<8>().unwrap(),
            claim_enrollment_v23::MAGIC_V23
        );
        assert_eq!(reader.u16().unwrap(), 23);
        assert_eq!(reader.u16().unwrap(), 0);
        for value in 1..=5 {
            assert_eq!(reader.take::<32>().unwrap(), [value; 32]);
        }
        assert_eq!(reader.u64().unwrap(), 1);
        for value in 6..=10 {
            assert_eq!(reader.take::<32>().unwrap(), [value; 32]);
        }
        assert_eq!(reader.u128().unwrap(), 100);
        for value in [30, 100, 200, 10] {
            assert_eq!(reader.u64().unwrap(), value);
        }
        let bond = decode_authorities(&mut reader).unwrap();
        decode_authorities(&mut reader).unwrap();
        for _ in 0..3 {
            decode_keys(&mut reader).unwrap();
        }
        for _ in 0..2 {
            validate_signer_descriptors(&bond, &decode_signers(&mut reader).unwrap()).unwrap();
        }
        claim_enrollment_v23::NativeClaimEnrollmentV23::decode(&mut reader).unwrap();
        assert_eq!(reader.position(), length);
        verify_bundle_signatures(
            &mut reader,
            &bytes[..length],
            &input(&secp).supplied_registry_roots,
            &secp,
        )
        .unwrap();
        reader.finish().unwrap();
    }

    #[test]
    fn public_f6_missing_reordered_duplicate_foreign_and_mutated_signatures_fail() {
        let secp = SecpContext::new(&[32; 32]);
        let original = PreparedUntrustedF6ArtifactV23::prepare(input(&secp), &secp).unwrap();
        let signatures = signatures(&secp, original.signing_digest());
        let mut foreign = signatures;
        foreign[1].0 = 2;
        let mut damaged = signatures;
        damaged[1].1[0] ^= 1;
        for supplied in [
            vec![],
            vec![signatures[0]],
            vec![signatures[1], signatures[0]],
            vec![signatures[0], signatures[0]],
            foreign.to_vec(),
            damaged.to_vec(),
        ] {
            let prepared = PreparedUntrustedF6ArtifactV23::prepare(input(&secp), &secp).unwrap();
            assert_eq!(
                prepared.finalize(&supplied, &secp),
                Err(F6ArtifactWriteErrorV23::InvalidSignature)
            );
        }
        for field in 0..3 {
            let mut changed = input(&secp);
            match field {
                0 => changed.route.registry_digest[0] ^= 1,
                1 => changed.reserved_relay_keys = vec![public_key(&secp, 18)],
                _ => {
                    if let PublicF6ClaimProfileV23::NativeEnrollment { downstream, .. } =
                        &mut changed.claim_profile
                    {
                        downstream.dom_leg.amount += 1;
                    }
                }
            }
            let changed = PreparedUntrustedF6ArtifactV23::prepare(changed, &secp).unwrap();
            assert_ne!(changed.signing_digest(), original.signing_digest());
            assert_eq!(
                changed.finalize(&signatures, &secp),
                Err(F6ArtifactWriteErrorV23::InvalidSignature)
            );
        }
    }

    #[test]
    fn public_f6_rejects_noncanonical_keys_collapsed_roles_and_unbounded_endpoints() {
        let secp = SecpContext::new(&[33; 32]);
        for case in 0..6 {
            let mut bad = input(&secp);
            match case {
                0 => bad.reserved_chain_keys.reverse(),
                1 => bad
                    .reserved_participant_keys
                    .push(bad.reserved_participant_keys[0]),
                2 => {
                    bad.signers[0][1].independent_authority_id =
                        bad.signers[0][0].independent_authority_id
                }
                3 => bad.signers[0][0].endpoint = PathBuf::from("/provided/../elsewhere"),
                4 => {
                    bad.signers[0][0].endpoint =
                        PathBuf::from(format!("/{}", "x".repeat(MAX_ENDPOINT_BYTES_V7)))
                }
                _ => bad.status_authorities = bad.bond_authorities.clone(),
            }
            assert!(matches!(
                PreparedUntrustedF6ArtifactV23::prepare(bad, &secp),
                Err(F6ArtifactWriteErrorV23::InvalidInput)
            ));
        }
    }

    #[test]
    fn public_f6_bound_profile_is_a07_and_cannot_be_rebound_or_downgraded() {
        use dom_final_claim_binding::{
            ComposedFinalClaimRolePlanInputV1, FinalClaimRevealModeV1, FinalClaimRoleSelectionV1,
            FinalClaimSecretSourceScopeInputV1, FinalClaimSecretSourceV1,
        };
        let secp = SecpContext::new(&[34; 32]);
        let mut supplied = input(&secp);
        let PublicF6ClaimProfileV23::NativeEnrollment {
            mut upstream,
            mut downstream,
        } = supplied.claim_profile
        else {
            unreachable!()
        };
        // A genuine public curve point for the typed role-plan constructor.
        upstream.adaptor_point_sec1[0] = 2;
        upstream.adaptor_point_sec1[1..].copy_from_slice(&public_key(&secp, 19));
        downstream.adaptor_point_sec1 = upstream.adaptor_point_sec1;
        let source = |terms: &SettlementTermsV1| {
            FinalClaimSecretSourceScopeV1::new(FinalClaimSecretSourceScopeInputV1 {
                secret_source: FinalClaimSecretSourceV1::LocalOrigin,
                reveal_mode: FinalClaimRevealModeV1::DomRevealsFirst,
                route_id: supplied.route.route_id,
                composition_binding_digest: supplied.route.composition_digest,
                source_chain_id: terms.dom_leg.chain_id,
                source_settlement_id: terms.settlement_id,
                source_session_id: terms.session_id,
                source_claim_template_hash: [50; 32],
                adaptor_point_sec1: terms.adaptor_point_sec1,
                adaptor_secret_origin_id: terms.counterparty_leg.refund_to,
                dom_claim_sender_id: terms.counterparty_leg.refund_to,
            })
            .unwrap()
        };
        let sources = [source(&upstream), source(&downstream)];
        let selection = |terms: &SettlementTermsV1, source| {
            FinalClaimRoleSelectionV1::new(
                terms.counterparty_leg.refund_to,
                terms.counterparty_leg.refund_to,
                terms.dom_leg.refund_to,
                FinalClaimRevealModeV1::DomRevealsFirst,
                FinalClaimSecretSourceV1::LocalOrigin,
                source,
            )
            .unwrap()
        };
        let plan = ComposedFinalClaimRolePlanV1::bind(ComposedFinalClaimRolePlanInputV1 {
            route_id: supplied.route.route_id,
            route_scope_digest: supplied.route.route_scope_digest,
            composition_binding_digest: supplied.route.composition_digest,
            upstream_terms: &upstream,
            downstream_terms: &downstream,
            upstream_selection: selection(&upstream, sources[0].clone()),
            downstream_selection: selection(&downstream, sources[1].clone()),
        })
        .unwrap();
        supplied.claim_profile = PublicF6ClaimProfileV23::Bound {
            role_plan: plan,
            sources,
        };
        supplied.route.route_id[0] ^= 1;
        assert!(validate_public_input(&supplied, &secp).is_err());
        supplied.route.route_id[0] ^= 1;
        let mut prepared = PreparedUntrustedF6ArtifactV23::prepare(supplied, &secp).unwrap();
        assert_eq!(&prepared.canonical_signing_prefix()[..8], BUNDLE_MAGIC_V7);
        let signatures = signatures(&secp, prepared.signing_digest());
        // Even replacing just the public profile marker changes the signing
        // domain; an A07 signature can never authorize A23 enrollment.
        prepared.prefix[..8].copy_from_slice(claim_enrollment_v23::MAGIC_V23);
        assert_eq!(
            prepared.finalize(&signatures, &secp),
            Err(F6ArtifactWriteErrorV23::InvalidSignature)
        );
    }

    #[test]
    fn public_f6_solana_enrollment_is_a25_under_its_own_domain() {
        let secp = SecpContext::new(&[35; 32]);
        let mut invalid = input(&secp);
        let PublicF6ClaimProfileV23::NativeEnrollment { upstream, downstream } = invalid.claim_profile
        else {
            unreachable!()
        };
        invalid.claim_profile = PublicF6ClaimProfileV23::SolanaEnrollment {
            upstream,
            downstream,
        };
        assert!(matches!(
            PreparedUntrustedF6ArtifactV23::prepare(invalid, &secp),
            Err(F6ArtifactWriteErrorV23::InvalidInput)
        ));
        let mut supplied = input(&secp);
        let PublicF6ClaimProfileV23::NativeEnrollment {
            mut upstream,
            mut downstream,
        } = supplied.claim_profile
        else {
            unreachable!()
        };
        upstream.policy_version = dom_adaptor::DOM_NATIVE_BOOTSTRAP_POLICY_V17;
        downstream.policy_version = dom_adaptor::DOM_NATIVE_BOOTSTRAP_POLICY_V17;
        // The ordinary route topology: the DOM roles swap between positions,
        // so the upstream DOM receiver is the downstream DOM sender and one
        // party owns T on the whole route.
        std::mem::swap(
            &mut downstream.dom_leg.beneficiary,
            &mut downstream.dom_leg.refund_to,
        );
        std::mem::swap(
            &mut downstream.counterparty_leg.beneficiary,
            &mut downstream.counterparty_leg.refund_to,
        );
        let expected =
            claim_enrollment_v23::SolClaimEnrollmentV25::from_terms(&upstream, &downstream)
                .unwrap();
        let xmr = public_enrollment_bytes(&upstream, &downstream).unwrap();
        // In the topology A25 requires, the upstream DOM receiver is the
        // downstream DOM sender, so both enrollments name the same origin,
        // senders and receivers: identical bytes by construction. Only the
        // signing domain separates the two profiles, which the end of this
        // test proves.
        assert_eq!(expected.bytes(), xmr.as_slice());
        supplied.claim_profile = PublicF6ClaimProfileV23::SolanaEnrollment {
            upstream,
            downstream,
        };
        let mut prepared = PreparedUntrustedF6ArtifactV23::prepare(supplied, &secp).unwrap();
        assert_eq!(
            prepared.signing_digest(),
            digest_parts(&[
                claim_enrollment_v23::DOMAIN_SOL_V25,
                prepared.canonical_signing_prefix()
            ])
            .unwrap()
        );
        let prefix = prepared.canonical_signing_prefix().to_vec();
        let mut reader = BundleReaderV7::new(&prefix);
        assert_eq!(
            &reader.take::<8>().unwrap(),
            claim_enrollment_v23::MAGIC_SOL_V25
        );
        assert_eq!(reader.u16().unwrap(), 25);
        assert_eq!(reader.u16().unwrap(), 0);
        assert!(prefix.ends_with(expected.bytes()));
        let signatures = signatures(&secp, prepared.signing_digest());
        // An A25 signature never authorizes the XMR A23 enrollment, nor A07.
        prepared.prefix[..8].copy_from_slice(claim_enrollment_v23::MAGIC_V23);
        prepared.prefix[8..10].copy_from_slice(&claim_enrollment_v23::VERSION_V23.to_be_bytes());
        assert_eq!(
            prepared.finalize(&signatures, &secp),
            Err(F6ArtifactWriteErrorV23::InvalidSignature)
        );
    }
}
