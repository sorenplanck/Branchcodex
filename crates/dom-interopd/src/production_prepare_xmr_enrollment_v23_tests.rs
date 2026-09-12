use super::*;
use kaystra_core::{terms::SettlementTermsV1, types::*};
use std::os::unix::fs::{symlink, PermissionsExt};
use xmr_dleq_sigma::{
    prove_bound, CrossCurveSecret252, ROLE_XMR_REFUND_SHARE, ROLE_XMR_SHARED_SPEND,
};
use xmr_refund_policy::NonCooperativeRefundCapability as _;
use xmr_setup_profile::{
    proof_context_hash, validate_setup, XmrAdapterProfileV1, XmrNetwork, XmrProofContextV1,
    XmrSetupBindingV1,
};

use crate::production_xmr_native_registry_fixture_v23 as registry_fixture;

fn scalar(value: u8) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[0] = value;
    bytes
}
fn root() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

// Exactly two real native proofs per campaign, reused by all negative cases.
fn context() -> EnrollmentContextV23 {
    let t = CrossCurveSecret252::from_little_endian(scalar(7)).unwrap();
    let u = CrossCurveSecret252::from_little_endian(scalar(11)).unwrap();
    let claim = t.public_claim().unwrap();
    let refund = u.public_claim().unwrap();
    let profile = XmrAdapterProfileV1::new(XmrNetwork::Stagenet, 3, 2).unwrap();
    let a = ParticipantId([1; 32]);
    let b = ParticipantId([2; 32]);
    let terms = SettlementTermsV1 {
        settlement_id: SettlementId([4; 32]),
        session_id: SessionId([5; 32]),
        intent_hash: IntentHash([6; 32]),
        solver_id: SolverId([7; 32]),
        roster: [a, b],
        dom_leg: LegTermsV1 {
            role: LegRole::Dom,
            chain_id: ChainId([8; 32]),
            asset_id: AssetId([9; 32]),
            amount: 100,
            beneficiary: b,
            refund_to: a,
            mechanism: LockMechanism::DomAdaptor2of2,
            deadline: TimelockSpec::BlockHeight { value: 100 },
            finality: FinalityPolicyV1 {
                min_confirmations: 1,
                max_reorg_depth: 2,
            },
            adapter_profile_hash: [10; 32],
        },
        counterparty_leg: LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: ChainId([11; 32]),
            asset_id: AssetId([12; 32]),
            amount: 100,
            beneficiary: a,
            refund_to: b,
            mechanism: LockMechanism::CrossCurveSharedSpend,
            deadline: TimelockSpec::TimestampSeconds {
                value: 1_900_000_000,
            },
            finality: FinalityPolicyV1 {
                min_confirmations: 10,
                max_reorg_depth: 20,
            },
            adapter_profile_hash: profile.profile_hash(),
        },
        adaptor_point_sec1: claim.secp_compressed,
        fee_limit: FeeLimitV1 {
            dom_max: 10,
            counterparty_max: 10,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 100,
        },
        assurance_policy_hash: None,
        policy_version: 1,
        metadata: vec![],
    };
    let proof_context = proof_context_hash(
        &profile,
        &XmrProofContextV1 {
            settlement_id: terms.settlement_id.0,
            chain_id: terms.counterparty_leg.chain_id.0,
            asset_id: terms.counterparty_leg.asset_id.0,
            amount_piconero: 100,
            min_confirmations: 10,
            max_reorg_depth: 20,
        },
    )
    .unwrap();
    let dleq = prove_bound(
        &t,
        terms.settlement_id.0,
        proof_context,
        ROLE_XMR_SHARED_SPEND,
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let refund_proof = prove_bound(
        &u,
        terms.settlement_id.0,
        proof_context,
        ROLE_XMR_REFUND_SHARE,
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let setup = validate_setup(
        &terms,
        &profile,
        XmrSetupBindingV1 {
            settlement_id: terms.settlement_id.0,
            terms_hash: terms.terms_hash().unwrap(),
            dleq,
            funding_tx_hash: [15; 32],
            expected_amount_piconero: 100,
            destination: "5FixtureDestination".into(),
            combined_spend_public_key: xmr_crypto::combine_public_shares(
                claim.ed_compressed,
                refund.ed_compressed,
            )
            .unwrap(),
        },
        None,
    )
    .unwrap();
    let enrollment =
        xmr_session_init::prepare_xmr_share_enrollment_v23(&setup, &refund_proof).unwrap();
    let public_enrollment = crate::production_inputs::ProductionXmrEnrollmentBundleV23::new(
        refund_proof,
        refund.secp_compressed,
        xmr_refund_adaptor::DomRefundAdaptorExecutor::new(refund).profile_hash(),
        1_900_000_000,
        "5FixtureRefund".into(),
    )
    .unwrap();
    EnrollmentContextV23 {
        enrollment,
        terms: terms.clone(),
        public_enrollment,
        role: XmrLocalShareRoleV11::ClaimReceiver,
        network_id: [20; 32],
        route_id: [21; 32],
        registry_digest: [22; 32],
        participant_digest: [23; 32],
        session_id: terms.session_id.0,
    }
}

#[test]
fn enrollment_writer_real_sdk_custody_reopens_both_roles_and_never_repairs_incomplete_state() {
    let mut context = context();
    let master = [31; 32];
    for (role, share, participant) in [
        (XmrLocalShareRoleV11::ClaimReceiver, 11, 1),
        (XmrLocalShareRoleV11::RefundReceiver, 7, 2),
    ] {
        context.role = role;
        let parent = root();
        let output = parent.path().join("custody");
        let report = report(
            &context,
            ProductionRoutePositionV1::Upstream,
            [participant; 32],
        );
        retain_custody(
            &context,
            &output,
            false,
            &master,
            Some((Zeroizing::new(scalar(share)), Zeroizing::new(scalar(17)))),
            &report,
        )
        .unwrap();
        assert!(!parent.path().join("custody.preparing-v23").exists());
        assert_eq!(std::fs::metadata(&output).unwrap().mode() & 0o7777, 0o700);
        let before = std::fs::read(output.join(SECRETS)).unwrap();
        for name in [SECRETS, NULLIFIERS, RECEIPT] {
            let metadata = std::fs::metadata(output.join(name)).unwrap();
            assert_eq!(metadata.mode() & 0o7777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
        retain_custody(&context, &output, true, &master, None, &report).unwrap();
        assert!(retain_custody(&context, &output, true, &[32; 32], None, &report).is_err());
        assert!(retain_custody(
            &context,
            &output,
            false,
            &master,
            Some((Zeroizing::new(scalar(share)), Zeroizing::new(scalar(17)))),
            &report
        )
        .is_err());
        assert_eq!(std::fs::read(output.join(SECRETS)).unwrap(), before);
        let receipt = serde_json::to_vec(&report).unwrap();
        context.role = if role == XmrLocalShareRoleV11::ClaimReceiver {
            XmrLocalShareRoleV11::RefundReceiver
        } else {
            XmrLocalShareRoleV11::ClaimReceiver
        };
        assert!(
            reopen_custody(
                &private_directory(&output).unwrap(),
                &context,
                &master,
                &receipt
            )
            .is_err(),
            "SDK rejects wrong role even with unchanged receipt"
        );
        context.role = role;
        let mut wrong_scope = report;
        wrong_scope.route_id = [99; 32];
        assert!(retain_custody(&context, &output, true, &master, None, &wrong_scope).is_err());
        std::fs::remove_file(output.join(NULLIFIERS)).unwrap();
        assert!(reopen_custody(
            &private_directory(&output).unwrap(),
            &context,
            &master,
            &receipt
        )
        .is_err());
        assert!(
            !output.join(NULLIFIERS).exists(),
            "reopen must not recreate absent nullifiers"
        );
        let dir = private_directory(&output).unwrap();
        write_new(&dir, NULLIFIERS, b"").unwrap();
        assert!(reopen_custody(&dir, &context, &master, &receipt).is_err());
        assert_eq!(
            std::fs::metadata(output.join(NULLIFIERS)).unwrap().len(),
            0,
            "reopen must not create schema"
        );
    }
}

#[test]
fn enrollment_publication_refuses_unsafe_roots_existing_outputs_and_retained_staging() {
    for name in ["custody", "custody.preparing-v23"] {
        for kind in ["file", "symlink", "hardlink"] {
            let root = root();
            let sentinel = root.path().join("sentinel");
            std::fs::write(&sentinel, b"unchanged").unwrap();
            let target = root.path().join(name);
            match kind {
                "file" => std::fs::write(&target, b"unchanged").unwrap(),
                "symlink" => symlink(&sentinel, &target).unwrap(),
                _ => std::fs::hard_link(&sentinel, &target).unwrap(),
            }
            assert!(Publication::create(&root.path().join("custody")).is_err());
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
        }
    }
    let root = root();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Publication::create(&root.path().join("custody")).is_err());
}

/// Requires the sibling binary from the SAME `cargo test --lib --tests`
/// build. Absence is a dependency failure, never an ignored or skipped test.
#[test]
fn enrollment_cli_positive_authenticates_signed_public_context_without_f6_or_route_stores() {
    use crate::production_config::*;
    use crate::production_inputs::*;
    use deployment_registry::{
        AuthoritySetV1, RegistrySignatureV1, RegistryStoreV1, RegistryValidationPolicyV1,
        SignedRegistryV1,
    };
    use std::process::{Command, Stdio};
    let executable = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("dom-interopd");
    let metadata = std::fs::symlink_metadata(&executable)
        .expect("cargo --lib --tests must build sibling dom-interopd binary");
    assert!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.mode() & 0o111 != 0
    );
    let f = crate::route_time_test_common::fixture();
    let mut manifest = f.registry.manifest().clone();
    let mut terms = [f.upstream.clone(), f.downstream.clone()];
    let [up, down] = &mut terms;
    registry_fixture::configure(&mut manifest, [up, down]).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    manifest.valid_from = now - 60;
    manifest.expires_at = now + 86_400;
    let profile = XmrAdapterProfileV1::new(XmrNetwork::Stagenet, 3, 2).unwrap();
    let t = CrossCurveSecret252::from_little_endian(scalar(7)).unwrap();
    let u = CrossCurveSecret252::from_little_endian(scalar(11)).unwrap();
    let claim = t.public_claim().unwrap();
    let refund_claim = u.public_claim().unwrap();
    terms[0].counterparty_leg.mechanism = LockMechanism::CrossCurveSharedSpend;
    registry_fixture::profile_for_terms_v24(&terms[0], &profile).unwrap();
    terms[0].adaptor_point_sec1 = claim.secp_compressed;
    // Negotiate the public compensation envelope BEFORE terms/proofs freeze.
    // This extends the existing two-proof CLI campaign, not a second graph.
    terms[0].fee_limit.counterparty_max = 3;
    let point = |marker| {
        let mut bytes = [marker; 33];
        bytes[0] = 2;
        bytes
    };
    let policy = xmr_refund_policy::compensation::XmrCompensationPolicyV11 {
        settlement_id: terms[0].settlement_id.0,
        session_id: terms[0].session_id.0,
        dom_chain_id: terms[0].dom_leg.chain_id.0,
        xmr_chain_id: terms[0].counterparty_leg.chain_id.0,
        dom_funder: terms[0].dom_leg.refund_to.0,
        xmr_funder: terms[0].counterparty_leg.refund_to.0,
        claim_principal_commitment: point(0x41),
        claim_change_commitment: point(0x42),
        refund_recipient_commitment: point(0x43),
        compensation_recipient_commitment: point(0x44),
        quote_dom_numerator: 5,
        quote_xmr_denominator: 6,
        xmr_principal_piconero: 60,
        dom_principal_noms: 50,
        volatility_margin_bps: 2500,
        collateral_confirmations: 3,
        cancel_height: 400,
        compensation_height: 424,
        cooperative_window_blocks: 13,
        reveal_safety_blocks: 10,
        claim_fee_noms: 1,
        cancel_fee_noms: 1,
        refund_fee_noms: 1,
        compensation_fee_noms: 5,
        bounded_availability_v23: Some(
            xmr_refund_policy::compensation::XmrRecoveryAvailabilityV23 {
                maximum_unavailability_blocks: 1,
                observation_delay_blocks: 1,
                cancel_inclusion_blocks: 1,
                refund_inclusion_blocks: 1,
            },
        ),
    };
    terms[0].assurance_policy_hash = Some(policy.policy_hash().unwrap());
    policy.validate_for(&terms[0]).unwrap();
    let up = &terms[0];
    let digest = proof_context_hash(
        &profile,
        &XmrProofContextV1 {
            settlement_id: up.settlement_id.0,
            chain_id: up.counterparty_leg.chain_id.0,
            asset_id: up.counterparty_leg.asset_id.0,
            amount_piconero: up.counterparty_leg.amount,
            min_confirmations: up.counterparty_leg.finality.min_confirmations,
            max_reorg_depth: up.counterparty_leg.finality.max_reorg_depth,
        },
    )
    .unwrap();
    let proof = prove_bound(
        &t,
        up.settlement_id.0,
        digest,
        ROLE_XMR_SHARED_SPEND,
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let refund = prove_bound(
        &u,
        up.settlement_id.0,
        digest,
        ROLE_XMR_REFUND_SHARE,
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let binding = XmrSetupBindingV1 {
        settlement_id: up.settlement_id.0,
        terms_hash: up.terms_hash().unwrap(),
        dleq: proof,
        funding_tx_hash: [0x73; 32],
        expected_amount_piconero: u64::try_from(up.counterparty_leg.amount).unwrap(),
        destination: "5PublicOfflineFixture".into(),
        combined_spend_public_key: xmr_crypto::combine_public_shares(
            claim.ed_compressed,
            refund_claim.ed_compressed,
        )
        .unwrap(),
    };
    let public = ProductionXmrEnrollmentBundleV23::new(
        refund,
        refund_claim.secp_compressed,
        xmr_refund_adaptor::DomRefundAdaptorExecutor::new(refund_claim).profile_hash(),
        100_000,
        "5RefundOfflineFixture".into(),
    )
    .unwrap();
    let leg = ProductionXmrLegSetupV1::new(ProductionRoutePositionV1::Upstream, profile, binding)
        .unwrap()
        .with_native_enrollment_v23(public)
        .unwrap();
    let route = [0x74; 32];
    // This pre-economic command enrolls ONE selected position; it is not an
    // assertion that the unselected leg has completed participant admission.
    let participants = ProductionParticipantBindingBundleV1::new_with_all_counterparty_bindings(
        route,
        vec![],
        vec![],
        vec![],
        vec![leg],
    )
    .unwrap();
    let registry_secrets = [[3; 32], [4; 32], [5; 32]];
    let registry_keys = registry_secrets
        .iter()
        .map(|secret| {
            f.secp
                .sign_bip340(secret, &[0x30; 32], &[0x31; 32])
                .unwrap()
                .1
        })
        .collect();
    let authorities = ProductionAuthorityBundleV1::new(
        AuthoritySetV1::new(2, registry_keys).unwrap(),
        f.policy_authorities.clone(),
        f.evidence_authorities.clone(),
    )
    .unwrap();
    let registry_digest = manifest.manifest_digest().unwrap();
    let signatures = registry_secrets
        .iter()
        .enumerate()
        .map(|(index, secret)| RegistrySignatureV1 {
            signer_index: index as u16,
            signature: f
                .secp
                .sign_bip340(secret, &registry_digest, &[0x32 + index as u8; 32])
                .unwrap()
                .0,
        })
        .collect();
    let signed = SignedRegistryV1::new(&manifest, signatures).unwrap();
    let roster_legs = std::array::from_fn(|index| ProductionRosterLegV1 {
        position: if index == 0 {
            ProductionRoutePositionV1::Upstream
        } else {
            ProductionRoutePositionV1::Downstream
        },
        session_id: terms[index].session_id.0,
        roster_snapshot: [0x50 + index as u8; 32],
        policy_version: terms[index].policy_version,
        members: std::array::from_fn(|member| ProductionRosterMemberV1 {
            participant_id: terms[index].roster[member],
            xonly_key: f
                .secp
                .sign_bip340(&[0x61 + member as u8; 32], &[0x34; 32], &[0x35; 32])
                .unwrap()
                .1,
            role: if member == 0 {
                relay::SenderRoleV1::Initiator
            } else {
                relay::SenderRoleV1::Solver
            },
        }),
    });
    let roster =
        ProductionRelayRosterBundleV1::new(manifest.network_id, route, roster_legs).unwrap();
    let parent = root();
    let state = parent.path();
    let mut config = None;
    for mode in [
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapModeV1::ReopenExisting,
    ] {
        let value = enrollment_fixture_v23(
            mode,
            |pins| {
                pins.network_id = manifest.network_id;
                pins.route_id = route;
                pins.registry_manifest_digest = registry_digest;
                pins.registry_minimum_epoch = manifest.epoch;
                pins.registry_authority_set_digest =
                    authorities.registry().authority_set_digest().unwrap();
                pins.time_policy_authority_set_digest =
                    authorities.time_policy().authority_set_digest().unwrap();
                pins.time_evidence_authority_set_digest =
                    authorities.time_evidence().authority_set_digest().unwrap();
                pins.upstream_terms_digest = terms[0].terms_hash().unwrap();
                pins.downstream_terms_digest = terms[1].terms_hash().unwrap();
                pins.route_scope_digest =
                    route_time_anchor::route_scope_digest(&terms[0], &terms[1]).unwrap();
                pins.participant_bindings_digest = participants.bundle_digest().unwrap();
                pins.relay_binding_digest = roster.bundle_digest().unwrap();
            },
            [&terms[0], &terms[1]],
        );
        let name = if mode == ProductionBootstrapModeV1::Create {
            PRODUCTION_CREATE_CONFIG_FILE_V11
        } else {
            PRODUCTION_REOPEN_CONFIG_FILE_V11
        };
        owner_write(&state.join(name), &value.canonical_bytes().unwrap());
        config = Some(value);
    }
    let config = config.unwrap();
    let inputs = state.join("inputs");
    std::fs::create_dir(&inputs).unwrap();
    std::fs::set_permissions(&inputs, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (role, bytes) in [
        (
            ProductionPathRoleV1::RegistryAuthorities,
            authorities.canonical_bytes().unwrap(),
        ),
        (
            ProductionPathRoleV1::UpstreamTerms,
            terms[0].canonical_bytes().unwrap(),
        ),
        (
            ProductionPathRoleV1::DownstreamTerms,
            terms[1].canonical_bytes().unwrap(),
        ),
        (
            ProductionPathRoleV1::ParticipantBindings,
            participants.canonical_bytes().unwrap(),
        ),
        (
            ProductionPathRoleV1::RelayRoster,
            roster.canonical_bytes().unwrap(),
        ),
    ] {
        owner_write(&state.join(config.relative_path(role)), &bytes);
    }
    let registry_path = state.join(config.relative_path(ProductionPathRoleV1::RegistryStore));
    {
        let mut registry = RegistryStoreV1::create(&registry_path).unwrap();
        registry
            .install(
                &signed,
                authorities.registry(),
                &f.secp,
                RegistryValidationPolicyV1 {
                    now_seconds: now,
                    expected_network_id: manifest.network_id,
                    minimum_epoch: manifest.epoch,
                },
            )
            .unwrap();
    }
    std::fs::set_permissions(&registry_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let participant = terms[0].counterparty_leg.beneficiary.0;
    let command = |output: &Path, reopen: bool, request: &serde_json::Value| {
        let mut cmd = Command::new(&executable);
        cmd.args(["prepare-xmr-enrollment-v23", "--state-dir"])
            .arg(state)
            .args(["--position", "upstream", "--output-dir"])
            .arg(output);
        if reopen {
            cmd.arg("--reopen");
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(request).unwrap())
            .unwrap();
        child.wait_with_output().unwrap()
    };
    let output = state.join("custody");
    let mut request = serde_json::json!({"schema":SCHEMA,"local_participant_id":participant,
        "master_key_hex":hex::encode([0x67;32]),"spend_share_le_hex":hex::encode(scalar(11)),"view_key_le_hex":hex::encode(scalar(17))});
    let created = command(&output, false, &request);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let public: PreparedXmrEnrollmentReportV23 = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(public.role, "claim_receiver");
    assert_eq!(public.settlement_id, terms[0].settlement_id.0);
    assert!(!public.network_access);
    request
        .as_object_mut()
        .unwrap()
        .remove("spend_share_le_hex");
    request.as_object_mut().unwrap().remove("view_key_le_hex");
    let reopened = command(&output, true, &request);
    assert!(
        reopened.status.success(),
        "{}",
        String::from_utf8_lossy(&reopened.stderr)
    );
    assert_eq!(created.stdout, reopened.stdout);
    request["master_key_hex"] = serde_json::json!(hex::encode([0x68; 32]));
    assert!(!command(&output, true, &request).status.success());
    let leg_output = state.join(&config.universal_v11().unwrap().legs[0].authority_bundle);
    let leg_input = serde_json::json!({"schema":"DOM-XMR-LEG-V23","compensation_policy":policy.to_bytes().unwrap(),
        "resources":{"local_participant_id":participant,"secret_store":"custody/secrets.sqlite",
            "nullifier_store":"custody/nullifiers.sqlite","sidecar_socket":"external/sidecar.sock","sidecar_timeout_ms":1000,
            "custody_directory":"archive-xmr","sealing_key_file":"external/seal.key","custody_id":vec![0x69u8;32]}});
    let leg_command = || {
        let mut child = Command::new(&executable)
            .args(["prepare-xmr-leg-v23", "--state-dir"])
            .arg(state)
            .args(["--position", "upstream", "--output-file"])
            .arg(&leg_output)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&leg_input).unwrap())
            .unwrap();
        child.wait_with_output().unwrap()
    };
    let leg_result = leg_command();
    assert!(
        leg_result.status.success(),
        "{}",
        String::from_utf8_lossy(&leg_result.stderr)
    );
    let leg_bytes = std::fs::read(&leg_output).unwrap();
    let leg_report: serde_json::Value = serde_json::from_slice(&leg_result.stdout).unwrap();
    assert_eq!(
        leg_report["authority_bundle_digest"],
        hex::encode(ProductionUniversalLegV11::bundle_digest(&leg_bytes).unwrap())
    );
    assert_eq!(leg_report["network_access"], false);
    let leg_wire: serde_json::Value = serde_json::from_slice(&leg_bytes).unwrap();
    assert_eq!(leg_wire["authority"]["family"], "XMR_ENROLLMENT_V23");
    assert_eq!(
        leg_wire["authority"]["parameters"]["secret_store"],
        "custody/secrets.sqlite"
    );
    assert!(
        !leg_command().status.success(),
        "the immutable bundle cannot be overwritten"
    );
    assert_eq!(std::fs::read(&leg_output).unwrap(), leg_bytes);
    assert!(!state.join("external").exists());
    assert!(
        !state.join("archive-xmr").exists(),
        "writer does not create graph custody"
    );
    for role in [
        ProductionPathRoleV1::RouteStore,
        ProductionPathRoleV1::TimeAnchorStore,
        ProductionPathRoleV1::DomWallet,
        ProductionPathRoleV1::TimePolicy,
        ProductionPathRoleV1::TimeEvidence,
    ] {
        assert!(!state.join(config.relative_path(role)).exists());
    }
    assert!(
        !state.join("state").exists(),
        "no runtime/F6 store provisioning is allowed"
    );
    // Missing public proof must fail before a new custody directory exists.
    std::fs::remove_file(
        state.join(config.relative_path(ProductionPathRoleV1::ParticipantBindings)),
    )
    .unwrap();
    assert!(!command(&state.join("refused"), true, &request)
        .status
        .success());
    assert!(!state.join("refused").exists());
}

fn owner_write(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
