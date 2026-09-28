//! Funded DOM-only abandonment experiment. Uses a fresh local node and test
//! coins. Public solver receives no dealer material. RSA setup is still
//! centralized; this is NOT secure timed recovery or an atomic swap.
#[path = "support/dom_regtest.rs"]
mod dom_regtest;
#[path = "support/recovery_bridge.rs"]
mod recovery_bridge;

use curve25519_dalek::scalar::Scalar;
use dxp1_clsag_lab::{
    dom_recovery::{DomRecoveryLink, DomRecoveryMaterial},
    dom_reserve::{ReserveIntent, ReserveShare},
};
use rand_core::{OsRng, RngCore};
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let bridge = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("absolute bridge binary path"),
    );
    assert!(bridge.is_absolute() && bridge.is_file());
    let count: u16 = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "198".into())
        .parse()
        .unwrap();
    assert!([6, 132, 166, 198].contains(&count));
    let total = Instant::now();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!(
            "dom-recovery-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    fs::create_dir(&root).unwrap();
    println!("recovery artifacts: {}", root.display());
    let chain = *dom_consensus::derive_chain_id(
        dom_wallet::Network::Regtest.magic(),
        &dom_core::Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
    )
    .as_bytes();
    let shares = [
        ReserveShare::generate_for_recovery(&mut OsRng).unwrap(),
        ReserveShare::generate_for_recovery(&mut OsRng).unwrap(),
    ];
    let mut session = [0; 32];
    OsRng.fill_bytes(&mut session);
    let intent = ReserveIntent::new(
        dom_regtest::RESERVE_VALUE,
        chain,
        session,
        [47; 32],
        shares.each_ref().map(|s| s.public_key()),
    )
    .unwrap();
    let proofs = [
        shares[0].prove(&intent, 0).unwrap(),
        shares[1].prove(&intent, 1).unwrap(),
    ];
    let reserve = intent.authorize(proofs).unwrap();
    let mut material =
        DomRecoveryMaterial::create(&shares[1], &reserve, 1, count, &mut OsRng).unwrap();
    let plan = material.plan.clone();
    let cross_curve = material.cross_curve.clone();
    let capsule = recovery_bridge::PublicCapsule::prepare(
        &bridge,
        &plan,
        Zeroizing::new(std::mem::take(&mut material.puzzle_shares)),
    );
    drop(material);
    let link = DomRecoveryLink::new(
        &reserve,
        1,
        &plan,
        &cross_curve,
        &capsule.challenge,
        &capsule.window,
    )
    .unwrap();
    let capsule_seconds = total.elapsed().as_secs_f64();
    println!("capsule checked; producer exited; funding fresh DOM test reserve");
    // This is only a laboratory funding decision. Setup still knows RSA factors.
    let funding = Instant::now();
    let mut dom =
        dom_regtest::FundedDom::new_prepared(&root.join("dom"), shares, reserve.clone()).await;
    let funding_seconds = funding.elapsed().as_secs_f64();
    dom.abandon_peer();
    let recovery = Instant::now();
    // The retained public verifier receives only the next solve index.
    let (delayed, solve_evidence) = capsule.solve().expect("no valid delayed share remained");
    let mut forged = delayed.clone();
    forged.scalar += Scalar::ONE;
    assert!(link.recover_after_opening(&reserve, 1, forged).is_err());
    let recovered = link.recover_after_opening(&reserve, 1, delayed).unwrap();
    let (refund_height, onward_height) = dom.refund_after_recovery(recovered).await;
    let report = json!({"experiment":"DOM reserve refund after peer abandonment and public puzzle solve",
        "atomic_swap":false,"bitcoin_involved":false,"xmr_leg_exercised":false,
        "setup_centralized":true,"minimum_adversarial_delay_proven":false,
        "public_solver_after_producer_exit":true,"original_peer_share_dropped":true,
        "prepared_claim_keys_dropped":true,"dom_reserve_opening_reconstructed":false,
        "cross_curve_share_link_verified":true,"forged_delayed_share_rejected":true,
        "participants":count,"threshold":count/2+1,"opened":count/2,"squarings":200000,
        "dom_reserve_funded":true,"dom_refund_included":true,"dom_refund_onward_spend_included":true,
        "funding_height":dom.funding_height,"refund_height":refund_height,"onward_height":onward_height,
        "capsule_preparation_verification_seconds":capsule_seconds,"funding_seconds":funding_seconds,
        "public_solve_seconds":solve_evidence.sequential_solve_seconds,"recovery_verification_refund_onward_seconds":recovery.elapsed().as_secs_f64(),
        "public_solve_attempted_indexes":solve_evidence.attempted_indexes,
        "public_solve_rejected_indexes":solve_evidence.rejected_indexes,
        "recovery_session_seconds":solve_evidence.verification_and_solve_seconds,
        "public_offer_verifications":solve_evidence.public_offer_verifications,
        "public_offer_verification_seconds":solve_evidence.public_verification_seconds,
        "setup_verification_seconds":solve_evidence.setup_verification_seconds,
        "setup_verified_before_offer":solve_evidence.setup_verified_before_offer,
        "public_offer_verified_before_funding":solve_evidence.public_offer_verified_before_funding,
        "public_verifier_started_before_offer":true,
        "total_seconds":total.elapsed().as_secs_f64(),"mainnet_latency_measurement":false,"dom_regtest_fast_pow":true});
    fs::write(
        root.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
