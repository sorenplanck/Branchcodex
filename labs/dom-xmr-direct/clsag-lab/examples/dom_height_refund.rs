//! Native-height refund candidate, DOM-only. No reserve-share capsule exists.
//! Does not establish safe cross-chain deadlines, XMR recovery or atomicity.
#[path = "support/dom_regtest.rs"]
mod dom_regtest;

use dom_scriptless_primitives::SecretScalar;
use dom_serialization::DomSerialize;
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let total = Instant::now();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!(
            "dom-height-refund-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    fs::create_dir(&root).unwrap();
    println!("height refund artifacts: {}", root.display());
    const NOT_BEFORE: u64 = 12;

    let mut abandoned =
        dom_regtest::FundedDom::new_with_height_refund(&root.join("abandoned"), NOT_BEFORE).await;
    let signed_before = abandoned.height_refund_transaction().to_bytes().unwrap();
    abandoned.discard_reserve_signing_material();
    abandoned.assert_height_refund_locked().await;
    abandoned.mine_to_refund_height().await;
    assert_eq!(
        signed_before,
        abandoned.height_refund_transaction().to_bytes().unwrap()
    );
    let (refund_height, onward_height) = abandoned.include_height_refund_and_spend().await;

    let mut claimed =
        dom_regtest::FundedDom::new_with_height_refund(&root.join("claimed"), NOT_BEFORE).await;
    claimed.assert_height_refund_locked().await;
    let witness = SecretScalar::from_be_bytes([1; 32]).unwrap();
    let offer = claimed.offer(
        &witness.public_key().unwrap().to_compressed_bytes(),
        [95; 32],
    );
    claimed.discard_reserve_signing_material();
    let claim = offer.complete(&witness, &claimed.context().await).unwrap();
    let (_, claim_height) = claimed.include(&claim).await;
    assert!(claim_height < NOT_BEFORE);
    let claim_onward_height = claimed.spend_claim_output().await;
    claimed.mine_to_refund_height().await;
    claimed
        .assert_spent_rejection(&claimed.height_refund_transaction())
        .await;

    let report = json!({
        "experiment":"DOM pre-signed height refund without reserve-share disclosure",
        "atomic_swap":false,"bitcoin_involved":false,"xmr_leg_exercised":false,
        "network":"owned offline regtest","setup_centralized":true,"mainnet_latency_measurement":false,
        "dom_reserve_share_capsule_exists":false,"refund_signed_before_shared_funding":true,
        "original_reserve_signing_material_dropped":true,"refund_bytes_unchanged":true,
        "premature_refund_rejected_by_node":true,"not_before_height":NOT_BEFORE,
        "abandoned_funding_height":abandoned.funding_height,
        "refund_height":refund_height,"refund_onward_height":onward_height,
        "refund_included_after_height":true,"refund_onward_spent":true,
        "claim_height":claim_height,"claim_onward_height":claim_onward_height,
        "cooperative_claim_before_height":true,"claim_onward_spent":true,
        "late_refund_after_claim_rejected_as_spent":true,
        "total_seconds":total.elapsed().as_secs_f64(),"dom_regtest_fast_pow":true
    });
    fs::write(
        root.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
