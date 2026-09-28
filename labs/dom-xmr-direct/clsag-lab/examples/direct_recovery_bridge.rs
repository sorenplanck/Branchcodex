//! Separate-process real puzzle -> original XMR peer share. No funds or nodes.
#[path = "support/direct_recovery_bridge.rs"]
mod direct_bridge;

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
use dalek_ff_group::EdwardsPoint as GroupPoint;
use dxp1_clsag_lab::xmr_recovery::{
    XmrDirectRecoveryLink, XmrDirectRecoveryMaterial, XmrRecoveryRoster,
};
use frost::{curve::Ed25519, dkg::Interpolation, Participant, ThresholdKeys, ThresholdParams};
use rand_core::OsRng;
use serde_json::json;
use std::{collections::HashMap, path::PathBuf, time::Instant};
use zeroize::Zeroizing;

fn main() {
    let bridge = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("absolute direct bridge path required"),
    );
    let started = Instant::now();
    let ids = [Participant::new(1).unwrap(), Participant::new(2).unwrap()];
    let shares = [
        Zeroizing::new(Scalar::random(&mut OsRng)),
        Zeroizing::new(Scalar::random(&mut OsRng)),
    ];
    let points = [*shares[0] * G, *shares[1] * G];
    let roster = XmrRecoveryRoster::new(Scalar::random(&mut OsRng).to_bytes(), points).unwrap();
    let public = HashMap::from([
        (ids[0], GroupPoint(points[0])),
        (ids[1], GroupPoint(points[1])),
    ]);
    let [own, peer]: [ThresholdKeys<Ed25519>; 2] = shares
        .into_iter()
        .enumerate()
        .map(|(i, share)| {
            ThresholdKeys::new(
                ThresholdParams::new(2, 2, ids[i]).unwrap(),
                Interpolation::Constant(vec![Scalar::ONE; 2]),
                share,
                public.clone(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let material = XmrDirectRecoveryMaterial::create(&peer, &roster).unwrap();
    let capsule = direct_bridge::DirectPublicCapsule::prepare(&bridge, material);
    let binding = capsule.binding();
    let link = XmrDirectRecoveryLink::new(
        &roster,
        ids[1],
        capsule.context(),
        capsule.public_key(),
        binding,
    )
    .unwrap();
    drop(peer);
    let (opening, mut report) = capsule.open();
    assert!(link
        .recover_after_opening(
            &roster,
            ids[1],
            binding,
            Zeroizing::new(*opening + Scalar::ONE)
        )
        .is_err());
    let recovered = link
        .recover_after_opening(&roster, ids[1], binding, opening)
        .unwrap();
    assert_eq!(**recovered.original_secret_share() * G, points[1]);
    assert_eq!(recovered.group_key(), own.group_key());
    assert_eq!(recovered.current_offset(), Scalar::ZERO);
    let offset = Scalar::random(&mut OsRng);
    assert_eq!(
        recovered.offset(offset).group_key().0,
        roster.spend_key() + offset * G
    );
    report["experiment"] = json!("direct capsule across producer/public verifier/Rust roster");
    report["original_peer_share_dropped"] = json!(true);
    report["aggregate_private_key_reconstructed"] = json!(false);
    report["restored_original_additive_peer_keys"] = json!(true);
    report["stealth_offset_applied_after_recovery"] = json!(true);
    report["forged_opening_rejected"] = json!(true);
    report["total_seconds"] = json!(started.elapsed().as_secs_f64());
    report["funding_included"] = json!(false);
    report["protocol_security_proven"] = json!(false);
    report["minimum_adversarial_delay_proven"] = json!(false);
    report["mainnet_latency_measurement"] = json!(false);
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
