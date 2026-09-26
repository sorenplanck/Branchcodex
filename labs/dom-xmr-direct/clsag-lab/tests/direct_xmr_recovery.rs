//! Public binding/reconstruction only, not proof verification or deposit policy.
use std::collections::HashMap;

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
use dalek_ff_group::EdwardsPoint as GroupPoint;
use dxp1_clsag_lab::xmr_recovery::{
    XmrDirectRecoveryLink, XmrDirectRecoveryMaterial, XmrRecoveryRoster,
};
use frost::{curve::Ed25519, dkg::Interpolation, Participant, ThresholdKeys, ThresholdParams};
use rand_core::OsRng;
use zeroize::Zeroizing;

fn fixture() -> (XmrRecoveryRoster, [ThresholdKeys<Ed25519>; 2]) {
    let ids = [Participant::new(1).unwrap(), Participant::new(2).unwrap()];
    let shares = [Scalar::random(&mut OsRng), Scalar::random(&mut OsRng)];
    let points = shares.map(|s| s * G);
    let public = HashMap::from([
        (ids[0], GroupPoint(points[0])),
        (ids[1], GroupPoint(points[1])),
    ]);
    let keys = std::array::from_fn(|i| {
        ThresholdKeys::new(
            ThresholdParams::new(2, 2, ids[i]).unwrap(),
            Interpolation::Constant(vec![Scalar::ONE; 2]),
            Zeroizing::new(shares[i]),
            public.clone(),
        )
        .unwrap()
    });
    (XmrRecoveryRoster::new([37; 32], points).unwrap(), keys)
}

fn link(
    roster: &XmrRecoveryRoster,
    role: Participant,
    binding: [u8; 32],
) -> Result<XmrDirectRecoveryLink, dxp1_clsag_lab::recovery::RecoveryError> {
    XmrDirectRecoveryLink::new(
        roster,
        role,
        roster.recovery_domain(role)?,
        roster.share_key(role)?,
        binding,
    )
}

#[test]
fn direct_opening_restores_only_original_peer_and_preserves_offset_order() {
    let (roster, [own, peer]) = fixture();
    let id = peer.params().i();
    let material = XmrDirectRecoveryMaterial::create(&peer, &roster).unwrap();
    assert_eq!(material.context, roster.recovery_domain(id).unwrap());
    assert_eq!(material.public_key, *material.secret * G);
    let link = link(&roster, id, [13; 32]).unwrap();
    drop(peer);
    let recovered = link
        .recover_after_opening(&roster, id, [13; 32], material.secret)
        .unwrap();
    assert_eq!(recovered.group_key(), own.group_key());
    assert_eq!(recovered.current_offset(), Scalar::ZERO);
    assert_eq!(
        **recovered.original_secret_share() * G,
        roster.share_key(id).unwrap()
    );
    let offset = Scalar::random(&mut OsRng);
    assert_eq!(
        recovered.offset(offset).group_key().0,
        roster.spend_key() + offset * G
    );
}

#[test]
fn direct_link_rejects_other_capsule_reservation_role_and_scalar() {
    let (roster, keys) = fixture();
    let id = keys[1].params().i();
    let material = XmrDirectRecoveryMaterial::create(&keys[1], &roster).unwrap();
    let original_link = link(&roster, id, [13; 32]).unwrap();
    let other = XmrRecoveryRoster::new(
        [38; 32],
        [
            roster.share_key(keys[0].params().i()).unwrap(),
            roster.share_key(id).unwrap(),
        ],
    )
    .unwrap();
    for (r, role, capsule, scalar) in [
        (&other, id, [13; 32], *material.secret),
        (&roster, keys[0].params().i(), [13; 32], *material.secret),
        (&roster, id, [14; 32], *material.secret),
        (&roster, id, [13; 32], *material.secret + Scalar::ONE),
    ] {
        assert!(original_link
            .recover_after_opening(r, role, capsule, Zeroizing::new(scalar))
            .is_err());
    }
    assert!(link(&roster, id, [0; 32]).is_err());
    assert!(link(&roster, Participant::new(3).unwrap(), [13; 32]).is_err());
    assert_ne!(
        original_link.binding(),
        link(&roster, id, [14; 32]).unwrap().binding()
    );
    assert_ne!(
        original_link.binding(),
        link(&other, id, [13; 32]).unwrap().binding()
    );
}

#[test]
fn direct_link_rejects_capsule_metadata_mismatch_before_any_opening() {
    let (roster, keys) = fixture();
    let peer = keys[1].params().i();
    let own = keys[0].params().i();
    let context = roster.recovery_domain(peer).unwrap();
    let public = roster.share_key(peer).unwrap();
    assert!(XmrDirectRecoveryLink::new(&roster, peer, [0; 32], public, [13; 32]).is_err());
    assert!(XmrDirectRecoveryLink::new(
        &roster,
        peer,
        roster.recovery_domain(own).unwrap(),
        public,
        [13; 32]
    )
    .is_err());
    assert!(XmrDirectRecoveryLink::new(
        &roster,
        peer,
        context,
        roster.share_key(own).unwrap(),
        [13; 32]
    )
    .is_err());
}

#[test]
fn direct_material_rejects_already_offset_or_scaled_keys() {
    let (roster, keys) = fixture();
    assert!(
        XmrDirectRecoveryMaterial::create(&keys[1].clone().offset(Scalar::ONE), &roster).is_err()
    );
    assert!(XmrDirectRecoveryMaterial::create(
        &keys[1].clone().scale(Scalar::from(2u64)).unwrap(),
        &roster
    )
    .is_err());
}
