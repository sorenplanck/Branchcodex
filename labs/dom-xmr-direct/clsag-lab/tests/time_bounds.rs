//! Test against the real timestamp validators, NOT full block/PoW validation.
use dom_consensus::{
    block::{validate_future_timestamp_with_limit, validate_parent_timestamp_progression},
    BlockHeader,
};
use dom_core::{BlockHeight, Timestamp, TARGET_SPACING};
use dom_serialization::DomDeserialize;
use dxp1_clsag_lab::time_bounds::{AssumedDomAnchor, DomClockNetwork, TimingError};

fn timestamp_fixture(height: u64, timestamp: u64) -> BlockHeader {
    // Intentionally not a valid block. Only height/time arithmetic is tested.
    let mut header = BlockHeader::from_bytes(&vec![0; BlockHeader::MIN_SERIALIZED_SIZE]).unwrap();
    header.height = BlockHeight(height);
    header.timestamp = Timestamp(timestamp);
    header
}

#[test]
fn calculated_boundary_matches_native_parent_and_future_rules() {
    let anchor = AssumedDomAnchor::new(BlockHeight(10), Timestamp(1000));
    for network in [
        DomClockNetwork::Mainnet,
        DomClockNetwork::Testnet,
        DomClockNetwork::Regtest,
    ] {
        for blocks in [1, 12, 121, 301] {
            let mut parent = timestamp_fixture(10, 1000);
            for height in 11..=10 + blocks {
                let next = timestamp_fixture(height, 1000 + height - 10);
                validate_parent_timestamp_progression(&next, &parent).unwrap();
                parent = next;
            }
            let ahead = 5;
            let first = anchor
                .earliest_refund_time(parent.height, network, ahead)
                .unwrap();
            assert!(validate_future_timestamp_with_limit(
                &parent,
                Timestamp(first.0 - 1 + ahead),
                network.future_tolerance()
            )
            .is_err());
            validate_future_timestamp_with_limit(
                &parent,
                Timestamp(first.0 + ahead),
                network.future_tolerance(),
            )
            .unwrap();
        }
    }
}

#[test]
fn average_block_spacing_does_not_supply_a_lower_bound() {
    let anchor = AssumedDomAnchor::new(BlockHeight(10), Timestamp(1000));
    let earliest = anchor
        .earliest_refund_time(BlockHeight(12), DomClockNetwork::Mainnet, 0)
        .unwrap();
    assert_eq!(earliest, Timestamp(882));
    assert!(earliest.0 < 1000 + 2 * TARGET_SPACING);
    let a = timestamp_fixture(11, 1001);
    let b = timestamp_fixture(12, 1002);
    validate_parent_timestamp_progression(&b, &a).unwrap();
    validate_future_timestamp_with_limit(
        &b,
        Timestamp(1000),
        DomClockNetwork::Mainnet.future_tolerance(),
    )
    .unwrap();
}

#[test]
fn chosen_height_is_minimal_and_strictly_after_deadline() {
    let anchor = AssumedDomAnchor::new(BlockHeight(10), Timestamp(1000));
    for deadline in [1000, 1100, 1500] {
        let height = anchor
            .refund_height_strictly_after(Timestamp(deadline), DomClockNetwork::Mainnet, 5)
            .unwrap();
        assert_eq!(
            anchor
                .earliest_refund_time(height, DomClockNetwork::Mainnet, 5)
                .unwrap(),
            Timestamp(deadline + 1)
        );
        assert_eq!(
            anchor
                .earliest_refund_time(BlockHeight(height.0 - 1), DomClockNetwork::Mainnet, 5)
                .unwrap(),
            Timestamp(deadline)
        );
    }
}

#[test]
fn arithmetic_never_wraps_and_reached_heights_are_not_future_protection() {
    let anchor = AssumedDomAnchor::new(BlockHeight(10), Timestamp(1000));
    for height in [0, 9, 10] {
        assert_eq!(
            anchor.earliest_refund_time(BlockHeight(height), DomClockNetwork::Mainnet, 0),
            Err(TimingError::HeightAlreadyReached)
        );
    }
    assert_eq!(
        anchor.refund_height_strictly_after(Timestamp(u64::MAX), DomClockNetwork::Mainnet, 0),
        Err(TimingError::Overflow)
    );
    assert_eq!(
        anchor.earliest_refund_time(BlockHeight(11), DomClockNetwork::Mainnet, u64::MAX),
        Err(TimingError::Overflow)
    );
    let late = AssumedDomAnchor::new(BlockHeight(u64::MAX), Timestamp(1000));
    assert_eq!(
        late.refund_height_strictly_after(Timestamp(1), DomClockNetwork::Mainnet, 0),
        Err(TimingError::Overflow)
    );
    let impossible = AssumedDomAnchor::new(BlockHeight(10), Timestamp(u64::MAX));
    assert_eq!(
        impossible.refund_height_strictly_after(Timestamp(1), DomClockNetwork::Mainnet, 0),
        Err(TimingError::Overflow)
    );
    assert_eq!(
        impossible.earliest_refund_time(BlockHeight(11), DomClockNetwork::Mainnet, 0),
        Err(TimingError::Overflow)
    );
    assert_eq!(
        AssumedDomAnchor::new(BlockHeight(0), Timestamp(0))
            .earliest_refund_time(BlockHeight(1), DomClockNetwork::Mainnet, 0)
            .unwrap(),
        Timestamp(0)
    );
}
