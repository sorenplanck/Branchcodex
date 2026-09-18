//! The two spellings of "which Solana cluster" are held together here, the
//! same way `xmr-profile` holds `XmrNetworkId` to `MoneroNetworkV1`: the
//! adapter enum and the chain-profile enum must never drift apart, and
//! mainnet-beta must be unrepresentable in both.

use solana_profile::{SolanaAdapterProfileV1, SolanaNetwork};
use solana_types::SolanaPubkey;

#[test]
fn network_discriminants_match_chain_profile() {
    for (adapter, registry) in [
        (
            SolanaNetwork::Devnet,
            chain_profile::SolanaNetworkV1::Devnet,
        ),
        (
            SolanaNetwork::Testnet,
            chain_profile::SolanaNetworkV1::Testnet,
        ),
        (
            SolanaNetwork::LocalValidator,
            chain_profile::SolanaNetworkV1::LocalValidator,
        ),
    ] {
        assert_eq!(adapter as u8, registry as u8);
        assert_eq!(
            SolanaNetwork::from_u8(adapter as u8),
            Some(adapter),
            "adapter decode round-trips"
        );
        assert_eq!(
            chain_profile::SolanaNetworkV1::from_u8(registry as u8),
            Some(registry),
            "registry decode round-trips"
        );
    }
    // Mainnet-beta's byte decodes in neither spelling.
    assert_eq!(SolanaNetwork::from_u8(1), None);
    assert_eq!(chain_profile::SolanaNetworkV1::from_u8(1), None);
}

#[test]
fn profiles_refuse_zero_program_and_degenerate_quorums() {
    let program = SolanaPubkey([7; 32]);
    assert!(SolanaAdapterProfileV1::new(SolanaNetwork::Devnet, program, 3, 2).is_ok());
    assert!(
        SolanaAdapterProfileV1::new(SolanaNetwork::Devnet, SolanaPubkey([0; 32]), 3, 2).is_err()
    );
    assert!(SolanaAdapterProfileV1::new(SolanaNetwork::Devnet, program, 3, 0).is_err());
    assert!(SolanaAdapterProfileV1::new(SolanaNetwork::Devnet, program, 2, 3).is_err());
}

#[test]
fn every_public_network_requires_an_immutable_program() {
    let program = SolanaPubkey([7; 32]);
    for network in [SolanaNetwork::Devnet, SolanaNetwork::Testnet] {
        let profile = SolanaAdapterProfileV1::new(network, program, 3, 2).expect("profile");
        assert!(profile.require_immutable_program);
    }
    let local =
        SolanaAdapterProfileV1::new(SolanaNetwork::LocalValidator, program, 3, 2).expect("profile");
    assert!(!local.require_immutable_program);
}

#[test]
fn the_attested_profile_requires_an_immutable_program_on_every_network() {
    let program = SolanaPubkey([7; 32]);
    for network in [
        SolanaNetwork::Devnet,
        SolanaNetwork::Testnet,
        SolanaNetwork::LocalValidator,
    ] {
        let attested =
            SolanaAdapterProfileV1::new_attested(network, program, 3, 2).expect("profile");
        assert!(attested.require_immutable_program);
        // Only the attestation flag differs from `new`, and it is part of the
        // profile hash: an attested local profile can never be confused with
        // the unattested one the daemon refuses.
        let plain = SolanaAdapterProfileV1::new(network, program, 3, 2).expect("profile");
        assert_eq!(
            SolanaAdapterProfileV1 {
                require_immutable_program: plain.require_immutable_program,
                ..attested
            },
            plain
        );
        if network == SolanaNetwork::LocalValidator {
            assert_ne!(attested.profile_hash(), plain.profile_hash());
        }
    }
    // Validation is shared with `new`, not relaxed.
    assert!(SolanaAdapterProfileV1::new_attested(
        SolanaNetwork::LocalValidator,
        SolanaPubkey([0; 32]),
        3,
        2
    )
    .is_err());
    assert!(
        SolanaAdapterProfileV1::new_attested(SolanaNetwork::LocalValidator, program, 2, 3)
            .is_err()
    );
}
