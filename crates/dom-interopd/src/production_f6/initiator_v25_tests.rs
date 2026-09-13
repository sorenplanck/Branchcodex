//! Focused boundary regressions, not an end-to-end F6 transport proof.
//! No opaque delivery, time, terms, or inventory capability is fabricated.

use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;

static_assertions::assert_not_impl_any!(ProductionInitiatorF6AuthorityV25: Clone, Copy);
static_assertions::assert_not_impl_any!(ProductionInitiatorF6AuthoritiesV25: Clone, Copy);

fn binding() -> ProductionSolverF6BindingV2 {
    let clock = NegotiationClockV2 {
        chain_id: ChainId([0x11; 32]),
        profile_digest: [0x12; 32],
        authority_scope: [0x13; 32],
        kind: rfq::v2::NativeClockKindV2::BlockHeight,
    };
    ProductionSolverF6BindingV2 {
        wire: RouteWireContextV1 {
            network_id: [0x14; 32],
            session_id: [0x15; 32],
            route_id: [0x16; 32],
            roster_snapshot: [0x17; 32],
            policy_version: 3,
        },
        rfq_id: [0x18; 32],
        composition_id: [0x19; 32],
        position: SettlementPositionV2::Upstream,
        initiator: ParticipantId([0x20; 32]),
        solver: ParticipantId([0x21; 32]),
        dom_chain_id: clock.chain_id,
        negotiation_clock: clock,
        pins: ProductionF6PinsV2 {
            inventory_binding_digest: [0x22; 32],
            registry_digest: [0x23; 32],
            registry_epoch: 4,
            profile_bundle_digest: [0x24; 32],
            bond_policy_hash: [0x25; 32],
            bond_asset_binding_digest: [0x26; 32],
            required_collateral: 10,
            bond_attestation_authority_set_digest: [0x27; 32],
            remote_status_authority_set_digest: [0x28; 32],
            solver_status_scope_digest: [0x29; 32],
            pre_f6_time_scope_digest: [0x30; 32],
        },
    }
}

#[test]
fn initiator_accepts_designated_solver_quote_sender_but_not_impersonation_v25() {
    let binding = binding();
    assert!(require_quote_sender(binding, binding.solver, binding.solver).is_ok());
    for (sender, solver) in [
        (binding.initiator, binding.solver),
        (binding.solver, binding.initiator),
        (binding.initiator, binding.initiator),
        (ParticipantId([0x31; 32]), binding.solver),
    ] {
        assert!(matches!(
            require_quote_sender(binding, sender, solver),
            Err(ProductionF6ErrorV2::WrongRole)
        ));
    }
}

#[test]
fn initiator_local_owner_and_selection_acceptance_sender_are_closed_v25() {
    let binding = binding();
    assert!(require_local_initiator(binding, binding.initiator).is_ok());
    assert!(require_initiator_sender(binding, binding.initiator).is_ok());
    for participant in [
        binding.solver,
        ParticipantId([0; 32]),
        ParticipantId([0x32; 32]),
    ] {
        assert!(matches!(
            require_local_initiator(binding, participant),
            Err(ProductionF6ErrorV2::WrongRole)
        ));
        assert!(matches!(
            require_initiator_sender(binding, participant),
            Err(ProductionF6ErrorV2::WrongRole)
        ));
    }
}

#[test]
fn initiator_physical_bindings_cannot_open_solver_or_other_position_logs_v25(
) -> Result<(), Box<dyn std::error::Error>> {
    let binding = binding();
    binding.validate()?;
    let initiator = binding.authority_digest(INITIATOR_LOG_DOMAIN)?;
    let receipts = binding.authority_digest(INITIATOR_RECEIPTS_DOMAIN)?;
    assert_ne!(initiator, binding.authority_digest(LOG_BINDING_DOMAIN)?);
    assert_ne!(receipts, binding.authority_digest(RECEIPT_BINDING_DOMAIN)?);
    assert_ne!(initiator, receipts);
    let other = ProductionSolverF6BindingV2 {
        position: SettlementPositionV2::Downstream,
        ..binding
    };
    assert_ne!(initiator, other.authority_digest(INITIATOR_LOG_DOMAIN)?);
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("initiator-log.sqlite3");
    drop(StoreLogV2::create_production(&path, initiator)?);
    assert!(
        StoreLogV2::open_production(&path, binding.authority_digest(LOG_BINDING_DOMAIN)?).is_err()
    );
    assert!(
        StoreLogV2::open_production(&path, other.authority_digest(INITIATOR_LOG_DOMAIN)?).is_err()
    );
    drop(StoreLogV2::open_production(&path, initiator)?);
    Ok(())
}

#[test]
fn initiator_exact_records_survive_reopen_and_conflicts_never_overwrite_v25(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("initiator-receipts.sqlite3");
    let binding = binding();
    let physical =
        ProductionStoreBindingV1::new(binding.authority_digest(INITIATOR_RECEIPTS_DOMAIN)?)?;
    let mut store = Store::create_production(&path, physical)?;
    for namespace in [RFQ_NAMESPACE, TERMS_NAMESPACE, DELIVERY_NAMESPACE] {
        retain_exact(
            &mut store,
            namespace,
            &binding.rfq_id,
            b"original exact public record",
        )?;
        retain_exact(
            &mut store,
            namespace,
            &binding.rfq_id,
            b"original exact public record",
        )?;
        assert!(matches!(
            retain_exact(&mut store, namespace, &binding.rfq_id, b"changed economics"),
            Err(ProductionF6ErrorV2::Receipt)
        ));
    }
    drop(store);
    let mut store = Store::open_production(&path, physical)?;
    for namespace in [RFQ_NAMESPACE, TERMS_NAMESPACE, DELIVERY_NAMESPACE] {
        assert_eq!(
            store.opaque(namespace, &binding.rfq_id)?.as_deref(),
            Some(b"original exact public record".as_slice())
        );
        assert!(matches!(
            retain_exact(
                &mut store,
                namespace,
                &binding.rfq_id,
                b"changed after restart"
            ),
            Err(ProductionF6ErrorV2::Receipt)
        ));
        retain_exact(
            &mut store,
            namespace,
            &binding.rfq_id,
            b"original exact public record",
        )?;
    }
    Ok(())
}

#[test]
fn initiator_delivery_replay_requires_exact_disposition_record_v25(
) -> Result<(), Box<dyn std::error::Error>> {
    // Exercises the byte-exact replay branch, not a constructed Relay owner.
    let applied = b"exact prior authenticated applied receipt";
    let failed = b"exact prior authenticated failed-closed receipt";
    let replay = exact_delivery_replay(applied, applied, failed)?;
    assert_eq!(replay.disposition(), DurablePayloadDispositionV1::Applied);
    assert!(replay.duplicate());
    let replay = exact_delivery_replay(failed, applied, failed)?;
    assert_eq!(
        replay.disposition(),
        DurablePayloadDispositionV1::FailedClosed
    );
    assert!(replay.duplicate());
    for bytes in [
        b"".as_slice(),
        b"different envelope",
        b"same payload, different sender",
    ] {
        assert!(matches!(
            exact_delivery_replay(bytes, applied, failed),
            Err(ProductionF6ErrorV2::Receipt)
        ));
    }
    Ok(())
}

#[test]
fn initiator_reuses_exact_time_scope_not_embedded_clock_scope_v25() {
    let binding = binding();
    assert!(validate_pre_f6_authority(
        binding,
        binding.pins.pre_f6_time_scope_digest,
        binding.negotiation_clock
    )
    .is_ok());
    assert!(matches!(
        validate_pre_f6_authority(
            binding,
            binding.negotiation_clock.authority_scope,
            binding.negotiation_clock
        ),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));
    let changed_clock = NegotiationClockV2 {
        authority_scope: [0x41; 32],
        ..binding.negotiation_clock
    };
    assert!(matches!(
        validate_pre_f6_authority(
            binding,
            binding.pins.pre_f6_time_scope_digest,
            changed_clock
        ),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));
}

#[test]
fn initiator_selection_cannot_switch_winner_or_authority_snapshot_v25() {
    let binding = binding();
    let selected = SelectionV2 {
        composition_id: binding.composition_id,
        position: binding.position,
        rfq_id: binding.rfq_id,
        winning_quote: [0x42; 32],
        inputs_digest: [0x43; 32],
    };
    assert!(validate_current_local_selection(
        selected.winning_quote,
        selected.inputs_digest,
        selected.winning_quote,
        selected.inputs_digest,
        &selected
    )
    .is_ok());
    for (winner, snapshot) in [
        ([0x44; 32], selected.inputs_digest),
        (selected.winning_quote, [0x45; 32]),
    ] {
        assert!(matches!(
            validate_current_local_selection(
                winner,
                snapshot,
                selected.winning_quote,
                selected.inputs_digest,
                &selected
            ),
            Err(ProductionF6ErrorV2::Binding)
        ));
    }
}
