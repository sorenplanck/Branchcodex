#!/usr/bin/env python3
"""Run the closed, serial DOM/XMR boundary regression list, never a ceremony.

The production daemon's test command does not execute dependency unit tests.
These selections cover those boundaries using the existing crypto-test build.
API/spend-port have no native tests: their compilation is reported separately,
not counted as a successful test. No private fixture files are archived.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

from run_native_daemon_scenario_v23 import OwnedProcesses, RUN_COUNT, TEST_START, write_result

ROOT = Path(__file__).resolve().parents[1]
LOG_LIMIT = 64 * 1024 * 1024
SUMMARY = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;.*$", re.MULTILINE)
CANCELLED = False


def selection(identifier, package, prefix, source, names, *, test_filter=None,
              features=(), integration=None):
    return {"id": identifier, "package": package, "module_prefix": prefix,
            "source": source, "required_tests": [prefix + name for name in names],
            "filter": prefix if test_filter is None else test_filter,
            "features": list(features), "integration": integration}


SELECTIONS = (
    selection("native-preflight-policy", "dom-interopd",
              "production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::",
              "crates/dom-interopd/src/production_xmr_native_daemon_scenario_v23_tests.rs", (
                  "native_real_daemon_policy_uses_the_signed_xmr_m8_floor_v24",),
              features=("production",),
              test_filter="production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::native_real_daemon_policy_uses_the_signed_xmr_m8_floor_v24"),
    selection("native-preflight-deadline", "dom-interopd",
              "production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::deadline_plan_v23::projection_v24::",
              "crates/dom-interopd/src/production_xmr_native_deadline_projection_v24_tests.rs", (
                  "native_deadline_admission_uses_snapshot_anchor_age_and_refuses_expired_v24",),
              features=("production",),
              test_filter="production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::deadline_plan_v23::projection_v24::native_deadline_admission_uses_snapshot_anchor_age_and_refuses_expired_v24"),
    selection("native-preflight-wallet", "dom-interopd",
              "production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_wallet_v23::scan_tests_v24::",
              "crates/dom-interopd/src/production_xmr_native_daemon_wallet_scan_v24_tests.rs", (
                  "baseline_scan_requests_genesis_and_all_three_wallet_origins_v24",),
              features=("production",),
              test_filter="production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_wallet_v23::scan_tests_v24::baseline_scan_requests_genesis_and_all_three_wallet_origins_v24"),
    selection("native-preflight-history", "dom-interopd",
              "production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::native_observation_v23::dom_snapshot::history_v24::tests::",
              "crates/dom-interopd/src/production_xmr_native_dom_history_v24_tests.rs", (
                  "campaign_pages_preserve_original_absolute_heights_and_request_bounds_v24",
                  "campaign_reader_rejects_truncated_or_mutated_storage_v24",
                  "campaign_append_refuses_skips_and_negotiated_limit_overflow_v24",
                  "campaign_frozen_reader_does_not_block_native_history_publication_v24"),
              features=("production",)),
    selection("dom-funding-dispatch-budget", "adapter-dom-real", "funding_deadline_v23_tests::",
              "crates/adapters/dom-real/src/funding_deadline_v23_tests.rs", (
                  "expired_funding_deadline_neither_scans_nor_posts_v23",
                  "expired_funding_reconciliation_cannot_mint_from_cached_progress_v23")),
    selection("dom-tip-original-budget", "adapter-dom-real", "tests::",
              "crates/adapters/dom-real/src/lib.rs", (
                  "bounded_tip_refuses_zero_budget_or_busy_checkpoint_without_rpc_v23",
                  "bounded_tip_revalidates_retained_anchor_and_resets_only_on_reorg_v23"),
              test_filter="tests::bounded_tip_"),
    selection("dom-funding-scan-budget", "adapter-dom-real", "terminal_finality::funding_bounded_v23::tests::",
              "crates/adapters/dom-real/src/funding_finality_bounded_v23.rs", (
                  "funding_scan_cache_evicts_old_scope_and_never_invents_a_transaction_v23",
                  "funding_scan_expired_budget_never_yields_authority_v23")),
    selection("dom-recovery-budget-and-roles", "adapter-dom-real", "xmr_recovery_execution_v12::tests::",
              "crates/adapters/dom-real/src/xmr_recovery_execution_v12.rs", (
                  "composed_recovery_deadline_refuses_zero_oversized_and_expired_without_sleep_v23",
                  "composed_recovery_reuses_one_absolute_deadline_across_steps_v23",
                  "public_observation_until_keeps_callers_exact_cutoff_v24",
                  "refund_reveal_has_strict_mempool_safety_cutoff_and_no_compensation_role",
                  "compensation_is_unilateral_but_never_early_or_adaptor_refund",
                  "bounded_compensation_still_rejects_wrong_role_and_invalid_windows",
                  "invalid_cancel_and_overflow_never_open_a_reveal_window")),
    selection("dom-refund-canonical-reorg", "adapter-dom-real", "xmr_recovery_finality::refund_reorg_v23::tests::",
              "crates/adapters/dom-real/src/xmr_refund_reorg_v23_tests.rs", (
                  "native_refund_checkpoint_exact_layout_and_ancestry_v23",
                  "native_refund_checkpoint_refuses_wrong_kind_digest_trailing_and_truncation_v23",
                  "native_refund_checkpoint_refuses_discontinuous_tail_wrong_block_and_weak_policy_v23",
                  "native_refund_fork_proves_exact_removed_tail_and_original_identity_v23",
                  "native_refund_fork_refuses_deep_or_unproved_ancestor_v23",
                  "native_refund_fork_still_canonical_or_depth_loss_is_not_invalidation_v23",
                  "native_refund_reinclusion_is_distinct_from_absence_and_replay_stable_v23",
                  "native_refund_fork_token_expires_without_sleep_v23",
                  "native_graph_progress_retains_only_bounded_scopes_and_never_shares_prefix_v23",
                  "native_graph_progress_resets_anchor_fork_discards_corruption_and_keeps_timeout_v23")),
    selection("dom-actuator-funding-deadline", "dom-actuator", "contracts::funding_dispatch_v23::tests::",
              "crates/dom-actuator/src/funding_dispatch_v23.rs", (
                  "original_dispatch_deadline_is_closed_at_its_boundary_v23",), features=("production",)),
    selection("dom-actuator-refund-checkpoint", "dom-actuator", "contracts::native_xmr_refund_v23::tests::",
              "crates/dom-actuator/src/native_xmr_refund_v23.rs", (
                  "native_refund_reobservation_preserves_original_receipt_checkpoint_v23",
                  "native_refund_reobservation_refuses_transaction_and_face_substitution_v23",
                  "native_refund_reobservation_never_weakens_negotiated_policy_v23",
                  "native_refund_changed_inclusion_needs_real_reorg_authority_v23"), features=("production",)),
    selection("dom-http-deadline-boundary", "dom-scriptless-chain-adapter", "tests::",
              "crates/dom-scriptless-chain-adapter/src/lib.rs", (
                  "expired_scan_budget_makes_no_network_request_v23",
                  "expired_submit_budget_never_opens_a_connection_v23",
                  "started_submit_timeout_is_unavailable_not_rejected_v23")),
    selection("store-claim-observation-clock", "dom-scriptless-store", "runtime::linux::session_store::f7_v12::tests::",
              "crates/dom-scriptless-store/src/runtime/linux/session_store/f7_v12.rs", (
                  "consumed_claim_retains_scan_age_across_revalidation_without_sleeping",)),
    selection("store-refund-transport-grant", "dom-scriptless-store", "runtime::linux::session_store::f7_v12::xmr_refund_transport_v23::tests::",
              "crates/dom-scriptless-store/src/runtime/linux/session_store/f7_xmr_refund_transport_v23.rs", (
                  "first_refund_waits_before_grant_then_exact_payload_can_retry",
                  "tampered_grant_and_disappeared_ancestor_never_become_pending",
                  "grant_covers_shared_economics_but_not_a_local_signing_effect",
                  "unpublished_old_local_effect_marker_is_not_reinterpreted",
                  "transport_record_is_canonical_and_session_bound_not_chain_authority")),
    selection("store-refund-exit-checkpoint", "dom-scriptless-store", "runtime::linux::xmr_recovery::execution_v12::refund_checkpoint_tests_v23::",
              "crates/dom-scriptless-store/src/runtime/linux/xmr_recovery/execution_v12.rs", (
                  "checkpoint_reader_refuses_scope_class_digest_and_truncation",)),
    selection("f7-original-observation-age", "f7-anchor-authority", "families_v11::authorization_v12::tests::",
              "crates/f7-anchor-authority/src/families_v11/authorization_v12.rs", (
                  "promotion_preserves_external_origin_for_every_family_without_a_new_lifetime",
                  "universal_dom_absence_does_not_hide_substituted_or_invalid_funding")),
    selection("f7-native-scan-deadline", "f7-anchor-authority", "native_scan_deadline_v23_tests::",
              "crates/f7-anchor-authority/src/native_scan_deadline_v23_tests.rs", (
                  "native_scan_does_not_start_another_page_at_or_after_external_expiry",)),
    selection("xmr-local-public-proof-scope", "xmr-key-image-proof", "local_build_request_v24::tests::",
              "crates/adapters/xmr-key-image-proof/src/local_build_request_v24.rs", (
                  "public_load_binds_every_static_pin_and_refuses_a_refreshed_nonce",
                  "ready_scope_authenticates_original_descriptors_without_calling_them_a_grant",
                  "every_local_effect_or_economic_field_changes_the_auth_preimage",
                  "local_scope_cannot_encode_missing_effect_or_a_remote_version"), test_filter=""),
    selection("xmr-sidecar-request-domains", "xmr-sidecar-auth", "tests::",
              "crates/adapters/xmr-sidecar-auth/src/lib.rs", (
                  "local_refund_build_and_read_tags_are_not_remote_or_v2_authority",
                  "challenge_proof_round_trips_and_binds_to_the_exact_nonce",
                  "challenge_domain_is_separated_from_the_request_tag_domain")),
    selection("xmr-private-uds-authentication", "xmr-live-sidecar-uds-client", "tests::",
              "crates/adapters/xmr-live-sidecar-uds-client/src/lib.rs", (
                  "honest_sidecar_completes_handshake_then_serves_the_request",
                  "impostor_with_wrong_key_never_receives_the_request",
                  "world_writable_and_relative_socket_paths_are_refused",
                  "v9_authenticated_but_mismatched_funding_is_hard_rejected",
                  "v9_retryable_sidecar_error_remains_distinct_from_rejection",
                  "v9_one_deadline_bounds_a_trickling_frame_and_refuses_invalid_budgets")),
    selection("xmr-public-load-original-deadline", "xmr-live-sidecar-uds-client",
              "local_load_deadline_v24_tests::",
              "crates/adapters/xmr-live-sidecar-uds-client/src/local_load_deadline_v24_tests.rs", (
                  "expired_public_load_does_not_connect_v24",
                  "public_load_preserves_original_deadline_and_caps_sixty_seconds_v24",
                  "public_load_deadline_covers_trickling_hello_and_never_sends_request_v24",
                  "public_load_response_uses_remaining_not_the_configured_180_seconds_v24")),
    selection("xmr-rpc-original-submit-deadline", "xmr-rpc-broadcast-blocking", "broadcast_deadline_v24::tests::",
              "crates/adapters/xmr-rpc-broadcast-blocking/src/broadcast_deadline_v24.rs", (
                  "timeout_shrinks_across_preparation_and_cannot_extend_the_original_window",
                  "expired_request_cannot_open_a_post_connection")),
    selection("xmr-rpc-original-observation-deadline", "xmr-rpc-broadcast-blocking",
              "observation_deadline_v24::tests::",
              "crates/adapters/xmr-rpc-broadcast-blocking/src/observation_deadline_v24.rs", (
                  "observation_budget_never_extends_an_inherited_deadline_v24",
                  "expired_reader_methods_never_contact_even_genesis_v24")),
    selection("xmr-quorum-original-observation-deadline", "dom-interopd",
              "production_children::tests::",
              "crates/dom-interopd/src/production_children.rs", (
                  "public_observation_deadline_expiry_contacts_no_voter_v24",),
              features=("production",),
              test_filter="production_children::tests::public_observation_deadline_expiry_contacts_no_voter_v24"),
    selection("xmr-dom-public-refund-original-deadline", "dom-interopd",
              "production_xmr_recovery_driver_v12::recovery_deadline_tests_v23::",
              "crates/dom-interopd/src/production_xmr_recovery_driver_v12.rs", (
                  "public_refund_passes_exact_instant_and_expiry_calls_nothing_v24",
                  "driver_keeps_the_initial_absolute_deadline_and_refuses_exhausted_budget_v23"),
              features=("production",)),
    selection("xmr-public-refund-publication-scope", "dom-interopd",
              "production_xmr_remote_sweep_v23::remote_refund_v23::local_custody_tests_v24::",
              "crates/dom-interopd/src/production_xmr_remote_refund_v23.rs", (
                  "independent_actor_effects_share_refund_economics_but_never_requester_replay",
                  "public_funding_recheck_accepts_descendants_but_not_relocation_or_rollback",
                  "read_only_publication_does_not_refresh_an_expired_observation",
                  "reopened_refund_projection_retains_original_nonce_epoch_and_semantics",
                  "publication_requires_exact_locally_retained_refund_bytes",
                  "publication_deadline_is_not_rebased_between_steps",
                  "historical_funding_digest_survives_confirmation_growth_but_not_unsigned_rewrite"),
              features=("production",)),
    selection("xmr-terminal-refund-transport", "dom-interopd",
              "relay_worker::terminal_refund_v24_tests::",
              "crates/dom-interopd/src/relay_worker_terminal_refund_v24_tests.rs", (
                  "terminal_filter_accepts_only_canonical_refund_request_not_claim_or_other_dsc1",
                  "terminal_filter_never_treats_malformed_public_payload_as_absent",
                  "terminal_ingress_never_dispatches_f6_and_frame_retry_never_creates_application",
                  "terminal_multiframe_reopen_keeps_original_expiry_and_exact_acknowledged_bytes"),
              features=("production",)),
    selection("store-terminal-ack-handoff-reopen", "dom-interopd", "",
              "crates/dom-interopd/tests/relay_worker.rs", (
                  "store_application_ack_loss_restarts_with_identical_bytes_and_no_new_sequence",),
              test_filter="store_application_ack_loss_restarts_with_identical_bytes_and_no_new_sequence",
              features=("production",), integration="relay_worker"),
    selection("relay-expiry-original-store-replay", "route-transport", "",
              "crates/route-transport/tests/expiry_recovery_characterization_v23.rs", (
                  "accepted_before_expiry_recovers_lost_acks_after_all_stores_reopen_v23",
                  "never_accepted_expired_head_is_quarantined_and_fresh_successor_cannot_skip_it_v23"),
              integration="expiry_recovery_characterization_v23"),
)

COMPILE_ONLY = (
    {"package": "xmr-live-sidecar-api", "native_test_count": 0,
     "compiled_by": "xmr-private-uds-authentication",
     "note": "DTO dependency compilation, not native test execution"},
    {"package": "xmr-spend-port", "native_test_count": 0,
     "compiled_by": "xmr-private-uds-authentication",
     "note": "trait dependency compilation; deadline behavior covered by RPC/daemon boundary tests"},
)


def spec_for(identifier):
    for spec in SELECTIONS:
        if spec["id"] == identifier:
            return spec
    raise ValueError("unknown boundary test selection")


def command(identifier):
    spec = spec_for(identifier)
    args = ["cargo", "test", "--locked", "--profile", "crypto-test", "-p", spec["package"]]
    if spec["features"]:
        args += ["--no-default-features", "--features", ",".join(spec["features"])]
    args += ["--test", spec["integration"]] if spec["integration"] else ["--lib"]
    if spec["filter"]:
        args.append(spec["filter"])
    return args + ["--", "--nocapture", "--test-threads=1", "--color", "never"]



def start_test_command_v24(identifier, *, cwd, env, stdout):
    """Closed literal argv dispatch, independently checked against the report.

    These deliberate literals keep the automation guard's no-dynamic-process
    boundary intact. A new selection or changed command must be reviewed here;
    changing the report/allowlist alone cannot execute an unreviewed command.
    No shell or caller-selected executable is accepted.
    """
    expected = command(identifier)
    if identifier == "native-preflight-policy":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::native_real_daemon_policy_uses_the_signed_xmr_m8_floor_v24","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::native_real_daemon_policy_uses_the_signed_xmr_m8_floor_v24","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-preflight-deadline":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::deadline_plan_v23::projection_v24::native_deadline_admission_uses_snapshot_anchor_age_and_refuses_expired_v24","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::deadline_plan_v23::projection_v24::native_deadline_admission_uses_snapshot_anchor_age_and_refuses_expired_v24","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-preflight-wallet":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_wallet_v23::scan_tests_v24::baseline_scan_requests_genesis_and_all_three_wallet_origins_v24","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_wallet_v23::scan_tests_v24::baseline_scan_requests_genesis_and_all_three_wallet_origins_v24","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-preflight-history":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::native_observation_v23::dom_snapshot::history_v24::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::native_observation_v23::dom_snapshot::history_v24::tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "dom-funding-dispatch-budget":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","adapter-dom-real","--lib","funding_deadline_v23_tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","adapter-dom-real","--lib","funding_deadline_v23_tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "dom-tip-original-budget":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","adapter-dom-real","--lib","tests::bounded_tip_","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","adapter-dom-real","--lib","tests::bounded_tip_","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "dom-funding-scan-budget":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","adapter-dom-real","--lib","terminal_finality::funding_bounded_v23::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","adapter-dom-real","--lib","terminal_finality::funding_bounded_v23::tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "dom-recovery-budget-and-roles":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","adapter-dom-real","--lib","xmr_recovery_execution_v12::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","adapter-dom-real","--lib","xmr_recovery_execution_v12::tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "dom-refund-canonical-reorg":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","adapter-dom-real","--lib","xmr_recovery_finality::refund_reorg_v23::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","adapter-dom-real","--lib","xmr_recovery_finality::refund_reorg_v23::tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "dom-actuator-funding-deadline":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-actuator","--no-default-features","--features","production","--lib","contracts::funding_dispatch_v23::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-actuator","--no-default-features","--features","production","--lib","contracts::funding_dispatch_v23::tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "dom-actuator-refund-checkpoint":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-actuator","--no-default-features","--features","production","--lib","contracts::native_xmr_refund_v23::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-actuator","--no-default-features","--features","production","--lib","contracts::native_xmr_refund_v23::tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "dom-http-deadline-boundary":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-chain-adapter","--lib","tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-chain-adapter","--lib","tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "store-claim-observation-clock":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::f7_v12::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::f7_v12::tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "store-refund-transport-grant":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::f7_v12::xmr_refund_transport_v23::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::f7_v12::xmr_refund_transport_v23::tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "store-refund-exit-checkpoint":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::xmr_recovery::execution_v12::refund_checkpoint_tests_v23::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::xmr_recovery::execution_v12::refund_checkpoint_tests_v23::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "f7-original-observation-age":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","f7-anchor-authority","--lib","families_v11::authorization_v12::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","f7-anchor-authority","--lib","families_v11::authorization_v12::tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "f7-native-scan-deadline":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","f7-anchor-authority","--lib","native_scan_deadline_v23_tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","f7-anchor-authority","--lib","native_scan_deadline_v23_tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "xmr-local-public-proof-scope":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","xmr-key-image-proof","--lib","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","xmr-key-image-proof","--lib","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "xmr-sidecar-request-domains":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","xmr-sidecar-auth","--lib","tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","xmr-sidecar-auth","--lib","tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "xmr-private-uds-authentication":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","xmr-live-sidecar-uds-client","--lib","tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","xmr-live-sidecar-uds-client","--lib","tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "xmr-public-load-original-deadline":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","xmr-live-sidecar-uds-client","--lib","local_load_deadline_v24_tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","xmr-live-sidecar-uds-client","--lib","local_load_deadline_v24_tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "xmr-rpc-original-submit-deadline":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","xmr-rpc-broadcast-blocking","--lib","broadcast_deadline_v24::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","xmr-rpc-broadcast-blocking","--lib","broadcast_deadline_v24::tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "xmr-rpc-original-observation-deadline":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","xmr-rpc-broadcast-blocking","--lib","observation_deadline_v24::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","xmr-rpc-broadcast-blocking","--lib","observation_deadline_v24::tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "xmr-quorum-original-observation-deadline":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_children::tests::public_observation_deadline_expiry_contacts_no_voter_v24","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_children::tests::public_observation_deadline_expiry_contacts_no_voter_v24","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "xmr-dom-public-refund-original-deadline":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_xmr_recovery_driver_v12::recovery_deadline_tests_v23::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_xmr_recovery_driver_v12::recovery_deadline_tests_v23::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "xmr-public-refund-publication-scope":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_xmr_remote_sweep_v23::remote_refund_v23::local_custody_tests_v24::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_xmr_remote_sweep_v23::remote_refund_v23::local_custody_tests_v24::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "xmr-terminal-refund-transport":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","relay_worker::terminal_refund_v24_tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","relay_worker::terminal_refund_v24_tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "store-terminal-ack-handoff-reopen":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--test","relay_worker","store_application_ack_loss_restarts_with_identical_bytes_and_no_new_sequence","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--test","relay_worker","store_application_ack_loss_restarts_with_identical_bytes_and_no_new_sequence","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "relay-expiry-original-store-replay":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","route-transport","--test","expiry_recovery_characterization_v23","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","route-transport","--test","expiry_recovery_characterization_v23","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    raise ValueError("unreviewed native test dispatch")


def evaluate_output(identifier, returncode, transcript):
    spec = spec_for(identifier)
    summaries = SUMMARY.findall(transcript)
    names = TEST_START.findall(transcript)
    counts = [int(value) for value in RUN_COUNT.findall(transcript)]
    missing = sorted(set(spec["required_tests"]) - set(names))
    valid = False
    if len(summaries) == 1:
        state, passed, failed, ignored = summaries[0]
        passed, failed, ignored = int(passed), int(failed), int(ignored)
        valid = (returncode == 0 and state == "ok" and passed > 0 and failed == ignored == 0
                 and not missing and len(names) == len(set(names)) == passed
                 and counts == [passed] and all(spec["filter"] in name for name in names))
    return {"status": "passed" if valid else "failed", "missing_required_tests": missing,
            "executed_test_names": names, "libtest_run_counts": counts,
            "libtest_summaries": summaries}


def interrupted(signum, _frame):
    global CANCELLED
    CANCELLED = True
    raise InterruptedError(f"boundary runner received signal {signum}")


def run_selection(identifier, evidence, timeout):
    spec = spec_for(identifier)
    case = evidence / identifier
    case.mkdir(mode=0o700)
    result = {"selection": spec, "command": command(identifier), "status": "starting",
              "returncode": None, "cleanup_verified": False}
    result_file = case / "result.json"
    write_result(result_file, result)
    env = dict(os.environ, CARGO_BUILD_JOBS="2", CARGO_TERM_COLOR="never", RUST_TEST_THREADS="1")
    process = tracker = None
    started = time.monotonic()
    log = case / "test.log"
    try:
        print(f"boundary selection: {identifier}", flush=True)
        with log.open("xb", buffering=0) as output, log.open("rb") as live:
            process = start_test_command_v24(identifier, cwd=ROOT, env=env, stdout=output)
            tracker = OwnedProcesses(process.pid)
            result["status"] = "running"
            write_result(result_file, result)
            while process.poll() is None:
                tracker.snapshot()
                data = live.read(65_536)
                if data:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                if log.stat().st_size > LOG_LIMIT:
                    raise RuntimeError("boundary log exceeds 64 MiB")
                if time.monotonic() - started >= timeout:
                    raise TimeoutError("boundary selection reached its time limit")
                time.sleep(0.1)
            if log.stat().st_size > LOG_LIMIT:
                raise RuntimeError("boundary log exceeds 64 MiB")
            sys.stdout.buffer.write(live.read())
            sys.stdout.buffer.flush()
            result["returncode"] = process.returncode
            result.update(evaluate_output(identifier, process.returncode, log.read_text(errors="replace")))
            result["log_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
    except BaseException as error:
        result.update(status="failed", error=f"{type(error).__name__}: {error}")
    finally:
        try:
            if tracker is not None and result["status"] == "passed":
                if any(info[3] != "Z" for info in tracker.snapshot().values()):
                    result.update(status="failed", error="passing test left live descendants")
            result["cleanup_verified"] = process is None or tracker.cleanup(process)
            if process is not None:
                result["returncode"] = process.returncode
            if not result["cleanup_verified"]:
                result.update(status="failed", cleanup_error="descendant cleanup unproven; next selection refused")
        except BaseException as error:
            result.update(status="failed", cleanup_verified=False, cleanup_error=str(error))
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        write_result(result_file, result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--list", action="store_true", help="print fixed commands without running them")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args(argv)
    if args.list:
        print(json.dumps({"selections": [{**item, "command": command(item["id"])} for item in SELECTIONS],
                          "compile_only_dependencies": COMPILE_ONLY}, indent=2))
        return 0
    if args.evidence_dir is None:
        parser.error("--evidence-dir is required unless --list is selected")
    if not 1 <= args.timeout_seconds <= 3600:
        parser.error("timeout must be between 1 and 3600 seconds per selection")
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (evidence / "campaign.json").exists():
        parser.error("evidence directory already contains a campaign; use a fresh path")
    campaign = {"schema": "DOM-XMR-SCOPED-BOUNDARY-CAMPAIGN-V24", "status": "not-run",
                "compile_only_dependencies": COMPILE_ONLY,
                "results": [{"selection": item["id"], "status": "not-run"} for item in SELECTIONS],
                "git_sha": os.environ.get("GITHUB_SHA"),
                "lock_sha256": hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest()}
    write_result(evidence / "campaign.json", campaign)
    try:
        if not sys.platform.startswith("linux") or not hasattr(os, "pidfd_open"):
            raise RuntimeError("Linux pidfd and child-subreaper ownership required")
        if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER failed")
        signal.signal(signal.SIGINT, interrupted)
        signal.signal(signal.SIGTERM, interrupted)
        for index, item in enumerate(SELECTIONS):
            campaign["results"][index] = run_selection(item["id"], evidence, args.timeout_seconds)
            write_result(evidence / "campaign.json", campaign)
            if CANCELLED or not campaign["results"][index]["cleanup_verified"]:
                break
        campaign["status"] = "passed" if all(result["status"] == "passed" for result in campaign["results"]) else "failed"
    except BaseException as error:
        campaign.update(status="failed", error=f"{type(error).__name__}: {error}")
    write_result(evidence / "campaign.json", campaign)
    return 0 if campaign["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
