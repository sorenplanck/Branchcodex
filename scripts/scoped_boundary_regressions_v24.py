#!/usr/bin/env python3
"""Run closed, serial DOM/XMR boundary regressions, not the full swap daemon.

The production daemon's test command does not execute dependency unit tests.
These selections cover those boundaries using the existing crypto-test build.
API/spend-port have no native tests: their compilation is reported separately,
not counted as a successful test. No private fixture files are archived.
Proof-cache selections include real cryptographic vectors and original-verifier
comparisons; they are not substitutes for the complete lifecycle scenarios.
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
from test_interop_hardening import production_environment_v24

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
    selection("native-preflight-http", "dom-interopd",
              "production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::native_observation_v23::dom_snapshot::http_v24::tests::",
              "crates/dom-interopd/src/production_xmr_native_dom_http_v24_tests.rs", (
                  "native_dom_get_peer_timeout_keeps_next_connection_available_v24",
                  "native_dom_post_lost_ack_preserves_exact_admission_for_readback_v24",
                  "native_dom_socket_retry_never_swallows_storage_scope_or_unknown_errors_v24",
                  "native_dom_incomplete_post_never_reaches_admission_v24",
                  "native_dom_post_storage_timeout_is_rejection_not_peer_retry_or_acceptance_v24"),
              features=("production",)),
    selection("native-preflight-funding-schedule", "dom-interopd",
              "production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::native_funding_v23::",
              "crates/dom-interopd/src/production_xmr_native_funding_fixture_v23.rs", (
                  "native_funding_sender_schedule_preserves_six_authenticated_roster_turns_v24",),
              features=("production",),
              test_filter="production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::native_funding_v23::native_funding_sender_schedule_preserves_six_authenticated_roster_turns_v24"),
    selection("native-preflight-participant-file", "dom-interopd",
              "production_inputs::tests::participant_file_bounds_v24::",
              "crates/dom-interopd/src/production_inputs.rs", (
                  "extended_xmr_file_uses_existing_codec_bound_v24",
                  "extended_xmr_read_still_requires_authenticated_manifest_pin_v24",
                  "participant_file_refuses_oversize_legacy_relabel_and_trailing_v24"),
              features=("production",)),
    selection("native-preflight-xmr-maturity", "dom-interopd",
              "production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::barrier::xmr_progress_v24::tests::",
              "crates/dom-interopd/src/production_xmr_native_daemon_scenario_v24_xmr_progress.rs", (
                  "scoped_funding_respects_negotiated_finality_and_native_unlock_v24",
                  "retained_funding_matures_with_empty_pool_at_exact_height_v24",
                  "unrelated_or_undispatched_pool_never_drives_inclusion_or_maturity_v24",
                  "terminal_spends_use_finality_and_multiple_fundings_use_latest_maturity_v24",
                  "planner_refuses_overflow_invalid_finality_and_inconsistent_history_v24"),
              features=("production",)),
    selection("native-preflight-leg-parameters", "dom-interopd",
              "production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::barrier::leg_parameters_v24_tests::",
              "crates/dom-interopd/src/production_xmr_native_daemon_scenario_v24_leg_parameters_tests.rs", (
                  "nested_enrollment_parameters_roundtrip_through_real_codec_v24",
                  "root_discriminator_other_families_and_open_parameters_are_refused_v24",
                  "manifest_digest_and_json_framing_remain_required_v24"),
              features=("production",)),
    selection("native-preflight-exit-diagnostic", "dom-interopd",
              "production_xmr_native_binary_v23_tests::process::exit_diagnostic_v24::tests::",
              "crates/dom-interopd/src/production_xmr_native_binary_v23_tests/process/exit_diagnostic_v24.rs", (
                  "exact_public_messages_map_only_to_fixed_codes_v24",
                  "secret_bytes_and_unknown_diagnostics_are_never_returned_v24",
                  "multiple_exact_errors_are_ambiguous_without_echoing_input_v24",
                  "diagnostic_respects_capture_bound_and_never_truncates_into_match_v24",
                  "allowlist_is_pinned_to_literal_production_errors_v24",
                  "stderr_capture_timeout_and_repeat_preserve_the_single_owned_result_v24"),
              features=("production",)),
    selection("native-preflight-xmr-rpc-budget", "dom-interopd",
              "production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_f6_v23::",
              "crates/dom-interopd/src/production_xmr_native_daemon_f6_v23_tests.rs", (
                  "native_runtime_bounds_cover_selected_xmr_rpc_deadline_v24",),
              features=("production",),
              test_filter="production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_f6_v23::native_runtime_bounds_cover_selected_xmr_rpc_deadline_v24"),
    selection("native-preflight-inventory-codec", "dom-interopd",
              "production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::native_observation_v23::route_funding_v23::inventory_fixture_compat_v24::",
              "crates/dom-interopd/src/production_xmr_native_inventory_fixture_compat_v24_tests.rs", (
                  "fixture_descriptor_roundtrips_through_production_reader_v24",
                  "production_reader_refuses_legacy_mutated_and_nonprivate_inventory_v24",
                  "inventory_fixture_scope_refuses_relabelled_source_v24",
                  "inventory_custody_derivation_binds_genesis_and_output_index_v24",
                  "inventory_public_evidence_keeps_production_domain_and_all_operands_v24"),
              features=("production",)),
    selection("native-preflight-original-bootstrap", "dom-interopd",
              "production_contracts_bootstrap::producer_v13::native_ceremony_tests::bootstrap_path_v24::",
              "crates/dom-interopd/src/production_xmr_native_bootstrap_path_v24_tests.rs", (
                  "original_native_bootstrap_path_is_selected_without_rewriting_v24",
                  "missing_copied_mutated_or_nonprivate_bootstrap_never_recreates_owner_v24",
                  "selected_native_bootstrap_path_reopens_real_xmr_private_owners_v24"),
              features=("production",)),
    selection("store-public-output-proof-cache", "dom-scriptless-store",
              "runtime::linux::session_store::xmr_graph_output_journal_v22::proof_cache_v24::tests::",
              "crates/dom-scriptless-store/src/runtime/linux/session_store/xmr_graph_output_proof_cache_v24.rs", (
                  "real_output_cold_warm_and_all_public_mutations_match_original_v24",
                  "cold_executes_and_warm_reuses_only_exact_success_v24",
                  "every_public_input_and_field_boundary_changes_key_v24",
                  "failures_are_never_memoized_v24",
                  "bounded_fifo_eviction_and_oversize_fall_back_v24",
                  "contention_and_poison_use_original_verifier_v24")),
    selection("native-public-phase-timing", "dom-interopd",
              "production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::timing_v24::",
              "crates/dom-interopd/src/production_xmr_native_daemon_timing_v24_tests.rs", (
                  "daemon_timing_observes_only_public_transitions_without_inventing_round_durations_v24",),
              features=("production",)),
    selection("xmr-graph-offer-proof-cache", "xmr-refund-policy",
              "graph_offer_v22::verification_cache_v24::tests::",
              "crates/adapters/xmr-refund-policy/src/graph_offer_verification_cache_v24_tests.rs", (
                  "real_graph_offer_cold_warm_and_uncached_results_are_identical_v24",
                  "real_graph_offer_cache_misses_every_trusted_scope_and_terms_family_v24",
                  "real_graph_offer_cache_misses_payload_keys_offsets_proofs_funding_and_payouts_v24",
                  "real_graph_offer_full_key_equality_and_strict_decode_survive_warm_cache_v24",
                  "real_graph_offer_cache_is_bounded_and_eviction_reexecutes_original_v24",
                  "real_graph_offer_poison_and_contention_fall_back_to_original_v24",
                  "real_graph_offer_warm_repeat64_reports_actual_verifier_counts_v24")),
    selection("adaptor-public-range-proof-cache", "dom-adaptor",
              "public_range_proof_cache_v24::tests::",
              "crates/dom-adaptor/src/public_range_proof_cache_v24.rs", (
                  "public_range_proof_cache_real_plain_and_capsule_64_replays_use_one_original_v24",
                  "public_range_proof_cache_mutations_never_reuse_success_or_cache_failure_v24",
                  "public_range_proof_cache_transaction_preserves_error_index_order_and_atomic_admission_v24",
                  "public_range_proof_cache_contention_and_poison_use_original_verifiers_v24",
                  "public_range_proof_cache_budget_eviction_is_bounded_and_not_a_validation_limit_v24")),
    selection("store-public-envelope-signature-cache", "dom-scriptless-store",
              "runtime::linux::session_store::public_envelope_signature_cache_v24::tests::",
              "crates/dom-scriptless-store/src/runtime/linux/session_store/public_envelope_signature_cache_v24_tests.rs", (
                  "public_envelope_real_64_replays_match_uncached_and_use_one_equation_v24",
                  "public_envelope_every_primitive_operand_mutation_misses_and_matches_original_v24",
                  "public_envelope_contention_falls_back_to_real_verifier_without_waiting_v24",
                  "public_envelope_poison_falls_back_to_real_verifier_and_never_admits_failure_v24",
                  "public_envelope_real_success_eviction_is_bounded_and_not_a_validation_limit_v24",
                  "public_envelope_warm_hit_never_accepts_changed_dsc1_context_or_framing_v24",
                  "public_envelope_malformed_signature_is_rejected_before_warm_lookup_v24")),
    selection("adaptor-collaborative-final-proof-cache", "dom-adaptor",
              "collaborative_range_proof::final_proof_cache_v25::tests::",
              "crates/dom-adaptor/src/collaborative_final_proof_cache_v25_tests.rs", (
                  "native_two_party_final_proof_cold_warm_repeat64_matches_original_v25",
                  "full_statement_scope_proof_and_raw_extra_mutations_match_original_v25",
                  "successful_cache_is_bounded_and_evicted_context_reexecutes_original_v25",
                  "oversized_valid_extra_commit_falls_back_and_framing_never_bypasses_v25",
                  "poisoned_or_busy_cache_reexecutes_original_without_reusing_finalizer_v25")),
    selection("adaptor-share-pop-equation-cache", "dom-adaptor",
              "share_pop::verification_cache_v25::tests::",
              "crates/dom-adaptor/src/share_pop_verification_cache_v25_tests.rs", (
                  "real_share_pop_cold_plus_warm64_matches_64_original_verifications_v25",
                  "every_statement_operand_and_proof_mutation_matches_original_v25",
                  "identical_statement_bytes_with_another_authenticated_roster_cannot_hit_v25",
                  "actual_public_point_operand_is_not_replaced_by_encoded_statement_bytes_v25",
                  "false_and_original_backend_errors_never_enter_success_cache_v25",
                  "fixed_capacity_evicts_only_successes_and_rechecks_old_equations_v25",
                  "contention_and_poison_fall_back_to_original_without_waiting_v25")),
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
    selection("native-f6-principal-face", "dom-interopd",
              "production_f6::terms::native_xmr_dom_face_v25::tests::",
              "crates/dom-interopd/src/production_f6/native_xmr_dom_face_v25_tests.rs", (
                  "real_principal_proofs_and_common_public_record_are_stable_v25",
                  "principal_recipient_roster_direction_chain_and_terms_transplants_fail_v25",
                  "other_valid_policy_payouts_cannot_be_relabelled_as_principal_v25",
                  "exact_public_principal_encoding_rejects_proof_and_capsule_mutations_v25",
                  "changed_availability_requires_new_proof_not_reused_principal_authority_v25"),
              features=("production",)),
    selection("native-f6-principal-slot", "dom-interopd",
              "production_f6_factory::native_principal_slot_v25::tests::",
              "crates/dom-interopd/src/production_f6_native_principal_slot_v25.rs", (
                  "awaiting_slot_preserves_absence_without_creating_an_owner",
                  "duplicate_publication_does_not_replenish_consumed_owner",
                  "different_principal_refused_before_and_after_consumption"),
              features=("production",)),
    selection("native-f6-principal-awaiting", "dom-interopd",
              "production_f6_activation::native_pending_v25_tests::",
              "crates/dom-interopd/src/production_f6_native_pending_v25_tests.rs", (
                  "awaiting_principal_retains_exact_factory_and_both_rfq_inputs_v25",
                  "principal_binding_refusal_still_poisoned_and_never_treated_as_wait_v25",
                  "changed_rfq_while_waiting_is_refused_without_rebinding_factory_v25"),
              features=("production",)),
    selection("native-f6-principal-provenance", "dom-interopd",
              "production_noise_relay::graph_offer_v22::f6_principal_v25::tests::",
              "crates/dom-interopd/src/production_noise_xmr_f6_principal_v25_tests.rs", (
                  "original_local_beneficiary_and_noise_peer_mint_identical_principal_owners_v25",
                  "peer_principal_reopens_from_original_journal_without_recreating_local_material_v25",
                  "valid_alternative_peer_proof_cannot_replace_original_retained_principal_v25",
                  "other_payouts_terms_and_corrupt_packets_never_publish_peer_principal_v25"),
              features=("production",)),
)

SELECTIONS += (
    selection("adaptor-native-round1-continuation", "dom-adaptor",
              "collaborative_range_proof::round1_continuation_v25::tests::",
              "crates/dom-adaptor/src/round1_continuation_v25_tests.rs", (
                  "real_two_party_round1_three_to_one_preserves_final_proof_and_durable_round2_v25",
                  "changed_private_origin_or_participant_refuses_without_replacing_round1_v25",
                  "complete_statement_and_raw_extra_are_compared_before_round1_reuse_v25",
                  "fresh_guards_and_consumed_state_never_become_round1_reuse_authority_v25",
                  "dropping_round1_holder_restarts_original_without_changing_public_share_v25",
                  "oversized_extra_always_computes_original_and_never_becomes_round1_memo_v25",
                  "failed_durable_round2_cannot_reuse_the_moved_round1_state_v25",
                  "poisoned_fresh_or_retained_round1_state_refuses_without_replacement_v25")),
    selection("native-f6-versioned-acceptance-codec", "rfq",
              "native_reconfirmation_v25::tests::",
              "crates/rfq/src/native_reconfirmation_v25_tests.rs", (
                  "genuine_rfq_quote_terms_roundtrip_preserves_complete_original_terms",
                  "legacy_and_new_acceptance_codecs_never_cross_decode",
                  "every_header_domain_version_flag_and_total_length_byte_is_closed",
                  "every_public_payload_bit_is_rejected_or_changes_expected_acceptance",
                  "all_inner_lengths_truncations_suffixes_and_overbounds_are_refused",
                  "inner_acceptance_must_match_full_terms_and_outer_initiator",
                  "every_terms_field_is_part_of_expected_acceptance_not_just_its_inner_id",
                  "missing_record_zero_identity_and_solver_as_initiator_are_refused",
                  "public_replay_is_exact_and_cannot_cross_record_initiator_session_or_position")),
    selection("native-f6-initiator-receiver-boundaries", "dom-interopd",
              "production_f6::initiator_v25::tests::",
              "crates/dom-interopd/src/production_f6/initiator_v25_tests.rs", (
                  "initiator_accepts_designated_solver_quote_sender_but_not_impersonation_v25",
                  "initiator_local_owner_and_selection_acceptance_sender_are_closed_v25",
                  "initiator_physical_bindings_cannot_open_solver_or_other_position_logs_v25",
                  "initiator_exact_records_survive_reopen_and_conflicts_never_overwrite_v25",
                  "initiator_delivery_replay_requires_exact_disposition_record_v25",
                  "initiator_reuses_exact_time_scope_not_embedded_clock_scope_v25",
                  "initiator_selection_cannot_switch_winner_or_authority_snapshot_v25"),
              features=("production",)),
    selection("native-proof-restart-cost-accounting", "dom-interopd",
              "production_contracts_bootstrap::producer_v13::native_ceremony_tests::native_proof_timing_v25::",
              "crates/dom-interopd/src/production_xmr_native_proof_timing_v25_tests.rs", (
                  "native_proof_restart_timing_counts_only_observed_calls_v25",
                  "native_proof_restart_timing_phases_are_disjoint_and_cover_total_v25"),
              features=("production",)),
    selection("adaptor-bound-partial-equation-cache", "dom-adaptor",
              "signing_round::partial_bound_verification_cache_v25::tests::",
              "crates/dom-adaptor/src/partial_bound_verification_cache_v25_tests.rs", (
                  "real_bound_partial_cold_plus_warm64_matches_64_original_verifications_v25",
                  "every_public_partial_equation_operand_matches_original_on_mutation_v25",
                  "warm_partial_cache_cannot_bypass_purpose_or_template_guards_v25",
                  "false_results_and_explicit_backend_error_policy_never_insert_success_v25",
                  "message_length_padding_and_oversize_preserve_original_acceptance_v25",
                  "fixed_capacity_rechecks_evicted_partial_equations_v25",
                  "partial_cache_contention_and_poison_use_original_without_waiting_v25")),
    selection("native-f6-public-reconfirmation", "dom-interopd",
              "production_f6::native_reconfirmation_v25::tests::",
              "crates/dom-interopd/src/production_f6/native_reconfirmation_v25_tests.rs", (
                  "public_checks_cover_both_positions_and_modes_without_rewriting_intent",
                  "altered_original_economics_and_authority_scope_are_refused",
                  "canonical_but_changed_quote_cannot_change_original_amounts_or_fee_cap",
                  "deadlines_require_same_dom_clock_without_comparing_foreign_heights",
                  "noncanonical_ids_and_missing_reservation_are_never_accepted_as_public_inputs",
                  "bounded_encoding_is_length_delimited_and_digest_binds_every_public_byte",
                  "real_signed_temporal_composition_constructs_and_retains_every_original_byte",
                  "another_real_composition_cannot_reuse_original_rfq_even_with_identical_terms"),
              features=("production",)),
)

SELECTIONS += (
    selection("native-f6-real-terms-proposal", "dom-interopd",
              "production_f6::terms::native_reconfirmation_terms_v25::tests::",
              "crates/dom-interopd/src/production_f6/terms/native_reconfirmation_terms_v25_tests.rs", (
                  "real_faces_and_signed_time_prepare_only_native_proposal_legacy_still_refuses",
                  "public_economic_and_scope_failures_preserve_real_faces_for_exact_retry",
                  "dom_registry_profile_is_not_wallet_consensus_and_wrong_domain_is_refused"),
              features=("production",)),
    selection("native-f6-original-acceptance-boundary", "dom-interopd",
              "production_f6::native_acceptance_v25::tests::",
              "crates/dom-interopd/src/production_f6/native_acceptance_v25_tests.rs", (
                  "opaque_native_proposal_exact_repeat_is_stable_and_never_legacy_authority",
                  "changed_binding_rfq_quote_or_signature_never_replaces_cached_real_proposal",
                  "physical_proposal_receipt_reopen_is_immutable_and_not_an_owner_decoder",
                  "native_proposal_refuses_legacy_foreign_and_development_stores_without_replacing_bytes",
                  "signed_outer_native_acceptance_reaches_boundary_unchanged_via_real_inbox",
                  "malformed_legacy_wrong_record_role_and_signature_never_authorize_native_boundary"),
              features=("production",)),
    selection("native-f6-solver-postcommit-confirmation", "dom-interopd",
              "production_f6::native_commitment_v25::tests::",
              "crates/dom-interopd/src/production_f6/native_commitment_v25_tests.rs", (
                  "native_commitment_public_codec_roundtrip_commits_complete_outer_acceptance_v25",
                  "native_commitment_never_decodes_legacy_acceptance_ready_or_ack_v25",
                  "native_commitment_header_bounds_truncations_suffixes_and_every_byte_are_closed_v25",
                  "native_commitment_zero_commit_revision_fence_or_scope_is_not_a_certificate_v25",
                  "native_commitment_matches_original_envelope_record_snapshot_and_all_wire_fields_v25",
                  "retained_native_acceptance_record_rejects_changed_payload_sequence_or_receipt_v25",
                  "native_commitment_receipts_are_role_scoped_immutable_and_missing_applied_refuses_v25",
                  "native_commitment_physical_store_reopen_rejects_legacy_downgrade_and_other_role_v25",
                  "native_commitment_producer_requires_real_solver_owner_not_caller_commit_fields_v25",
                  "native_commitment_sequence_zero_is_valid_but_exactly_bound_v25",
                  "native_commitment_uses_only_existing_solver_quote_role_and_receipt_kind_v25"),
              features=("production",)),
)

SELECTIONS += (
    selection("store-public-signing-semantics-cache", "dom-scriptless-store",
              "runtime::linux::session_store::xmr_graph_proposal_v22::public_signing_semantics_cache_v25::tests::",
              "crates/dom-scriptless-store/src/runtime/linux/session_store/public_signing_semantics_cache_v25_tests.rs", (
                  "public_signing_replay_cold_plus_warm64_matches_original_for_all_native_purposes_v25",
                  "every_public_signing_key_field_changes_identity_and_preserves_original_result_v25",
                  "bounded_transaction_key_matches_complete_original_codec_v25",
                  "unsigned_candidate_and_authenticated_envelope_never_alias_in_public_memo_v25",
                  "malformed_prefix_purpose_and_missing_fields_preserve_uncached_errors_v25",
                  "public_signing_memo_capacity_evicts_without_replacing_original_semantics_v25",
                  "busy_or_poisoned_public_signing_memo_always_calls_original_v25",
                  "oversized_public_operands_fall_back_without_new_protocol_limits_v25")),
)

SELECTIONS += (
    selection("store-session-head-exact-scan", "dom-scriptless-store",
              "runtime::linux::session_store::tests::session_head_scan_v25_tests::",
              "crates/dom-scriptless-store/src/runtime/linux/session_store/session_head_scan_v25_tests.rs", (
                  "session_head_scan_shuffled_revisions_match_original_lexical_head_v25",
                  "session_head_scan_missing_origin_and_interior_gap_stay_quarantined_v25",
                  "session_head_scan_changed_terms_and_irreversible_regression_refuse_v25",
                  "session_head_scan_projection_is_exact_scoped_and_never_a_cached_head_v25",
                  "session_head_scan_disk_projection_duplicate_revision_is_not_deduplicated_v25",
                  "session_head_scan_invalid_foreign_registered_entry_cannot_be_filtered_out_v25",
                  "session_head_scan_filename_cannot_substitute_record_session_or_revision_v25",
                  "session_head_scan_same_open_observes_append_then_removed_origin_v25")),
    selection("store-readonly-physical-inventory", "dom-scriptless-store",
              "runtime::linux::unordered_readonly_scan_v25_tests::",
              "crates/dom-scriptless-store/src/runtime/linux/unordered_readonly_scan_v25_tests.rs", (
                  "unordered_readonly_static_corpus_matches_original_inventory_v25",
                  "unordered_readonly_physical_refusals_match_original_before_callbacks_v25",
                  "unordered_readonly_exclusions_pin_identity_and_snapshot_without_callback_lock_v25",
                  "unordered_readonly_excluded_replacement_refuses_before_and_after_collection_v25",
                  "unordered_readonly_persistent_namespace_mutations_refuse_without_replaying_callbacks_v25",
                  "unordered_readonly_moved_directory_refuses_after_last_callback_v25",
                  "unordered_readonly_callback_error_is_exact_and_never_retried_v25",
                  "unordered_readonly_small_budget_falls_back_before_any_callback_v25",
                  "unordered_readonly_measures_three_physical_passes_and_one_callback_per_entry_v25")),
)

SELECTIONS += (
    selection("dom-refund-profile-domains", "dom-interopd",
              "production_refund_arming::tests::dom_profile_domains_v25_tests::",
              "crates/dom-interopd/src/production_refund_arming_dom_profile_v25_tests.rs", (
                  "refund_dom_profile_domains_match_real_registry_and_wallet_independently_v25",
                  "refund_dom_profile_domain_substitution_and_foreign_pins_refuse_v25"),
              features=("production",)),
    selection("resolved-dom-deployment-profile", "route-time-anchor", "",
              "crates/route-time-anchor/tests/dom_deployment_profile_v25.rs", (
                  "resolved_dom_deployment_matches_original_profile_on_all_authenticated_networks_v25",
                  "every_independently_mutable_dom_profile_field_changes_both_authenticated_digests_v25",
                  "isolated_chain_genesis_and_runtime_changes_cannot_mint_resolved_dom_capability_v25",
                  "dom_adapter_profile_remains_distinct_from_consensus_and_registry_domains_v25",
                  "registry_provenance_remains_separate_from_the_unchanged_twelve_field_dom_profile_v25",
                  "changed_dom_profile_with_old_registry_signatures_cannot_issue_typed_capability_v25"),
              integration="dom_deployment_profile_v25"),
)

SELECTIONS += (
    selection("store-graph-message-exact-scan", "dom-scriptless-store",
              "runtime::linux::session_store::xmr_graph_proposal_v22::message_collect_v25::tests::",
              "crates/dom-scriptless-store/src/runtime/linux/session_store/xmr_graph_message_collect_v25_tests.rs", (
                  "graph_message_collect_shuffled_physical_records_preserve_lexical_bytes_v25",
                  "graph_message_collect_preserves_foreign_and_equivocation_suffix_filters_v25",
                  "graph_message_collect_checks_invalid_and_foreign_physical_entries_before_filter_v25",
                  "graph_message_collect_corruption_keeps_original_error_flattening_v25",
                  "graph_message_collect_fresh_reload_observes_append_remove_and_tamper_v25",
                  "graph_message_collect_exclusions_require_original_physical_identity_v25",
                  "graph_message_collect_never_deduplicates_or_authenticates_records_v25")),
    selection("store-unsigned-graph-candidate-refusal", "dom-scriptless-store",
              "runtime::linux::session_store::tests::",
              "crates/dom-scriptless-store/src/runtime/linux/session_store/xmr_graph_candidate_v22_tests.rs", (
                  "unsigned_xmr_candidate_cache_is_immutable_scoped_and_not_a_transport_grant",),
              test_filter="runtime::linux::session_store::tests::unsigned_xmr_candidate_cache_is_immutable_scoped_and_not_a_transport_grant"),
    selection("store-transport-sequence-exact-scan", "dom-scriptless-store",
              "runtime::linux::session_store::tests::transport_sequence_scan_v25_tests::",
              "crates/dom-scriptless-store/src/runtime/linux/session_store/transport_sequence_scan_v25_tests.rs", (
                  "transport_sequence_scan_real_ingress_zero_inclusive_and_live_append_v25",
                  "transport_sequence_scan_shuffled_publication_and_real_reopen_match_lexical_v25",
                  "transport_sequence_scan_sender_session_and_equivocation_scope_v25",
                  "transport_sequence_scan_missing_zero_and_interior_gap_quarantine_v25",
                  "transport_sequence_scan_duplicate_embedded_sequence_quarantines_v25",
                  "transport_sequence_scan_tamper_is_fresh_and_decoded_before_revision_filter_v25")),
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
    if identifier == "native-preflight-http":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::native_observation_v23::dom_snapshot::http_v24::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::native_observation_v23::dom_snapshot::http_v24::tests::","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-preflight-funding-schedule":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::native_funding_v23::native_funding_sender_schedule_preserves_six_authenticated_roster_turns_v24","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::native_funding_v23::native_funding_sender_schedule_preserves_six_authenticated_roster_turns_v24","--","--nocapture","--test-threads=1","--color","never"],
                                cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-preflight-participant-file":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_inputs::tests::participant_file_bounds_v24::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_inputs::tests::participant_file_bounds_v24::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-preflight-xmr-maturity":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::barrier::xmr_progress_v24::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::barrier::xmr_progress_v24::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-preflight-leg-parameters":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::barrier::leg_parameters_v24_tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::barrier::leg_parameters_v24_tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-preflight-exit-diagnostic":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_xmr_native_binary_v23_tests::process::exit_diagnostic_v24::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_xmr_native_binary_v23_tests::process::exit_diagnostic_v24::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-preflight-xmr-rpc-budget":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_f6_v23::native_runtime_bounds_cover_selected_xmr_rpc_deadline_v24","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_f6_v23::native_runtime_bounds_cover_selected_xmr_rpc_deadline_v24","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-preflight-inventory-codec":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::native_observation_v23::route_funding_v23::inventory_fixture_compat_v24::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::native_observation_v23::route_funding_v23::inventory_fixture_compat_v24::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-preflight-original-bootstrap":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::bootstrap_path_v24::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::bootstrap_path_v24::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "store-public-output-proof-cache":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::xmr_graph_output_journal_v22::proof_cache_v24::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::xmr_graph_output_journal_v22::proof_cache_v24::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-public-phase-timing":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::timing_v24::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::timing_v24::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "xmr-graph-offer-proof-cache":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","xmr-refund-policy","--lib","graph_offer_v22::verification_cache_v24::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","xmr-refund-policy","--lib","graph_offer_v22::verification_cache_v24::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "adaptor-public-range-proof-cache":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-adaptor","--lib","public_range_proof_cache_v24::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-adaptor","--lib","public_range_proof_cache_v24::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "store-public-envelope-signature-cache":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::public_envelope_signature_cache_v24::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::public_envelope_signature_cache_v24::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "adaptor-collaborative-final-proof-cache":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-adaptor","--lib","collaborative_range_proof::final_proof_cache_v25::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-adaptor","--lib","collaborative_range_proof::final_proof_cache_v25::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "adaptor-share-pop-equation-cache":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-adaptor","--lib","share_pop::verification_cache_v25::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-adaptor","--lib","share_pop::verification_cache_v25::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "store-public-signing-semantics-cache":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::xmr_graph_proposal_v22::public_signing_semantics_cache_v25::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::xmr_graph_proposal_v22::public_signing_semantics_cache_v25::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "store-session-head-exact-scan":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::tests::session_head_scan_v25_tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::tests::session_head_scan_v25_tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "store-graph-message-exact-scan":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::xmr_graph_proposal_v22::message_collect_v25::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::xmr_graph_proposal_v22::message_collect_v25::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "store-unsigned-graph-candidate-refusal":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::tests::unsigned_xmr_candidate_cache_is_immutable_scoped_and_not_a_transport_grant","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::tests::unsigned_xmr_candidate_cache_is_immutable_scoped_and_not_a_transport_grant","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "store-transport-sequence-exact-scan":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::tests::transport_sequence_scan_v25_tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::session_store::tests::transport_sequence_scan_v25_tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "store-readonly-physical-inventory":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::unordered_readonly_scan_v25_tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-scriptless-store","--lib","runtime::linux::unordered_readonly_scan_v25_tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "dom-refund-profile-domains":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_refund_arming::tests::dom_profile_domains_v25_tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_refund_arming::tests::dom_profile_domains_v25_tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "resolved-dom-deployment-profile":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","route-time-anchor","--test","dom_deployment_profile_v25","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","route-time-anchor","--test","dom_deployment_profile_v25","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "adaptor-native-round1-continuation":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-adaptor","--lib","collaborative_range_proof::round1_continuation_v25::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-adaptor","--lib","collaborative_range_proof::round1_continuation_v25::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-f6-real-terms-proposal":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_f6::terms::native_reconfirmation_terms_v25::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_f6::terms::native_reconfirmation_terms_v25::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-f6-original-acceptance-boundary":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_f6::native_acceptance_v25::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_f6::native_acceptance_v25::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-f6-solver-postcommit-confirmation":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_f6::native_commitment_v25::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_f6::native_commitment_v25::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-f6-versioned-acceptance-codec":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","rfq","--lib","native_reconfirmation_v25::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","rfq","--lib","native_reconfirmation_v25::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-f6-initiator-receiver-boundaries":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_f6::initiator_v25::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_f6::initiator_v25::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-proof-restart-cost-accounting":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::native_proof_timing_v25::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_contracts_bootstrap::producer_v13::native_ceremony_tests::native_proof_timing_v25::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "adaptor-bound-partial-equation-cache":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-adaptor","--lib","signing_round::partial_bound_verification_cache_v25::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-adaptor","--lib","signing_round::partial_bound_verification_cache_v25::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-f6-public-reconfirmation":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_f6::native_reconfirmation_v25::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_f6::native_reconfirmation_v25::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-f6-principal-face":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_f6::terms::native_xmr_dom_face_v25::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_f6::terms::native_xmr_dom_face_v25::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-f6-principal-slot":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_f6_factory::native_principal_slot_v25::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_f6_factory::native_principal_slot_v25::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-f6-principal-awaiting":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_f6_activation::native_pending_v25_tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_f6_activation::native_pending_v25_tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
                                stderr=subprocess.STDOUT, start_new_session=True)
    if identifier == "native-f6-principal-provenance":
        if expected != ["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_noise_relay::graph_offer_v22::f6_principal_v25::tests::","--","--nocapture","--test-threads=1","--color","never"]:
            raise ValueError("native test dispatch differs from its closed argv")
        return subprocess.Popen(["cargo","test","--locked","--profile","crypto-test","-p","dom-interopd","--no-default-features","--features","production","--lib","production_noise_relay::graph_offer_v22::f6_principal_v25::tests::","--","--nocapture","--test-threads=1","--color","never"], cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=stdout,
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
    process = tracker = None
    started = time.monotonic()
    log = case / "test.log"
    try:
        env = production_environment_v24(dict(os.environ))
        env.update(CARGO_BUILD_JOBS="2", CARGO_TERM_COLOR="never", RUST_TEST_THREADS="1")
        result["private_fixture_root"] = env["TMPDIR"]
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
