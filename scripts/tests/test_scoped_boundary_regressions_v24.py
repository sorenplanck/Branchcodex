"""Validate the closed CI boundary list without running Cargo or any daemon."""
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scoped_boundary_regressions_v24 as runner


class ClosedBoundaryListTests(unittest.TestCase):
    def test_every_required_name_is_an_actual_test_in_the_declared_package(self):
        ids = [item["id"] for item in runner.SELECTIONS]
        self.assertEqual(len(ids), 42)
        self.assertEqual(ids[:8], [
            "native-preflight-policy", "native-preflight-deadline", "native-preflight-wallet",
            "native-preflight-history", "native-preflight-http",
            "native-preflight-funding-schedule",
            "native-preflight-participant-file",
            "native-preflight-xmr-maturity",
        ])
        self.assertEqual(len(ids), len(set(ids)))
        for item in runner.SELECTIONS:
            with self.subTest(selection=item["id"]):
                source = runner.ROOT / item["source"]
                text = source.read_text()
                definitions = set(re.findall(r"#\[test\]\s*(?:#\[[^\]]+\]\s*)*(?:async\s+)?fn\s+(\w+)\s*\(", text))
                self.assertTrue(item["required_tests"])
                self.assertEqual(len(item["required_tests"]), len(set(item["required_tests"])))
                for name in item["required_tests"]:
                    self.assertTrue(name.startswith(item["module_prefix"]))
                    self.assertIn(name.removeprefix(item["module_prefix"]), definitions)
                    self.assertIn(item["filter"], name)
                manifest = next(parent / "Cargo.toml" for parent in source.parents
                                if (parent / "Cargo.toml").is_file())
                package = re.search(r'^name\s*=\s*"([^"]+)"', manifest.read_text(), re.MULTILINE)
                self.assertEqual(package[1], item["package"])

    def test_declared_nested_modules_match_the_rust_module_graph(self):
        # Explicit path attributes use module identifiers, NOT the filenames:
        # f7_xmr_refund_transport_v23.rs lives under f7_v12::xmr_refund_transport_v23.
        edges = (
            ("crates/dom-interopd/src/lib.rs", "production_inputs"),
            ("crates/dom-interopd/src/production_bootstrap_v13_tests.rs", "xmr_graph_wallet_tests"),
            ("crates/dom-interopd/src/production_xmr_graph_wallet_v22_tests.rs", "native_observation_v23"),
            ("crates/dom-interopd/src/production_xmr_graph_wallet_v22_tests.rs", "native_funding_v23"),
            ("crates/dom-interopd/src/production_xmr_native_observation_v23_tests.rs", "dom_snapshot"),
            ("crates/dom-interopd/src/production_xmr_native_dom_snapshot_v23_tests.rs", "history_v24"),
            ("crates/dom-interopd/src/production_xmr_native_dom_snapshot_v23_tests.rs", "http_v24"),
            ("crates/dom-interopd/src/production_bootstrap_v13_tests.rs", "xmr_coldstart_v23"),
            ("crates/dom-interopd/src/production_xmr_native_coldstart_v23_tests.rs", "daemon_scenario_v23"),
            ("crates/dom-interopd/src/production_xmr_native_daemon_scenario_v23_tests.rs", "timing_v24"),
            ("crates/dom-interopd/src/production_xmr_native_daemon_scenario_v23_tests.rs", "barrier"),
            ("crates/dom-interopd/src/production_xmr_native_daemon_scenario_v23_barrier.rs", "xmr_progress_v24"),
            ("crates/dom-interopd/src/production_xmr_native_daemon_scenario_v23_barrier.rs", "leg_parameters_v24_tests"),
            ("crates/dom-interopd/src/lib.rs", "production_xmr_native_binary_v23_tests"),
            ("crates/dom-interopd/src/production_xmr_native_binary_v23_tests.rs", "process"),
            ("crates/dom-interopd/src/production_xmr_native_binary_v23_tests/process.rs", "exit_diagnostic_v24"),
            ("crates/dom-interopd/src/production_xmr_native_coldstart_v23_tests.rs", "deadline_plan_v23"),
            ("crates/dom-interopd/src/production_xmr_native_coldstart_v23_tests.rs", "daemon_wallet_v23"),
            ("crates/dom-interopd/src/production_xmr_native_coldstart_v23_tests.rs", "daemon_f6_v23"),
            ("crates/dom-interopd/src/production_xmr_native_deadline_plan_v23_tests.rs", "projection_v24"),
            ("crates/dom-interopd/src/production_xmr_native_daemon_wallet_v23_tests.rs", "scan_tests_v24"),
            ("crates/adapters/dom-real/src/lib.rs", "funding_deadline_v23_tests"),
            ("crates/adapters/dom-real/src/lib.rs", "terminal_finality"),
            ("crates/adapters/dom-real/src/lib.rs", "xmr_recovery_execution_v12"),
            ("crates/adapters/dom-real/src/lib.rs", "xmr_recovery_finality"),
            ("crates/adapters/dom-real/src/terminal_finality.rs", "funding_bounded_v23"),
            ("crates/adapters/dom-real/src/xmr_recovery_finality.rs", "refund_reorg_v23"),
            ("crates/dom-actuator/src/lib.rs", "contracts"),
            ("crates/dom-actuator/src/contracts.rs", "funding_dispatch_v23"),
            ("crates/dom-actuator/src/contracts.rs", "native_xmr_refund_v23"),
            ("crates/dom-scriptless-store/src/runtime/linux.rs", "session_store"),
            ("crates/dom-scriptless-store/src/runtime/linux.rs", "xmr_recovery"),
            ("crates/dom-scriptless-store/src/runtime/linux/session_store.rs", "f7_v12"),
            ("crates/dom-scriptless-store/src/runtime/linux/session_store.rs", "xmr_graph_output_journal_v22"),
            ("crates/dom-scriptless-store/src/runtime/linux/session_store.rs", "public_envelope_signature_cache_v24"),
            ("crates/dom-scriptless-store/src/runtime/linux/session_store/public_envelope_signature_cache_v24.rs", "tests"),
            ("crates/dom-scriptless-store/src/runtime/linux/session_store/xmr_graph_output_journal_v22.rs", "proof_cache_v24"),
            ("crates/adapters/xmr-refund-policy/src/lib.rs", "graph_offer_v22"),
            ("crates/adapters/xmr-refund-policy/src/graph_offer_v22.rs", "verification_cache_v24"),
            ("crates/adapters/xmr-refund-policy/src/graph_offer_verification_cache_v24.rs", "tests"),
            ("crates/dom-adaptor/src/lib.rs", "public_range_proof_cache_v24"),
            ("crates/dom-adaptor/src/lib.rs", "collaborative_range_proof"),
            ("crates/dom-adaptor/src/collaborative_range_proof.rs", "final_proof_cache_v25"),
            ("crates/dom-adaptor/src/collaborative_final_proof_cache_v25.rs", "tests"),
            ("crates/dom-scriptless-store/src/runtime/linux/session_store/f7_v12.rs", "xmr_refund_transport_v23"),
            ("crates/dom-scriptless-store/src/runtime/linux/xmr_recovery.rs", "execution_v12"),
            ("crates/f7-anchor-authority/src/families_v11/mod.rs", "authorization_v12"),
            ("crates/f7-anchor-authority/src/lib.rs", "native_scan_deadline_v23_tests"),
            ("crates/adapters/xmr-key-image-proof/src/lib.rs", "local_build_request_v24"),
            ("crates/adapters/xmr-live-sidecar-uds-client/src/lib.rs", "local_load_deadline_v24_tests"),
            ("crates/adapters/xmr-rpc-broadcast-blocking/src/lib.rs", "broadcast_deadline_v24"),
            ("crates/adapters/xmr-rpc-broadcast-blocking/src/lib.rs", "observation_deadline_v24"),
            ("crates/dom-interopd/src/lib.rs", "production_children"),
            ("crates/dom-interopd/src/lib.rs", "production_xmr_recovery_driver_v12"),
            ("crates/dom-interopd/src/lib.rs", "production_xmr_remote_sweep_v23"),
            ("crates/dom-interopd/src/production_xmr_remote_sweep_v23.rs", "remote_refund_v23"),
            ("crates/dom-interopd/src/lib.rs", "relay_worker"),
            ("crates/dom-interopd/src/relay_worker.rs", "terminal_refund_v24_tests"),
        )
        for source, module in edges:
            with self.subTest(source=source, module=module):
                self.assertRegex((runner.ROOT / source).read_text(), rf"\bmod {module};")
        self.assertEqual(runner.spec_for("store-refund-transport-grant")["module_prefix"],
                         "runtime::linux::session_store::f7_v12::xmr_refund_transport_v23::tests::")

    def test_history_preflight_keeps_all_four_tests_and_literal_process_dispatch(self):
        spec = runner.spec_for("native-preflight-history")
        self.assertEqual(spec["module_prefix"],
                         "production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::native_observation_v23::dom_snapshot::history_v24::tests::")
        self.assertEqual(spec["filter"], spec["module_prefix"])
        self.assertEqual(spec["required_tests"], [
            spec["module_prefix"] + "campaign_pages_preserve_original_absolute_heights_and_request_bounds_v24",
            spec["module_prefix"] + "campaign_reader_rejects_truncated_or_mutated_storage_v24",
            spec["module_prefix"] + "campaign_append_refuses_skips_and_negotiated_limit_overflow_v24",
            spec["module_prefix"] + "campaign_frozen_reader_does_not_block_native_history_publication_v24",
        ])
        with mock.patch.object(runner.subprocess, "Popen") as process:
            runner.start_test_command_v24(spec["id"], cwd=runner.ROOT, env={}, stdout=None)
            self.assertEqual(process.call_args.args[0], runner.command(spec["id"]))
            process.assert_called_once()

    def test_http_preflight_keeps_all_five_tests_and_literal_process_dispatch(self):
        spec = runner.spec_for("native-preflight-http")
        self.assertEqual(spec["module_prefix"],
                         "production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::native_observation_v23::dom_snapshot::http_v24::tests::")
        self.assertEqual(spec["filter"], spec["module_prefix"])
        self.assertEqual(spec["required_tests"], [
            spec["module_prefix"] + "native_dom_get_peer_timeout_keeps_next_connection_available_v24",
            spec["module_prefix"] + "native_dom_post_lost_ack_preserves_exact_admission_for_readback_v24",
            spec["module_prefix"] + "native_dom_socket_retry_never_swallows_storage_scope_or_unknown_errors_v24",
            spec["module_prefix"] + "native_dom_incomplete_post_never_reaches_admission_v24",
            spec["module_prefix"] + "native_dom_post_storage_timeout_is_rejection_not_peer_retry_or_acceptance_v24",
        ])
        with mock.patch.object(runner.subprocess, "Popen") as process:
            runner.start_test_command_v24(spec["id"], cwd=runner.ROOT, env={}, stdout=None)
            self.assertEqual(process.call_args.args[0], runner.command(spec["id"]))
            process.assert_called_once()

    def test_funding_schedule_preflight_selects_only_the_cheap_roster_test(self):
        spec = runner.spec_for("native-preflight-funding-schedule")
        exact = "production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_graph_wallet_tests::native_funding_v23::native_funding_sender_schedule_preserves_six_authenticated_roster_turns_v24"
        self.assertEqual(spec["required_tests"], [exact])
        self.assertEqual(spec["filter"], exact)
        with mock.patch.object(runner.subprocess, "Popen") as process:
            runner.start_test_command_v24(spec["id"], cwd=runner.ROOT, env={}, stdout=None)
            self.assertEqual(process.call_args.args[0], runner.command(spec["id"]))
            process.assert_called_once()

    def test_participant_file_preflight_keeps_all_three_bounds_and_pin_tests(self):
        spec = runner.spec_for("native-preflight-participant-file")
        source = (runner.ROOT / spec["source"]).read_text()
        self.assertIn("mod participant_file_bounds_v24 {", source)
        self.assertEqual(spec["filter"], "production_inputs::tests::participant_file_bounds_v24::")
        self.assertEqual(spec["required_tests"], [
            spec["filter"] + "extended_xmr_file_uses_existing_codec_bound_v24",
            spec["filter"] + "extended_xmr_read_still_requires_authenticated_manifest_pin_v24",
            spec["filter"] + "participant_file_refuses_oversize_legacy_relabel_and_trailing_v24",
        ])
        with mock.patch.object(runner.subprocess, "Popen") as process:
            runner.start_test_command_v24(spec["id"], cwd=runner.ROOT, env={}, stdout=None)
            self.assertEqual(process.call_args.args[0], runner.command(spec["id"]))
            process.assert_called_once()

    def test_proof_caches_and_timing_are_additive_and_keep_real_verifier_comparisons(self):
        expected = {
            "store-public-output-proof-cache": (6, "real_output_cold_warm_and_all_public_mutations_match_original_v24"),
            "native-public-phase-timing": (1, "daemon_timing_observes_only_public_transitions_without_inventing_round_durations_v24"),
            "xmr-graph-offer-proof-cache": (7, "real_graph_offer_warm_repeat64_reports_actual_verifier_counts_v24"),
            "adaptor-public-range-proof-cache": (5, "public_range_proof_cache_transaction_preserves_error_index_order_and_atomic_admission_v24"),
            "store-public-envelope-signature-cache": (7, "public_envelope_real_64_replays_match_uncached_and_use_one_equation_v24"),
            "adaptor-collaborative-final-proof-cache": (5, "native_two_party_final_proof_cold_warm_repeat64_matches_original_v25"),
        }
        self.assertEqual([item["id"] for item in runner.SELECTIONS[11:17]], list(expected))
        for identifier, (count, mandatory) in expected.items():
            with self.subTest(selection=identifier):
                spec = runner.spec_for(identifier)
                self.assertEqual(len(spec["required_tests"]), count)
                self.assertIn(spec["module_prefix"] + mandatory, spec["required_tests"])
                self.assertEqual(spec["filter"], spec["module_prefix"])
                self.assertNotIn("--ignored", runner.command(identifier))
                with mock.patch.object(runner.subprocess, "Popen") as process:
                    runner.start_test_command_v24(identifier, cwd=runner.ROOT, env={}, stdout=None)
                    self.assertEqual(process.call_args.args[0], runner.command(identifier))
                    process.assert_called_once()

    def test_xmr_maturity_preflight_keeps_five_pure_scope_and_height_tests(self):
        spec = runner.spec_for("native-preflight-xmr-maturity")
        self.assertEqual(spec["module_prefix"],
                         "production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::barrier::xmr_progress_v24::tests::")
        self.assertEqual(spec["filter"], spec["module_prefix"])
        self.assertEqual(spec["required_tests"], [spec["module_prefix"] + name for name in (
            "scoped_funding_respects_negotiated_finality_and_native_unlock_v24",
            "retained_funding_matures_with_empty_pool_at_exact_height_v24",
            "unrelated_or_undispatched_pool_never_drives_inclusion_or_maturity_v24",
            "terminal_spends_use_finality_and_multiple_fundings_use_latest_maturity_v24",
            "planner_refuses_overflow_invalid_finality_and_inconsistent_history_v24",
        )])
        with mock.patch.object(runner.subprocess, "Popen") as process:
            runner.start_test_command_v24(spec["id"], cwd=runner.ROOT, env={}, stdout=None)
            self.assertEqual(process.call_args.args[0], runner.command(spec["id"]))
            process.assert_called_once()

    def test_safe_exit_and_leg_codec_preflights_remain_closed_pure_tests(self):
        for identifier, count in (("native-preflight-leg-parameters", 3),
                                  ("native-preflight-exit-diagnostic", 6)):
            with self.subTest(selection=identifier):
                spec = runner.spec_for(identifier)
                self.assertEqual(len(spec["required_tests"]), count)
                self.assertEqual(spec["filter"], spec["module_prefix"])
                self.assertEqual(spec["features"], ["production"])
                with mock.patch.object(runner.subprocess, "Popen") as process:
                    runner.start_test_command_v24(identifier, cwd=runner.ROOT, env={}, stdout=None)
                    self.assertEqual(process.call_args.args[0], runner.command(identifier))
                    process.assert_called_once()

    def test_xmr_rpc_budget_preflight_runs_only_the_selected_bound_regression(self):
        spec = runner.spec_for("native-preflight-xmr-rpc-budget")
        exact = "production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_f6_v23::native_runtime_bounds_cover_selected_xmr_rpc_deadline_v24"
        self.assertEqual(spec["required_tests"], [exact])
        self.assertEqual(spec["filter"], exact)
        with mock.patch.object(runner.subprocess, "Popen") as process:
            runner.start_test_command_v24(spec["id"], cwd=runner.ROOT, env={}, stdout=None)
            self.assertEqual(process.call_args.args[0], runner.command(spec["id"]))
            process.assert_called_once()

    def test_every_command_is_locked_serial_and_reuses_crypto_test(self):
        for item in runner.SELECTIONS:
            args = runner.command(item["id"])
            with self.subTest(selection=item["id"]):
                self.assertEqual(args[:5], ["cargo", "test", "--locked", "--profile", "crypto-test"])
                self.assertEqual(args[args.index("-p") + 1], item["package"])
                self.assertEqual(args[-5:], ["--", "--nocapture", "--test-threads=1", "--color", "never"])
                for forbidden in ("--workspace", "--all-targets", "--ignored", "--include-ignored", "--release"):
                    self.assertNotIn(forbidden, args)
                if item["integration"]:
                    self.assertEqual(args[args.index("--test") + 1], item["integration"])
                else:
                    self.assertIn("--lib", args)
                if item["package"] in {"dom-actuator", "dom-interopd"}:
                    self.assertIn("--no-default-features", args)
                    self.assertEqual(args[args.index("--features") + 1], "production")
        with self.assertRaises(ValueError):
            runner.command("native_graph_or_arbitrary_input")

    def test_api_and_spend_port_are_honestly_compile_only(self):
        self.assertEqual({item["package"] for item in runner.COMPILE_ONLY},
                         {"xmr-live-sidecar-api", "xmr-spend-port"})
        for item in runner.COMPILE_ONLY:
            self.assertEqual(item["native_test_count"], 0)
            self.assertEqual(runner.spec_for(item["compiled_by"])["package"], "xmr-live-sidecar-uds-client")
            source = runner.ROOT / "crates/adapters" / item["package"] / "src/lib.rs"
            self.assertNotRegex(source.read_text(), r"#\[(?:test|tokio::test)\]")

    def test_store_handoff_selection_cannot_run_the_whole_relay_integration_suite(self):
        identifier = "store-terminal-ack-handoff-reopen"
        name = "store_application_ack_loss_restarts_with_identical_bytes_and_no_new_sequence"
        selection = runner.spec_for(identifier)
        self.assertEqual(selection["required_tests"], [name])
        self.assertEqual(selection["filter"], name)
        self.assertEqual(runner.command(identifier), [
            "cargo", "test", "--locked", "--profile", "crypto-test", "-p", "dom-interopd",
            "--no-default-features", "--features", "production", "--test", "relay_worker",
            name, "--", "--nocapture", "--test-threads=1", "--color", "never",
        ])


class BoundaryEvidenceTests(unittest.TestCase):
    def transcript(self, identifier):
        names = runner.spec_for(identifier)["required_tests"]
        count = len(names)
        return (f"running {count} tests\n"
                + "".join(f"test {name} ... captured output\nok\n" for name in names)
                + f"test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 99 filtered out\n")

    def test_all_real_names_and_a_nonzero_summary_are_mandatory(self):
        for item in runner.SELECTIONS:
            identifier = item["id"]
            body = self.transcript(identifier)
            with self.subTest(selection=identifier):
                self.assertEqual(runner.evaluate_output(identifier, 0, body)["status"], "passed")
                self.assertEqual(runner.evaluate_output(identifier, 1, body)["status"], "failed")
                for invalid in ("", "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored;\n",
                                body.split("test result:")[0], body + body,
                                body.replace(item["required_tests"][0], "unrelated::test")):
                    self.assertEqual(runner.evaluate_output(identifier, 0, invalid)["status"], "failed")

    def test_store_handoff_evidence_rejects_unrelated_integration_tests(self):
        identifier = "store-terminal-ack-handoff-reopen"
        expected = self.transcript(identifier)
        self.assertEqual(runner.evaluate_output(identifier, 0, expected)["status"], "passed")
        entire_suite = expected.replace("running 1 tests", "running 2 tests").replace(
            "test result: ok. 1 passed;",
            "test prepared_operational_signing ... ok\ntest result: ok. 2 passed;",
        )
        self.assertEqual(runner.evaluate_output(identifier, 0, entire_suite)["status"], "failed")

    def test_failed_selection_continues_only_after_proven_cleanup(self):
        for cleaned in (False, True):
            with self.subTest(cleaned=cleaned), tempfile.TemporaryDirectory() as directory:
                results = [{"status": "failed", "cleanup_verified": cleaned}]
                results += [{"status": "passed", "cleanup_verified": True}] * (len(runner.SELECTIONS) - 1)
                with mock.patch.object(runner, "run_selection", side_effect=results) as execute, \
                        mock.patch.object(runner.ctypes, "CDLL") as libc, \
                        mock.patch.object(runner.signal, "signal"), \
                        mock.patch.object(runner, "CANCELLED", False):
                    libc.return_value.prctl.return_value = 0
                    self.assertEqual(runner.main(["--evidence-dir", directory]), 1)
                self.assertEqual(execute.call_count, len(runner.SELECTIONS) if cleaned else 1)
                report = json.loads((Path(directory) / "campaign.json").read_text())
                self.assertEqual(report["status"], "failed")
                if not cleaned:
                    self.assertEqual(report["results"][1]["status"], "not-run")


class ProductionEnvironmentTests(unittest.TestCase):
    def test_private_tmp_is_scoped_to_child_and_parent_is_unchanged(self):
        import shutil
        from run_native_daemon_scenario_v23 import private_synthetic_tmp
        root = private_synthetic_tmp()
        self.addCleanup(shutil.rmtree, root)
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(runner.os.environ, {"DOM_XMR_PRIVATE_TMP_V23": str(root), "TMPDIR": "/tmp"}), \
                mock.patch.object(runner, "start_test_command_v24", side_effect=OSError("no process launched")) as start:
            result = runner.run_selection("native-preflight-http", Path(directory), 1)
            self.assertEqual(start.call_args.kwargs["env"]["TMPDIR"], str(root))
            self.assertEqual(start.call_args.kwargs["env"]["CARGO_BUILD_JOBS"], "2")
            self.assertEqual(start.call_args.kwargs["env"]["RUST_TEST_THREADS"], "1")
            self.assertEqual(runner.os.environ["TMPDIR"], "/tmp")
            self.assertEqual(result["private_fixture_root"], str(root))
            self.assertEqual(result["status"], "failed")
            self.assertTrue(result["cleanup_verified"])

    def test_invalid_private_root_refuses_before_any_cargo_process(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(runner.os.environ, {"DOM_XMR_PRIVATE_TMP_V23": "/tmp"}), \
                mock.patch.object(runner, "start_test_command_v24") as start:
            result = runner.run_selection("native-preflight-http", Path(directory), 1)
            start.assert_not_called()
            self.assertEqual(result["status"], "failed")
            self.assertTrue(result["cleanup_verified"])
            self.assertIn("PermissionError", result["error"])


if __name__ == "__main__":
    unittest.main()
