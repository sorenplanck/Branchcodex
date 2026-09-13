"""Fast dispatch contracts; no Cargo, Forge, daemon or network is executed."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_interop_hardening as runner


FULL_ORDER = (
    "independent-oracles", "workspace-lock", "bitcoin",
    "rust-driver-final-signature-verification", "rust-participant-independent-verification",
    "solana-adapters", "solana-program-host", "monero-rpc-and-actuator-v5", "production",
    "rust-route-independent-verification", "rust-time-independent-verification",
    "bitcoin-regtest", "evm-deep", "evm-anvil",
)
COMPONENT_PACKAGES = {
    "bitcoin": ("btc-crypto", "adapter-btc", "btc-actuator"),
    "solana-adapters": (
        "kaystra-core", "solana-kaystra-source", "solana-escrow-wire", "solana-program-client",
        "solana-observer", "solana-evidence", "solana-observation-store", "solana-observer-pump",
    ),
    "monero-rpc-and-actuator-v5": ("xmr-rpc-broadcast-blocking", "xmr-actuator"),
}


class HardeningProfileCache(unittest.TestCase):
    def test_native_exact_splits_name_real_distinct_tests_and_never_skip_another_symbol(self):
        expected = {
            "production-native-funding": "v23_native_two_leg_templates_custody_ready_and_bounded_funding",
            "production-native-claim": "v23_native_claim_six_messages_and_presignature_with_real_output_scan",
            "production-native-wallet-reopen": "v22_both_wallets_reopen_payout_proofs_and_five_native_graph_excesses",
            "production-native-templates": "v23_two_wallets_and_native_cd_proofs_form_identical_graph_templates",
        }
        self.assertEqual(runner.NATIVE_EXACT_TESTS, {
            shard: runner.NATIVE_TEST_PREFIX + "::" + name for shard, name in expected.items()
        })
        self.assertEqual(runner.NATIVE_EXACT_SHARDS, frozenset(expected))
        source = (runner.ROOT / "crates/dom-interopd/src/production_xmr_graph_wallet_v22_tests.rs").read_text()
        tests = re.findall(r"#\[test\]\s*fn\s+(\w+)\s*\(", source)
        for name in expected.values():
            self.assertIn(name, tests)
            # libtest --skip is substring-based, while each separated shard is
            # exact. A future similarly named top-level test must not vanish.
            self.assertEqual([other for other in tests if name in other], [name])

    def test_exact_native_shards_fail_closed_on_zero_or_multiple_tests(self):
        with tempfile.TemporaryDirectory(prefix="exact-native-") as directory:
            log = Path(directory) / "test.log"
            for count in (0, 2):
                log.write_text(
                    f"test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured;\n")
                for shard in runner.NATIVE_EXACT_SHARDS:
                    self.assertEqual(
                        runner.exact_native_shard_error(shard, log),
                        "exact native shard did not report exactly one passed test")
            log.write_text("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;\n")
            for shard in runner.NATIVE_EXACT_SHARDS:
                self.assertIsNone(runner.exact_native_shard_error(shard, log))
            self.assertIsNone(runner.exact_native_shard_error("production-native", log))

    def test_production_tmp_is_owned_private_canonical_and_does_not_mutate_parent(self):
        # Use a real owner-only ancestor instead of shared /tmp; no daemon or
        # native fixture is created by this lightweight filesystem check.
        with tempfile.TemporaryDirectory(prefix="hp-", dir=Path.home()) as directory:
            home = Path(directory)
            base = home / ".dx-v23"
            base.mkdir(mode=0o700)
            private = base / "dx-test"
            private.mkdir(mode=0o700)
            env = {"DOM_XMR_PRIVATE_TMP_V23": str(private), "TMPDIR": "/original/tmp", "KEPT": "yes"}
            with mock.patch.object(runner.Path, "home", return_value=home):
                adjusted = runner.production_environment_v24(env)
            self.assertEqual(adjusted, {**env, "TMPDIR": str(private)})
            self.assertEqual(env["TMPDIR"], "/original/tmp")
            self.assertIsNot(adjusted, env)

    def test_production_tmp_refuses_missing_foreign_symlink_and_unsafe_permissions(self):
        with tempfile.TemporaryDirectory(prefix="hp-", dir=Path.home()) as directory:
            home = Path(directory)
            base = home / ".dx-v23"
            base.mkdir(mode=0o700)
            private = base / "dx-test"
            private.mkdir(mode=0o700)
            link = base / "dx-link"
            link.symlink_to(private, target_is_directory=True)
            regular = base / "dx-file"
            regular.write_text("not a directory")
            with mock.patch.object(runner.Path, "home", return_value=home):
                for raw in (None, "", "/tmp", ".dx-v23/dx-test", str(base), str(link),
                            str(regular), str(base / "dx-missing"), str(private) + "/..", "\0"):
                    with self.subTest(raw=raw), self.assertRaises(OSError):
                        runner.production_environment_v24({"DOM_XMR_PRIVATE_TMP_V23": raw})
                env = {"DOM_XMR_PRIVATE_TMP_V23": str(private)}
                for path, mode in ((private, 0o702), (private, 0o750), (base, 0o750), (home, 0o777)):
                    with self.subTest(path=path.name, mode=mode):
                        path.chmod(mode)
                        try:
                            with self.assertRaises(OSError):
                                runner.production_environment_v24(env)
                        finally:
                            path.chmod(0o700)
                with mock.patch.object(runner.os, "getuid", return_value=os.getuid() + 1):
                    with self.assertRaises(OSError):
                        runner.production_environment_v24(env)

    def test_component_commands_keep_targets_continue_after_failures_and_match_literal_dispatch(self):
        evidence = Path("/synthetic-evidence")
        for mode in ("full", "components", "runtime"):
            for name, command, env in runner.commands(mode, evidence):
                if name not in COMPONENT_PACKAGES:
                    continue
                expected = ["cargo", "test", "--locked", "--no-fail-fast", "--profile", "crypto-test"]
                for package in COMPONENT_PACKAGES[name]:
                    expected.extend(("-p", package))
                self.assertEqual(command, expected)
                with mock.patch.object(runner.subprocess, "Popen") as start:
                    runner.start_test_command(name, env, evidence)
                self.assertEqual(start.call_count, 1)
                self.assertEqual(start.call_args.args[0], command)
                self.assertEqual(start.call_args.kwargs["cwd"], runner.ROOT)
                self.assertEqual(start.call_args.kwargs["env"], env)

    def test_full_preserves_every_command_oracle_and_original_production_targets(self):
        specs = runner.commands("full", Path("/synthetic-evidence"))
        self.assertEqual(tuple(name for name, _, _ in specs), FULL_ORDER)
        by_name = {name: (command, env) for name, command, env in specs}
        production, env = by_name["production"]
        self.assertEqual(production, [
            "cargo", "test", "-p", "dom-interopd", "--no-default-features",
            "--features", "production", "--lib", "--tests", "--locked",
            "--profile", "crypto-test", "--no-fail-fast", "--", "--nocapture", "--test-threads=1",
        ])
        self.assertEqual(set(env), {"DOM_INTEROP_V4_ROUTE_TRACE", "DOM_INTEROP_V5_TIME_FIXTURE"})
        self.assertEqual(set(by_name["bitcoin"][1]), {
            "DOM_INTEROP_V6_DRIVER_CLAIM", "DOM_INTEROP_V3_PUBLIC_FIXTURE",
        })
        self.assertEqual(by_name["solana-program-host"][0], [
            "cargo", "test", "--manifest-path", "programs/dom-solana-escrow/Cargo.toml", "--locked", "--no-fail-fast",
        ])
        self.assertEqual(by_name["bitcoin-regtest"][0], ["bash", "scripts/f5-regtest-e2e.sh"])
        self.assertEqual(by_name["evm-deep"], (["forge", "test", "--root", "contracts"],
                                                {"FOUNDRY_PROFILE": "deep"}))
        self.assertEqual(by_name["evm-anvil"][0], ["bash", "scripts/e2e_anvil.sh"])

    def test_cached_profile_keeps_debug_and_arithmetic_guards(self):
        manifest = (runner.ROOT / "Cargo.toml").read_text()
        profile = re.search(r"^\[profile\.crypto-test\]\n(.*?)(?=^\[|\Z)",
                            manifest, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(profile)
        for setting in ('inherits = "dev"', "opt-level = 2", "debug-assertions = true",
                        "overflow-checks = true", "lto = false"):
            self.assertIn(setting, profile[1])
        self.assertNotIn('panic = "abort"', profile[1])
        action = (runner.ROOT / ".github/actions/xmr-test-tools/action.yml").read_text()
        self.assertIn("--lib --tests --profile crypto-test --no-run", action)

    def test_full_shards_preserve_every_original_check_exactly_once_except_partitioned_production(self):
        evidence = Path("/synthetic-evidence")
        original = runner.commands("full", evidence)
        self.assertEqual(original, runner.commands("full", evidence, "all"))
        original_by_name = {name: (name, command, env) for name, command, env in original}
        expected = {
            "protocol": FULL_ORDER[:8],
            "production-native": ("production-native",),
            "production-native-funding": ("production-native-funding",),
            "production-native-claim": ("production-native-claim",),
            "production-native-wallet-reopen": ("production-native-wallet-reopen",),
            "production-native-templates": ("production-native-templates",),
            "production-lib": ("production-lib", "rust-route-independent-verification"),
            "production-integration": ("production-integration", "rust-time-independent-verification"),
            "live": FULL_ORDER[-3:],
        }
        selected = []
        for shard in runner.FULL_SHARDS:
            specs = runner.commands("full", evidence, shard)
            self.assertEqual(tuple(name for name, _, _ in specs), expected[shard])
            for spec in specs:
                name = spec[0]
                selected.append(name)
                if not name.startswith("production-"):
                    self.assertEqual(spec, original_by_name[name])
        self.assertEqual(len(selected), len(set(selected)))
        unchanged = [name for name in selected if not name.startswith("production-")]
        self.assertCountEqual(unchanged, [name for name in FULL_ORDER if name != "production"])

    def test_production_shard_target_domains_are_disjoint_and_cover_lib_bin_and_all_integrations(self):
        specs = {shard: runner.commands("full", Path("/synthetic-evidence"), shard)[0]
                 for shard in runner.FULL_SHARDS if shard.startswith("production-")}
        native = specs["production-native"][1]
        exact_commands = {shard: specs[shard][1] for shard in runner.NATIVE_EXACT_TESTS}
        ordinary = specs["production-lib"][1]
        integration = specs["production-integration"][1]
        self.assertIn("--lib", native)
        self.assertEqual(native[native.index("--") - 1], runner.NATIVE_TEST_PREFIX)
        self.assertEqual(native[-8:],
                         [arg for name in runner.NATIVE_EXACT_TESTS.values() for arg in ("--skip", name)])
        for shard, command in exact_commands.items():
            selected = runner.NATIVE_EXACT_TESTS[shard]
            self.assertIn("--lib", command)
            self.assertEqual(command[command.index("--") - 1], selected)
            self.assertIn("--exact", command)
        self.assertIn("--lib", ordinary)
        self.assertEqual(ordinary[-2:], ["--skip", runner.NATIVE_TEST_PREFIX])
        self.assertEqual(tuple(integration[index + 1] for index, argument in enumerate(integration)
                               if argument == "--test"), runner.PRODUCTION_INTEGRATION_TARGETS)
        self.assertNotIn("*", integration)
        self.assertIn("--bins", integration)
        for command in (native, *exact_commands.values(), ordinary, integration):
            self.assertNotIn("--tests", command)  # This would include lib again.
            self.assertNotIn("--ignored", command)
            self.assertNotIn("--no-run", command)
            self.assertNotIn("--exclude", command)
            for flag in ("--locked", "--no-default-features", "--no-fail-fast", "--test-threads=1"):
                self.assertIn(flag, command)
            self.assertEqual(command[command.index("--features") + 1], "production")
            self.assertEqual(command[command.index("--profile") + 1], "crypto-test")
            name = next(name for name, args, _ in specs.values() if args == command)
            with mock.patch.object(runner.subprocess, "Popen") as start:
                runner.start_test_command(name, {}, Path("/synthetic-evidence"))
            self.assertEqual(start.call_args.args[0], command)
        self.assertNotIn("--lib", integration)

        # Symbolic libtest filters plus the enabled integration target names:
        # prefix and its complement divide every possible lib name; --bins and
        # the closed --test list own the enabled non-library targets.
        targets = [
            ("lib", runner.NATIVE_TEST_PREFIX + "::native_case"),
            ("lib", runner.NATIVE_TEST_PREFIX + "::nested::another_case"),
            ("lib", runner.NATIVE_FUNDING_TEST),
            ("lib", runner.NATIVE_CLAIM_TEST),
            ("lib", runner.NATIVE_WALLET_REOPEN_TEST),
            ("lib", runner.NATIVE_TEMPLATES_TEST),
            ("lib", "production_child_router::route_tests_v4::matrix"),
            ("lib", "future_module::regression"), ("bin", "dom-interopd::unit"),
        ] + [("test", name + "::case") for name in runner.PRODUCTION_INTEGRATION_TARGETS]
        self.assertGreater(len(targets), 6)
        for kind, name in targets:
            selected = [
                kind == "lib" and runner.NATIVE_TEST_PREFIX in name
                and not any(excluded in name for excluded in runner.NATIVE_EXACT_TESTS.values()),
                *(kind == "lib" and name == exact for exact in runner.NATIVE_EXACT_TESTS.values()),
                kind == "lib" and runner.NATIVE_TEST_PREFIX not in name,
                kind in ("bin", "test"),
            ]
            self.assertEqual(sum(selected), 1, (kind, name))

    def test_explicit_integration_targets_cover_all_sources_except_verified_feature_gates(self):
        crate = runner.ROOT / "crates/dom-interopd"
        excluded = {
            "self_check": ("development",),
            "simulation": ("simulation",),
            "relay_worker_post_anchor_v2": ("production", "evidence-only-ancestry-tests"),
        }
        discovered = {path.stem for path in (crate / "tests").glob("*.rs")}
        selected = runner.PRODUCTION_INTEGRATION_TARGETS
        self.assertEqual(len(selected), 11)
        self.assertEqual(len(selected), len(set(selected)))
        self.assertTrue(set(excluded) <= discovered)
        self.assertEqual(set(selected), discovered - set(excluded),
                         "new integration target must be explicitly assigned before CI can pass")
        manifest = (crate / "Cargo.toml").read_text()
        entries = re.findall(r"^\[\[test\]\]\n(.*?)(?=^\[|\Z)",
                             manifest, re.MULTILINE | re.DOTALL)
        gates = {}
        for entry in entries:
            name = re.search(r'^name\s*=\s*"([^"]+)"\s*$', entry, re.MULTILINE)
            path = re.search(r'^path\s*=\s*"([^"]+)"\s*$', entry, re.MULTILINE)
            required = re.search(r'^required-features\s*=\s*\[([^\]]*)\]', entry, re.MULTILINE)
            self.assertIsNotNone(name)
            self.assertIsNotNone(path)
            self.assertIsNotNone(required)
            self.assertNotIn(name[1], gates)
            self.assertEqual(path[1], f"tests/{name[1]}.rs")
            gates[name[1]] = tuple(re.findall(r'"([^"]+)"', required[1]))
        self.assertEqual(gates, excluded,
                         "target feature gates changed; re-evaluate the disjoint production selection")
        feature_section = re.search(r"^\[features\]\n(.*?)(?=^\[|\Z)",
                                    manifest, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(feature_section)
        features = {name: set(re.findall(r'"([^"]+)"', body)) for name, body in
                    re.findall(r'^([A-Za-z0-9_-]+)\s*=\s*\[([^\]]*)\]',
                               feature_section[1], re.MULTILINE)}
        enabled = {"production"}  # Every shard retains --no-default-features.
        pending = ["production"]
        while pending:
            for feature in features[pending.pop()]:
                if feature in features and feature not in enabled:
                    enabled.add(feature)
                    pending.append(feature)
        for target, required in excluded.items():
            self.assertFalse(set(required) <= enabled, target)

    def test_shard_oracles_share_the_actual_producers_evidence_and_dependencies(self):
        evidence = Path("/synthetic-evidence")
        for shard, variable, filename, oracle in (
            ("production-lib", "DOM_INTEROP_V4_ROUTE_TRACE", "rust-route-trace-v4.json",
             "rust-route-independent-verification"),
            ("production-integration", "DOM_INTEROP_V5_TIME_FIXTURE", "rust-time-evidence-v5.json",
             "rust-time-independent-verification"),
        ):
            producer, verifier = runner.commands("full", evidence, shard)
            self.assertEqual(producer[2], {variable: str(evidence / filename)})
            self.assertEqual(verifier[0], oracle)
            self.assertEqual(verifier[1][-1], str(evidence / filename))
        source = runner.ROOT / "crates/dom-interopd"
        self.assertIn("DOM_INTEROP_V4_ROUTE_TRACE",
                      (source / "src/production_route_router_tests.rs").read_text())
        self.assertIn("DOM_INTEROP_V5_TIME_FIXTURE",
                      (source / "tests/support/production_time_inbox_v5.rs").read_text())
        self.assertIn('support/production_time_inbox_v5.rs',
                      (source / "tests/production_time_guard.rs").read_text())
        self.assertIn("mod xmr_graph_wallet_tests;",
                      (source / "src/production_bootstrap_v13_tests.rs").read_text())
        for shard in ("production-native", *runner.NATIVE_EXACT_TESTS):
            self.assertEqual(runner.commands("full", evidence, shard)[0][2], {})
        self.assertEqual(runner.required_tools("full", "all"), [
            "git", "cargo", "rustc", "cc", "clang", "cmake", "pkg-config",
            "bitcoind", "bitcoin-cli", "forge", "anvil", "curl",
        ])
        for shard in runner.FULL_SHARDS:
            required = runner.required_tools("full", shard)
            self.assertEqual("bitcoind" in required, shard in ("protocol", "live"))
            self.assertEqual("bitcoin-cli" in required, shard in ("protocol", "live"))
            for tool in ("forge", "anvil", "curl"):
                self.assertEqual(tool in required, shard == "live")

    def test_shard_option_is_full_only_and_unknown_shards_are_refused_before_execution(self):
        for mode in ("offline", "routing", "runtime", "v6", "components"):
            for shard in ("all", *runner.FULL_SHARDS):
                with mock.patch.object(sys, "argv", ["hardening", "--mode", mode, "--full-shard", shard]), \
                        mock.patch.object(sys, "stderr"), \
                        mock.patch.object(runner, "source_digest") as digest:
                    with self.assertRaises(SystemExit) as error:
                        runner.main()
                    self.assertEqual(error.exception.code, 2)
                    digest.assert_not_called()
        for mode, shard in (("full", "unknown"), ("components", "live")):
            with self.assertRaises(ValueError):
                runner.commands(mode, Path("/synthetic-evidence"), shard)

    def test_every_shard_records_its_scope_and_scopes_tmp_only_to_production_children(self):
        for shard in runner.FULL_SHARDS:
            with self.subTest(shard=shard), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                calls = []

                def start(name, env, evidence):
                    is_production = name.startswith("production-")
                    self.assertEqual(env["TMPDIR"], "/synthetic/production" if is_production
                                     else "/original/tmp")
                    calls.append(name)
                    output = (b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;\n"
                              if name in runner.NATIVE_EXACT_SHARDS
                              else b"synthetic dispatch only\n")
                    return SimpleNamespace(args=[name], stdout=io.BytesIO(output),
                                           wait=lambda: 0)

                with mock.patch.object(runner, "ROOT", root), \
                        mock.patch.object(sys, "argv", ["hardening", "--mode", "full", "--full-shard", shard]), \
                        mock.patch.object(sys, "stdout"), \
                        mock.patch.object(runner, "source_digest", return_value="synthetic"), \
                        mock.patch.object(runner.subprocess, "check_output", return_value=b"synthetic\n"), \
                        mock.patch.object(runner.shutil, "which", return_value="/synthetic/tool"), \
                        mock.patch.dict(os.environ, {"TMPDIR": "/original/tmp"}), \
                        mock.patch.object(runner, "production_environment_v24",
                                          side_effect=lambda env: {**env, "TMPDIR": "/synthetic/production"}) as scope, \
                        mock.patch.object(runner, "start_test_command", side_effect=start):
                    self.assertEqual(runner.main(), 0)
                    self.assertEqual(scope.call_count, int(shard.startswith("production-")))
                self.assertEqual(calls, [name for name, _, _ in runner.commands("full", root, shard)])
                report_path, = (root / "artifacts/interop-hardening").glob("*/report.json")
                report = json.loads(report_path.read_text())
                self.assertEqual(report["full_shard"], shard)
                self.assertEqual(report["status"], "completed")
                self.assertIn(f"-full-{shard}-", report_path.parent.name)

    def test_full_remains_serial_and_records_all_failures_and_log_hashes(self):
        # Fake child processes exercise orchestration only. No test result is
        # reused as evidence of real Rust execution, and no external tool runs.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []
            active = set()

            def start(name, env, evidence):
                self.assertFalse(active, "a second command started before the first was reaped")
                self.assertEqual(env["TMPDIR"], "/synthetic/production" if name == "production"
                                 else "/original/tmp")
                active.add(name)
                calls.append(name)
                command = next(command for selected, command, _ in runner.commands("full", evidence)
                               if selected == name)

                def wait():
                    active.remove(name)
                    return 1 if name == "bitcoin" else 0

                return SimpleNamespace(args=command, stdout=io.BytesIO(b"synthetic dispatch only\n"),
                                       wait=wait)

            with mock.patch.object(runner, "ROOT", root), \
                    mock.patch.object(sys, "argv", ["hardening", "--mode", "full"]), \
                    mock.patch.object(sys, "stdout"), \
                    mock.patch.object(runner, "source_digest", side_effect=["before", "after"]), \
                    mock.patch.object(runner.subprocess, "check_output", return_value=b"synthetic\n"), \
                    mock.patch.object(runner.shutil, "which", return_value="/synthetic/tool"), \
                    mock.patch.dict(os.environ, {"TMPDIR": "/original/tmp"}), \
                    mock.patch.object(runner, "production_environment_v24",
                                      side_effect=lambda env: {**env, "TMPDIR": "/synthetic/production"}) as scope, \
                    mock.patch.object(runner, "start_test_command", side_effect=start):
                self.assertEqual(runner.main(), 1)
                self.assertEqual(scope.call_count, 1)
            self.assertEqual(tuple(calls), FULL_ORDER)
            self.assertFalse(active)
            reports = list((root / "artifacts/interop-hardening").glob("*/report.json"))
            self.assertEqual(len(reports), 1)
            report = json.loads(reports[0].read_text())
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["source_sha256_before"], "before")
            self.assertEqual(report["source_sha256_after"], "after")
            self.assertEqual(tuple(check["id"] for check in report["checks"]), FULL_ORDER)
            for check in report["checks"]:
                code = 1 if check["id"] == "bitcoin" else 0
                self.assertEqual(check["exit_code"], code)
                self.assertEqual(check["status"], "failed" if code else "passed")
                self.assertEqual(check["command"], check["executed_command"])
                content = (reports[0].parent / check["log"]).read_bytes()
                self.assertEqual(check["log_sha256"], hashlib.sha256(content).hexdigest())

    def test_invalid_production_root_records_failure_and_still_runs_full_extras(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []

            def start(name, env, evidence):
                self.assertNotEqual(name, "production", "refused production must never spawn")
                calls.append(name)
                return SimpleNamespace(args=[name], stdout=io.BytesIO(b"synthetic dispatch only\n"),
                                       wait=lambda: 0)

            with mock.patch.object(runner, "ROOT", root), \
                    mock.patch.object(sys, "argv", ["hardening", "--mode", "full"]), \
                    mock.patch.object(sys, "stdout"), \
                    mock.patch.object(runner, "source_digest", return_value="synthetic"), \
                    mock.patch.object(runner.subprocess, "check_output", return_value=b"synthetic\n"), \
                    mock.patch.object(runner.shutil, "which", return_value="/synthetic/tool"), \
                    mock.patch.dict(os.environ, {"DOM_XMR_PRIVATE_TMP_V23": "/tmp"}), \
                    mock.patch.object(runner, "start_test_command", side_effect=start):
                self.assertEqual(runner.main(), 1)
            self.assertEqual(tuple(calls), tuple(name for name in FULL_ORDER if name != "production"))
            report_path, = (root / "artifacts/interop-hardening").glob("*/report.json")
            report = json.loads(report_path.read_text())
            self.assertEqual(report["status"], "failed")
            production = next(check for check in report["checks"] if check["id"] == "production")
            self.assertEqual(production["status"], "failed")
            self.assertEqual(production["exit_code"], 127)
            self.assertNotIn("executed_command", production)
            log = (report_path.parent / production["log"]).read_bytes()
            self.assertEqual(production["log_sha256"], hashlib.sha256(log).hexdigest())


if __name__ == "__main__":
    unittest.main()
