"""Exercise literal CI dispatch and isolated oracle inputs through real processes."""
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_interop_hardening as runner
import run_native_daemon_scenario_v23 as native_runner


class HardeningDispatchTests(unittest.TestCase):
    def test_sidecar_restart_guards_execute_before_long_scenarios(self):
        root = Path(__file__).resolve().parents[2]
        action = (root / ".github/actions/xmr-test-tools/action.yml").read_text()
        step = action.split("- name: Verify custody paths and real offline helper startup", 1)[1].split("- name:", 1)[0]
        self.assertIn("--lib --profile crypto-test peer_sidecar_v23::", step)
        self.assertIn("-- --nocapture --test-threads=1 --color never", step)
        self.assertIn("set -euo pipefail", step)
        self.assertIn("[1-9][0-9]* passed; 0 failed; 0 ignored;", step)
        self.assertNotIn("--no-run", step)
        self.assertNotIn("if:", step)
        self.assertNotIn("continue-on-error", step)
        observation = (root / "crates/dom-interopd/src/production_xmr_native_observation_v23_tests.rs").read_text()
        self.assertIn('mod peer_sidecar_v23;', observation)
        source = (root / "crates/dom-interopd/src/production_xmr_native_peer_sidecar_v23_tests.rs").read_text()
        for name in ("sidecar_readiness_cannot_reuse_another_hello_nonce_v24",
                     "sidecar_drop_preserves_cache_until_private_parent_cleanup_v24"):
            self.assertRegex(source, rf"#\[test\]\s+fn {name}\(")

    def test_dependency_regressions_have_direct_execution_and_failure_evidence(self):
        action = (Path(__file__).resolve().parents[2]
                  / ".github/actions/xmr-test-tools/action.yml").read_text()
        step = action.split("- name: Verify scoped funding, custody and transport regressions", 1)[1].split("- name:", 1)[0]
        self.assertIn("python3 scripts/scoped_boundary_regressions_v24.py", step)
        self.assertIn('--evidence-dir "$RUNNER_TEMP/dom-xmr-boundary-evidence"', step)
        self.assertIn("CARGO_BUILD_JOBS: '2'", step)
        self.assertIn("RUST_TEST_THREADS: '1'", step)
        self.assertIn("if: ${{ inputs.run-once-regressions == 'true' }}", step)
        self.assertNotIn("continue-on-error", step)
        evidence = action.split("- name: Preserve scoped boundary regression outcomes", 1)[1].split("- name:", 1)[0]
        self.assertIn("if: ${{ always() && inputs.run-once-regressions == 'true' }}", evidence)
        self.assertIn("actions/upload-artifact@v4", evidence)
        self.assertIn("${{ runner.temp }}/dom-xmr-boundary-evidence/", evidence)
        self.assertIn("test_scoped_boundary_regressions_v24.py", action)

    def test_shared_regressions_run_once_per_push_not_on_every_heavy_runner(self):
        root = Path(__file__).resolve().parents[2]
        action = (root / ".github/actions/xmr-test-tools/action.yml").read_text()
        self.assertRegex(
            action,
            r"run-once-regressions:\n\s+description:.*\n\s+default: 'true'",
        )
        for name in (
            "Verify Funding and Claim reservation audit purposes",
            "Verify scoped funding, custody and transport regressions",
            "Verify XMR recovery participant ordering",
            "Verify offline operational artifact producers",
        ):
            step = action.split(f"- name: {name}", 1)[1].split("- name:", 1)[0]
            self.assertIn("if: ${{ inputs.run-once-regressions == 'true' }}", step)
        heavy = (root / ".github/workflows/heavy-tests.yml").read_text()
        self.assertEqual(heavy.count("run-once-regressions: 'false'"), 4)
        interop = (root / ".github/workflows/interop-hardening.yml").read_text()
        self.assertIn("uses: ./.github/actions/xmr-test-tools", interop)
        self.assertNotIn("run-once-regressions: 'false'", interop)

    def test_public_refund_auth_and_ready_regressions_execute_on_cached_tools(self):
        action = (Path(__file__).resolve().parents[2]
                  / ".github/actions/xmr-test-tools/action.yml").read_text()
        step = action.split("- name: Verify public refund authentication and durable Ready recovery", 1)[1].split("- name:", 1)[0]
        self.assertIn("for filter in auth::local_refund_tests_v24 cache::build_v23_tests", step)
        self.assertIn("cargo test --locked", step)
        self.assertIn('-p dom-xmr-sidecar --bin dom-xmr-sidecar "$filter"', step)
        self.assertIn("-- --nocapture --test-threads=1 --color never", step)
        self.assertIn("[1-9][0-9]* passed; 0 failed; 0 ignored;", step)
        self.assertIn("set -euo pipefail", step)
        self.assertNotIn("--no-run", step)
        self.assertNotIn("cache-hit", step)
        self.assertNotIn("continue-on-error", step)
        self.assertNotIn("if:", step)
        self.assertIn("test_native_daemon_campaign_v24.py", action)

    def test_bitcoin_actuator_live_gate_enables_rpc_and_rejects_zero_tests(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/heavy-tests.yml").read_text()
        step = workflow.split("- name: btc-actuator — Bitcoin Core regtest daemon suite", 1)[1].split("- name:", 1)[0]
        self.assertIn("--features rpc-http --test bitcoin_core_regtest", step)
        self.assertIn("exact_transaction_is_persisted_broadcast_and_finalized_by_real_core", step)
        self.assertIn("-- --ignored --exact --nocapture --test-threads=1 --color never", step)
        self.assertIn("set -euo pipefail", step)
        self.assertIn("1 passed; 0 failed; 0 ignored;", step)
        self.assertIn("grep -Eq", step)

    def test_real_bitcoin_fixtures_own_and_reap_rpc_only_processes(self):
        root = Path(__file__).resolve().parents[2]
        for name in ("composed_route_live.rs", "f7_bitcoin_regtest.rs"):
            source = (root / "crates/f5-e2e/tests" / name).read_text()
            fixture = source.split("struct RegtestNode {", 1)[1].split("fn canonical_ancestry", 1)[0]
            for required in ("child: Child", '"-daemon=0"', '"-server=1"', '"-listen=0"',
                             '"-rpcbind=127.0.0.1"', '"-rpcclienttimeout=2"',
                             ".try_wait()", ".kill()", ".wait()", "process.log", "retain_on_failure"):
                self.assertIn(required, fixture, name)
            self.assertNotIn('"-daemon"', fixture, name)
            self.assertNotIn(".cookie", fixture, name)
            self.assertLess(fixture.index("self.child.wait()"), fixture.index("remove_dir_all"))

    def test_crypto_caches_survive_test_failure_but_never_skip_test_execution(self):
        root = Path(__file__).resolve().parents[2]
        action = (root / ".github/actions/xmr-test-tools/action.yml").read_text()
        cache = action.split("- name: Restore GPL crypto compilation", 1)[1].split("- name:", 1)[0]
        for setting in ("workspaces: .ci-eigenwallet -> target", "cache-all-crates: 'true'",
                        "cache-on-failure: 'true'", "github.event_name != 'pull_request'",
                        "xmr-gpl-crypto-test-v23-0e17c7f7cd8f0657af176c8852aa4c9949586051"):
            self.assertIn(setting, cache)
        self.assertLess(action.index("Install pinned offline tool sources"), action.index("Restore GPL crypto compilation"))
        self.assertLess(action.index("Restore GPL crypto compilation"), action.index("Build pinned offline tools"))
        self.assertNotIn("cache-hit", action)
        self.assertNotIn("continue-on-error:", action)
        for filename, job_name in (("heavy-tests.yml", "dom-xmr-native"),
                                   ("heavy-tests.yml", "interop-full"),
                                   ("interop-hardening.yml", "components")):
            workflow = (root / ".github/workflows" / filename).read_text()
            jobs = dict(re.findall(r"^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
                                   workflow, re.MULTILINE | re.DOTALL))
            job = jobs[job_name]
            self.assertIn("cache-workspace-crates: 'true'", job)
            self.assertIn("cache-on-failure: 'true'", job)
            self.assertNotIn("cache-hit", job)

    def test_gpl_children_are_optimized_without_disabling_debug_safety(self):
        action = (Path(__file__).resolve().parents[2]
                  / ".github/actions/xmr-test-tools/action.yml").read_text()
        tools_step = action.split("- name: Build pinned offline tools", 1)[1].split("- name:", 1)[0]
        self.assertIn("--profile crypto-test", tools_step)
        for setting in (
            'inherits="dev"', "opt-level=2", "debug=1", "debug-assertions=true",
            "overflow-checks=true", "lto=false", "codegen-units=16", "incremental=false",
        ):
            self.assertIn(f"--config 'profile.crypto-test.{setting}'", tools_step)
        self.assertNotIn("target/debug/", tools_step)
        self.assertIn("DOM_XMR_REAL_SIDECAR_V23=$XMR_TEST_WORKSPACE/target/crypto-test/dom-xmr-sidecar", tools_step)
        self.assertIn("DOM_XMR_OFFLINE_FUNDING_HELPER_V23=$XMR_TEST_WORKSPACE/target/crypto-test/examples/offline_native_funding_v23", tools_step)
        self.assertIn("--bin dom-xmr-sidecar --example offline_native_funding_v23", tools_step)

    def test_offline_producers_compile_all_targets_and_run_before_long_graphs(self):
        action = (Path(__file__).resolve().parents[2]
                  / ".github/actions/xmr-test-tools/action.yml").read_text()
        self.assertNotIn("continue-on-error:", action)
        compile_command = (
            "cargo test --locked -p dom-interopd --no-default-features --features production "
            "--lib --tests --profile crypto-test --no-run"
        )
        self.assertIn(compile_command, action)
        self.assertLess(action.index(compile_command), action.index("Build pinned offline tools"))
        self.assertIn(
            "--lib --tests --profile crypto-test production_prepare_ -- --nocapture --test-threads=1",
            action,
        )
        self.assertIn(
            "--test route_services_cli --test xmr_enrollment_cli --test xmr_leg_cli --test f6_artifact_cli --test planning_cli "
            "--profile crypto-test --no-fail-fast -- --nocapture --test-threads=1",
            action,
        )
        self.assertIn(
            "cargo test --locked -p dom-adaptor --lib --profile crypto-test "
            "reservation_binding::public_audit_v23::tests -- --nocapture --test-threads=1",
            action,
        )

    def test_f7_regtest_and_boundaries_are_mandatory_in_heavy_gate(self):
        workflow = (Path(__file__).resolve().parents[2]
                    / ".github/workflows/heavy-tests.yml").read_text()
        jobs = dict(re.findall(r"^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
                               workflow, re.MULTILINE | re.DOTALL))
        live = jobs["live-composed-route"]
        self.assertNotIn("continue-on-error:", live)
        steps = re.split(r"^      - ", live, flags=re.MULTILINE)
        f7 = [step for step in steps if "--test f7_bitcoin_regtest" in step]
        self.assertEqual(len(f7), 1)
        self.assertNotRegex(f7[0], r"(?m)^        if:")
        command = next(line.strip().removeprefix("run: ") for line in f7[0].splitlines()
                       if line.strip().startswith("run: "))
        self.assertEqual(command.split(), [
            "cargo", "test", "--locked", "-p", "f5-e2e", "--test", "f7_bitcoin_regtest",
            "--", "--include-ignored", "--nocapture", "--test-threads=1",
        ])
        gate = jobs["heavy-gate"]
        dependencies = re.search(r"^    needs: \[([^\]]+)\]$", gate, re.MULTILINE)
        self.assertIsNotNone(dependencies)
        self.assertIn("live-composed-route", [name.strip() for name in dependencies[1].split(",")])
        self.assertIn("${{ needs.live-composed-route.result }}", gate)

    def test_real_daemon_scenarios_are_mandatory_and_never_a_blanket_ignored_suite(self):
        workflow = (Path(__file__).resolve().parents[2]
                    / ".github/workflows/heavy-tests.yml").read_text()
        jobs = dict(re.findall(r"^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
                               workflow, re.MULTILINE | re.DOTALL))
        job = jobs["dom-xmr-real-daemon"]
        self.assertNotIn("continue-on-error:", job)
        self.assertIn("github.event_name == 'push' || inputs.suite == 'all' || inputs.suite == 'dom-xmr-native'", job)
        self.assertIn("./dom/.github/actions/xmr-test-tools", job)
        self.assertIn("real-daemon: 'true'", job)
        action = (Path(__file__).resolve().parents[2]
                  / ".github/actions/xmr-test-tools/action.yml").read_text()
        self.assertIn("cargo build --locked --release -p dom-interopd --no-default-features --features production --bin dom-interopd", action)
        self.assertIn("if: ${{ inputs.real-daemon == 'true' }}", action)
        self.assertIn("DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23", job)
        self.assertEqual(job.count("python3 scripts/run_native_daemon_scenario_v23.py"), 1)
        self.assertIn("if: always()", job)
        self.assertIn("synthetic-fixtures.tar.gz", job)
        self.assertIn("dom-xmr-real-daemon", jobs["heavy-gate"])
        self.assertIn('[[ "${{ needs.dom-xmr-real-daemon.result }}" == success ]]', jobs["heavy-gate"])
        refund = jobs["dom-xmr-real-refund"]
        self.assertNotIn("continue-on-error:", refund)
        self.assertNotRegex(refund, r"(?m)^    needs:")
        self.assertIn("github.event_name == 'push' || inputs.suite == 'all' || inputs.suite == 'dom-xmr-native'", refund)
        self.assertIn("real-daemon: 'true'", refund)
        self.assertIn("--scenario native_real_daemon_xmr_refund_after_public_u_without_counterparty_v23", refund)
        self.assertIn('[[ "${{ needs.dom-xmr-real-refund.result }}" == success ]]', jobs["heavy-gate"])
        self.assertEqual(len(native_runner.SCENARIOS), 3)
        selected = re.findall(r"--scenario ([a-z0-9_]+)", job + refund)
        self.assertCountEqual(selected, native_runner.SCENARIOS)
        scenario_source = (Path(__file__).resolve().parents[2]
                           / "crates/dom-interopd/src/production_xmr_native_daemon_scenario_v23_tests.rs").read_text()
        for name in native_runner.SCENARIOS:
            self.assertIn(f"fn {name}() -> Result<()>", scenario_source)
            args = native_runner.command(name)
            self.assertEqual(args[args.index("--") + 1:], [
                "--ignored", "--exact", "--nocapture", "--test-threads=1", "--color", "never",
            ])
            self.assertIn(native_runner.PREFIX + name, args)
        with self.assertRaises(ValueError):
            native_runner.command("other_test")
        self.assertIsNotNone(native_runner.RESULT.search(
            "test result: ok. 1 passed; 0 failed; 0 ignored; 531 filtered out; finished in 12s\n"))
        for summary in ("test result: ok. 0 passed; 0 failed; 0 ignored;",
                        "test result: ok. 0 passed; 0 failed; 1 ignored;",
                        "test result: FAILED. 0 passed; 1 failed; 0 ignored;"):
            self.assertIsNone(native_runner.RESULT.search(summary))

    def test_native_campaign_runs_second_after_failure_only_when_cleanup_is_proven(self):
        dependencies = {name: "fixture" for name in (
            "DOM_INTEROP_REAL_BINARY_V23", "DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23",
            "DOM_XMR_REAL_SIDECAR_V23", "DOM_XMR_OFFLINE_FUNDING_HELPER_V23")}
        for clean, expected_calls in ((True, 2), (False, 1)):
            with self.subTest(clean=clean), tempfile.TemporaryDirectory() as directory:
                args = ["native-runner", "--evidence-dir", directory]
                for name in native_runner.SCENARIOS[:2]:
                    args.extend(["--scenario", name])
                results = [{"status": "failed", "cleanup_verified": clean},
                           {"status": "passed", "cleanup_verified": True}]
                with mock.patch.object(sys, "argv", args), \
                        mock.patch.dict(os.environ, dependencies), \
                        mock.patch.object(native_runner.ctypes, "CDLL") as libc, \
                        mock.patch.object(native_runner.signal, "signal"), \
                        mock.patch.object(native_runner, "run_one", side_effect=results) as execute, \
                        mock.patch.object(native_runner, "CANCELLED", False):
                    libc.return_value.prctl.return_value = 0
                    self.assertEqual(native_runner.main(), 1)
                self.assertEqual(execute.call_count, expected_calls)
                report = json.loads((Path(directory) / "campaign.json").read_text())
                self.assertEqual(report["status"], "failed")
                if not clean:
                    self.assertEqual(report["results"][1]["status"], "not-run")

    def test_native_cleanup_owns_other_groups_and_adopted_session_escape_not_neighbors(self):
        owner = native_runner.OwnedProcesses(100)
        table = {
            100: (os.getpid(), 100, 10, "S"),
            101: (100, 100, 11, "S"),
            102: (101, 102, 12, "S"),  # Changed session while still attached.
            103: (os.getpid(), 103, 13, "S"),  # Adopted by our child-subreaper.
            200: (1, 200, 20, "S"),  # Unrelated runner process: never owned.
        }
        with mock.patch.object(native_runner, "processes", return_value=table):
            self.assertEqual(set(owner.snapshot()), {100, 101, 102, 103})
        table[102] = (1, 102, 12, "S")
        with mock.patch.object(native_runner, "processes", return_value=table):
            self.assertIn(102, owner.snapshot())
        with mock.patch.object(native_runner.os, "pidfd_open", return_value=5), \
                mock.patch.object(native_runner.os, "close"), \
                mock.patch.object(native_runner, "processes", return_value={200: table[200]}), \
                mock.patch.object(native_runner.signal, "pidfd_send_signal") as send:
            owner.send(200, (1, 200, 999, "S"), native_runner.signal.SIGKILL)
            send.assert_not_called()  # PID reused: start ticks differ.

    def test_native_fixture_archive_never_follows_a_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            case = base / "evidence"
            case.mkdir()
            synthetic = base / "synthetic"
            synthetic.mkdir(mode=0o700)
            secret = base / "not-a-fixture"
            secret.write_text("must not be archived")
            (synthetic / "link").symlink_to(secret)
            (synthetic / "journal").write_text("synthetic journal")
            archive = native_runner.preserve_fixture(case, synthetic)
            with native_runner.tarfile.open(case / archive) as contents:
                linked = contents.getmember("link")
                self.assertTrue(linked.issym())
                self.assertEqual(linked.size, 0)
                self.assertEqual(contents.extractfile("journal").read(), b"synthetic journal")
                self.assertEqual(set(contents.getnames()), {"link", "journal"})

    def test_production_keeps_all_targets_and_continues_after_a_failed_target(self):
        root = Path(".")
        for mode in ("components", "full", "runtime", "v6"):
            with self.subTest(mode=mode):
                declared = next(args for name, args, _ in runner.commands(mode, root)
                                if name == "production")
                with mock.patch.object(runner.subprocess, "Popen") as spawn:
                    runner.start_test_command("production", {}, root)
                actual = spawn.call_args.args[0]
                self.assertEqual(actual, declared)
                cargo_args, test_args = actual[:actual.index("--")], actual[actual.index("--") + 1:]
                for flag in ("--lib", "--tests", "--locked", "--no-fail-fast"):
                    self.assertIn(flag, cargo_args)
                self.assertEqual(test_args, ["--nocapture", "--test-threads=1"])

    def test_unknown_command_names_never_spawn_a_process(self):
        with mock.patch.object(runner.subprocess, "Popen") as spawn:
            for name in ("", "bash", "bitcoin-regtest;echo injected", "scripts/f5-signet-e2e.sh"):
                with self.assertRaises(ValueError):
                    runner.start_test_command(name, {}, Path("."))
            spawn.assert_not_called()

    def test_oracle_modules_read_only_their_fixed_run_input_and_refuse_invalid_data(self):
        cases = {
            "rust-route-independent-verification": "rust-route-trace-v4.json",
            "rust-time-independent-verification": "rust-time-evidence-v5.json",
            "rust-driver-final-signature-verification": "rust-driver-claim-v6.json",
            "rust-participant-independent-verification": "rust-participant-round-v3.json",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, filename in cases.items():
                with self.subTest(name=name):
                    (root / filename).write_text("{}\n")
                    process = runner.start_test_command(name, dict(os.environ), root)
                    try:
                        output, _ = process.communicate(timeout=10)
                    except BaseException:
                        process.kill()
                        process.communicate()
                        raise
                    self.assertEqual(process.returncode, 1)
                    # A genuine verifier refusal, not an import/launch failure.
                    self.assertIn(json.loads(output)["status"], ("refused", "failed"))
