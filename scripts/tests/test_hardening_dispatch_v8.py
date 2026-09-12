"""Exercise literal CI dispatch and isolated oracle inputs through real processes."""
import json
import os
import re
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_interop_hardening as runner


class HardeningDispatchTests(unittest.TestCase):
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
