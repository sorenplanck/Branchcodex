"""Exercise literal CI dispatch and isolated oracle inputs through real processes."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_interop_hardening as runner


class HardeningDispatchTests(unittest.TestCase):
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
