"""Lightweight contracts; written alongside the port, not its execution evidence."""
import importlib.util
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]


class LiveDispatch(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(SCRIPTS))
        spec = importlib.util.spec_from_file_location("live_dispatch", SCRIPTS / "run_xmr_live_leg_v23.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.original = (self.module.runner.PREFIX, self.module.runner.SCENARIOS)
        self.allocator = self.module.runner.private_synthetic_tmp
        self.module.configure()

    def tearDown(self):
        self.module.runner.PREFIX, self.module.runner.SCENARIOS = self.original
        sys.path.remove(str(SCRIPTS))

    def test_all_ten_names_are_unique_real_ignored_functions(self):
        self.assertEqual(len(self.module.SCENARIOS), 10)
        self.assertEqual(len(set(self.module.SCENARIOS)), 10)
        for group, names in self.module.GROUPS.items():
            source = (SCRIPTS.parent / "crates/dom-interopd/src" /
                      f"production_xmr_native_live_{group}_v23_tests.rs").read_text()
            for name in names:
                self.assertIn("fn " + name.split("::")[-1], source)

    def test_exact_selection_and_zero_test_refusal(self):
        runner = self.module.runner
        for name in self.module.SCENARIOS:
            command = runner.command(name)
            for option in ("--exact", "--ignored", "--test-threads=1", "crypto-test"):
                self.assertIn(option, command)
            self.assertIn(runner.PREFIX + name, command)
            result = runner.transcript_evidence(name, 0,
                "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored;\n")
            self.assertEqual(result["status"], "failed")

    def test_wrong_test_and_missing_archive_do_not_pass(self):
        runner = self.module.runner
        first, second = self.module.SCENARIOS[:2]
        transcript = (f"running 1 test\ntest {runner.PREFIX + second} ... ok\n"
                      "test result: ok. 1 passed; 0 failed; 0 ignored;\n")
        self.assertEqual(runner.transcript_evidence(first, 0, transcript)["status"], "failed")
        result = {"status": "passed"}
        runner.record_fixture_evidence(result, None)
        self.assertEqual(result["status"], "failed")

    def test_existing_private_allocator_and_cleanup_are_not_replaced(self):
        self.assertIs(self.module.runner.private_synthetic_tmp, self.allocator)
        self.assertNotIn("private_synthetic_tmp", vars(self.module))
        self.assertNotIn("tempfile", vars(self.module))


if __name__ == "__main__":
    unittest.main()
