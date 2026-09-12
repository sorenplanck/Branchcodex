"""Lightweight campaign evidence checks: no Cargo, daemon or cryptographic run."""
import hashlib
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_native_daemon_scenario_v23 as runner


class ExactScenarioEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.name = runner.SCENARIOS[2]
        self.full = runner.PREFIX + self.name
        self.summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 1.00s\n"

    def evidence(self, body, returncode=0):
        return runner.transcript_evidence(self.name, returncode, body)

    def test_exact_name_and_one_test_summary_survive_nocapture_interleaving(self):
        body = f"running 1 test\ntest {self.full} ... native graph: preparing\nmore output\nok\n\n{self.summary}"
        self.assertEqual(self.evidence(body)["status"], "passed")
        self.assertEqual(self.evidence(body, 1)["status"], "failed")

    def test_zero_tests_cannot_borrow_a_passing_nested_helper_summary(self):
        bodies = [
            f"running 0 tests\n{self.summary}",
            f"running 1 test\ntest unrelated::helper ... ok\n{self.summary}",
            f"running 1 test\ntest {self.full} ... ok\n{self.summary}running 0 tests\n",
            f"running 1 test\ntest {self.full} ... ok\n{self.summary}{self.summary}",
            f"running 1 test\ntest {self.full} ... ignored\n",
            f"running 1 test\ntest {self.full} ... ok\n",
        ]
        for body in bodies:
            with self.subTest(body=body):
                self.assertEqual(self.evidence(body)["status"], "failed")

    def test_names_from_distinct_claim_compensation_and_refund_cases_do_not_alias(self):
        for other in runner.SCENARIOS[:2]:
            body = f"running 1 test\ntest {runner.PREFIX + other} ... ok\n{self.summary}"
            self.assertEqual(self.evidence(body)["status"], "failed")

    def test_success_requires_original_fixture_archive_without_falsifying_cleanup(self):
        result = {"status": "passed", "cleanup_verified": True}
        runner.record_fixture_evidence(result, None)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["cleanup_verified"])
        self.assertIn("original synthetic fixture", result["evidence_error"])
        result = {"status": "passed", "cleanup_verified": True}
        runner.record_fixture_evidence(result, "synthetic-fixtures.tar.gz")
        self.assertEqual(result["status"], "passed")
        result = {"status": "failed", "error": "original test failure"}
        runner.record_fixture_evidence(result, None)
        self.assertEqual(result["error"], "original test failure")
        self.assertNotIn("evidence_error", result)


class DependencyProvenanceTests(unittest.TestCase):
    def test_real_bytes_match_supplied_digest_and_sidecar_replacement_is_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {}
            for index, name in enumerate(runner.DEPENDENCIES):
                path = Path(directory) / str(index)
                path.write_bytes(b"synthetic executable fixture, never executed" + bytes([index]))
                path.chmod(0o700)
                env[name] = str(path)
            env["DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23"] = hashlib.blake2b(
                Path(env[runner.DEPENDENCIES[0]]).read_bytes(), digest_size=32).hexdigest()
            original = runner.dependency_fingerprints(env)
            self.assertEqual(original, runner.dependency_fingerprints(env))
            Path(env[runner.DEPENDENCIES[1]]).write_bytes(b"different sidecar implementation")
            self.assertNotEqual(original, runner.dependency_fingerprints(env))
            env["DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23"] = "0" * 64
            with self.assertRaises(ValueError):
                runner.dependency_fingerprints(env)

    def test_symlink_group_writable_or_nonexecutable_dependencies_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture"
            path.write_bytes(b"not executed")
            path.chmod(0o700)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                runner.fingerprint_executable(str(link))
            for mode in (0o720, 0o600):
                path.chmod(mode)
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    runner.fingerprint_executable(str(path))
            with self.assertRaises(ValueError):
                runner.fingerprint_executable("relative-path")


class PrivateSyntheticDirectoryTests(unittest.TestCase):
    def test_private_fixture_root_avoids_shared_tmp_and_is_owner_only(self):
        path = runner.private_synthetic_tmp()
        try:
            self.assertNotEqual(path.parent, Path("/tmp"))
            self.assertEqual(path.parent, Path.home() / ".dx-v23")
            metadata = path.lstat()
            self.assertEqual(metadata.st_uid, os.getuid())
            self.assertTrue(stat.S_ISDIR(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o700)
        finally:
            shutil.rmtree(path)

    def test_fixture_archive_is_complete_before_private_source_cleanup(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            root = Path(directory) / "source"
            case = Path(directory) / "case"
            root.mkdir(mode=0o700)
            case.mkdir(mode=0o700)
            (root / "journal").write_bytes(b"durable evidence")
            name = runner.preserve_fixture(case, root)
            self.assertEqual(name, "synthetic-fixtures.tar.gz")
            self.assertGreater((case / name).stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
