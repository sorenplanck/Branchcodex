"""Static workflow boundaries; no Rust, tool installation or network calls."""
from pathlib import Path
import re
import unittest


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/heavy-tests.yml"


class FullInteropMatrixV24Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text()
        cls.jobs = dict(re.findall(
            r"^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
            cls.workflow, re.MULTILINE | re.DOTALL))
        cls.job = cls.jobs["interop-full"]
        cls.steps = re.split(r"^      - ", cls.job, flags=re.MULTILINE)[1:]

    def step(self, unique_text):
        matches = [step for step in self.steps if unique_text in step]
        self.assertEqual(len(matches), 1, unique_text)
        return matches[0]

    def test_five_exact_shards_run_independently_with_the_full_mode(self):
        self.assertIn("fail-fast: false", self.job)
        self.assertIn(
            "shard: [protocol, production-native, production-lib, production-integration, live]",
            self.job)
        self.assertIn("timeout-minutes: 240", self.job)
        step = self.step("id: interop_full_graph")
        self.assertIn(
            "python3 scripts/test_interop_hardening.py --mode full --full-shard ${{ matrix.shard }}",
            step)
        self.assertNotIn("if:", step)

    def test_installation_scope_follows_actual_shard_requirements(self):
        bitcoin = self.step("name: Install pinned Bitcoin Core")
        self.assertIn("matrix.shard == 'protocol' || matrix.shard == 'live'", bitcoin)
        for selector in ("uses: foundry-rs/foundry-toolchain@v1",
                         "name: Install pinned Solidity dependencies"):
            self.assertIn("if: ${{ matrix.shard == 'live' }}", self.step(selector))
        xmr = self.step("id: interop_xmr_tools")
        self.assertIn("if: ${{ startsWith(matrix.shard, 'production-') }}", xmr)
        self.assertIn("run-once-regressions: ${{ matrix.shard == 'production-native'", xmr)
        ingress = self.step("id: interop_prepared_ingress")
        self.assertIn("if: ${{ matrix.shard == 'production-integration' }}", ingress)
        self.assertIn("--test relay_worker --profile crypto-test prepared_operational", ingress)

    def test_each_shard_verifies_consensus_and_retains_failures(self):
        consensus = self.step("id: interop_consensus")
        self.assertIn("run: bash scripts/check-consensus-unchanged.sh", consensus)
        self.assertNotIn("if:", consensus)
        self.assertIn("cache-on-failure: 'true'", self.job)
        self.assertIn("key: interop-full-${{ matrix.shard }}", self.job)
        evidence = self.step("id: interop_evidence")
        self.assertIn("if: always()", evidence)
        self.assertIn("name: interop-hardening-full-${{ matrix.shard }}-${{ github.sha }}", evidence)
        self.assertIn("if-no-files-found: error", evidence)

    def test_final_gate_uses_real_outcomes_and_requires_the_entire_matrix(self):
        gate = self.step("name: Fail after every full-interop check has reported")
        self.assertIn("if: always()", gate)
        for identifier in ("interop_consensus", "interop_xmr_tools", "interop_prepared_ingress",
                           "interop_full_graph", "interop_evidence"):
            self.assertIn("${{ steps." + identifier + ".outcome }}", gate)
        self.assertIn("*=success|*=skipped) ;;", gate)
        self.assertIn("*=failure|*=cancelled) failed=1 ;;", gate)
        self.assertIn("*) failed=1 ;;", gate)
        self.assertIn('exit "$failed"', gate)
        aggregate = self.jobs["heavy-gate"]
        self.assertRegex(aggregate, r"needs: \[[^\]]*\binterop-full\b")
        self.assertIn("${{ needs.interop-full.result }}", aggregate)


if __name__ == "__main__":
    unittest.main()
