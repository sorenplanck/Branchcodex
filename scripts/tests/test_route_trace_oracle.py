"""Oracle self-tests use synthetic records, not evidence of Rust execution."""
import copy
import importlib.util
import itertools
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("route_trace_oracle", Path(__file__).resolve().parents[1] / "route_trace_oracle.py")
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def fixture():
    # Test-only witness generator. The production test runner instead reads
    # the file emitted by the real Rust router, never this synthetic fixture.
    routes = []
    for a, b in itertools.product(("Evm", "Bitcoin", "Solana", "Monero"), repeat=2):
        trace = []
        for _ in range(2):
            for action in ("Funding", "Refund"):
                for leg, face, owner in (("Downstream", b, 32), ("Upstream", a, 31)):
                    for phase, target in (("materialize", face), ("observe", face), ("materialize", "Dom")):
                        trace.append(dict(phase=phase, action=action, leg=leg, requested_face=target,
                                          returned_face=target, owner=90 if target == "Dom" else owner,
                                          settlement=owner, chain={"Dom": 9, "Evm": 10, "Bitcoin": 11, "Monero": 12, "Solana": 13}[target]))
        routes.append(dict(upstream=a, downstream=b, trace=trace))
    return dict(schema="DOM-ROUTER-V4", chain_e2e=False, scope="real-router-instrumented-children", routes=routes)


class RouteTraceOracleTests(unittest.TestCase):
    def test_complete_synthetic_witness(self):
        result = oracle.verify(fixture())
        self.assertEqual((result["ordered_pairs"], result["checked_calls"]), (16, 384))
        self.assertFalse(result["chain_e2e"])

    def test_every_identity_and_dispatch_mutation_is_refused(self):
        original = fixture()
        for field, value in (("owner", 31), ("settlement", 31), ("chain", 9),
                             ("leg", "Upstream"), ("action", "Claim"),
                             ("phase", "observe"), ("requested_face", "Dom"), ("returned_face", "Bitcoin")):
            with self.subTest(field=field):
                changed = copy.deepcopy(original)
                changed["routes"][0]["trace"][0][field] = value
                with self.assertRaises(oracle.TraceError):
                    oracle.verify(changed)

    def test_same_family_owner_transplant_is_refused(self):
        value = fixture()
        same = next(r for r in value["routes"] if r["upstream"] == r["downstream"] == "Bitcoin")
        same["trace"][0]["owner"] = 31
        with self.assertRaises(oracle.TraceError):
            oracle.verify(value)

    def test_missing_duplicated_and_replayed_calls_are_refused(self):
        for operation in (lambda v: v["routes"].pop(),
                          lambda v: v["routes"].__setitem__(1, copy.deepcopy(v["routes"][0])),
                          lambda v: v["routes"][0]["trace"].pop(),
                          lambda v: v["routes"][0]["trace"].__setitem__(3, copy.deepcopy(v["routes"][0]["trace"][0]))):
            value = fixture()
            operation(value)
            with self.assertRaises(oracle.TraceError):
                oracle.verify(value)

    def test_dom_cannot_be_omitted_or_redirected(self):
        value = fixture()
        value["routes"][0]["trace"][2]["owner"] = 32
        with self.assertRaises(oracle.TraceError):
            oracle.verify(value)

    def test_e2e_claims_unknown_fields_and_bool_identities_are_refused(self):
        for operation in (lambda v: v.__setitem__("chain_e2e", True),
                          lambda v: v.__setitem__("certified", True),
                          lambda v: v["routes"][0]["trace"][0].__setitem__("owner", True)):
            value = fixture()
            operation(value)
            with self.assertRaises(oracle.TraceError):
                oracle.verify(value)

    def test_duplicate_json_keys_and_oversized_file_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.json"
            path.write_text('{"schema":"DOM-ROUTER-V4","schema":"DOM-ROUTER-V4"}')
            with self.assertRaises(oracle.TraceError):
                oracle.load_trace(path)
            path.write_bytes(b" " * (oracle.MAX_BYTES + 1))
            with self.assertRaises(oracle.TraceError):
                oracle.load_trace(path)

    def test_file_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.json"
            path.write_text(json.dumps(fixture()))
            self.assertEqual(oracle.verify(oracle.load_trace(path))["checked_calls"], 384)


if __name__ == "__main__":
    unittest.main()
