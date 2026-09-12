import copy
import itertools
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import route_services_v8 as oracle


def export():
    routes = []
    for a, b in itertools.product(oracle.FAMILIES, repeat=2):
        legs = []
        for i, family in enumerate((a, b)):
            port = 18081 + i * 10000
            url = f"http://127.0.0.1:{port}"
            if family == "Evm":
                service = {"family": "EVM", "endpoint": url, "refund_timeout_seconds": 30}
            elif family == "Bitcoin":
                service = {"family": "BTC", "endpoint": url, "wallet": f"wallet-{port}", "cookie": "/owned/core.cookie"}
            else:
                service = {"family": oracle.FAMILIES[family], "endpoints": [url], "quorum": 1}
            legs.append({"settlement_id": [10+i]*32, "chain_id": [20+i]*32, "service": service})
        document = {"version": 8, "route_id": [1]*32, "composition_digest": [2]*32,
                    "registry_digest": [5]*32, "legs": legs}
        routes.append({"upstream": a, "downstream": b, "dom_chain_id": [3]*32,
                       "document": json.dumps(document, separators=(",", ":"))+"\n"})
    return {"schema": 8, "chain_e2e": False, "routes": routes}


class RouteServicesTests(unittest.TestCase):
    def test_all_sixteen_configurations_include_same_family_and_no_btc_evm(self):
        self.assertEqual(oracle.verify_export(export())["configuration_pairs"], 16)

    def test_missing_repeated_and_relabelled_pairs_fail(self):
        for action in ("missing", "repeat", "relabel"):
            value = export()
            if action == "missing":
                value["routes"].pop()
            elif action == "repeat":
                value["routes"][0] = copy.deepcopy(value["routes"][1])
            else:
                value["routes"][0]["upstream"] = "DOM"
            with self.assertRaises(ValueError):
                oracle.verify_export(value)

    def test_dom_is_mandatory_in_every_route(self):
        for index in range(16):
            value = export()
            value["routes"][index]["dom_chain_id"] = [0]*32
            with self.assertRaises(ValueError):
                oracle.verify_export(value)

    def test_leg_chain_settlement_and_scope_substitutions_fail(self):
        for mode in ("swap", "settlement", "chain", "route", "registry"):
            value = export()
            doc = json.loads(value["routes"][0]["document"])
            if mode == "swap":
                doc["legs"].reverse()
            elif mode == "settlement":
                doc["legs"][0]["settlement_id"][0] ^= 1
            elif mode == "chain":
                doc["legs"][1]["chain_id"][0] ^= 1
            else:
                doc["route_id" if mode == "route" else "registry_digest"][0] ^= 1
            value["routes"][0]["document"] = json.dumps(doc, separators=(",", ":"))+"\n"
            with self.assertRaises(ValueError):
                oracle.verify_export(value)

    def test_wire_duplicates_extensions_and_fake_e2e_fail(self):
        value = export()
        text = value["routes"][0]["document"]
        value["routes"][0]["document"] = text.replace('"version":8', '"version":8,"version":8')
        with self.assertRaises(ValueError):
            oracle.verify_export(value)
        value = export(); value["chain_e2e"] = True
        with self.assertRaises(ValueError):
            oracle.verify_export(value)
        value = export(); value["routes"][0]["document"] += "\n"
        with self.assertRaises(ValueError):
            oracle.verify_export(value)

    def test_service_family_endpoints_and_boolean_quorum_fail(self):
        for field, replacement in (("family", "BTC"), ("endpoints", ["http://127.0.0.1:99"]), ("quorum", True)):
            value = export()
            row = next(r for r in value["routes"] if r["upstream"] == "Solana")
            doc = json.loads(row["document"]); doc["legs"][0]["service"][field] = replacement
            row["document"] = json.dumps(doc, separators=(",", ":"))+"\n"
            with self.assertRaises(ValueError):
                oracle.verify_export(value)


if __name__ == "__main__":
    unittest.main()
