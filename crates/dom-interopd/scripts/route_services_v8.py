#!/usr/bin/env python3
"""Independent check of the 16 PUBLIC Rust service-configuration exports.

This checks configuration/position bindings, not network execution or signed
admission. No claim, funding, refund or F7 authority is created by this tool.
"""
import argparse
import itertools
import json
from pathlib import Path

FAMILIES = {"Evm": "EVM", "Bitcoin": "BTC", "Solana": "SOL", "Monero": "XMR"}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse(text):
    return json.loads(text, object_pairs_hook=no_duplicates)


def digest(value, expected=None):
    require(isinstance(value, list) and len(value) == 32
            and all(type(v) is int and 0 <= v <= 255 for v in value)
            and any(value), "invalid digest")
    if expected is not None:
        require(value == [expected] * 32, "public fixture binding mismatch")


def verify_export(value):
    require(isinstance(value, dict) and set(value) == {"schema", "chain_e2e", "routes"}, "export fields")
    require(type(value["schema"]) is int and value["schema"] == 8 and value["chain_e2e"] is False, "export scope")
    require(isinstance(value["routes"], list) and len(value["routes"]) == 16, "16 distinct pairs required")
    seen = set()
    for row in value["routes"]:
        require(isinstance(row, dict) and set(row) == {"upstream", "downstream", "dom_chain_id", "document"}, "row fields")
        a, b = row["upstream"], row["downstream"]
        require(isinstance(a, str) and isinstance(b, str) and a in FAMILIES and b in FAMILIES, "family")
        require((a, b) not in seen, "duplicate pair")
        seen.add((a, b))
        digest(row["dom_chain_id"], 3)
        text = row["document"]
        require(isinstance(text, str) and 0 < len(text.encode()) <= 131072, "document bounds")
        document = parse(text)
        require(isinstance(document, dict) and list(document) == ["version", "route_id", "composition_digest", "registry_digest", "legs"], "document fields/order")
        require(type(document["version"]) is int and document["version"] == 8, "document version")
        for field, expected in (("route_id", 1), ("composition_digest", 2), ("registry_digest", 5)):
            digest(document[field], expected)
        require(isinstance(document["legs"], list) and len(document["legs"]) == 2, "two positions required")
        for i, (leg, family) in enumerate(zip(document["legs"], (a, b))):
            require(isinstance(leg, dict) and list(leg) == ["settlement_id", "chain_id", "service"], "leg fields/order")
            digest(leg["settlement_id"], 10 + i)
            digest(leg["chain_id"], 20 + i)
            require(leg["chain_id"] != row["dom_chain_id"], "DOM cannot replace a counterparty")
            service = leg["service"]
            require(isinstance(service, dict) and service.get("family") == FAMILIES[family], "service position/family")
            port = 18081 + i * 10000
            endpoint = f"http://127.0.0.1:{port}"
            if family == "Evm":
                expected = {"family": "EVM", "endpoint": endpoint, "refund_timeout_seconds": 30}
            elif family == "Bitcoin":
                expected = {"family": "BTC", "endpoint": endpoint, "wallet": f"wallet-{port}", "cookie": "/owned/core.cookie"}
            else:
                expected = {"family": FAMILIES[family], "endpoints": [endpoint], "quorum": 1}
            # Exact JSON also refuses bools in place of integer fields.
            require(json.dumps(service, separators=(",", ":")) == json.dumps(expected, separators=(",", ":")), "endpoint binding")
        require(json.dumps(document, separators=(",", ":"), ensure_ascii=False) + "\n" == text, "noncanonical document")
    require(seen == set(itertools.product(FAMILIES, repeat=2)), "missing route")
    return {"status": "passed", "configuration_pairs": 16, "chain_e2e": False,
            "scope": "public configuration export; no RPC/consensus/funding/claim/refund validation"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    args = parser.parse_args()
    require(args.export.stat().st_size <= 3_000_000, "export bounds")
    print(json.dumps(verify_export(parse(args.export.read_text())), indent=2))


if __name__ == "__main__":
    main()
