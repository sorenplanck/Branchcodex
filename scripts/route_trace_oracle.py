#!/usr/bin/env python3
"""Independent checker for the public trace emitted by the V4 Rust router test.

This validates deterministic routing at instrumented child boundaries. It does
not verify transactions, chain finality, signatures, or economic outcomes.
No production adapter implementation is imported or reimplemented here.
"""
import argparse
import itertools
import json
from pathlib import Path
import sys

FAMILIES = ("Bitcoin", "Evm", "Monero", "Solana")
CHAIN_TAG = {"Dom": 9, "Evm": 10, "Bitcoin": 11, "Monero": 12, "Solana": 13}
MAX_BYTES = 2 * 1024 * 1024
FIELDS = {"phase", "action", "leg", "requested_face", "returned_face", "owner", "settlement", "chain"}


class TraceError(ValueError):
    """The trace violates the independently specified two-leg routing contract."""


def require(condition, message):
    if not condition:
        raise TraceError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def load_trace(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, "trace exceeds byte limit")
    return json.loads(data, object_pairs_hook=unique_object)


def verify(document):
    require(type(document) is dict and set(document) == {"schema", "chain_e2e", "scope", "routes"}, "invalid envelope")
    require(document["schema"] == "DOM-ROUTER-V4", "wrong schema")
    require(document["chain_e2e"] is False, "routing trace cannot claim chain E2E")
    require(document["scope"] == "real-router-instrumented-children", "wrong scope")
    routes = document["routes"]
    require(type(routes) is list and len(routes) == 16, "all sixteen ordered pairs are required")
    seen = set()
    records = 0
    for route in routes:
        require(type(route) is dict and set(route) == {"upstream", "downstream", "trace"}, "invalid route")
        a, b = route["upstream"], route["downstream"]
        require(type(a) is str and type(b) is str and a in FAMILIES and b in FAMILIES, "unknown family")
        require((a, b) not in seen, "duplicate route")
        seen.add((a, b))
        trace = route["trace"]
        require(type(trace) is list and len(trace) == 24, "missing or duplicated calls")
        position = 0
        # Reference sequence declared independently of the Rust implementation:
        # two retries, funding then refund, downstream then upstream, each
        # counterparty materialize/observe followed by its mandatory DOM child.
        for _ in range(2):
            for action in ("Funding", "Refund"):
                for leg, face, settlement in (("Downstream", b, 32), ("Upstream", a, 31)):
                    for phase, requested in (("materialize", face), ("observe", face), ("materialize", "Dom")):
                        item = trace[position]
                        position += 1
                        require(type(item) is dict and set(item) == FIELDS, "invalid trace record")
                        for key in ("owner", "settlement", "chain"):
                            require(type(item[key]) is int, "identity tag must be an integer")
                        expected = {"phase": phase, "action": action, "leg": leg,
                                    "requested_face": requested, "returned_face": requested,
                                    "owner": 90 if requested == "Dom" else settlement,
                                    "settlement": settlement, "chain": CHAIN_TAG[requested]}
                        require(item == expected, f"routing divergence at {a}->DOM->{b}, call {position}")
                        records += 1
    require(seen == set(itertools.product(FAMILIES, repeat=2)), "incomplete family matrix")
    return {"status": "passed", "ordered_pairs": len(seen), "checked_calls": records,
            "scope": "instrumented-router-traces", "chain_e2e": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    args = parser.parse_args()
    try:
        result = verify(load_trace(args.trace))
    except (OSError, ValueError, TypeError, RecursionError) as error:
        print(json.dumps({"status": "failed", "error": str(error), "chain_e2e": False}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
