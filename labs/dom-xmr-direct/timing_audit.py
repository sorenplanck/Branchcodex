#!/usr/bin/env python3
"""Reproduce direct-pair timing counterexamples; never a funding authorization."""
from dataclasses import asdict, replace
import json

from model import Policy, explore


def report():
    safe_assumptions = Policy(("DOM", "XMR"), (12, 5), (1, 1),
                              honest_recovery=(14, 7), funded_at=(2, 2), ready_at=3)
    equal_speed = replace(safe_assumptions, recovery=(9, 5), honest_recovery=None)
    slow_honest = replace(equal_speed, honest_recovery=(11, 7))
    late_preparation = replace(safe_assumptions, ready_at=4)
    cases = {}
    for name, policy, coalitions in [
        ("conditional_separated_bounds", safe_assumptions, [(), (0,), (1,)]),
        ("equal_speed_assumption", equal_speed, [(0,)]),
        ("slower_honest_refunder", slow_honest, [(0,)]),
        ("preparation_exhausts_window", late_preparation, [()]),
    ]:
        cases[name] = {"policy": asdict(policy), "timing_violations": policy.timing_violations(),
                       "outcomes": [{"malicious": malicious, **asdict(explore(policy, frozenset(malicious)))}
                                    for malicious in coalitions]}
    assert cases["slower_honest_refunder"]["outcomes"][0]["harmed_actor"] == 1
    assert cases["conditional_separated_bounds"]["outcomes"][0]["terminal_allocations"] == ((1, 0),)
    assert cases["preparation_exhausts_window"]["outcomes"][0]["terminal_allocations"] == ((0, 1),)
    return {"experiment": "absolute preparation and asymmetric recovery timing",
            "bitcoin_involved": False, "units": "dimensionless ticks",
            "atomic_swap_proven": False, "cryptographic_delay_proven": False,
            "funding_and_maturity_assumed": True, "authenticated_setup_proven": False,
            "cases": cases}


if __name__ == "__main__":
    print(json.dumps(report(), indent=2))
