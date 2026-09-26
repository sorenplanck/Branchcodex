"""Exact conditional soundness budget; not a proof of the DXP1 implementation.

Assumes a uniform half-subset challenge bound to immutable, well-formed puzzles,
valid polynomial commitments, and valid range/setup proofs. A bad capsule has
no correct unopened share. Acceptance then requires guessing exactly the opened
half-subset. Repeated Fiat-Shamir trials use a union bound, not an independence
assumption. Puzzle hardness, range proofs and chain timing are outside this bound.
"""

from fractions import Fraction
from math import comb
import json


def failure_bound(participants: int, attempts: int = 1) -> Fraction:
    if participants < 2 or participants % 2 or attempts < 1:
        raise ValueError("require positive attempts and an even participant count >= 2")
    return min(Fraction(1), Fraction(attempts, comb(participants, participants // 2)))


def minimum_participants(security_bits: int, attempt_bits: int = 0) -> int:
    if security_bits < 1 or attempt_bits < 0:
        raise ValueError("invalid bit budget")
    # Compare integers; floating-point logarithms cannot authorize a parameter.
    target = 1 << (security_bits + attempt_bits)
    participants = 2
    while comb(participants, participants // 2) < target:
        participants += 2
    return participants


def accepted_search_failure_bound(participants: int, solve_budget: int,
                                  attempts: int = 1) -> Fraction:
    """Bound finding an accepted capsule that defeats a bounded sorted search.

    The challenge opens n/2 uniformly chosen indexes; the solver then visits
    the other indexes in ascending order and verifies each scalar. For a fixed
    offer with b bad puzzles, acceptance requires avoiding all b. Search
    failure after k solves requires b >= k. Avoidance is maximized at b=k,
    and placing the k bad puzzles first attains that maximum. This is the
    JOINT event of acceptance and search failure, not a probability conditioned
    on acceptance. Q candidate transcripts use a conservative union bound.

    All the setup/range/polynomial/random-oracle assumptions still apply.
    Counts do not establish a time bound or the soundness of the other proofs.
    """
    if any(type(value) is not int for value in (participants, solve_budget, attempts)):
        raise ValueError("integer parameters required")
    if (participants < 2 or participants % 2 or attempts < 1
            or not 1 <= solve_budget <= participants // 2):
        raise ValueError("require even n >= 2, positive attempts, and 1 <= solves <= n/2")
    return min(Fraction(1), Fraction(
        attempts * comb(participants - solve_budget, participants // 2),
        comb(participants, participants // 2)))


def minimum_search_budget(participants: int, security_bits: int,
                          attempt_bits: int = 0) -> int:
    if (any(type(value) is not int for value in (security_bits, attempt_bits))
            or security_bits < 1 or attempt_bits < 0):
        raise ValueError("invalid bit budget")
    # Validate n before iterating, including the zero-iteration case.
    accepted_search_failure_bound(participants, 1)
    target = Fraction(1, 1 << security_bits)
    for solves in range(1, participants // 2 + 1):
        if accepted_search_failure_bound(participants, solves, 1 << attempt_bits) <= target:
            return solves
    raise ValueError("participant count cannot meet the requested search budget security")


if __name__ == "__main__":
    examples = []
    for attempts_bits in (0, 32, 64):
        participants = minimum_participants(128, attempts_bits)
        bound = failure_bound(participants, 1 << attempts_bits)
        examples.append({
            "target_bits": 128,
            "attempt_bits": attempts_bits,
            "participants": participants,
            "threshold": participants // 2 + 1,
            "minimum_sorted_search_solves": minimum_search_budget(participants, 128, attempts_bits),
            "upper_bound": f"{bound.numerator}/{bound.denominator}",
            "within_target": bound <= Fraction(1, 1 << 128),
        })
    print(json.dumps({"scope": "conditional cut-and-choose bound only", "parameters": examples}, indent=2))
