import itertools
from fractions import Fraction
from math import comb
import unittest

from cut_choose_budget import failure_bound, minimum_participants


class CutChooseBudgetTests(unittest.TestCase):
    def test_exhaustive_bad_capsule_acceptance_matches_bound(self):
        for n in (2, 4, 6, 8):
            subsets = [set(s) for s in itertools.combinations(range(n), n // 2)]
            worst = Fraction(0)
            universe = set(range(n))
            for bad_mask in range(1 << n):
                bad = {i for i in range(n) if bad_mask & (1 << i)}
                accepted_without_recovery = sum(
                    not (opened & bad) and (universe - opened) <= bad
                    for opened in subsets
                )
                worst = max(worst, Fraction(accepted_without_recovery, len(subsets)))
            self.assertEqual(worst, failure_bound(n))

    def test_selected_parameters_are_minimal_and_meet_target(self):
        for security in (32, 64, 128):
            for grinding in (0, 32, 64):
                n = minimum_participants(security, grinding)
                target = Fraction(1, 1 << security)
                self.assertLessEqual(failure_bound(n, 1 << grinding), target)
                self.assertGreater(failure_bound(n - 2, 1 << grinding), target)

    def test_small_fixtures_do_not_claim_security(self):
        self.assertEqual(failure_bound(6), Fraction(1, 20))
        self.assertEqual(failure_bound(20), Fraction(1, 184756))
        self.assertEqual(failure_bound(20, 1 << 32), Fraction(1))

    def test_grinding_uses_conservative_union_bound(self):
        self.assertEqual(failure_bound(20, 7), Fraction(7, comb(20, 10)))
        self.assertEqual(failure_bound(6, 21), Fraction(1))

    def test_invalid_parameters_fail(self):
        for n, attempts in ((0, 1), (3, 1), (6, 0), (-2, 1)):
            with self.assertRaises(ValueError):
                failure_bound(n, attempts)
        for security, grinding in ((0, 0), (128, -1)):
            with self.assertRaises(ValueError):
                minimum_participants(security, grinding)


if __name__ == "__main__":
    unittest.main()
