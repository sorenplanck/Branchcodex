"""Exact adversarial operation budgets, independently checked by enumeration."""
import itertools
from fractions import Fraction
import unittest

from cut_choose_budget import (
    accepted_search_failure_bound, failure_bound, minimum_search_budget,
)


class RecoverySearchBudgetTests(unittest.TestCase):
    def test_exhaustive_openings_and_bad_positions_attain_bound(self):
        for n in (2, 4, 6, 8):
            opened_sets = [set(s) for s in itertools.combinations(range(n), n // 2)]
            for solves in range(1, n // 2 + 1):
                worst = Fraction(0)
                for mask in range(1 << n):
                    bad = {i for i in range(n) if mask & (1 << i)}
                    failures = 0
                    for opened in opened_sets:
                        if opened & bad:
                            continue
                        delayed = [i for i in range(n) if i not in opened]
                        failures += all(i in bad for i in delayed[:solves])
                    worst = max(worst, Fraction(failures, len(opened_sets)))
                self.assertEqual(worst, accepted_search_failure_bound(n, solves))

    def test_one_or_two_good_benchmark_attempts_do_not_bound_adversarial_search(self):
        self.assertEqual(accepted_search_failure_bound(198, 1), Fraction(1, 2))
        self.assertEqual(accepted_search_failure_bound(198, 2), Fraction(49, 197))
        self.assertEqual(accepted_search_failure_bound(198, 2, 1 << 64), 1)
        self.assertGreater(accepted_search_failure_bound(198, 98, 1 << 64), Fraction(1, 1 << 128))
        self.assertEqual(minimum_search_budget(198, 128, 64), 99)

    def test_full_search_matches_existing_no_recovery_bound(self):
        for n in (6, 132, 166, 198, 512):
            for attempts in (1, 7, 1 << 64):
                self.assertEqual(accepted_search_failure_bound(n, n // 2, attempts),
                                 failure_bound(n, attempts))

    def test_selected_budget_is_minimal_and_insufficient_profiles_are_rejected(self):
        for n, security, grinding in [(20, 8, 0), (132, 128, 0), (166, 128, 32), (198, 128, 64)]:
            selected = minimum_search_budget(n, security, grinding)
            target = Fraction(1, 1 << security)
            self.assertLessEqual(accepted_search_failure_bound(n, selected, 1 << grinding), target)
            if selected > 1:
                self.assertGreater(accepted_search_failure_bound(n, selected - 1, 1 << grinding), target)
        with self.assertRaises(ValueError):
            minimum_search_budget(6, 128)

    def test_invalid_counts_do_not_produce_a_security_result(self):
        for args in [(0, 1), (3, 1), (6, 0), (6, 4), (6, 1, 0), (True, 1), (6, 1.0), (6, 1, True)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                accepted_search_failure_bound(*args)
        for args in [(0, 128), (6, 0), (6, 8, -1), (6, True), (6, 8, 0.5)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                minimum_search_budget(*args)


if __name__ == "__main__":
    unittest.main()
