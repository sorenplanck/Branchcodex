"""Archived composition experiment; outside the active DOM/XMR leg.

Run explicitly from the lab with:
PYTHONPATH=. python3 -B -m unittest discover -s historical -p 'test_*.py'
"""

from dataclasses import replace
import unittest

from model import Policy, State, explore, knows_witness, powerset, publications


ROUTE = Policy(("BTC", "DOM", "XMR"), (11, 7, 3), (1, 1, 1))


class HistoricalCompositionTests(unittest.TestCase):
    def test_route_exhausts_single_adversaries_and_colluding_pairs(self):
        checked = 0
        for coalition in powerset((0, 1, 2)):
            if len(coalition) == 3:
                continue
            with self.subTest(coalition=coalition):
                outcome = explore(ROUTE, frozenset(coalition))
                self.assertIsNone(outcome.counterexample, outcome)
                if not coalition:
                    self.assertEqual(outcome.terminal_allocations, ((1, 2, 0),))
                checked += 1
        self.assertEqual(checked, 7)

    def test_colluding_endpoints_can_harm_router_with_insufficient_margin(self):
        outcome = explore(replace(ROUTE, recovery=(10, 7, 3)), frozenset((0, 2)))
        self.assertEqual(outcome.harmed_actor, 1)
        trace = "\n".join(outcome.counterexample)
        self.assertIn("final claim DOM -> actor=2", trace)
        self.assertIn("final refund BTC -> actor=0", trace)

    def test_router_cannot_extract_from_an_unrelated_chains_signature(self):
        initial = State((-1,) * 3, (-1,) * 6)
        first, _ = next(publications(ROUTE, initial, frozenset(), tick=0))
        self.assertEqual(first.witness_at, (0, -1, 1))
        self.assertTrue(knows_witness(first, 2, frozenset(), 1))
        self.assertFalse(knows_witness(first, 1, frozenset(), 1))
        second, _ = next(publications(ROUTE, first, frozenset(), tick=1))
        self.assertEqual(second.witness_at, (0, 2, 1))
        self.assertTrue(knows_witness(second, 1, frozenset(), 2))

    def test_colluders_can_share_secret_without_giving_it_to_honest_router(self):
        initial = State((-1,) * 3, (-1,) * 6)
        coalition = frozenset((0, 2))
        self.assertTrue(knows_witness(initial, 2, coalition, 0))
        self.assertFalse(knows_witness(initial, 1, coalition, 0))

    def test_reverse_direction_only_checks_schedule_not_chain_compatibility(self):
        reverse = replace(ROUTE, assets=("XMR", "DOM", "BTC"))
        self.assertFalse(reverse.timing_violations())
        self.assertIsNone(explore(reverse, frozenset((0, 2))).counterexample)


if __name__ == "__main__":
    unittest.main()
