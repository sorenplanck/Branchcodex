"""Direct DOM/XMR timing assumptions; no chain-time or puzzle-speed proof."""
from dataclasses import replace
import unittest

from model import Policy, State, explore, inclusions, publications


class PreparationTimingTests(unittest.TestCase):
    def test_asymmetric_bounds_allow_actual_swap_under_explicit_assumptions(self):
        policy = Policy(("DOM", "XMR"), (12, 5), (1, 1),
                        honest_recovery=(14, 7), funded_at=(2, 2), ready_at=3)
        self.assertFalse(policy.timing_violations())
        self.assertEqual(explore(policy).terminal_allocations, ((1, 0),))
        for malicious in ((), (0,), (1,)):
            outcome = explore(policy, frozenset(malicious))
            self.assertIsNone(outcome.counterexample, outcome)
            self.assertGreater(outcome.settled_states, 0)

    def test_equal_solver_speeds_hide_loss_for_slower_honest_refunder(self):
        assumed_equal = Policy(("DOM", "XMR"), (9, 5), (1, 1),
                               funded_at=(2, 2), ready_at=3)
        self.assertFalse(assumed_equal.timing_violations())
        self.assertIsNone(explore(assumed_equal, frozenset((0,))).counterexample)
        slower_honest = replace(assumed_equal, honest_recovery=(11, 7))
        self.assertTrue(slower_honest.timing_violations())
        outcome = explore(slower_honest, frozenset((0,)))
        self.assertEqual(outcome.harmed_actor, 1)
        trace = "\n".join(outcome.counterexample)
        self.assertIn("final refund DOM -> actor=0", trace)
        self.assertIn("final claim XMR -> actor=0", trace)

    def test_preparation_consumes_window_and_expired_offer_does_not_exchange(self):
        original = Policy(("DOM", "XMR"), (12, 5), (1, 1),
                          honest_recovery=(14, 7), funded_at=(2, 2), ready_at=3)
        delayed = replace(original, ready_at=4)
        self.assertTrue(delayed.timing_violations())  # Equality is insufficient.
        self.assertEqual(explore(delayed).terminal_allocations, ((0, 1),))
        # Pretending disclosure occurred at funding would revive this window;
        # those larger deadlines describe a DIFFERENT assumed cryptographic fact.
        reset_clock = replace(delayed, recovery=(14, 7), honest_recovery=(16, 9))
        self.assertFalse(reset_clock.timing_violations())
        self.assertEqual(explore(reset_clock).terminal_allocations, ((1, 0),))

    def test_no_spending_before_funding_or_claim_delivery(self):
        policy = Policy(("DOM", "XMR"), (1, 1), (1, 1),
                        funded_at=(2, 3), ready_at=4)
        state = State((-1, -1), (-1,) * 4)
        self.assertEqual(list(publications(policy, state, frozenset((0, 1)), 1)), [(state, ())])
        for after, _ in publications(policy, state, frozenset((0, 1)), 3):
            self.assertEqual(after.published[:2], (-1, -1))
        injected = State((-1, -1), (0, 0, 0, 0))
        self.assertEqual([s.owner for s, _ in inclusions(policy, injected, frozenset(), 1)], [(-1, -1)])

    def test_invalid_or_inverted_bounds_are_rejected(self):
        policy = Policy(("DOM", "XMR"), (12, 5), (1, 1))
        for update in ({"honest_recovery": (11, 5)}, {"honest_recovery": (12,)},
                       {"funded_at": (True, 0)}, {"funded_at": (0, 1)},
                       {"ready_at": True}, {"ready_at": 25},
                       {"honest_recovery": (12, 25)}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                replace(policy, **update)


if __name__ == "__main__":
    unittest.main()
