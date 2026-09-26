"""Protocol-schedule experiments; not tests of actual signatures or chains."""

from dataclasses import replace
from contextlib import redirect_stdout
from io import StringIO
import json
import unittest

from model import Policy, State, explore, inclusions, knows_witness, main, publications


PAIR = Policy(("DOM", "XMR"), (7, 3), (1, 1))


class PreparedReserveModelTests(unittest.TestCase):
    def test_honest_participants_actually_exchange_all_assets(self):
        for policy in (PAIR, replace(PAIR, assets=("XMR", "DOM"))):
            with self.subTest(assets=policy.assets):
                outcome = explore(policy)
                self.assertIsNone(outcome.counterexample)
                expected = tuple((i + 1) % len(policy.assets)
                                 for i in range(len(policy.assets)))
                self.assertEqual(outcome.terminal_allocations, (expected,))
                self.assertGreater(outcome.settled_states, 0)

    def test_pair_exhausts_every_nontrivial_coalition(self):
        for coalition in ((), (0,), (1,)):
            with self.subTest(coalition=coalition):
                outcome = explore(PAIR, frozenset(coalition))
                self.assertIsNone(outcome.counterexample, outcome)
                self.assertGreater(outcome.explored_states, 0)

    def test_default_report_covers_only_direct_leg_and_its_counterexample(self):
        output = StringIO()
        with redirect_stdout(output):
            main()
        report = json.loads(output.getvalue())
        experiments = report["safe_margin_experiments"]
        self.assertEqual([case["assets"] for case in experiments], [["DOM", "XMR"]])
        self.assertEqual(experiments[0]["coalitions_checked"], 3)
        attack = report["insufficient_margin_experiment"]
        self.assertEqual(attack["harmed_actor"], 1)
        self.assertIn("final refund DOM -> actor=0", "\n".join(attack["trace"]))

    def test_equality_at_pair_recovery_boundary_is_unsafe(self):
        policy = replace(PAIR, recovery=(6, 3))
        self.assertTrue(policy.timing_violations())
        outcome = explore(policy, frozenset((0,)))
        self.assertEqual(outcome.harmed_actor, 1)
        self.assertIsNotNone(outcome.counterexample)
        trace = "\n".join(outcome.counterexample)
        self.assertIn("final claim XMR -> actor=0", trace)
        self.assertIn("final refund DOM -> actor=0", trace)

    def test_stopping_claims_at_refund_admits_double_claiming_despite_safe_margins(self):
        policy = replace(PAIR, resume_claim_after_recovery=False)
        self.assertFalse(policy.timing_violations())
        outcome = explore(policy, frozenset((0,)))
        self.assertEqual(outcome.harmed_actor, 1)
        trace = "\n".join(outcome.counterexample)
        self.assertIn("publishes refund XMR", trace)
        self.assertIn("final claim XMR -> actor=0", trace)
        self.assertIn("final refund DOM -> actor=0", trace)
        # Restoring reaction to a late claim removes this counterexample within
        # the same bounded, always-online model. It is not a general proof.
        self.assertIsNone(explore(PAIR, frozenset((0,))).counterexample)

    def test_unusable_initiation_window_aborts_without_releasing_claim(self):
        policy = replace(PAIR, recovery=(7, 1))
        self.assertTrue(policy.timing_violations())
        outcome = explore(policy)
        self.assertIsNone(outcome.counterexample)
        self.assertEqual(outcome.terminal_allocations, ((0, 1),))

    def test_a_published_signature_does_not_expire_at_a_local_deadline(self):
        # Adversarial witness owner can publish a claim after the XMR cutoff.
        state = State((-1, -1), (-1, -1, -1, -1))
        choices = list(publications(PAIR, state, frozenset((0,)), tick=4))
        self.assertTrue(any(after.published[1] == 4 for after, _ in choices))

    def test_due_honest_refund_can_lose_to_new_conflicting_claim(self):
        # The environmental bound resolves a spend; it does not choose the winner.
        state = State((-1, -1), (-1, 4, -1, 3), witness_at=(0, 5))
        choices = list(inclusions(PAIR, state, frozenset((0,)), tick=4))
        owners = {after.owner[1] for after, _ in choices}
        self.assertEqual(owners, {0, 1})
        self.assertNotIn(-1, owners)

    def test_malicious_submission_has_no_guaranteed_inclusion(self):
        state = State((-1, -1), (-1, 0, -1, -1), witness_at=(0, 0))
        choices = list(inclusions(PAIR, state, frozenset((0,)), tick=3))
        self.assertTrue(any(after.owner[1] == -1 for after, _ in choices))

    def test_spent_asset_cannot_be_spent_again(self):
        state = State((1, 0), (-1,) * 4, witness_at=(0, 0))
        for published, _ in publications(PAIR, state, frozenset((0, 1)), tick=8):
            for after, _ in inclusions(PAIR, published, frozenset((0, 1)), tick=8):
                self.assertEqual(after.owner, state.owner)

    def test_higher_observation_delay_requires_larger_margins(self):
        unsafe = replace(PAIR, observation=2)
        self.assertTrue(unsafe.timing_violations())
        self.assertEqual(explore(unsafe, frozenset((0,))).harmed_actor, 1)
        repaired = replace(unsafe, recovery=(8, 3))
        self.assertFalse(repaired.timing_violations())
        self.assertIsNone(explore(repaired, frozenset((0,))).counterexample)

    def test_counterparty_observes_secret_after_direct_claim(self):
        initial = State((-1,) * 2, (-1,) * 4)
        first, _ = next(publications(PAIR, initial, frozenset(), tick=0))
        self.assertEqual(first.witness_at, (0, 1))
        self.assertFalse(knows_witness(first, 1, frozenset(), 0))
        self.assertTrue(knows_witness(first, 1, frozenset(), 1))

    def test_reverse_direction_only_checks_schedule_not_chain_compatibility(self):
        reverse = replace(PAIR, assets=("XMR", "DOM"))
        self.assertFalse(reverse.timing_violations())
        # The parameterized model is symmetric. Actual adaptor and chain formats
        # are deliberately outside this claim and still require integration.
        self.assertIsNone(explore(reverse, frozenset((0,))).counterexample)

    def test_exploration_limit_is_inconclusive_not_success(self):
        with self.assertRaisesRegex(RuntimeError, "inconclusive"):
            explore(PAIR, frozenset((0,)), state_limit=1)

    def test_bad_policy_and_coalition_do_not_create_empty_success(self):
        for update in ({"assets": ("DOM", "DOM")},
                       {"inclusion": (0, 1)},
                       {"recovery": (-1, 3)},
                       {"observation": True},
                       {"resume_claim_after_recovery": 1},
                       {"inclusion": (1,)}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                replace(PAIR, **update)
        with self.assertRaises(ValueError):
            explore(PAIR, frozenset((2,)))


if __name__ == "__main__":
    unittest.main()
