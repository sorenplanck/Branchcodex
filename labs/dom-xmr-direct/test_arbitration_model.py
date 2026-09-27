"""Counterexample search for the proposed native DOM arbitration alternative."""

import unittest

from arbitration_model import Window, first_double_capture, settle


class ArbiterRaceTests(unittest.TestCase):
    def test_secret_visible_before_claim_inclusion_allows_double_capture(self):
        window = Window(last_claim_height=4, first_refund_height=5,
                        latest_honest_claim_send=4, max_dom_inclusion_delay=3)
        attack = first_double_capture(window, window.max_dom_inclusion_delay)
        self.assertIsNotNone(attack)
        self.assertEqual((attack.submitted_height, attack.inclusion_delay), (2, 3))
        self.assertIsNone(attack.claim_included_height)
        self.assertEqual(attack.refund_included_height, 5)
        self.assertTrue(attack.alice_keeps_dom and attack.alice_can_take_xmr)

    def test_honest_send_margin_excludes_race_only_under_inclusion_bound(self):
        window = Window(last_claim_height=4, first_refund_height=5,
                        latest_honest_claim_send=1, max_dom_inclusion_delay=3)
        self.assertIsNone(first_double_capture(window, 3))
        # A single inclusion delay beyond the assumed bound breaks the claim.
        attack = settle(window, submitted_height=1, inclusion_delay=4)
        self.assertTrue(attack.alice_double_capture)

    def test_claim_and_refund_must_be_consensus_disjoint(self):
        with self.assertRaises(ValueError):
            Window(last_claim_height=5, first_refund_height=5,
                   latest_honest_claim_send=1, max_dom_inclusion_delay=2)


if __name__ == "__main__":
    unittest.main()
