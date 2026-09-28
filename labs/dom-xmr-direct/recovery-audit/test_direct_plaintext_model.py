"""Algebra and forgery controls; no ZK, delay or production security claim."""
from dataclasses import replace
import unittest

from direct_plaintext_model import (
    Commitment, Parameters, Puzzle, Response, commit, decode_signed, encrypt,
    enumerate_accepting_pairs, extract, respond, solve_residue, verify,
)


class DirectPlaintextAlgebraTests(unittest.TestCase):
    def setUp(self):
        self.p = Parameters()

    def test_small_parameter_exhaustion_finds_no_false_paired_statement(self):
        result = enumerate_accepting_pairs(self.p)
        self.assertEqual(result["checked_statements"], 77 * 3 * 5)
        self.assertGreater(result["accepting_pairs_checked"], 1000)
        self.assertEqual(result["false_accepting_pairs"], 0)

    def test_extraction_includes_negative_messages_and_nonce_differences(self):
        for message, nonce, a, b in [(3, 2, 4, 5), (-3, -2, 5, 4), (6, -3, 1, 8)]:
            ciphertext = encrypt(self.p, message, nonce)
            commitment = commit(self.p, a, b)
            zero, one = [respond(message, nonce, a, b, bit) for bit in (0, 1)]
            self.assertEqual(extract(self.p, ciphertext, message % self.p.q, commitment, zero, one), (message, nonce))
            self.assertEqual(decode_signed(self.p, solve_residue(self.p, ciphertext)), message)

    def test_unbounded_crt_forgery_passes_equations_but_opens_wrong_point(self):
        message, nonce = 3, 2
        fake_integer = message + 2 * self.p.n
        wrong_point = fake_integer % self.p.q
        ciphertext = encrypt(self.p, message, nonce)
        commitment = commit(self.p, 0, 0)
        zero, one = Response(0, 0), Response(fake_integer, nonce)
        self.assertNotEqual(wrong_point, message % self.p.q)
        for bit, response in [(0, zero), (1, one)]:
            self.assertTrue(verify(self.p, ciphertext, wrong_point, commitment, bit, response, unsafe_unbounded=True))
        self.assertFalse(verify(self.p, ciphertext, wrong_point, commitment, 1, one))
        self.assertNotEqual(decode_signed(self.p, solve_residue(self.p, ciphertext)) % self.p.q, wrong_point)

    def test_ambiguous_range_can_accept_two_representatives_with_different_points(self):
        unsafe = replace(self.p, message_response_limit=40)
        ciphertext = encrypt(unsafe, 38, 2)
        commitment = commit(unsafe, 39, 0)
        zero, one = Response(39, 0), Response(0, 2)
        wrong_point = -39 % unsafe.q
        # Both response values are in [0,40); the missing condition is 2R<N.
        for bit, response in [(0, zero), (1, one)]:
            self.assertTrue(verify(unsafe, ciphertext, wrong_point, commitment, bit, response, unsafe_unbounded=True))
        self.assertNotEqual(solve_residue(unsafe, ciphertext) % unsafe.q, wrong_point)
        with self.assertRaises(ValueError):
            unsafe.validate()

    def test_both_ciphertext_components_and_the_point_are_required(self):
        ciphertext = encrypt(self.p, 3, 2)
        commitment = commit(self.p, 4, 5)
        response = respond(3, 2, 4, 5, 1)
        self.assertTrue(verify(self.p, ciphertext, 3, commitment, 1, response))
        for wrong in [replace(ciphertext, u=encrypt(self.p, 3, 3).u), replace(ciphertext, v=encrypt(self.p, 4, 2).v)]:
            self.assertFalse(verify(self.p, wrong, 3, commitment, 1, response))
        self.assertFalse(verify(self.p, ciphertext, 4, commitment, 1, response))

    def test_nonunits_noncanonical_elements_and_unbounded_responses_are_rejected(self):
        ciphertext = encrypt(self.p, 3, 2)
        commitment = commit(self.p, 4, 5)
        response = respond(3, 2, 4, 5, 1)
        for wrong in [Puzzle(0, 1), Puzzle(7, 1), Puzzle(1, 0), Puzzle(1, 11), Puzzle(1, self.p.n**2 + 1)]:
            self.assertFalse(verify(self.p, wrong, 3, commitment, 1, response))
            self.assertFalse(verify(self.p, ciphertext, 3, Commitment(wrong, 4), 1, response))
        for wrong in [Response(-1, 2), Response(12, 2), Response(1, -1), Response(1, 16)]:
            self.assertFalse(verify(self.p, ciphertext, 3, commitment, 1, wrong))
        for point in [-1, self.p.q]:
            self.assertFalse(verify(self.p, ciphertext, point, commitment, 1, response))
        self.assertFalse(verify(self.p, ciphertext, 3, commitment, 2, response))

    def test_subgroup_and_decoding_boundaries(self):
        for value in [-11, -1, 0, 1, 11]:
            self.assertEqual(decode_signed(self.p, solve_residue(self.p, encrypt(self.p, value, 2))), value)
        for value in [-12, 12, 38]:
            with self.assertRaises(ValueError):
                decode_signed(self.p, solve_residue(self.p, encrypt(self.p, value, 2)))
        with self.assertRaises(ValueError):
            solve_residue(self.p, Puzzle(1, 2))
        for residue in [-1, self.p.n]:
            with self.assertRaises(ValueError):
                decode_signed(self.p, residue)

    def test_extract_requires_the_same_commitment_and_both_challenges(self):
        ciphertext = encrypt(self.p, 3, 2)
        commitment = commit(self.p, 4, 5)
        zero, one = Response(4, 5), Response(7, 7)
        for invalid_zero, invalid_one in [(one, zero), (zero, replace(one, message=8))]:
            with self.assertRaises(ValueError):
                extract(self.p, ciphertext, 3, commitment, invalid_zero, invalid_one)
        with self.assertRaises(ValueError):
            extract(self.p, ciphertext, 3, commit(self.p, 5, 5), zero, one)


if __name__ == "__main__":
    unittest.main()
