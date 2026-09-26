"""Small-integer algebra audit, not cryptography or a funding verifier.

The additive group Z/q stands in for the prime-order curve subgroup. These
tiny moduli have no hiding/delay security. There is no Fiat-Shamir transform.
"""

from dataclasses import dataclass
from math import gcd


@dataclass(frozen=True)
class Parameters:
    n: int = 77
    g: int = 4
    steps: int = 3
    q: int = 5
    message_response_limit: int = 12
    nonce_response_limit: int = 16

    @property
    def h(self):
        return pow(self.g, 1 << self.steps, self.n)

    def validate(self):
        if (
            self.n < 3
            or self.n % 2 == 0
            or not 1 < self.g < self.n
            or gcd(self.g, self.n) != 1
            or self.steps < 1
            or self.q < 2
            or self.message_response_limit < 2
            or 2 * self.message_response_limit >= self.n
            or self.nonce_response_limit < 2
        ):
            raise ValueError("invalid toy parameters or ambiguous decoding range")


@dataclass(frozen=True)
class Puzzle:
    u: int
    v: int

    def validate(self, p):
        if not (
            0 < self.u < p.n
            and 0 < self.v < p.n**2
            and gcd(self.u, p.n) == 1
            and gcd(self.v, p.n) == 1
        ):
            raise ValueError("nonunit or noncanonical puzzle")


@dataclass(frozen=True)
class Commitment:
    puzzle: Puzzle
    point: int


@dataclass(frozen=True)
class Response:
    message: int
    nonce: int


def encrypt(p, message, nonce):
    return Puzzle(
        pow(p.g, nonce, p.n),
        pow(p.h, nonce * p.n, p.n**2)
        * pow(1 + p.n, message, p.n**2)
        % p.n**2,
    )


def commit(p, message_mask, nonce_mask):
    return Commitment(encrypt(p, message_mask, nonce_mask), message_mask % p.q)


def respond(message, nonce, message_mask, nonce_mask, challenge):
    if challenge not in (0, 1):
        raise ValueError("not a bit challenge")
    return Response(message_mask + challenge * message, nonce_mask + challenge * nonce)


def verify(p, ciphertext, point, commitment, challenge, response, *, unsafe_unbounded=False):
    """The unsafe switch exists ONLY to reproduce a negative control."""
    if not unsafe_unbounded:
        p.validate()
    try:
        ciphertext.validate(p)
        commitment.puzzle.validate(p)
    except ValueError:
        return False
    if challenge not in (0, 1) or not 0 <= point < p.q or not 0 <= commitment.point < p.q:
        return False
    if not unsafe_unbounded and not (
        0 <= response.message < p.message_response_limit
        and 0 <= response.nonce < p.nonce_response_limit
    ):
        return False
    computed = encrypt(p, response.message, response.nonce)
    return (
        computed.u == commitment.puzzle.u * pow(ciphertext.u, challenge, p.n) % p.n
        and computed.v == commitment.puzzle.v * pow(ciphertext.v, challenge, p.n**2) % p.n**2
        and response.message % p.q == (commitment.point + challenge * point) % p.q
    )


def solve_residue(p, ciphertext):
    ciphertext.validate(p)
    w = ciphertext.u
    for _ in range(p.steps):
        w = w * w % p.n
    unmasked = ciphertext.v * pow(pow(w, p.n, p.n**2), -1, p.n**2) % p.n**2
    if (unmasked - 1) % p.n:
        raise ValueError("plaintext not in message subgroup")
    return (unmasked - 1) // p.n


def decode_signed(p, residue):
    p.validate()
    if not 0 <= residue < p.n:
        raise ValueError("noncanonical residue")
    value = residue if residue <= p.n // 2 else residue - p.n
    if abs(value) >= p.message_response_limit:
        raise ValueError("outside extracted message range")
    return value


def extract(p, ciphertext, point, commitment, zero, one):
    if not verify(p, ciphertext, point, commitment, 0, zero) or not verify(
        p, ciphertext, point, commitment, 1, one
    ):
        raise ValueError("not two accepting transcripts")
    message, nonce = one.message - zero.message, one.nonce - zero.nonce
    if encrypt(p, message, nonce) != ciphertext or message % p.q != point:
        raise AssertionError("extraction equation failed")
    recovered = decode_signed(p, solve_residue(p, ciphertext))
    if recovered != message:
        raise AssertionError("extracted and recovered representatives disagree")
    return message, nonce


def enumerate_accepting_pairs(p=Parameters()):
    """Search every bounded response against every plaintext and toy point.

    Three nonce witnesses suffice to vary ciphertexts; response pairs themselves
    cover the entire configured response rectangle. Does NOT prove generality.
    """
    p.validate()
    responses = [
        Response(message, nonce)
        for message in range(p.message_response_limit)
        for nonce in range(p.nonce_response_limit)
    ]
    zero_by_commitment = {}
    for response in responses:
        zero_by_commitment.setdefault(commit(p, response.message, response.nonce), []).append(response)
    checked_statements = 0
    accepting_pairs = 0
    for message in range(p.n):
        for nonce in range(3):
            ciphertext = encrypt(p, message, nonce)
            inv_u = pow(ciphertext.u, -1, p.n)
            inv_v = pow(ciphertext.v, -1, p.n**2)
            for point in range(p.q):
                checked_statements += 1
                for one in responses:
                    encoded = encrypt(p, one.message, one.nonce)
                    commitment = Commitment(
                        Puzzle(encoded.u * inv_u % p.n, encoded.v * inv_v % p.n**2),
                        (one.message - point) % p.q,
                    )
                    for zero in zero_by_commitment.get(commitment, ()):
                        extracted, _ = extract(p, ciphertext, point, commitment, zero, one)
                        if extracted % p.n != message or extracted % p.q != point:
                            raise AssertionError("accepted a false paired statement")
                        accepting_pairs += 1
    return {
        "checked_statements": checked_statements,
        "bounded_responses_per_challenge": len(responses),
        "accepting_pairs_checked": accepting_pairs,
        "false_accepting_pairs": 0,
        "cryptographic_security_proven": False,
        "fiat_shamir_exercised": False,
        "curve_exercised": False,
        "parameters": p.__dict__,
    }


if __name__ == "__main__":
    import json

    print(json.dumps(enumerate_accepting_pairs(), indent=2))
