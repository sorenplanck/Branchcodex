"""Bounded model of a proposed DOM arbiter, not an implemented swap.

Alice owns DOM and share a of a jointly controlled XMR output. Bob owns XMR
and share b. A DOM Claim(b) pays Bob and exposes b; Refund(a) pays Alice and
exposes a. A published claim exposes b even if consensus never includes it.
The model begins AFTER a correct mature XMR lock and irreversible DOM Ready.
It deliberately excludes key generation, initial abort, reorgs, fees, and
eventual XMR confirmation. The assumed DOM inclusion bound is a premise, not
a fact established by this explorer.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Window:
    last_claim_height: int
    first_refund_height: int
    latest_honest_claim_send: int
    max_dom_inclusion_delay: int

    def __post_init__(self):
        if not (0 <= self.latest_honest_claim_send <= self.last_claim_height
                < self.first_refund_height):
            raise ValueError("claim and refund heights must be disjoint")
        if self.max_dom_inclusion_delay < 1:
            raise ValueError("positive bounded inclusion delay required")

    def admits_honest_claim(self, submitted_height: int) -> bool:
        return 0 <= submitted_height <= self.latest_honest_claim_send


@dataclass(frozen=True)
class Schedule:
    submitted_height: int
    inclusion_delay: int
    claim_included_height: int | None
    refund_included_height: int | None
    alice_can_take_xmr: bool
    bob_can_take_xmr: bool
    alice_keeps_dom: bool
    bob_gets_dom: bool

    @property
    def alice_double_capture(self) -> bool:
        return self.alice_keeps_dom and self.alice_can_take_xmr


def settle(window: Window, submitted_height: int, inclusion_delay: int) -> Schedule:
    """Resolve one schedule assuming refund wins whenever claim misses cutoff.

    This gives the malicious DOM owner the most favorable legal ordering. It
    cannot prove chain liveness; inclusion_delay is supplied by the caller.
    """
    if not window.admits_honest_claim(submitted_height):
        raise ValueError("honest claim outside send window")
    if inclusion_delay < 1:
        raise ValueError("invalid inclusion delay")
    candidate_height = submitted_height + inclusion_delay
    claim_height = candidate_height if candidate_height <= window.last_claim_height else None
    refund_height = None if claim_height is not None else window.first_refund_height
    # The signed claim bytes reveal b at submission. Alice already knows a.
    alice_can_take_xmr = True
    # A successful DOM refund exposes a; Bob already knows b.
    bob_can_take_xmr = refund_height is not None
    return Schedule(
        submitted_height, inclusion_delay, claim_height, refund_height,
        alice_can_take_xmr, bob_can_take_xmr,
        refund_height is not None, claim_height is not None,
    )


def first_double_capture(window: Window, max_observed_delay: int) -> Schedule | None:
    for sent in range(window.latest_honest_claim_send + 1):
        for delay in range(1, max_observed_delay + 1):
            schedule = settle(window, sent, delay)
            if schedule.alice_double_capture:
                return schedule
    return None
