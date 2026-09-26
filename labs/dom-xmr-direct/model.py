#!/usr/bin/env python3
"""Bounded adversarial model for the NEW prepared-reserve protocol candidate.

No signing, blockchain, wallet or clock implementation is supplied here.
Each actor pays asset[i] and receives asset[i-1]; actor 0 knows the common
witness. The model ASSUMES valid reserves appear at fixed funding ticks, valid
adaptor offers become usable at ready_at, and delayed recovery has the supplied
earliest/latest bounds. It does not verify cryptography, a funding protocol,
fair delivery, chain maturity, or those time bounds. Defaults retain the prior
already-prepared experiment with funding and offers ready at tick zero.

We enumerate malicious publications and chain winner/delay choices, under an
explicit finality-or-conflict bound for honest submissions. Reorganizations
are abstracted into that assumed bound, NOT explicitly verified by this model.
Ticks are dimensionless. Runtime of this explorer is not swap latency.
"""

from dataclasses import dataclass, replace
from itertools import combinations, product
import json


@dataclass(frozen=True)
class Policy:
    assets: tuple[str, ...]
    recovery: tuple[int, ...]
    inclusion: tuple[int, ...]
    observation: int = 1
    # False is an intentionally unsafe control experiment: the participant
    # abandons its incoming claim when recovery of its own reserve starts.
    resume_claim_after_recovery: bool = True
    # Absolute ticks since capsule disclosure, not since the UI says "start".
    # Separate earliest adversarial opening from latest honest recovery.
    honest_recovery: tuple[int, ...] | None = None
    funded_at: tuple[int, ...] | None = None
    ready_at: int = 0

    def __post_init__(self):
        n = len(self.assets)
        if n not in (2, 3) or len(set(self.assets)) != n:
            raise ValueError("model supports two or three distinct assets")
        if len(self.recovery) != n or len(self.inclusion) != n:
            raise ValueError("one deadline and inclusion bound per asset required")
        if any(type(x) is not int or not 0 <= x <= 24 for x in self.recovery):
            raise ValueError("recovery tick outside finite model domain")
        if any(type(x) is not int or not 1 <= x <= 4 for x in self.inclusion):
            raise ValueError("inclusion bound outside finite model domain")
        if type(self.observation) is not int or not 1 <= self.observation <= 4:
            raise ValueError("observation bound outside finite model domain")
        if type(self.resume_claim_after_recovery) is not bool:
            raise ValueError("recovery behavior must be an explicit boolean")
        for times in (self.honest_recovery, self.funded_at):
            if times is not None and (len(times) != n or any(
                    type(x) is not int or not 0 <= x <= 24 for x in times)):
                raise ValueError("absolute timing outside finite model domain")
        if self.honest_recovery is not None and any(
                latest < earliest for latest, earliest in zip(self.honest_recovery, self.recovery)):
            raise ValueError("honest latest recovery precedes adversarial earliest opening")
        if (type(self.ready_at) is not int or not 0 <= self.ready_at <= 24
                or self.ready_at < max(self.funded_at or (0,) * n)):
            raise ValueError("offers ready before funding or outside model domain")

    def timing_violations(self):
        """Necessary conservative margins for this abstract schedule only."""
        failures = []
        if self.ready_at + self.inclusion[-1] >= self.recovery[-1]:
            failures.append("initiator has no strict final-asset settlement margin")
        for incoming in range(len(self.assets) - 1):
            outgoing = incoming + 1
            latest = ((self.honest_recovery or self.recovery)[outgoing] + self.inclusion[outgoing]
                      + self.observation + self.inclusion[incoming])
            if latest >= self.recovery[incoming]:
                failures.append(f"insufficient recovery separation: {self.assets[incoming]}")
        return tuple(failures)


@dataclass(frozen=True)
class State:
    # -1 means unspent. A spend assigns the asset to its payer or recipient.
    owner: tuple[int, ...]
    # Publication tick of claim[0..n], refund[0..n], or -1 if absent.
    published: tuple[int, ...]
    # Each payer can extract ONLY from the claim of its own outgoing asset.
    # -1: unknown; 0: already known; positive: that actor's observation tick.
    witness_at: tuple[int, ...] = ()

    def __post_init__(self):
        if not self.witness_at:
            object.__setattr__(self, "witness_at", (0,) + (-1,) * (len(self.owner) - 1))


@dataclass(frozen=True)
class Outcome:
    explored_states: int
    settled_states: int
    counterexample: tuple[str, ...] | None
    harmed_actor: int | None
    terminal_allocations: tuple[tuple[int, ...], ...]


def powerset(items):
    for size in range(len(items) + 1):
        yield from combinations(items, size)


def knows_witness(state, actor, malicious, tick):
    if actor == 0:
        return True
    if actor in malicious:
        # A coalition can share any witness one of its members already knows.
        return any(0 <= state.witness_at[peer] <= tick for peer in malicious)
    return 0 <= state.witness_at[actor] <= tick


def publications(policy, state, malicious, tick):
    n = len(policy.assets)
    required = []
    optional = []
    for actor in range(n):
        incoming = (actor - 1) % n
        has_witness = knows_witness(state, actor, malicious, tick)
        claim_ready = (tick >= policy.ready_at and has_witness and state.owner[incoming] < 0
                       and state.published[incoming] < 0)
        if actor not in malicious and not policy.resume_claim_after_recovery:
            claim_ready &= tick < policy.recovery[actor]
        if actor == 0 and actor not in malicious:
            # An honest initiator never starts near the final recovery cutoff.
            claim_ready &= tick + policy.inclusion[incoming] < policy.recovery[incoming]
        recovery_at = (policy.recovery if actor in malicious
                       else policy.honest_recovery or policy.recovery)[actor]
        refund_ready = (tick >= recovery_at
                        and tick >= (policy.funded_at or (0,) * n)[actor]
                        and state.owner[actor] < 0
                        and state.published[n + actor] < 0)
        target = optional if actor in malicious else required
        if claim_ready:
            target.append(incoming)
        if refund_ready:
            target.append(n + actor)

    for chosen in powerset(optional):
        selected = tuple(required) + chosen
        published = list(state.published)
        witness_at = list(state.witness_at)
        events = []
        for action in selected:
            published[action] = tick
            claim = action < n
            asset = action % n
            actor = (asset + 1) % n if claim else asset
            events.append(f"t={tick} actor={actor} publishes {'claim' if claim else 'refund'} {policy.assets[asset]}")
            if claim and witness_at[asset] < 0:
                witness_at[asset] = tick + (0 if asset in malicious else policy.observation)
        next_state = replace(state, published=tuple(published), witness_at=tuple(witness_at))
        # A malicious observer may see a newly published witness immediately.
        # Honest participants conservatively use the full observation bound.
        extra = []
        for actor in malicious:
            incoming = (actor - 1) % n
            if (tick >= policy.ready_at and knows_witness(next_state, actor, malicious, tick)
                    and next_state.owner[incoming] < 0
                    and next_state.published[incoming] < 0):
                extra.append(incoming)
        for immediate in powerset(extra):
            more = list(next_state.published)
            more_witness = list(next_state.witness_at)
            extra_events = []
            for asset in immediate:
                more[asset] = tick
                if more_witness[asset] < 0:
                    more_witness[asset] = tick + (0 if asset in malicious else policy.observation)
                extra_events.append(f"t={tick} actor={(asset+1)%n} immediately publishes claim {policy.assets[asset]}")
            yield replace(next_state, published=tuple(more), witness_at=tuple(more_witness)), tuple(events + extra_events)


def inclusions(policy, state, malicious, tick):
    n = len(policy.assets)
    choices = []
    for asset in range(n):
        if state.owner[asset] >= 0 or tick < (policy.funded_at or (0,) * n)[asset]:
            choices.append((None,))
            continue
        candidates = [action for action in (asset, n + asset)
                      if state.published[action] >= 0]
        honest_due = any(
            ((asset + 1) % n if action < n else asset) not in malicious
            and tick - state.published[action] >= policy.inclusion[asset]
            for action in candidates
        )
        # A conflicting spend is allowed to beat an overdue honest submission.
        # This preserves a bounded resolution guarantee without assuming who wins.
        choices.append(tuple(candidates) if honest_due else (None, *candidates))
    for winners in product(*choices):
        owners = list(state.owner)
        published = list(state.published)
        events = []
        for asset, action in enumerate(winners):
            if action is None:
                continue
            claim = action < n
            owners[asset] = (asset + 1) % n if claim else asset
            # Spent inputs cannot be spent again. Drop irrelevant pending times.
            published[asset] = published[n + asset] = -1
            events.append(f"t={tick} final {'claim' if claim else 'refund'} {policy.assets[asset]} -> actor={owners[asset]}")
        witness_at = tuple(0 if 0 <= observed <= tick else observed
                           for observed in state.witness_at)
        yield State(tuple(owners), tuple(published), witness_at), tuple(events)


def harmed(state, malicious, at_end=False):
    n = len(state.owner)
    for actor in range(n):
        if actor in malicious:
            continue
        incoming = (actor - 1) % n
        own_lost = state.owner[actor] == (actor + 1) % n
        incoming_lost = state.owner[incoming] == incoming
        if own_lost and incoming_lost:
            return actor
        if at_end and state.owner[actor] != actor and state.owner[incoming] != actor:
            return actor
    return None


def explore(policy, malicious=frozenset(), state_limit=200_000):
    """Exhaust schedules in the finite domain or return an explicit attack.

    Refusing the state limit is an inconclusive run, never a successful check.
    No cryptographic or native-consensus property is asserted by this routine.
    """
    n = len(policy.assets)
    malicious = frozenset(malicious)
    if any(type(actor) is not int or not 0 <= actor < n for actor in malicious):
        raise ValueError("invalid adversarial actor")
    if type(state_limit) is not int or state_limit <= 0:
        raise ValueError("state limit must be positive")
    initial = State((-1,) * n, (-1,) * (2 * n))
    frontier = {initial: ()}
    explored = 0
    settled = 0
    allocations = set()
    horizon = max(max(policy.honest_recovery or policy.recovery), policy.ready_at) + max(policy.inclusion) + policy.observation + 2
    for tick in range(horizon + 1):
        following = {}
        for state, history in frontier.items():
            explored += 1
            if explored > state_limit:
                raise RuntimeError("inconclusive: finite exploration limit reached")
            for published, sent in publications(policy, state, malicious, tick):
                for after, mined in inclusions(policy, published, malicious, tick):
                    trace = history + sent + mined
                    loser = harmed(after, malicious, at_end=tick == horizon)
                    if loser is not None:
                        return Outcome(explored, settled, trace, loser,
                                       tuple(sorted(allocations)))
                    if all(owner >= 0 for owner in after.owner):
                        settled += 1
                        allocations.add(after.owner)
                    else:
                        following.setdefault(after, trace)
                        if tick == horizon:
                            allocations.add(after.owner)
        frontier = following
        if not frontier:
            break
    return Outcome(explored, settled, None, None, tuple(sorted(allocations)))


def main():
    reports = []
    for policy in (
        Policy(("DOM", "XMR"), (7, 3), (1, 1)),
    ):
        states = 0
        checked = 0
        for coalition in powerset(tuple(range(len(policy.assets)))):
            if len(coalition) == len(policy.assets):
                continue
            outcome = explore(policy, frozenset(coalition))
            if outcome.counterexample is not None:
                raise RuntimeError(f"candidate counterexample: {outcome}")
            states += outcome.explored_states
            checked += 1
        reports.append({"assets": policy.assets, "coalitions_checked": checked,
                        "states_explored": states, "counterexample_in_model": False})
    unsafe = Policy(("DOM", "XMR"), (6, 3), (1, 1))
    attack = explore(unsafe, frozenset((0,)))
    print(json.dumps({
        "scope": "finite post-preparation model only; not cryptography or mainnet",
        "swap_implemented": False,
        "latency_measured": False,
        "safe_margin_experiments": reports,
        "insufficient_margin_experiment": {
            "violations": unsafe.timing_violations(),
            "harmed_actor": attack.harmed_actor,
            "trace": attack.counterexample,
        },
    }, indent=2))


if __name__ == "__main__":
    main()
