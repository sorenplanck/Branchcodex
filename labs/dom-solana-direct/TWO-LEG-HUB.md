# DOM is a hop, not a route: what that means for the Solana leg

Written 2026-09-27. Rewritten the same day, because the first version described the
wrong architecture. That correction is the most useful thing in this file, so it
comes first.

## 0. The correction

The first version of this document assumed a **composed route**: one operation
moving an asset from chain A to chain B through DOM, with the two legs
cryptographically joined so the whole thing settles atomically. It then went
looking for how the two legs should be joined, found `DR-PRIV-001` and its secret
leg offset, and listed what this leg would have to accept in order to participate.

That is not the objective. The objective, as stated by the operator:

> An operation starts on Solana and sends to DOM. DOM takes that operation and
> distributes: if it is going to Bitcoin, to the Bitcoin leg; if to Monero, to
> Monero; if to EVM, to EVM. It passes through DOM because the passage through DOM
> is where privacy is mitigated. It is **not one operation**. An asset leaving
> Solana, passing through DOM and arriving at Bitcoin is **two operations,
> independent**: one Solana → DOM, and another DOM → the destination.

And, said again more sharply afterwards:

> I said DOM to Solana and DOM to Bitcoin. That is why your job is to integrate
> with the DOM daemon. It is to integrate with DOM. Solana↔DOM. That is why it has
> to be with DOM. Then the DOM centre is what distributes.

So there is no route object joining two legs, and nothing for a leg offset to
relate. Every consequence the first version drew from the composed-route premise
was answering a question nobody asked.

Two things follow, and they set the scope of this leg. **One:** the leg's
counterparty is DOM and nothing else. It never needs to know which chain an asset
goes to next, because that is a separate operation. **Two:** the distribution --
which destination a received asset goes out to -- belongs to the DOM centre, not to
any leg. A leg that tried to reason about the destination would be taking work away
from the place that is supposed to decide it, and would re-link the two operations
in the process.

## 1. What this leg already is

Exactly one of those independent operations, and it needs no change to be one.
Checked rather than assumed: this laboratory contains no reference to `upstream`,
`downstream`, a composed binding, `route_composer` or an offset relation. Each
settlement carries its own `settlement_id`, its own session and intent, its own
freshly generated condition, its own pair of deadlines, and its own evidence.

Two operations run back to back through it share nothing: not a witness, not a
deadline, not an escrow, not a DOM reserve. That is the property the objective
wants, and it is the property the leg has — by construction rather than by effort.

The three "points of contact" the first version listed — take a witness instead of
minting one, verify an offset relation, take deadlines from a route policy — are
requirements of the composed-route design. Under the stated objective they are
**not** needed, and adding them would couple two things the design wants apart.

## 2. Where the privacy actually comes from, and what can quietly destroy it

This is the part worth writing down, because under this model the privacy is not a
cryptographic property of the leg. The leg contributes only one thing: two
operations are independent, so nothing in either operation's public bytes names the
other. That is necessary and nowhere near sufficient. What remains is correlation,
and correlation does not care that the cryptography is separate.

**The DOM output is the sharpest edge.** Operation 1 pays a DOM output to the user.
If operation 2 funds its reserve by spending *that same output*, the DOM chain
itself links the two operations in plain sight, and the hop bought nothing. This is
not hypothetical bookkeeping: this leg's DOM claim pays a specific commitment, and
the next operation's reserve is funded from some commitment. Whether they are the
same one is a decision made outside this leg, and it is the decision the whole
privacy argument rests on.

**Amounts.** One SOL in and the equivalent out, with nothing else moving nearby,
correlates the two operations whatever the cryptography does. The privacy budget is
whatever else is happening on the DOM chain in that window at comparable value.

**Timing.** The user holds DOM between the two operations. That holding period is
the budget. Two operations seconds apart are two halves of one observable event.

**Counterparties.** If the same party serves both operations, it knows both sides
regardless of what any chain observer can see. Off-chain metadata does the same:
this leg's terms carry a `solver_id` and a roster, and two operations sharing them
are linked for anyone holding both sets of terms — off chain, but linked.

None of these are defects in the leg, and none can be fixed inside it. They are the
reason the hop exists, and they are where it can silently fail.

## 3. The price of independence, stated plainly

Two independent operations are not atomic. Between them the user holds DOM. If the
second operation never happens — no counterparty, a price move, a refund — the user
holds DOM rather than the asset they wanted. A composed route would have made that
impossible and would have made the two legs linkable; this design chose the
opposite trade. It is a choice, not an oversight, and it is worth being explicit
that the refund paths this leg proves protect *one* operation. Nothing protects a
user who completed the first and could not start the second.

## 4. What `DR-PRIV-001` is, and why it is not this

`docs/specifications/design/DR-PRIV-001-leg-unlinkability-blinding-and-a2lplus.en.md`
exists in this tree and is implemented in part (`route-composer::leg_blinding`,
`ComposedBindingV3`). It solves the composed-route problem: when two legs *are* one
route and therefore carry one witness, Level 1 gives each leg its own witness joined
by a secret offset `δ` with `D = δ·G` and a Schnorr proof under DLEQ role 4, so an
observer of both chains cannot link them; Level 2 blinds the solver itself, A²L+
shape, restricted in its first version to routes whose two counterparty locks share
a curve.

It is a real answer to a real problem, and it is a different problem. Under the
stated objective the legs are already unlinked because they are not one route. Which
of the two architectures DXP1 keeps is the operator's decision; this document only
records that the leg satisfies the stated one today and would need §1's three
additions for the other.

## 5. What this document is not

It is not a plan to change code. The DOM-side modules this laboratory copied are
being edited in another working tree, and the merge stays with the operator. The
first version of this file also claimed that a Bitcoin leg carries
`LockMechanism::SchnorrAdaptor`; no BTC crate in this tree references that byte, the
claim was not supported, and it is gone. What those crates do say is that the
Bitcoin side is a Taproot contract with a MuSig2 2-of-2 adaptor.
