//! DOM<->Solana condition-lock leg, both directions, against real chains.
//!
//! # What this crate is
//!
//! One leg of a settlement whose hub is always DOM. A BTC<->SOL settlement is
//! never a single transfer between two counterparty chains: it is BTC<->DOM
//! followed by DOM<->SOL, and this crate is only ever that second leg. The DOM
//! side is a jointly-owned reserve spent by a 2-of-2 adapted claim; the Solana
//! side is the escrow program in `programs/dom-solana-escrow`. The two are tied
//! together by one 252-bit scalar with a public face on each curve, proved equal
//! by the bound DLEQ under `ROLE_SOLANA_CONDITION_LOCK`.
//!
//! Both directions are the same two transactions in the opposite reveal order:
//!
//! | direction  | first claim            | reveals through                  | second claim |
//! |------------|------------------------|----------------------------------|--------------|
//! | SOL -> DOM | the DOM claim          | the kernel's excess signature    | the escrow   |
//! | DOM -> SOL | the escrow claim       | the instruction data and state   | the DOM claim|
//!
//! and the deadline that must be later is always the second claimant's. That is
//! the only asymmetry, and [`time_bounds`] refuses a schedule that gets it
//! wrong.
//!
//! # Modules
//!
//! * [`native_dom`], [`dom_joint`], [`dom_reserve`] — the DOM side, copied from
//!   the operator's DXP1 laboratory; see `NOTICE.md` for provenance and for the
//!   one edit applied.
//! * [`time_bounds`] — the two deadlines and the inequality between them.
//! * [`condition`] — the cross-curve condition and the only type that
//!   represents a checked opening of it.
//! * [`leg`] — the frozen terms, the escrow setup and the four escrow
//!   instructions, for either direction.
//! * [`cluster`] — signing, delivery and observation against a real cluster.
//!
//! # What it is not
//!
//! It is not the daemon. `dom-interopd` owns route state, redelivery, evidence
//! and recovery, and its Solana settlement face already exists; what it cannot
//! yet do is *plan* the DOM side of a non-Monero leg, because that path is
//! reached only through a fixture hard-coded to two Monero session bindings.
//! This crate supplies that DOM side directly so the leg can execute the real
//! operation now. It keeps no durable anti-rollback state and authenticates no
//! identity: a production route gets both from the daemon, not from here.

#![forbid(unsafe_code)]

pub mod cluster;
pub mod condition;
pub mod dom_joint;
pub mod dom_reserve;
pub mod leg;
pub mod native_dom;
pub mod time_bounds;
