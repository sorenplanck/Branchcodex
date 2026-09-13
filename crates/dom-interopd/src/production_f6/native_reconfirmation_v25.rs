//! Public preparation for an explicitly versioned post-enrollment reconfirmation.
//!
//! This is NOT authenticated consent, a reserved quote, an F6 authority or a
//! funding grant. It neither verifies signatures nor observes inventory/time.
//! The eventual runtime must authenticate both participants' consent to this
//! exact record, the quote signature and real reservation/status evidence, and
//! the still-current negotiated time policy before releasing any authority.
//! Existing enrollment/bootstrap signatures MUST NOT substitute for that
//! consent. This module does not change the legacy intent == RFQ check.
//!
//! The old intention and the new content-addressed RFQ have separate fields.
//! The RFQ commits the complete ORIGINAL composition; neither original terms
//! nor their deadlines are rewritten to solve the legacy circular hash.

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use kaystra_core::{terms::SettlementTermsV1, types::TimelockSpec};
use rfq::{
    v2::{NativeClockKindV2, QuoteV2, RfqV2, SettlementPositionV2},
    LegDirectionV1, RfqModeV1,
};
use route_composer::ComposedBindingV2;
use route_transport::RouteWireContextV1;

const MAGIC: &[u8; 8] = b"DOMF6R25";
const VERSION: u16 = 25;
const DOMAIN: &[u8] = b"DOM-INTEROP/F6/NATIVE-RECONFIRMATION-PUBLIC-RECORD/V25\0";
const MAX_RECORD_BYTES: usize = 16_384;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum NativeReconfirmationRefusalV25 {
    InvalidInput,
    ScopeMismatch,
    EconomicsMismatch,
    DeadlineMismatch,
    Encoding,
}

type Result<T> = core::result::Result<T, NativeReconfirmationRefusalV25>;

/// Move-only PUBLIC proposal. Its presence, bytes and digest imply no consent.
/// No decoder or conversion can manufacture an authenticated capability.
pub(super) struct PreparedNativeReconfirmationRecordV25 {
    bytes: Vec<u8>,
    digest: [u8; 32],
}

impl PreparedNativeReconfirmationRecordV25 {
    /// Reconstructs a public proposal from a real frozen composition. Wire
    /// inputs are committed, not authenticated here; the consumer must match
    /// them against authenticated Relay/registry owners, not caller assertions.
    pub(super) fn prepare(
        composition: &ComposedBindingV2,
        wire: RouteWireContextV1,
        position: SettlementPositionV2,
        rfq: &RfqV2,
        quote: &QuoteV2,
    ) -> Result<Self> {
        let original = match position {
            SettlementPositionV2::Upstream => composition.upstream(),
            SettlementPositionV2::Downstream => composition.downstream(),
        };
        validate_public_economics(original, wire, position, rfq, quote)?;
        if rfq.route.composition_id != composition.binding_digest()
            || [
                composition.binding_digest(),
                composition.route_scope_digest(),
                composition.time_policy_digest(),
                composition.time_evidence_digest(),
                composition.time_proof_digest(),
            ]
            .contains(&[0; 32])
            || composition.evidence_sequence() == 0
        {
            return Err(NativeReconfirmationRefusalV25::ScopeMismatch);
        }
        let mut bytes = Vec::with_capacity(2048);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&wire.network_id);
        bytes.extend_from_slice(&wire.route_id);
        bytes.extend_from_slice(&wire.session_id);
        bytes.extend_from_slice(&wire.roster_snapshot);
        bytes.extend_from_slice(&wire.policy_version.to_be_bytes());
        bytes.push(match position {
            SettlementPositionV2::Upstream => 1,
            SettlementPositionV2::Downstream => 2,
        });
        bytes.extend_from_slice(&original.intent_hash.0);
        bytes.extend_from_slice(&rfq.rfq_id);
        bytes.extend_from_slice(&quote.quote_id);
        bytes.extend_from_slice(&quote.bond_reservation_id);
        for participant in original.roster {
            bytes.extend_from_slice(&participant.0);
        }
        for digest in [
            composition.binding_digest(),
            composition.route_scope_digest(),
            composition.time_policy_digest(),
            composition.time_evidence_digest(),
            composition.time_proof_digest(),
        ] {
            bytes.extend_from_slice(&digest);
        }
        bytes.extend_from_slice(&composition.evidence_sequence().to_be_bytes());
        // Complete ordered terms retain ALL original deadlines, mechanisms,
        // finality, availability/recovery requirements and metadata bytes.
        for terms in [composition.upstream(), composition.downstream()] {
            append_bounded(
                &mut bytes,
                &terms
                    .canonical_bytes()
                    .map_err(|_| NativeReconfirmationRefusalV25::Encoding)?,
            )?;
        }
        append_bounded(
            &mut bytes,
            &rfq.canonical_bytes()
                .map_err(|_| NativeReconfirmationRefusalV25::Encoding)?,
        )?;
        append_bounded(
            &mut bytes,
            &quote
                .canonical_bytes()
                .map_err(|_| NativeReconfirmationRefusalV25::Encoding)?,
        )?;
        let digest = public_record_digest(&bytes)?;
        Ok(Self { bytes, digest })
    }

    pub(super) fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

fn append_bounded(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let next = output
        .len()
        .checked_add(4)
        .and_then(|len| len.checked_add(value.len()))
        .ok_or(NativeReconfirmationRefusalV25::Encoding)?;
    if next > MAX_RECORD_BYTES {
        return Err(NativeReconfirmationRefusalV25::Encoding);
    }
    let len = u32::try_from(value.len()).map_err(|_| NativeReconfirmationRefusalV25::Encoding)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn public_record_digest(bytes: &[u8]) -> Result<[u8; 32]> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| NativeReconfirmationRefusalV25::Encoding)?;
    hasher.update(DOMAIN);
    hasher.update(bytes);
    let mut digest = [0; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| NativeReconfirmationRefusalV25::Encoding)?;
    Ok(digest)
}

/// Public consistency only. This helper is private so it cannot replace the
/// real-composition constructor at a caller boundary.
fn validate_public_economics(
    original: &SettlementTermsV1,
    wire: RouteWireContextV1,
    position: SettlementPositionV2,
    rfq: &RfqV2,
    quote: &QuoteV2,
) -> Result<()> {
    use NativeReconfirmationRefusalV25 as E;
    original.validate().map_err(|_| E::InvalidInput)?;
    rfq.validate().map_err(|_| E::InvalidInput)?;
    quote.validate().map_err(|_| E::InvalidInput)?;
    let mut roster = [rfq.initiator, quote.solver];
    roster.sort_by_key(|participant| participant.0);
    if [
        wire.network_id,
        wire.route_id,
        wire.session_id,
        wire.roster_snapshot,
    ]
    .contains(&[0; 32])
        || original.intent_hash.0 == [0; 32]
        || original.roster != roster
        || rfq.initiator == quote.solver
        || original.solver_id.0 != quote.solver.0
        || wire.session_id != original.session_id.0
        || rfq.session_id != wire.session_id
        || rfq.route.position != position
        || quote.rfq_id != rfq.rfq_id
        || quote.route != rfq.route
        || wire.policy_version != original.policy_version
        || rfq.policy_version != original.policy_version
        || quote.bond_policy_version != rfq.policy_version
        || original.assurance_policy_hash != Some(rfq.assurance_policy_ref.0)
        || rfq.negotiation_clock.chain_id != original.dom_leg.chain_id
    {
        return Err(E::ScopeMismatch);
    }
    let (dom_direction, counterparty_direction, dom_amount, counterparty_amount) = match position {
        SettlementPositionV2::Upstream => (
            LegDirectionV1::UserReceives,
            LegDirectionV1::UserGives,
            quote.net_output,
            quote.total_input,
        ),
        SettlementPositionV2::Downstream => (
            LegDirectionV1::UserGives,
            LegDirectionV1::UserReceives,
            quote.total_input,
            quote.net_output,
        ),
    };
    let dom = rfq
        .route
        .legs
        .iter()
        .find(|leg| leg.chain_id == original.dom_leg.chain_id);
    let counterparty = rfq
        .route
        .legs
        .iter()
        .find(|leg| leg.chain_id == original.counterparty_leg.chain_id);
    let protects_amounts = match rfq.mode {
        RfqModeV1::ExactIn {
            input_amount,
            minimum_output,
        } => input_amount == quote.total_input && quote.net_output >= minimum_output,
        RfqModeV1::ExactOut {
            exact_output,
            maximum_input,
        } => exact_output == quote.net_output && quote.total_input <= maximum_input,
    };
    if original.dom_leg.amount != dom_amount
        || original.counterparty_leg.amount != counterparty_amount
        || original.fee_limit != rfq.fee_limit
        || !protects_amounts
        || rfq
            .fee_limit
            .dom_max
            .checked_add(rfq.fee_limit.counterparty_max)
            .map_or(true, |maximum| quote.total_fee > maximum)
        || dom.map_or(true, |leg| {
            leg.asset != original.dom_leg.asset_id || leg.direction != dom_direction
        })
        || counterparty.map_or(true, |leg| {
            leg.asset != original.counterparty_leg.asset_id
                || leg.direction != counterparty_direction
        })
    {
        return Err(E::EconomicsMismatch);
    }
    // Only compare values on the identical DOM negotiation clock. The other
    // chain's deadline is retained verbatim and MUST be checked by the actual
    // authenticated cross-chain time authority, never converted here.
    let dom_deadline = match (rfq.negotiation_clock.kind, original.dom_leg.deadline) {
        (NativeClockKindV2::BlockHeight, TimelockSpec::BlockHeight { value }) => value,
        (NativeClockKindV2::TimestampSeconds, TimelockSpec::TimestampSeconds { value }) => value,
        _ => return Err(E::DeadlineMismatch),
    };
    if quote.execution_deadline.clock != rfq.negotiation_clock
        || quote.expiry.clock != rfq.negotiation_clock
        || quote.execution_deadline.value > dom_deadline
    {
        return Err(E::DeadlineMismatch);
    }
    Ok(())
}

#[cfg(test)]
#[path = "native_reconfirmation_v25_tests.rs"]
mod tests;
