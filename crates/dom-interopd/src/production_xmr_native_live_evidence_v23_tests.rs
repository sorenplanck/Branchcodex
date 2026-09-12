//! The leg's evidence read from the daemons' own durable Contracts custody.
//!
//! Everything else in these scenarios observes the leg from outside the
//! process: artifacts exist, processes survive, nothing shrinks. That is a
//! proxy. This module removes the proxy for the facts that actually gate a
//! controlled mainnet test — the F7 funding gate, the irreversible funding
//! authorization, the exposure of the adaptor secret, and the three signed
//! edges of the XMR recovery graph — by opening the exact Stores the stopped
//! daemons wrote and reading them.
//!
//! Three properties keep that honest. It runs only while the owning daemon is
//! stopped, because the Store takes a cooperative lock and a second live owner
//! must be refused rather than raced. It authenticates rather than parses: the
//! chain scope is derived from the node configuration's genesis, the budget
//! policy is the ratified production profile the daemon itself was opened
//! under, and every read goes through the Store's own authenticated accessor,
//! so a corrupted or foreign Store is refused instead of misread. And it adds
//! no authority: no signing session is bound, no gate is consumed, nothing is
//! issued. Opening does perform the Store's own authenticated recovery, which
//! is the same recovery the daemon would perform on its next reopen, and every
//! caller here reopens the daemon afterwards so that remains checked rather
//! than assumed.
use super::*;
use dom_adaptor::TrustedChainIdV1;
use dom_scriptless_store::{BudgetPolicyV1, ContractsSessionStoreV1, SessionPhaseV1};

/// What one position's Contracts custody actually holds after a run.
///
/// Every field is a fact the Store authenticated, not an inference from a file
/// name or a size. `None` means the Store answered that the object is absent,
/// which it distinguishes from a malformed or foreign one; a malformed one is
/// an error and never reaches this struct.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct XmrLegEvidenceV23 {
    /// Route position this evidence belongs to.
    pub(super) position: usize,
    /// Session revision, which only advances.
    pub(super) revision: u64,
    /// Current normative phase of the session.
    pub(super) phase: SessionPhaseV1,
    /// Some signing share left this process.
    pub(super) any_signing_share_sent: bool,
    /// Funding was irreversibly authorized.
    pub(super) funding_authorized: bool,
    /// The adaptor secret was observed.
    pub(super) adaptor_secret_exposed: bool,
    /// A retained native F7 funding gate exists for this session.
    pub(super) f7_gate_present: bool,
    /// Complete edges authenticated by historical Ready reconstruction, in
    /// cancel/refund-adaptor/compensation order. Partial rounds are not observed.
    pub(super) graph_edges_bound: [bool; 3],
    /// Ready reconstruction requires all six authenticated messages per edge;
    /// zero means no Ready evidence, not a count of a partial signing round.
    pub(super) graph_edge_messages: [usize; 3],
}

impl XmrLegEvidenceV23 {
    /// Every one of the three recovery edges is bound and complete.
    ///
    /// Historical Ready reconstruction checks all three complete six-message
    /// transcripts. It neither reissues a signing handle nor treats a partial
    /// graph as complete.
    pub(super) fn recovery_graph_complete(&self) -> bool {
        self.graph_edges_bound == [true; 3] && self.graph_edge_messages == [6; 3]
    }
}

/// Reads both positions' evidence from one stopped actor's state directory.
///
/// The caller must have stopped or crashed that actor first. If it is still
/// running, the Store's cooperative lock refuses this open, which surfaces as
/// an error rather than as a silently empty reading.
pub(super) fn read_leg_evidence_v23(state_dir: &Path) -> ColdStartResult<[XmrLegEvidenceV23; 2]> {
    use crate::production_config::ProductionPathRoleV1 as Role;

    // The trusted chain scope comes from the same authenticated node identity
    // the daemon was configured with, derived from its genesis rather than
    // copied from a field that could disagree with it.
    let node = crate::production_node::load_production_node_config_v1(state_dir)
        .map_err(|_| "the stopped actor has no readable DOM node configuration")?;
    let identity = node.expected_identity();
    identity.validate()?;
    let chain = TrustedChainIdV1::from_authenticated_genesis(
        identity.network_magic,
        &dom_core::Hash256::from_bytes(identity.genesis_hash),
    );
    if chain.as_bytes() != &identity.chain_id {
        return Err("the node configuration's chain id is not its own genesis".into());
    }

    // The ratified production budget policy the daemon itself opened under. A
    // laboratory profile is refused by the Store, not tolerated here.
    let policy = BudgetPolicyV1::from_bytes(&std::fs::read(
        state_dir.join("native-contracts-budget.bin"),
    )?)
    .map_err(|_| "the retained budget policy is not canonical")?;

    let capability = std::sync::Arc::new(cap_std::fs::Dir::from_std_file(std::fs::File::open(
        state_dir,
    )?));

    let mut evidence = Vec::with_capacity(2);
    for (position, (terms_role, contracts_role)) in [
        (Role::UpstreamTerms, Role::UpstreamContracts),
        (Role::DownstreamTerms, Role::DownstreamContracts),
    ]
    .into_iter()
    .enumerate()
    {
        let terms = SettlementTermsV1::decode(&std::fs::read(
            state_dir.join(super::live_funding_v23::path_role_file_v23(terms_role)),
        )?)?;
        terms.validate()?;
        if terms.dom_leg.chain_id.0 != identity.chain_id {
            return Err("a retained leg does not belong to this DOM chain".into());
        }
        let store = ContractsSessionStoreV1::open_production_with_trusted_chain_v23(
            std::sync::Arc::clone(&capability),
            &super::live_funding_v23::path_role_file_v23(contracts_role),
            policy.clone(),
            chain,
        )
        .map_err(|_| "the stopped actor's Contracts custody refused an authenticated open")?;
        evidence.push(read_position_evidence_v23(&store, position, chain, &terms)?);
        // Release the cooperative lock before the next position and before the
        // caller reopens the daemon.
        drop(store);
    }
    evidence
        .try_into()
        .map_err(|_| "two positions of leg evidence required".into())
}

fn read_position_evidence_v23(
    store: &ContractsSessionStoreV1,
    position: usize,
    chain: TrustedChainIdV1,
    terms: &SettlementTermsV1,
) -> ColdStartResult<XmrLegEvidenceV23> {
    let session = terms.session_id.0;
    let record = store
        .load_session(session)
        .map_err(|_| "the retained session could not be authenticated")?;
    if record.session_id() != session || record.terms_hash() != terms.terms_hash()? {
        return Err("the retained session belongs to different terms".into());
    }
    let irreversible = record.irreversible();

    // Absent is distinguished from malformed by the Store itself. A gate that
    // exists but fails its ancestry check is an error here, never a `false`.
    let f7_gate_present = store
        .retained_f7_funding_gate_v19(chain, session)
        .map_err(|_| "the retained F7 funding gate is present but not authentic")?
        .is_some();

    // Read completed historical custody, not a prefunding signing capability.
    // This accessor resolves the two derived ordinary sessions, authenticates
    // their original six-message rounds and the parent refund-adaptor round,
    // and reconstructs the complete Produced graph even after funding. Missing
    // Ready evidence remains absent; malformed history is never downgraded.
    let graph_ready = store
        .retained_xmr_graph_ready_for_activation_v23(chain, session)
        .map_err(|_| "the retained recovery graph is present but not authentic")?
        .is_some();
    let graph_edges_bound = [graph_ready; 3];
    let graph_edge_messages = if graph_ready { [6; 3] } else { [0; 3] };

    Ok(XmrLegEvidenceV23 {
        position,
        revision: record.revision(),
        phase: record.phase(),
        any_signing_share_sent: irreversible.any_signing_share_sent,
        funding_authorized: irreversible.funding_authorized,
        adaptor_secret_exposed: irreversible.adaptor_secret_exposed,
        f7_gate_present,
        graph_edges_bound,
        graph_edge_messages,
    })
}

/// Requires that the second reading did not lose anything the first one had.
///
/// Every field here is monotone by construction in the protocol: a revision
/// only advances, an irreversible flag never clears, a gate that exists is
/// never withdrawn, and an accepted signing message is never un-accepted. A
/// restart that regressed any of them would be a durability failure of exactly
/// the kind these scenarios exist to catch.
pub(super) fn require_evidence_never_regressed_v23(
    before: &[XmrLegEvidenceV23; 2],
    after: &[XmrLegEvidenceV23; 2],
) -> ColdStartResult<()> {
    for (old, new) in before.iter().zip(after) {
        if old.position != new.position {
            return Err("leg evidence readings are not comparable".into());
        }
        if new.revision < old.revision {
            return Err("a session revision regressed across the restart".into());
        }
        if (old.any_signing_share_sent && !new.any_signing_share_sent)
            || (old.funding_authorized && !new.funding_authorized)
            || (old.adaptor_secret_exposed && !new.adaptor_secret_exposed)
        {
            return Err("an irreversible session flag cleared across the restart".into());
        }
        if old.f7_gate_present && !new.f7_gate_present {
            return Err("a retained F7 funding gate disappeared across the restart".into());
        }
        for index in 0..3 {
            if old.graph_edges_bound[index] && !new.graph_edges_bound[index] {
                return Err("a recovery-graph edge lost its signing session".into());
            }
            if new.graph_edge_messages[index] < old.graph_edge_messages[index] {
                return Err("a recovery-graph edge lost accepted messages".into());
            }
        }
    }
    Ok(())
}

/// Requires that a session never reached a terminal failure phase.
///
/// `FailedClosed` is the protocol's own statement that the route cannot
/// continue. A scenario that ran to its budget and left a session there has not
/// produced evidence of a healthy leg, however intact its files are.
pub(super) fn require_no_failed_session_v23(
    evidence: &[XmrLegEvidenceV23; 2],
) -> ColdStartResult<()> {
    for leg in evidence {
        if leg.phase == SessionPhaseV1::FailedClosed {
            return Err("a route position ended in the terminal failed-closed phase".into());
        }
    }
    Ok(())
}

/// Requires that funding was irreversibly authorized under a retained F7 gate.
///
/// This is the item the controlled mainnet test actually turns on, and it is
/// deliberately two facts rather than one: the irreversible flag alone would
/// not say the authorization came from a native F7 gate, and a gate alone would
/// not say funding was authorized under it.
pub(super) fn require_f7_authorized_funding_v23(
    evidence: &[XmrLegEvidenceV23; 2],
) -> ColdStartResult<()> {
    for leg in evidence {
        if !leg.f7_gate_present {
            return Err("a route position holds no retained native F7 funding gate".into());
        }
        if !leg.funding_authorized {
            return Err("a route position never authorized funding".into());
        }
    }
    Ok(())
}

/// Requires all three recovery-graph edges to be signed on both positions.
///
/// Cancel, the U-adaptor refund and compensation are what a non-cooperative
/// recovery is executed from. A leg whose graph is incomplete has no recovery
/// to fall back on, whatever else it persisted.
pub(super) fn require_complete_recovery_graph_v23(
    evidence: &[XmrLegEvidenceV23; 2],
) -> ColdStartResult<()> {
    for leg in evidence {
        if !leg.recovery_graph_complete() {
            return Err("a route position has no complete three-edge recovery graph".into());
        }
    }
    Ok(())
}
