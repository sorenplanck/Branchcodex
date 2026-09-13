//! The DOM+XMR leg's own evidence, produced by two real daemon processes.
//!
//! Everything below drives the actual release binary over a cold-started
//! two-party route whose only counterparty family is Monero. Nothing here mints
//! admission, substitutes a fixture for a missing companion, or treats a
//! process staying alive as proof that a route stage completed: each scenario
//! says in its own name exactly which property it observes.
//!
//! These scenarios are `#[ignore]`d because they need three things this
//! repository cannot provide for itself — the release-production binary and its
//! fingerprint, the offline funding helper, and the real GPL sidecar. Absence of
//! any of them is an explicit dependency failure, never a silent skip.
use super::*;
use route_executor::{ActionKindV1, LegIdV1};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
type Result<T> = ColdStartResult<T>;
use super::daemon_scenario_v23::{coordinator, observer};
#[path = "production_xmr_native_live_owner_v24_tests.rs"]
mod live_owner_v24;
use live_owner_v24::NativeXmrLivePairV23;
use xmr_graph_wallet_tests::native_observation_v23::Configuration;

#[path = "production_xmr_native_live_custody_v23_tests.rs"]
mod live_custody_v23;
#[path = "production_xmr_native_live_evidence_v23_tests.rs"]
mod live_evidence_v23;
#[path = "production_xmr_native_live_funding_v23_tests.rs"]
mod live_funding_v23;
#[path = "production_xmr_native_live_refund_v23_tests.rs"]
mod live_refund_v23;
#[path = "production_xmr_native_live_startup_v23_tests.rs"]
mod live_startup_v23;

/// Frozen offline funding fee cap, in piconero.
///
/// The same value bounds the negotiated `fee_limit.counterparty_max`, the
/// registry deployment's `max_fee_piconero` and the offline producer's own
/// ceiling, so a sweep that exceeded it could not be built, admitted or paid.
const LIVE_FEE_CAP_PICONERO_V23: u64 = 10_000;

/// How long a freshly launched pair must keep running before the scenario
/// accepts that its configuration and admission were not refused.
///
/// A refusal exits in well under a second; this budget is long enough that a
/// refusal cannot hide inside it, and short enough to stay a startup
/// observation rather than a claim about route progress.
const LIVE_STARTUP_BUDGET_V23: Duration = Duration::from_secs(30);

/// Upper bound, not a mandatory delay: return when both actors retain Funding.
const LIVE_ROUTE_BUDGET_V23: Duration = Duration::from_secs(7200);

/// Signed route-time limits anchored to the real clock.
///
/// The signed time producer observes a live DOM node and the local XMR quorum
/// and then verifies its own policy/evidence through the same durable ladder
/// admission uses, so the validity window has to bracket the actual present.
/// The policy matches the existing real-daemon local negotiation; no production
/// default or already-signed availability object is changed.
fn live_limits_v23() -> ColdStartResult<route_time_anchor::RouteTimePolicyLimitsV2> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok(route_time_anchor::RouteTimePolicyLimitsV2 {
        valid_from_seconds: now.checked_sub(60).ok_or("host clock before epoch")?,
        expires_at_seconds: now.checked_add(21600).ok_or("route validity overflow")?,
        max_evidence_age_seconds: 21600,
        max_anchor_interval_width_seconds: 600,
        max_anchor_time_skew_seconds: 1800,
        max_future_skew_seconds: 600,
        max_upstream_funding_anchor_delay_seconds: 14400,
        max_downstream_funding_anchor_delay_seconds: 14400,
        hub_margin_seconds: 300,
        // The signed policy refuses any counterparty margin below the additive
        // floor of the selected Monero registry profile: both checkpoints carry
        // its 1080 s reorg plus 5 s observation and 5 s broadcast budgets, so
        // the floor is 2180 s. 300 s is only enough for the DOM hub rung.
        counterparty_margin_seconds: 2_400,
    })
}

/// Cold-starts a two-party DOM+XMR route and launches both real daemons.
///
/// The order is the order the artifacts depend on each other: the ceremony and
/// enrollment first, then the local helper processes, then the two Relay
/// endpoints, then the two authenticated exports, and only then the binary.
/// Reserving the endpoints before the export is what lets the manifest name
/// them; the daemons themselves open the sockets.
fn start_live_pair_v23(
    binary: &crate::production_xmr_native_binary_v23_tests::NativeDaemonBinaryV23,
) -> ColdStartResult<NativeXmrLivePairV23> {
    let configuration = Configuration::require()?;
    let limits = live_limits_v23()?;
    let startup = NativeMainnetStartupV23::prepare_live_bounded_v24(
        &configuration,
        limits,
        LIVE_FEE_CAP_PICONERO_V23,
    )?;
    let plan = startup.planning(0)?;
    let confirmations = plan
        .composition()
        .upstream()
        .counterparty_leg
        .finality
        .min_confirmations
        .max(
            plan.composition()
                .downstream()
                .counterparty_leg
                .finality
                .min_confirmations,
        );
    if confirmations == 0 || confirmations > 64 {
        return Err("live XMR finality bound".into());
    }
    let first = std::net::TcpListener::bind("127.0.0.1:0")?;
    let second = std::net::TcpListener::bind("127.0.0.1:0")?;
    let endpoints = [first.local_addr()?, second.local_addr()?];
    drop((first, second));
    let running = startup.export_and_launch_shared_peer_v23(binary, endpoints, 1)?;
    Ok(NativeXmrLivePairV23 {
        running: Some(running),
        confirmations,
        last_pump: None,
    })
}

/// Requires that this state directory selects Monero for both positions and
/// carries no EVM, Bitcoin or Solana resource at all.
///
/// Two independent documents have to agree: the selected-services document the
/// runtime reads for endpoints, and the universal manifest that names each
/// position's family and its own actuator database. A directory that satisfied
/// one while quietly carrying the other family's state would be refused here.
fn require_xmr_only_state_dir_v23(state_dir: &Path) -> ColdStartResult<()> {
    use crate::production_config::{
        ProductionBootstrapConfigV1, ProductionBootstrapModeV1, ProductionChainFamilyV11,
        PRODUCTION_CREATE_CONFIG_FILE_V11, PRODUCTION_REOPEN_CONFIG_FILE_V11,
    };
    use crate::production_route_services::{RouteServicesV8, ServiceV8, FILE_V8};

    let services = RouteServicesV8::decode(&std::fs::read(state_dir.join(FILE_V8))?)?;
    for leg in services.legs {
        match leg.service {
            ServiceV8::Monero { endpoints, quorum } => {
                if endpoints.is_empty() || quorum == 0 || usize::from(quorum) > endpoints.len() {
                    return Err("selected Monero service has no usable quorum".into());
                }
                for endpoint in endpoints {
                    if !endpoint.starts_with("http://127.0.0.1:")
                        && !endpoint.starts_with("http://[::1]:")
                    {
                        return Err("selected Monero endpoint is not local".into());
                    }
                }
            }
            _ => return Err("a non-Monero counterparty service is selected".into()),
        }
    }
    for (name, mode) in [
        (
            PRODUCTION_CREATE_CONFIG_FILE_V11,
            ProductionBootstrapModeV1::Create,
        ),
        (
            PRODUCTION_REOPEN_CONFIG_FILE_V11,
            ProductionBootstrapModeV1::ReopenExisting,
        ),
    ] {
        let config = ProductionBootstrapConfigV1::decode_canonical_v11_for_mode(
            &std::fs::read(state_dir.join(name))?,
            mode,
        )?;
        let fields = config
            .universal_v11()
            .ok_or("a DOM+XMR manifest must be the universal family")?;
        for leg in &fields.legs {
            if leg.family != ProductionChainFamilyV11::Xmr {
                return Err("a route position selects a non-XMR family".into());
            }
        }
        if !fields.shared_relay_peer_v23 {
            return Err("a two-party route must declare its shared counterparty".into());
        }
    }
    // No EVM, Bitcoin or Solana durable state may exist under this directory,
    // whatever the manifests say. The name fragments are the ones the
    // family-specific openers use for their own databases and credentials.
    for entry in std::fs::read_dir(state_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("state directory entry encoding")?;
        for forbidden in ["evm", "bitcoin", "btc", "solana", "sol-"] {
            if name.to_ascii_lowercase().contains(forbidden) {
                return Err("a foreign-family resource exists in an XMR-only route".into());
            }
        }
    }
    Ok(())
}

/// Requires that a named durable artifact exists as an owner-only regular file
/// with content, or as an owner-only directory.
fn require_durable_artifact_v23(path: &Path, directory: bool) -> ColdStartResult<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err("durable artifact is not an owner-only original".into());
    }
    if directory {
        if !metadata.is_dir() {
            return Err("durable custody artifact is not a directory".into());
        }
    } else if !metadata.is_file() || metadata.len() == 0 {
        return Err("durable artifact is absent or empty".into());
    }
    Ok(())
}

/// Reads one public artifact, so a scenario can restore it byte for byte after
/// deliberately corrupting it.
fn read_public_artifact_v23(path: &Path) -> ColdStartResult<Vec<u8>> {
    require_durable_artifact_v23(path, false)?;
    Ok(std::fs::read(path)?)
}

/// Overwrites one public artifact in place, preserving its owner-only mode.
///
/// Used only to corrupt and then restore an artifact the daemon has already
/// accepted; it never creates a new document and never widens permissions.
fn overwrite_public_artifact_v23(path: &Path, bytes: &[u8]) -> ColdStartResult<()> {
    use std::io::Write as _;
    require_durable_artifact_v23(path, false)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if std::fs::read(path)? != bytes {
        return Err("public artifact did not persist exactly".into());
    }
    Ok(())
}
