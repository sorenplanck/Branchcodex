use std::ffi::{OsStr, OsString};
#[cfg(any(feature = "production", feature = "simulation"))]
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(feature = "production")]
const PRODUCTION_USAGE_V1: &str = "usage: dom-interopd self-check [--json]\n       dom-interopd run --state-dir PATH [--create]\n              the V3 secret stream is read from standard input, one pass, no trailing newline:\n              DOM-INTEROPD-SECRETS-V3\n<bearer token>\n<upstream Relay signing secret: 64 lowercase hex>\n<downstream Relay signing secret: 64 lowercase hex>\n<Contracts identity passphrase>\n<DOM wallet passphrase>\n<Bitcoin participant secret: 64 lowercase hex>\n<route-secret seal key: 64 lowercase hex>\n<refund-arming credential: 64 lowercase hex>\n<local EVM signing secret: 64 lowercase hex>\nupstream_f6_hsm_credentials=<count, then that many 64-hex lines>\ndownstream_f6_hsm_credentials=<count, then that many 64-hex lines>";

/// The universal V4 stream, which is what the V11 per-position bootstrap reads.
///
/// V3 stays byte-frozen above: it names one Bitcoin participant and one EVM
/// signer because that is the only pair its family can express. V4 names the
/// family of each position and then that family's own secrets, so any of the
/// sixteen ordered pairs can be expressed. Both headers are accepted on the same
/// stdin; the header selects the family, never a flag.
#[cfg(feature = "production")]
const PRODUCTION_USAGE_V4: &str = "       dom-interopd run --state-dir PATH [--create]\n              the universal V4 secret stream, one pass, no trailing newline:\n              DOM-INTEROPD-SECRETS-V4\n<bearer token>\n<upstream Relay signing secret: 64 lowercase hex>\n<downstream Relay signing secret: 64 lowercase hex>\n<Contracts identity passphrase>\n<DOM wallet passphrase>\n<route-secret seal key: 64 lowercase hex>\n<refund-arming credential: 64 lowercase hex>\nupstream_family=BTC|EVM|SOL|XMR\n<that family's secrets, 64 lowercase hex each: BTC one participant; EVM one signing; SOL seed then peer-auth; XMR local-store then sidecar-auth>\ndownstream_family=BTC|EVM|SOL|XMR\n<the downstream family's own secrets, same shape>\nupstream_f6_hsm_credentials=<count, then that many 64-hex lines>\ndownstream_f6_hsm_credentials=<count, then that many 64-hex lines>\n              every field above must differ from every other, including the\n              bearer token, both passphrases, the leg secrets and every HSM\n              credential; a repeat is refused as a reused key";

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    match arguments.as_slice() {
        [command] if command == OsStr::new("self-check") => print_self_check(),
        [command, format]
            if command == OsStr::new("self-check") && format == OsStr::new("--json") =>
        {
            print_self_check()
        }
        #[cfg(feature = "production")]
        [command, rest @ ..] if command == OsStr::new("run") => run_production(rest),
        #[cfg(feature = "production")]
        [command, rest @ ..] if command == OsStr::new("prepare-xmr-funding-v12") => {
            prepare_xmr_funding(rest)
        }
        #[cfg(feature = "production")]
        [command, rest @ ..] if command == OsStr::new("prepare-xmr-inventory-v23") => {
            prepare_xmr_inventory(rest)
        }
        #[cfg(feature = "production")]
        [command, rest @ ..] if command == OsStr::new("bootstrap-v13") => {
            prepare_bootstrap_v13(rest)
        }
        #[cfg(feature = "production")]
        [command, rest @ ..] if command == OsStr::new("prepare-route-services-v11") => {
            prepare_route_services(rest)
        }
        #[cfg(feature = "production")]
        [command, rest @ ..] if command == OsStr::new("prepare-f6-artifact-v23") => {
            prepare_f6_artifact(rest)
        }
        #[cfg(feature = "production")]
        [command, rest @ ..] if command == OsStr::new("prepare-planning-v23") => {
            prepare_planning(rest)
        }
        #[cfg(feature = "production")]
        [command, rest @ ..] if command == OsStr::new("prepare-xmr-leg-v23") => {
            prepare_xmr_leg(rest)
        }
        #[cfg(feature = "production")]
        [command, rest @ ..] if command == OsStr::new("prepare-xmr-enrollment-v23") => {
            prepare_xmr_enrollment(rest)
        }
        #[cfg(feature = "simulation")]
        [command, rest @ ..] if command == OsStr::new("simulate") => run_simulation(rest),
        _ => {
            print_usage();
            ExitCode::from(2)
        }
    }
}

#[cfg(feature = "production")]
fn prepare_planning(arguments: &[OsString]) -> ExitCode {
    use dom_interopd::{prepare_planning_command_v23, PREPARE_PLANNING_USAGE_V23};
    if matches!(arguments, [flag] if flag == OsStr::new("--help")) {
        println!("{PREPARE_PLANNING_USAGE_V23}");
        return ExitCode::SUCCESS;
    }
    let [input_flag, input, output_flag, output] = arguments else {
        eprintln!("{PREPARE_PLANNING_USAGE_V23}");
        return ExitCode::from(2);
    };
    if input_flag != OsStr::new("--input") || output_flag != OsStr::new("--output-dir") {
        eprintln!("{PREPARE_PLANNING_USAGE_V23}");
        return ExitCode::from(2);
    }
    match prepare_planning_command_v23(&PathBuf::from(input), &PathBuf::from(output)) {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!("planning report unavailable; preserve the output directory");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "production")]
fn prepare_f6_artifact(arguments: &[OsString]) -> ExitCode {
    use dom_interopd::{
        finalize_f6_artifact_command_v23, prepare_f6_artifact_command_v23,
        resume_f6_artifact_command_v23, PREPARE_F6_ARTIFACT_USAGE_V23,
    };
    if matches!(arguments, [flag] if flag == OsStr::new("--help")) {
        println!("{PREPARE_F6_ARTIFACT_USAGE_V23}");
        return ExitCode::SUCCESS;
    }
    let result = match arguments {
        [input_flag, input, output_flag, output]
            if input_flag == OsStr::new("--input") && output_flag == OsStr::new("--output-dir") =>
        {
            prepare_f6_artifact_command_v23(&PathBuf::from(input), &PathBuf::from(output))
        }
        [mode, request_flag, request]
            if mode == OsStr::new("--resume") && request_flag == OsStr::new("--request-dir") =>
        {
            resume_f6_artifact_command_v23(&PathBuf::from(request))
        }
        [mode, request_flag, request, signatures_flag, signatures]
            if mode == OsStr::new("--finalize")
                && request_flag == OsStr::new("--request-dir")
                && signatures_flag == OsStr::new("--signatures") =>
        {
            finalize_f6_artifact_command_v23(&PathBuf::from(request), &PathBuf::from(signatures))
        }
        _ => {
            eprintln!("{PREPARE_F6_ARTIFACT_USAGE_V23}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!("F6 artifact report unavailable; preserve the request directory");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "production")]
fn prepare_xmr_leg(arguments: &[OsString]) -> ExitCode {
    use dom_interopd::{
        prepare_xmr_leg_command_v23, ProductionRoutePositionV1, PREPARE_XMR_LEG_USAGE_V23,
    };
    if matches!(arguments, [flag] if flag == OsStr::new("--help")) {
        println!("{PREPARE_XMR_LEG_USAGE_V23}");
        return ExitCode::SUCCESS;
    }
    let [state_flag, state, position_flag, position, output_flag, output] = arguments else {
        eprintln!("{PREPARE_XMR_LEG_USAGE_V23}");
        return ExitCode::from(2);
    };
    let position = match position.to_str() {
        Some("upstream") => ProductionRoutePositionV1::Upstream,
        Some("downstream") => ProductionRoutePositionV1::Downstream,
        _ => {
            eprintln!("{PREPARE_XMR_LEG_USAGE_V23}");
            return ExitCode::from(2);
        }
    };
    if state_flag != OsStr::new("--state-dir")
        || position_flag != OsStr::new("--position")
        || output_flag != OsStr::new("--output-file")
    {
        eprintln!("{PREPARE_XMR_LEG_USAGE_V23}");
        return ExitCode::from(2);
    }
    match prepare_xmr_leg_command_v23(&PathBuf::from(state), position, &PathBuf::from(output)) {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!("XMR leg report unavailable; preserve the published bundle");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "production")]
fn prepare_xmr_enrollment(arguments: &[OsString]) -> ExitCode {
    use dom_interopd::{
        prepare_xmr_enrollment_command_v23, ProductionRoutePositionV1,
        PREPARE_XMR_ENROLLMENT_USAGE_V23,
    };
    if matches!(arguments, [flag] if flag == OsStr::new("--help")) {
        println!("{PREPARE_XMR_ENROLLMENT_USAGE_V23}");
        return ExitCode::SUCCESS;
    }
    let (arguments, reopen) = match arguments.split_last() {
        Some((last, rest)) if last == OsStr::new("--reopen") => (rest, true),
        _ => (arguments, false),
    };
    let [state_flag, state, position_flag, position, output_flag, output] = arguments else {
        eprintln!("{PREPARE_XMR_ENROLLMENT_USAGE_V23}");
        return ExitCode::from(2);
    };
    let position = if position == OsStr::new("upstream") {
        Some(ProductionRoutePositionV1::Upstream)
    } else if position == OsStr::new("downstream") {
        Some(ProductionRoutePositionV1::Downstream)
    } else {
        None
    };
    if state_flag != OsStr::new("--state-dir")
        || position_flag != OsStr::new("--position")
        || output_flag != OsStr::new("--output-dir")
        || position.is_none()
    {
        eprintln!("{PREPARE_XMR_ENROLLMENT_USAGE_V23}");
        return ExitCode::from(2);
    }
    let Some(position) = position else {
        return ExitCode::from(2);
    };
    match prepare_xmr_enrollment_command_v23(
        &PathBuf::from(state),
        position,
        &PathBuf::from(output),
        reopen,
    ) {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!("enrollment report unavailable; preserve custody");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "production")]
fn prepare_route_services(arguments: &[OsString]) -> ExitCode {
    use dom_interopd::{prepare_route_services_command_v11, PREPARE_ROUTE_SERVICES_USAGE_V11};
    if matches!(arguments, [flag] if flag == OsStr::new("--help")) {
        println!("{PREPARE_ROUTE_SERVICES_USAGE_V11}");
        return ExitCode::SUCCESS;
    }
    let [flag, state_dir] = arguments else {
        eprintln!("{PREPARE_ROUTE_SERVICES_USAGE_V11}");
        return ExitCode::from(2);
    };
    if flag != OsStr::new("--state-dir") || state_dir.is_empty() {
        eprintln!("{PREPARE_ROUTE_SERVICES_USAGE_V11}");
        return ExitCode::from(2);
    }
    match prepare_route_services_command_v11(&PathBuf::from(state_dir)) {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!("route services report unavailable; preserve the published document");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "production")]
fn prepare_bootstrap_v13(arguments: &[OsString]) -> ExitCode {
    const USAGE: &str = "usage: dom-interopd bootstrap-v13 --plan ABSOLUTE_JSON_PATH --work-dir ABSOLUTE_PRIVATE_DIRECTORY\nRead private credentials as one bounded JSON on non-terminal stdin. Exchange only the reported public packets; repeat to resume.";
    if arguments == [OsString::from("--help")] {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let [plan_flag, plan, work_flag, work] = arguments else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    if plan_flag != OsStr::new("--plan") || work_flag != OsStr::new("--work-dir") {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    match dom_interopd::bootstrap_command_v13(&PathBuf::from(plan), &PathBuf::from(work)) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!("bootstrap report encoding failed; preserve ceremony custody");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn print_self_check() -> ExitCode {
    match dom_interopd::self_check_json_v1() {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Prints the commands this binary accepts.
///
/// Under `production` there is now a `run` command. It does not yet drive a
/// route: it authenticates everything it can and then refuses, naming the
/// parts that have no production implementation. That is deliberate and the
/// refusal prints the list; see `production_run` for why a refusal is a result
/// and a loop on test doubles would not be.
fn print_usage() {
    #[cfg(feature = "production")]
    eprintln!("{PRODUCTION_USAGE_V1}");
    #[cfg(feature = "production")]
    eprintln!("{PRODUCTION_USAGE_V4}");
    #[cfg(feature = "production")]
    eprintln!("{}", dom_interopd::PREPARE_XMR_FUNDING_USAGE_V12);
    #[cfg(feature = "production")]
    eprintln!("{}", dom_interopd::PREPARE_XMR_INVENTORY_USAGE_V23);
    #[cfg(feature = "production")]
    eprintln!("{}", dom_interopd::PREPARE_ROUTE_SERVICES_USAGE_V11);
    #[cfg(feature = "production")]
    eprintln!("{}", dom_interopd::PREPARE_F6_ARTIFACT_USAGE_V23);
    #[cfg(feature = "production")]
    eprintln!("{}", dom_interopd::PREPARE_PLANNING_USAGE_V23);
    #[cfg(feature = "production")]
    eprintln!("{}", dom_interopd::PREPARE_XMR_ENROLLMENT_USAGE_V23);
    #[cfg(feature = "production")]
    eprintln!("{}", dom_interopd::PREPARE_XMR_LEG_USAGE_V23);
    #[cfg(feature = "simulation")]
    eprintln!(
        "usage: dom-interopd self-check [--json]\n       dom-interopd simulate --state-dir PATH --scenario claim|refund [--crash-after authority-persist|timer-event-commit]"
    );
    #[cfg(not(any(feature = "production", feature = "simulation")))]
    eprintln!("usage: dom-interopd self-check [--json]");
}

#[cfg(feature = "production")]
fn prepare_xmr_funding(arguments: &[OsString]) -> ExitCode {
    use dom_interopd::{prepare_xmr_funding_command_v12, PREPARE_XMR_FUNDING_USAGE_V12};
    if matches!(arguments, [flag] if flag == OsStr::new("--help")) {
        println!("{PREPARE_XMR_FUNDING_USAGE_V12}");
        return ExitCode::SUCCESS;
    }
    let [flag, path] = arguments else {
        eprintln!("{PREPARE_XMR_FUNDING_USAGE_V12}");
        return ExitCode::from(2);
    };
    if flag != OsStr::new("--output-dir") || path.is_empty() {
        eprintln!("{PREPARE_XMR_FUNDING_USAGE_V12}");
        return ExitCode::from(2);
    }
    match prepare_xmr_funding_command_v12(&PathBuf::from(path)) {
        Ok(report) => {
            match serde_json::to_string_pretty(&report) {
                Ok(json) => {
                    println!("{json}");
                    ExitCode::SUCCESS
                }
                Err(_) => {
                    eprintln!("funding report output failed; inspect the durably published output directory");
                    ExitCode::FAILURE
                }
            }
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "production")]
fn prepare_xmr_inventory(arguments: &[OsString]) -> ExitCode {
    use dom_interopd::{prepare_xmr_inventory_command_v23, PREPARE_XMR_INVENTORY_USAGE_V23};
    if matches!(arguments, [flag] if flag == OsStr::new("--help")) {
        println!("{PREPARE_XMR_INVENTORY_USAGE_V23}");
        return ExitCode::SUCCESS;
    }
    let [state_flag, state_dir, store_flag, secret_store] = arguments else {
        eprintln!("{PREPARE_XMR_INVENTORY_USAGE_V23}");
        return ExitCode::from(2);
    };
    if state_flag != OsStr::new("--state-dir")
        || store_flag != OsStr::new("--secret-store")
        || state_dir.is_empty()
        || secret_store.is_empty()
    {
        eprintln!("{PREPARE_XMR_INVENTORY_USAGE_V23}");
        return ExitCode::from(2);
    }
    match prepare_xmr_inventory_command_v23(&PathBuf::from(state_dir), &PathBuf::from(secret_store))
    {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!(
                    "XMR inventory report encoding failed; retained custody was not replaced"
                );
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(all(test, feature = "production"))]
mod production_usage_tests {
    use super::PRODUCTION_USAGE_V1;

    #[test]
    fn usage_pins_all_nine_secret_lines() {
        assert!(PRODUCTION_USAGE_V1.contains("DOM-INTEROPD-SECRETS-V3"));
        assert_eq!(PRODUCTION_USAGE_V1.matches('<').count(), 11);
        assert!(PRODUCTION_USAGE_V1.contains("upstream_f6_hsm_credentials="));
        assert!(PRODUCTION_USAGE_V1.contains("downstream_f6_hsm_credentials="));
        assert!(PRODUCTION_USAGE_V1.contains("upstream Relay signing secret"));
        assert!(PRODUCTION_USAGE_V1.contains("downstream Relay signing secret"));
        assert!(PRODUCTION_USAGE_V1.contains("DOM wallet passphrase"));
        assert!(PRODUCTION_USAGE_V1.contains("Bitcoin participant secret"));
        assert!(PRODUCTION_USAGE_V1.contains("refund-arming credential"));
        assert!(PRODUCTION_USAGE_V1.contains("local EVM signing secret"));
    }

    /// The V4 text must list the fields in the order `parse` reads them.
    ///
    /// A stream documented out of order is worse than one not documented: the
    /// operator builds it once, on a machine that holds real keys, and the
    /// parser reports only "shape", never which line was wrong.
    #[test]
    fn universal_usage_lists_the_v4_fields_in_parse_order() {
        let text = super::PRODUCTION_USAGE_V4;
        let at = |needle: &str| text.find(needle).unwrap_or_else(|| panic!("{needle}"));
        let ordered = [
            "DOM-INTEROPD-SECRETS-V4",
            "<bearer token>",
            "upstream Relay signing secret",
            "downstream Relay signing secret",
            "Contracts identity passphrase",
            "DOM wallet passphrase",
            "route-secret seal key",
            "refund-arming credential",
            "upstream_family=",
            "downstream_family=",
            "upstream_f6_hsm_credentials=",
            "downstream_f6_hsm_credentials=",
        ];
        for pair in ordered.windows(2) {
            assert!(at(pair[0]) < at(pair[1]), "{} before {}", pair[0], pair[1]);
        }
        // Every family the parser admits, and no Bitcoin/EVM field promoted
        // out of its position: V4 names families, V3 named two chains.
        for family in ["BTC", "EVM", "SOL", "XMR"] {
            assert!(text.contains(family), "{family}");
        }
        assert!(!text.contains("local EVM signing secret"));
        assert!(!text.contains("Bitcoin participant secret"));
        // The reuse refusal is the one rule an operator cannot infer.
        assert!(text.contains("reused key"));
    }
}

/// Parses `run` and hands off to the composition root.
///
/// The fail-closed limits of this build are printed one per line at startup,
/// from `PRODUCTION_KNOWN_LIMITS_V1`, so an operator knows which paths refuse
/// by policy before the route is driven.
#[cfg(feature = "production")]
fn run_production(arguments: &[OsString]) -> ExitCode {
    use dom_interopd::{
        require_operational_artifact_v1, run_production_v1, ProductionRunModeV1,
        ProductionRunOptionsV1, PRODUCTION_KNOWN_LIMITS_V1,
    };

    // Refuse a debug-profile or otherwise incomplete artifact before parsing
    // a state path, reading the nine secrets, opening a store or reaching a
    // network boundary. Merely selecting the `production` Cargo feature does
    // not make an artifact operational.
    if let Err(error) = require_operational_artifact_v1() {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }

    let mut state_dir: Option<PathBuf> = None;
    let mut mode = ProductionRunModeV1::ReopenExisting;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        index += 1;
        if flag == OsStr::new("--create") {
            if mode == ProductionRunModeV1::Create {
                print_usage();
                return ExitCode::from(2);
            }
            mode = ProductionRunModeV1::Create;
            continue;
        }
        let Some(value) = arguments.get(index) else {
            print_usage();
            return ExitCode::from(2);
        };
        index += 1;
        if flag == OsStr::new("--state-dir") && state_dir.is_none() {
            let path = PathBuf::from(value);
            if path.as_os_str().is_empty() {
                print_usage();
                return ExitCode::from(2);
            }
            state_dir = Some(path);
        } else {
            print_usage();
            return ExitCode::from(2);
        }
    }
    let Some(state_dir) = state_dir else {
        print_usage();
        return ExitCode::from(2);
    };

    for limit in PRODUCTION_KNOWN_LIMITS_V1 {
        eprintln!("  known limit: {limit}");
    }
    match run_production_v1(&ProductionRunOptionsV1 { state_dir, mode }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "simulation")]
fn run_simulation(arguments: &[OsString]) -> ExitCode {
    use dom_interopd::{
        run_simulation_v1, SimulationCrashPointV1, SimulationOptionsV1, SimulationScenarioV1,
    };

    let mut state_dir: Option<PathBuf> = None;
    let mut scenario = None;
    let mut crash_after = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        index += 1;
        let Some(value) = arguments.get(index) else {
            print_usage();
            return ExitCode::from(2);
        };
        index += 1;
        if flag == OsStr::new("--state-dir") && state_dir.is_none() {
            let path = PathBuf::from(value);
            if path.as_os_str().is_empty() {
                print_usage();
                return ExitCode::from(2);
            }
            state_dir = Some(path);
        } else if flag == OsStr::new("--scenario") && scenario.is_none() {
            scenario = match value.to_str() {
                Some("claim") => Some(SimulationScenarioV1::Claim),
                Some("refund") => Some(SimulationScenarioV1::Refund),
                _ => {
                    print_usage();
                    return ExitCode::from(2);
                }
            };
        } else if flag == OsStr::new("--crash-after") && crash_after.is_none() {
            crash_after = match value.to_str() {
                Some("authority-persist") => Some(SimulationCrashPointV1::AfterAuthorityPersist),
                Some("timer-event-commit") => Some(SimulationCrashPointV1::AfterTimerEventCommit),
                _ => {
                    print_usage();
                    return ExitCode::from(2);
                }
            };
        } else {
            print_usage();
            return ExitCode::from(2);
        }
    }
    let (Some(state_dir), Some(scenario)) = (state_dir, scenario) else {
        print_usage();
        return ExitCode::from(2);
    };
    let options = SimulationOptionsV1 {
        state_dir,
        scenario,
        crash_after,
    };
    match run_simulation_v1(options) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!("simulation report encoding failed");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
