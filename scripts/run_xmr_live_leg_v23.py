#!/usr/bin/env python3
"""Complementary live-daemon custody/startup evidence, with exact selection.

Reuse the existing isolated runner's pidfd/subreaper cleanup, bounded archives,
dependency fingerprints and one-test outcome checks. No duplicate cleanup or
less strict success parser is introduced. Economic terminal scenarios remain
in their existing independent workflow.
"""
import argparse
import os
import sys
import run_native_daemon_scenario_v23 as runner

GROUPS = {
    "startup": (
        "live_startup_v23::v23_dom_and_xmr_only_pair_starts_and_holds_with_no_foreign_family_resource",
        "live_startup_v23::v23_live_state_directory_refuses_a_second_owner_in_either_mode",
        "live_startup_v23::v23_stopped_state_directory_reopens_but_refuses_a_second_creation",
    ),
    "funding": (
        "live_funding_v23::v23_route_evidence_persists_across_a_clean_shutdown_and_reopen",
        "live_funding_v23::v23_route_evidence_survives_an_uncontrolled_crash_of_both_daemons",
    ),
    "refund": (
        "live_refund_v23::v23_second_actor_survives_and_restarts_with_the_first_unavailable",
        "live_refund_v23::v23_first_actor_survives_and_restarts_with_the_second_unavailable",
        "live_refund_v23::v23_survivor_reopens_repeatedly_with_a_permanently_absent_counterparty",
    ),
    "custody": (
        "live_custody_v23::v23_custody_stores_survive_repeated_uncontrolled_restarts_on_both_sides",
        "live_custody_v23::v23_corrupted_manifest_or_leg_authority_is_refused_and_the_original_is_not",
    ),
}
SCENARIOS = tuple(case for group in GROUPS.values() for case in group)


def configure():
    # Private Python process: only this runner instance gets the supplemental
    # names. The original script, economic allowlist and workflow are unchanged.
    runner.PREFIX = ("production_contracts_bootstrap::producer_v13::native_ceremony_tests::"
                     "xmr_coldstart_v23::live_route_v23::")
    runner.SCENARIOS = SCENARIOS


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--group", choices=(*GROUPS, "all"))
    selection.add_argument("--scenario", choices=SCENARIOS)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=9000)
    args = parser.parse_args()
    cases = ((args.scenario,) if args.scenario else
             SCENARIOS if args.group == "all" else GROUPS[args.group])
    configure()
    sys.argv = [sys.argv[0], "--evidence-dir", args.evidence_dir,
                "--timeout-seconds", str(args.timeout_seconds)]
    for case in cases:
        sys.argv.extend(("--scenario", case))
    return runner.main()


if __name__ == "__main__":
    raise SystemExit(main())
