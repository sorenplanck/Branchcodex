#!/usr/bin/env python3
"""Run the three funded DXA1 outcomes concurrently and verify their evidence."""

from __future__ import annotations

import argparse
import json
import os
import signal
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


OUTCOMES = ("claim", "refund", "punish")
REQUIRED_TRUE = (
    "dom_node",
    "monerod",
    "recovery_offers_persisted_before_dom_funding",
    "claim_offer_persisted_after_xmr_ready",
    "durable_ordering_journal_complete",
    "dom_release_recorded_before_submit",
    "dom_finality_recorded_before_xmr_submit",
    "private_xmr_shares_held_by_separate_processes",
    "authenticated_noise_transport",
    "noise_peer_identity_pinned",
    "transport_session_bound",
    "wrong_role_operations_rejected",
    "unauthorized_dom_offer_rejected",
    "participant_restart_restored_bound_shares",
    "prepared_mature_reserve_required_for_three_minute_target",
)


def executable(path: str) -> Path:
    result = Path(path).expanduser().resolve(strict=True)
    mode = result.stat().st_mode
    if not stat.S_ISREG(mode) or not os.access(result, os.X_OK):
        raise argparse.ArgumentTypeError(f"not an executable file: {result}")
    return result


def evidence_directory(path: str) -> Path:
    result = Path(path).expanduser().resolve()
    result.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(result, 0o700)
    return result


def result_line(output: str) -> dict:
    for line in reversed(output.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("experiment") == "DXA1 DOM-XMR daemon end-to-end":
            return value
    raise ValueError("missing DXA1 JSON result")


def verify(outcome: str, result: dict) -> None:
    if result.get("outcome") != outcome:
        raise ValueError(f"wrong outcome: {result.get('outcome')!r}")
    if result.get("bitcoin_involved") is not False:
        raise ValueError("BTC appeared in the DOM-XMR leg")
    for field in REQUIRED_TRUE:
        if result.get(field) is not True:
            raise ValueError(f"missing required evidence: {field}")
    active = result.get("ready_to_complete_seconds")
    total = result.get("total_seconds")
    if not isinstance(active, (int, float)) or not 0 < active <= 180:
        raise ValueError(f"active settlement outside 180 seconds: {active!r}")
    if not isinstance(total, (int, float)) or not 0 < total <= 180:
        raise ValueError(f"whole isolated test outside 180 seconds: {total!r}")
    if result.get("xmr_default_lock_window_blocks") != 10:
        raise ValueError("unexpected XMR output lock window")
    if result.get("dom_min_confirmations") != 2:
        raise ValueError("unexpected DOM confirmation policy")
    dom_depth = result.get("dom_confirmation_depth")
    if type(dom_depth) is not int or dom_depth < result["dom_min_confirmations"]:
        raise ValueError("DOM settlement was not final before XMR submission")
    expected_role = "xmr_owner" if outcome == "refund" else "dom_owner"
    if result.get("xmr_recipient_role") != expected_role:
        raise ValueError("XMR was delivered to the wrong economic role")


def run_one(binary: Path, monerod: Path, outcome: str, root: Path, timeout: int) -> dict:
    started = time.monotonic()
    process = subprocess.Popen(
        [str(binary), str(monerod), outcome],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        output, _ = process.communicate()
        (root / f"{outcome}.log").write_text(output)
        raise RuntimeError(f"{outcome} exceeded {timeout} seconds")
    (root / f"{outcome}.log").write_text(output)
    if process.returncode != 0:
        raise RuntimeError(f"{outcome} exited {process.returncode}")
    result = result_line(output)
    verify(outcome, result)
    result["runner_wall_seconds"] = time.monotonic() - started
    (root / f"{outcome}.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=executable)
    parser.add_argument("--monerod", required=True, type=executable)
    parser.add_argument("--evidence-dir", required=True, type=evidence_directory)
    parser.add_argument("--case-timeout", type=int, default=180)
    args = parser.parse_args()
    if not 1 <= args.case_timeout <= 300:
        parser.error("--case-timeout must be between 1 and 300 seconds")

    started = time.monotonic()
    results: dict[str, dict] = {}
    errors: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=len(OUTCOMES)) as executor:
        futures = {
            executor.submit(
                run_one,
                args.binary,
                args.monerod,
                outcome,
                args.evidence_dir,
                args.case_timeout,
            ): outcome
            for outcome in OUTCOMES
        }
        for future in as_completed(futures):
            outcome = futures[future]
            try:
                results[outcome] = future.result()
            except Exception as error:  # report every independent outcome
                errors[outcome] = str(error)

    campaign = {
        "schema": "DXA1-ARBITER-MATRIX-V1",
        "status": "passed" if not errors and len(results) == len(OUTCOMES) else "failed",
        "wall_seconds": time.monotonic() - started,
        "results": {key: results[key] for key in sorted(results)},
        "errors": {key: errors[key] for key in sorted(errors)},
    }
    (args.evidence_dir / "campaign.json").write_text(
        json.dumps(campaign, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(campaign, sort_keys=True))
    return 0 if campaign["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
