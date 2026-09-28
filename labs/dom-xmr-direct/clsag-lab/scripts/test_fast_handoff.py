#!/usr/bin/env python3
"""Run and verify the funded DXF1 fast handoff through both native daemons."""

from __future__ import annotations

import argparse
import json
import os
import signal
import stat
import subprocess
import time
from pathlib import Path


REQUIRED_TRUE = (
    "dom_node",
    "monerod",
    "dxf1_protocol_authority",
    "prepared_dom_reserve",
    "prepared_mature_xmr_reserve",
    "dom_claim_mempool_admitted_before_xmr_release",
    "dom_daemon_observation_enforced_by_authority",
    "xmr_release_committed_before_rpc",
    "xmr_exact_transaction_persisted_before_rpc",
    "xmr_daemon_submission_enforced_by_authority",
    "xmr_daemon_absolute_submission_deadline",
    "durable_absolute_active_deadline",
    "durable_restart_before_xmr_signing",
    "refund_permanently_forbidden_after_xmr_commitment",
    "dom_claim_eventually_included",
    "dom_claim_eventually_finalized",
    "xmr_payment_eventually_included",
)


def executable(value: str) -> Path:
    path = Path(value).expanduser().resolve(strict=True)
    if not stat.S_ISREG(path.stat().st_mode) or not os.access(path, os.X_OK):
        raise argparse.ArgumentTypeError(f"not an executable file: {path}")
    return path


def result_line(output: str) -> dict:
    for line in reversed(output.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("experiment") == (
            "DXF1 prepared DOM-XMR fast handoff"
        ):
            return value
    raise RuntimeError("missing DXF1 result record")


def verify(result: dict, outcome: str) -> None:
    if result.get("outcome") != outcome:
        raise RuntimeError(f"DXF1 did not execute {outcome}")
    if result.get("bitcoin_involved") is not False:
        raise RuntimeError("BTC appeared in the DOM-XMR leg")
    for field in REQUIRED_TRUE:
        if result.get(field) is not True:
            raise RuntimeError(f"missing DXF1 evidence: {field}")
    for field in ("dom_block_wait_in_active_interval", "xmr_block_wait_in_active_interval"):
        if result.get(field) is not False:
            raise RuntimeError(f"active handoff waited for a block: {field}")
    if result.get("bounded_dom_inclusion_assumption_blocks") != 57:
        raise RuntimeError("unexpected DXF1 inclusion assumption")
    if result.get("minimum_dom_claim_confirmations_before_refund") != 6:
        raise RuntimeError("unexpected DXF1 recovery finality depth")
    if result.get("active_deadline_seconds") != 180:
        raise RuntimeError("unexpected DXF1 active deadline")
    active = result.get("active_handoff_seconds")
    if not isinstance(active, (int, float)) or not 0 < active <= 180:
        raise RuntimeError(f"DXF1 active handoff exceeded 180 seconds: {active!r}")
    latest = result.get("latest_assumed_dom_claim_height")
    if type(latest) is not int or latest <= 0:
        raise RuntimeError("missing bounded DOM Claim height")
    required_finality = result.get("required_dom_finality_height")
    if type(required_finality) is not int or required_finality <= latest:
        raise RuntimeError("missing DOM finality margin before Refund")
    reorg = outcome == "fast-reorg"
    if result.get("xmr_ambiguous_response_recovered_after_restart") is not reorg:
        raise RuntimeError("incorrect DXF1 ambiguous XMR recovery evidence")
    for field in (
        "dom_claim_reorg_exercised",
        "dom_claim_rebroadcast_after_xmr_commitment",
        "refund_forbidden_after_reorg",
    ):
        if result.get(field) is not reorg:
            raise RuntimeError(f"incorrect DXF1 reorg evidence: {field}")
    canonical = result.get("dom_claim_canonical_block")
    finality = result.get("dom_claim_finality_tip_block")
    for field, value in (
        ("dom_claim_canonical_block", canonical),
        ("dom_claim_finality_tip_block", finality),
    ):
        if (
            not isinstance(value, str)
            or len(value) != 64
            or value == "0" * 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise RuntimeError(f"invalid canonical DOM block evidence: {field}")
    if canonical == finality:
        raise RuntimeError("DOM finality tip did not advance beyond Claim inclusion")
    orphaned = result.get("dom_claim_orphaned_block")
    if reorg:
        if (
            not isinstance(orphaned, str)
            or len(orphaned) != 64
            or orphaned == "0" * 64
            or orphaned == canonical
        ):
            raise RuntimeError("invalid orphaned DOM Claim block evidence")
    elif orphaned is not None:
        raise RuntimeError("normal DXF1 path unexpectedly reported an orphaned block")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=executable)
    parser.add_argument("--monerod", required=True, type=executable)
    parser.add_argument(
        "--outcome", choices=("fast-claim", "fast-reorg"), default="fast-claim"
    )
    parser.add_argument("--evidence-file", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()
    if not 180 <= args.timeout <= 300:
        parser.error("--timeout must be between 180 and 300 seconds")
    evidence = args.evidence_file.expanduser().resolve()
    evidence.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    started = time.monotonic()
    process = subprocess.Popen(
        [str(args.binary), str(args.monerod), args.outcome],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        output, _ = process.communicate()
        raise RuntimeError(f"DXF1 fixture exceeded {args.timeout} seconds:\n{output}")
    if process.returncode != 0:
        raise RuntimeError(f"DXF1 exited {process.returncode}:\n{output}")
    result = result_line(output)
    verify(result, args.outcome)
    result["runner_wall_seconds"] = time.monotonic() - started
    document = {"schema": "DXF1-FAST-HANDOFF-V1", "status": "passed", "result": result}
    evidence.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    os.chmod(evidence, 0o600)
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
