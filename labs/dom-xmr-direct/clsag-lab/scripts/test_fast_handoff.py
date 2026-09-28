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
    "prepared_dom_reserve",
    "prepared_mature_xmr_reserve",
    "dom_claim_mempool_admitted_before_xmr_release",
    "xmr_release_committed_before_rpc",
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


def verify(result: dict) -> None:
    if result.get("outcome") != "fast-claim":
        raise RuntimeError("DXF1 did not execute its fast Claim path")
    if result.get("bitcoin_involved") is not False:
        raise RuntimeError("BTC appeared in the DOM-XMR leg")
    for field in REQUIRED_TRUE:
        if result.get(field) is not True:
            raise RuntimeError(f"missing DXF1 evidence: {field}")
    for field in ("dom_block_wait_in_active_interval", "xmr_block_wait_in_active_interval"):
        if result.get(field) is not False:
            raise RuntimeError(f"active handoff waited for a block: {field}")
    if result.get("bounded_dom_inclusion_assumption_blocks") != 3:
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=executable)
    parser.add_argument("--monerod", required=True, type=executable)
    parser.add_argument("--evidence-file", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()
    if not 180 <= args.timeout <= 300:
        parser.error("--timeout must be between 180 and 300 seconds")
    evidence = args.evidence_file.expanduser().resolve()
    evidence.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    started = time.monotonic()
    process = subprocess.Popen(
        [str(args.binary), str(args.monerod), "fast-claim"],
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
    verify(result)
    result["runner_wall_seconds"] = time.monotonic() - started
    document = {"schema": "DXF1-FAST-HANDOFF-V1", "status": "passed", "result": result}
    evidence.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    os.chmod(evidence, 0o600)
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
