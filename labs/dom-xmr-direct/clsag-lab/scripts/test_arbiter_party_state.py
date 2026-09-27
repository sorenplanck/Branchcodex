#!/usr/bin/env python3
"""Exercise DXA1 participant-state locking, restart, binding, and corruption checks."""

from __future__ import annotations

import argparse
import json
import os
import select
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path


SETTLEMENT = "72" * 32
CONTEXT = "73" * 32
CHAIN = "61" * 32


def executable(path: str) -> Path:
    result = Path(path).expanduser().resolve(strict=True)
    if not stat.S_ISREG(result.stat().st_mode) or not os.access(result, os.X_OK):
        raise argparse.ArgumentTypeError(f"not an executable file: {result}")
    return result


def start(binary: Path, role: str, state: Path) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [str(binary), role, SETTLEMENT, CONTEXT, CHAIN, str(state)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )


def ready(process: subprocess.Popen[str], timeout: float = 10) -> dict:
    assert process.stdout is not None
    readable, _, _ = select.select([process.stdout], [], [], timeout)
    if not readable:
        process.kill()
        output, error = process.communicate()
        raise RuntimeError(f"party did not become ready: {output!r} {error!r}")
    line = process.stdout.readline()
    if not line:
        _, error = process.communicate(timeout=2)
        raise RuntimeError(f"party exited before ready: {error!r}")
    result = json.loads(line)
    if result.get("ok") is not True:
        raise RuntimeError(f"party returned invalid ready record: {result!r}")
    return result


def stop(process: subprocess.Popen[str]) -> None:
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def must_fail(process: subprocess.Popen[str], reason: str) -> None:
    try:
        output, error = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise RuntimeError(f"{reason} did not fail closed")
    if process.returncode == 0:
        raise RuntimeError(f"{reason} unexpectedly succeeded: {output!r} {error!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=executable)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="dxa1-party-state-") as directory:
        root = Path(directory)
        state = root / "dom-owner.state"

        first = start(args.binary, "dom-owner", state)
        first_ready = ready(first)
        if first_ready.get("restored") is not False:
            raise RuntimeError("new state was reported as restored")
        if stat.S_IMODE(state.stat().st_mode) != 0o600:
            raise RuntimeError("participant state is not mode 0600")

        must_fail(start(args.binary, "dom-owner", state), "concurrent state owner")
        stop(first)

        restarted = start(args.binary, "dom-owner", state)
        restarted_ready = ready(restarted)
        if restarted_ready.get("restored") is not True:
            raise RuntimeError("existing state was not restored")
        if (
            restarted_ready["proof"]["bundle"]["claim"]
            != first_ready["proof"]["bundle"]["claim"]
        ):
            raise RuntimeError("restart changed the participant public claim")
        stop(restarted)

        must_fail(start(args.binary, "xmr-owner", state), "role-mismatched state")

        corrupt = root / "corrupt.state"
        shutil.copyfile(state, corrupt)
        os.chmod(corrupt, 0o600)
        damaged = bytearray(corrupt.read_bytes())
        damaged[-1] ^= 1
        corrupt.write_bytes(damaged)
        must_fail(start(args.binary, "dom-owner", corrupt), "corrupt state")

    print(
        json.dumps(
            {
                "schema": "DXA1-PARTY-STATE-TEST-V1",
                "status": "passed",
                "mode_0600": True,
                "exclusive_lock": True,
                "restart_preserved_claim": True,
                "role_mismatch_rejected": True,
                "corruption_rejected": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
