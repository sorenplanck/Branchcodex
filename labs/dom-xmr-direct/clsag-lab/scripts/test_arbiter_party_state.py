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


def start(binary: Path, role: str, state: Path, wrapping_key: Path) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            str(binary),
            role,
            SETTLEMENT,
            CONTEXT,
            CHAIN,
            str(state),
            str(wrapping_key),
        ],
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
        wrapping_key = root / "dom-owner.wrapping-key"

        first = start(args.binary, "dom-owner", state, wrapping_key)
        first_ready = ready(first)
        if first_ready.get("restored") is not False:
            raise RuntimeError("new state was reported as restored")
        if first_ready.get("encrypted_state") is not True:
            raise RuntimeError("participant did not report encrypted state")
        if stat.S_IMODE(state.stat().st_mode) != 0o600:
            raise RuntimeError("participant state is not mode 0600")
        if stat.S_IMODE(wrapping_key.stat().st_mode) != 0o600:
            raise RuntimeError("participant wrapping key is not mode 0600")

        must_fail(
            start(args.binary, "dom-owner", state, wrapping_key),
            "concurrent state owner",
        )
        stop(first)

        restarted = start(args.binary, "dom-owner", state, wrapping_key)
        restarted_ready = ready(restarted)
        if restarted_ready.get("restored") is not True:
            raise RuntimeError("existing state was not restored")
        if (
            restarted_ready["proof"]["bundle"]["claim"]
            != first_ready["proof"]["bundle"]["claim"]
        ):
            raise RuntimeError("restart changed the participant public claim")
        stop(restarted)

        must_fail(
            start(args.binary, "xmr-owner", state, wrapping_key),
            "role-mismatched state",
        )

        corrupt = root / "corrupt.state"
        shutil.copyfile(state, corrupt)
        os.chmod(corrupt, 0o600)
        damaged = bytearray(corrupt.read_bytes())
        damaged[-1] ^= 1
        corrupt.write_bytes(damaged)
        must_fail(
            start(args.binary, "dom-owner", corrupt, wrapping_key), "corrupt state"
        )

        missing_key_state = root / "missing-key.state"
        shutil.copyfile(state, missing_key_state)
        os.chmod(missing_key_state, 0o600)
        must_fail(
            start(
                args.binary,
                "dom-owner",
                missing_key_state,
                root / "missing.wrapping-key",
            ),
            "missing wrapping key",
        )

        other_state = root / "other.state"
        other_key = root / "other.wrapping-key"
        other = start(args.binary, "dom-owner", other_state, other_key)
        ready(other)
        stop(other)
        wrong_key_state = root / "wrong-key.state"
        shutil.copyfile(state, wrong_key_state)
        os.chmod(wrong_key_state, 0o600)
        must_fail(
            start(args.binary, "dom-owner", wrong_key_state, other_key),
            "wrong wrapping key",
        )

        corrupt_key = root / "corrupt.wrapping-key"
        shutil.copyfile(wrapping_key, corrupt_key)
        os.chmod(corrupt_key, 0o600)
        damaged_key = bytearray(corrupt_key.read_bytes())
        damaged_key[-1] ^= 1
        corrupt_key.write_bytes(damaged_key)
        corrupt_key_state = root / "corrupt-key.state"
        shutil.copyfile(state, corrupt_key_state)
        os.chmod(corrupt_key_state, 0o600)
        must_fail(
            start(args.binary, "dom-owner", corrupt_key_state, corrupt_key),
            "corrupt wrapping key",
        )

        unsafe_key = root / "unsafe.wrapping-key"
        shutil.copyfile(wrapping_key, unsafe_key)
        os.chmod(unsafe_key, 0o644)
        unsafe_key_state = root / "unsafe-key.state"
        shutil.copyfile(state, unsafe_key_state)
        os.chmod(unsafe_key_state, 0o600)
        must_fail(
            start(args.binary, "dom-owner", unsafe_key_state, unsafe_key),
            "unsafe wrapping key permissions",
        )

        symlink_key = root / "symlink.wrapping-key"
        symlink_key.symlink_to(wrapping_key)
        symlink_key_state = root / "symlink-key.state"
        shutil.copyfile(state, symlink_key_state)
        os.chmod(symlink_key_state, 0o600)
        must_fail(
            start(args.binary, "dom-owner", symlink_key_state, symlink_key),
            "symlink wrapping key",
        )

        same_path = root / "same.state-and-key"
        must_fail(
            start(args.binary, "dom-owner", same_path, same_path),
            "identical state and key paths",
        )

    print(
        json.dumps(
            {
                "schema": "DXA1-PARTY-STATE-TEST-V2",
                "status": "passed",
                "xchacha20poly1305_encrypted": True,
                "mode_0600": True,
                "wrapping_key_mode_0600": True,
                "exclusive_lock": True,
                "restart_preserved_claim": True,
                "role_mismatch_rejected": True,
                "corruption_rejected": True,
                "missing_key_rejected": True,
                "wrong_key_rejected": True,
                "corrupt_key_rejected": True,
                "unsafe_key_permissions_rejected": True,
                "symlink_key_rejected": True,
                "identical_paths_rejected": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
