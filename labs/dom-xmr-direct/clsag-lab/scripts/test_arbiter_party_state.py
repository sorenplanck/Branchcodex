#!/usr/bin/env python3
"""Exercise DXA1 participant-state locking, restart, binding, and corruption checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
from pathlib import Path


SETTLEMENT = "72" * 32
CONTEXT = "73" * 32
CHAIN = "61" * 32
KEY_REQUEST_MAGIC = b"DXA1/key-provider/request/v1\0"
KEY_RESPONSE_MAGIC = b"DXA1/key-provider/response/v1\0"
KEY_REQUEST_BYTES = len(KEY_REQUEST_MAGIC) + 1 + 32 + 32 + 32 + 1


class KeyBroker:
    def __init__(
        self,
        path: Path,
        key: bytes,
        *,
        mode: int = 0o600,
        wrong_digest: bool = False,
        stall: bool = False,
    ) -> None:
        if len(key) != 32:
            raise ValueError("broker key must contain 32 bytes")
        self.path = path
        self.key = key
        self.wrong_digest = wrong_digest
        self.stall = stall
        self.requests: list[bytes] = []
        self.errors: list[BaseException] = []
        self.stopping = threading.Event()
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path))
        os.chmod(path, mode)
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        try:
            while not self.stopping.is_set():
                try:
                    connection, _ = self.listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    if self.stopping.is_set():
                        return
                    request = bytearray()
                    while len(request) <= KEY_REQUEST_BYTES:
                        chunk = connection.recv(KEY_REQUEST_BYTES + 1 - len(request))
                        if not chunk:
                            break
                        request.extend(chunk)
                    request_bytes = bytes(request)
                    self.requests.append(request_bytes)
                    if self.stall:
                        self.stopping.wait(10)
                        continue
                    digest = bytearray(hashlib.sha256(request_bytes).digest())
                    if self.wrong_digest:
                        digest[0] ^= 1
                    connection.sendall(KEY_RESPONSE_MAGIC + digest + self.key)
        except BaseException as error:
            self.errors.append(error)

    def close(self) -> None:
        self.stopping.set()
        try:
            wake = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            wake.connect(str(self.path))
            wake.close()
        except OSError:
            pass
        self.thread.join(timeout=2)
        self.listener.close()
        if self.path.exists() or self.path.is_symlink():
            self.path.unlink()
        if self.thread.is_alive():
            raise RuntimeError("key broker did not stop")
        if self.errors:
            raise RuntimeError(f"key broker failed: {self.errors!r}")


def executable(path: str) -> Path:
    result = Path(path).expanduser().resolve(strict=True)
    if not stat.S_ISREG(result.stat().st_mode) or not os.access(result, os.X_OK):
        raise argparse.ArgumentTypeError(f"not an executable file: {result}")
    return result


def start(
    binary: Path, role: str, state: Path, wrapping_key: str | Path
) -> subprocess.Popen[str]:
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


def must_fail(
    process: subprocess.Popen[str], reason: str, timeout: float = 5
) -> None:
    try:
        output, error = process.communicate(timeout=timeout)
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

        symlink_state = root / "symlink.state"
        symlink_state.symlink_to(state)
        must_fail(
            start(args.binary, "dom-owner", symlink_state, wrapping_key),
            "symlink participant state",
        )

        provider_state = root / "provider.state"
        provider_socket = root / "provider.sock"
        provider_key = os.urandom(32)
        provider = KeyBroker(provider_socket, provider_key)
        external = start(
            args.binary,
            "dom-owner",
            provider_state,
            f"unix:{provider_socket}",
        )
        external_ready = ready(external)
        if external_ready.get("wrapping_key_source") != "unix-provider":
            raise RuntimeError("external provider source was not reported")
        if external_ready.get("external_wrapping_key_provider") is not True:
            raise RuntimeError("external provider was not reported as active")
        stop(external)
        external_restart = start(
            args.binary,
            "dom-owner",
            provider_state,
            f"unix:{provider_socket}",
        )
        external_restart_ready = ready(external_restart)
        if external_restart_ready.get("restored") is not True:
            raise RuntimeError("provider-backed state was not restored")
        if (
            external_restart_ready["proof"]["bundle"]["claim"]
            != external_ready["proof"]["bundle"]["claim"]
        ):
            raise RuntimeError("provider restart changed the participant claim")
        stop(external_restart)
        provider.close()
        if len(provider.requests) != 2:
            raise RuntimeError("key provider did not receive create and restore requests")
        expected_binding = (
            bytes([1])
            + bytes.fromhex(SETTLEMENT)
            + bytes.fromhex(CONTEXT)
            + bytes.fromhex(CHAIN)
        )
        for index, request in enumerate(provider.requests):
            if len(request) != KEY_REQUEST_BYTES or not request.startswith(
                KEY_REQUEST_MAGIC + expected_binding
            ):
                raise RuntimeError("key provider request was not bound to the operation")
            if request[-1] != index:
                raise RuntimeError("key provider create/restore phase was not bound")

        wrong_provider_state = root / "wrong-provider.state"
        shutil.copyfile(provider_state, wrong_provider_state)
        os.chmod(wrong_provider_state, 0o600)
        wrong_provider_socket = root / "wrong-provider.sock"
        wrong_provider = KeyBroker(wrong_provider_socket, os.urandom(32))
        must_fail(
            start(
                args.binary,
                "dom-owner",
                wrong_provider_state,
                f"unix:{wrong_provider_socket}",
            ),
            "wrong provider key",
        )
        wrong_provider.close()

        mismatch_socket = root / "mismatch-provider.sock"
        mismatch_provider = KeyBroker(
            mismatch_socket, provider_key, wrong_digest=True
        )
        must_fail(
            start(
                args.binary,
                "dom-owner",
                root / "mismatch-provider.state",
                f"unix:{mismatch_socket}",
            ),
            "mismatched provider response",
        )
        mismatch_provider.close()

        unsafe_socket = root / "unsafe-provider.sock"
        unsafe_provider = KeyBroker(unsafe_socket, provider_key, mode=0o666)
        must_fail(
            start(
                args.binary,
                "dom-owner",
                root / "unsafe-provider.state",
                f"unix:{unsafe_socket}",
            ),
            "unsafe provider socket",
        )
        unsafe_provider.close()

        real_socket = root / "real-provider.sock"
        symlink_socket = root / "symlink-provider.sock"
        symlink_provider = KeyBroker(real_socket, provider_key)
        symlink_socket.symlink_to(real_socket)
        must_fail(
            start(
                args.binary,
                "dom-owner",
                root / "symlink-provider.state",
                f"unix:{symlink_socket}",
            ),
            "symlink provider socket",
        )
        symlink_socket.unlink()
        symlink_provider.close()

        must_fail(
            start(
                args.binary,
                "dom-owner",
                root / "missing-provider.state",
                f"unix:{root / 'missing-provider.sock'}",
            ),
            "missing provider socket",
        )

        stalled_socket = root / "stalled-provider.sock"
        stalled_provider = KeyBroker(stalled_socket, provider_key, stall=True)
        must_fail(
            start(
                args.binary,
                "dom-owner",
                root / "stalled-provider.state",
                f"unix:{stalled_socket}",
            ),
            "stalled provider",
            timeout=8,
        )
        stalled_provider.close()

    print(
        json.dumps(
            {
                "schema": "DXA1-PARTY-STATE-TEST-V3",
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
                "symlink_state_rejected": True,
                "external_key_provider": True,
                "provider_restart_preserved_claim": True,
                "provider_request_operation_bound": True,
                "wrong_provider_key_rejected": True,
                "mismatched_provider_response_rejected": True,
                "unsafe_provider_socket_rejected": True,
                "symlink_provider_socket_rejected": True,
                "missing_provider_socket_rejected": True,
                "stalled_provider_timed_out": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
