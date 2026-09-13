#!/usr/bin/env python3
"""Check the native fixture's real private UDS path before any Cargo build.

No daemon, key, transaction or network beyond one owned AF_UNIX socket exists
here. This is transport readiness, not a substitute for authenticated sidecar
startup, which still runs after the actual pinned executable is built.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import stat
import tempfile

from test_interop_hardening import production_environment_v24


def probe_private_uds_v24(env):
    scoped = production_environment_v24(dict(env))
    root = Path(scoped["TMPDIR"])
    # Use the kernel's real sockaddr_un bound, not a new smaller arbitrary
    # ceiling. The allocation helper has already reserved native nesting room.
    with tempfile.TemporaryDirectory(prefix="uds-v24-", dir=root) as directory:
        directory = Path(directory)
        directory.chmod(0o700)
        production_environment_v24(dict(env))
        metadata = directory.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or directory.resolve() != directory
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700):
            raise PermissionError("UDS probe directory is not privately owned")
        path = directory / "sidecar.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.settimeout(1)
            listener.bind(str(path))
            path.chmod(0o600)
            metadata = path.lstat()
            if (not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600):
                raise PermissionError("UDS probe socket ownership refused")
            listener.listen(1)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(1)
                client.connect(str(path))
                client.sendall(b"DOM-UDS?")
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(1)
                    if receive_exact_v24(connection, 8) != b"DOM-UDS?":
                        raise ValueError("UDS probe request differs")
                    connection.sendall(b"DOM-UDS!")
                if receive_exact_v24(client, 8) != b"DOM-UDS!":
                    raise ValueError("UDS probe response differs")
        result = {"private_fixture_root": str(root),
                  "socket_path_bytes": len(os.fsencode(path)),
                  "transport_roundtrip": True}
    if directory.exists():
        raise RuntimeError("UDS probe cleanup incomplete")
    return {**result, "cleanup_verified": True}


def receive_exact_v24(connection, count):
    result = bytearray()
    while len(result) < count:
        part = connection.recv(count - len(result))
        if not part:
            raise EOFError("UDS probe closed early")
        result.extend(part)
    return bytes(result)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args(argv)
    result = {"schema": "DOM-XMR-PRIVATE-UDS-PREFLIGHT-V24", "status": "failed"}
    try:
        result.update(probe_private_uds_v24(os.environ), status="passed")
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    # Public status only. Never replace an earlier result or follow a link.
    descriptor = os.open(args.result, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
