#!/usr/bin/env python3
"""Run DXF1 through two persistent remote participant endpoints."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from test_arbiter_remote import (
    CONTEXT,
    SETTLEMENT,
    checked_output,
    executable,
    identity,
    start_server,
    stop,
)
from test_fast_handoff import result_line, verify


REMOTE_REQUIRED_TRUE = (
    "remote_participant_servers",
    "authenticated_noise_transport",
    "bounded_noise_handshake_and_message_deadlines",
    "encrypted_participant_state",
    "noise_peer_identity_pinned",
    "transport_session_bound",
    "private_xmr_shares_held_by_separate_processes",
    "distributed_dom_presigning",
    "collaborative_dom_range_proofs",
    "coordinator_never_receives_dom_signing_keys",
    "participant_restart_restored_bound_shares",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=executable)
    parser.add_argument("--party", required=True, type=executable)
    parser.add_argument("--proxy", required=True, type=executable)
    parser.add_argument("--monerod", required=True, type=executable)
    parser.add_argument(
        "--outcome", choices=("fast-claim", "fast-reorg"), default="fast-reorg"
    )
    parser.add_argument("--evidence-file", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    if not 180 <= args.timeout <= 300:
        parser.error("--timeout must be between 180 and 300 seconds")

    servers = []
    error_files = []
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="dxf1-remote-") as directory:
        root = Path(directory)
        bootstrap = json.loads(
            checked_output(
                [str(args.proxy), "regtest-bootstrap", SETTLEMENT, CONTEXT]
            )
        )
        chain = bootstrap["chain_id"]
        session = bootstrap["session"]
        entries: dict[str, dict[str, str]] = {}
        coordinator = None
        try:
            for role, name in (("dom-owner", "dom_owner"), ("xmr-owner", "xmr_owner")):
                server_key = root / f"{name}.server-noise"
                client_key = root / f"{name}.client-noise"
                server_public = identity(args.proxy, server_key)
                client_public = identity(args.proxy, client_key)
                process, address, error_file = start_server(
                    args.proxy,
                    args.party,
                    role,
                    chain,
                    session,
                    root / f"{name}.state",
                    root / f"{name}.wrapping-key",
                    server_key,
                    client_public,
                    root / f"{name}.server.log",
                )
                servers.append(process)
                error_files.append(error_file)
                entries[name] = {
                    "address": address,
                    "server_public": server_public,
                    "client_key_path": str(client_key),
                }

            config = root / "remote-parties.json"
            config.write_text(json.dumps(entries, sort_keys=True) + "\n")
            os.chmod(config, 0o600)
            environment = os.environ.copy()
            environment["DXA1_REMOTE_PARTIES"] = str(config)
            coordinator = subprocess.Popen(
                [str(args.binary), str(args.monerod), args.outcome],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=environment,
                start_new_session=True,
            )
            try:
                output, _ = coordinator.communicate(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                os.killpg(coordinator.pid, signal.SIGKILL)
                output, _ = coordinator.communicate()
                raise RuntimeError(
                    f"remote DXF1 exceeded {args.timeout} seconds:\n{output}"
                )
            if coordinator.returncode != 0:
                raise RuntimeError(
                    f"remote DXF1 exited {coordinator.returncode}:\n{output}"
                )
            result = result_line(output)
            verify(result, args.outcome)
            for field in REMOTE_REQUIRED_TRUE:
                if result.get(field) is not True:
                    raise RuntimeError(f"missing remote DXF1 evidence: {field}")
            if any(server.poll() is not None for server in servers):
                raise RuntimeError("remote participant server exited during DXF1")

            result["remote_runner_wall_seconds"] = time.monotonic() - started
            result["remote_servers_alive_after_run"] = True
            document = {
                "schema": "DXF1-REMOTE-PARTICIPANTS-V1",
                "status": "passed",
                "result": result,
            }
            evidence = args.evidence_file.expanduser().resolve()
            evidence.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            evidence.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
            os.chmod(evidence, 0o600)
            print(json.dumps(document, sort_keys=True))
        finally:
            if coordinator is not None and coordinator.poll() is None:
                os.killpg(coordinator.pid, signal.SIGKILL)
                coordinator.wait(timeout=5)
            for server in reversed(servers):
                stop(server)
            for error_file in error_files:
                error_file.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
