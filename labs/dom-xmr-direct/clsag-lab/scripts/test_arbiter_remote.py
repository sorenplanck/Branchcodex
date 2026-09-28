#!/usr/bin/env python3
"""Exercise a funded DXA1 Claim through persistent remote party servers."""

from __future__ import annotations

import argparse
import json
import os
import select
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path


SETTLEMENT = "72" * 32
CONTEXT = "73" * 32
REQUIRED_TRUE = (
    "dom_node",
    "monerod",
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
    "dom_canonicality_rechecked_before_xmr_signing",
)


def executable(value: str) -> Path:
    path = Path(value).expanduser().resolve(strict=True)
    if not stat.S_ISREG(path.stat().st_mode) or not os.access(path, os.X_OK):
        raise argparse.ArgumentTypeError(f"not an executable file: {path}")
    return path


def checked_output(arguments: list[str]) -> str:
    result = subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout.strip()


def identity(proxy: Path, path: Path) -> str:
    public = checked_output([str(proxy), "identity", str(path)])
    if len(public) != 64 or any(char not in "0123456789abcdef" for char in public):
        raise RuntimeError("proxy returned an invalid public identity")
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise RuntimeError("Noise identity is not mode 0600")
    return public


def start_server(
    proxy: Path,
    party: Path,
    role: str,
    chain: str,
    session: str,
    state: Path,
    wrapping_key: Path,
    server_key: Path,
    client_public: str,
    error_log: Path,
) -> tuple[subprocess.Popen[str], str, object]:
    error_file = error_log.open("w")
    process = subprocess.Popen(
        [
            str(proxy),
            "server-persistent",
            str(party),
            role,
            SETTLEMENT,
            CONTEXT,
            chain,
            str(state),
            str(wrapping_key),
            "127.0.0.1:0",
            str(server_key),
            client_public,
            session,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=error_file,
        text=True,
        start_new_session=True,
    )
    assert process.stdout is not None
    readable, _, _ = select.select([process.stdout], [], [], 15)
    if not readable:
        stop(process)
        error_file.close()
        raise RuntimeError(f"{role} server did not begin listening")
    address = process.stdout.readline().strip()
    if not address or process.poll() is not None:
        stop(process)
        error_file.close()
        raise RuntimeError(f"{role} server exited before listening")
    return process, address, error_file


def stop(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=3)


def result_line(output: str) -> dict:
    for line in reversed(output.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("experiment") == "DXA1 DOM-XMR daemon end-to-end":
            return value
    raise RuntimeError("missing DXA1 result record")


def verify(result: dict) -> None:
    if result.get("outcome") != "claim":
        raise RuntimeError("remote run did not complete the Claim path")
    if result.get("bitcoin_involved") is not False:
        raise RuntimeError("BTC appeared in the DOM-XMR leg")
    for field in REQUIRED_TRUE:
        if result.get(field) is not True:
            raise RuntimeError(f"missing remote evidence: {field}")
    active = result.get("ready_to_complete_seconds")
    total = result.get("total_seconds")
    if not isinstance(active, (int, float)) or not 0 < active <= 180:
        raise RuntimeError(f"remote settlement exceeded 180 seconds: {active!r}")
    if not isinstance(total, (int, float)) or not 0 < total <= 180:
        raise RuntimeError(f"remote test exceeded 180 seconds: {total!r}")
    if result.get("dom_target_block_seconds") != 120:
        raise RuntimeError("unexpected public DOM target block interval")
    if result.get("dom_nominal_confirmation_wait_seconds") != 240:
        raise RuntimeError("two-confirmation nominal wait was hidden")
    if result.get("dom_max_nominal_confirmations_within_three_minutes") != 1:
        raise RuntimeError("three-minute confirmation capacity was misstated")
    if result.get("dom_two_confirmations_nominally_fit_three_minutes") is not False:
        raise RuntimeError("Regtest timing was presented as public-network timing")
    if result.get("dom_pow_has_deterministic_confirmation_deadline") is not False:
        raise RuntimeError("PoW finality was presented as deterministic")
    probability = result.get(
        "dom_two_confirmation_probability_within_three_minutes_poisson"
    )
    if not isinstance(probability, (int, float)) or not 0.44 < probability < 0.45:
        raise RuntimeError("unexpected Poisson timing evidence")
    if result.get("regtest_fast_mining_timing_only") is not True:
        raise RuntimeError("accelerated Regtest timing was not disclosed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=executable)
    parser.add_argument("--party", required=True, type=executable)
    parser.add_argument("--proxy", required=True, type=executable)
    parser.add_argument("--monerod", required=True, type=executable)
    parser.add_argument("--evidence-file", type=Path)
    args = parser.parse_args()

    servers: list[subprocess.Popen[str]] = []
    error_files: list[object] = []
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="dxa1-remote-") as directory:
        root = Path(directory)
        bootstrap = json.loads(
            checked_output(
                [str(args.proxy), "regtest-bootstrap", SETTLEMENT, CONTEXT]
            )
        )
        chain = bootstrap["chain_id"]
        session = bootstrap["session"]

        entries: dict[str, dict[str, str]] = {}
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
            process = subprocess.run(
                [str(args.binary), str(args.monerod), "claim"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=environment,
                check=False,
                timeout=190,
            )
            if process.returncode != 0:
                raise RuntimeError(
                    f"remote Claim exited {process.returncode}:\n{process.stdout}"
                )
            result = result_line(process.stdout)
            verify(result)
            result["remote_runner_wall_seconds"] = time.monotonic() - started
            evidence = {
                "schema": "DXA1-REMOTE-PARTICIPANTS-V1",
                "status": "passed",
                "result": result,
            }
            if args.evidence_file is not None:
                path = args.evidence_file.expanduser().resolve()
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
            print(json.dumps(evidence, sort_keys=True))
        finally:
            for server in reversed(servers):
                stop(server)
            for error_file in error_files:
                error_file.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
