#!/usr/bin/env python3
"""Run a funded DXA1 Claim across three isolated Docker containers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import subprocess
import tempfile
import time
from pathlib import Path

from test_arbiter_remote import CONTEXT, SETTLEMENT, result_line, verify


DEFAULT_IMAGE = (
    "ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba"
    "065f7503eab3078a2d7a57a2ab987517"
)
PARTICIPANT_PORT = 47001


def executable(value: str) -> Path:
    path = Path(value).expanduser().resolve(strict=True)
    if not stat.S_ISREG(path.stat().st_mode) or not os.access(path, os.X_OK):
        raise argparse.ArgumentTypeError(f"not an executable file: {path}")
    return path


def run(
    arguments: list[str],
    *,
    timeout: int = 30,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"command failed ({result.returncode}): {detail}")
    return result


def docker_security() -> list[str]:
    return [
        f"--user={os.getuid()}:{os.getgid()}",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=128",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
    ]


def bind(source: Path, destination: str, readonly: bool = False) -> str:
    suffix = ",readonly" if readonly else ""
    return f"type=bind,src={source},dst={destination}{suffix}"


def one_shot(
    image: str,
    binary_directory: Path,
    state_directory: Path,
    arguments: list[str],
) -> str:
    result = run(
        [
            "docker",
            "run",
            "--rm",
            *docker_security(),
            "--network=none",
            "--mount",
            bind(binary_directory, "/opt/dxa1", True),
            "--mount",
            bind(state_directory, "/state"),
            image,
            "/opt/dxa1/arbiter_party_proxy",
            *arguments,
        ],
        timeout=30,
    )
    return result.stdout.strip()


def identity(
    image: str,
    binary_directory: Path,
    state_directory: Path,
    filename: str,
) -> str:
    public = one_shot(
        image,
        binary_directory,
        state_directory,
        ["identity", f"/state/{filename}"],
    )
    if len(public) != 64 or any(char not in "0123456789abcdef" for char in public):
        raise RuntimeError("container returned an invalid Noise identity")
    return public


def bootstrap(image: str, binary_directory: Path, coordinator: Path) -> dict:
    value = one_shot(
        image,
        binary_directory,
        coordinator,
        ["regtest-bootstrap", SETTLEMENT, CONTEXT],
    )
    result = json.loads(value)
    for field in ("chain_id", "session"):
        encoded = result.get(field)
        if not isinstance(encoded, str) or len(encoded) != 64:
            raise RuntimeError(f"invalid bootstrap {field}")
    return result


def start_participant(
    *,
    image: str,
    binary_directory: Path,
    network: str,
    name: str,
    role: str,
    state_directory: Path,
    client_public: str,
    chain: str,
    session: str,
) -> None:
    run(
        [
            "docker",
            "run",
            "--detach",
            "--name",
            name,
            "--network",
            network,
            *docker_security(),
            "--mount",
            bind(binary_directory, "/opt/dxa1", True),
            "--mount",
            bind(state_directory, "/state"),
            image,
            "/opt/dxa1/arbiter_party_proxy",
            "server-persistent",
            "/opt/dxa1/arbiter_party",
            role,
            SETTLEMENT,
            CONTEXT,
            chain,
            "/state/party.state",
            "/state/party.wrapping-key",
            f"0.0.0.0:{PARTICIPANT_PORT}",
            "/state/server-noise",
            client_public,
            session,
        ]
    )


def wait_listening(name: str) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        inspected = json.loads(run(["docker", "inspect", name]).stdout)[0]
        if not inspected["State"]["Running"]:
            logs = run(["docker", "logs", name], check=False).stdout
            raise RuntimeError(f"participant {name} stopped before listening: {logs}")
        logs = run(["docker", "logs", name], check=False).stdout
        if f"0.0.0.0:{PARTICIPANT_PORT}" in logs:
            return
        time.sleep(0.1)
    raise RuntimeError(f"participant {name} did not listen in time")


def container_address(name: str, network: str) -> str:
    record = json.loads(run(["docker", "inspect", name]).stdout)[0]
    address = record["NetworkSettings"]["Networks"][network]["IPAddress"]
    if not address:
        raise RuntimeError(f"container {name} has no address on {network}")
    return address


def inspect_isolation(names: list[str], network: str) -> dict:
    records = [json.loads(run(["docker", "inspect", name]).stdout)[0] for name in names]
    sandboxes = [record["NetworkSettings"]["SandboxKey"] for record in records]
    addresses = [record["NetworkSettings"]["Networks"][network]["IPAddress"] for record in records]
    if any(not value for value in sandboxes + addresses):
        raise RuntimeError("container network namespace was not initialized")
    if len(set(sandboxes)) != len(records) or len(set(addresses)) != len(records):
        raise RuntimeError("containers unexpectedly share a network namespace")

    participant_sources: list[str] = []
    for record in records[:2]:
        state_mounts = [
            mount
            for mount in record["Mounts"]
            if mount["Destination"] == "/state" and mount["RW"] is True
        ]
        if len(state_mounts) != 1:
            raise RuntimeError("participant state mount is not exclusive and writable")
        participant_sources.append(state_mounts[0]["Source"])
    if len(set(participant_sources)) != 2:
        raise RuntimeError("participants share the same state directory")
    if any(mount["Destination"] == "/state" for mount in records[2]["Mounts"]):
        raise RuntimeError("coordinator can mount participant private state")

    network_record = json.loads(run(["docker", "network", "inspect", network]).stdout)[0]
    if network_record.get("Internal") is not True:
        raise RuntimeError("DXA1 container network permits external routing")
    return {
        "three_distinct_network_namespaces": True,
        "three_distinct_network_addresses": True,
        "participant_state_mounts_separate": True,
        "coordinator_has_no_participant_state_mount": True,
        "network_external_routing_disabled": True,
        "namespace_fingerprints": [
            hashlib.sha256(value.encode()).hexdigest() for value in sandboxes
        ],
    }


def container_logs(name: str) -> str:
    result = run(["docker", "logs", name], check=False)
    return result.stdout + result.stderr


def cleanup(names: list[str], network: str | None) -> None:
    for name in reversed(names):
        run(["docker", "rm", "--force", name], timeout=20, check=False)
    if network is not None:
        run(["docker", "network", "rm", network], timeout=20, check=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=executable)
    parser.add_argument("--party", required=True, type=executable)
    parser.add_argument("--proxy", required=True, type=executable)
    parser.add_argument("--monerod", required=True, type=executable)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--evidence-file", type=Path)
    args = parser.parse_args()

    if args.party.parent != args.binary.parent or args.proxy.parent != args.binary.parent:
        parser.error("binary, party and proxy must share one directory")
    certificate_directory = Path("/etc/ssl/certs").resolve(strict=True)
    run(["docker", "version", "--format", "{{.Server.Version}}"])
    inspected_image = run(
        ["docker", "image", "inspect", args.image, "--format", "{{.Id}}"],
        check=False,
    )
    if inspected_image.returncode != 0:
        run(["docker", "pull", args.image], timeout=180)
    image_id = run(["docker", "image", "inspect", args.image, "--format", "{{.Id}}"])
    image_id = image_id.stdout.strip()
    prefix = f"dxa1-{secrets.token_hex(6)}"
    network = prefix
    dom_name = f"{prefix}-dom"
    xmr_name = f"{prefix}-xmr"
    coordinator_name = f"{prefix}-coordinator"
    created: list[str] = []
    started = time.monotonic()

    with tempfile.TemporaryDirectory(prefix="dxa1-containers-") as directory:
        root = Path(directory)
        coordinator = root / "coordinator"
        dom_state = root / "dom-owner"
        xmr_state = root / "xmr-owner"
        for path in (coordinator, dom_state, xmr_state):
            path.mkdir(mode=0o700)
        (coordinator / "runtime").mkdir(mode=0o700)
        try:
            run(
                [
                    "docker",
                    "network",
                    "create",
                    "--internal",
                    "--label",
                    "org.dom.dxa1-test=true",
                    network,
                ]
            )
            bootstrap_value = bootstrap(args.image, args.binary.parent, coordinator)
            chain = bootstrap_value["chain_id"]
            session = bootstrap_value["session"]
            dom_client_public = identity(
                args.image, args.binary.parent, coordinator, "dom-client-noise"
            )
            xmr_client_public = identity(
                args.image, args.binary.parent, coordinator, "xmr-client-noise"
            )
            dom_server_public = identity(
                args.image, args.binary.parent, dom_state, "server-noise"
            )
            xmr_server_public = identity(
                args.image, args.binary.parent, xmr_state, "server-noise"
            )

            start_participant(
                image=args.image,
                binary_directory=args.binary.parent,
                network=network,
                name=dom_name,
                role="dom-owner",
                state_directory=dom_state,
                client_public=dom_client_public,
                chain=chain,
                session=session,
            )
            created.append(dom_name)
            start_participant(
                image=args.image,
                binary_directory=args.binary.parent,
                network=network,
                name=xmr_name,
                role="xmr-owner",
                state_directory=xmr_state,
                client_public=xmr_client_public,
                chain=chain,
                session=session,
            )
            created.append(xmr_name)
            wait_listening(dom_name)
            wait_listening(xmr_name)
            dom_address = container_address(dom_name, network)
            xmr_address = container_address(xmr_name, network)

            remote_config = {
                "dom_owner": {
                    "address": f"{dom_address}:{PARTICIPANT_PORT}",
                    "server_public": dom_server_public,
                    "client_key_path": "/coordinator/dom-client-noise",
                },
                "xmr_owner": {
                    "address": f"{xmr_address}:{PARTICIPANT_PORT}",
                    "server_public": xmr_server_public,
                    "client_key_path": "/coordinator/xmr-client-noise",
                },
            }
            config = coordinator / "remote-parties.json"
            config.write_text(json.dumps(remote_config, sort_keys=True) + "\n")
            os.chmod(config, 0o600)

            run(
                [
                    "docker",
                    "run",
                    "--detach",
                    "--name",
                    coordinator_name,
                    "--network",
                    network,
                    *docker_security(),
                    "--mount",
                    bind(args.binary.parent, "/opt/dxa1", True),
                    "--mount",
                    bind(args.monerod.parent, "/opt/monero", True),
                    "--mount",
                    bind(certificate_directory, "/etc/ssl/certs", True),
                    "--mount",
                    bind(coordinator, "/coordinator"),
                    "--env",
                    "DXA1_REMOTE_PARTIES=/coordinator/remote-parties.json",
                    "--env",
                    "TMPDIR=/coordinator/runtime",
                    "--env",
                    "HOME=/coordinator",
                    "--workdir=/coordinator",
                    args.image,
                    "/opt/dxa1/arbiter_regtest",
                    f"/opt/monero/{args.monerod.name}",
                    "claim",
                ]
            )
            created.append(coordinator_name)
            isolation = inspect_isolation(
                [dom_name, xmr_name, coordinator_name], network
            )
            try:
                waited = run(
                    ["docker", "wait", coordinator_name], timeout=190, check=False
                )
            except subprocess.TimeoutExpired:
                run(["docker", "kill", coordinator_name], check=False)
                raise RuntimeError("containerized Claim exceeded 190 seconds")
            output = container_logs(coordinator_name)
            if waited.returncode != 0 or waited.stdout.strip() != "0":
                raise RuntimeError(f"containerized Claim failed:\n{output}")
            result = result_line(output)
            verify(result)
            wall = time.monotonic() - started
            if wall > 180:
                raise RuntimeError(f"containerized test exceeded 180 seconds: {wall}")
            evidence = {
                "schema": "DXA1-CONTAINER-PARTICIPANTS-V1",
                "status": "passed",
                "container_image": args.image,
                "container_image_id": image_id,
                "container_runner_wall_seconds": wall,
                **isolation,
                "result": result,
            }
            if args.evidence_file is not None:
                path = args.evidence_file.expanduser().resolve()
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
            print(json.dumps(evidence, sort_keys=True))
        except Exception:
            for name in created:
                logs = container_logs(name)
                if logs:
                    print(f"[{name}]\n{logs}", file=os.sys.stderr)
            for log_path in coordinator.rglob("monerod*.log"):
                try:
                    log_text = log_path.read_text(errors="replace")[-16_384:]
                except OSError:
                    continue
                if log_text:
                    print(f"[{log_path.name}]\n{log_text}", file=os.sys.stderr)
            raise
        finally:
            cleanup(created, network)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
