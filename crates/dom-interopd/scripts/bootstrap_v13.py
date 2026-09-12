#!/usr/bin/env python3
"""Prepare a public V13 plan or seal a new configuration copy. Native Rust authenticates all authorities."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

ARTIFACT = "contracts-bootstrap-v13.bin"
DOMAIN = b"DOM-INTEROPD/BOOTSTRAP-CONFIG/V1\0"


def digest(domain, data):
    return hashlib.blake2b(domain + data, digest_size=32).digest()


def read_owned(path, maximum=65536):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("expected an absolute canonical path")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        meta = os.fstat(stream.fileno())
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
                or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_nlink != 1):
            raise ValueError("expected an owner-only regular file")
        data = stream.read(maximum + 1)
    if not data or len(data) > maximum:
        raise ValueError("input size refused")
    return data


def parse_config(data):
    if len(data) > 65536 or b"\r" in data or not data.endswith(b"\n"):
        raise ValueError("configuration encoding refused")
    lines = data.decode("ascii").splitlines()
    if not re.fullmatch(r"DOM-INTEROPD-BOOTSTRAP-V(?:[5-9]|10|11)", lines[0]):
        raise ValueError("expected a V5 through V11 production configuration")
    values = {}
    for line in lines[1:]:
        key, value = line.split("=", 1)
        if key in values or not key or not value:
            raise ValueError("duplicate or empty configuration field")
        values[key] = value
    if lines[-1] != "end=1" or not lines[-2].startswith("config_digest="):
        raise ValueError("configuration trailer refused")
    body = ("\n".join(lines[:-2]) + "\n").encode()
    if values["config_digest"] != digest(DOMAIN, body).hex():
        raise ValueError("configuration digest mismatch")
    if values.get("mode") not in ("create", "reopen_existing"):
        raise ValueError("configuration mode refused")
    return lines, values


def common_config(data):
    lines, values = parse_config(data)
    if lines[0].endswith("-V11"):
        raw = values["common_v6"]
        if len(raw) % 2 or not re.fullmatch("[0-9a-f]+", raw):
            raise ValueError("noncanonical common configuration")
        common = bytes.fromhex(raw)
        inner_lines, inner = parse_config(common)
        if inner_lines[0] != "DOM-INTEROPD-BOOTSTRAP-V6" or inner["mode"] != values["mode"]:
            raise ValueError("common configuration scope mismatch")
        return inner
    return values


def hex32(value):
    if not re.fullmatch("[0-9a-f]{64}", value) or value == "00" * 32:
        raise ValueError("expected a nonzero lowercase 32-byte digest")
    return list(bytes.fromhex(value))


def private_root(root):
    root = Path(root)
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise ValueError("expected an absolute canonical directory")
    meta = root.stat()
    if not stat.S_ISDIR(meta.st_mode) or stat.S_IMODE(meta.st_mode) != 0o700 or meta.st_uid != os.getuid():
        raise ValueError("expected an owner-only directory")
    return root


def resolve_reference(root, value):
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts) or value.startswith("/"):
        raise ValueError("invalid relative configuration reference")
    target = root.joinpath(*parts)
    if target.resolve(strict=True) != target:
        raise ValueError("configuration reference uses a symlink")
    return str(target)


def make_plan(data, state_dir, participant):
    values = common_config(data)
    root = private_root(state_dir)
    epoch = values["registry_minimum_epoch"]
    if not re.fullmatch(r"[1-9][0-9]*", epoch) or int(epoch) > 2**64 - 1:
        raise ValueError("registry epoch refused")
    plan = {"schema": 13, "local_participant_id": hex32(participant),
            "minimum_registry_epoch": int(epoch)}
    for key in ("network_id", "route_id", "registry_authority_set_digest", "registry_manifest_digest"):
        plan[key] = hex32(values[key])
    plan["terms_digests"] = [hex32(values[p + "_terms_digest"]) for p in ("upstream", "downstream")]
    plan["roster_digest"] = hex32(values["relay_binding_digest"])
    for key, source in {"authority_bundle_file": "registry_authorities", "registry_store": "registry_store",
                        "roster_file": "relay_roster", "identity_store": "contracts_transport_identity_store",
                        "budget_policy_file": "contracts_budget_policy"}.items():
        plan[key] = resolve_reference(root, values["path_" + source])
    plan["terms_files"] = [resolve_reference(root, values["path_" + p + "_terms"]) for p in ("upstream", "downstream")]
    return plan


def artifact_pins(data):
    # Only public byte commitments; the native daemon verifies all eight
    # signatures, participant identities, terms and capsule before accepting.
    if len(data) != 2538 or data[:12] != b"DOMCTC1\0\0\x01\0\0" or data[1450:1462] != b"DOMCTR1\0\0\x01\0\0":
        raise ValueError("bootstrap codec refused")
    commit = digest(b"DOM-INTEROPD/PRODUCTION-CONTRACTS-BOOTSTRAP-COMMIT/V1\0", data[:1194])
    if data[1462:1494] != commit:
        raise ValueError("bootstrap stage link mismatch")
    reveal = digest(b"DOM-INTEROPD/PRODUCTION-CONTRACTS-BOOTSTRAP-REVEAL/V1\0", data[1450:2282])
    return commit.hex(), reveal.hex()


def rewrite_config(data, replacements):
    lines, values = parse_config(data)
    if lines[0].endswith("-V11"):
        common_config(data)  # checks canonical inner family and mode
        replacement = rewrite_config(bytes.fromhex(values["common_v6"]), replacements)
        replacements = {"common_v6": replacement.hex()}
    if not replacements.keys() <= values.keys():
        raise ValueError("missing bootstrap configuration field")
    output = [lines[0]]
    for line in lines[1:-2]:
        key = line.split("=", 1)[0]
        output.append(key + "=" + replacements[key] if key in replacements else line)
    body = ("\n".join(output) + "\n").encode()
    result = body + b"config_digest=" + digest(DOMAIN, body).hex().encode() + b"\nend=1\n"
    parse_config(result)
    return result


def seal_config(data, artifact, relative_path):
    if Path(relative_path).name != ARTIFACT or any(p in ("", ".", "..") for p in relative_path.split("/")):
        raise ValueError("reserved V13 artifact name/path required")
    commit, reveal = artifact_pins(artifact)
    return rewrite_config(data, {"path_contracts_bootstrap": relative_path,
                                "contracts_bootstrap_commit_digest": commit,
                                "contracts_bootstrap_reveal_digest": reveal})


def write_new(path, data):
    path = Path(path)
    private_root(path.parent)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "seal"):
        command = sub.add_parser(name)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--state-dir", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        if name == "plan":
            command.add_argument("--participant", required=True)
        else:
            command.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        data = read_owned(args.manifest)
        if args.command == "plan":
            output = (json.dumps(make_plan(data, args.state_dir, args.participant), indent=2) + "\n").encode()
        else:
            state = private_root(args.state_dir)
            work = private_root(args.work_dir)
            relative = (work / ARTIFACT).relative_to(state).as_posix()
            output = seal_config(data, read_owned(work / ARTIFACT, 2538), relative)
        write_new(args.output, output)
    except (OSError, ValueError, KeyError, IndexError):
        parser.exit(2, "Public bootstrap input or output refused; originals preserved.\n")
    print(str(args.output))


if __name__ == "__main__":
    main()
