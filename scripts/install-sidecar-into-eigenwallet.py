#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

EXPECTED_COMMIT = "0e17c7f7cd8f0657af176c8852aa4c9949586051"
HERE = Path(__file__).resolve().parents[1]
SOURCE = HERE / "external-gpl/dom-xmr-sidecar"
TOOL_MEMBERS = ("monero-wallet-ng", "dom-xmr-sidecar", "xmr-key-image-proof", "xmr-raw-tx-verify")


def fail(message: str) -> None:
    raise SystemExit(message)


def insert_member(cargo: Path, member: str) -> None:
    text = cargo.read_text()
    if f'"{member}"' in text:
        return
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip().startswith("members = [")), None)
    if start is None:
        fail("Eigenwallet workspace members array not found")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].strip() == "]"), None)
    if end is None:
        fail("Eigenwallet workspace members array is not closed")
    lines.insert(end, f'  "{member}",')
    cargo.write_text("\n".join(lines) + "\n")


def verify_commit(root: Path) -> None:
    # A tarball checkout has no .git and therefore no provable identity;
    # skipping verification there would silently void the pin, so it fails.
    if not (root / ".git").exists():
        fail(
            "Eigenwallet checkout has no .git directory; the pinned commit "
            "cannot be verified. Clone the repository instead of unpacking a tarball."
        )
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail("could not resolve Eigenwallet HEAD")
    actual = result.stdout.strip()
    if actual != EXPECTED_COMMIT and os.environ.get("DOM_XMR_ALLOW_SOURCE_DRIFT") != "1":
        fail(
            f"Eigenwallet source drift: expected {EXPECTED_COMMIT}, got {actual}; "
            "set DOM_XMR_ALLOW_SOURCE_DRIFT=1 only after review"
        )


def restrict_to_offline_tools(root: Path) -> None:
    """Select only real tool packages; retain SDK sources, dependencies and lock."""
    for member in TOOL_MEMBERS:
        if not (root / member / "Cargo.toml").is_file():
            fail(f"offline tool package is missing: {member}")
    cargo = root / "Cargo.toml"
    original = cargo.read_text()
    # The pinned root has a multiline workspace.members array. Refuse drift
    # instead of producing an ambiguous manifest or modifying another table.
    workspace = re.search(r"(?m)^\[workspace\]\s*$", original)
    if workspace is None:
        fail("pinned workspace table is missing")
    tail = original[workspace.end():]
    next_table = re.search(r"(?m)^\[", tail)
    table_end = workspace.end() + (next_table.start() if next_table else len(tail))
    table = original[workspace.end():table_end]
    members = re.search(r"(?ms)^members\s*=\s*\[.*?^\]", table)
    if members is None or re.search(r"(?m)^default-members\s*=", table):
        fail("pinned workspace member layout changed")
    replacement = "members = [\n" + "".join(f'  "{name}",\n' for name in TOOL_MEMBERS) + "]"
    start, end = workspace.end() + members.start(), workspace.end() + members.end()
    cargo.write_text(original[:start] + replacement + original[end:])


def main() -> None:
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--tools-only"):
        fail(f"usage: {sys.argv[0]} /path/to/eigenwallet-core [--tools-only]")
    root = Path(sys.argv[1]).resolve()
    cargo = root / "Cargo.toml"
    if not cargo.is_file() or not (root / "monero-wallet-ng").is_dir():
        fail("target is not an Eigenwallet core checkout")
    verify_commit(root)
    proof_destination = root / "xmr-key-image-proof"
    if proof_destination.exists():
        fail("proof library destination already exists; inspect/remove that exact generated directory before reinstalling")
    raw_destination = root / "xmr-raw-tx-verify"
    if raw_destination.exists():
        fail("raw verifier destination already exists; inspect that exact generated directory before reinstalling")
    destination = root / "dom-xmr-sidecar"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(SOURCE, destination)
    insert_member(cargo, "dom-xmr-sidecar")
    # This original MIT proof library is shared by GPL producer and MIT verifier.
    # Do not alter the pinned upstream cryptographic implementation or lockfile.
    shutil.copytree(HERE / "crates/adapters/xmr-key-image-proof", proof_destination)
    insert_member(cargo, "xmr-key-image-proof")
    shutil.copytree(HERE / "crates/adapters/xmr-raw-tx-verify", raw_destination)
    insert_member(cargo, "xmr-raw-tx-verify")
    if len(sys.argv) == 3:
        restrict_to_offline_tools(root)
    print(f"installed sidecar at {destination}")
    print("run once without --locked to add the local package, then rerun with --locked")


if __name__ == "__main__":
    main()
