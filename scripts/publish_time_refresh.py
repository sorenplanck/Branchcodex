#!/usr/bin/env python3
"""Verify public signature/scope pins and atomically publish a runtime refresh.

Never creates evidence or signatures. The daemon independently authenticates
the full policy, frozen anchors and durable sequence before new funding.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import time
import time_evidence_oracle as oracle

TARGET = "route-time-refresh.v2"
LOCK = "route-time-refresh.lock"


def owner_file(metadata):
    oracle.require(stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600
                   and metadata.st_uid == os.geteuid() and metadata.st_nlink == 1, "invalid owner-only file")


def read_at(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        owner_file(before)
        oracle.require(0 < before.st_size <= oracle.MAX_BYTES, "invalid file size")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(oracle.MAX_BYTES + 1)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        oracle.require(len(data) == before.st_size and after.st_mtime_ns == before.st_mtime_ns
                       and after.st_ctime_ns == before.st_ctime_ns and after.st_nlink == 1
                       and named.st_ino == after.st_ino and named.st_dev == after.st_dev,
                       "file changed while reading")
        return data
    finally:
        os.close(fd)


def publish(raw, pins, state_dir, now):
    checked = oracle.verify(raw, pins, now)
    directory = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    lock_fd = None
    temporary = None
    try:
        metadata = os.fstat(directory)
        oracle.require(stat.S_IMODE(metadata.st_mode) == 0o700 and metadata.st_uid == os.geteuid(), "invalid state directory")
        lock_fd = os.open(LOCK, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
        lock_meta = os.fstat(lock_fd)
        owner_file(lock_meta)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        named = os.stat(LOCK, dir_fd=directory, follow_symlinks=False)
        oracle.require(named.st_ino == lock_meta.st_ino and named.st_dev == lock_meta.st_dev, "lock replaced")
        try:
            previous = read_at(directory, TARGET)
        except FileNotFoundError:
            previous = None
        if previous is not None:
            old, new = oracle.decode(previous), oracle.decode(raw)
            oracle.require(old["policy_digest"] == new["policy_digest"]
                           and old["route_scope_digest"] == new["route_scope_digest"], "cross-route overwrite")
            oracle.require(new["sequence"] > old["sequence"] or previous == raw, "rollback or equivocation")
        if previous != raw:
            temporary = "route-time-refresh-" + secrets.token_hex(16) + ".new"
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, TARGET, src_dir_fd=directory, dst_dir_fd=directory)
            temporary = None
        else:
            # A prior attempt may have renamed successfully and then failed
            # directory fsync. An idempotent retry must finish durability.
            fd = os.open(TARGET, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                owner_file(os.fstat(fd))
                os.fsync(fd)
            finally:
                os.close(fd)
        os.fsync(directory)
        return dict(status="published" if previous != raw else "already_published", sequence=checked["sequence"],
                    wire_sha256=hashlib.sha256(raw).hexdigest(), runtime_policy_verification_required=True)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signed", required=True, type=Path)
    parser.add_argument("--pins", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        with args.signed.open("rb") as stream:
            raw = stream.read(oracle.MAX_BYTES + 1)
        print(json.dumps(publish(raw, oracle.load_json(args.pins), args.state_dir, int(time.time())), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, RecursionError):
        print('{"status":"refused","scope":"time-refresh-publication"}', file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
