#!/usr/bin/env python3
"""Install one public peer wallet offer atomically; never execute a swap.

This validates file bounds and the four expected scope identifiers. Native
Rust still verifies the codec, proofs, balances and bilateral DSC1 commitment.
File installation itself is not authentication or signing authorization.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

MAX_BYTES = 16_384
MAGIC = b'DWO17\0\0\x01'


def identifier(value: str) -> bytes:
    if len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise argparse.ArgumentTypeError('expected exactly 64 lowercase hexadecimal characters')
    data = bytes.fromhex(value)
    if not any(data):
        raise argparse.ArgumentTypeError('identifier cannot be zero')
    return data


def read_regular(path: Path, *, private: bool) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 400 <= before.st_size <= MAX_BYTES:
            raise ValueError('offer must be one regular bounded file')
        if private and (stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.geteuid()):
            raise ValueError('retained peer offer must be owned by the operator with mode 0600')
        data = source.read(MAX_BYTES + 1)
        after = os.fstat(source.fileno())
        named = path.lstat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or (named.st_dev, named.st_ino) != (after.st_dev, after.st_ino) or len(data) != before.st_size:
            raise ValueError('offer changed while being read')
        return data


def install(source: Path, directory: Path, scope: tuple[bytes, bytes, bytes, bytes]) -> dict:
    info = directory.lstat()
    if not directory.is_absolute() or directory.resolve() != directory or not stat.S_ISDIR(info.st_mode):
        raise ValueError('state directory must be an absolute canonical directory')
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('state directory must be owned by the operator with mode 0700')
    data = read_regular(source, private=False)
    if data[:8] != MAGIC or tuple(data[8+i*32:40+i*32] for i in range(4)) != scope:
        raise ValueError('wrong offer format, chain, session, signed terms or peer participant')
    destination = directory / f'dom-wallet-offer-v17-{scope[1].hex()}.peer'
    lock_path = directory / f'dom-wallet-offer-v17-{scope[1].hex()}.import-lock'
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(lock_fd, 'rb') as lock:
        meta = os.fstat(lock.fileno())
        if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_size != 0
            or meta.st_uid != os.geteuid() or stat.S_IMODE(meta.st_mode) != 0o600):
            raise ValueError('invalid importer lock')
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            existing = read_regular(destination, private=True)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if existing != data:
                raise ValueError('refusing a conflicting retained peer offer')
            action = 'already_present'
        else:
            fd, temporary_name = tempfile.mkstemp(prefix='dom-wallet-offer-v17-', suffix='.pending', dir=directory)
            temporary = Path(temporary_name)
            try:
                with os.fdopen(fd, 'wb') as output:
                    output.write(data)
                    output.flush()
                    os.fchmod(output.fileno(), 0o600)
                    os.fsync(output.fileno())
                os.replace(temporary, destination)
                dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            finally:
                temporary.unlink(missing_ok=True)
            action = 'installed'
    return {'status': action, 'file': str(destination), 'sha256': hashlib.sha256(data).hexdigest(),
            'native_verification_pending': True, 'funding_authorized': False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--state-dir', required=True, type=Path)
    for name in ('chain', 'session', 'terms', 'peer-participant'):
        parser.add_argument('--' + name, required=True, type=identifier)
    args = parser.parse_args()
    try:
        result = install(args.source, args.state_dir, (args.chain, args.session, args.terms, args.peer_participant))
    except (OSError, ValueError) as error:
        parser.exit(1, f'Offer import refused: {error}\n')
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
