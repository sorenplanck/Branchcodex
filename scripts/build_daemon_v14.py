#!/usr/bin/env python3
"""Build the production Linux daemon and publish only a verified ELF artifact.

No node, wallet, daemon, swap, or secret input is started by this command.
Cargo/Rust and native build dependencies must already exist on the host.
A successful build is not certification that all routes are operational.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def publish_elf(source: Path, destination: Path) -> str:
    if source.is_symlink() or not source.is_file():
        raise ValueError('Cargo did not produce a regular executable')
    with source.open('rb') as stream:
        header = stream.read(20)
    if len(header) != 20 or header[:4] != b'\x7fELF' or header[4] not in (1, 2):
        raise ValueError('The Cargo artifact is not an ELF binary')
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(prefix='.dom-interopd-', dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, 'wb') as target, source.open('rb') as original:
            shutil.copyfileobj(original, target)
            target.flush()
            os.fsync(target.fileno())
            os.fchmod(target.fileno(), 0o755)
        expected = digest(source)
        if digest(temporary) != expected:
            raise ValueError('Executable changed during publication')
        os.replace(temporary, destination)
        descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return expected
    finally:
        temporary.unlink(missing_ok=True)


def build_command(cargo: str) -> list[str]:
    return [cargo, 'build', '--locked', '--release', '-p', 'dom-interopd',
            '--bin', 'dom-interopd', '--no-default-features', '--features', 'production',
            '--message-format=json-render-diagnostics']


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/v14/dom-interopd')
    parser.add_argument('--report-dir', type=Path, default=ROOT / 'artifacts/daemon-v14-build')
    args = parser.parse_args()
    report_dir = args.report_dir.resolve() / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    report_dir.mkdir(parents=True, exist_ok=False)
    report = {'status': 'failed', 'rust_compiled': False, 'routes_validated': 0,
              'source_root': str(ROOT), 'platform': platform.platform(), 'binary': None}
    code = 1
    try:
        if sys.platform != 'linux':
            raise RuntimeError('Production custody requires Linux; use your Linux environment or WSL2')
        cargo = shutil.which('cargo')
        if cargo is None:
            report['status'] = 'blocked'
            raise RuntimeError('cargo is absent; install the project toolchain in your build environment')
        command = build_command(cargo)
        report['command'] = command
        artifacts: set[Path] = set()
        with (report_dir / 'cargo.log').open('w') as log:
            process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')
            assert process.stdout is not None
            for line in process.stdout:
                log.write(line)
                log.flush()
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    print(line, end='', flush=True)
                    continue
                if event.get('reason') == 'compiler-message':
                    print(event.get('message', {}).get('rendered', ''), end='', flush=True)
                if (event.get('reason') == 'compiler-artifact'
                    and event.get('target', {}).get('name') == 'dom-interopd'
                    and 'bin' in event.get('target', {}).get('kind', [])
                    and event.get('executable')):
                    artifacts.add(Path(event['executable']).resolve())
            code = process.wait()
        report['cargo_exit_code'] = code
        if code:
            raise RuntimeError(f'Cargo failed with exit code {code}; see cargo.log')
        if len(artifacts) != 1:
            raise RuntimeError('Cargo did not report exactly one daemon executable')
        executable = artifacts.pop()
        target = args.output.resolve()
        if executable == target:
            raise ValueError('Choose an output outside the Cargo artifact path')
        binary_hash = publish_elf(executable, target)
        report.update(status='built', rust_compiled=True, binary=str(target),
                      binary_sha256=binary_hash, bytes=target.stat().st_size)
        code = 0
        print(f'Executable: {target}\nSHA256: {binary_hash}')
    except (OSError, RuntimeError, ValueError) as error:
        report['error'] = str(error)
        code = code or 1
        print(str(error), file=sys.stderr)
    finally:
        (report_dir / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f'Build report: {report_dir / "report.json"}')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
