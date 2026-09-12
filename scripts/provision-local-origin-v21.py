#!/usr/bin/env python3
"""Provision the ORIGINAL adaptor scalar privately; never generate a replacement.

This is an operator utility, not a protocol authority. The daemon independently
checks the scalar against the authenticated composed terms and local role.
"""
import argparse
import getpass
import os
from pathlib import Path
import stat
import sys
import warnings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    args = parser.parse_args()
    if not sys.stdin.isatty():
        raise ValueError("Execute em um terminal privado para digitar sem eco.")
    state = args.state_dir.resolve(strict=True)
    parent = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    scalar = bytearray()
    try:
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("O diretório de estado deve pertencer ao usuário atual e ter modo 0700.")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            scalar = bytearray.fromhex(getpass.getpass("Segredo adaptor ORIGINAL dos termos (64 hex, sem eco): "))
        order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        if len(scalar) != 32 or not 0 < int.from_bytes(scalar, "big") < order:
            raise ValueError("Formato de scalar inválido.")
        name = "production-local-origin-secret.v21"
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, "wb") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(scalar)
                output.flush()
                os.fsync(output.fileno())
            os.fsync(parent)
        except BaseException:
            os.unlink(name, dir_fd=parent)
            os.fsync(parent)
            raise
    finally:
        scalar[:] = b"\x00" * len(scalar)
        os.close(parent)
    print("Arquivo privado criado. O daemon verificará o ponto e o papel nos termos assinados.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, EOFError, getpass.GetPassWarning):
        # Never include the input, its representation, or a traceback.
        print("Não foi possível provisionar. Confira o diretório, as permissões, o formato e se o arquivo já existe.", file=sys.stderr)
        sys.exit(1)
