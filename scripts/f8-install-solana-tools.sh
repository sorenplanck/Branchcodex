#!/usr/bin/env bash
# F8 — pinned Agave toolchain for the Solana leg harness, content-verified.
#
# Installs `solana` and `solana-test-validator` from crates.io through cargo,
# pinned to one exact version and built with `--locked`. Cargo verifies the
# SHA256 of every downloaded crate against the registry index before it
# compiles anything, so the content is pinned by a mechanism this repository
# already trusts for its entire dependency tree. There is no third-party
# prebuilt binary to trust and no checksum to record by hand: the older
# tarball route had exactly that problem, and this replaces it rather than
# managing it.
#
# Fail-closed by construction:
#   * one pinned VERSION, passed to cargo as an exact requirement;
#   * `--locked`, so the published lockfile decides every transitive version;
#   * installs into a user-owned prefix, never a system path, no sudo;
#   * refuses a different installed version unless FORCE=1;
#   * verifies after installing that each binary reports the pinned version.
#
# Cost, stated plainly: building from source takes far longer than unpacking a
# release. That is the price of the content pin, and it is paid on CI CPU.
set -euo pipefail

# Agave's CLI and test validator are published together under one version.
VERSION="${DOM_SOLANA_TOOLS_VERSION:-2.1.11}"
PREFIX="${SOLANA_PREFIX:-$HOME/.local/dom-solana-tools}"
BIN="$PREFIX/bin"

log() { printf 'f8-solana-tools: %s\n' "$1" >&2; }

command -v cargo >/dev/null 2>&1 || {
  log "cargo is required to install the content-pinned toolchain"
  exit 1
}

report_version() {
  "$1" --version 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | head -1
}

already_installed() {
  for tool in solana solana-test-validator; do
    [ -x "$BIN/$tool" ] || return 1
    [ "$(report_version "$BIN/$tool")" = "$VERSION" ] || return 1
  done
  return 0
}

if already_installed; then
  log "version $VERSION already installed at $BIN"
  printf '%s\n' "$BIN"
  exit 0
fi

if [ -x "$BIN/solana" ] && [ "${FORCE:-0}" != "1" ]; then
  present="$(report_version "$BIN/solana")"
  log "refusing to replace installed version ${present:-unknown} with $VERSION (set FORCE=1)"
  exit 1
fi

# The validator links native libraries; a missing one fails the build late, so
# name the requirement instead of letting cargo report it obscurely.
for header in /usr/include/udev.h /usr/include/libudev.h; do
  [ -f "$header" ] && found_udev=1
done
if [ "${found_udev:-0}" != "1" ]; then
  log "note: libudev headers not found; on Debian/Ubuntu install libudev-dev"
fi

mkdir -p "$PREFIX"

install_crate() {
  local crate="$1"
  log "installing $crate $VERSION with --locked"
  cargo install "$crate" \
    --version "=$VERSION" \
    --locked \
    --root "$PREFIX" \
    --force
}

# solana-cli brings the `solana` binary used to deploy, finalize, read the
# genesis hash and dump the programdata account.
install_crate solana-cli
# solana-test-validator brings the cluster the daemon actually settles against.
install_crate solana-test-validator

for tool in solana solana-test-validator; do
  [ -x "$BIN/$tool" ] || {
    log "cargo did not produce $tool"
    exit 1
  }
  reported="$(report_version "$BIN/$tool")"
  if [ "$reported" != "$VERSION" ]; then
    log "$tool reports ${reported:-unknown}, expected $VERSION"
    exit 1
  fi
done

# `solana-keygen` ships with solana-cli in some versions and separately in
# others. Install it only when the CLI did not provide it, so the pinned set
# stays minimal.
if [ ! -x "$BIN/solana-keygen" ]; then
  install_crate solana-keygen
  [ -x "$BIN/solana-keygen" ] || {
    log "solana-keygen is unavailable at $VERSION"
    exit 1
  }
fi

log "installed $VERSION into $BIN, content-verified by cargo"
printf '%s\n' "$BIN"
