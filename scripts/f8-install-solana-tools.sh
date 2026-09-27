#!/usr/bin/env bash
# F8 — pinned Agave toolchain for the Solana leg harness, digest-enforced.
#
# Installs the `solana`, `solana-test-validator` and `solana-keygen` binaries
# from Anza's official release archive for one exact version.
#
# Why not `cargo install`: it was tried and it does not work here.
# `solana-test-validator` is published as a LIBRARY crate -- run 36280398680
# failed with "there is nothing to install in `solana-test-validator v2.1.11`,
# because it has no binaries" -- so the validator this harness needs simply is
# not installable that way. Building the whole validator tree from source also
# cost ~40 minutes and dragged in a build-dependency chain (libudev, protoc,
# cmake, llvm) whose every missing link failed the job late.
#
# Why this is not the weaker option it looks like: the archive is pinned by the
# same measure-record-enforce mechanism as `f8-install-platform-tools.sh`.
#
#   * the version is pinned here;
#   * the digest lives in scripts/f8-solana-tools.lock;
#   * when the lock holds a digest, a drifted archive is refused and deleted;
#   * when the lock has no entry, the measured digest is WRITTEN to it and
#     printed, so the establishing run leaves one line to commit and every run
#     after it is enforced;
#   * a lock that exists and disagrees is never overwritten, only refused.
#
# This pins the exact bytes of the binaries that are executed, which is a
# stronger statement about what runs than pinning the sources they were built
# from and then trusting whatever toolchain built them.
#
# Fail-closed after unpacking too: each binary must exist AND report the pinned
# version, so an archive with a missing or mismatched tool is refused here
# rather than inside the scenario.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${DOM_SOLANA_TOOLS_VERSION:-2.1.11}"
PREFIX="${SOLANA_PREFIX:-$HOME/.local/dom-solana-tools}"
BIN="$PREFIX/bin"
LOCK="${DOM_SOLANA_TOOLS_LOCK:-$ROOT/scripts/f8-solana-tools.lock}"
ARCHIVE="solana-release-x86_64-unknown-linux-gnu.tar.bz2"
BASE_URL="https://github.com/anza-xyz/agave/releases/download/v${VERSION}"
TOOLS="solana solana-test-validator solana-keygen"

log() { printf 'f8-solana-tools: %s\n' "$1" >&2; }

for tool in curl tar bzip2 sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || {
    log "missing required tool: $tool"
    exit 1
  }
done

report_version() {
  "$1" --version 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | head -1
}

already_installed() {
  for tool in $TOOLS; do
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

expected=""
if [ -f "$LOCK" ]; then
  expected="$(awk -v v="$VERSION" '$1 == v {print $2}' "$LOCK" | head -1)"
  if [ -n "$expected" ]; then
    log "lock pins $VERSION to $expected"
  else
    log "lock exists but has no entry for $VERSION"
  fi
fi

work="$(mktemp -d)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

log "downloading Agave $VERSION release archive"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  --retry 5 --retry-connrefused \
  --output "$work/$ARCHIVE" "$BASE_URL/$ARCHIVE"

measured="$(sha256sum "$work/$ARCHIVE" | awk '{print $1}')"
log "measured sha256 $measured"

if [ -n "$expected" ]; then
  if [ "$measured" != "$expected" ]; then
    log "REFUSING: archive digest differs from the committed pin"
    log "  expected $expected"
    log "  measured $measured"
    rm -f "$work/$ARCHIVE"
    exit 1
  fi
  log "digest verified against the committed pin"
else
  printf '%s %s\n' "$VERSION" "$measured" >>"$LOCK"
  log "recorded the pin in $LOCK"
  log "COMMIT THIS LINE so subsequent runs are enforced:"
  log "  $VERSION $measured"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      printf '### Agave toolchain pin established\n\n'
      printf 'Commit this line into `scripts/f8-solana-tools.lock`:\n\n'
      printf '```\n%s %s\n```\n' "$VERSION" "$measured"
    } >>"$GITHUB_STEP_SUMMARY"
  fi
fi

log "unpacking into $PREFIX"
rm -rf "$PREFIX"
mkdir -p "$PREFIX"
# The archive carries a single top-level directory; stripping it puts the
# binaries at $PREFIX/bin without this script having to know its name.
tar -xjf "$work/$ARCHIVE" -C "$PREFIX" --strip-components=1

for tool in $TOOLS; do
  [ -x "$BIN/$tool" ] || {
    log "the archive does not provide an executable $tool at $BIN"
    exit 1
  }
  reported="$(report_version "$BIN/$tool")"
  if [ "$reported" != "$VERSION" ]; then
    log "$tool reports ${reported:-unknown}, expected $VERSION"
    exit 1
  fi
done

log "installed $VERSION into $BIN, digest-enforced"
printf '%s\n' "$BIN"
