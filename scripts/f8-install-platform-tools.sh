#!/usr/bin/env bash
# F8 — pinned platform-tools for the one build cargo cannot content-verify.
#
# `sbf-solana-solana` is a custom target: its rustc and LLVM come from Anza's
# platform-tools release, not from crates.io, so the cargo checksum mechanism
# that pins the rest of this harness does not reach it. A digest for that
# archive does not exist in this repository until the archive has been fetched
# once, and no invented value is committed in its place.
#
# This script closes that gap by mechanism instead of leaving it open:
#
#   * the version is pinned here;
#   * the digest lives in scripts/f8-platform-tools.lock;
#   * when the lock holds a digest, a drifted archive is refused and deleted;
#   * when the lock is absent, the measured digest is WRITTEN to it and printed,
#     so the establishing run leaves a one-line change to commit and every run
#     after it is enforced;
#   * a lock that exists and disagrees is never overwritten, only refused,
#     unless the operator states FORCE_RELOCK=1 for a deliberate version bump.
#
# So the only value that must come from the network once is this digest, and it
# is captured automatically the first time rather than trusted forever.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${DOM_PLATFORM_TOOLS_VERSION:-v1.48}"
PREFIX="${PLATFORM_TOOLS:-$HOME/platform-tools}"
LOCK="${DOM_PLATFORM_TOOLS_LOCK:-$ROOT/scripts/f8-platform-tools.lock}"
ARCHIVE="platform-tools-linux-x86_64.tar.bz2"
BASE_URL="https://github.com/anza-xyz/platform-tools/releases/download/${VERSION}"

log() { printf 'f8-platform-tools: %s\n' "$1" >&2; }

for tool in curl tar sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || {
    log "missing required tool: $tool"
    exit 1
  }
done

expected=""
if [ -f "$LOCK" ]; then
  expected="$(awk -v v="$VERSION" '$1 == v {print $2}' "$LOCK" | head -1)"
  if [ -n "$expected" ]; then
    log "lock pins $VERSION to $expected"
  else
    log "lock exists but has no entry for $VERSION"
  fi
fi

if [ -x "$PREFIX/rust/bin/cargo" ] && [ -f "$PREFIX/.dom-version" ]; then
  if [ "$(cat "$PREFIX/.dom-version")" = "$VERSION" ]; then
    log "$VERSION already installed at $PREFIX"
    printf '%s\n' "$PREFIX"
    exit 0
  fi
  if [ "${FORCE:-0}" != "1" ]; then
    log "refusing to replace $(cat "$PREFIX/.dom-version") with $VERSION (set FORCE=1)"
    exit 1
  fi
fi

work="$(mktemp -d)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

log "downloading platform-tools $VERSION"
curl --fail --location --silent --show-error \
  --output "$work/$ARCHIVE" "$BASE_URL/$ARCHIVE"

measured="$(sha256sum "$work/$ARCHIVE" | awk '{print $1}')"
log "measured sha256 $measured"

if [ -n "$expected" ]; then
  if [ "$measured" != "$expected" ]; then
    log "REFUSING: archive digest differs from the committed pin"
    log "  expected $expected"
    log "  measured $measured"
    rm -f "$work/$ARCHIVE"
    if [ "${FORCE_RELOCK:-0}" = "1" ]; then
      log "FORCE_RELOCK=1 was set, but a mismatch is never relocked silently"
      log "remove the $VERSION line from $LOCK and rerun to establish a new pin"
    fi
    exit 1
  fi
  log "digest verified against the committed pin"
else
  # Establishing run: record the measurement so every later run is enforced.
  printf '%s %s\n' "$VERSION" "$measured" >>"$LOCK"
  log "recorded the pin in $LOCK"
  log "COMMIT THIS LINE so subsequent runs are enforced:"
  log "  $VERSION $measured"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      printf '### platform-tools pin established\n\n'
      printf 'Commit this line into `scripts/f8-platform-tools.lock`:\n\n'
      printf '```\n%s %s\n```\n' "$VERSION" "$measured"
    } >>"$GITHUB_STEP_SUMMARY"
  fi
fi

log "unpacking into $PREFIX"
rm -rf "$PREFIX"
mkdir -p "$PREFIX"
tar -xjf "$work/$ARCHIVE" -C "$PREFIX"

# Both are required, and the second is the one that matters: the custom target
# `sbf-solana-solana` exists only in THIS rustc. A tree with cargo but no rustc
# would pass a check for cargo alone and then fail inside the build with an
# unhelpful "could not find specification for target" — which is exactly how the
# establishing run failed when the host rustc was reached through PATH instead.
for tool in cargo rustc; do
  [ -x "$PREFIX/rust/bin/$tool" ] || {
    log "unpacked tree has no rust/bin/$tool"
    exit 1
  }
done
printf '%s\n' "$VERSION" >"$PREFIX/.dom-version"

log "installed $VERSION"
printf '%s\n' "$PREFIX"
