#!/usr/bin/env bash
# Source-only guard for the frozen consensus surfaces. Does not certify binaries,
# deployments, P2P changes outside these paths, or interoperability correctness.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
consensus_base=38dd70536f088a467f2b7175978c5a6ebb4e5bd4
consensus_paths=(
  crates/dom-consensus
  crates/dom-core
  crates/dom-crypto
  crates/dom-pow
  crates/dom-pmmr
  crates/dom-serialization
  crates/dom-mempool
  crates/dom-node/src/miner.rs
  crates/dom-scriptless-consensus
)

# A missing baseline must fail, never silently select another revision.
git cat-file -e "${consensus_base}^{commit}"
git diff --exit-code --no-ext-diff "$consensus_base" -- "${consensus_paths[@]}"
# Also reject new files, including ignored files: a new module must not escape
# the frozen inventory just because it has not been added to Git.
consensus_extra=$(git ls-files --others -- "${consensus_paths[@]}")
if [[ -n "$consensus_extra" ]]; then
  printf 'Unexpected files in frozen consensus paths:\n%s\n' "$consensus_extra" >&2
  exit 1
fi
printf 'Frozen consensus sources match %s.\n' "$consensus_base"
