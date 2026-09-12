#!/usr/bin/env bash
# Dependencies (including the fingerprinted release daemon) must already exist.
# The GitHub workflow supplies them through the pinned GPL preparation action.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export CARGO_BUILD_JOBS=2
export RUST_TEST_THREADS=1
exec python3 scripts/run_xmr_live_leg_v23.py "$@"
