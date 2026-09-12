#!/usr/bin/env bash
# Apenas compila; não inicia daemon ou swap.
set -euo pipefail
v21_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$v21_root"
cargo build --locked --release -p dom-interopd --bin dom-interopd --no-default-features --features production
