#!/usr/bin/env bash
# F8 — bring up a real Solana cluster and hand the daemon scenario the exact
# values it must authenticate.
#
# Why a deployment and not a preloaded program: `AuthenticatedProductionInputs`
# refuses a Solana leg whose profile does not require an immutable program and
# whose binding's `program_data_hash` does not equal the one the signed registry
# declares (crates/dom-interopd/src/production_inputs.rs, the
# `ChainKindV1::Solana` arm). A program loaded with
# `solana-test-validator --bpf-program` has no programdata account and so no
# such hash. The only shape the daemon accepts is therefore a real upgradeable
# deployment whose upgrade authority is then revoked, which is also exactly the
# step NAR-DC-P1-010 section 5 item 2 names as missing.
#
# What this script measures and exports, all read back from the running node,
# never assumed:
#   DOM_SOLANA_LIVE_RPC_V1           the JSON-RPC endpoint
#   DOM_SOLANA_LIVE_PROGRAM_V1       deployed program id, base58
#   DOM_SOLANA_LIVE_PROGRAMDATA_V1   programdata account, base58
#   DOM_SOLANA_LIVE_PROGRAMDATA_SHA256_V1  sha256 of the on-chain programdata
#   DOM_SOLANA_LIVE_GENESIS_V1       cluster genesis hash, base58
#   DOM_SOLANA_LIVE_PAYER_V1         funded deploy payer keypair path
#   DOM_SOLANA_LIVE_FUNDER_V1        funded escrow funder keypair path
#   DOM_SOLANA_LIVE_BENEFICIARY_V1   funded beneficiary keypair path
#   DOM_SOLANA_LIVE_REFUND_V1        funded refund-recipient keypair path
#
# The scenario does not mint: the faucet is the cluster's, and these three keys
# are funded here so the daemon's Solana face only ever pays fees it already
# has, exactly as it would on a cluster it does not control.
#
# It executes the command passed as arguments with those exported, then always
# tears the validator down and writes an evidence file. With no arguments it
# prints the environment and exits, so the values can be inspected alone.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${DOM_SOLANA_LIVE_DIR_V1:-$(mktemp -d)}"
LEDGER="$WORK/ledger"
EVIDENCE="${DOM_SOLANA_LIVE_EVIDENCE_V1:-$WORK/solana-live-evidence.json}"
RPC_PORT="${DOM_SOLANA_LIVE_PORT_V1:-8899}"
RPC_URL="http://127.0.0.1:${RPC_PORT}"
FAUCET_PORT="${DOM_SOLANA_LIVE_FAUCET_PORT_V1:-9900}"
PROGRAM_SO="${DOM_SOLANA_PROGRAM_SO_V1:-$ROOT/programs/dom-solana-escrow/target/sbf-solana-solana/release/dom_solana_escrow.so}"
VALIDATOR_LOG="$WORK/validator.log"
STATUS="incomplete"
VALIDATOR_PID=""

log() { printf 'f8-solana-live: %s\n' "$1" >&2; }

write_evidence() {
  cat >"$EVIDENCE" <<JSON
{
  "schema": "DOM-SOLANA-LIVE-HARNESS-V1",
  "status": "$STATUS",
  "rpc_url": "$RPC_URL",
  "program_id": "${PROGRAM_ID:-}",
  "programdata_account": "${PROGRAMDATA:-}",
  "programdata_sha256": "${PROGRAMDATA_SHA256:-}",
  "genesis_hash": "${GENESIS:-}",
  "upgrade_authority_revoked": ${REVOKED:-false},
  "curve_syscall_enabled": ${CURVE_OK:-false},
  "curve_syscall_gate": "${CURVE_GATE_STATE:-unknown}",
  "validator_log": "$VALIDATOR_LOG",
  "limits": [
    "A local cluster is not mainnet-beta: fees, congestion and validator set differ.",
    "The genesis hash is this cluster's own; it pins identity, not economics.",
    "Revoking the upgrade authority here proves the sequence, not a production deployment."
  ]
}
JSON
  log "evidence written to $EVIDENCE"
}

cleanup() {
  if [ -n "$VALIDATOR_PID" ] && kill -0 "$VALIDATOR_PID" 2>/dev/null; then
    log "stopping validator (pid $VALIDATOR_PID)"
    kill "$VALIDATOR_PID" 2>/dev/null || true
    for _ in $(seq 1 40); do
      kill -0 "$VALIDATOR_PID" 2>/dev/null || break
      sleep 0.25
    done
    kill -9 "$VALIDATOR_PID" 2>/dev/null || true
  fi
  write_evidence
}
trap cleanup EXIT

for tool in solana solana-test-validator solana-keygen; do
  command -v "$tool" >/dev/null 2>&1 || {
    log "missing $tool; run scripts/f8-install-solana-tools.sh and add its bin to PATH"
    exit 1
  }
done

[ -f "$PROGRAM_SO" ] || {
  log "escrow program object not found at $PROGRAM_SO"
  log "build it first: scripts/build-solana-program-v8.sh"
  exit 1
}

mkdir -p "$WORK"
PAYER="$WORK/payer.json"
PROGRAM_KEYPAIR="$WORK/program.json"
FUNDER="$WORK/funder.json"
BENEFICIARY="$WORK/beneficiary.json"
REFUND="$WORK/refund.json"
for keypair in "$PAYER" "$PROGRAM_KEYPAIR" "$FUNDER" "$BENEFICIARY" "$REFUND"; do
  solana-keygen new --no-bip39-passphrase --silent --force --outfile "$keypair" >/dev/null
done

log "starting validator on $RPC_URL"
# A fresh ledger every run: a reused ledger would carry escrow accounts from a
# previous scenario and a claim could pass on stale state.
rm -rf "$LEDGER"
solana-test-validator \
  --ledger "$LEDGER" \
  --rpc-port "$RPC_PORT" \
  --faucet-port "$FAUCET_PORT" \
  --quiet \
  --reset >"$VALIDATOR_LOG" 2>&1 &
VALIDATOR_PID=$!

log "waiting for the validator to answer"
ready=0
for _ in $(seq 1 120); do
  if solana --url "$RPC_URL" cluster-version >/dev/null 2>&1; then
    ready=1
    break
  fi
  kill -0 "$VALIDATOR_PID" 2>/dev/null || {
    log "validator exited during startup; see $VALIDATOR_LOG"
    exit 1
  }
  sleep 0.5
done
[ "$ready" = 1 ] || {
  log "validator did not become ready; see $VALIDATOR_LOG"
  exit 1
}

# The escrow claim verifies `secret * G` through `sol_curve_group_op`, so a
# cluster without that syscall cannot run this leg at all. Refuse early rather
# than fail later inside a claim, where the cause would be ambiguous.
#
# Read the gate carefully, because two shapes are both healthy and only one of
# them is a refusal:
#
#   * a gate line that says inactive  -> refuse, the syscall really is off;
#   * a gate line that says active    -> proceed;
#   * NO gate line at all             -> proceed. A feature gate is deleted from
#     the client once its activation is permanent, so an absent gate on a modern
#     cluster means the syscall is unconditionally on, not missing. Refusing here
#     would be refusing the newest clusters.
#
# The match is also order-insensitive: `feature status` prints the status in its
# first column and the description in its last, so a single regexp expecting
# "curve25519" before "active" would never match.
CURVE_GATE="$(solana --url "$RPC_URL" feature status 2>/dev/null | grep -i curve25519 || true)"
if [ -z "$CURVE_GATE" ]; then
  CURVE_OK=true
  CURVE_GATE_STATE="absent"
  log "no curve25519 feature gate is listed; the syscall is permanently enabled"
elif printf '%s\n' "$CURVE_GATE" | grep -qiE "inactive|pending"; then
  CURVE_OK=false
  CURVE_GATE_STATE="inactive"
  log "the curve25519 feature gate is NOT active on this cluster:"
  printf '%s\n' "$CURVE_GATE" >&2
  log "the escrow claim verifies secret*G through sol_curve_group_op and cannot run here"
  exit 1
else
  CURVE_OK=true
  CURVE_GATE_STATE="active"
  log "curve25519 feature gate reported active"
fi

GENESIS="$(solana --url "$RPC_URL" genesis-hash)"
log "genesis hash $GENESIS"

solana --url "$RPC_URL" config set --keypair "$PAYER" >/dev/null 2>&1 || true
log "funding the deploy payer and the three settlement roles"
# `airdrop` takes a recipient ADDRESS. Resolve every keypair to its pubkey
# rather than relying on the CLI to accept a path in that position.
PAYER_ADDRESS="$(solana-keygen pubkey "$PAYER")"
solana --url "$RPC_URL" airdrop 500 "$PAYER_ADDRESS" >/dev/null
log "funded payer $PAYER_ADDRESS"
for keypair in "$FUNDER" "$BENEFICIARY" "$REFUND"; do
  address="$(solana-keygen pubkey "$keypair")"
  solana --url "$RPC_URL" airdrop 100 "$address" >/dev/null
  log "funded $(basename "$keypair" .json) $address"
done

log "deploying the escrow through the upgradeable loader"
solana --url "$RPC_URL" program deploy \
  --keypair "$PAYER" \
  --program-id "$PROGRAM_KEYPAIR" \
  "$PROGRAM_SO" >"$WORK/deploy.log" 2>&1 || {
  log "deploy failed; see $WORK/deploy.log"
  exit 1
}
PROGRAM_ID="$(solana-keygen pubkey "$PROGRAM_KEYPAIR")"
log "deployed program $PROGRAM_ID"

log "revoking the upgrade authority"
# No `--skip-new-upgrade-authority-signer-check`: `--final` sets no new
# authority, so there is no new signer to skip checking, and passing both risks
# being refused as a conflicting argument.
solana --url "$RPC_URL" program set-upgrade-authority \
  --keypair "$PAYER" \
  --final "$PROGRAM_ID" >"$WORK/finalize.log" 2>&1 || {
  log "could not revoke the upgrade authority; see $WORK/finalize.log"
  exit 1
}
if solana --url "$RPC_URL" program show "$PROGRAM_ID" | grep -qi "Authority: none"; then
  REVOKED=true
else
  # Agave phrasing has varied; treat an absent authority line as revoked only
  # when the explicit one is gone, never assume it.
  if solana --url "$RPC_URL" program show "$PROGRAM_ID" | grep -qi "Authority:"; then
    REVOKED=false
    log "upgrade authority is still set; the daemon requires an immutable program"
    exit 1
  fi
  REVOKED=true
fi
log "upgrade authority revoked"

PROGRAMDATA="$(solana --url "$RPC_URL" program show "$PROGRAM_ID" \
  | awk -F': *' '/ProgramData Address/ {print $2}')"
[ -n "$PROGRAMDATA" ] || {
  log "could not read the ProgramData address"
  exit 1
}
log "programdata account $PROGRAMDATA"

# Measure the hash over the programdata account as the cluster holds it. This
# value is reported for the record; the scenario measures the same account over
# RPC itself and binds ITS OWN measurement into the setup, so a difference in how
# the CLI serializes its dump can never silently become the pinned hash.
if solana --url "$RPC_URL" account "$PROGRAMDATA" \
  --output-file "$WORK/programdata.bin" >/dev/null 2>&1; then
  PROGRAMDATA_SHA256="$(sha256sum "$WORK/programdata.bin" | awk '{print $1}')"
  log "programdata sha256 $PROGRAMDATA_SHA256"
else
  # Not fatal: the scenario measures this account over RPC itself and binds its
  # own measurement, so a CLI that cannot dump an account costs a record entry,
  # not the run.
  PROGRAMDATA_SHA256=""
  log "could not dump the programdata account; the scenario measures it itself"
fi

export DOM_SOLANA_LIVE_RPC_V1="$RPC_URL"
export DOM_SOLANA_LIVE_PROGRAM_V1="$PROGRAM_ID"
export DOM_SOLANA_LIVE_PROGRAMDATA_V1="$PROGRAMDATA"
export DOM_SOLANA_LIVE_PROGRAMDATA_SHA256_V1="$PROGRAMDATA_SHA256"
export DOM_SOLANA_LIVE_GENESIS_V1="$GENESIS"
export DOM_SOLANA_LIVE_PAYER_V1="$PAYER"
export DOM_SOLANA_LIVE_FUNDER_V1="$FUNDER"
export DOM_SOLANA_LIVE_BENEFICIARY_V1="$BENEFICIARY"
export DOM_SOLANA_LIVE_REFUND_V1="$REFUND"
export DOM_SOLANA_LIVE_DIR_V1="$WORK"

if [ "$#" -eq 0 ]; then
  STATUS="ready"
  log "no command supplied; printing the environment"
  env | grep '^DOM_SOLANA_LIVE_' | sort
  exit 0
fi

log "running: $*"
if "$@"; then
  STATUS="passed"
  log "command passed"
else
  code=$?
  STATUS="failed"
  log "command failed with exit $code"
  exit "$code"
fi
