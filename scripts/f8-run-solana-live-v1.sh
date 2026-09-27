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
#   DOM_SOLANA_LIVE_PROGRAM_SO_V1    the object that was loaded, so the scenario
#                                    can prove the on-chain bytes are those bytes
#   DOM_SOLANA_LIVE_MINT_V1          legacy SPL mint, base58
#   DOM_SOLANA_LIVE_MINT_DECIMALS_V1 its decimals; the escrow's transfer_checked
#                                    fails if the frozen setup disagrees
#   DOM_SOLANA_LIVE_FUNDER_TOKEN_V1       funded source token account
#   DOM_SOLANA_LIVE_BENEFICIARY_TOKEN_V1  destination owned by the beneficiary
#   DOM_SOLANA_LIVE_REFUND_TOKEN_V1       destination owned by the refund role
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
# The program id is NOT ours to pick. `processor::process` refuses any
# invocation whose program_id differs from the one `declare_id!` fixes in the
# source, so a deployment to a freshly generated keypair has every instruction
# rejected at the door -- which is precisely how run 36282372857 failed, all
# three scenarios dying on their first Solana transaction. Read the declared id
# out of the source so it can never drift from what the program enforces.
PROGRAM_SOURCE="$ROOT/programs/dom-solana-escrow/src/lib.rs"
PROGRAM_ID="${DOM_SOLANA_PROGRAM_ID_V1:-$(sed -n 's/.*declare_id!("\([^"]*\)").*/\1/p' "$PROGRAM_SOURCE" | head -1)}"
[ -n "$PROGRAM_ID" ] || {
  printf 'f8-solana-live: could not read declare_id! from %s\n' "$PROGRAM_SOURCE" >&2
  exit 1
}
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
  "upgrade_authority": "${UPGRADE_AUTHORITY:-unknown}",
  "curve_syscall_enabled": ${CURVE_OK:-false},
  "curve_syscall_gate": "${CURVE_GATE_STATE:-unknown}",
  "spl_mint": "${MINT:-}",
  "spl_mint_decimals": ${MINT_DECIMALS:-0},
  "validator_log": "$VALIDATOR_LOG",
  "limits": [
    "A local cluster is not mainnet-beta: fees, congestion and validator set differ.",
    "The genesis hash is this cluster's own; it pins identity, not economics.",
    "The program is loaded into genesis at its declared id with an unsignable upgrade authority. That makes upgrades impossible on this cluster, which is not the same act as deploying to mainnet and revoking a real authority.",
    "The program id is the one declare_id! fixes in the source, because the program refuses to run under any other; no keypair for it exists in this repository, so a normal deployment to that id is not possible here."
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

for tool in solana solana-test-validator solana-keygen spl-token; do
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
# Held only so the genesis-loaded program has an authority that CAN be revoked.
# `--upgradeable-program ... none` writes Some(11111111111111111111111111111111),
# and `solana-program-attestation` -- this project's own rule for an immutable
# program -- requires the bincode Option tag to be 0, a real None. So the program
# starts with an authority we hold and that authority is revoked below.
UPGRADE_AUTHORITY_KEYPAIR="$WORK/upgrade-authority.json"
FUNDER="$WORK/funder.json"
BENEFICIARY="$WORK/beneficiary.json"
REFUND="$WORK/refund.json"
for keypair in "$PAYER" "$UPGRADE_AUTHORITY_KEYPAIR" "$FUNDER" "$BENEFICIARY" "$REFUND"; do
  solana-keygen new --no-bip39-passphrase --silent --force --outfile "$keypair" >/dev/null
done

log "starting validator on $RPC_URL"
# A fresh ledger every run: a reused ledger would carry escrow accounts from a
# previous scenario and a claim could pass on stale state.
rm -rf "$LEDGER"
# No `--quiet`: it silences exactly the `Program log` lines that say WHY a
# transaction was refused, and run 36282372857 lost them -- its validator.log was
# four lines long while three scenarios died on a refusal with no stated cause.
# The log is verbose and is uploaded as an artifact, which is the right trade for
# being able to diagnose a refusal without spending another run on it.
# `--upgradeable-program <ADDRESS> <SO> none` puts the program at its declared
# id, through the upgradeable loader -- so a programdata account exists and the
# hash the daemon binds still means something -- and with the authority set to
# "none" it is immutable from the genesis slot. That is stronger than deploying
# and then revoking, and it removes two CLI steps whose output this harness would
# otherwise have to parse.
solana-test-validator \
  --ledger "$LEDGER" \
  --rpc-port "$RPC_PORT" \
  --faucet-port "$FAUCET_PORT" \
  --upgradeable-program "$PROGRAM_ID" "$PROGRAM_SO" "$UPGRADE_AUTHORITY_KEYPAIR" \
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
# The upgrade authority only signs the revocation and pays nothing, but a signer
# whose account does not exist is a needless way for that step to fail.
solana --url "$RPC_URL" airdrop 1 "$(solana-keygen pubkey "$UPGRADE_AUTHORITY_KEYPAIR")" >/dev/null

# ── the legacy SPL asset ────────────────────────────────────────────────────
# The escrow's token path requires `spl_token::id()`, the LEGACY program, so it is
# named outright rather than left to the CLI's default, which can follow
# Token-2022. Every address below is the pubkey of a keypair generated here: this
# harness does not read addresses out of a CLI's prose, which is where several of
# its earlier failures came from.
LEGACY_TOKEN_PROGRAM="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
MINT_DECIMALS="${DOM_SOLANA_LIVE_MINT_DECIMALS_V1:-6}"
MINT_SUPPLY_UI="${DOM_SOLANA_LIVE_MINT_SUPPLY_UI_V1:-1000}"
MINT_KEYPAIR="$WORK/mint.json"
FUNDER_TOKEN_KEYPAIR="$WORK/funder-token.json"
BENEFICIARY_TOKEN_KEYPAIR="$WORK/beneficiary-token.json"
REFUND_TOKEN_KEYPAIR="$WORK/refund-token.json"
for keypair in "$MINT_KEYPAIR" "$FUNDER_TOKEN_KEYPAIR" "$BENEFICIARY_TOKEN_KEYPAIR" \
  "$REFUND_TOKEN_KEYPAIR"; do
  solana-keygen new --no-bip39-passphrase --silent --force --outfile "$keypair" >/dev/null
done
MINT="$(solana-keygen pubkey "$MINT_KEYPAIR")"
FUNDER_TOKEN="$(solana-keygen pubkey "$FUNDER_TOKEN_KEYPAIR")"
BENEFICIARY_TOKEN="$(solana-keygen pubkey "$BENEFICIARY_TOKEN_KEYPAIR")"
REFUND_TOKEN="$(solana-keygen pubkey "$REFUND_TOKEN_KEYPAIR")"

log "creating the legacy SPL mint $MINT with $MINT_DECIMALS decimals"
spl-token --url "$RPC_URL" --fee-payer "$PAYER" --program-id "$LEGACY_TOKEN_PROGRAM" \
  create-token --decimals "$MINT_DECIMALS" "$MINT_KEYPAIR" >"$WORK/spl.log" 2>&1 || {
  log "could not create the SPL mint; see $WORK/spl.log"
  exit 1
}
# One token account per settlement role, OWNED BY that role: the escrow's terminal
# transfer refuses a destination whose owner is not the recipient the terms froze.
for entry in "funder:$FUNDER:$FUNDER_TOKEN_KEYPAIR" \
  "beneficiary:$BENEFICIARY:$BENEFICIARY_TOKEN_KEYPAIR" \
  "refund:$REFUND:$REFUND_TOKEN_KEYPAIR"; do
  role="${entry%%:*}"
  rest="${entry#*:}"
  owner_keypair="${rest%%:*}"
  account_keypair="${rest#*:}"
  owner="$(solana-keygen pubkey "$owner_keypair")"
  spl-token --url "$RPC_URL" --fee-payer "$PAYER" \
    create-account "$MINT" "$account_keypair" --owner "$owner" \
    >>"$WORK/spl.log" 2>&1 || {
    log "could not create the $role token account; see $WORK/spl.log"
    exit 1
  }
  log "token account for $role: $(solana-keygen pubkey "$account_keypair") owned by $owner"
done
log "minting $MINT_SUPPLY_UI tokens to the funder's token account"
spl-token --url "$RPC_URL" --fee-payer "$PAYER" \
  mint "$MINT" "$MINT_SUPPLY_UI" "$FUNDER_TOKEN" >>"$WORK/spl.log" 2>&1 || {
  log "could not mint to the funder's token account; see $WORK/spl.log"
  exit 1
}

log "verifying the genesis-loaded program $PROGRAM_ID"
solana --url "$RPC_URL" program show "$PROGRAM_ID" >"$WORK/program-show.log" 2>&1 || {
  log "the program is not present at its declared id; see $WORK/program-show.log"
  exit 1
}
# Revoke for real. The authority is ours, so `--final` can be signed; the payer
# stays the fee payer. This is the step that turns Some(<key>) into None, and
# `solana-program-attestation` accepts nothing else.
log "revoking the upgrade authority"
solana --url "$RPC_URL" program set-upgrade-authority \
  --keypair "$PAYER" \
  --upgrade-authority "$UPGRADE_AUTHORITY_KEYPAIR" \
  --final "$PROGRAM_ID" >"$WORK/finalize.log" 2>&1 || {
  log "could not revoke the upgrade authority; see $WORK/finalize.log"
  exit 1
}
solana --url "$RPC_URL" program show "$PROGRAM_ID" >"$WORK/program-show.log" 2>&1 || {
  log "the program disappeared after revoking; see $WORK/program-show.log"
  exit 1
}

# Only an absent authority passes. A line naming any key -- including
# 11111111111111111111111111111111, which would mean the revoke did not take --
# is refused. The scenario re-establishes the same fact through
# `attest_immutable_program`, over an RPC quorum, from the account's own bytes.
AUTHORITY_LINE="$(grep -i "^Authority:" "$WORK/program-show.log" | head -1 | sed 's/^[Aa]uthority: *//')"
if [ -z "$AUTHORITY_LINE" ] || [ "$AUTHORITY_LINE" = "none" ] || [ "$AUTHORITY_LINE" = "None" ]; then
  REVOKED=true
  UPGRADE_AUTHORITY="none"
  log "upgrade authority revoked; the program is immutable"
else
  REVOKED=false
  UPGRADE_AUTHORITY="$AUTHORITY_LINE"
  log "the upgrade authority is still $AUTHORITY_LINE; refusing"
  sed -n '1,20p' "$WORK/program-show.log" >&2
  exit 1
fi

# Read it out of the answer already saved above rather than asking twice.
PROGRAMDATA="$(awk -F': *' '/ProgramData Address/ {print $2}' "$WORK/program-show.log")"
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
export DOM_SOLANA_LIVE_PROGRAM_SO_V1="$PROGRAM_SO"
export DOM_SOLANA_LIVE_MINT_V1="$MINT"
export DOM_SOLANA_LIVE_MINT_DECIMALS_V1="$MINT_DECIMALS"
export DOM_SOLANA_LIVE_FUNDER_TOKEN_V1="$FUNDER_TOKEN"
export DOM_SOLANA_LIVE_BENEFICIARY_TOKEN_V1="$BENEFICIARY_TOKEN"
export DOM_SOLANA_LIVE_REFUND_TOKEN_V1="$REFUND_TOKEN"
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
