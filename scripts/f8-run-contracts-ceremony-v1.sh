#!/usr/bin/env bash
# F8 -- drive the Contracts bootstrap ceremony between two parties.
#
# The ceremony is bilateral and file-based. `dom-interopd bootstrap-v13` is invoked once per
# party, with that party's plan and its own private work directory, and reads that party's
# secrets from stdin. Each invocation publishes the packets for the slots it owns, reports
# which peer packets it is still awaiting, and returns. The packets are then copied to the
# peer and the other party runs. When both have everything, the artifact is published and
# the report carries the two stage digests the manifest must pin.
#
# WHAT THIS SCRIPT DOES NOT DO: collapse the two custodies. Each invocation sees one party's
# secrets and one party's work directory, which is the flow the command is written for. What
# a single machine running both invocations does not prove is a custody separation, and this
# laboratory never had one -- the same thing its provisioner says about the condition scalar,
# the authority keys and the roster secrets.
#
# Only the names the report lists are copied. A work directory also holds that party's
# retained custody, and copying it wholesale would hand the peer material the ceremony
# exists to keep apart.
set -euo pipefail

BIN="${DOM_INTEROPD_BIN:?the release dom-interopd binary}"
CEREMONY_DIR="${DOM_CEREMONY_DIR:?the directory holding the plans and secrets}"
WORK_ROOT="${DOM_CEREMONY_WORK:?a private root for the two work directories}"
ARTIFACT_OUT="${DOM_CONTRACTS_BOOTSTRAP_OUT:?where to place the finished artifact}"
MAX_ROUNDS="${DOM_CEREMONY_MAX_ROUNDS:-8}"
ARTIFACT="contracts-bootstrap-v13.bin"

log() { printf 'f8-ceremony: %s\n' "$1" >&2; }

for tool in jq; do
  command -v "$tool" >/dev/null 2>&1 || {
    log "missing required tool: $tool"
    exit 1
  }
done
[ -x "$BIN" ] || {
  log "not executable: $BIN"
  exit 1
}

# Private, and created here rather than assumed: the command requires an absolute private
# directory and refuses anything else.
for slot in 0 1; do
  mkdir -p -m 700 "$WORK_ROOT/party-$slot"
  chmod 700 "$WORK_ROOT/party-$slot"
  [ -f "$CEREMONY_DIR/ceremony-plan-party-$slot.json" ] || {
    log "missing plan for party $slot"
    exit 1
  }
  [ -f "$CEREMONY_DIR/secrets-party-$slot.json" ] || {
    log "missing secrets for party $slot"
    exit 1
  }
done

report_for() { printf '%s/report-party-%s.json' "$WORK_ROOT" "$1"; }

run_party() {
  local slot="$1"
  local work="$WORK_ROOT/party-$slot"
  local report
  report="$(report_for "$slot")"
  # Secrets on stdin, never on the command line: an argument is visible in the process table.
  if ! "$BIN" bootstrap-v13 \
    --plan "$CEREMONY_DIR/ceremony-plan-party-$slot.json" \
    --work-dir "$work" \
    <"$CEREMONY_DIR/secrets-party-$slot.json" \
    >"$report" 2>"$report.err"; then
    log "party $slot refused the ceremony:"
    sed 's/^/  /' "$report.err" >&2
    # The plan is public data, and the refusal is one word for many conditions. Printing
    # what the party actually read is the difference between a diagnosis and a guess.
    log "the plan party $slot read:"
    sed 's/^/  /' "$CEREMONY_DIR/ceremony-plan-party-$slot.json" >&2
    log "the secrets it read, with the secret values redacted:"
    jq '{identity_passphrase_len: (.identity_passphrase|length),
         upstream_relay_secret_len: (.upstream_relay_secret|length),
         downstream_relay_secret_len: (.downstream_relay_secret|length),
         secrets_differ: (.upstream_relay_secret != .downstream_relay_secret)}' \
      "$CEREMONY_DIR/secrets-party-$slot.json" >&2
    exit 1
  fi
  local stage awaiting
  stage="$(jq -r '.stage' "$report")"
  awaiting="$(jq -r '.awaiting | length' "$report")"
  log "party $slot: stage=$stage awaiting=$awaiting"
}

# Copy exactly the packets this party published into the peer's work directory. The artifact
# is not a packet to exchange: whoever finishes has it, and it is collected separately.
publish_to_peer() {
  local slot="$1"
  local peer=$((1 - slot))
  local name
  while IFS= read -r name; do
    [ -z "$name" ] && continue
    [ "$name" = "$ARTIFACT" ] && continue
    if [ -f "$WORK_ROOT/party-$slot/$name" ]; then
      cp -p "$WORK_ROOT/party-$slot/$name" "$WORK_ROOT/party-$peer/$name"
    fi
  done < <(jq -r '.local_packets[]?' "$(report_for "$slot")")
}

complete_for() {
  local slot="$1"
  jq -e '.commit_stage_digest != null and .reveal_stage_digest != null' \
    "$(report_for "$slot")" >/dev/null 2>&1
}

round=0
while [ "$round" -lt "$MAX_ROUNDS" ]; do
  round=$((round + 1))
  log "round $round"
  for slot in 0 1; do
    run_party "$slot"
    publish_to_peer "$slot"
  done
  if complete_for 0 && complete_for 1; then
    log "both parties completed in $round round(s)"
    break
  fi
done

if ! (complete_for 0 && complete_for 1); then
  log "the ceremony did not complete in $MAX_ROUNDS rounds; the last reports are:"
  for slot in 0 1; do
    log "party $slot:"
    sed 's/^/  /' "$(report_for "$slot")" >&2
  done
  exit 1
fi

# The two parties must agree on the artifact and on both digests. A disagreement means they
# completed two different ceremonies, which is worth refusing here rather than discovering
# when the daemon compares the pins.
commit="$(jq -r '.commit_stage_digest' "$(report_for 0)")"
reveal="$(jq -r '.reveal_stage_digest' "$(report_for 0)")"
for slot in 0 1; do
  [ "$(jq -r '.commit_stage_digest' "$(report_for "$slot")")" = "$commit" ] || {
    log "the parties report different commit stage digests"
    exit 1
  }
  [ "$(jq -r '.reveal_stage_digest' "$(report_for "$slot")")" = "$reveal" ] || {
    log "the parties report different reveal stage digests"
    exit 1
  }
done

found=""
for slot in 0 1; do
  if [ -f "$WORK_ROOT/party-$slot/$ARTIFACT" ]; then
    if [ -n "$found" ]; then
      cmp -s "$found" "$WORK_ROOT/party-$slot/$ARTIFACT" || {
        log "the parties published different artifacts"
        exit 1
      }
    else
      found="$WORK_ROOT/party-$slot/$ARTIFACT"
    fi
  fi
done
[ -n "$found" ] || {
  log "both parties completed and neither published $ARTIFACT"
  exit 1
}

install -m 600 "$found" "$ARTIFACT_OUT"
log "artifact at $ARTIFACT_OUT"
printf 'commit_stage_digest=%s\n' "$commit"
printf 'reveal_stage_digest=%s\n' "$reveal"
