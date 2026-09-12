# Dedicated real-daemon DOM↔XMR scenarios

Implementation and CI wiring are written; this document is not evidence that
the scenarios have run or passed. No mainnet readiness is claimed by writing
them. These use synthetic keys and local RPC ledgers with mainnet identities
and unchanged L1 rules, not public-network funds or deployments.

`heavy-tests.yml` selects dedicated `dom-xmr-real-daemon` and
`dom-xmr-real-refund` jobs on pushes to `codex/domxmr` and dispatches selecting
`all` or `dom-xmr-native`. The heavy gate requires both jobs to succeed when
selected; a skipped job does not satisfy it. Both jobs first prepare pinned
GPL tools with `xmr-test-tools` and its `real-daemon: 'true'` input, then build the
real `dom-interopd` release executable with `--no-default-features --features
production`. Its BLAKE2b-256 digest is supplied to the Rust binary verifier,
which also checks the executable's production build identity.

## Three distinct scenarios, no shared machine concurrency

All full test names start with:

```text
production_contracts_bootstrap::producer_v13::native_ceremony_tests::xmr_coldstart_v23::daemon_scenario_v23::
```

- `native_real_daemon_two_claims_survive_original_store_reopen_v23`: fresh
  negotiation, real daemon launch, both final claims, authenticated original
  store replay, and actual daemon reopen with unchanged economic identities.
- `native_real_daemon_dom_compensation_without_counterparty_v23`: a separately
  constructed route, validated DOM collateral held before inclusion, actual
  process crashes, exact inclusion after the counterparty is gone, and
  survivor compensation in DOM across the original negotiated deadlines. The
  economic predicate requires the exact collateral identity and rejects an
  unfunded abort; this is explicitly **not** counted as an XMR refund. XMR pool
  inclusion is scoped to transaction identities observed in authenticated
  route state.
- `native_real_daemon_xmr_refund_after_public_u_without_counterparty_v23`:
  real independent XMR refund BUILD after public U: keep the XMR funder stopped
  while only the DOM U owner runs; observe the original refund template in the
  native-validated public DOM history at the negotiated depth, then remove/reap
  that peer. Require the survivor's original state inventory to be unchanged
  and its refund still unprepared before reopening only that survivor. Its new
  exact refund must enter the verified XMR pool and then reach native finality.
  No scalar, private peer state, transport request or authority token is supplied
  by the scenario. This is distinct from compensation in DOM.

The runner invokes each exact name using:

```text
cargo test --locked -p dom-interopd --no-default-features --features production --lib --profile crypto-test FULL_TEST_NAME -- --ignored --exact --nocapture --test-threads=1 --color never
```

It requires exit status zero, the **exact selected test name**, exactly one
`running 1 test` record and exactly one passing-test summary for each case.
Cargo's zero-test success cannot borrow a helper's summary to pass this gate. The ignored attributes
only prevent accidental heavy execution in component suites; the dedicated
jobs explicitly select all three. Claims and DOM compensation run serially
on one runner. XMR refund runs on another isolated runner, without depending
on the first job's success. No whole-suite rerun is hidden here.

## Evidence, time limits, and process ownership

The workflow runs the following after all implementation is ready:

```sh
python3 scripts/run_native_daemon_scenario_v23.py \
  --evidence-dir "$RUNNER_TEMP/dom-xmr-real-evidence" --timeout-seconds 9000 \
  --scenario native_real_daemon_two_claims_survive_original_store_reopen_v23 \
  --scenario native_real_daemon_dom_compensation_without_counterparty_v23
```

The isolated refund job selects only its allowlisted case:

```sh
python3 scripts/run_native_daemon_scenario_v23.py \
  --evidence-dir "$RUNNER_TEMP/dom-xmr-refund-evidence" --timeout-seconds 9000 \
  --scenario native_real_daemon_xmr_refund_after_public_u_without_counterparty_v23
```

Dependencies are explicit environment variables:
`DOM_INTEROP_REAL_BINARY_V23`, `DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23`,
`DOM_XMR_REAL_SIDECAR_V23`, and `DOM_XMR_OFFLINE_FUNDING_HELPER_V23`.
Missing tools fail; there is no simulation fallback.
The runner fingerprints all three executables before and after each scenario
and records their bytes, inode identity and BLAKE2b-256 digests in its result.
The production daemon's supplied digest must match the actual executable.

The shared preparation action also runs the sidecar's
`auth::local_refund_tests_v24` and `cache::build_v23_tests` regressions with the
same optimized profile, serially. These cover the separated BUILD/LOAD tags,
authenticated Ready data and public reads after cache reopen and private-plan
retirement. They do not substitute for the real daemon's economic scenarios.
Before long scenarios, `peer_sidecar_v23::` also exercises the private-path,
fresh authenticated handshake and cache lifetime guards. These unit tests do
not by themselves demonstrate a real sidecar restart or economic recovery.

`scripts/scoped_boundary_regressions_v24.py` runs twenty-five fixed selections
serially with `--locked --profile crypto-test`. Each selection must report its
required test names, a nonzero executed count and a successful summary. This
separately exercises dependency tests that `cargo test -p dom-interopd` does not
run: bounded DOM/XMR submission and observation, original F7 observation age,
refund transport grants, public proof/authentication scopes and Relay expiry
replay. Per-selection logs and results are retained even on failure. The
sidecar API and spend-port packages have no native tests; their compilation as
dependencies is recorded as compilation only, not passing test coverage.
On a branch push this shared regression campaign runs once in
`interop-hardening`; the parallel heavy runners set `run-once-regressions=false`
and reuse their own required compile/tool caches instead of repeating all
twenty-five selections before each long scenario.

Each case gets a private short temporary path (to respect Unix socket pathname
limits), bounded live log, real return code, elapsed time, and JSON result. A
campaign result remains `not-run` when prerequisites prevent execution. Each
case is limited to 150 minutes. The claims/compensation job has a 360-minute
overall limit including preparation; the isolated refund job has a 240-minute
limit. Cases are never shortened to fit a shared runner budget.
Host cancellation or an exhausted overall limit is not passing evidence.

Linux session ownership, child-subreaper adoption, `/proc` ancestry and start
ticks, and pidfd signaling identify only this runner's descendants. This
covers the daemon's separate process group and orphaned helper processes.
After any result, cleanup must be verified before another case starts. A
failed case can be followed by the other case only after that cleanup; the
aggregate stays failed. Unknown cleanup state stops the campaign. Live
descendants remaining after an otherwise successful test also fail the case.

Successful scenarios retain their original synthetic fixture after explicitly
reaping both daemon owners. The runner independently verifies that all helper
descendants have stopped before archiving, and refuses a passing result without
a fixture archive. No live database is copied to manufacture restart evidence.

Failure and timeout leave synthetic fixture contents under that case's private
temporary directory, recorded in its result; an archive preserves file modes
and never follows symlinks. The artifact contains per-case logs/results,
campaign status, binary digest, and
available original fixture archives, with seven-day retention. Abrupt host
termination can prevent final archival; it never creates a success result.
Only synthetic test credentials are archived, never operator wallets.

The lightweight Python checks passed on the working tree: six campaign checks,
sixteen dispatch checks, six scoped-selection checks and four offline-tool
installer checks. These exercise
CI selection, result validation and artifact handling, not the Rust economic
flows. The newly written Rust/GPL regressions and real-daemon scenarios still
require execution on the integrated candidate.
