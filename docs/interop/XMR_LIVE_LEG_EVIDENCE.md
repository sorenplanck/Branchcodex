# Complementary DOM↔XMR live-daemon evidence

This suite ports the ten startup/custody/restart scenarios from `b6e1d8a` onto
the current production harness. It does **not** replace the existing real-daemon
claim, DOM compensation, or XMR refund-after-public-U scenarios. No result has
been obtained merely by writing these tests.

## Scope

The release-production daemon is real; both chain histories and all endpoints
are private loopback fixtures using Mainnet profiles. Transactions enter the
native local validators. Nothing is submitted to a public chain and no real
funds move. This is not mined-mainnet acceptance evidence.

The current enrollment, operational F6/bundle writers, mutable funding producer
and `NativeXmrRunningColdStartV23` remain in use. Native XMR candidates start
unconfirmed. The supplemental observer includes **only Funding** transactions
already dispatched by the daemon and correlated to the exact route/coordinator
effect. Unknown pool entries, Claim and Refund transactions are not included by
this suite. No private T/U scalar is read or injected.

| Group | Cases | What must actually be observed |
|---|---:|---|
| startup | 3 | XMR-only resources, live single-owner refusals, stopped Create refusal and accepted Reopen |
| funding | 2 | Durable restart/crash behavior; clean-shutdown case additionally requires native F7 gate and irreversible funding authorization on both positions |
| refund | 3 | Both directions of peerless restart and repeated absence; signed recovery graph retained where required |
| custody | 2 | Repeated crash/reopen and corrupt-public-input refusal followed by exact restoration and accepted reopen |

The refund group does not prove a refund was built, broadcast or finalized.
The custody group does not restart the independent GPL sidecar or prove public
LOAD without its private build plan; the existing V24 publication scenario
provides that separate coverage. A corrupted JSON byte proves refusal of that
input, not independently a particular cross-curve cryptographic equation.

Authenticated Contracts readings happen only after the owning daemon is
stopped/reaped. They compare session scope, revision, irreversible flags,
retained native F7 gate and accepted recovery graph messages. The refusal test
requires these readings to be **equal**, not merely nondecreasing. File-size
inventories are additional presence checks, never proof of economic settlement
or complete byte-for-byte Store immutability.

Progress scenarios poll once per second and return as soon as both actors retain
Funding on both positions, with a 7200-second maximum, instead of sleeping for
300 seconds and assuming readiness. Abort/exit-only state or a failed process
fails immediately. Aggregate Committed is only a stop-and-inspect trigger; the
post-reap authenticated F7/graph assertions remain mandatory. Startup-only
observations retain their explicit 30-second liveness interval.

## Bounded live negotiation, not relaxed production

`prepare_live_bounded_v24` is a separate test-only entry point. All existing
callers retain their original `+100` DOM horizon. The live route negotiates
`+900` blocks before ceremony/signatures, keeping the existing local time policy:
anchor skew **1800 seconds**, evidence age **21600 seconds**, width 600 seconds
and hub margin 300 seconds. No signed route is extended or repaired later.

With baseline 1003 and the signed DOM timing bounds 1–2 seconds/block, the live
downstream deadline is 1903 and the conservative upstream deadline is 4707.
The bounded window includes baseline anchor plus at most 4095 additional blocks,
ending at 5098. Preflight reserves another 256 blocks beyond upstream for the
entire supported compensation span (at most 128), confirmations (at most 64),
and inclusion/reconciliation. Unsupported arithmetic, policy spans or finality
are refused rather than clamped. The original compensation span is preserved.

The window is a quantity bound, not a new absolute-height bound. The authenticated
baseline remains available through paginated RPC for genesis-based replay;
ledger heights, UTXOs and hash links are never rebased. Read materialization and
the scanner's retained window remain bounded. The `tip+2000` handoff patch is
not applied: it exceeds the supported recovery horizon under this policy.

The 900-block horizon provides room for the reported 300–700 second slow setup;
it does not guarantee completion on arbitrarily slow hardware. Production time
checks continue to refuse genuinely expired evidence or deadlines.

## Execution and evidence

The manual `xmr-live-leg` workflow uses GitHub-hosted Linux runners and the
existing pinned `.github/actions/xmr-test-tools` action. It compiles the GPL
tools and release daemon from the selected sources. Each selected case gets
its own runner and a 150-minute scenario budget; failure does not cancel other
cases. Shared regressions run once within this dispatched campaign. Existing
mandatory economic workflows remain unchanged.

Local invocation, **only after implementation is complete and test execution
is authorized**, requires the same three executable inputs and daemon digest
as the existing native-daemon runner:

```bash
bash scripts/run-xmr-live-leg-v23.sh --group startup \
  --evidence-dir /absolute/private/evidence-directory --timeout-seconds 9000
```

Groups are `startup`, `funding`, `refund`, `custody`, or `all`. The wrapper does
not rebuild a possibly running binary. Supply `DOM_INTEROP_REAL_BINARY_V23`,
`DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23`, `DOM_XMR_REAL_SIDECAR_V23`, and
`DOM_XMR_OFFLINE_FUNDING_HELPER_V23` from one compatible build. The daemon must
match the test binary's commit and lockfile metadata.

The runner reuses the existing isolated process owner and evidence recorder:

- Each allowlisted full test name runs with `--ignored --exact`, `crypto-test`,
  two build jobs and one test thread. Zero tests, another test, absent artifacts
  or a missing passing summary are failures.
- Dependency fingerprints are checked before and after each case.
- Original synthetic fixtures are retained after daemon/helper cleanup on both
  success and failure, alongside logs and actual result JSON. Retention itself
  makes no success claim; the exact libtest outcome determines success.
- PID identity/subreaper cleanup is scoped to the launched descendants. An
  inconclusive cleanup prevents the next local case and prevents archiving live
  writers as consistent Store evidence.
- Synthetic temporary roots use the shared runner's short owner-only base
  under the invoking user's canonical `HOME/.dx-v23`, never world-writable `/tmp`.
  Symlinks, foreign owners, writable ancestors and an excessive UDS path
  budget are refused; existing user directory permissions are not changed.
  After successful archival and verified cleanup, the owned temporary case
  directory is removed by that same shared implementation.
- GitHub always uploads the outcome directory, including a `not-run` result if
  prerequisites fail. No `continue-on-error` hides failures.

Do not present these ten additional observations as a completed mainnet leg.
Release readiness still requires the independent economic terminal scenarios
and the separately authorized controlled mainnet validation.
