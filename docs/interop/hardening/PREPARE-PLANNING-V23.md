# Production planning before F6

`prepare-planning-v23` derives the public route pins required by
`prepare-f6-artifact-v23` from actual signed deployment-registry and route-time
artifacts. It needs no existing daemon manifest, F6 bundle, participant DLEQ,
Contracts ceremony, credentials or private key. It makes no network requests,
invokes no signer, moves no funds and changes no L1 rule.

Build the daemon with its production feature using the project's normal build
process. The operational command is:

```text
dom-interopd prepare-planning-v23 --input /absolute/private/planning-input.json --output-dir /absolute/private/new-planning
```

The input file must be a regular, single-link, owner-owned `0600` file. Its
parent and the output parent must be canonical, owner-owned `0700` directories.
Artifact files follow the same rules. Symlinks, hard links, noncanonical paths,
unknown JSON fields and malformed canonical encodings are refused. The JSON
input and retained snapshot are limited to 1 MiB; each decoded artifact is
limited to 256 KiB.

## Input

The JSON object accepts only these fields:

| Field | Value |
| --- | --- |
| `schema` | `DOM-PRE-F6-PLANNING-INPUT-V23` |
| `network_id` | Actual registry network ID, array of 32 bytes |
| `route_id` | Negotiated route ID matching the Relay roster, array of 32 bytes |
| `minimum_registry_epoch` | Operator's minimum permitted registry epoch |
| `authorities` | Canonical `ProductionAuthorityBundleV1` containing the three distinct registry, time-policy and time-evidence authority sets |
| `signed_registry` | Canonical `SignedRegistryV1`, with actual threshold signatures |
| `upstream_terms` | Canonical negotiated upstream `SettlementTermsV1` |
| `downstream_terms` | Canonical negotiated downstream `SettlementTermsV1` |
| `relay_roster` | Canonical `ProductionRelayRosterBundleV1` matching both terms, their participant ordering and public keys |
| `signed_time_policy` | Canonical `SignedRouteTimePolicyV2` for those exact registry profiles and terms |
| `signed_time_evidence` | Canonical `SignedRouteTimeEvidenceV2`, with currently valid signed checkpoints |

Each artifact field uses one of these two forms:

```json
{"source":"file","path":"/absolute/private/signed-registry.bin"}
```

```json
{"source":"canonical_hex","hex":"<complete lowercase canonical hex>"}
```

The placeholder is explanatory, not a valid artifact. Do not substitute
arbitrary digests, signatures, keys or IDs. Obtain the signed artifacts from
their actual negotiated authorities. This command verifies signatures under
the supplied roots; choosing and independently pinning the trusted roots is
still the operator's responsibility.

There is deliberately no `now_seconds` parameter. The command uses the system
clock for current registry and time-evidence checks. The composition digest is
anchored at the signed evidence's observation time, exactly as in the daemon's
create loader. Consequently a normal startup delay does not change the F6
composition pin. Current expiry, rollback and retained checkpoint ancestry are
checked separately at entry and again before publication; the signed validity
window is never lengthened.

## Output and F6 handoff

Successful publication creates one new directory containing:

- `route-pins.json`: the complete seven-field `route` object for the F6 public
  signing-request input: network, route, composition, route scope, registry
  digest, registry epoch and profile-bundle digest. Copy this object without
  changing its values into the F6 input's `route` field.
- `public-input.json`: the exact accepted public input snapshot, with file
  references replaced by their immutable canonical hexadecimal bytes.
- `planning-report.json`: the same route pins, supplied registry-root digest,
  signed original validation time and actual final freshness-check time. The
  report explicitly states that it grants no funding authority and made no
  network request.
- `planning-registry.sqlite`, `planning-time.sqlite`, and any backend-owned
  lock/SQLite sidecars: dedicated authenticated planning state, not the daemon's
  mutable runtime state. Keep these files together with the export.

The F6 workflow still needs its real economics, inventory and bond bindings,
independent signer endpoints, externally supplied signatures and claim profile.
This planner does not invent any of them. Follow `PREPARE-F6-ARTIFACT-V23.md`.
The daemon must independently authenticate the resulting F6 bundle and all
other required route artifacts before operation. A planning report, even when
fresh, is never a signing, custody, funding or mainnet-readiness authorization.

All stores are closed and files/directories synced before the staging directory
is published with a no-replace atomic rename. Existing output is never changed.
If verification or storage fails after creation begins, an owner-only sibling
named `<output>.preparing-v23` is deliberately retained. No report is published
as successful, and another invocation refuses that staging state instead of
repairing it, deleting it or resetting its rollback history. Preserve it for
diagnosis; do not relabel partial output as complete. To make a separate plan,
use a new output name with current signed inputs. New evidence may legitimately
produce a new composition digest and therefore requires fresh corresponding
F6 request signatures; never silently reuse old signatures.

## Written regressions

The dedicated Rust regressions cover deterministic real pins across startup
delays, equivalence to the authenticated admission, rejected registry/signature
and scope changes, time-signature refusal, expiry during preparation, clock
rollback, no-overwrite and retained partial state, linked/broad-permission input
refusal, rejected private/clock JSON fields, directory substitution, and immutable
snapshots of file-sourced public artifacts. They are intended for the coordinated
test run; writing this interface does not itself establish that they have passed.
