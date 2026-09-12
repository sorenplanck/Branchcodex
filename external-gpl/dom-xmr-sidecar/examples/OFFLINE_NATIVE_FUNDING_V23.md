# Offline native funding fixture

This GPL example is copied by the existing Eigenwallet graft installer, alongside
the production sidecar. It must use the workspace fixed by
`docs/interop/xmr-v6/SOURCE_LOCK.json`: Eigenwallet
`0e17c7f7cd8f0657af176c8852aa4c9949586051` and monero-oxide
`c8be5d3d1287669946a83fbfcb296ce2a8852e47`. It is not part of the DOM daemon or
the root workspace. No upstream sources or source locks are changed.

The example receives one bounded JSON line on stdin:

```json
{"schema":"DOM-XMR-OFFLINE-FUNDING-REQUEST-V23","combined_spend_public_key":"<32-byte hex>","amount_piconero":100,"max_fee_piconero":10000}
```

It rejects a signed transaction whose fee exceeds `max_fee_piconero`, which
must come from the scenario terms frozen before C/D and setup initialization.
The original Funding-only scenario retains its unchanged fee policy.

It signs a complete Monero V2 CLSAG/Bulletproofs+ transaction paying that public
spend key with the test-only view key 13 used by `NativeXmrCustodyFixtureV23`.
The input and ring are synthetic local test data, with actual matching signing
keys. They are **not existing blockchain funds**, and the resulting transaction
is not claimed to be mined, consensus-admitted or broadcastable on any network.
Neither private T nor private U is received or printed.

Before publishing a result, it:

- requires canonical full transaction roundtrip;
- derives the real transaction and prunable hashes from those signed bytes;
- starts two read-only loopback RPC endpoints containing precisely those bytes;
- uses the real `MoneroDaemon<SimpleRequestTransport>` and the pinned
  `monero_wallet_ng::verify::largest_received_utxo` to scan the output;
- requires the exact native amount, and rejects the wrong view and spend keys.

Only then does stdout receive `DOM-XMR-OFFLINE-FUNDING-V23`: public destination,
public spend/view keys, amount, complete transaction hex, derived tx hash and
the two loopback URLs. Its scope is explicitly
`local-component-only-no-chain-funding`. RPC block locations/finality are a
fixed local simulation, not network evidence. Unsupported methods, including
transaction submission, return 404. EOF or `STOP` on stdin closes the RPC owner.

The Claim fixture must invoke this **before** `initialize_custody`, derive/check
the transaction hash using the MIT `xmr_raw_tx_verify` parser, compare spend,
view, amount and destination, and put that derived hash into the authenticated
setup. It must retain the helper process until all observations/reopens finish.
The real sidecar should scan these RPC bytes, using the actual encrypted native
SecretStore view key; no positive UDS echo is a substitute. A separate local DOM
scanner snapshot must contain the exact signed DOM funding bytes. Finally, the
concrete bounded F7 verifier, not this envelope, issues the opaque authorization
required by `claim_after_observed_funding`.

Missing helper/sidecar/observer infrastructure is a hard incomplete fixture,
not a silently skipped or successful Claim test. This code has been written
without running the generator, compiling, or executing tests.
