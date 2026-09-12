# Public interoperability verifier fixtures

`bip340-public.json` preserves all 19 verification cases from Bitcoin BIP340,
omitting signing keys and auxiliary randomness. `bip341-default-public.json`
contains the public SIGHASH_DEFAULT case from the BIP341 wallet test vectors.
Each file records its upstream URL and the SHA-256 of the full downloaded file.
The tests run offline against these checked-in snapshots.

Sources: https://github.com/bitcoin/bips/tree/master/bip-0340 and
https://github.com/bitcoin/bips/tree/master/bip-0341.
BIP340 authors: Pieter Wuille, Jonas Nick, Tim Ruffing (BSD-2-Clause;
code additionally offered under MIT or CC0-1.0).
BIP341 authors: Pieter Wuille, Jonas Nick, Anthony Towns (BSD-3-Clause).
The public numeric test vectors are used for specification conformance.
No upstream implementation code was copied into the verifier.

`synthetic-bitcoin-claim.json` is an artificial, offline, one-input claim
fixture generated for these tests. Its funding input is fictional and it has
never been observed on a chain. It is not a production swap or recovery result.
The fixture generation used a publicly known toy key; no wallet keys appear
in the JSON. Mutation tests use it to exercise the frozen economics and strict
transaction parser, while the independent BIP vectors check cryptographic
results against published expected values.
