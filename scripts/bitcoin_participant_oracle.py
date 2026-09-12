#!/usr/bin/env python3
"""Independent offline verifier of V3 participant message authentication.

Public inputs only; no signing or networking. Pins must be authenticated outside
this program. This checks packet signatures/scope, not M.8 proofs, MuSig2 partial
validity, chain finality, participant liveness or a complete production swap.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from bitcoin_claim_oracle import Refused, hex_bytes, require, unique_object, verify_schnorr

DOMAIN = b"DOM-INTEROP/BTC-ACTUATOR/PARTICIPANT-MESSAGE/V3\0"
MAX_CASE = 16_384


def fields(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected), "unexpected fields")


def nonzero32(value):
    result = hex_bytes(value, 32, 32)
    require(result != bytes(32), "zero identity")
    return result


def verify_packet(raw, phase, role, identity, public_key, scope):
    require(len(raw) == (270 if phase == 1 else 268), "incorrect frame length")
    require(raw[:12] == b"DOMBTCM3\x00\x03" + bytes([phase, role]), "invalid frame tags")
    require(raw[12:44] == scope[0] and raw[44:76] == identity
            and raw[76:108] == scope[1] and raw[108:140] == scope[2], "frame scope mismatch")
    message = hashlib.blake2b(DOMAIN + raw[:-64], digest_size=32).digest()
    require(verify_schnorr(public_key[1:], message, raw[-64:]), "invalid frame signature")
    return raw[140:-64]


def verify_round(case):
    fields(case, ("schema_version", "session_digest", "policy_digest", "anchor_evidence_digest",
                  "participants", "messages"))
    require(type(case["schema_version"]) is int and case["schema_version"] == 3, "unsupported schema")
    scope = tuple(nonzero32(case[key]) for key in
                  ("session_digest", "policy_digest", "anchor_evidence_digest"))
    people = case["participants"]
    require(isinstance(people, list) and len(people) == 2, "expected two participants")
    participants = []
    for expected_role, person in enumerate(people, 1):
        fields(person, ("id", "role", "public_key"))
        require(type(person["role"]) is int and person["role"] == expected_role, "invalid roster role")
        identity = nonzero32(person["id"])
        public = hex_bytes(person["public_key"], 33, 33)
        require(public[0] in (2, 3), "invalid compressed key")
        participants.append((identity, public))
    require(participants[0][0] != participants[1][0]
            and participants[0][1][1:] != participants[1][1][1:], "duplicate participant identity/key")
    names = ("maker_nonce", "taker_nonce", "maker_partial", "taker_partial")
    fields(case["messages"], names)
    partials, nonces = [], []
    for index, name in enumerate(names):
        role, phase = index % 2 + 1, index // 2 + 1
        identity, public = participants[role - 1]
        raw = hex_bytes(case["messages"][name], 270)
        payload = verify_packet(raw, phase, role, identity, public, scope)
        if phase == 2:
            partials.append(payload[:32])
        else:
            nonces.append(payload)
    require(nonces[0] != nonces[1], "identical participant nonces")
    transcript = hashlib.blake2b(b"DOM-INTEROP/BTC-ACTUATOR/CLAIM-TRANSCRIPT/V1\0"
        + scope[0] + b"".join(sorted(nonces)), digest_size=32).digest()
    require(partials[0] == partials[1] == transcript, "partial transcript mismatch")
    return {"schema_version": 3, "status": "verified-offline", "authenticated_messages": 4,
            "session_digest": scope[0].hex(), "transcript_digest": partials[0].hex(),
            "limits": ["Pins are externally authenticated inputs, not F7/M.8 proof verification.",
                       "No independent MuSig2 partial verification or end-to-end swap evidence.",
                       "Message authentication exposes public session/participant linkage."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path)
    args = parser.parse_args()
    try:
        with args.case.open("rb") as stream:
            raw = stream.read(MAX_CASE + 1)
        require(len(raw) <= MAX_CASE, "case too large")
        report = verify_round(json.loads(raw, object_pairs_hook=unique_object))
        report["input_sha256"] = hashlib.sha256(raw).hexdigest()
        report["verifier_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except (ValueError, OSError, RecursionError) as error:
        print(json.dumps({"status": "refused", "reason": str(error) if isinstance(error, Refused)
                          else "unreadable or invalid case"}))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
