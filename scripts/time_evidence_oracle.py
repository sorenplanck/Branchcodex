#!/usr/bin/env python3
"""Independent BIP340 threshold/scope checker for DOMRTSE2 public evidence.

Does not replace the Rust policy, time-ladder, ancestry or durable rollback
checks. Pins must come from an independently trusted authority configuration.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import bitcoin_claim_oracle as crypto

MAX_BYTES = 16_384
DOMAIN = b"DOM-INTEROP/ROUTE-TIME-EVIDENCE/V2\0"


class Refused(ValueError):
    pass


def require(value, message):
    if not value:
        raise Refused(message)


def hex_bytes(value, size):
    require(type(value) is str and len(value) == size * 2 and value == value.lower(), "invalid hex field")
    try:
        result = bytes.fromhex(value)
    except ValueError:
        raise Refused("invalid hex field") from None
    require(len(result) == size and result.hex() == value, "noncanonical hex field")
    return result


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def load_json(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(128 * 1024 + 1)
    require(len(raw) <= 128 * 1024, "JSON exceeds limit")
    return json.loads(raw, object_pairs_hook=unique_object)


def decode(raw):
    require(type(raw) is bytes and 18 <= len(raw) <= MAX_BYTES, "invalid envelope size")
    require(raw[:12] == b"DOMRTSE2\x00\x02\x00\x00", "invalid signed header")
    length = int.from_bytes(raw[12:16], "big")
    require(length == 880 and len(raw) >= 18 + length, "invalid evidence size")
    body = raw[16:16 + length]
    require(body[:12] == b"DOMRTEV2\x00\x02\x00\x00", "invalid evidence header")
    count = int.from_bytes(raw[16 + length:18 + length], "big")
    require(1 <= count <= 16 and len(raw) == 18 + length + count * 66, "invalid signature vector")
    sequence, observed, expiry = struct.unpack_from(">QQQ", body, 76)
    require(sequence > 0 and 0 < observed < expiry, "invalid sequence or lifetime")
    require(body[12:44] != bytes(32) and body[44:76] != bytes(32), "zero scope")
    for index in range(3):
        checkpoint = body[100 + index * 260:100 + (index + 1) * 260]
        require(checkpoint[0] == index + 1 and 1 <= checkpoint[1] <= 5
                and checkpoint[2:4] == b"\0\0", "invalid checkpoint role or clock")
    signatures = []
    for offset in range(18 + length, len(raw), 66):
        signer = int.from_bytes(raw[offset:offset + 2], "big")
        signature = raw[offset + 2:offset + 66]
        require(signature != bytes(64) and (not signatures or signer > signatures[-1][0]), "duplicate or unordered signer")
        signatures.append((signer, signature))
    return dict(body=body, policy_digest=body[12:44], route_scope_digest=body[44:76],
                sequence=sequence, observed=observed, expiry=expiry, signatures=signatures)


def verify(raw, pins, now):
    require(type(pins) is dict and set(pins) == {"public_keys", "threshold", "minimum_sequence", "policy_digest", "route_scope_digest"}, "invalid pins")
    require(type(pins["public_keys"]) is list and 1 <= len(pins["public_keys"]) <= 16, "invalid authority set")
    keys = [hex_bytes(key, 32) for key in pins["public_keys"]]
    require(len(keys) == len(set(keys)), "duplicate authority key")
    require(type(pins["threshold"]) is int and 1 <= pins["threshold"] <= len(keys), "invalid threshold")
    require(type(pins["minimum_sequence"]) is int and 1 <= pins["minimum_sequence"] < 2**64, "invalid minimum sequence")
    require(type(now) is int and 0 < now < 2**64, "invalid verification time")
    data = decode(raw)
    for key in ("policy_digest", "route_scope_digest"):
        require(data[key] == hex_bytes(pins[key], 32), "scope transplant")
    require(data["sequence"] >= pins["minimum_sequence"], "sequence rollback")
    require(data["observed"] <= now < data["expiry"], "expired or future evidence")
    require(len(data["signatures"]) >= pins["threshold"], "threshold not reached")
    digest = hashlib.blake2b(DOMAIN + data["body"], digest_size=32).digest()
    for index, signature in data["signatures"]:
        require(index < len(keys) and crypto.verify_schnorr(keys[index], digest, signature), "invalid signature")
    return dict(status="passed", scope="threshold-signatures-and-public-scope", sequence=data["sequence"],
                evidence_digest=digest.hex(), signatures=len(data["signatures"]), full_time_ladder_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path, help="public fixture exported by the Rust test")
    args = parser.parse_args()
    try:
        value = load_json(args.fixture)
        require(type(value) is dict and set(value) == {"schema", "signed_hex", "pins", "verification_time"}
                and value["schema"] == "DOM-TIME-EVIDENCE-V5", "invalid fixture")
        require(type(value["signed_hex"]) is str and len(value["signed_hex"]) <= MAX_BYTES * 2, "invalid evidence hex")
        raw = hex_bytes(value["signed_hex"], len(value["signed_hex"]) // 2)
        print(json.dumps(verify(raw, value["pins"], value["verification_time"]), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, RecursionError):
        print('{"status":"refused","scope":"time-evidence-oracle"}', file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
