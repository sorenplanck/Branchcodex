#!/usr/bin/env python3
"""Offline, independent verifier for DOM's frozen Bitcoin key-path claim.

Uses Python's standard library and public data only. Does not import the Rust
adapter, sign, broadcast, contact RPC, or establish chain inclusion/finality.
The JSON pins must come from independently authenticated route terms.
Specification: https://bips.dev/340/ and https://bips.dev/341/.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

MAX_BYTES = 4_000_000
MAX_MONEY = 21_000_000 * 100_000_000
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


class Refused(ValueError):
    """Public input is invalid or outside the frozen claim format."""


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def sha(data):
    return hashlib.sha256(data).digest()


def tagged(tag, data):
    prefix = sha(tag.encode("ascii"))
    return sha(prefix + prefix + data)


def add(a, b):
    # Verification only: this arithmetic is deliberately not a secret signer.
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3 * x * x) * pow(2 * y, -1, P) if a == b
             else (v - y) * pow(u - x, -1, P)) % P
    out = (slope * slope - x - u) % P
    return out, (slope * (x - out) - y) % P


def multiply(scalar, point):
    result = None
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


def verify_schnorr(public_key, message, signature):
    if len(public_key) != 32 or len(signature) != 64:
        return False
    x = int.from_bytes(public_key, "big")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if x >= P or r >= P or s >= N:
        return False
    square = (pow(x, 3, P) + 7) % P
    y = pow(square, (P + 1) // 4, P)
    if y * y % P != square:
        return False
    point = (x, y if y % 2 == 0 else P - y)
    challenge = int.from_bytes(tagged("BIP0340/challenge", signature[:32] + public_key + message), "big") % N
    candidate = add(multiply(s, G), multiply((N - challenge) % N, point))
    return candidate is not None and candidate[1] % 2 == 0 and candidate[0] == r


def compact(value):
    require(type(value) is int and 0 <= value <= 0xFFFFFFFFFFFFFFFF, "invalid CompactSize")
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def vector(data):
    return compact(len(data)) + data


class Reader:
    def __init__(self, raw):
        require(0 < len(raw) <= MAX_BYTES, "transaction size out of bounds")
        self.raw, self.position = raw, 0

    def take(self, size):
        require(0 <= size <= len(self.raw) - self.position, "truncated transaction")
        result = self.raw[self.position:self.position + size]
        self.position += size
        return result

    def integer(self, size):
        return int.from_bytes(self.take(size), "little")

    def count(self, limit):
        prefix = self.integer(1)
        size = {253: 2, 254: 4, 255: 8}.get(prefix)
        if size is None:
            value = prefix
        else:
            value = self.integer(size)
            require(value >= {2: 253, 4: 65536, 8: 4294967296}[size], "noncanonical CompactSize")
        require(value <= limit, "vector bound exceeded")
        return value

    def blob(self):
        return self.take(self.count(MAX_BYTES))


def output_bytes(output):
    return struct.pack("<Q", output["amount_sat"]) + vector(output["script"])


def parse_transaction(raw):
    reader = Reader(raw)
    version = reader.take(4)
    segwit = reader.raw[reader.position:reader.position + 1] == b"\0"
    if segwit:
        require(reader.take(2) == b"\x00\x01", "unsupported witness flags")
    count = reader.count(100_000)
    require(count > 0, "no transaction inputs")
    inputs, encoded_inputs, seen = [], [], set()
    for _ in range(count):
        start = reader.position
        outpoint = reader.take(36)
        require(outpoint not in seen, "duplicate input")
        seen.add(outpoint)
        script = reader.blob()
        sequence = reader.take(4)
        inputs.append({"outpoint": outpoint, "script": script, "sequence": sequence, "witness": []})
        encoded_inputs.append(raw[start:reader.position])
    count_outputs = reader.count(100_000)
    require(count_outputs > 0, "no transaction outputs")
    outputs, total = [], 0
    for _ in range(count_outputs):
        amount = reader.integer(8)
        total += amount
        require(amount <= MAX_MONEY and total <= MAX_MONEY, "output amount out of range")
        outputs.append({"amount_sat": amount, "script": reader.blob()})
    if segwit:
        for txin in inputs:
            txin["witness"] = [reader.blob() for _ in range(reader.count(100_000))]
        require(any(txin["witness"] for txin in inputs), "superfluous witness encoding")
    locktime = reader.take(4)
    require(reader.position == len(raw), "trailing transaction bytes")
    stripped = (version + compact(count) + b"".join(encoded_inputs) + compact(count_outputs)
                + b"".join(output_bytes(out) for out in outputs) + locktime)
    return {"version": version, "locktime": locktime, "inputs": inputs, "outputs": outputs,
            "txid": sha(sha(stripped)), "weight": len(stripped) * 3 + len(raw)}


def sighash_default(transaction, spent_outputs, input_index=0):
    inputs = transaction["inputs"]
    require(len(inputs) == len(spent_outputs) and 0 <= input_index < len(inputs), "prevout context mismatch")
    # epoch=0, SIGHASH_DEFAULT=0, ext_flag=0, annex_present=0.
    message = (b"\x00\x00" + transaction["version"] + transaction["locktime"]
               + sha(b"".join(txin["outpoint"] for txin in inputs))
               + sha(b"".join(struct.pack("<Q", out["amount_sat"]) for out in spent_outputs))
               + sha(b"".join(vector(out["script"]) for out in spent_outputs))
               + sha(b"".join(txin["sequence"] for txin in inputs))
               + sha(b"".join(output_bytes(out) for out in transaction["outputs"]))
               + b"\x00" + struct.pack("<I", input_index))
    return tagged("TapSighash", message)


def hex_bytes(value, maximum, exact=None):
    require(isinstance(value, str) and len(value) <= maximum * 2 and len(value) % 2 == 0,
            "invalid hex field")
    require(all(char in "0123456789abcdefABCDEF" for char in value), "noncanonical hex field")
    decoded = bytes.fromhex(value)
    require(exact is None or len(decoded) == exact, "incorrect hex length")
    return decoded


def verify_claim(case):
    keys = {"schema_version", "route_id", "funding_transaction", "expected_funding_txid", "funding_vout",
            "contract_script_pubkey", "principal_sat", "claim_transaction", "expected_claim_txid",
            "recipient_script_pubkey", "fee_sat"}
    require(isinstance(case, dict) and set(case) == keys, "unknown or missing case fields")
    require(type(case["schema_version"]) is int and case["schema_version"] == 1, "unsupported schema")
    require(hex_bytes(case["route_id"], 32, 32) != bytes(32), "zero route identity")
    principal, fee, vout = case["principal_sat"], case["fee_sat"], case["funding_vout"]
    require(type(principal) is int and 0 < principal <= MAX_MONEY, "invalid principal")
    require(type(fee) is int and 0 < fee < principal, "invalid fee")
    require(type(vout) is int and 0 <= vout <= 0xFFFFFFFF, "invalid funding vout")
    contract = hex_bytes(case["contract_script_pubkey"], 34, 34)
    recipient = hex_bytes(case["recipient_script_pubkey"], 10_000)
    require(contract[:2] == b"\x51\x20" and recipient, "invalid frozen scripts")
    funding = parse_transaction(hex_bytes(case["funding_transaction"], MAX_BYTES))
    claim = parse_transaction(hex_bytes(case["claim_transaction"], MAX_BYTES))
    require(funding["txid"][::-1] == hex_bytes(case["expected_funding_txid"], 32, 32), "funding txid mismatch")
    require(claim["txid"][::-1] == hex_bytes(case["expected_claim_txid"], 32, 32), "claim txid mismatch")
    require(vout < len(funding["outputs"]), "missing funding output")
    spent = funding["outputs"][vout]
    require(spent == {"amount_sat": principal, "script": contract}, "funding principal/script mismatch")
    require(claim["version"] == b"\x02\0\0\0" and claim["locktime"] == bytes(4), "claim version/locktime mismatch")
    require(len(claim["inputs"]) == 1 and len(claim["outputs"]) == 1, "claim must have one input and output")
    txin = claim["inputs"][0]
    require(txin["outpoint"] == funding["txid"] + struct.pack("<I", vout), "claim spends different funding")
    require(txin["script"] == b"" and txin["sequence"] == b"\xff" * 4, "claim input differs from frozen template")
    require(claim["outputs"][0] == {"amount_sat": principal - fee, "script": recipient}, "claim payout/fee mismatch")
    require(len(txin["witness"]) == 1 and len(txin["witness"][0]) == 64, "claim requires DEFAULT key-path signature without annex")
    message = sighash_default(claim, [spent])
    require(verify_schnorr(contract[2:], message, txin["witness"][0]), "invalid BIP340 claim signature")
    return {"schema_version": 1, "status": "verified-offline", "scope": "bitcoin-frozen-key-path-claim",
            "route_id": case["route_id"], "funding_txid": funding["txid"][::-1].hex(),
            "claim_txid": claim["txid"][::-1].hex(), "principal_sat": principal,
            "recipient_sat": principal - fee, "fee_sat": fee, "claim_weight": claim["weight"],
            "sighash": message.hex(), "verifier_sha256": sha(Path(__file__).read_bytes()).hex(),
            "limits": ["Route pins are caller-authenticated inputs.",
                       "No chain inclusion, finality, funding-input signature, refund or DOM/EVM-leg verification.",
                       "No independent audit or end-to-end production route certification."]}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path, help="public transaction bytes and independently authenticated route pins")
    args = parser.parse_args()
    try:
        with args.case.open("rb") as stream:
            raw = stream.read(MAX_BYTES * 4 + 100_001)
        require(len(raw) <= MAX_BYTES * 4 + 100_000, "case size out of bounds")
        case = json.loads(raw, object_pairs_hook=unique_object)
        report = verify_claim(case)
        report["input_sha256"] = sha(raw).hex()
    except (ValueError, OSError, RecursionError) as error:
        # No input data (including paths or malformed JSON) is copied to logs.
        reason = str(error) if isinstance(error, Refused) else "unreadable or invalid case"
        print(json.dumps({"status": "refused", "reason": reason}))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
