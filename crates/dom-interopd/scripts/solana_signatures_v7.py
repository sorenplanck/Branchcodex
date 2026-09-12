#!/usr/bin/env python3
"""Independent decoder/verifier for PUBLIC V7 signer test exports, not live swaps.

Uses OpenSSL through cryptography, not the Rust transaction builder or dalek.
Checks Ed25519, complete wire consumption, signer/program identities, action
data, principal/deadline and account continuity across fund/claim/refund.
Does not verify DLEQ, PDA derivation, chain inclusion or finality.
"""
import argparse
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAGIC = b"DOMSLIX1\x00\x01"
PROGRAM = bytes([13]) * 32
TOKEN_PROGRAM = bytes.fromhex("06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9")
FUNDER = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32).public_key().public_bytes_raw()
RECIPIENT = Ed25519PrivateKey.from_private_bytes(bytes([8]) * 32).public_key().public_bytes_raw()
PAIRS = {(asset, action) for asset in ("sol", "spl") for action in ("Funding", "Claim", "Refund")}


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Cursor:
    def __init__(self, data):
        self.data, self.at = data, 0

    def take(self, count):
        end = self.at + count
        require(0 <= count and end <= len(self.data), "truncated wire")
        value, self.at = self.data[self.at:end], end
        return value

    def short(self):
        value = 0
        for index in range(3):
            byte = self.take(1)[0]
            require(index < 2 or byte <= 3, "compact length overflow")
            value |= (byte & 127) << (7 * index)
            if byte < 128:
                require(index == 0 or byte != 0, "noncanonical compact length")
                return value
        raise ValueError("unterminated compact length")


def unhex(value, maximum):
    require(isinstance(value, str) and len(value) <= 2 * maximum, "hex bound")
    require(len(value) % 2 == 0 and all(c in "0123456789abcdef" for c in value), "noncanonical hex")
    return bytes.fromhex(value)


def decode_message(message):
    require(0 < len(message) <= 1167, "message bound")
    cursor = Cursor(message)
    signed, readonly_signed, readonly_unsigned = cursor.take(3)
    require(signed == 1 and readonly_signed == 0, "unexpected signer header")
    count = cursor.short()
    require(1 <= count <= 256 and readonly_unsigned < count, "account bounds")
    keys = [cursor.take(32) for _ in range(count)]
    require(len(set(keys)) == len(keys), "duplicate account key")
    require(cursor.take(32) == bytes([50]) * 32, "wrong public fixture blockhash")
    count_instructions = cursor.short()
    require(count_instructions in (1, 2), "instruction count")
    instructions = []
    for _ in range(count_instructions):
        program = cursor.take(1)[0]
        require(program < count and keys[program] == PROGRAM, "unexpected program")
        require(program >= count - readonly_unsigned, "writable program")
        indices = list(cursor.take(cursor.short()))
        require(all(i < count for i in indices), "account index overflow")
        data = cursor.take(cursor.short())
        require(data.startswith(MAGIC), "instruction domain/version")
        instructions.append(([keys[i] for i in indices], data))
    require(cursor.at == len(message), "trailing message bytes")
    return keys[0], instructions


def verify_record(record):
    require(isinstance(record, dict) and set(record) == {"asset", "action", "payer", "message", "signature", "transaction"}, "record fields")
    pair = (record["asset"], record["action"])
    require(pair in PAIRS, "unknown action or asset")
    payer, signature = unhex(record["payer"], 32), unhex(record["signature"], 64)
    message, wire = unhex(record["message"], 1167), unhex(record["transaction"], 1232)
    require(len(payer) == 32 and len(signature) == 64, "signature/key size")
    expected_payer = RECIPIENT if record["action"] == "Claim" else FUNDER
    require(payer == expected_payer, "wrong signer role")
    require(wire == b"\x01" + signature + message, "transaction/message substitution")
    try:
        Ed25519PublicKey.from_public_bytes(payer).verify(signature, message)
    except InvalidSignature as exc:
        raise ValueError("invalid Ed25519 signature") from exc
    wire_payer, instructions = decode_message(message)
    require(wire_payer == payer, "payer/header substitution")
    spl, action = record["asset"] == "spl", record["action"]
    if action == "Funding":
        require(len(instructions) == 2, "funding must initialize atomically")
        init_accounts, data = instructions[0]
        fund_accounts, fund_data = instructions[1]
        require(len(data) == 252 and data[:11] == MAGIC + bytes([2 if spl else 1]), "initialize data")
        require(data[11:43] == bytes([32 if spl else 31]) * 32, "settlement substitution")
        require(data[43:75] != bytes(32) and data[75:107] != bytes(32), "empty setup/terms")
        require(data[107:139] == RECIPIENT and data[139:171] == FUNDER, "payout substitution")
        require(int.from_bytes(data[236:244], "big") == 500, "principal changed")
        require(int.from_bytes(data[244:252], "big", signed=True) == 2_000_000_000, "deadline changed")
        require(fund_data == MAGIC + b"\x03", "wrong funding action")
        if spl:
            require(len(init_accounts) == 7 and len(fund_accounts) == 6, "SPL funding accounts")
            funder, state, authority, vault, mint, token, system = init_accounts
            require(mint == bytes([70]) * 32 and token == TOKEN_PROGRAM and system == bytes(32), "SPL deployment")
            require(fund_accounts == [FUNDER, state, bytes([80]) * 32, vault, mint, token], "SPL funding source")
        else:
            require(len(init_accounts) == 4 and fund_accounts == init_accounts, "SOL funding accounts")
            funder, state, vault, system = init_accounts
            authority = None
            require(system == bytes(32), "system program")
        require(funder == FUNDER and state != vault and state != bytes(32) and vault != bytes(32), "funding identity")
        return pair, (state, vault, authority)
    require(len(instructions) == 1, "terminal action count")
    accounts, data = instructions[0]
    expected = MAGIC + (b"\x04" + (9).to_bytes(32, "big") if action == "Claim" else b"\x05")
    require(data == expected, "terminal action/secret substitution")
    if spl:
        require(len(accounts) == 6, "SPL terminal accounts")
        state, authority, vault, destination, mint, token = accounts
        require(destination == bytes([81 if action == "Claim" else 82]) * 32, "SPL destination")
        require(mint == bytes([70]) * 32 and token == TOKEN_PROGRAM, "SPL asset substitution")
    else:
        require(len(accounts) == 3, "SOL terminal accounts")
        state, vault, destination = accounts
        authority = None
        require(destination == expected_payer, "SOL destination")
    return pair, (state, vault, authority)


def verify_export(document):
    require(isinstance(document, dict) and set(document) == {"schema", "chain_e2e", "signatures"}, "export fields")
    require(type(document["schema"]) is int and document["schema"] == 7 and document["chain_e2e"] is False, "export scope")
    require(isinstance(document["signatures"], list) and len(document["signatures"]) == 6, "six distinct actions required")
    seen, accounts_by_asset = set(), {}
    for record in document["signatures"]:
        pair, accounts = verify_record(record)
        require(pair not in seen, "duplicated action")
        seen.add(pair)
        previous = accounts_by_asset.setdefault(pair[0], accounts)
        require(previous == accounts, "vault/state changed between actions")
    require(seen == PAIRS, "incomplete action matrix")
    return {"status": "passed", "signature_cases": 6, "chain_e2e": False,
            "scope": "public signer fixtures; no DLEQ/PDA/inclusion/finality verification"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    args = parser.parse_args()
    require(args.export.stat().st_size <= 65_536, "export file bound")
    print(json.dumps(verify_export(json.loads(args.export.read_text())), indent=2))


if __name__ == "__main__":
    main()
