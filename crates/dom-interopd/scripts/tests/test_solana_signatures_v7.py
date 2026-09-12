"""Python-only oracle tests; do not stand in for Rust signer execution."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import solana_signatures_v7 as oracle


def short(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result + bytes([value]))


def fixture(asset, action):
    spl = asset == "spl"
    payer = oracle.RECIPIENT if action == "Claim" else oracle.FUNDER
    state, vault, authority = [bytes([i]) * 32 for i in (41, 42, 43)]
    if action == "Funding":
        accounts = ([oracle.FUNDER, state, authority, vault, bytes([70]) * 32, oracle.TOKEN_PROGRAM, bytes(32)]
                    if spl else [oracle.FUNDER, state, vault, bytes(32)])
        initialization = (oracle.MAGIC + bytes([2 if spl else 1]) + bytes([32 if spl else 31]) * 32
                          + bytes([44]) * 32 + bytes([45]) * 32 + oracle.RECIPIENT + oracle.FUNDER
                          + bytes([2]) * 33 + bytes([3]) * 32 + (500).to_bytes(8, "big")
                          + (2_000_000_000).to_bytes(8, "big"))
        funding_accounts = ([oracle.FUNDER, state, bytes([80]) * 32, vault, bytes([70]) * 32, oracle.TOKEN_PROGRAM]
                            if spl else accounts)
        instructions = [(accounts, initialization), (funding_accounts, oracle.MAGIC + b"\x03")]
    else:
        accounts = ([state, authority, vault, bytes([81 if action == "Claim" else 82]) * 32,
                     bytes([70]) * 32, oracle.TOKEN_PROGRAM] if spl else [state, vault, payer])
        instructions = [(accounts, oracle.MAGIC + (b"\x04" + (9).to_bytes(32, "big") if action == "Claim" else b"\x05"))]
    keys = [payer]
    for accounts, _ in instructions:
        for account in accounts:
            if account not in keys:
                keys.append(account)
    keys.append(oracle.PROGRAM)
    message = b"\x01\x00\x01" + short(len(keys)) + b"".join(keys) + bytes([50]) * 32 + short(len(instructions))
    for accounts, data in instructions:
        message += bytes([len(keys) - 1]) + short(len(accounts)) + bytes(keys.index(a) for a in accounts) + short(len(data)) + data
    record = {"asset": asset, "action": action, "payer": payer.hex(), "message": message.hex()}
    return resign(record)


def resign(record):
    seed = bytes([8 if record["action"] == "Claim" else 7]) * 32
    message = bytes.fromhex(record["message"])
    signature = oracle.Ed25519PrivateKey.from_private_bytes(seed).sign(message)
    record.update(signature=signature.hex(), transaction=(b"\x01" + signature + message).hex())
    return record


def document():
    return {"schema": 7, "chain_e2e": False, "signatures": [fixture(a, b) for a, b in sorted(oracle.PAIRS)]}


class IndependentSignerOracleTests(unittest.TestCase):
    def test_accepts_six_independently_encoded_signed_messages(self):
        self.assertEqual(oracle.verify_export(document())["signature_cases"], 6)

    def test_rejects_invalid_signature_and_transaction_substitution(self):
        for field in ("signature", "transaction", "payer"):
            value = fixture("sol", "Refund")
            changed = bytearray.fromhex(value[field]); changed[-1] ^= 1
            value[field] = changed.hex()
            with self.assertRaises(ValueError):
                oracle.verify_record(value)

    def test_resigned_wrong_principal_deadline_or_payout_refuses(self):
        for asset in ("sol", "spl"):
            for field, old in (("principal", (500).to_bytes(8, "big")),
                               ("deadline", (2_000_000_000).to_bytes(8, "big")),
                               ("payout", oracle.RECIPIENT)):
                value = fixture(asset, "Funding")
                message = bytes.fromhex(value["message"])
                replacement = old[:-1] + bytes([old[-1] ^ 1])
                self.assertIn(old, message, field)
                value["message"] = message.replace(old, replacement).hex()
                with self.assertRaises(ValueError):
                    oracle.verify_record(resign(value))

    def test_resigned_program_or_secret_substitution_refuses(self):
        for asset in ("sol", "spl"):
            for old in (oracle.PROGRAM, (9).to_bytes(32, "big")):
                value = fixture(asset, "Claim")
                value["message"] = bytes.fromhex(value["message"]).replace(old, bytes([92]) * 32).hex()
                with self.assertRaises(ValueError):
                    oracle.verify_record(resign(value))

    def test_resigned_vault_swap_between_actions_refuses(self):
        value = document()
        record = value["signatures"][0]
        record["message"] = bytes.fromhex(record["message"]).replace(bytes([42]) * 32, bytes([99]) * 32).hex()
        resign(record)
        with self.assertRaisesRegex(ValueError, "vault/state changed"):
            oracle.verify_export(value)

    def test_duplicate_missing_or_overclaimed_evidence_refuses(self):
        for mode in ("duplicate", "missing", "e2e", "schema"):
            value = document()
            if mode == "duplicate":
                value["signatures"][0] = copy.deepcopy(value["signatures"][1])
            elif mode == "missing":
                value["signatures"].pop()
            elif mode == "e2e":
                value["chain_e2e"] = True
            else:
                value["schema"] = True
            with self.assertRaises(ValueError):
                oracle.verify_export(value)

    def test_strict_lengths_and_trailing_wire_refuse(self):
        for encoded in (b"\x80\x00", b"\xff\xff\x04", b"\x80\x80\x00", b"\x80"):
            with self.assertRaises(ValueError):
                oracle.Cursor(encoded).short()
        for asset in ("sol", "spl"):
            message = bytes.fromhex(fixture(asset, "Funding")["message"])
            for end in range(len(message)):
                with self.assertRaises(ValueError):
                    oracle.decode_message(message[:end])
            with self.assertRaises(ValueError):
                oracle.decode_message(message + b"\x00")


if __name__ == "__main__":
    unittest.main()
