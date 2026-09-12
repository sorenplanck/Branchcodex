"""Public BIP vectors and synthetic adversarial bytes; no network or wallet."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bitcoin_claim_oracle as oracle

VECTORS = Path(__file__).parent / "vectors"


class BitcoinClaimOracleTests(unittest.TestCase):
    def test_all_19_official_bip340_verification_vectors(self):
        rows = json.loads((VECTORS / "bip340-public.json").read_text())["vectors"]
        self.assertEqual(len(rows), 19)
        for row in rows:
            with self.subTest(vector=row["index"]):
                self.assertEqual(oracle.verify_schnorr(bytes.fromhex(row["public_key"]),
                    bytes.fromhex(row["message"]), bytes.fromhex(row["signature"])), row["valid"])

    def test_official_bip341_default_sighash_and_signature(self):
        case = json.loads((VECTORS / "bip341-default-public.json").read_text())
        tx = oracle.parse_transaction(bytes.fromhex(case["raw_unsigned_tx"]))
        spent = [{"amount_sat": out["amountSats"], "script": bytes.fromhex(out["scriptPubKey"])}
                 for out in case["utxos"]]
        message = oracle.sighash_default(tx, spent, case["input_index"])
        self.assertEqual(message.hex(), case["sighash"])
        self.assertTrue(oracle.verify_schnorr(spent[case["input_index"]]["script"][2:],
                                            message, bytes.fromhex(case["witness"][0])))
        spent[0]["amount_sat"] += 1
        self.assertNotEqual(oracle.sighash_default(tx, spent, case["input_index"]), message)

    def setUp(self):
        self.case = json.loads((VECTORS / "synthetic-bitcoin-claim.json").read_text())

    def test_synthetic_frozen_claim_and_exact_economics(self):
        report = oracle.verify_claim(self.case)
        self.assertEqual(report["status"], "verified-offline")
        self.assertEqual(report["principal_sat"], report["recipient_sat"] + report["fee_sat"])
        self.assertEqual(report["claim_txid"], self.case["expected_claim_txid"])

    def test_independently_pinned_fields_cannot_be_substituted(self):
        replacements = {"principal_sat": 199_999, "fee_sat": 2001, "funding_vout": 1,
                        "expected_claim_txid": "ff" * 32, "expected_funding_txid": "ee" * 32,
                        "contract_script_pubkey": "5120" + "01" * 32,
                        "recipient_script_pubkey": "51", "schema_version": 2,
                        "route_id": "00" * 32}
        for key, value in replacements.items():
            with self.subTest(field=key):
                case = dict(self.case, **{key: value})
                with self.assertRaises(oracle.Refused):
                    oracle.verify_claim(case)

    def test_signature_mutation_keeps_txid_but_is_refused(self):
        raw = bytearray.fromhex(self.case["claim_transaction"])
        raw[-5] ^= 1
        before = oracle.parse_transaction(bytes.fromhex(self.case["claim_transaction"]))
        after = oracle.parse_transaction(bytes(raw))
        self.assertEqual(before["txid"], after["txid"])
        with self.assertRaisesRegex(oracle.Refused, "signature"):
            oracle.verify_claim(dict(self.case, claim_transaction=raw.hex()))

    def test_amount_mutation_with_relabelled_txid_and_fee_still_fails_signature(self):
        raw = bytearray.fromhex(self.case["claim_transaction"])
        # Frozen one-input transaction: version+marker+count+outpoint+empty
        # script+sequence+output-count put the output amount at byte 49.
        self.assertEqual(int.from_bytes(raw[49:57], "little"), 198_000)
        raw[49:57] = struct.pack("<Q", 197_999)
        claim_id = oracle.parse_transaction(bytes(raw))["txid"][::-1].hex()
        with self.assertRaisesRegex(oracle.Refused, "signature"):
            oracle.verify_claim(dict(self.case, claim_transaction=raw.hex(), fee_sat=2001,
                                     expected_claim_txid=claim_id))

    def test_every_truncated_prefix_and_trailing_bytes_are_refused(self):
        raw = bytes.fromhex(self.case["claim_transaction"])
        for length in range(len(raw)):
            with self.subTest(length=length), self.assertRaises(oracle.Refused):
                oracle.parse_transaction(raw[:length])
        with self.assertRaises(oracle.Refused):
            oracle.parse_transaction(raw + b"\x00")

    def test_noncanonical_sizes_witness_flags_and_superfluous_witness_are_refused(self):
        raw = bytes.fromhex(self.case["claim_transaction"])
        malformed = [raw[:6] + b"\xfd\x01\x00" + raw[7:], raw[:5] + b"\x02" + raw[6:],
                     raw[:-70] + b"\x00" + raw[-4:]]
        for candidate in malformed:
            with self.assertRaises(oracle.Refused):
                oracle.parse_transaction(candidate)

    def test_schema_types_unknown_fields_and_duplicate_json_are_refused(self):
        for key, value in [("principal_sat", True), ("fee_sat", 2000.0), ("funding_vout", -1),
                           ("schema_version", True), ("extra", 1), ("claim_transaction", "aa aa")]:
            with self.subTest(field=key), self.assertRaises(oracle.Refused):
                oracle.verify_claim(dict(self.case, **{key: value}))
        with self.assertRaises(oracle.Refused):
            json.loads('{"fee_sat":1,"fee_sat":2}', object_pairs_hook=oracle.unique_object)

    def test_cli_success_and_failure_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "case.json"
            path.write_text(json.dumps(self.case))
            command = [sys.executable, oracle.__file__, str(path)]
            passed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(passed.returncode, 0, passed.stderr + passed.stdout)
            self.assertEqual(json.loads(passed.stdout)["status"], "verified-offline")
            path.write_text('{"fee_sat":1,"fee_sat":2}')
            failed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(failed.returncode, 1)
            self.assertEqual(json.loads(failed.stdout)["status"], "refused")


if __name__ == "__main__":
    unittest.main()
