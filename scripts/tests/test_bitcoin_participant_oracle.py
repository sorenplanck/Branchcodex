"""Synthetic known-key message fixtures, plus protocol mutation coverage.
The fixed scalars below are test data and must never sign real funds.
"""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bitcoin_claim_oracle as crypto
import bitcoin_participant_oracle as oracle


def test_signature(message, scalar):
    # Fixture-only Schnorr construction; intentionally absent from the verifier.
    point = crypto.multiply(scalar, crypto.G)
    secret = scalar if point[1] % 2 == 0 else crypto.N - scalar
    public = point[0].to_bytes(32, "big")
    nonce = 17
    r = crypto.multiply(nonce, crypto.G)
    if r[1] % 2:
        nonce = crypto.N - nonce
    first = r[0].to_bytes(32, "big")
    e = int.from_bytes(crypto.tagged("BIP0340/challenge", first + public + message), "big") % crypto.N
    return first + ((nonce + e * secret) % crypto.N).to_bytes(32, "big")


def fixture():
    case = {"schema_version": 3, "session_digest": "11" * 32, "policy_digest": "22" * 32,
            "anchor_evidence_digest": "33" * 32, "participants": [], "messages": {}}
    nonces = []
    for scalar in (3, 5):
        point = crypto.multiply(scalar, crypto.G)
        nonces.append((bytes([2 + point[1] % 2]) + point[0].to_bytes(32, "big")) * 2)
    transcript = hashlib.blake2b(b"DOM-INTEROP/BTC-ACTUATOR/CLAIM-TRANSCRIPT/V1\0"
        + bytes.fromhex(case["session_digest"]) + b"".join(sorted(nonces)), digest_size=32).digest()
    for role, scalar in ((1, 3), (2, 5)):
        point = crypto.multiply(scalar, crypto.G)
        public = bytes([2 + point[1] % 2]) + point[0].to_bytes(32, "big")
        person = {"id": f"{role:02x}" * 32, "role": role, "public_key": public.hex()}
        case["participants"].append(person)
        for phase, suffix in ((1, "nonce"), (2, "partial")):
            payload = public * 2 if phase == 1 else transcript + bytes([role]) * 32
            raw = (b"DOMBTCM3\x00\x03" + bytes([phase, role])
                   + bytes.fromhex(case["session_digest"] + person["id"]
                                   + case["policy_digest"] + case["anchor_evidence_digest"]) + payload)
            signature = test_signature(hashlib.blake2b(oracle.DOMAIN + raw, digest_size=32).digest(), scalar)
            case["messages"][("maker_" if role == 1 else "taker_") + suffix] = (raw + signature).hex()
    return case


class BitcoinParticipantOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case = fixture()

    def test_four_authenticated_synthetic_frames(self):
        self.assertEqual(oracle.verify_round(self.case)["authenticated_messages"], 4)

    def test_each_frame_scope_payload_signature_and_tags_are_bound(self):
        for name, packet in self.case["messages"].items():
            for position in (0, 8, 10, 11, 12, 44, 76, 108, 140, len(packet) // 2 - 1):
                case = copy.deepcopy(self.case)
                raw = bytearray.fromhex(packet)
                raw[position] ^= 1
                case["messages"][name] = raw.hex()
                with self.subTest(frame=name, position=position), self.assertRaises(crypto.Refused):
                    oracle.verify_round(case)

    def test_truncated_extended_reflected_and_replayed_role(self):
        for name, packet in self.case["messages"].items():
            for altered in (packet[:-2], packet + "00", self.case["messages"]["maker_nonce"]):
                if altered == packet:
                    continue
                case = copy.deepcopy(self.case)
                case["messages"][name] = altered
                with self.subTest(frame=name), self.assertRaises(crypto.Refused):
                    oracle.verify_round(case)

    def test_invalid_roster_schema_and_pins(self):
        cases = [dict(self.case, schema_version=True), dict(self.case, extra=1),
                 dict(self.case, session_digest="00" * 32), dict(self.case, participants=[])]
        duplicate = copy.deepcopy(self.case)
        duplicate["participants"][1]["public_key"] = duplicate["participants"][0]["public_key"]
        cases.append(duplicate)
        for case in cases:
            with self.assertRaises(crypto.Refused):
                oracle.verify_round(case)

    def test_cli_reports_refusal_without_echoing_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public.json"
            path.write_text(json.dumps(self.case))
            command = [sys.executable, oracle.__file__, str(path)]
            passed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(passed.returncode, 0, passed.stdout + passed.stderr)
            path.write_text('{"schema_version":3,"schema_version":3}')
            refused = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(refused.returncode, 1)
            self.assertEqual(json.loads(refused.stdout)["status"], "refused")


if __name__ == "__main__":
    unittest.main()
