import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bitcoin_driver_oracle as oracle


def fixture():
    value = json.loads((Path(__file__).parent/'vectors/synthetic-bitcoin-claim.json').read_text())
    return {'schema_version': 6, 'claim_transaction': value['claim_transaction'],
            'funding_txid': value['expected_funding_txid'], 'funding_vout': value['funding_vout'],
            **{k: value[k] for k in ('principal_sat', 'contract_script_pubkey', 'recipient_script_pubkey', 'fee_sat')}}


class BitcoinDriverOracleTests(unittest.TestCase):
    def test_valid_final_signature_and_exact_economics(self):
        result = oracle.verify(fixture())
        self.assertEqual(result['recipient_sat'], 198000)
        self.assertFalse(result['funding_inclusion_verified'])

    def test_modified_pins_cannot_preserve_acceptance(self):
        for key, value in [('funding_txid','12'*32),('funding_vout',1),('principal_sat',200001),
                           ('fee_sat',1999),('recipient_script_pubkey','5120'+'13'*32),
                           ('contract_script_pubkey','5120'+'14'*32)]:
            candidate=fixture(); candidate[key]=value
            with self.subTest(key=key),self.assertRaises(oracle.Refused): oracle.verify(candidate)

    def test_all_truncated_claim_prefixes_and_extended_claim_fail(self):
        value=fixture(); wire=bytes.fromhex(value['claim_transaction'])
        for prefix in [wire[:i] for i in range(len(wire))]+[wire+b'\0']:
            candidate=copy.deepcopy(value);candidate['claim_transaction']=prefix.hex()
            with self.assertRaises(oracle.Refused): oracle.verify(candidate)

    def test_signature_substitution_and_boolean_amounts_fail(self):
        value=fixture();wire=bytearray.fromhex(value['claim_transaction']);wire[-5]^=1
        value['claim_transaction']=wire.hex()
        with self.assertRaises(oracle.Refused):oracle.verify(value)
        for key in ['principal_sat','fee_sat','funding_vout','schema_version']:
            value=fixture();value[key]=True
            with self.assertRaises(oracle.Refused):oracle.verify(value)
