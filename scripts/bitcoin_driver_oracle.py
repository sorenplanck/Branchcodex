#!/usr/bin/env python3
"""Verify a driver-produced key-path claim against independently supplied prevout pins.

Checks final BIP340 signature and exact payout. Funding inclusion and the
source of pins remain outside this verifier; it does not certify a swap.
"""
import argparse
import json
import struct
import sys
from pathlib import Path
from bitcoin_claim_oracle import (require, Refused, hex_bytes, parse_transaction,
                                  sighash_default, verify_schnorr, unique_object, MAX_MONEY)


def verify(case):
    require(type(case) is dict and set(case) == {'schema_version', 'claim_transaction', 'funding_txid',
        'funding_vout', 'principal_sat', 'contract_script_pubkey', 'recipient_script_pubkey', 'fee_sat'}, 'invalid schema')
    require(type(case['schema_version']) is int and case['schema_version'] == 6, 'invalid version')
    principal, fee, vout = (case[k] for k in ('principal_sat', 'fee_sat', 'funding_vout'))
    require(type(principal) is int and 0 < principal <= MAX_MONEY, 'invalid principal')
    require(type(fee) is int and 0 < fee < principal, 'invalid fee')
    require(type(vout) is int and 0 <= vout < 2**32, 'invalid vout')
    contract = hex_bytes(case['contract_script_pubkey'], 34, 34)
    recipient = hex_bytes(case['recipient_script_pubkey'], 10_000)
    require(contract[:2] == b'\x51\x20' and recipient, 'invalid scripts')
    tx = parse_transaction(hex_bytes(case['claim_transaction'], 400_000))
    require(tx['version'] == b'\x02\0\0\0' and tx['locktime'] == bytes(4), 'wrong version or locktime')
    require(len(tx['inputs']) == len(tx['outputs']) == 1, 'wrong transaction shape')
    txin = tx['inputs'][0]
    require(txin['outpoint'] == hex_bytes(case['funding_txid'], 32, 32)[::-1] + struct.pack('<I', vout), 'wrong funding')
    require(txin['script'] == b'' and txin['sequence'] == b'\xff'*4, 'wrong input template')
    require(tx['outputs'][0] == {'amount_sat': principal-fee, 'script': recipient}, 'wrong payout')
    require(len(txin['witness']) == 1 and len(txin['witness'][0]) == 64, 'wrong witness')
    sighash = sighash_default(tx, [{'amount_sat': principal, 'script': contract}])
    require(verify_schnorr(contract[2:], sighash, txin['witness'][0]), 'invalid claim signature')
    return {'schema_version': 6, 'status': 'verified-offline', 'claim_txid': tx['txid'][::-1].hex(),
            'principal_sat': principal, 'recipient_sat': principal-fee, 'fee_sat': fee,
            'funding_inclusion_verified': False, 'complete_route_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture', type=Path)
    args = parser.parse_args()
    try:
        with args.fixture.open('rb') as f:
            raw = f.read(850_001)
        require(len(raw) <= 850_000, 'input too large')
        print(json.dumps(verify(json.loads(raw, object_pairs_hook=unique_object)), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print('{"status":"refused","scope":"bitcoin-driver-oracle"}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
