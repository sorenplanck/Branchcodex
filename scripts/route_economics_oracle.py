#!/usr/bin/env python3
"""Independent conservation/state checker over pinned route terms and observations.

This verifies a supplied accounting witness, not consensus or inclusion. A
caller must authenticate pins and obtain observations independently; a JSON
claim of finality never becomes a cryptographic proof here. Amounts are atomic
units. Different assets are never added or priced against each other.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

MAX_BYTES = 2_000_000
FACES = {'BTC', 'EVM', 'SOL', 'XMR'}


class Refused(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Refused(reason)


def fields(value, expected):
    require(type(value) is dict and set(value) == set(expected), 'unexpected fields')


def identity(value):
    require(type(value) is str and len(value) == 64 and set(value) <= set('0123456789abcdef')
            and value != '0'*64, 'invalid identity')
    return value


def units(value, allow_zero=False):
    require(type(value) is int and (0 if allow_zero else 1) <= value < 2**128, 'invalid atomic amount')
    return value


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def load(path):
    with Path(path).open('rb') as f:
        raw = f.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, 'witness exceeds limit')
    return json.loads(raw, object_pairs_hook=unique)


def verify(pins, witness):
    fields(pins, ('schema_version', 'route_id', 'dom_chain_id', 'legs', 'locks'))
    require(type(pins['schema_version']) is int and pins['schema_version'] == 6, 'invalid version')
    route = identity(pins['route_id']); dom_chain = identity(pins['dom_chain_id'])
    require(type(pins['legs']) is list and len(pins['legs']) == 2, 'expected two ordered legs')
    settlements, face_for = [], {}
    for index, leg in enumerate(pins['legs']):
        fields(leg, ('position', 'settlement_id', 'face', 'chain_id'))
        require(type(leg['position']) is int and leg['position'] == index, 'wrong leg order')
        require(leg['face'] in FACES, 'invalid counterparty family')
        chain = identity(leg['chain_id']); require(chain != dom_chain, 'DOM must be distinct')
        settlements.append(identity(leg['settlement_id']))
        face_for[index] = (leg['face'], chain)
    require(settlements[0] != settlements[1], 'settlement alias')
    if face_for[0][1] == face_for[1][1]:
        require(face_for[0][0] == face_for[1][0], 'chain family contradiction')
    require(type(pins['locks']) is list and len(pins['locks']) == 4, 'two DOM and two counterparty locks required')
    locks, positions = {}, set()
    for lock in pins['locks']:
        fields(lock, ('lock_id', 'position', 'face', 'asset_id', 'principal', 'funder', 'recipient',
                      'maximum_deducted_fee', 'minimum_recipient'))
        key = identity(lock['lock_id']); require(key not in locks, 'duplicate lock')
        position, face = lock['position'], lock['face']
        require(type(position) is int and position in (0, 1), 'wrong lock position')
        require(face in ('DOM', face_for[position][0]), 'wrong lock face')
        require((position, face) not in positions, 'duplicate lock face')
        positions.add((position, face)); identity(lock['asset_id'])
        require(identity(lock['funder']) != identity(lock['recipient']), 'funder equals recipient')
        principal = units(lock['principal']); fee = units(lock['maximum_deducted_fee'], True)
        minimum = units(lock['minimum_recipient'])
        require(fee < principal and minimum <= principal and principal-fee >= minimum, 'invalid payout bounds')
        locks[key] = lock
    fields(witness, ('schema_version', 'route_id', 'outcome', 'observations'))
    require(type(witness['schema_version']) is int and witness['schema_version'] == 6, 'wrong witness version')
    require(witness['route_id'] == route, 'route transplant')
    require(witness['outcome'] in ('settled', 'compensated', 'aborted'), 'nonterminal route')
    observations = witness['observations']
    require(type(observations) is list and len(observations) <= 128, 'unbounded observations')
    state = {key: {'funded': False, 'terminal': None, 'principal': 0, 'surplus': 0} for key in locks}
    seen_events, seen_effects, consumed = set(), set(), set()
    totals = {}
    for observation in observations:
        fields(observation, ('event_id', 'route_id', 'settlement_id', 'lock_id', 'effect_id', 'chain_id',
            'asset_id', 'txid', 'event_index', 'action', 'amount', 'recipient', 'deducted_fee', 'finalized'))
        event = identity(observation['event_id']); require(event not in seen_events, 'replayed event')
        seen_events.add(event)
        key = observation['lock_id']; require(key in locks, 'unknown lock')
        lock = locks[key]; current = state[key]; position = lock['position']
        chain = dom_chain if lock['face'] == 'DOM' else face_for[position][1]
        require(observation['route_id'] == route and observation['settlement_id'] == settlements[position], 'wrong route or settlement')
        require(observation['chain_id'] == chain and observation['asset_id'] == lock['asset_id'], 'wrong chain or asset')
        require(observation['finalized'] is True, 'unfinalized observation')
        txid = identity(observation['txid']); idx = observation['event_index']
        require(type(idx) is int and 0 <= idx < 2**32, 'invalid event index')
        event_locator = (chain, txid, idx)
        require(event_locator not in consumed, 'one chain event used twice'); consumed.add(event_locator)
        effect = identity(observation['effect_id']); require((key, effect) not in seen_effects, 'effect executed twice')
        seen_effects.add((key, effect))
        amount = units(observation['amount']); fee = units(observation['deducted_fee'], True)
        action = observation['action']; require(action in ('fund', 'surplus', 'claim', 'refund'), 'unknown action')
        total = totals.setdefault((chain, lock['asset_id']), {'in': 0, 'out': 0, 'deducted_fees': 0, 'residual_surplus': 0})
        if action in ('fund', 'surplus'):
            require(current['terminal'] is None and observation['recipient'] == key and fee == 0, 'invalid deposit')
            if action == 'fund':
                require(not current['funded'] and amount == lock['principal'], 'funding mismatch or duplicate')
                current['funded'] = True; current['principal'] = amount
            else:
                current['surplus'] += amount
            total['in'] += amount
        else:
            require(current['funded'] and current['terminal'] is None, 'terminal without funding or double terminal')
            require(fee <= lock['maximum_deducted_fee'] and amount + fee == current['principal'], 'principal is not conserved')
            expected = lock['recipient'] if action == 'claim' else lock['funder']
            require(observation['recipient'] == expected, 'wrong payout recipient')
            if action == 'claim':
                require(amount >= lock['minimum_recipient'], 'payout below minimum')
            current['terminal'] = action; total['out'] += amount; total['deducted_fees'] += fee
    if witness['outcome'] == 'settled':
        require(all(v['funded'] and v['terminal'] == 'claim' for v in state.values()), 'settled route has incomplete locks')
    elif witness['outcome'] == 'compensated':
        require(any(v['funded'] for v in state.values()), 'empty compensation')
        require(all((v['terminal'] == 'refund') if v['funded'] else v['terminal'] is None for v in state.values()), 'principal not refunded')
    else:
        require(all(not v['funded'] and v['terminal'] is None for v in state.values()), 'aborted route has committed principal')
    for key, current in state.items():
        lock = locks[key]; chain = dom_chain if lock['face'] == 'DOM' else face_for[lock['position']][1]
        if current['surplus']:
            totals[(chain, lock['asset_id'])]['residual_surplus'] += current['surplus']
    for total in totals.values():
        require(total['in'] == total['out'] + total['deducted_fees'] + total['residual_surplus'], 'asset ledger not conserved')
    canonical = json.dumps(pins, sort_keys=True, separators=(',', ':')).encode()
    return {'schema_version': 6, 'status': 'accounting-witness-verified', 'route_id': route,
            'route': face_for[0][0]+'->DOM->'+face_for[1][0], 'outcome': witness['outcome'],
            'pins_sha256': hashlib.sha256(canonical).hexdigest(), 'observations': len(observations),
            'assets': [dict(chain_id=chain, asset_id=asset, **total) for (chain, asset), total in sorted(totals.items())],
            'consensus_and_inclusion_verified': False, 'complete_production_route_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pins', type=Path, required=True)
    parser.add_argument('--witness', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(load(args.pins), load(args.witness)), indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print('{"status":"refused","scope":"route-accounting"}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
