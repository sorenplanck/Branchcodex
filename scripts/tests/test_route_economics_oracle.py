import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import route_economics_oracle as oracle


def h(n): return f'{n:064x}'


def example(first='BTC',second='EVM',outcome='settled'):
    faces=['BTC','EVM','XMR','SOL'];legs=[{'position':i,'settlement_id':h(10+i),'face':face,
        'chain_id':h(20+faces.index(face))} for i,face in enumerate([first,second])]
    pins={'schema_version':6,'route_id':h(1),'dom_chain_id':h(2),'legs':legs,'locks':[]}
    witness={'schema_version':6,'route_id':h(1),'outcome':outcome,'observations':[]}
    for i in range(2):
        for j,face in enumerate(['DOM',legs[i]['face']]):
            index=i*2+j;key=h(30+index)
            lock={'lock_id':key,'position':i,'face':face,'asset_id':h(40+j+i*2),
                'principal':1000,'funder':h(50+index),'recipient':h(60+index),'maximum_deducted_fee':10,'minimum_recipient':990}
            pins['locks'].append(lock)
            if outcome=='aborted':continue
            for action in ['fund','claim' if outcome=='settled' else 'refund']:
                n=len(witness['observations'])+1
                witness['observations'].append({'event_id':h(100+n),'route_id':h(1),
                    'settlement_id':legs[i]['settlement_id'],'lock_id':key,'effect_id':h(200+n),
                    'chain_id':h(2) if face=='DOM' else legs[i]['chain_id'],'asset_id':lock['asset_id'],
                    'txid':h(300+n),'event_index':0,'action':action,'amount':1000 if action=='fund' else 995,
                    'recipient':key if action=='fund' else lock['recipient'] if action=='claim' else lock['funder'],
                    'deducted_fee':0 if action=='fund' else 5,'finalized':True})
    return pins,witness


class RouteEconomicsOracleTests(unittest.TestCase):
    def test_all_sixteen_pairs_in_three_terminal_accounting_scenarios(self):
        count=0
        for a in ['BTC','EVM','XMR','SOL']:
            for b in ['BTC','EVM','XMR','SOL']:
                for outcome in ['settled','compensated','aborted']:
                    with self.subTest(a=a,b=b,outcome=outcome):
                        pins,witness=example(a,b,outcome);result=oracle.verify(pins,witness)
                        self.assertEqual(result['route'],a+'->DOM->'+b)
                        self.assertFalse(result['complete_production_route_verified']);count+=1
        self.assertEqual(count,48)

    def test_principal_fee_recipient_asset_and_chain_mutations_are_refused(self):
        for key,value in [('amount',994),('deducted_fee',6),('recipient',h(999)),('asset_id',h(999)),
                          ('chain_id',h(999)),('settlement_id',h(999)),('route_id',h(999)),('finalized',False)]:
            pins,witness=example();witness['observations'][1][key]=value
            with self.subTest(key=key),self.assertRaises(oracle.Refused):oracle.verify(pins,witness)

    def test_duplicate_tx_event_effect_and_terminal_are_refused(self):
        for variant in range(4):
            pins,witness=example();event=copy.deepcopy(witness['observations'][1])
            if variant>=1:event['event_id']=h(999)
            if variant>=2:event['txid']=h(999)
            if variant>=3:event['effect_id']=h(999)
            witness['observations'].append(event)
            with self.assertRaises(oracle.Refused):oracle.verify(pins,witness)

    def test_dom_cannot_be_removed_or_replaced_with_counterparty(self):
        pins,witness=example();pins['locks']=pins['locks'][1:]
        with self.assertRaises(oracle.Refused):oracle.verify(pins,witness)
        pins,witness=example();pins['legs'][0]['chain_id']=pins['dom_chain_id']
        with self.assertRaises(oracle.Refused):oracle.verify(pins,witness)

    def test_wrong_terminal_claim_and_unrecovered_funding_are_refused(self):
        for outcome in ['compensated','aborted']:
            pins,witness=example();witness['outcome']=outcome
            with self.assertRaises(oracle.Refused):oracle.verify(pins,witness)
        pins,witness=example();witness['observations'].pop()
        with self.assertRaises(oracle.Refused):oracle.verify(pins,witness)

    def test_partial_funding_can_be_compensated_without_inventing_other_funding(self):
        pins,witness=example(outcome='compensated');witness['observations']=witness['observations'][:2]
        self.assertEqual(oracle.verify(pins,witness)['outcome'],'compensated')
        witness['observations'].pop()
        with self.assertRaises(oracle.Refused):oracle.verify(pins,witness)

    def test_surplus_is_separate_from_principal_and_reported_as_residual(self):
        pins,witness=example();event=copy.deepcopy(witness['observations'][0])
        event.update(event_id=h(901),effect_id=h(902),txid=h(903),action='surplus',amount=1)
        witness['observations'].insert(1,event)
        result=oracle.verify(pins,witness)
        self.assertEqual(sum(asset['residual_surplus'] for asset in result['assets']),1)
        witness['observations'][2]['amount']+=1
        with self.assertRaises(oracle.Refused):oracle.verify(pins,witness)

    def test_cross_asset_amounts_are_never_netted_and_boolean_numbers_fail(self):
        pins,witness=example();witness['observations'][1]['amount']-=1;witness['observations'][3]['amount']+=1
        with self.assertRaises(oracle.Refused):oracle.verify(pins,witness)
        for key in ['amount','deducted_fee','event_index']:
            pins,witness=example();witness['observations'][0][key]=True
            with self.assertRaises(oracle.Refused):oracle.verify(pins,witness)

    def test_duplicate_json_and_oversized_input_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'witness.json';path.write_text('{"route_id":1,"route_id":2}')
            with self.assertRaises(oracle.Refused):oracle.load(path)
            path.write_bytes(b' '* (oracle.MAX_BYTES+1))
            with self.assertRaises(oracle.Refused):oracle.load(path)

    def test_same_family_settlement_and_lock_transplants_fail(self):
        pins,witness=example('EVM','EVM');witness['observations'][1]['settlement_id']=pins['legs'][1]['settlement_id']
        with self.assertRaises(oracle.Refused):oracle.verify(pins,witness)
        pins,witness=example('XMR','XMR');pins['locks'][2]['lock_id']=pins['locks'][0]['lock_id']
        with self.assertRaises(oracle.Refused):oracle.verify(pins,witness)
