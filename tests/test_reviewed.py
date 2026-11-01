import unittest
from copy import deepcopy
from surge_merge.core import Invalid, parse_module
from surge_merge.reviewed import apply_reviewed

class ReviewedRepairs(unittest.TestCase):
 def setUp(self):
  self.text='#!name=T\n[Rule]\nDOMAIN-SUFFIX,example.com,REJECT\nDOMAIN,ad.example.com,REJECT\nDOMAIN,other.net,REJECT\n[MITM]\nhostname = %APPEND% example.com\n'
  es=parse_module(self.text.encode(),'t').entries
  self.policy={'schema_version':1,'entries':[dict(entry_id=es[1].id,replacement=None,kind='covered-domain',reason='Same action coverage.',evidence='Fixture proves suffix inclusion.',witnesses=[es[0].id])],'mitm':None}
 def test_cover_preserves_everything_else(self):
  out,r=apply_reviewed(self.text,self.policy)
  self.assertEqual(out,self.text.replace('DOMAIN,ad.example.com,REJECT',''))
  self.assertEqual(len(r['applied']),1)
 def test_changed_anchor_blocks(self):
  with self.assertRaises(Invalid):apply_reviewed(self.text.replace('ad.example','ad2.example'),self.policy)
 def test_changed_witness_blocks(self):
  with self.assertRaises(Invalid):apply_reviewed(self.text.replace('DOMAIN-SUFFIX,example.com','DOMAIN-SUFFIX,example.net'),self.policy)
 def test_ambiguous_anchor_blocks(self):
  with self.assertRaises(Invalid):apply_reviewed(self.text.replace('DOMAIN,ad.example.com,REJECT','DOMAIN,ad.example.com,REJECT\nDOMAIN,ad.example.com,REJECT'),self.policy)
 def test_wrong_action_not_coverage(self):
  changed=self.text.replace('DOMAIN,ad.example.com,REJECT','DOMAIN,ad.example.com,DIRECT')
  p=deepcopy(self.policy);p['entries'][0]['entry_id']=parse_module(changed.encode(),'t').entries[1].id
  with self.assertRaises(Invalid):apply_reviewed(changed,p)
 def test_cover_must_precede(self):
  changed=self.text.replace('DOMAIN-SUFFIX,example.com,REJECT\nDOMAIN,ad.example.com,REJECT','DOMAIN,ad.example.com,REJECT\nDOMAIN-SUFFIX,example.com,REJECT')
  with self.assertRaises(Invalid):apply_reviewed(changed,self.policy)
 def test_exact_new_host_only(self):
  p=deepcopy(self.policy);p['mitm']={'entry_id':parse_module(self.text.encode(),'t').entries[-1].id,'add_hosts':['api.example.net'],'reason':'Explicit test confirmation.'}
  out,_=apply_reviewed(self.text,p);self.assertIn('example.com, api.example.net',out)
  p['mitm']['add_hosts']=['*.example.net']
  with self.assertRaises(Invalid):apply_reviewed(self.text,p)
 def test_no_security_replacement(self):
  p=deepcopy(self.policy); p['entries'][0].update(entry_id=parse_module(self.text.encode(),'t').entries[-1].id,kind='exact-fix',replacement='hostname = %APPEND% other.net',witnesses=[])
  with self.assertRaises(Invalid):apply_reviewed(self.text,p)
 def test_missing_policy_no_change(self):self.assertEqual(apply_reviewed(self.text)[0],self.text)
 def test_replacement_cannot_insert_section(self):
  p=deepcopy(self.policy);p['entries'][0].update(kind='exact-fix',replacement='[MITM]',witnesses=[])
  with self.assertRaises(Invalid):apply_reviewed(self.text,p)
