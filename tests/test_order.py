import copy
import unittest
from surge_merge.core import Invalid,digest
from surge_merge.order import restore_reviewed_order

SECTIONS=['General','Rule','URL Rewrite','Header Rewrite','Body Rewrite','Map Local','Script','MITM']
class OrderTests(unittest.TestCase):
    def setUp(self):
        self.lines=['[General]','force-http-engine-hosts = %APPEND% a:80','[Rule]','DOMAIN,b,REJECT','DOMAIN,a,REJECT','[URL Rewrite]','[Header Rewrite]','[Body Rewrite]','[Map Local]','[Script]','[MITM]','hostname = %APPEND% b, a']
        self.p={'schema_version':1,'moves':[{'section':'Rule','targets':[digest('DOMAIN,a,REJECT')],'before':digest('DOMAIN,b,REJECT')}],'hostname_order':{'input_sha256':digest(self.lines[-1]),'raw':'hostname = %APPEND% a, b'},'section_order':SECTIONS,'reason':'Retain reviewed order'}
    def run_policy(self,p=None,lines=None):
        return restore_reviewed_order(lines or self.lines,p or self.p,{'changes':[]})
    def test_exact_permutation(self):
        out=self.run_policy();self.assertLess(out.index('DOMAIN,a,REJECT'),out.index('DOMAIN,b,REJECT'));self.assertEqual(len(out),len(self.lines));self.assertEqual(out[-1],'hostname = %APPEND% a, b')
    def test_no_policy_preserves_bytes(self):
        self.assertEqual(restore_reviewed_order(self.lines,None,{}),self.lines)
    def test_missing_changed_or_duplicate_target_blocks(self):
        for lines in [self.lines[:-2]+self.lines[-2:], [x.replace('DOMAIN,a,','DOMAIN,c,') for x in self.lines], self.lines[:4]+['DOMAIN,a,REJECT']+self.lines[4:]]:
            if lines==self.lines:continue
            with self.assertRaises(Invalid):self.run_policy(lines=lines)
        p=copy.deepcopy(self.p);p['moves'][0]['before']=digest('absent')
        with self.assertRaises(Invalid):self.run_policy(p)
    def test_forbidden_section_and_duplicate_policy_block(self):
        p=copy.deepcopy(self.p);p['moves'][0]['section']='MITM'
        with self.assertRaises(Invalid):self.run_policy(p)
        p=copy.deepcopy(self.p);p['moves']*=2
        with self.assertRaises(Invalid):self.run_policy(p)
    def test_hostname_expansion_removal_or_mode_change_blocks(self):
        for raw in ['hostname = %APPEND% a, b, c','hostname = %APPEND% a','hostname = a, b','hostname = %APPEND% a, a, b','hostname = %APPEND% a, b\nfoo=bar']:
            p=copy.deepcopy(self.p);p['hostname_order']['raw']=raw
            with self.assertRaises(Invalid):self.run_policy(p)
    def test_hostname_source_drift_blocks(self):
        with self.assertRaises(Invalid):self.run_policy(lines=self.lines[:-1]+['hostname = %APPEND% c, a'])
    def test_section_loss_or_duplicate_blocks(self):
        with self.assertRaises(Invalid):self.run_policy(lines=self.lines+['[General]'])
        with self.assertRaises(Invalid):self.run_policy(lines=[x for x in self.lines if x!='[Body Rewrite]'])
    def test_policy_not_mutated(self):
        p=copy.deepcopy(self.p);lines=self.lines.copy();self.run_policy();self.assertEqual(p,self.p);self.assertEqual(lines,self.lines)
