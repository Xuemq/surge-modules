import unittest
from surge_merge.core import Invalid,digest,parse_module
from surge_merge.single import optimize_single

class SingleSourceTests(unittest.TestCase):
    def run_single(self,text,**changes):
        data=text.encode()
        policy={'source_id':'base','source_sha256':digest(data),'modification_date':'2026-10-17','argument_defaults':{},'confirmed_invalid_entries':[]}
        policy.update(changes)
        return optimize_single(data,'base',policy)

    def test_comments_metadata_preserved(self):
        out,r=self.run_single('#!name=Original\n#!author=Original Author\n#!raw-url=https://example.test/x\n# Source comment\n[Rule]\nDOMAIN,a,REJECT\n')
        self.assertIn('#!author=Original Author',out)
        self.assertIn('# Source comment',out)
        self.assertNotIn('\n#!raw-url=',out)

    def test_only_safe_duplicates_removed(self):
        out,r=self.run_single('[Rule]\nDOMAIN,a,REJECT\nDOMAIN,a,REJECT\n[Body Rewrite]\nhttp-response ^a a aa\nhttp-response ^a a aa\n')
        self.assertEqual(out.count('DOMAIN,a,REJECT'),1)
        self.assertEqual(out.count('http-response ^a a aa'),2)

    def test_same_key_distinct_behavior_preserved(self):
        out,r=self.run_single('[Rule]\nDOMAIN,a,REJECT\nDOMAIN,a,DIRECT\n')
        self.assertLess(out.index('DOMAIN,a,REJECT'),out.index('DOMAIN,a,DIRECT'))
        self.assertEqual(len(r['retained_conflicts']),1)

    def test_script_names_unique_and_stable(self):
        script='same = type=http-response, pattern=^a, script-path=https://example.test/a.js'
        out,r=self.run_single('[Script]\n'+script+'\n'+script.replace('pattern=^a','pattern=^b')+'\n')
        names=[e.key for e in parse_module(out.encode(),'x').entries]
        self.assertEqual(len(names),len(set(names)))
        self.assertEqual(r['changes_by_kind']['unique-script-label'],1)

    def test_defaults_require_evidence_values(self):
        text='#!arguments=first:true\n[Script]\nx = type=http-response, pattern=^a, script-path=https://example.test/a.js, argument={{{second}}}\n'
        with self.assertRaises(Invalid):self.run_single(text)
        out,r=self.run_single(text,argument_defaults={'second':'false'},defaults_evidence={'url':'https://example.test/original'})
        self.assertIn('#!arguments=first:true,second:false',out)

    def test_stale_policy_rejected(self):
        with self.assertRaises(Invalid):self.run_single('[Rule]\nDOMAIN,a,REJECT\n',source_sha256='0'*64)

    def test_json_body_encoding_preserves_content(self):
        out,r=self.run_single('[Map Local]\n^a data-type=text data="{"code": 0}" header="Content-Type:application/json"\n')
        self.assertIn('data-type=base64 data="eyJjb2RlIjogMH0="',out)
        self.assertIn('Content-Type:application/json',out)

    def test_invalid_rule_removal_requires_evidence(self):
        line='DOMAIN,a,REJECT';text='[Rule]\n'+line+'\nDOMAIN,b,REJECT\n'
        decision={'line_sha256':digest(line),'classification':'timeout','reason':'failed','evidence':['https://example.test']}
        with self.assertRaises(Invalid):self.run_single(text,confirmed_invalid_entries=[decision])
        decision['classification']='upstream-retired'
        out,r=self.run_single(text,confirmed_invalid_entries=[decision])
        self.assertNotIn(line,out);self.assertEqual(len(r['removed']),1)

    def test_unused_removal_rejected(self):
        decision={'line_sha256':'0'*64,'classification':'confirmed-404','reason':'retired','evidence':['https://example.test']}
        with self.assertRaises(Invalid):self.run_single('[Rule]\nDOMAIN,a,REJECT\n',confirmed_invalid_entries=[decision])

    def test_reviewed_script_argument_object(self):
        import json,re
        from surge_merge.core import params
        raw='x = type=http-response, pattern=^a, script-path=https://example.test/a.js, argument=[{option}]'
        repair={'argument':'"{"option":{{{option}}}}"','reason':'Reviewed runtime expects object','evidence':'https://example.test/source'}
        out,r=self.run_single('[Script]\n'+raw+'\n',argument_defaults={'option':'true'},script_argument_repairs={digest(raw):repair})
        mod=parse_module(out.encode(),'x')
        arg=params(mod.entries[0].raw.partition('=')[2])['argument'].replace('{{{option}}}','true')
        self.assertEqual(json.loads(arg),{'option':True})
        self.assertEqual(r['changes_by_kind']['script-argument-object'],1)

    def test_netease_home_object_preserves_selected_modules(self):
        import json
        from surge_merge.core import params
        defaults={'PRGG':'true','PRRK':'false','PRDRD':'false','PRSCVPT':'false','PRST':'false','PRRR':'true','HMPR':'false','PRMST':'true','PRCN':'true'}
        raw='home = type=http-response, pattern=^a, script-path=https://example.test/home.js, argument=[{PRGG},{PRRK}]'
        arg='"{'+','.join('"'+k+'":{{{'+k+'}}}' for k in defaults)+'}"'
        repair={'argument':arg,'reason':'Official named-object defaults','evidence':'https://example.test/native.sgmodule'}
        out,r=self.run_single('[Script]\n'+raw+'\n',argument_defaults=defaults,script_argument_repairs={digest(raw):repair})
        p=params(parse_module(out.encode(),'x').entries[0].raw.partition('=')[2])['argument']
        for k,v in defaults.items():p=p.replace('{{{'+k+'}}}',v)
        obj=json.loads(p)
        self.assertIsInstance(obj,dict)
        self.assertEqual({k for k,v in obj.items() if v != 1},{'PRRK','PRDRD','PRSCVPT','PRST','HMPR'})

    def test_argument_repair_requires_exact_entry(self):
        repair={'argument':'"{}"','reason':'Reviewed','evidence':'https://example.test/source'}
        with self.assertRaises(Invalid):
            self.run_single('[Rule]\nDOMAIN,a,REJECT\n',script_argument_repairs={'0'*64:repair})

    def test_reproducible_output(self):
        text='[Rule]\nDOMAIN,a,REJECT\n'
        self.assertEqual(self.run_single(text),self.run_single(text))

if __name__=='__main__':unittest.main()
