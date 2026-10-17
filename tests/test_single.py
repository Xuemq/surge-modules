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

    def scope_decision(self, raw='DOMAIN,a,REJECT', line=2, section='Rule'):
        return {'line':line, 'section':section, 'line_sha256':digest(raw),
                'classification':'manual-scope-exclusion', 'reason':'Reviewed module scope selection.'}

    def test_scope_exclusion_is_one_occurrence_not_a_domain_filter(self):
        text='[Rule]\nDOMAIN,a,REJECT\nDOMAIN,a,REJECT\nDOMAIN,a,DIRECT\nDOMAIN-SUFFIX,shared.example,REJECT\n[MITM]\nhostname = %APPEND% a, *.shared.example, -excluded.shared.example\n'
        out,r=self.run_single(text,scope_exclusions=[self.scope_decision()])
        self.assertEqual(out.count('DOMAIN,a,REJECT'),1)
        self.assertIn('DOMAIN,a,DIRECT',out)
        self.assertIn('DOMAIN-SUFFIX,shared.example,REJECT',out)
        self.assertIn('hostname = %APPEND% a, *.shared.example, -excluded.shared.example',out)
        self.assertEqual(r['removed'],[{'kind':'scope-exclusion',**self.scope_decision()}])
        self.assertNotIn('confirmed-invalid',out)

    def test_scope_exclusion_rejects_wrong_section_line_or_hash(self):
        for changed in ({'section':'Map Local'},{'line':3},{'line_sha256':'0'*64}):
            with self.subTest(changed=changed),self.assertRaises(Invalid):
                self.run_single('[Rule]\nDOMAIN,a,REJECT\n',scope_exclusions=[{**self.scope_decision(),**changed}])

    def test_scope_exclusion_rejects_comments_and_headers(self):
        for raw in ('[Rule]','# comment'):
            with self.subTest(raw=raw),self.assertRaises(Invalid):
                self.run_single(raw+'\n[Rule]\nDOMAIN,a,REJECT\n',scope_exclusions=[self.scope_decision(raw,line=1)])

    def test_scope_exclusion_rejects_duplicate_decisions(self):
        with self.assertRaises(Invalid):
            self.run_single('[Rule]\nDOMAIN,a,REJECT\n',scope_exclusions=[self.scope_decision(),self.scope_decision()])

    def test_scope_exclusion_cannot_remove_mitm_or_general(self):
        for section,raw in [('MITM','hostname = %APPEND% a'),('General','force-http-engine-hosts = %APPEND% a')]:
            with self.subTest(section=section),self.assertRaises(Invalid):
                self.run_single('['+section+']\n'+raw+'\n',scope_exclusions=[self.scope_decision(raw,section=section)])

    def test_scope_exclusion_rejects_malformed_or_unbounded_decisions(self):
        for changed in ({'reason':''},{'classification':'timeout'},{'line':True},{'line':0},
                        {'line_sha256':'bad'}, {'reason':'multiline\nreason'}, {'private_inventory':[]}):
            with self.subTest(changed=changed),self.assertRaises(Invalid):
                self.run_single('[Rule]\nDOMAIN,a,REJECT\n',scope_exclusions=[{**self.scope_decision(),**changed}])

    def test_scope_exclusion_cannot_mask_an_invalid_rule(self):
        raw='not a native rule'
        with self.assertRaises(Invalid):
            self.run_single('[Rule]\n'+raw+'\n',scope_exclusions=[self.scope_decision(raw)])

    def test_scope_exclusion_rejects_conflicting_decisions(self):
        raw='DOMAIN,a,REJECT'
        stale={'line_sha256':digest(raw),'classification':'upstream-retired','reason':'Retired','evidence':['https://example.test/retirement']}
        repair={digest(raw):{'argument':'"{}"','reason':'Reviewed','evidence':'https://example.test/runtime'}}
        for other in ({'confirmed_invalid_entries':[stale]},{'script_argument_repairs':repair}):
            with self.subTest(other=other),self.assertRaises(Invalid):
                self.run_single('[Rule]\n'+raw+'\n',scope_exclusions=[self.scope_decision(raw)],**other)

    def test_nine_scope_exclusions_preserve_every_other_active_line(self):
        from collections import Counter
        selected={'Rule':['DOMAIN,scope.example,REJECT'],
                  'URL Rewrite':['^https://scope.example/'+str(i)+' - reject' for i in range(4)],
                  'Map Local':['^https://scope.example/map'+str(i)+' data-type=text data="{}" status-code=200' for i in range(4)]}
        lines=[];decisions=[]
        for section,entries in selected.items():
            lines.append('['+section+']')
            for raw in entries:
                lines.append(raw)
                decisions.append(self.scope_decision(raw,len(lines),section))
            if section == 'Rule':
                lines.append('DOMAIN,keep.example,REJECT')
        lines.extend(['[Header Rewrite]','http-response ^keep header-add X-Test yes',
                      '[Body Rewrite]','http-response ^keep a aa','http-response ^keep a aa',
                      '[Script]','keep = type=http-response, pattern=^keep, script-path=https://example.test/keep.js',
                      '[MITM]','hostname = %APPEND% keep.example, *.shared.example, -excluded.shared.example'])
        text='\n'.join(lines)+'\n'
        baseline,_=self.run_single(text)
        out,r=self.run_single(text,scope_exclusions=decisions)
        removed_raw={raw for entries in selected.values() for raw in entries}
        expected=[(e.section,e.raw) for e in parse_module(baseline.encode(),'base').entries if e.raw not in removed_raw]
        actual=[(e.section,e.raw) for e in parse_module(out.encode(),'pruned').entries]
        self.assertEqual(actual,expected)
        self.assertEqual(Counter(x['section'] for x in r['removed']),{'Rule':1,'URL Rewrite':4,'Map Local':4})
        self.assertEqual((out,r),self.run_single(text,scope_exclusions=decisions))

    def test_failed_scope_exclusion_keeps_last_good_file(self):
        import json,tempfile
        from pathlib import Path
        from surge_merge.__main__ import main
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';output=root/'candidate';policy=root/'policy';report=root/'report'
            source.write_text('[Rule]\nDOMAIN,a,REJECT\n');output.write_bytes(b'last-good')
            policy.write_text(json.dumps({'source_id':'base','source_sha256':digest(source.read_bytes()),
                                         'modification_date':'2026-10-17','scope_exclusions':[self.scope_decision(line=3)]}))
            code=main(['optimize-base',str(source),'--policy',str(policy),'--output',str(output),'--report',str(report)])
            self.assertEqual(code,2)
            self.assertEqual(output.read_bytes(),b'last-good')
            self.assertEqual(json.loads(report.read_text())['status'],'blocked')

    def test_reviewed_module_metadata_preserves_upstream_attribution(self):
        text='#!name=Original\n#!desc=Original description\n#!author=Original Author\n[Rule]\nDOMAIN,a,REJECT\n'
        out,r=self.run_single(text,module_metadata={'name':'去广告优化 · fmz200','desc':'fmz200 单来源优化；静态校验，尚未实机测试。'})
        self.assertIn('\n#!name=去广告优化 · fmz200\n',out)
        self.assertIn('\n#!desc=fmz200 单来源优化；静态校验，尚未实机测试。\n',out)
        self.assertIn('# Upstream #!name=Original',out)
        self.assertIn('# Upstream #!desc=Original description',out)
        self.assertIn('#!author=Original Author',out)
        self.assertEqual(r['changes_by_kind']['module-metadata'],2)

    def test_reviewed_metadata_added_if_missing(self):
        out,r=self.run_single('[Rule]\nDOMAIN,a,REJECT\n',module_metadata={'name':'Title','desc':'Description'})
        self.assertIn('\n#!name=Title\n',out)
        self.assertIn('\n#!desc=Description\n',out)
        self.assertLess(out.index('#!name=Title'),out.index('[Rule]'))

    def test_reviewed_metadata_rejects_directive_injection(self):
        for metadata in ({'name':'Title\n[MITM]'},{'desc':''},{'author':'Override'}, {'name':None}):
            with self.subTest(metadata=metadata),self.assertRaises(Invalid):
                self.run_single('[Rule]\nDOMAIN,a,REJECT\n',module_metadata=metadata)

if __name__=='__main__':unittest.main()
