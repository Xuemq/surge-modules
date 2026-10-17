import copy
import unittest
from surge_merge.core import Invalid, merge, parse_module


def mod(text, source):
    return parse_module((text+'\n').encode(), source)


def preserving_policy(modules):
    base = modules[0].source
    policy = {'schema_version': 2, 'base_source': base,
            'source_sha256': {m.source: m.sha256 for m in modules},
            'excluded_entries': [], 'decisions': []}
    _, report = merge(modules, policy)
    policy['decisions'] = [{'conflict_id': c['id'], 'action': 'preserve-base',
                           'entry_ids': list(dict.fromkeys(e['id'] for e in c['entries'] if e['source'] == base)),
                           'reason': 'Reviewed baseline-first handling; preserve all base occurrences and order.'}
                          for c in report['conflicts']]
    return policy


class BaselinePreservingPolicyTests(unittest.TestCase):
    def modules(self):
        return [mod('[Map Local]\n^a data-type=text data="{}" status-code=200\n^a data-type=text data="[]" status-code=200','base'),
                mod('[URL Rewrite]\n^a _ reject\n^b _ reject','extra')]

    def test_multiple_base_entries_survive_cross_section_conflicts(self):
        modules=self.modules();out,r=merge(modules,preserving_policy(modules))
        self.assertIsNotNone(out)
        self.assertNotIn('^a _ reject',out)
        self.assertIn('^b _ reject',out)
        self.assertLess(out.index('data="{}"'),out.index('data="[]"'))
        self.assertEqual(r['base_entries_preserved'],2)
        self.assertEqual(len(r['inherited_conflicts']),2)

    def test_inherited_ordered_duplicate_occurrences_remain(self):
        line='^a https://example.test/new 302'
        modules=[mod('[URL Rewrite]\n'+line+'\n'+line,'base')]
        out,r=merge(modules,preserving_policy(modules))
        self.assertEqual(out.count(line),2)
        self.assertEqual(r['base_entries_preserved'],2)

    def test_safe_base_duplicates_are_not_silently_reoptimized(self):
        modules=[mod('[Rule]\nDOMAIN,a,REJECT\nDOMAIN,a,REJECT','base')]
        out,r=merge(modules,preserving_policy(modules))
        self.assertEqual(out.count('DOMAIN,a,REJECT'),2)
        self.assertFalse(r['duplicates'])

    def test_missing_base_selection_rejected(self):
        modules=self.modules();p=preserving_policy(modules)
        p['decisions'][0]['entry_ids']=p['decisions'][0]['entry_ids'][:1]
        with self.assertRaises(Invalid): merge(modules,p)

    def test_preserve_action_cannot_select_supplement(self):
        modules=self.modules();p=preserving_policy(modules)
        p['decisions'][-1]['entry_ids'].append(modules[1].entries[0].id)
        with self.assertRaises(Invalid): merge(modules,p)

    def test_ordinary_keep_cannot_drop_base(self):
        modules=[mod('[Rule]\nDOMAIN,a,REJECT','base'),mod('[Rule]\nDOMAIN,a,DIRECT','extra')]
        p=preserving_policy(modules)
        p['decisions'][0].update(action='keep',entry_ids=[modules[1].entries[0].id])
        with self.assertRaises(Invalid): merge(modules,p)

    def test_all_source_hashes_and_order_are_bound(self):
        modules=self.modules();p=preserving_policy(modules)
        for source in ('base','extra'):
            changed=copy.deepcopy(p);changed['source_sha256'][source]='0'*64
            with self.subTest(source=source),self.assertRaises(Invalid):merge(modules,changed)
        with self.assertRaises(Invalid): merge(list(reversed(modules)),p)
        changed=copy.deepcopy(p);changed['source_sha256']=dict(reversed(list(p['source_sha256'].items())))
        with self.assertRaises(Invalid):merge(modules,changed)

    def test_unreviewed_conflicts_still_block(self):
        modules=self.modules();p=preserving_policy(modules);p['decisions'].pop()
        out,r=merge(modules,p)
        self.assertIsNone(out);self.assertTrue(r['conflicts'])

    def test_supplement_overlap_exclusion_keeps_base_and_reports_evidence(self):
        modules=[mod('[Map Local]\n^a/narrow data-type=text data="{}"','base'),mod('[URL Rewrite]\n^a _ reject\n^b _ reject','extra')]
        p=preserving_policy(modules)
        selection={'source':'extra','line':2,'entry_id':modules[1].entries[0].id,
                   'base_entry_ids':[modules[0].entries[0].id], 'reason':'Reviewed broader reject overlaps base response.',
                   'evidence':'Literal-prefix overlap witness: a/narrow; no general regex-equivalence claim.'}
        p['excluded_entries']=[selection]
        out,r=merge(modules,p)
        self.assertNotIn('^a _ reject',out);self.assertIn('^a/narrow',out);self.assertIn('^b _ reject',out)
        self.assertEqual(r['excluded_entries'],[selection])

    def test_overlap_exclusions_cannot_drop_base_or_drift(self):
        modules=[mod('[Map Local]\n^a/narrow data-type=text data="{}"','base'),mod('[URL Rewrite]\n^a _ reject','extra')]
        p=preserving_policy(modules)
        selection={'source':'extra','line':2,'entry_id':modules[1].entries[0].id,
                   'base_entry_ids':[modules[0].entries[0].id], 'reason':'Reviewed overlap.', 'evidence':'a/narrow'}
        for change in ({'source':'base','entry_id':modules[0].entries[0].id}, {'line':3},
                       {'entry_id':'0'*64},{'base_entry_ids':['0'*64]}, {'reason':''},{'evidence':''}):
            with self.subTest(change=change),self.assertRaises(Invalid):
                merge(modules,{**p,'excluded_entries':[{**selection,**change}]})
        with self.assertRaises(Invalid):merge(modules,{**p,'excluded_entries':[selection,selection]})

    def test_base_mitm_order_preserved_and_hosts_only_appended(self):
        modules=[mod('[MITM]\nhostname = %APPEND% first.example, *.shared.example','base'),mod('[MITM]\nhostname = %APPEND% extra.example','extra')]
        out,r=merge(modules,preserving_policy(modules))
        self.assertIn('hostname = %APPEND% first.example, *.shared.example, extra.example',out)

    def test_legacy_single_keep_rule_stays_strict(self):
        modules=self.modules();p=preserving_policy(modules)
        legacy={'schema_version':1,'decisions':p['decisions']}
        with self.assertRaises(Invalid):merge(modules,legacy)

    def test_request_reject_cannot_silently_shadow_baidu_style_response_script(self):
        pattern=r'^https://maps.example.test/\?qt=ads'
        original=f'map_cleanup = type=http-response, pattern={pattern}, script-path=https://scripts.example.test/maps.js, requires-body=true'
        modules=[mod('[Script]\n'+original,'base'),mod('[URL Rewrite]\n'+pattern+' _ reject','extra')]
        out,report=merge(modules)
        self.assertIsNone(out)
        self.assertIn('request-shadows-transform',[c['kind'] for c in report['conflicts']])
        out,report=merge(modules,preserving_policy(modules))
        self.assertIn(original,out);self.assertNotIn('_ reject',out)

    def test_netease_style_broader_reject_exclusion_protects_response_script(self):
        pattern=r'^https://music.example.test/api/mybarad'
        original=f'music_cleanup = type=http-response, pattern={pattern}, script-path=https://scripts.example.test/music.js, requires-body=true'
        modules=[mod('[Script]\n'+original,'base'),mod('[URL Rewrite]\n^https://music.example.test/api/ _ reject','extra')]
        p=preserving_policy(modules)
        p['excluded_entries']=[{'source':'extra','line':2,'entry_id':modules[1].entries[0].id,
            'base_entry_ids':[modules[0].entries[0].id],'reason':'Reviewed finite overlap can short-circuit the expected origin response.',
            'evidence':'Both literal regexes match https://music.example.test/api/mybarad; not an exhaustive overlap proof.'}]
        out,report=merge(modules,p)
        self.assertIn(original,out);self.assertNotIn('_ reject',out)
        self.assertEqual(report['excluded_entries'],p['excluded_entries'])

    def test_reject_conflicts_with_body_rewrites_in_both_phases(self):
        for phase in ('http-request','http-response','http-request-jq','http-response-jq'):
            raw=phase+' ^https://app.example.test/a '+('del(.ad)' if phase.endswith('-jq') else 'old new')
            modules=[mod('[Body Rewrite]\n'+raw,'base'),mod('[URL Rewrite]\n^https://app.example.test/a _ reject','extra')]
            with self.subTest(phase=phase):
                out,report=merge(modules);self.assertIsNone(out)
                self.assertIn('request-shadows-transform',[c['kind'] for c in report['conflicts']])
                out,_=merge(modules,preserving_policy(modules));self.assertIn(raw,out);self.assertNotIn('_ reject',out)

    def test_local_response_and_redirects_conflict_with_header_and_script(self):
        for phase in ('http-request','http-response'):
            for section,raw in [('Header Rewrite',phase+' ^https://app.example.test/a header-del x-ad'),
                    ('Script','cleanup = type='+phase+', pattern=^https://app.example.test/a, script-path=https://scripts.example.test/a.js')]:
                for terminal_section,terminal in [('Map Local','^https://app.example.test/a data-type=text data=" "'),
                        ('URL Rewrite','^https://app.example.test/a https://app.example.test/b 302')]:
                    modules=[mod('['+section+']\n'+raw,'base'),mod('['+terminal_section+']\n'+terminal,'extra')]
                    with self.subTest(phase=phase,section=section,terminal=terminal_section):
                        out,report=merge(modules);self.assertIsNone(out)
                        self.assertIn('request-shadows-transform',[c['kind'] for c in report['conflicts']])
                        out,_=merge(modules,preserving_policy(modules));self.assertIn(raw,out);self.assertNotIn(terminal,out)

    def test_inherited_request_shadow_keeps_all_base_transformations(self):
        base=mod('[URL Rewrite]\n^a _ reject\n[Body Rewrite]\nhttp-response ^a first second\nhttp-response ^a second third','base')
        extra=mod('[Map Local]\n^a data-type=text data=" "','extra')
        out,report=merge([base,extra],preserving_policy([base,extra]))
        for e in base.entries:self.assertIn(e.raw,out)
        self.assertNotIn('data-type=text',out)
        self.assertTrue(any(c['kind']=='request-shadows-transform' for c in report['inherited_conflicts']))

    def test_nonliteral_overlap_is_not_claimed_resolved_by_exact_guard(self):
        modules=[mod('[Body Rewrite]\nhttp-response ^https://app.example.test/ads old new','base'),
                 mod('[URL Rewrite]\n^https://app.example.test/ _ reject','extra')]
        out,report=merge(modules)
        self.assertIsNotNone(out)
        self.assertTrue(any('No regex equivalence/overlap proof' in x for x in report['warnings']))

    def test_supplement_body_and_header_cannot_silently_modify_script_input(self):
        raw='cleanup = type=http-response, pattern=^a, script-path=https://scripts.example.test/a.js'
        for section,line in [('Body Rewrite','http-response ^a old new'),
                             ('Header Rewrite','http-response ^a header-del x-example')]:
            modules=[mod('[Script]\n'+raw,'base'),mod('['+section+']\n'+line,'extra')]
            with self.subTest(section=section):
                out,report=merge(modules);self.assertIsNone(out)
                self.assertIn('cross-section-transform',[c['kind'] for c in report['conflicts']])
                out,_=merge(modules,preserving_policy(modules));self.assertIn(raw,out);self.assertNotIn(line,out)

    def test_explicit_response_contract_policy_keeps_json_gif_and_blank_payloads(self):
        payloads=['data-type=text data="{}" status-code=200 header="Content-Type:application/json"']*3
        payloads+=['data-type=tiny-gif status-code=200']*2
        payloads+=['data-type=text data=" " status-code=200']
        for index,payload in enumerate(payloads):
            pattern='^https://contract.example.test/endpoint'+str(index)
            native=pattern+' '+payload
            modules=[mod('[Rule]\nDOMAIN,unrelated.example.test,REJECT','base'),
                     mod('[URL Rewrite]\n'+pattern+' _ reject','reject-source'),
                     mod('[Map Local]\n'+native,'response-source')]
            p={'schema_version':2,'base_source':'base','source_sha256':{m.source:m.sha256 for m in modules},
               'excluded_entries':[],'decisions':[]}
            out,r=merge(modules,p);self.assertIsNone(out)
            p['decisions']=[{'conflict_id':c['id'],'action':'keep','entry_ids':[modules[2].entries[0].id],
                'reason':'Explicit local proposal preserves the original successful response contract; runtime unverified.'}
                for c in r['conflicts']]
            with self.subTest(payload=payload,index=index):
                out,r=merge(modules,p)
                self.assertIn(native,out);self.assertNotIn('_ reject',out)
                self.assertEqual(r['base_entries_preserved'],1)

if __name__=='__main__':unittest.main()
