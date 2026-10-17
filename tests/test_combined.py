import copy
import json
from pathlib import Path
import tempfile
import unittest
from surge_merge.combined import active_signature, build_combined, main, prepare_modules, source_comment_archive
from surge_merge.converter import convert_qx
from surge_merge.core import Invalid, digest, parse_module
from surge_merge.single import optimize_single


def fixture():
    sources={'fmz200':b'#!name=upstream\n#!author=original author\n# attribution kept\n[Map Local]\n^https://base.example.test/path data-type=text data="{}"\n[MITM]\nhostname = %APPEND% base.example.test\n',
             'blackmatrix7':b'#!author=second author\n[URL Rewrite]\n^https://second.example.test/ _ reject\n',
             'moyu':b'// @Author third author\n^https://third.example.test/ url reject-200\n'}
    base_policy={'source_id':'fmz200','source_sha256':digest(sources['fmz200']),'modification_date':'2026-10-17'}
    conversion={'source_sha256':digest(sources['moyu'])}
    base,_=optimize_single(sources['fmz200'],'fmz200',base_policy)
    native,_=convert_qx(sources['moyu'],conversion)
    bundle={'schema_version':1,'source_sha256':{s:digest(data) for s,data in sources.items()},
        'fmz_policy':base_policy,'conversion_policy':conversion,
        'scope_policies':{s:{'source_id':s,'source_sha256':digest(data),'excluded_entries':[]} for s,data in [('blackmatrix7',sources['blackmatrix7']),('moyu-native',native.encode())]},
        'merge_policy':{'schema_version':2,'base_source':'fmz200-optimized','source_sha256':{'fmz200-optimized':digest(base),'blackmatrix7':digest(sources['blackmatrix7']),'moyu-native':digest(native)},'decisions':[],'excluded_entries':[]},
        'overlap_review':{'witnesses':[],'exceptions':[]},
        'module_metadata':{'name':'去广告合并优化 · 三源','desc':'Static tests only; runtime unverified.','author':'original authors; assembly by fixture','homepage':'https://example.test/repo','raw-url':'https://example.test/module','category':'test','modification_date':'2026-10-17'}}
    return sources,bundle


def overlap_fixture():
    sources,bundle=fixture()
    sources['blackmatrix7']=b'[URL Rewrite]\n^https://base.example.test/ _ reject\n'
    sha=digest(sources['blackmatrix7']);bundle['source_sha256']['blackmatrix7']=sha
    bundle['scope_policies']['blackmatrix7']['source_sha256']=sha;bundle['merge_policy']['source_sha256']['blackmatrix7']=sha
    mods,_=prepare_modules(sources,bundle)
    base=mods[0].entries[0];supplement=mods[1].entries[0]
    bundle['overlap_review']['witnesses']=[{'base_id':base.id,'supplement_id':supplement.id,'witness':'https://base.example.test/path'}]
    return sources,bundle,base,supplement


class CombinedBuildTests(unittest.TestCase):
    def test_reproducible_metadata_first_and_attribution_preserved(self):
        sources,bundle=fixture();text,report=build_combined(sources,bundle)
        self.assertEqual((text,report),build_combined(sources,copy.deepcopy(bundle)))
        self.assertTrue(text.startswith('#!name=去广告合并优化 · 三源\n#!desc='))
        self.assertIn('# #!author=original author',text)
        self.assertIn('# // @Author third author',text)
        self.assertEqual(report['base_entries_preserved'],2)
        self.assertEqual(report['baseline_mitm_hosts_preserved'],1)
        self.assertEqual(report['finite_overlap_review']['unexpected_hits'],0)

    def test_inputs_and_policies_are_not_mutated(self):
        sources,bundle=fixture();before=copy.deepcopy((sources,bundle))
        build_combined(sources,bundle);self.assertEqual((sources,bundle),before)

    def test_every_source_hash_is_bound(self):
        sources,bundle=fixture()
        for source in sources:
            changed=dict(sources);changed[source]+=b'# drift\n'
            with self.subTest(source=source),self.assertRaises(Invalid):build_combined(changed,bundle)

    def test_missing_source_fails_instead_of_skipping(self):
        sources,bundle=fixture();sources.pop('moyu')
        with self.assertRaises(Invalid):build_combined(sources,bundle)

    def test_finite_witness_reintroduction_fails(self):
        sources,bundle,_,_=overlap_fixture()
        with self.assertRaisesRegex(Invalid,'reintroduced'):build_combined(sources,bundle)

    def test_exact_exclusion_clears_only_known_witness(self):
        sources,bundle,base,supplement=overlap_fixture()
        bundle['merge_policy']['excluded_entries']=[{'source':supplement.source,'line':supplement.line,'entry_id':supplement.id,
            'base_entry_ids':[base.id],'reason':'Reviewed finite witness overlap.','evidence':'Both patterns match https://base.example.test/path'}]
        text,report=build_combined(sources,bundle)
        self.assertNotIn(supplement.raw,text);self.assertIn(base.raw,text)
        self.assertEqual(report['finite_overlap_review']['witness_pairs_checked'],1)

    def test_stale_overlap_review_fails(self):
        sources,bundle,_,_=overlap_fixture()
        for change in ({'base_id':'0'*64},{'supplement_id':'0'*64},{'witness':'https://unrelated.test/'}):
            changed=copy.deepcopy(bundle);changed['overlap_review']['witnesses'][0].update(change)
            with self.subTest(change=change),self.assertRaises(Invalid):build_combined(sources,changed)

    def test_unused_idempotence_exception_fails(self):
        sources,bundle=fixture();bundle['overlap_review']['exceptions']=[{'base_id':'1'*64,'supplement_id':'2'*64,'reason':'No supporting witness'}]
        with self.assertRaisesRegex(Invalid,'unused/stale'):build_combined(sources,bundle)

    def test_metadata_injection_fails(self):
        sources,bundle=fixture()
        for value in ('bad\n[Rule]','',123):
            changed=copy.deepcopy(bundle);changed['module_metadata']['desc']=value
            with self.subTest(value=value),self.assertRaises(Invalid):build_combined(sources,changed)

    def test_source_comments_keep_every_original_comment_line(self):
        data=b'#!author=A\n\n[Rule]\n # contributor=B\nDOMAIN,a,REJECT\n// copyright=C\n; note\n'
        self.assertEqual(source_comment_archive(data),'#!author=A\n # contributor=B\n// copyright=C\n; note\n')

    def test_cli_validation_failure_preserves_last_good(self):
        sources,bundle=fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cache=root/'cache';cache.mkdir();out=root/'out';target=out/'modules/merged.optimized.sgmodule';target.parent.mkdir(parents=True);target.write_text('last good')
            for name,data in sources.items():(cache/(name+'.source')).write_bytes(data)
            (cache/'moyu.source').write_bytes(b'bad replacement')
            policy=root/'policy.json';policy.write_text(json.dumps(bundle))
            with self.assertRaises(Invalid):main(['--cache',str(cache),'--bundle',str(policy),'--output-dir',str(out)])
            self.assertEqual(target.read_text(),'last good')
            self.assertFalse((out/'reports/merged-build-report.json').exists())

    def test_stage_api_does_not_require_current_merge_hashes(self):
        sources,bundle=fixture();bundle['merge_policy']['source_sha256']['blackmatrix7']='0'*64
        modules,stages=prepare_modules(sources,bundle)
        self.assertEqual([m.source for m in modules],['fmz200-optimized','blackmatrix7','moyu-native'])
        self.assertIn('conversion',stages)
        with self.assertRaises(Invalid):build_combined(sources,bundle)

if __name__=='__main__':unittest.main()
