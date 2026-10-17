import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from surge_merge.core import Invalid, digest
from surge_merge.converter import convert_qx
from surge_merge.__main__ import main
from surge_merge.pipeline import atomic_write, audit, cache_path, check_updates, check_url, fetch, json_write, load_manifest, verify_bytes


class ConversionTests(unittest.TestCase):
    def convert(self,text,policy=None):
        return convert_qx((text+'\n').encode(),policy)

    def test_reject_variants(self):
        out,r=self.convert('^a url reject\n^b url reject-200\n^c url reject-dict\n^d url reject-img\nhostname = a,b')
        self.assertIn('data=" " status-code=200',out)
        self.assertIn('Content-Type:application/json',out)
        self.assertIn('data-type=tiny-gif',out)
        self.assertIn('%APPEND% a,b',out)

    def test_native_rule_mapping(self):
        out,r=self.convert('host, a.test, direct\nhost-suffix,b.test,reject')
        self.assertIn('DOMAIN,a.test,DIRECT',out)
        self.assertIn('DOMAIN-SUFFIX,b.test,REJECT',out)

    def test_body_and_jq(self):
        out,r=self.convert("^a url response-body old value response-body new value\n^b url jsonjq-response-body '.data={}'")
        self.assertIn("'old value' 'new value'",out)
        self.assertIn('http-response-jq',out)

    def test_request_body_requires_exact_review(self):
        raw='^a url request-body x request-body y'
        out,r=self.convert(raw)
        self.assertIsNone(out)
        out,r=self.convert(raw,{'approved_request_body_hashes':[digest(raw)]})
        self.assertIsNotNone(out)

    def test_script_runtime_review(self):
        raw='^a url script-response-body https://example.test/x.js'
        out,r=self.convert(raw)
        self.assertIsNone(out)
        out,r=self.convert(raw,{'approved_script_urls':['https://example.test/x.js']})
        self.assertIn('type=http-response',out)
        self.assertIn('requires-body=true',out)

    def test_script_name_stable_unique(self):
        policy={'approved_script_urls':['https://example.test/x.js']}
        out,r=self.convert('^a url script-response-body https://example.test/x.js\n^b url script-response-body https://example.test/x.js',policy)
        names=[x.split('=')[0] for x in out.splitlines() if x.startswith('moyu_')]
        self.assertEqual(len(names),len(set(names)))

    def test_unsupported_never_partial_output(self):
        for action in ('echo-response text/json echo-response https://example.test/x','script-analyze-echo-response https://example.test/x','unknown'):
            with self.subTest(action=action):
                out,r=self.convert('^a url reject\n^b url '+action)
                self.assertIsNone(out)
                self.assertEqual(r['converted'],1)
                self.assertEqual(len(r['unsupported']),1)

    def test_reviewed_analyze_echo(self):
        url='https://example.test/12306.js'
        out,r=self.convert('^a url script-analyze-echo-response '+url,{'approved_analyze_script_urls':[url]})
        self.assertIn('type=http-request',out)
        self.assertIn('requires-body=true',out)

    def test_reviewed_static_echo(self):
        url='https://example.test/static.json'
        out,r=self.convert('^a url echo-response application/json echo-response '+url,{'approved_static_response_urls':[url]})
        self.assertIn('data-type=file',out)
        self.assertIn('Content-Type:application/json',out)

    def test_reviewed_binary_script(self):
        url='https://example.test/binary.js'
        out,r=self.convert('^a url script-response-body '+url,{'approved_script_urls':[url],'binary_script_urls':[url]})
        self.assertIn('binary-body-mode=true',out)

    def test_html_and_credentials(self):
        for data in (b'<html>Error</html>',b'# password = x\n^a url reject\n'):
            with self.assertRaises(Invalid):
                convert_qx(data)

    def exclusion_policy(self, data, raw, line=1):
        return {'source_sha256':digest(data),'excluded_entries':[{'line':line,'line_sha256':digest(raw),
                'directive':'request-body','classification':'manual-scope-exclusion',
                'reason':'Region modification explicitly excluded from requested ad-blocking scope.'}]}

    def test_request_body_scope_exclusion_is_reported(self):
        raw='^testflight url request-body old request-body new'
        data=(raw+'\n^keep url reject\nhostname = keep.example\n').encode()
        policy=self.exclusion_policy(data,raw)
        out,r=convert_qx(data,policy)
        self.assertNotIn('testflight',out)
        self.assertIn('^keep _ reject',out)
        self.assertIn('hostname = %APPEND% keep.example',out)
        self.assertEqual(r['excluded'],policy['excluded_entries'])
        self.assertEqual(r['converted'],2)
        self.assertEqual(r['directives']['request-body'],1)

    def test_request_body_scope_exclusion_source_bound(self):
        raw='^testflight url request-body old request-body new';data=(raw+'\n^keep url reject\n').encode()
        policy=self.exclusion_policy(data,raw)
        for source_hash in (None,'0'*64):
            with self.subTest(source_hash=source_hash),self.assertRaises(Invalid):
                convert_qx(data,{**policy,'source_sha256':source_hash})

    def test_request_body_scope_exclusion_target_bound(self):
        raw='^testflight url request-body old request-body new';data=(raw+'\n^keep url reject\n').encode()
        policy=self.exclusion_policy(data,raw)
        for changed in ({'line':2},{'line':3},{'line_sha256':'0'*64},{'directive':'hostname'},{'line':True}):
            with self.subTest(changed=changed),self.assertRaises(Invalid):
                convert_qx(data,{**policy,'excluded_entries':[{**policy['excluded_entries'][0],**changed}]})

    def test_request_body_scope_exclusion_does_not_hide_other_failures(self):
        raw='^testflight url request-body old request-body new';data=(raw+'\n^other url unknown\n').encode()
        out,r=convert_qx(data,self.exclusion_policy(data,raw))
        self.assertIsNone(out)
        self.assertEqual(len(r['excluded']),1)
        self.assertEqual(len(r['unsupported']),1)
        self.assertEqual(r['unsupported'][0]['line'],2)

    def test_request_body_scope_exclusion_one_occurrence_only(self):
        raw='^testflight url request-body old request-body new';data=(raw+'\n'+raw+'\n^keep url reject\n').encode()
        out,r=convert_qx(data,self.exclusion_policy(data,raw))
        self.assertIsNone(out)
        self.assertEqual(len(r['excluded']),1)
        self.assertEqual(r['unsupported'][0]['line'],2)

    def test_request_body_scope_exclusion_rejects_duplicate_or_conflicting_policy(self):
        raw='^testflight url request-body old request-body new';data=(raw+'\n^keep url reject\n').encode()
        policy=self.exclusion_policy(data,raw)
        for changed in ({'excluded_entries':policy['excluded_entries']*2},{'approved_request_body_hashes':[digest(raw)]}):
            with self.subTest(changed=changed),self.assertRaises(Invalid):
                convert_qx(data,{**policy,**changed})

    def test_request_body_scope_exclusion_cannot_hide_comments(self):
        raw='# scope comment';data=(raw+'\n^keep url reject\n').encode()
        with self.assertRaises(Invalid):
            convert_qx(data,self.exclusion_policy(data,raw))


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.data=b'[Rule]\nDOMAIN,a.test,REJECT\n'
        self.manifest={'schema_version':1,'base':'base','sources':[{'id':'base','format':'surge','url':'https://raw.githubusercontent.com/fmz200/wool_scripts/main/test.module','sha256':digest(self.data),'bytes':len(self.data)}],'redistribution':{'approved':False},'conversion_policy':{'reviewed':False}}
        self.path=self.root/'sources.json';json_write(self.path,self.manifest)
        self.cache=self.root/'cache';self.cache.mkdir()
        cache_path(self.cache,self.manifest['sources'][0]).write_bytes(self.data)
        self.overrides={'schema_version':1,'decisions':[]}

    def tearDown(self):
        self.tmp.cleanup()

    def test_manifest_validation(self):
        self.assertEqual(load_manifest(self.path)['base'],'base')
        self.manifest['base']='not-base';json_write(self.path,self.manifest)
        with self.assertRaises(Invalid):load_manifest(self.path)

    def test_urls_restrict_origins(self):
        for url in ('http://raw.githubusercontent.com/fmz200/wool_scripts/a','https://evil.test/x','https://raw.githubusercontent.com/evil/repo/main/file','https://raw.githubusercontent.com/fmz200/wool_scripts/a?token=secret','https://user:secret@ddgksf2013.top/rewrite/StartUpAds.conf','https://ddgksf2013.top/other'):
            with self.subTest(url=url),self.assertRaises(Invalid):check_url(url)

    def test_hash_mismatch_and_truncation(self):
        with self.assertRaises(Invalid):verify_bytes(self.manifest['sources'][0],self.data[:-1])

    def test_local_build_publication_blocked(self):
        out,r=audit(self.manifest,self.cache,self.overrides)
        self.assertIsNotNone(out)
        self.assertFalse(r['redistribution_reviewed'])
        self.assertIn('publication_blocked',r)

    def test_missing_source_blocks(self):
        self.manifest['sources'].append({**self.manifest['sources'][0],'id':'missing'})
        out,r=audit(self.manifest,self.cache,self.overrides)
        self.assertIsNone(out)
        self.assertIn('missing',r['blockers'][0])

    def test_fetch_failure_preserves_cache(self):
        with patch('surge_merge.pipeline.download',return_value=b'wrong\n'):
            with self.assertRaises(Invalid):fetch(self.manifest,self.cache)
        self.assertEqual(cache_path(self.cache,self.manifest['sources'][0]).read_bytes(),self.data)

    def test_fetch_does_not_run_source(self):
        with patch('surge_merge.pipeline.download',return_value=self.data) as d:
            fetch(self.manifest,self.cache)
            self.assertEqual(d.call_count,1)

    def test_atomic_failure_preserves_previous(self):
        path=self.root/'candidate';path.write_bytes(b'last good')
        with patch('surge_merge.pipeline.os.replace',side_effect=OSError('test')):
            with self.assertRaises(OSError):atomic_write(path,b'new')
        self.assertEqual(path.read_bytes(),b'last good')
        self.assertFalse(list(self.root.glob('.candidate.*')))

    def test_cli_failure_preserves_last_candidate(self):
        output=self.root/'candidate.sgmodule';output.write_bytes(b'last good')
        overrides=self.root/'overrides.json';json_write(overrides,self.overrides)
        cache_path(self.cache,self.manifest['sources'][0]).write_bytes(b'bad')
        rc=main(['build','--manifest',str(self.path),'--cache',str(self.cache),'--overrides',str(overrides),'--output',str(output),'--report',str(self.root/'report.json')])
        self.assertEqual(rc,2);self.assertEqual(output.read_bytes(),b'last good')

    def test_updates_sanitized(self):
        with patch('surge_merge.pipeline.download',side_effect=RuntimeError('SECRET-UPSTREAM-TEXT')):
            r=check_updates(self.manifest)
        self.assertNotIn('SECRET-UPSTREAM-TEXT',json.dumps(r))
        self.assertEqual(r['status'],'blocked')

    def test_updates_change_does_not_modify_lock(self):
        before=self.path.read_bytes()
        m=copy.deepcopy(self.manifest);m['redistribution']['approved']=True;m['conversion_policy']['reviewed']=True
        with patch('surge_merge.pipeline.download',return_value=self.data+b'# change\n'):
            r=check_updates(m)
        self.assertEqual(r['status'],'changed');self.assertEqual(self.path.read_bytes(),before)

    def test_converter_failure_preserves_output(self):
        input_file=self.root/'qx';input_file.write_text('^a url unknown\n')
        output=self.root/'candidate';output.write_bytes(b'last good')
        rc=main(['convert-qx',str(input_file),'--output',str(output),'--report',str(self.root/'report.json')])
        self.assertEqual(rc,2);self.assertEqual(output.read_bytes(),b'last good')

if __name__ == '__main__':unittest.main()
