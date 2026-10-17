"""Execute only our original generic adapter in a synthetic JS VM; never upstream JS."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which('node'), 'Node unavailable; native JS fixture tests not run')
class HeaderAdapterTests(unittest.TestCase):
    def run_adapter(self, headers=None, spec=None, argument=None):
        if spec is None: spec={'headerNames':['x-operation','X-Operation'],'keywords':['ad.example','splash'],'status':404}
        request={} if headers is None else {'headers':headers}
        js="""const fs=require('fs'),vm=require('vm');const input=JSON.parse(fs.readFileSync(0,'utf8'));const results=[];
        const ctx={$argument:input.argument,$request:input.request,$response:{status:200,body:'unchanged'},$done:r=>results.push(r)};
        const before=JSON.stringify(ctx.$request);vm.runInNewContext(fs.readFileSync('scripts/header-status.js','utf8'),ctx,{timeout:100});
        process.stdout.write(JSON.stringify({results,requestUntouched:before===JSON.stringify(ctx.$request),response:ctx.$response}));"""
        data={'argument':argument if argument is not None else json.dumps(spec),'request':request}
        result=subprocess.run(['node','-e',js],input=json.dumps(data),text=True,capture_output=True,check=True,cwd=Path(__file__).resolve().parents[1])
        out=json.loads(result.stdout)
        self.assertTrue(out['requestUntouched']);self.assertEqual(out['response'],{'status':200,'body':'unchanged'})
        self.assertEqual(len(out['results']),1)
        return out['results'][0]

    def test_match_changes_only_status(self):
        self.assertEqual(self.run_adapter({'x-operation':'prefix.ad.example.suffix'}),{'status':404})

    def test_normal_operations_pass_through(self):
        self.assertEqual(self.run_adapter({'x-operation':'login.account'}),{})

    def test_missing_headers_pass_through(self):
        self.assertEqual(self.run_adapter(),{})

    def test_exact_header_spelling_and_case_sensitive_keyword(self):
        self.assertEqual(self.run_adapter({'X-Operation':'splash'}),{'status':404})
        self.assertEqual(self.run_adapter({'X-OPERATION':'splash'}),{})
        self.assertEqual(self.run_adapter({'x-operation':'SPLASH'}),{})

    def test_priority_and_empty_fallback_preserved(self):
        self.assertEqual(self.run_adapter({'x-operation':'normal','X-Operation':'splash'}),{})
        self.assertEqual(self.run_adapter({'x-operation':'','X-Operation':'splash'}),{'status':404})

    def test_numeric_header_does_not_throw_or_expand_match(self):
        self.assertEqual(self.run_adapter({'x-operation':42,'X-Operation':'splash'}),{})

    def test_malformed_json_passes_through(self):
        self.assertEqual(self.run_adapter({'x-operation':'splash'},argument='not JSON'),{})

    def test_bad_settings_fail_open(self):
        for spec in ({}, {'headerNames':['x-operation'],'keywords':[''],'status':404},
                     {'headerNames':['x-operation'],'keywords':['splash'],'status':200},
                     {'headerNames':['x-operation'],'keywords':['splash'],'status':404,'extra':True}):
            with self.subTest(spec=spec): self.assertEqual(self.run_adapter({'x-operation':'splash'},spec=spec),{})
