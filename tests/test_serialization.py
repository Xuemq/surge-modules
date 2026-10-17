"""Synthetic regression fixtures only; no private effective profile is included."""
import copy
import itertools
import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest
from urllib.parse import quote, unquote as uri_unquote
from surge_merge.core import Invalid, digest, params, parse_module, words, unquote
from surge_merge.serialization import ADAPTER_URL, repair_serialization


def fixture(raw, kind, section='Script'):
    arguments = re.findall(r'\{\{\{([^{}]+)\}\}\}', raw)
    prefix = '#!arguments=' + ','.join(key + ':0' for key in dict.fromkeys(arguments)) + '\n' if arguments else ''
    text = prefix + '[%s]\n%s\n' % (section, raw)
    entry = parse_module(text.encode(), 'fixture').entries[0]
    return text, {'schema_version': 1, 'adapter_url': ADAPTER_URL, 'adapter_sha256': '1' * 64,
                  'entries': [{'entry_id': entry.id, 'kind': kind,
                               'reason': 'Synthetic exact regression.', 'evidence': 'Public format documentation.'}]}


def first_entry(text):
    return parse_module(text.encode(), 'test').entries[0].raw


def export_default(value):
    # Real legacy export strips default quotation before replacing placeholders.
    return unquote(value)


class SerializationTests(unittest.TestCase):
    def test_without_policy_preserves_every_byte(self):
        raw='[Rule]\nDOMAIN,example.test,REJECT\n'
        self.assertEqual(repair_serialization(raw)[0], raw)

    def test_exact_anchor_and_policy_are_not_mutated(self):
        raw='x = type=http-response, pattern=^https://example.test/, script-path=https://example.test/a.js, argument=[{{{per_filter_video_thread}}}]'
        text, policy = fixture(raw, 'key-value-template'); before = copy.deepcopy(policy)
        fixed, report = repair_serialization(text, policy)
        self.assertEqual(policy, before); self.assertEqual(len(report['applied']), 1)
        self.assertIn('argument=per_filter_video_thread={{{per_filter_video_thread}}}', fixed)
        self.assertEqual(repair_serialization(text, policy), (fixed, report))

    def test_missing_changed_duplicated_target_fails_closed(self):
        raw='x = type=http-response, pattern=^https://example.test/, script-path=https://example.test/a.js, argument=[{{{per_filter_video_thread}}}]'
        text, policy = fixture(raw, 'key-value-template')
        for changed in (text.replace('example.test/', 'other.test/'), '[Script]\n', text + raw + '\n'):
            with self.subTest(changed=changed), self.assertRaises(Invalid): repair_serialization(changed, policy)

    def test_duplicate_selection_unknown_kind_and_other_adapter_rejected(self):
        raw='x = type=http-response, pattern=^https://example.test/, script-path=https://example.test/a.js, argument=[{{{per_filter_video_thread}}}]'
        text, policy = fixture(raw, 'key-value-template')
        variants=[]
        p=copy.deepcopy(policy);p['entries']*=2;variants.append(p)
        p=copy.deepcopy(policy);p['entries'][0]['kind']='arbitrary-replacement';variants.append(p)
        p=copy.deepcopy(policy);p['adapter_url']='https://example.test/new.js';variants.append(p)
        for p in variants:
            with self.subTest(policy=p), self.assertRaises(Invalid):repair_serialization(text,p)

    def test_host_range_equivalence_on_protocol_ports_labels_paths_and_suffixes(self):
        cases = 0
        for protocol, tail in [('https?', r'\/api\/v\d\/movie\/index_recommend'), ('http', r'\/amdc\/mobileDispatch')]:
            old = '^' + protocol + r':\/\/[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+){1,4}(:\d+)?' + tail
            raw="x = type=http-response, pattern='"+old+"', script-path=https://example.test/a.js, requires-body=true"
            text,policy=fixture(raw,'comma-free-host-range');fixed,_=repair_serialization(text,policy)
            new=params(first_entry(fixed).partition('=')[2])['pattern']
            self.assertNotIn(',',new);self.assertNotIn("pattern='",fixed)
            path='/api/v1/movie/index_recommend' if 'movie' in tail else '/amdc/mobileDispatch'
            for scheme,count,label,port,suffix in itertools.product(('http','https','ftp'),range(1,8),('a','X_y-2'),('',':443',':x'),('', '?q=1','/tail')):
                url=scheme+'://'+'.'.join([label]*count)+port+path+suffix
                self.assertEqual(bool(re.search(old,url)),bool(re.search(new,url)),url);cases+=1
            # A comma-delimited profile reader sees an incomplete old regex.
            truncated=old.split(',',1)[0]
            self.assertNotEqual(truncated,old)
        self.assertEqual(cases,756)

    def test_uri_argument_has_no_profile_delimiters_and_exact_decoded_bytes(self):
        spec={'headerNames':['x-operation','X-Operation'],'keywords':['splash','ad.example'],'status':404}
        arg=json.dumps(spec,separators=(',',':'))
        raw="x = type=http-response, pattern='^https://example.test/', script-path="+ADAPTER_URL.replace('-v2.js','.js')+", requires-body=false, argument='"+arg+"'"
        text,policy=fixture(raw,'uri-header-argument');fixed,_=repair_serialization(text,policy)
        p=params(first_entry(fixed).partition('=')[2]);self.assertEqual(p['script-path'],ADAPTER_URL)
        self.assertTrue(p['argument'].startswith('uri:'));self.assertEqual(uri_unquote(p['argument'][4:]),arg)
        self.assertFalse(any(c in p['argument'] for c in ',\"\' \t\n'))
        # Original single quotes did not protect JSON commas in effective exports.
        truncated=("'"+arg+"'").split(',',1)[0]
        with self.assertRaises(ValueError):json.loads(truncated)

    def test_json_template_quotes_survive_default_quote_stripping(self):
        raw='x = type=http-response, pattern=^https://example.test/, script-path=https://example.test/a.js, argument="{"displayUpList":{{{displayUpList}}},"purifyComment":true,"logLevel":{{{logLevel}}}}"'
        text,policy=fixture(raw,'json-string-templates');fixed,_=repair_serialization(text,policy)
        oldarg=params(raw.partition('=')[2])['argument'];newarg=params(first_entry(fixed).partition('=')[2])['argument']
        for display,level in itertools.product(('"show"','"hide"'),('"error"','"debug"')):
            expand=lambda s:s.replace('{{{displayUpList}}}',export_default(display)).replace('{{{logLevel}}}',export_default(level))
            with self.assertRaises(ValueError):json.loads(expand(oldarg))
            self.assertEqual(json.loads(expand(newarg)),{'displayUpList':export_default(display),'purifyComment':True,'logLevel':export_default(level)})

    def test_tieba_key_value_expands_default_and_nondefault(self):
        raw='x = type=http-response, pattern=^https://example.test/, script-path=https://example.test/a.js, argument=[{{{per_filter_video_thread}}}]'
        text,policy=fixture(raw,'key-value-template');fixed,_=repair_serialization(text,policy)
        value=params(first_entry(fixed).partition('=')[2])['argument']
        for default in ('"0"','"1"','"2"'):
            expanded=value.replace('{{{per_filter_video_thread}}}',export_default(default))
            self.assertEqual(dict(x.split('=') for x in expanded.split('&')),{'per_filter_video_thread':export_default(default)})

    def test_body_token_quotes_preserve_exact_operations_and_other_lines(self):
        raw=r'http-response ^https://example.test/cms offset_ms":\d+ offset_ms":99999999999999'
        text,policy=fixture(raw,'body-token-quotes','Body Rewrite');text += '[Rule]\nDOMAIN,unchanged.test,REJECT\n'
        fixed,report=repair_serialization(text,policy)
        self.assertEqual(list(map(unquote,words(raw))),list(map(unquote,words(fixed.splitlines()[1]))))
        self.assertEqual(fixed.splitlines()[2:],text.splitlines()[2:]);self.assertEqual(len(report['applied']),1)
        self.assertIn("'offset_ms",fixed)


@unittest.skipUnless(shutil.which('node'), 'Node unavailable; original-adapter VM tests not run')
class HeaderAdapterV2Tests(unittest.TestCase):
    def run_adapter(self,argument,headers):
        js="""const fs=require('fs'),vm=require('vm');const x=JSON.parse(fs.readFileSync(0,'utf8'));const results=[];
        const ctx={$argument:x.argument,$request:{headers:x.headers},$response:{status:200,body:'unchanged'},$done:r=>results.push(r)};
        const before=JSON.stringify(ctx.$request);vm.runInNewContext(fs.readFileSync('scripts/header-status-v2.js','utf8'),ctx,{timeout:100});
        process.stdout.write(JSON.stringify({results,before,after:JSON.stringify(ctx.$request),response:ctx.$response}));"""
        r=subprocess.run(['node','-e',js],input=json.dumps({'argument':argument,'headers':headers}),text=True,capture_output=True,check=True,cwd=Path(__file__).resolve().parents[1])
        out=json.loads(r.stdout);self.assertEqual(out['before'],out['after']);self.assertEqual(out['response'],{'status':200,'body':'unchanged'});self.assertEqual(len(out['results']),1)
        return out['results'][0]

    def test_uri_and_legacy_json_have_identical_status_only_behavior(self):
        spec=json.dumps({'headerNames':['x-operation','X-Operation'],'keywords':['splash','ad.example'],'status':404})
        for headers,expected in [({'x-operation':'splash'},{'status':404}),({'X-Operation':'ad.example'},{'status':404}),({'x-operation':'login'},{}),({'x-operation':'SPLASH'},{}),({'x-operation':'normal','X-Operation':'splash'},{}),({}, {})]:
            for argument in (spec,'uri:'+quote(spec,safe='')):
                with self.subTest(headers=headers,uri=argument.startswith('uri:')):self.assertEqual(self.run_adapter(argument,headers),expected)

    def test_bad_uri_json_and_policy_leave_response_untouched(self):
        for argument in ('uri:%ZZ','uri:%7B','uri:'+quote('{"status":200}',safe=''),'not JSON',"'{\"headerNames\":[\"x-operation\""):
            with self.subTest(argument=argument):self.assertEqual(self.run_adapter(argument,{'x-operation':'splash'}),{})


if __name__ == '__main__': unittest.main()
