import copy
import re
import unittest
from surge_merge.converter import convert_qx
from surge_merge.core import Invalid,digest,parse_module,params,words,unquote


class NativeHeaderConversionTests(unittest.TestCase):
    def setUp(self):
        self.raw='^https://example.test/gateway url script-response-header https://example.test/old.js'
        self.data=(self.raw+'\n^keep url reject\n').encode()
        self.adapter={'line':1,'line_sha256':digest(self.raw),'source_script_url':'https://example.test/old.js',
                      'source_script_sha256':'1'*64,'adapter_url':'https://example.test/native.js','adapter_sha256':'2'*64,
                      'header_names':['x-operation','X-Operation'],'keywords':['splash'],'status':404,
                      'reason':'Reviewed status-only adapter.','evidence':'Static literal inspection and official Surge response-script documentation.'}
        self.policy={'source_sha256':digest(self.data),'native_header_adapters':[self.adapter],
                     'known_incompatible':[{'url':'https://example.test/old.js','reason':'Original has no Surge effect.'}]}

    def test_exact_adapter_preserves_phase_and_body_mode(self):
        out,r=convert_qx(self.data,self.policy)
        entry=next(e for e in parse_module(out.encode(),'x').entries if e.section=='Script')
        p=params(entry.raw.partition('=')[2])
        self.assertEqual(p['type'],'http-response');self.assertEqual(p['requires-body'],'false')
        self.assertEqual(p['script-path'],'https://example.test/native.js')
        self.assertIn('"status":404',p['argument'])
        self.assertEqual(r['adapted'],[self.adapter]);self.assertEqual(r['converted'],2)

    def test_source_hash_required(self):
        for h in (None,'0'*64):
            with self.subTest(h=h),self.assertRaises(Invalid):convert_qx(self.data,{**self.policy,'source_sha256':h})

    def test_target_drift_fails_closed(self):
        for changed in ({'line':2},{'line':3},{'line_sha256':'0'*64},{'source_script_url':'https://example.test/wrong.js'}):
            with self.subTest(changed=changed),self.assertRaises(Invalid):
                convert_qx(self.data,{**self.policy,'native_header_adapters':[{**self.adapter,**changed}]})

    def test_duplicate_and_unsafe_adapter_rejected(self):
        bad=[{**self.adapter,'status':200},{**self.adapter,'keywords':['']},{**self.adapter,'header_names':['bad\nname']},
             {**self.adapter,'adapter_sha256':'bad'},{**self.adapter,'adapter_url':'file:///tmp/x.js'}]
        for adapter in bad:
            with self.subTest(adapter=adapter),self.assertRaises(Invalid):
                convert_qx(self.data,{**self.policy,'native_header_adapters':[adapter]})
        with self.assertRaises(Invalid):
            convert_qx(self.data,{**self.policy,'native_header_adapters':[self.adapter,self.adapter]})

    def test_unreviewed_second_script_still_blocks(self):
        data=self.data+b'^other url script-response-header https://example.test/other.js\n'
        out,r=convert_qx(data,{**self.policy,'source_sha256':digest(data)})
        self.assertIsNone(out);self.assertEqual(len(r['unsupported']),1)
        self.assertEqual(len(r['adapted']),1)

    def test_adapter_deterministic(self):
        self.assertEqual(convert_qx(self.data,self.policy),convert_qx(self.data,copy.deepcopy(self.policy)))

    def test_targeted_year_replacement_keeps_response_structure_and_literal_pattern(self):
        source=r'^https://shop.example.test/screen url response-body egin_time":"\d{4} response-body egin_time":"2099'
        out,report=convert_qx((source+'\n').encode())
        entry=parse_module(out.encode(),'converted').entries[0]
        tokens=words(entry.raw);pattern,replacement=map(unquote,tokens[2:])
        self.assertEqual(pattern,r'egin_time":"\d{4}')
        cases=[('{"begin_time":"2026-10-17","other":1}','{"begin_time":"2099-10-17","other":1}'),
               ('{"begin_time":"123"}','{"begin_time":"123"}'),
               ('{"end_time":"2026"}','{"end_time":"2026"}'),
               ('{"begin_time":"none"}','{"begin_time":"none"}'),
               # No boundary was present upstream: preserve prefix matching.
               ('{"begin_time":"12345"}','{"begin_time":"20995"}')]
        for before,after in cases:
            with self.subTest(before=before):self.assertEqual(re.sub(pattern,replacement,before),after)
        self.assertEqual(entry.phase,'http-response')
        self.assertEqual(report['converted'],1)

if __name__=='__main__':unittest.main()
