import unittest
from surge_merge.scope import filter_native_scope
from surge_merge.core import Invalid,digest


class SupplementalScopeTests(unittest.TestCase):
    def policy(self,data,raw,line=2,section='URL Rewrite'):
        return {'source_id':'extra','source_sha256':digest(data),'excluded_entries':[
            {'line':line,'section':section,'line_sha256':digest(raw),'classification':'manual-scope-exclusion',
             'reason':'Exact reviewed supplemental rule would reintroduce an excluded application scope.'}]}

    def test_exact_supplement_exclusion_prevents_scope_reintroduction(self):
        raw='"^https://scope.example/app3/start" - reject'
        data=('[URL Rewrite]\n'+raw+'\n^https://keep.example _ reject\n[MITM]\nhostname = %APPEND% scope.example, keep.example\n').encode()
        out,r=filter_native_scope(data,'extra',self.policy(data,raw))
        self.assertNotIn(raw.encode(),out);self.assertIn(b'^https://keep.example _ reject',out)
        self.assertIn(b'hostname = %APPEND% scope.example, keep.example',out)
        self.assertEqual(len(r['removed']),1)

    def test_reviewed_broader_same_app_matcher_can_be_excluded_without_regex_rewriting(self):
        raw=r'^https://scope.example/app\d/start data-type=text data=" " status-code=200'
        data=('[Map Local]\n'+raw+'\n^https://keep.example data-type=text data="{}"\n').encode()
        out,r=filter_native_scope(data,'extra',self.policy(data,raw,section='Map Local'))
        self.assertNotIn(raw.encode(),out);self.assertIn(b'^https://keep.example',out)

    def test_source_hash_or_id_drift_rejected(self):
        raw='^a _ reject';data=('[URL Rewrite]\n'+raw+'\n^b _ reject\n').encode();p=self.policy(data,raw)
        with self.assertRaises(Invalid):filter_native_scope(data+b'\n','extra',p)
        with self.assertRaises(Invalid):filter_native_scope(data,'different',p)

    def test_line_hash_section_and_duplicates_rejected(self):
        raw='^a _ reject';data=('[URL Rewrite]\n'+raw+'\n^b _ reject\n').encode();p=self.policy(data,raw)
        for change in ({'line':3},{'line_sha256':'0'*64},{'section':'Map Local'}):
            with self.subTest(change=change),self.assertRaises(Invalid):
                filter_native_scope(data,'extra',{**p,'excluded_entries':[{**p['excluded_entries'][0],**change}]})
        with self.assertRaises(Invalid):filter_native_scope(data,'extra',{**p,'excluded_entries':p['excluded_entries']*2})

    def test_mitm_cannot_be_excluded(self):
        raw='hostname = %APPEND% example.test';data=('[MITM]\n'+raw+'\n').encode()
        with self.assertRaises(Invalid):filter_native_scope(data,'extra',self.policy(data,raw,section='MITM'))

    def test_other_bytes_and_crlf_preserved(self):
        raw='^a _ reject';data=('#!name=X\r\n[URL Rewrite]\r\n'+raw+'\r\n  ^b _ reject  \r\n# note\r\n').encode()
        out,r=filter_native_scope(data,'extra',self.policy(data,raw,line=3))
        self.assertTrue(out.startswith(b'#!name=X\r\n[URL Rewrite]\r\n'))
        self.assertTrue(out.endswith(b'  ^b _ reject  \r\n# note\r\n'))

if __name__=='__main__':unittest.main()
