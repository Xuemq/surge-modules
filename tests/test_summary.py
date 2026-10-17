import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from surge_merge.summary import main,summarize

class SummaryTests(unittest.TestCase):
    def report(self):
        return {'schema_version':1,'status':'unchanged','sources':[{'id':'fmz200','status':'unchanged','expected_sha256':'a'*64,'sha256':'a'*64}]}

    def test_valid_metadata(self):
        text=summarize(self.report())
        self.assertIn('Status: unchanged',text)
        self.assertIn('read-only',text)

    def test_remote_error_never_echoed(self):
        r=self.report();r['status']='blocked';r['sources'][0]['status']='error';r['sources'][0]['error']='SECRET REMOTE HTML'
        self.assertNotIn('SECRET',summarize(r))

    def test_digest_restricted(self):
        r=self.report();r['sources'][0]['sha256']='[untrusted link](https://evil.test)'
        with self.assertRaises(ValueError):summarize(r)

    def test_identifier_restricted(self):
        r=self.report();r['sources'][0]['id']='foo\n# INJECTION'
        with self.assertRaises(ValueError):summarize(r)

    def test_missing_report_fails(self):
        with tempfile.TemporaryDirectory() as d:
            summary=Path(d)/'summary'
            with patch.dict('os.environ',{'GITHUB_STEP_SUMMARY':str(summary)}):
                self.assertEqual(main([str(Path(d)/'missing')]),2)
            self.assertIn('No valid update report',summary.read_text())

if __name__=='__main__':unittest.main()
