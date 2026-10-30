"""Published files must describe one coherent, reviewed release."""
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import unittest

from surge_merge.core import digest, parse_module


ROOT = Path(__file__).resolve().parents[1]
RETAINED_RULE = 'DOMAIN, ads-img-al.xhscdn.com, REJECT'
SERIALIZATION_RESULTS = {
    'a327b500d8438e39da4b8ab87b8a8bda611fc8aa350e7973bc2436b20a6bfc39',
    'fe51affd2ba33525b59374ff546c61e214b6cc15504266bc500575931006e7d6',
    '2bab23ba30e58af81e9c4bbd977668aa70f4dc336cd2b1f77695187985f4f44e',
    'df890afe5bedc3f10b04abb5cddc581211e6c80b607b5bc533917592160398a9',
    '29ea4a0814ba77fc1a3994c617b78e8a9ade06e8b4d76d0464e36609b3bb3866',
    '859c1d9f9a7a4b9f1b14b5a692b4e88d38db2840e669dd9d0a16e76e08f161a3',
    '46321d628bd1c03a4d46ab7c4f9f9590452ba59a42cf39a65b8c5f4a59b6dd4f',
    '1c07ac186419c5ca3bfca944c1b27ad9e28ea4b994aa2d6e81d5b1c7ed9fce74',
    'ee5fee091f5c035872317aa869aaf90180fdccd2dff92dc70cbc07e2a2f37603',
}


def read_json(path):
    return json.loads((ROOT / path).read_bytes())


class PublishedBaselineTests(unittest.TestCase):
    def test_published_records_match_module_and_policy_bytes(self):
        for prefix, module, policy in (
                ('fmz200', 'modules/fmz200.optimized.sgmodule', 'fmz-policy.json'),
                ('merged', 'modules/merged.optimized.sgmodule', 'merged-policy.json')):
            with self.subTest(module=module):
                record = read_json('reports/' + prefix + '-update.json')
                self.assertEqual(record['module_sha256'], digest((ROOT / module).read_bytes()))
                self.assertEqual(record['policy_sha256'], digest((ROOT / policy).read_bytes()))
                for path, checksum in record.get('support_sha256', {}).items():
                    self.assertEqual(checksum, digest((ROOT / path).read_bytes()), path)

    def test_exact_retained_rule_exists_once_in_both_outputs(self):
        for path in ('modules/fmz200.optimized.sgmodule', 'modules/merged.optimized.sgmodule'):
            parsed = parse_module((ROOT / path).read_bytes(), 'published-test')
            self.assertEqual(sum(e.section == 'Rule' and e.raw == RETAINED_RULE
                                 for e in parsed.entries), 1, path)

    def assert_release_bindings(self, fmz, bundle, fmz_manifest, merged_manifest):
        # The two independently published subscriptions may legitimately use
        # different source locks, dates and relocated anchors between runs.
        for policy in (fmz, bundle['fmz_policy']):
            self.assertEqual(len(policy['scope_exclusions']), 9)
            self.assertEqual(len(policy['retained_entries']), 1)
        self.assertEqual(sum(len(p['excluded_entries']) for p in bundle['scope_policies'].values()), 2)
        self.assertEqual(len(bundle['conversion_policy']['excluded_entries']), 1)
        self.assertEqual(bundle['source_sha256'], {
            s['id']: s['sha256'] for s in merged_manifest['sources']})
        self.assertEqual(bundle['fmz_policy']['source_sha256'], bundle['source_sha256']['fmz200'])
        self.assertEqual(fmz['source_sha256'], fmz_manifest['sources'][0]['sha256'])

    def bindings(self):
        return (read_json('fmz-policy.json'), read_json('merged-policy.json'),
                read_json('sources-fmz.json'), read_json('sources-merged.json'))

    def test_scope_and_source_bindings_remain_coherent(self):
        self.assert_release_bindings(*self.bindings())

    def test_independent_subscription_updates_do_not_block_each_other(self):
        fmz, bundle, manifest, merged_manifest = deepcopy(self.bindings())
        fmz['source_sha256'] = manifest['sources'][0]['sha256'] = 'a' * 64
        fmz['modification_date'] = '2026-11-01'
        for item in fmz['scope_exclusions']:
            item['line'] += 1
        fmz['retained_entries'][0]['after']['line'] += 1
        self.assert_release_bindings(fmz, bundle, manifest, merged_manifest)

    def test_each_subscription_still_rejects_its_own_mismatched_lock(self):
        values = self.bindings()
        values[0]['source_sha256'] = 'a' * 64
        with self.assertRaises(AssertionError):
            self.assert_release_bindings(*values)

    def test_all_nine_serialization_repairs_remain_applied(self):
        report = read_json('reports/merged-build-report.json')
        applied = report['serialization_repairs']['applied']
        self.assertEqual(len(applied), 9)
        self.assertEqual({x['result_entry_id'] for x in applied}, SERIALIZATION_RESULTS)
        parsed = parse_module((ROOT / 'modules/merged.optimized.sgmodule').read_bytes(), 'published-test')
        self.assertLessEqual(SERIALIZATION_RESULTS, {e.id for e in parsed.entries})
        self.assertEqual(report['counts'], dict(Counter(e.section for e in parsed.entries)))


if __name__ == '__main__':
    unittest.main()
