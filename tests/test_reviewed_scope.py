"""Exact approved scope identities must survive future source relocation."""
import json
from pathlib import Path
import unittest
from surge_merge.core import digest, parse_module
ROOT = Path(__file__).resolve().parents[1]
class ReviewedScopeTests(unittest.TestCase):
    def fixture(self):
        return json.loads((ROOT / 'tests/fixtures/reviewed-scope-2026-11-01.json').read_bytes())
    def reviewed(self):
        return {(x['section'],x['line_sha256']) for x in self.fixture()['removed_output_entries']}
    def test_exact_selection_remains_in_both_policies(self):
        fixture=self.fixture()
        fmz=json.loads((ROOT/'fmz-policy.json').read_bytes())
        merged=json.loads((ROOT/'merged-policy.json').read_bytes())
        identities=lambda entries: sorted([x['section'],x['line_sha256']] for x in entries)
        for policy in (fmz,merged['fmz_policy']):
            self.assertEqual(identities(policy['scope_exclusions']),fixture['fmz_scope_identities'])
        for source,policy in merged['scope_policies'].items():
            self.assertEqual(identities(policy['excluded_entries']),fixture['supplement_scope_identities'][source])
    def test_no_selected_rule_returns_in_either_subscription(self):
        self.assertEqual(len(self.reviewed()),872)
        for path in ('modules/fmz200.optimized.sgmodule','modules/merged.optimized.sgmodule'):
            entries=parse_module((ROOT/path).read_bytes(),'scope-regression').entries
            active={(e.section,digest(e.raw)) for e in entries}
            self.assertFalse(active & self.reviewed(),path)
    def test_selection_never_targets_general_or_mitm(self):
        self.assertFalse({'General','MITM'} & {s for s,_ in self.reviewed()})
if __name__=='__main__':unittest.main()
