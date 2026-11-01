"""Independent fail-closed checks for output-stage reviewed decisions."""
import unittest
from surge_merge.core import Invalid, parse_module
from surge_merge.reviewed import apply_reviewed

class IndependentReviewedGuards(unittest.TestCase):
    def fixture(self):
        text = '[Rule]\nDOMAIN-SUFFIX,example.com,REJECT\nDOMAIN,ad.example.com,REJECT\n'
        entries = parse_module(text.encode(), 'test').entries
        selection = {'entry_id': entries[1].id, 'replacement': None,
                     'reason': 'Covered by prior suffix.', 'evidence': 'Synthetic exact proof.',
                     'kind': 'covered-domain', 'witnesses': [entries[0].id]}
        return text, entries, {'schema_version': 1, 'entries': [selection], 'mitm': None}

    def test_coverage_witness_cannot_change_action_in_same_transaction(self):
        text, entries, policy = self.fixture()
        policy['entries'].append({'entry_id': entries[0].id,
            'replacement': 'DOMAIN-SUFFIX,example.com,DIRECT',
            'reason': 'Synthetic independent replacement.', 'evidence': 'Guard fixture.',
            'kind': 'exact-fix', 'witnesses': []})
        with self.assertRaises(Invalid):
            apply_reviewed(text, policy)

    def test_coverage_witness_cannot_be_deleted_in_same_transaction(self):
        text, entries, policy = self.fixture()
        policy['entries'].append({'entry_id': entries[0].id, 'replacement': None,
            'reason': 'Synthetic deletion.', 'evidence': 'Guard fixture.',
            'kind': 'exact-fix', 'witnesses': []})
        with self.assertRaises(Invalid):
            apply_reviewed(text, policy)

    def test_domain_suffix_boundary_is_required(self):
        text, entries, policy = self.fixture()
        text = text.replace('ad.example.com', 'notexample.com')
        policy['entries'][0]['entry_id'] = parse_module(text.encode(), 'test').entries[1].id
        with self.assertRaises(Invalid):
            apply_reviewed(text, policy)
