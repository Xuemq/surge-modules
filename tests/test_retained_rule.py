"""A narrowly reviewed historical DOMAIN REJECT survives source deduplication."""
from copy import deepcopy
import unittest

from surge_merge.auto_update import Blocked, migrate_policy, retained_conflict_signatures, validate_delta
from surge_merge.core import Invalid, digest, parse_module
from surge_merge.single import (optimize_single, RETAINED_AD_RULE, RETAINED_AD_RULE_SHA256,
                                RETAINED_AD_ANCHOR, RETAINED_AD_ANCHOR_SHA256, RETAINED_AD_EVIDENCE)


SOURCE = ('#!name=Original\n#!author=Original author\n[Rule]\n'
          'DOMAIN,before.example,REJECT\n' + RETAINED_AD_ANCHOR + '\n'
          'DOMAIN,after.example,REJECT\n[MITM]\nhostname = %APPEND% keep.example\n').encode()


def selection():
    return {'section': 'Rule', 'raw': RETAINED_AD_RULE, 'line_sha256': RETAINED_AD_RULE_SHA256,
            'evidence': deepcopy(RETAINED_AD_EVIDENCE),
            'after': {'section': 'Rule', 'line': 5, 'line_sha256': RETAINED_AD_ANCHOR_SHA256},
            'reason': 'Preserve reviewed baseline ad-domain rejection; upstream removal was not confirmed obsolete.'}


def policy(data=SOURCE):
    return {'schema_version': 1, 'source_id': 'fmz200', 'source_sha256': digest(data),
            'modification_date': '2026-10-30', 'argument_defaults': {}, 'script_argument_repairs': {},
            'confirmed_invalid_entries': [], 'scope_exclusions': [], 'retained_entries': [selection()]}


class RetainedRuleTests(unittest.TestCase):
    def test_exact_placement_only_one_added_line_and_report_origin(self):
        chosen = policy()
        text, report = optimize_single(SOURCE, 'fmz200', chosen)
        baseline = deepcopy(chosen); baseline.pop('retained_entries')
        before, _ = optimize_single(SOURCE, 'fmz200', baseline)
        self.assertEqual(text, before.replace(RETAINED_AD_ANCHOR + '\n',
                                             RETAINED_AD_ANCHOR + '\n' + RETAINED_AD_RULE + '\n'))
        self.assertEqual(text.count(RETAINED_AD_RULE), 1)
        entries = parse_module(text.encode(), 'result').entries
        self.assertEqual([e.raw for e in entries if e.section == 'Rule'],
                         ['DOMAIN,before.example,REJECT', RETAINED_AD_ANCHOR,
                          RETAINED_AD_RULE, 'DOMAIN,after.example,REJECT'])
        retained = report['retained_entries'][0]
        self.assertIsNone(retained['source_line'])
        self.assertEqual(retained['after_source_line'], 5)
        self.assertNotIn('line', retained)
        self.assertEqual(retained['evidence'], RETAINED_AD_EVIDENCE)
        self.assertEqual(report['changes_by_kind']['retained-baseline-rule'], 1)
        self.assertEqual(retained_conflict_signatures(SOURCE, report), set())
        self.assertEqual(chosen, policy())

    def test_replay_is_idempotent_and_no_policy_keeps_existing_behavior(self):
        chosen = policy()
        first = optimize_single(SOURCE, 'fmz200', chosen)
        self.assertEqual(first, optimize_single(SOURCE, 'fmz200', chosen))
        self.assertEqual(migrate_policy(SOURCE, SOURCE, chosen, '2026-10-31'), chosen)
        absent = policy(); absent.pop('retained_entries')
        empty = deepcopy(absent); empty['retained_entries'] = []
        self.assertEqual(optimize_single(SOURCE, 'fmz200', absent), optimize_single(SOURCE, 'fmz200', empty))

    def test_changed_raw_hash_or_historical_evidence_is_rejected(self):
        for path, value in [
            (('raw',), RETAINED_AD_RULE.replace('REJECT', 'DIRECT')),
            (('raw',), RETAINED_AD_RULE + '\nDOMAIN,other.example,REJECT'),
            (('raw',), 'DOMAIN, other.example, REJECT'),
            (('line_sha256',), '0' * 64),
            (('evidence', 'source_sha256'), '0' * 64),
            (('evidence', 'line'), 2449),
            (('evidence', 'line'), 2448.0),
            (('evidence', 'extra'), 'unreviewed'),
        ]:
            with self.subTest(path=path, value=value):
                chosen = policy(); obj = chosen['retained_entries'][0]
                for key in path[:-1]: obj = obj[key]
                obj[path[-1]] = value
                if path == ('raw',):
                    chosen['retained_entries'][0]['line_sha256'] = digest(value)
                with self.assertRaises(Invalid): optimize_single(SOURCE, 'fmz200', chosen)

    def test_unsafe_schema_sections_and_duplicate_selections_are_rejected(self):
        for path, value in [
            (('section',), 'MITM'), (('section',), 'Script'), (('section',), 'General'),
            (('after', 'section'), 'MITM'), (('after', 'line'), True),
            (('after', 'line'), 5.0), (('after', 'line'), '5'), (('after', 'line'), 0),
            (('after', 'line'), 6), (('after', 'line_sha256'), '0' * 64),
            (('after', 'extra'), 'unreviewed'), (('reason',), ''), (('reason',), 'bad\nreason'),
            (('extra',), 'unreviewed'),
        ]:
            with self.subTest(path=path, value=value):
                chosen = policy(); obj = chosen['retained_entries'][0]
                for key in path[:-1]: obj = obj[key]
                obj[path[-1]] = value
                with self.assertRaises(Invalid): optimize_single(SOURCE, 'fmz200', chosen)
        for selections in (None, {}, 'invalid', [selection(), selection()], [{}]):
            with self.subTest(selections=selections):
                chosen = policy(); chosen['retained_entries'] = selections
                with self.assertRaises(Invalid): optimize_single(SOURCE, 'fmz200', chosen)
        for key, value in (('source_id', 'other'), ('source_sha256', '0' * 64)):
            chosen = policy(); chosen[key] = value
            with self.assertRaises(Invalid): optimize_single(SOURCE, 'fmz200', chosen)

    def test_missing_changed_and_ambiguous_anchors_are_rejected(self):
        anchor = RETAINED_AD_ANCHOR.encode()
        for replacement in (b'', b'# ' + anchor, anchor.replace(b',', b', '),
                            anchor + b'\n' + anchor,
                            anchor + b'\nDOMAIN, ads-img-qc.xhscdn.com, DIRECT',
                            anchor.replace(b'REJECT', b'DIRECT')):
            with self.subTest(replacement=replacement):
                changed = SOURCE.replace(anchor, replacement)
                with self.assertRaises(Invalid): optimize_single(changed, 'fmz200', policy(changed))

    def test_any_canonical_upstream_reintroduction_is_rejected(self):
        for raw in (RETAINED_AD_RULE, 'DOMAIN,ads-img-al.xhscdn.com,REJECT',
                    'DOMAIN,ads-img-al.xhscdn.com,DIRECT', 'DOMAIN,ADS-IMG-AL.XHSCDN.COM,REJECT',
                    'DOMAIN,ads-img-al.xhscdn.com.,REJECT'):
            with self.subTest(raw=raw):
                changed = SOURCE.replace(b'[MITM]', raw.encode() + b'\n[MITM]')
                with self.assertRaisesRegex(Invalid, 'reintroduced'):
                    optimize_single(changed, 'fmz200', policy(changed))

    def test_anchor_cannot_be_excluded_or_removed(self):
        for key, decision in (
            ('scope_exclusions', {'line': 5, 'section': 'Rule', 'line_sha256': RETAINED_AD_ANCHOR_SHA256,
                                  'classification': 'manual-scope-exclusion', 'reason': 'Synthetic exclusion.'}),
            ('confirmed_invalid_entries', {'line_sha256': RETAINED_AD_ANCHOR_SHA256,
                                            'classification': 'upstream-retired', 'reason': 'Synthetic removal.',
                                            'evidence': 'https://example.test/review'}),
        ):
            with self.subTest(policy=key):
                chosen = policy(); chosen[key] = [decision]
                with self.assertRaisesRegex(Invalid, 'anchor was removed'):
                    optimize_single(SOURCE, 'fmz200', chosen)

    def test_future_migration_only_moves_exact_anchor(self):
        chosen = policy(); previous = deepcopy(chosen)
        changed = b'# Additional upstream comment\n' + SOURCE
        migrated = migrate_policy(SOURCE, changed, chosen, '2026-10-31')
        expected = deepcopy(chosen)
        expected['retained_entries'][0]['after']['line'] = 6
        expected['source_sha256'] = digest(changed); expected['modification_date'] = '2026-10-31'
        self.assertEqual(migrated, expected)
        self.assertEqual(chosen, previous)
        old_text, _ = optimize_single(SOURCE, 'fmz200', chosen)
        new_text, _ = optimize_single(changed, 'fmz200', migrated)
        delta = validate_delta(SOURCE, changed, old_text, new_text)
        self.assertEqual(delta['added_active_entries'], 0)
        self.assertEqual(delta['removed_active_entries'], 0)

    def test_future_anchor_drift_duplicate_or_reintroduction_blocks(self):
        anchor = RETAINED_AD_ANCHOR.encode()
        variants = [SOURCE.replace(anchor, b''), SOURCE.replace(anchor, anchor + b'\n' + anchor),
                    SOURCE.replace(anchor, anchor.replace(b',', b', ')),
                    SOURCE.replace(b'[MITM]', RETAINED_AD_RULE.encode() + b'\n[MITM]'),
                    SOURCE.replace(anchor, anchor + b'\nDOMAIN, ads-img-qc.xhscdn.com, DIRECT')]
        for changed in variants:
            with self.subTest(changed=changed):
                with self.assertRaises(Blocked): migrate_policy(SOURCE, changed, policy(), '2026-10-31')

    def test_retention_does_not_relax_routing_or_mitm_delta_gates(self):
        old_text, _ = optimize_single(SOURCE, 'fmz200', policy())
        for changed, reason in (
            (SOURCE.replace(b'[MITM]', b'DOMAIN,new.example,REJECT\n[MITM]'),
             'routing_definition_changed_requires_review'),
            (SOURCE.replace(b'keep.example', b'new.example'), 'mitm_or_general_changed'),
        ):
            migrated = migrate_policy(SOURCE, changed, policy(), '2026-10-31')
            new_text, _ = optimize_single(changed, 'fmz200', migrated)
            with self.assertRaisesRegex(Blocked, reason): validate_delta(SOURCE, changed, old_text, new_text)


if __name__ == '__main__':
    unittest.main()
