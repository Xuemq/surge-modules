"""Independent regressions for the reviewed NetEase priority restoration."""
from copy import deepcopy
from pathlib import Path
import re
import unittest

from surge_merge.core import Invalid, digest, parse_module
from surge_merge.order import restore_reviewed_order
from tests import test_order as order_fixture

ROOT = Path(__file__).resolve().parents[1]


class ReviewedOrderRegressionTests(unittest.TestCase):
    def test_json_responses_precede_tiny_gif_for_reviewed_witnesses(self):
        for module in ('fmz200', 'merged'):
            parsed = parse_module((ROOT / 'modules' / (module + '.optimized.sgmodule')).read_bytes(), module)
            for host in ('interface.music.163.com', 'interface3.music.163.com'):
                for path in ('ad', 'search/specialkeyword', 'search/defaultkeyword'):
                    url = 'https://' + host + '/eapi/' + path
                    matches = [entry for entry in parsed.entries
                               if entry.section == 'Map Local' and re.search(entry.pattern, url)]
                    self.assertGreaterEqual(len(matches), 2, url)
                    self.assertIn('data-type=text data="{}"', matches[0].raw, url)
                    self.assertIn('header="Content-Type:application/json"', matches[0].raw, url)
                    self.assertTrue(any('data-type=tiny-gif' in entry.raw for entry in matches[1:]), url)

    def test_missing_target_blocks_without_partial_mutation(self):
        fixture = order_fixture.OrderTests(); fixture.setUp()
        lines = [line for line in fixture.lines if line != 'DOMAIN,a,REJECT']
        before = lines[:]
        with self.assertRaises(Invalid):
            restore_reviewed_order(lines, fixture.p, {'changes': []})
        self.assertEqual(lines, before)

    def test_duplicate_anchor_blocks(self):
        fixture = order_fixture.OrderTests(); fixture.setUp()
        lines = fixture.lines[:3] + ['DOMAIN,b,REJECT'] + fixture.lines[3:]
        with self.assertRaises(Invalid):
            restore_reviewed_order(lines, fixture.p, {'changes': []})

    def test_host_negation_cannot_be_changed(self):
        fixture = order_fixture.OrderTests(); fixture.setUp()
        policy = deepcopy(fixture.p)
        policy['hostname_order']['raw'] = 'hostname = %APPEND% -a, b'
        with self.assertRaises(Invalid):
            restore_reviewed_order(fixture.lines, policy, {'changes': []})
