import unittest
from surge_merge.core import Invalid, digest, merge, parse_module, words, split_fields


def module(text, name='base'):
    return parse_module((text + '\n').encode(), name)


def script(name='one', pattern=r'^https://example\.test/a', url='https://example.test/x.js'):
    return f'{name} = type=http-response, pattern={pattern}, script-path={url}, requires-body=true'


class ParserTests(unittest.TestCase):
    def test_minimal(self):
        self.assertEqual(len(module('[Rule]\nDOMAIN,a.test,REJECT').entries), 1)

    def test_html_empty_binary(self):
        for text in (b'', b'<html>Oops</html>', b'\x00', b'\xff'):
            with self.subTest(text=text), self.assertRaises(Invalid):
                parse_module(text, 'bad')

    def test_no_final_newline_accepted_when_syntax_complete(self):
        self.assertEqual(len(parse_module(b'[Rule]\nDOMAIN,a.test,REJECT', 'x').entries), 1)

    def test_truncated_rule(self):
        with self.assertRaises(Invalid):
            module('[Rule]\nDOMAIN,a.test,')

    def test_credentials_even_in_comment(self):
        for text in ('[MITM]\nca-p12 = very-private', '# password = secret\n[Rule]\nDOMAIN,a,REJECT', '# https://x.test/?token=abc\n[Rule]\nDOMAIN,a,REJECT', '# https://user:password@x.test/x\n[Rule]\nDOMAIN,a,REJECT'):
            with self.subTest(text=text), self.assertRaises(Invalid):
                module(text)

    def test_reject_profile_sections(self):
        for text in ('[Proxy]\na=x', '[Proxy Group]\na=x', '[MITM]\nskip-server-cert-verify = true', '[General]\nhttp-api = 0.0.0.0:6166', '[Unknown]\nx=y'):
            with self.subTest(text=text), self.assertRaises(Invalid):
                module(text)

    def test_external_rules_rejected(self):
        with self.assertRaises(Invalid):
            module('[Rule]\nRULE-SET,https://x.test/list,REJECT')

    def test_repeated_sections(self):
        with self.assertRaises(Invalid):
            module('[Rule]\nDOMAIN,a,REJECT\n[Rule]\nDOMAIN,b,REJECT')

    def test_comments_and_bom(self):
        m = parse_module('\ufeff#!name=X\n# comment\n// comment\n[Rule]\nDOMAIN,a,REJECT\n'.encode(), 'x')
        self.assertEqual(len(m.entries), 1)

    def test_nested_logical_rule(self):
        m = module('[Rule]\nAND,((DOMAIN,a.test),(DOMAIN-KEYWORD,ad)),REJECT')
        self.assertEqual(m.entries[0].key, 'AND,((DOMAIN,a.test),(DOMAIN-KEYWORD,ad))')

    def test_script_regex_quantifier_comma(self):
        m = module('[Script]\n' + script(pattern=r'^https://[a-z]{1,3}\.test'))
        self.assertEqual(m.entries[0].pattern, r'^https://[a-z]{1,3}\.test')

    def test_script_name_unicode(self):
        self.assertEqual(module('[Script]\n' + script(name='墨鱼：广告')).entries[0].key, '墨鱼：广告')

    def test_scripts_never_local(self):
        for url in ('/tmp/evil.js', 'file:///tmp/evil.js', 'http://x.test/x.js'):
            with self.subTest(url=url), self.assertRaises(Invalid):
                module('[Script]\n' + script(url=url))

    def test_quoted_mapping_spaces(self):
        m = module('[Map Local]\n^https://a.test/ data-type=text data=" " status-code=200 header="Content-Type:application/json"')
        self.assertEqual(len(m.entries), 1)

    def test_remote_mapping_requires_review(self):
        with self.assertRaises(Invalid):
            module('[Map Local]\n^a data-type=file data="https://a.test/x"')

    def test_body_quotes_backslashes(self):
        line = r'''http-response ^https:\/\/a.test/ 'a\\b' 'c d' '''.strip()
        self.assertEqual(module('[Body Rewrite]\n' + line).entries[0].raw, line)

    def test_unclosed_quote(self):
        with self.assertRaises(Invalid):
            module('[Body Rewrite]\nhttp-response ^a "unfinished b')

    def test_arguments_preserved(self):
        m = module('#!system=ios\n#!arguments=toggle:true\n[Script]\n' + script() + ', argument={{{toggle}}}')
        self.assertEqual(m.metadata['arguments'], 'toggle:true')

    def test_undefined_argument_blocks(self):
        with self.assertRaises(Invalid):
            module('[Script]\n' + script() + ', argument={{{missing}}}')

    def test_mid_file_metadata_blocks(self):
        with self.assertRaises(Invalid):
            module('[Rule]\n#!if x\nDOMAIN,a,REJECT')


class MergeTests(unittest.TestCase):
    def test_exact_rule_duplicate(self):
        a = module('[Rule]\nDOMAIN,a,REJECT\nDOMAIN,b,REJECT')
        b = module('[Rule]\nDOMAIN,a,REJECT\nDOMAIN,c,REJECT', 'extra')
        out, report = merge([a, b])
        self.assertEqual(len(report['duplicates']), 1)
        self.assertLess(out.index('DOMAIN,b'), out.index('DOMAIN,c'))

    def test_no_regex_equivalence_dedup(self):
        a = module('[URL Rewrite]\n^https://a _ reject')
        b = module('[URL Rewrite]\n' + r'^https:\/\/a _ reject', 'extra')
        out, report = merge([a,b])
        self.assertIsNotNone(out)
        self.assertFalse(report['duplicates'])

    def test_same_rule_different_policy_blocks(self):
        out, r = merge([module('[Rule]\nDOMAIN,a,REJECT'), module('[Rule]\nDOMAIN,a,DIRECT', 'extra')])
        self.assertIsNone(out)
        self.assertEqual(r['conflicts'][0]['kind'], 'same-key')

    def test_same_map_different_body_blocks(self):
        out, r = merge([module('[Map Local]\n^a data-type=text data="{}"'), module('[Map Local]\n^a data-type=text data="[]"','extra')])
        self.assertIsNone(out)

    def test_same_script_label_different_pattern(self):
        out, r = merge([module('[Script]\n'+script()), module('[Script]\n'+script(pattern='^other'),'extra')])
        self.assertIsNone(out)

    def test_different_script_label_same_trigger(self):
        out, r = merge([module('[Script]\n'+script()), module('[Script]\n'+script(name='two'),'extra')])
        self.assertIsNone(out)
        self.assertEqual(r['conflicts'][0]['kind'], 'script-trigger')

    def test_exact_script_duplicate(self):
        out, r = merge([module('[Script]\n'+script()), module('[Script]\n'+script(),'extra')])
        self.assertEqual(len(r['duplicates']), 1)

    def test_body_duplicates_preserved(self):
        line = 'http-response ^a a aa'
        out, r = merge([module('[Body Rewrite]\n'+line+'\n'+line)])
        self.assertEqual(out.count(line), 2)
        self.assertFalse(r['duplicates'])

    def test_body_cross_source_duplicate_blocks(self):
        a = '[Body Rewrite]\nhttp-response ^a a aa'
        out, r = merge([module(a),module(a,'extra')])
        self.assertIsNone(out)

    def test_header_add_duplicates_preserved(self):
        line = 'http-response ^a header-add X-Test value'
        out, r = merge([module('[Header Rewrite]\n'+line+'\n'+line)])
        self.assertEqual(out.count(line), 2)

    def test_mitm_exact_only_preserves_modes_order(self):
        out, r = merge([module('[MITM]\nhostname = %APPEND% -*.apple.com, *.example.com, example.com:8443'), module('[MITM]\nhostname = %APPEND% *.example.com, example.com, example.com:0','extra')])
        self.assertIn('hostname = %APPEND% -*.apple.com, *.example.com, example.com:8443, example.com, example.com:0',out)

    def test_mitm_modes_block(self):
        out, r = merge([module('[MITM]\nhostname = %APPEND% a'), module('[MITM]\nhostname = a,b','extra')])
        self.assertIsNone(out)

    def test_mitm_opposing_exact_host_blocks(self):
        out,r = merge([module('[MITM]\nhostname = %APPEND% a'),module('[MITM]\nhostname = %APPEND% -a','extra')])
        self.assertIsNone(out)

    def test_cross_section_request_blocks(self):
        out, r = merge([module('[URL Rewrite]\n^a _ reject\n[Map Local]\n^a data-type=text data="{}"')])
        self.assertIsNone(out)
        self.assertEqual(r['conflicts'][0]['kind'],'cross-section-request')

    def test_override_exact_and_stale(self):
        mods = [module('[Rule]\nDOMAIN,a,REJECT'),module('[Rule]\nDOMAIN,a,DIRECT','extra')]
        _,r = merge(mods); c = r['conflicts'][0]
        overrides = {'schema_version':1,'decisions':[{'conflict_id':c['id'],'entry_ids':[c['entries'][0]['id']],'action':'keep','reason':'Reviewed ad blocking requirement'}]}
        out,r = merge(mods,overrides)
        self.assertIn('DOMAIN,a,REJECT',out);self.assertNotIn('DOMAIN,a,DIRECT',out)
        with self.assertRaises(Invalid):
            merge([mods[0]],overrides)

    def test_conflicting_metadata_blocks(self):
        out,r=merge([module('#!system=ios\n[Rule]\nDOMAIN,a,REJECT'),module('#!system=mac\n[Rule]\nDOMAIN,b,REJECT','extra')])
        self.assertIsNone(out)

    def test_determinism(self):
        mods=[module('[Rule]\nDOMAIN,z,REJECT\nDOMAIN,a,REJECT')]
        self.assertEqual(merge(mods),merge(mods))

if __name__ == '__main__':
    unittest.main()
