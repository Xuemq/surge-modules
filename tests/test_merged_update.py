"""Offline synthetic tests of three-source migration and the write boundary."""
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from surge_merge import merged_update as update
from surge_merge.combined import build_combined, prepare_modules
from surge_merge.converter import convert_qx
from surge_merge.core import Invalid, digest, parse_module
from surge_merge.pipeline import json_write

BASE_SHA, OLD_SHA, NEW_SHA = '1'*40, '2'*40, '3'*40


def fixture():
    sources = {
        'fmz200': ('#!name=Original\n#!author=Original author\n[Rule]\n' + ''.join(f'DOMAIN,excluded{i}.test,REJECT\n' for i in range(9))
            + 'DOMAIN,keep.test,REJECT\n[URL Rewrite]\n^https://fmz.example.test/ _ reject\n[Map Local]\n^https://base.example.test/path data-type=text data="{}"\n[MITM]\nhostname = %APPEND% base.example.test\n').encode(),
        'blackmatrix7': b'#!author=Second author\n[URL Rewrite]\n^https://excluded.test/ _ reject\n^https://base.example.test/ _ reject\n^https://second.example.test/ _ reject\n',
        'moyu': (''.join('// Original notice '+str(i)+'\n' for i in range(20))
            + '^https://tf.test/ url request-body a request-body b\n^https://excluded-moyu.test/ url reject-dict\n^https://third.example.test/ url reject-200\n').encode(),
    }
    fmz = {'schema_version': 1, 'source_id': 'fmz200', 'source_sha256': digest(sources['fmz200']), 'modification_date': '2026-10-17',
        'argument_defaults': {}, 'script_argument_repairs': {}, 'confirmed_invalid_entries': [],
        'module_metadata': {'name': 'Reviewed base', 'desc': 'Static fixture.'}, 'scope_exclusions': []}
    for i in range(9):
        fmz['scope_exclusions'].append({'line': 4+i, 'section': 'Rule', 'line_sha256': digest(f'DOMAIN,excluded{i}.test,REJECT'),
            'classification': 'manual-scope-exclusion', 'reason': 'Exact reviewed scope.'})
    conversion = {'source_sha256': digest(sources['moyu']), 'excluded_entries': [{'line': 21,
        'line_sha256': digest('^https://tf.test/ url request-body a request-body b'), 'directive': 'request-body',
        'classification': 'manual-scope-exclusion', 'reason': 'Outside reviewed scope.'}]}
    native, _ = convert_qx(sources['moyu'], conversion)
    scope = {}
    for s, data, match in [('blackmatrix7', sources['blackmatrix7'], 'excluded.test'), ('moyu-native', native.encode(), 'excluded-moyu.test')]:
        target = next(e for e in parse_module(data, s).entries if match in e.raw)
        scope[s] = {'source_id': s, 'source_sha256': digest(data), 'excluded_entries': [{'line': target.line, 'section': target.section,
            'line_sha256': digest(target.raw), 'classification': 'manual-scope-exclusion', 'reason': 'Exact supplemental scope.'}]}
    bundle = {'schema_version': 1, 'source_sha256': {s:digest(d) for s,d in sources.items()}, 'fmz_policy': fmz,
        'conversion_policy': conversion, 'scope_policies': scope,
        'merge_policy': {'schema_version': 2, 'base_source': 'fmz200-optimized', 'source_sha256': {}, 'decisions': [], 'excluded_entries': []},
        'overlap_review': {'witnesses': [], 'exceptions': []},
        'module_metadata': {'name':'去广告合并优化 · 三源', 'desc':'Static fixture; runtime unverified.', 'author':'Original authors; assembly fixture',
            'homepage':'https://github.com/Xuemq/surge-modules', 'raw-url':'https://raw.githubusercontent.com/Xuemq/surge-modules/main/'+update.MODULE_PATH,
            'category':'test', 'modification_date':'2026-10-17'}}
    modules, _ = prepare_modules(sources, bundle)
    bundle['merge_policy']['source_sha256'] = {m.source:m.sha256 for m in modules}
    basis = next(e for e in modules[0].entries if e.section == 'Map Local')
    target = next(e for e in modules[1].entries if 'base.example.test' in e.raw)
    bundle['merge_policy']['excluded_entries'] = [{'source':target.source, 'line':target.line, 'entry_id':target.id,
        'base_entry_ids':[basis.id], 'reason':'Reviewed overlap.', 'evidence':'https://base.example.test/path'}]
    bundle['overlap_review']['witnesses'] = [{'base_id':basis.id, 'supplement_id':target.id, 'witness':'https://base.example.test/path'}]
    return sources, bundle


class MergedUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)/'repo'; self.root.mkdir()
        self.package = Path(self.tmp.name)/'package'
        self.sources, self.bundle = fixture()
        records=[]
        for s in update.SOURCE_IDS:
            data=self.sources[s]
            record={'id':s,'format':'qx' if s=='moyu' else 'surge','sha256':digest(data),'bytes':len(data)}
            if s == 'moyu': record.update(url=update.MOYU_URL,snapshot_path='upstream/moyu.source')
            else:
                repo,branch,tail=update.UPSTREAMS[s]
                record.update(url='https://raw.githubusercontent.com/'+repo+'/'+branch+'/'+tail,immutable_url=update.upstream_url(s,OLD_SHA))
            records.append(record)
        self.notices={p:(update.first20lines(self.sources['moyu']) if s=='moyu' else ('Reviewed notice '+p+'\n').encode()) for p,(s,_,_) in update.NOTICE_SPECS.items()}
        guards=[]
        for p,(s,tail,extraction) in update.NOTICE_SPECS.items():
            data=self.notices[p]
            guards.append({'path':p,'sha256':digest(data),'bytes':len(data),'url':update.MOYU_URL if s=='moyu' else update.upstream_url(s,OLD_SHA,tail),'extraction':extraction})
            self.install(p,data)
        self.manifest={'schema_version':1,'base':'fmz200','sources':records,'policy':'merged-policy.json','redistribution':{'combined_license':'No blanket license asserted.'},'notice_guards':guards}
        json_write(self.root/'sources-merged.json',self.manifest);json_write(self.root/'merged-policy.json',self.bundle)
        self.install('upstream/moyu.source',self.sources['moyu'])
        self.install('docs/merged-notice.md',b'Observed notices do not grant additional rights.\n')
        self.install('scripts/header-status.js',b'// Synthetic adapter fixture\n')
        self.install(update.SERIALIZATION_ADAPTER_PATH,b'// Synthetic v2 adapter fixture\n')
        self.install(update.MODULE_PATH,build_combined(self.sources,self.bundle)[0].encode())
        self.install('modules/fmz200.optimized.sgmodule',b'last good fallback\n')

    def tearDown(self): self.tmp.cleanup()
    def install(self,p,data):
        path=self.root/p;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    def build(self,new=None,**kwargs):
        return update.build_release(self.root,self.sources,new or self.sources,{s:NEW_SHA for s in update.UPSTREAMS},kwargs.get('notices',self.notices),'2026-10-18')
    def blocked(self,new,code=None,**kwargs):
        before={str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with self.assertRaises(Invalid) as caught:self.build(new,**kwargs)
        if code:self.assertEqual(str(caught.exception),code)
        self.assertEqual(before,{str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
    def changed(self,source,old,new):
        sources=dict(self.sources);sources[source]=sources[source].replace(old,new);return sources
    def ready(self):
        files,status=self.build();sha=update.write_package(self.package,files,BASE_SHA);return files,sha
    def publish_env(self):return patch.dict(os.environ,{'GITHUB_REPOSITORY':update.REPOSITORY,'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'push'})

    def test_first_run_publishes_record_without_changing_module(self):
        files,status=self.build();self.assertEqual(status['status'],'ready');self.assertFalse(status['source_changed'])
        self.assertEqual(files[update.MODULE_PATH],(self.root/update.MODULE_PATH).read_bytes())
        self.assertEqual(set(files),set(update.PACKAGE_FILES));self.assertNotIn('modules/fmz200.optimized.sgmodule',files)
        record=json.loads(files['reports/merged-update.json']);self.assertEqual(record['scope_exclusion_count'],9)
        self.assertEqual(record['supplement_scope_exclusion_count'],2);self.assertEqual(record['conversion_exclusion_count'],1)

    def test_unchanged_is_idempotent(self):
        files,_=self.build()
        for p,data in files.items():self.install(p,data)
        second,status=self.build();self.assertEqual(status['status'],'unchanged');self.assertEqual(files,second)

    def test_safe_comment_shift_preserves_all_exact_choices(self):
        new={s:(b'# comment\n'+d if s!='moyu' else d[:d.index(b'^')]+b'// shift\n'+d[d.index(b'^'):]) for s,d in self.sources.items()}
        files,status=self.build(new);b=json.loads(files['merged-policy.json'])
        self.assertTrue(status['source_changed']);self.assertEqual(b['overlap_review'],self.bundle['overlap_review'])
        self.assertEqual(b['merge_policy']['decisions'],self.bundle['merge_policy']['decisions'])
        self.assertEqual(b['conversion_policy']['excluded_entries'][0]['line'],22)
        self.assertEqual(b['fmz_policy']['scope_exclusions'][0]['line'],5)
        self.assertEqual(b['merge_policy']['excluded_entries'][0]['line'],self.bundle['merge_policy']['excluded_entries'][0]['line']+1)
        self.assertNotIn(b'DOMAIN,excluded0',files[update.MODULE_PATH]);self.assertNotIn(b'^https://tf.test/',files[update.MODULE_PATH])

    def test_small_normal_reject_updates_are_allowed(self):
        for source,marker,addition in [('fmz200',b'^https://fmz.example.test/ _ reject',b'^https://fmz.example.test/ _ reject\n^https://new.test/ _ reject'),
            ('blackmatrix7',b'^https://second.example.test/ _ reject',b'^https://second.example.test/ _ reject\n^https://new.test/ _ reject'),
            ('moyu',b'^https://third.example.test/ url reject-200',b'^https://third.example.test/ url reject-200\n^https://new.test/ url reject')]:
            with self.subTest(source=source):
                files,status=self.build(self.changed(source,marker,addition));self.assertTrue(status['source_changed']);self.assertIn(b'new.test',files[update.MODULE_PATH])

    def test_missing_changed_or_duplicated_scope_target_is_blocked(self):
        for replace in (b'',b'DOMAIN,changed0.test,REJECT\n',b'DOMAIN,excluded0.test,REJECT\n'*2):
            with self.subTest(replace=replace):self.blocked(self.changed('fmz200',b'DOMAIN,excluded0.test,REJECT\n',replace),'scope_target_missing_changed_or_ambiguous')

    def test_supplement_scope_target_drift_is_blocked(self):
        self.blocked(self.changed('blackmatrix7',b'excluded.test',b'changed.test'),'reviewed_target_missing_changed_or_ambiguous')
        self.blocked(self.changed('moyu',b'excluded-moyu.test',b'changed.test'),'reviewed_target_missing_changed_or_ambiguous')

    def test_testflight_exclusion_cannot_silently_change(self):
        self.blocked(self.changed('moyu',b'^https://tf.test/',b'^https://changed.test/'),'reviewed_target_missing_changed_or_ambiguous')

    def test_witness_target_drift_is_blocked(self):
        self.blocked(self.changed('blackmatrix7',b'^https://base.example.test/',b'^https://base.example.test/new'),'conflict_exclusion_missing_changed_or_ambiguous')

    def test_known_witness_new_supplement_reintroduction_is_blocked(self):
        new=dict(self.sources);new['blackmatrix7']+=b'^https://base.example.test/p _ reject\n'
        self.blocked(new)

    def test_new_domain_rule_cannot_bypass_known_url_witness(self):
        new=dict(self.sources);new['blackmatrix7']+=b'[Rule]\nDOMAIN,base.example.test,REJECT\n'
        self.blocked(new,'routing_definition_changed_requires_review')

    def test_map_local_cannot_bypass_redirect_and_header_review(self):
        new=dict(self.sources)
        new['blackmatrix7']+=b'[Map Local]\n^https://new.test/ data-type=text data="{}" status-code=302 header="Location:https://destination.test/"\n'
        self.blocked(new,'map_local_definition_changed_requires_review')

    def test_new_literal_conflict_requires_review(self):
        new=dict(self.sources);new['blackmatrix7']+=b'^https://base.example.test/path _ reject\n';self.blocked(new)

    def test_new_runtime_script_is_blocked(self):
        new=dict(self.sources);new['blackmatrix7']+=b'[Script]\na = type=http-response, pattern=.*, script-path=https://example.test/a.js\n';self.blocked(new)

    def test_new_redirect_header_body_and_direct_route_are_blocked(self):
        for entry in (b'^https://new.test/ https://destination.test/ 302\n',
            b'[Header Rewrite]\nhttp-response ^https://new.test/ header-del X-Test\n',
            b'[Body Rewrite]\nhttp-response ^https://new.test/ a b\n',b'[Rule]\nDOMAIN,new.test,DIRECT\n'):
            with self.subTest(entry=entry):
                new=dict(self.sources);new['blackmatrix7']+=entry;self.blocked(new)

    def test_metadata_mitm_and_author_changes_blocked(self):
        for old,new in ((b'Second author',b'Changed author'),(b'[URL Rewrite]',b'#!arguments=x\n[URL Rewrite]')):
            self.blocked(self.changed('blackmatrix7',old,new))
        self.blocked(self.changed('fmz200',b'%APPEND% base.example.test',b'%APPEND% base.example.test, new.test'))

    def test_upstream_notice_changes_blocked(self):
        for path in self.notices:
            notices=dict(self.notices);notices[path]+=b'changed\n'
            with self.subTest(path=path):self.blocked(self.sources,'upstream_notice_changed_requires_review',notices=notices)

    def test_moyu_notice_guard_uses_new_source_not_supplied_old_notice(self):
        self.blocked(self.changed('moyu',b'Original notice 0',b'Changed notice 0'),'moyu_header_notice_mismatch')

    def test_baseline_reproduction_required(self):
        self.install(update.MODULE_PATH,b'changed\n');self.blocked(self.sources,'published_baseline_not_reproducible')

    def test_source_set_and_destination_cannot_expand(self):
        manifest=deepcopy(self.manifest);manifest['sources'][1]['url']='https://evil.test/source';json_write(self.root/'sources-merged.json',manifest)
        self.blocked(self.sources)

    def test_blanket_license_approval_is_rejected(self):
        manifest=deepcopy(self.manifest);manifest['redistribution']['approved']=True;json_write(self.root/'sources-merged.json',manifest)
        self.blocked(self.sources,'blanket_permission_claim_forbidden')

    def test_package_binding_and_exact_paths(self):
        files,sha=self.ready();self.assertEqual(files,update.verify_package(self.package,sha,BASE_SHA))
        for expected,base in (('0'*64,BASE_SHA),(sha,OLD_SHA)):
            with self.assertRaises(update.Blocked):update.verify_package(self.package,expected,base)
        (self.package/'extra.txt').write_text('extra')
        with self.assertRaisesRegex(update.Blocked,'unexpected_package_path'):update.verify_package(self.package,sha,BASE_SHA)

    def test_package_file_tampering_blocked(self):
        _,sha=self.ready();(self.package/update.MODULE_PATH).write_bytes(b'tampered')
        with self.assertRaises(update.Blocked):update.verify_package(self.package,sha,BASE_SHA)

    def test_package_symlink_blocked(self):
        _,sha=self.ready();p=self.package/'docs/merged-notice.md';p.unlink();p.symlink_to(self.root/'docs/merged-notice.md')
        with self.assertRaisesRegex(update.Blocked,'package_symlink_forbidden'):update.verify_package(self.package,sha,BASE_SHA)

    def test_prepare_fetches_only_fixed_sources_and_notices(self):
        downloads={update.upstream_url(s,OLD_SHA):self.sources[s] for s in update.UPSTREAMS}
        downloads.update({update.upstream_url(s,NEW_SHA):self.sources[s] for s in update.UPSTREAMS});downloads[update.MOYU_URL]=self.sources['moyu']
        downloads.update({update.upstream_url(s,NEW_SHA,tail):self.notices[p] for p,(s,tail,_) in update.NOTICE_SPECS.items() if s!='moyu'})
        with patch.object(update,'download',side_effect=lambda url:downloads[url]),patch.object(update,'resolve_commit',return_value=NEW_SHA):
            status=update.prepare(self.root,self.package,BASE_SHA,'2026-10-18')
        self.assertEqual(status['status'],'ready');update.verify_package(self.package,status['package_sha256'],BASE_SHA)

    def test_prepare_failure_writes_no_package_or_tracked_files(self):
        with patch.object(update,'download',side_effect=OSError('remote untrusted text')):
            with self.assertRaises(OSError):update.prepare(self.root,self.package,BASE_SHA)
        self.assertFalse(self.package.exists());self.assertEqual((self.root/'modules/fmz200.optimized.sgmodule').read_bytes(),b'last good fallback\n')

    def test_main_sanitizes_errors_and_restores_alarm(self):
        report=Path(self.tmp.name)/'report.json'
        with patch.object(update,'prepare',side_effect=ValueError('do not expose upstream SECRET')),patch.object(update.signal,'alarm') as alarm:
            code=update.main(['prepare','--root',str(self.root),'--base-sha',BASE_SHA,'--report',str(report)])
        self.assertEqual(code,2);self.assertNotIn('SECRET',report.read_text());self.assertEqual(alarm.call_args_list[-1].args,(0,))

    def test_main_race_blocks_before_writes(self):
        _,sha=self.ready()
        with self.publish_env(),patch.object(update,'github_json',return_value={'object':{'sha':OLD_SHA}}) as api:
            with self.assertRaisesRegex(update.Blocked,'main_advanced_rebuild_required'):update.publish(self.package,sha,BASE_SHA,'synthetic')
        self.assertEqual(api.call_count,1);self.assertNotIn('method',api.call_args.kwargs)

    def test_publish_permissions_and_token_are_required(self):
        _,sha=self.ready()
        for context in ({'GITHUB_EVENT_NAME':'pull_request'},{'GITHUB_REF':'refs/heads/untrusted'},{'GITHUB_REPOSITORY':'other/repo'}):
            with self.publish_env(),patch.dict(os.environ,context),patch.object(update,'github_json') as api,self.assertRaises(update.Blocked):update.publish(self.package,sha,BASE_SHA,'synthetic')
            api.assert_not_called()
        with self.publish_env(),patch.object(update,'github_json') as api,self.assertRaises(update.Blocked):update.publish(self.package,sha,BASE_SHA,None)
        api.assert_not_called()

    def fake_api(self,calls,uncertain=False):
        def fake(url,**kw):
            calls.append((url,kw));endpoint=url.split('/git/')[1]
            if endpoint=='ref/heads/main':return {'object':{'sha':'7'*40 if any(k.get('method')=='PATCH' for _,k in calls) else BASE_SHA}}
            if endpoint=='commits/'+BASE_SHA:return {'tree':{'sha':'4'*40}}
            if endpoint=='blobs':return {'sha':'5'*40}
            if endpoint=='trees':return {'sha':'6'*40}
            if endpoint=='commits':return {'sha':'7'*40}
            if endpoint=='refs/heads/main':
                if uncertain:raise OSError('uncertain')
                return {'object':{'sha':'7'*40}}
            raise AssertionError(endpoint)
        return fake

    def test_publish_atomic_fixed_merged_paths_and_no_force(self):
        _,sha=self.ready();calls=[]
        with self.publish_env(),patch.object(update,'github_json',side_effect=self.fake_api(calls)):result=update.publish(self.package,sha,BASE_SHA,'synthetic')
        self.assertEqual(result['status'],'published')
        tree=next(k['payload'] for u,k in calls if u.endswith('/trees'));self.assertEqual({e['path'] for e in tree['tree']},set(update.PUBLIC_FILES))
        self.assertTrue(all('fmz200.optimized.sgmodule' not in e['path'] for e in tree['tree']))
        commit=next(k['payload'] for u,k in calls if u.endswith('/commits'));self.assertEqual(commit['parents'],[BASE_SHA])
        self.assertEqual([k['payload'] for u,k in calls if k.get('method')=='PATCH'],[{'sha':'7'*40,'force':False}])

    def test_uncertain_publication_is_not_retried(self):
        _,sha=self.ready();calls=[]
        with self.publish_env(),patch.object(update,'github_json',side_effect=self.fake_api(calls,True)),self.assertRaises(update.PublicationUncertain):update.publish(self.package,sha,BASE_SHA,'synthetic')
        self.assertEqual(sum(k.get('method')=='PATCH' for _,k in calls),1)

    def install_adapter_fixture(self):
        line='^https://bank.test/ url script-response-header https://example.test/bank.js'
        self.sources['moyu'] += (line+'\n').encode()
        conversion=self.bundle['conversion_policy'];conversion['source_sha256']=digest(self.sources['moyu'])
        conversion['native_header_adapters']=[{'line':len(self.sources['moyu'].splitlines()),'line_sha256':digest(line),
            'source_script_url':'https://example.test/bank.js','source_script_sha256':'a'*64,
            'adapter_url':'https://raw.githubusercontent.com/Xuemq/surge-modules/main/scripts/header-status.js',
            'adapter_sha256':digest((self.root/'scripts/header-status.js').read_bytes()),
            'header_names':['Operation'],'keywords':['ad'],'status':404,'reason':'Reviewed status-only fixture.','evidence':'Synthetic review.'}]
        native,_=convert_qx(self.sources['moyu'],conversion)
        self.bundle['scope_policies']['moyu-native']['source_sha256']=digest(native)
        self.bundle['source_sha256']['moyu']=digest(self.sources['moyu'])
        modules,_=prepare_modules(self.sources,self.bundle);self.bundle['merge_policy']['source_sha256']={m.source:m.sha256 for m in modules}
        self.manifest['sources'][2].update(sha256=digest(self.sources['moyu']),bytes=len(self.sources['moyu']))
        json_write(self.root/'sources-merged.json',self.manifest);json_write(self.root/'merged-policy.json',self.bundle)
        self.install('upstream/moyu.source',self.sources['moyu']);self.install(update.MODULE_PATH,build_combined(self.sources,self.bundle)[0].encode())

    def test_native_adapter_hash_and_exact_source_target_are_frozen(self):
        self.install_adapter_fixture()
        self.blocked(self.changed('moyu',b'^https://bank.test/',b'.*'),'reviewed_target_missing_changed_or_ambiguous')
        self.install('scripts/header-status.js',b'changed adapter')
        self.blocked(self.sources,'native_adapter_hash_changed')

    def test_native_adapter_line_shift_preserves_all_parameters(self):
        self.install_adapter_fixture();old=deepcopy(self.bundle['conversion_policy']['native_header_adapters'][0])
        new=self.changed('moyu',b'^https://bank.test/',b'// shifted\n^https://bank.test/')
        files,_=self.build(new);adapter=json.loads(files['merged-policy.json'])['conversion_policy']['native_header_adapters'][0]
        old['line']+=1;self.assertEqual(adapter,old)

    def install_serialization_fixture(self):
        self.install_adapter_fixture()
        before=parse_module((self.root/update.MODULE_PATH).read_bytes(),'fixture')
        target=next(e for e in before.entries if e.section=='Script' and e.key.startswith('moyu_native_'))
        self.bundle['serialization_repairs']={'schema_version':1,'adapter_url':update.SERIALIZATION_ADAPTER_URL,
            'adapter_sha256':digest((self.root/update.SERIALIZATION_ADAPTER_PATH).read_bytes()),
            'entries':[{'entry_id':target.id,'kind':'uri-header-argument','reason':'Reviewed transport fixture.',
                'evidence':'https://manual.nssurge.com/scripting/http-response.html'}]}
        json_write(self.root/'merged-policy.json',self.bundle)
        self.install(update.MODULE_PATH,build_combined(self.sources,self.bundle)[0].encode())

    def test_repaired_baseline_rebuilds_exactly_and_then_is_noop(self):
        self.install_serialization_fixture();files,status=self.build()
        self.assertEqual(files[update.MODULE_PATH],(self.root/update.MODULE_PATH).read_bytes())
        self.assertIn(b'script-path='+update.SERIALIZATION_ADAPTER_URL.encode(),files[update.MODULE_PATH])
        self.assertIn(b'argument=uri:%7B',files[update.MODULE_PATH])
        for path,data in files.items():self.install(path,data)
        second,status=self.build();self.assertEqual(status['status'],'unchanged');self.assertEqual(second,files)

    def test_serialization_policy_is_unchanged_after_source_line_migration(self):
        self.install_serialization_fixture();expected=deepcopy(self.bundle['serialization_repairs'])
        new=self.changed('moyu',b'^https://bank.test/',b'// Shift line only\n^https://bank.test/')
        files,_=self.build(new);migrated=json.loads(files['merged-policy.json'])
        self.assertEqual(migrated['serialization_repairs'],expected)
        self.assertIn(b'argument=uri:%7B',files[update.MODULE_PATH])
        self.assertEqual(migrated['merge_policy']['decisions'],self.bundle['merge_policy']['decisions'])
        self.assertEqual(migrated['overlap_review'],self.bundle['overlap_review'])

    def test_v2_adapter_checksum_or_destination_change_blocks(self):
        self.install_serialization_fixture()
        bundle=deepcopy(self.bundle);bundle['serialization_repairs']['adapter_url']='https://example.test/other.js'
        json_write(self.root/'merged-policy.json',bundle);self.blocked(self.sources,'serialization_adapter_binding_changed')
        json_write(self.root/'merged-policy.json',self.bundle)
        self.install(update.SERIALIZATION_ADAPTER_PATH,b'changed v2 runtime')
        self.blocked(self.sources,'serialization_adapter_binding_changed')

    def test_serialization_target_drift_cannot_remove_the_fix(self):
        self.install_serialization_fixture()
        self.blocked(self.changed('moyu',b'^https://bank.test/',b'^https://different.test/'),'reviewed_target_missing_changed_or_ambiguous')
        bundle=deepcopy(self.bundle);bundle['serialization_repairs']['entries'][0]['entry_id']='0'*64
        json_write(self.root/'merged-policy.json',bundle)
        self.blocked(self.sources)

    def test_v2_artifact_is_verified_but_never_automatically_published(self):
        self.install_serialization_fixture();files,sha=self.ready()
        self.assertIn(update.SERIALIZATION_ADAPTER_PATH,files)
        self.assertNotIn(update.SERIALIZATION_ADAPTER_PATH,update.PUBLIC_FILES)
        self.assertEqual(update.verify_package(self.package,sha,BASE_SHA),files)
        bundle=json.loads(files['merged-policy.json']);bundle['serialization_repairs']['adapter_sha256']='0'*64
        files['merged-policy.json']=update.json_bytes(bundle)
        record=json.loads(files['reports/merged-update.json']);record['policy_sha256']=digest(files['merged-policy.json'])
        files['reports/merged-update.json']=update.json_bytes(record)
        forged=Path(self.tmp.name)/'forged';forged_sha=update.write_package(forged,files,BASE_SHA)
        with self.assertRaisesRegex(update.Blocked,'serialization_adapter_binding_changed'):
            update.verify_package(forged,forged_sha,BASE_SHA)

    def test_existing_script_matcher_body_and_argument_cannot_expand(self):
        old='[Script]\na = type=http-response, pattern=^https://ads.test/, script-path=https://example.test/a.js, requires-body=false, argument=x\n'
        for new in (old.replace('^https://ads.test/','.*'),old.replace('requires-body=false','requires-body=true'),old.replace('argument=x','argument=y')):
            with self.subTest(new=new),self.assertRaisesRegex(update.Blocked,'script_definition_changed_requires_review'):
                update.conservative_delta(old.encode(),new.encode(),old,new)

    def test_sequential_duplicate_occurrences_keep_their_order(self):
        a='http-response ^https://example.test/ a aa';b='http-response ^https://example.test/path aa b'
        old='[Body Rewrite]\n'+a+'\n'+b+'\n'+a+'\n';new='[Body Rewrite]\n'+a+'\n'+a+'\n'+b+'\n'
        with self.assertRaisesRegex(update.Blocked,'existing_rule_order_changed'):
            update.conservative_delta(old.encode(),new.encode(),old,new)

    def test_validation_alarm_is_fail_closed(self):
        report=Path(self.tmp.name)/'timeout.json'
        with patch.object(update,'prepare',side_effect=lambda *args:update.signal.raise_signal(update.signal.SIGALRM)):
            code=update.main(['prepare','--base-sha',BASE_SHA,'--report',str(report)])
        self.assertEqual(code,2);self.assertEqual(json.loads(report.read_text())['reason'],'validation_time_budget_exceeded')
        self.assertFalse(self.package.exists())

    def test_workflows_share_queue_and_exact_resolved_commit(self):
        root=Path(__file__).resolve().parents[1]
        for filename in ('update.yml','update-merged.yml'):
            text=(root/'.github/workflows'/filename).read_text()
            self.assertIn('group: surge-safe-auto-update',text);self.assertIn('cancel-in-progress: false',text)
            self.assertIn('ref: main',text);self.assertIn('git rev-parse HEAD',text)
            self.assertIn('base_sha: ${{ steps.revision.outputs.sha }}',text)
            self.assertIn('ref: ${{ needs.prepare.outputs.base_sha }}',text)
            self.assertEqual(text.count('--base-sha "$BASE_SHA"'),3)
            self.assertEqual(text.count('persist-credentials: false'),2)
            self.assertEqual(text.count('contents: write'),1);self.assertNotIn('pull_request',text)
            self.assertIn("cron: '37 3 * * *'",text)
            if filename=='update-merged.yml':self.assertIn("'scripts/header-status-v2.js'",text)


if __name__=='__main__':unittest.main()
