"""Guarded three-source updates; upstream text is data, never executable code.

Exact reviewed decisions may move line numbers. Their content, conflict choices,
finite witnesses, scope exclusions and runtime permissions are never synthesized.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from datetime import date, datetime, timezone
import json
import os
from pathlib import Path
import re
import signal
import urllib.request

from .auto_update import (Blocked, PublicationUncertain, HEX64, REPOSITORY, commit_sha,
    github_json, json_bytes, migrate_policy, raw_records, require,
    retained_conflict_signatures, validate_delta)
from .combined import SOURCE_IDS, build_combined, prepare_modules, source_comment_archive
from .converter import convert_qx
from .core import clean_bytes, digest, parse_module
from .pipeline import MAX_BYTES, NoRedirect, atomic_write, download, json_write, load_manifest, read_json, verify_bytes
from .scope import filter_native_scope

MODULE_PATH = 'modules/merged.optimized.sgmodule'
MOYU_URL = 'https://ddgksf2013.top/rewrite/StartUpAds.conf'
UPSTREAMS = {
    'fmz200': ('fmz200/wool_scripts', 'main', 'Surge/module/blockAds.module'),
    'blackmatrix7': ('blackmatrix7/ios_rule_script', 'master', 'rewrite/Surge/AllInOne/AllInOne.sgmodule'),
}
NOTICE_SPECS = {
    'licenses/fmz200-GPL-3.0.txt': ('fmz200', 'LICENSE', 'whole-file'),
    'licenses/blackmatrix7-GPL-2.0.txt': ('blackmatrix7', 'LICENSE', 'whole-file'),
    'notices/blackmatrix7-README.md': ('blackmatrix7', 'README.md', 'whole-file'),
    'notices/blackmatrix7-AllInOne-README.md': ('blackmatrix7', 'rewrite/Surge/AllInOne/README.md', 'whole-file'),
    'notices/moyu-original-header.txt': ('moyu', None, 'first20lines'),
}
PUBLIC_FILES = (MODULE_PATH, 'sources-merged.json', 'merged-policy.json', 'upstream/moyu.source',
    'reports/merged-build-report.json', 'reports/merged-update.json',
    *('notices/' + s + '-source-comments.txt' for s in SOURCE_IDS))
SUPPORT_FILES = (*NOTICE_SPECS, 'docs/merged-notice.md', 'scripts/header-status.js')
PACKAGE_FILES = PUBLIC_FILES + SUPPORT_FILES


def upstream_url(source, sha, path=None):
    repo, _, source_path = UPSTREAMS[source]
    return 'https://raw.githubusercontent.com/' + repo + '/' + commit_sha(sha) + '/' + (path or source_path)


def source_commit(source):
    identity = source['id']
    repo, _, path = UPSTREAMS[identity]
    match = re.fullmatch(re.escape('https://raw.githubusercontent.com/' + repo + '/')
        + r'([0-9a-f]{40})/' + re.escape(path), source.get('immutable_url', ''))
    require(match is not None, 'exact_source_commit_required')
    return match[1]


def validate_scope(manifest, bundle):
    require(manifest.get('schema_version') == 1 and manifest.get('base') == 'fmz200'
        and [s.get('id') for s in manifest.get('sources', [])] == list(SOURCE_IDS)
        and manifest.get('policy') == 'merged-policy.json', 'exact_three_source_manifest_required')
    sources = {s['id']: s for s in manifest['sources']}
    for identity, (repo, branch, path) in UPSTREAMS.items():
        source = sources[identity]
        require(source.get('format') == 'surge' and source.get('url') ==
            'https://raw.githubusercontent.com/' + repo + '/' + branch + '/' + path, 'unapproved_source_url')
        source_commit(source)
    require(sources['moyu'].get('format') == 'qx' and sources['moyu'].get('url') == MOYU_URL
        and sources['moyu'].get('snapshot_path') == 'upstream/moyu.source', 'exact_moyu_snapshot_required')
    require(bundle.get('schema_version') == 1 and bundle.get('source_sha256') ==
        {s: sources[s]['sha256'] for s in SOURCE_IDS}, 'bundle_source_lock_mismatch')
    guards = manifest.get('notice_guards', [])
    require(len(guards) == len(NOTICE_SPECS) and {g.get('path') for g in guards} == set(NOTICE_SPECS), 'exact_notice_guards_required')
    for guard in guards:
        identity, tail, extraction = NOTICE_SPECS[guard['path']]
        expected = MOYU_URL if identity == 'moyu' else upstream_url(identity, source_commit(sources[identity]), tail)
        require(guard.get('url') == expected and guard.get('extraction') == extraction, 'notice_guard_binding_mismatch')
    # Hosting was requested; this tool must not turn that into a legal permission claim.
    require('approved' not in manifest.get('redistribution', {}), 'blanket_permission_claim_forbidden')
    return sources


def resolve_commit(identity):
    repo, branch, _ = UPSTREAMS[identity]
    url = 'https://api.github.com/repos/' + repo + '/git/ref/heads/' + branch
    # Deliberately no token parameter, redirects or API-provided follow-up URL.
    request = urllib.request.Request(url, headers={'User-Agent': 'surge-merged-safe-updater/1', 'Accept': 'application/vnd.github+json'})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        require(response.status == 200 and response.geturl() == url, 'unexpected_upstream_ref_response')
        data = response.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, 'oversized_upstream_ref')
    ref = json.loads(data)
    require(ref.get('ref') == 'refs/heads/' + branch and ref.get('object', {}).get('type') == 'commit', 'invalid_upstream_ref')
    return commit_sha(ref['object']['sha'])


def first20lines(data):
    return ('\n'.join(clean_bytes(data).splitlines()[:20]) + '\n').encode()


def relocate_lines(old_data, new_data, selections, section_required=False):
    old, new = raw_records(old_data), raw_records(new_data)
    for selection in selections:
        target = selection['line_sha256']
        identity = lambda sec, sha: sha == target and (not section_required or sec == selection['section'])
        before = [n for sec, sha, n in old if identity(sec, sha)]
        after = [n for sec, sha, n in new if identity(sec, sha)]
        require(before == [selection['line']] and len(after) == 1, 'reviewed_target_missing_changed_or_ambiguous')
        selection['line'] = after[0]


def migrate_scope(old_data, new_data, policy):
    filter_native_scope(old_data, policy['source_id'], policy)
    migrated = deepcopy(policy)
    relocate_lines(old_data, new_data, migrated['excluded_entries'], section_required=True)
    migrated['source_sha256'] = digest(new_data)
    filter_native_scope(new_data, policy['source_id'], migrated)
    return migrated


def module_text(module):
    lines = ['#!' + k + '=' + v for k, v in module.metadata.items()]
    section = None
    for entry in module.entries:
        if entry.section != section:
            section = entry.section
            lines.append('[' + section + ']')
        lines.append(entry.raw)
    return '\n'.join(lines) + '\n'


def conservative_delta(old_data, new_data, old_text, new_text):
    # Shared with the fmz fallback: only new URL Rewrite rejects are eligible;
    # existing reviewed execution/routing/response definitions remain exact.
    return validate_delta(old_data, new_data, old_text, new_text)


def migrate_bundle(old, new, bundle, modification_date):
    date.fromisoformat(modification_date)
    old_modules, old_stages = prepare_modules(old, bundle)
    migrated = deepcopy(bundle)
    migrated['fmz_policy'] = migrate_policy(old['fmz200'], new['fmz200'], bundle['fmz_policy'], modification_date)
    conversion = migrated['conversion_policy']
    require(conversion.get('source_sha256') == digest(old['moyu']), 'conversion_lock_mismatch')
    for key in ('excluded_entries', 'native_header_adapters'):
        relocate_lines(old['moyu'], new['moyu'], conversion.get(key, []))
    # Exact reviewed request-body hashes cannot silently vanish or duplicate.
    for sha in conversion.get('approved_request_body_hashes', []):
        before = [h for _, h, _ in raw_records(old['moyu']) if h == sha]
        after = [h for _, h, _ in raw_records(new['moyu']) if h == sha]
        require(before and before == after, 'approved_body_target_changed')
    conversion['source_sha256'] = digest(new['moyu'])
    old_native, _ = convert_qx(old['moyu'], bundle['conversion_policy'])
    new_native, _ = convert_qx(new['moyu'], conversion)
    require(old_native is not None and new_native is not None, 'conversion_requires_manual_review')
    migrated['scope_policies']['blackmatrix7'] = migrate_scope(old['blackmatrix7'], new['blackmatrix7'], bundle['scope_policies']['blackmatrix7'])
    migrated['scope_policies']['moyu-native'] = migrate_scope(old_native.encode(), new_native.encode(), bundle['scope_policies']['moyu-native'])
    migrated['source_sha256'] = {s: digest(new[s]) for s in SOURCE_IDS}
    if old != new:
        migrated['module_metadata']['modification_date'] = modification_date
    new_modules, new_stages = prepare_modules(new, migrated)
    require(retained_conflict_signatures(new['fmz200'], new_stages['fmz']) <=
        retained_conflict_signatures(old['fmz200'], old_stages['fmz']), 'new_inherited_base_conflict')
    for before, after in zip(old_modules, new_modules):
        source = 'fmz200' if before.source == 'fmz200-optimized' else before.source
        old_raw, new_raw = (old_native.encode(), new_native.encode()) if source == 'moyu-native' else (old[source], new[source])
        conservative_delta(old_raw, new_raw, module_text(before), module_text(after))
    old_by_source, new_by_source = ({m.source: m for m in group} for group in (old_modules, new_modules))
    for selection in migrated['merge_policy']['excluded_entries']:
        before = [e for e in old_by_source[selection['source']].entries if e.id == selection['entry_id']]
        after = [e for e in new_by_source[selection['source']].entries if e.id == selection['entry_id']]
        require(len(before) == len(after) == 1 and before[0].line == selection['line'], 'conflict_exclusion_missing_changed_or_ambiguous')
        selection['line'] = after[0].line
    migrated['merge_policy']['source_sha256'] = {m.source: m.sha256 for m in new_modules}
    # Decisions, witness identities and exceptions remain byte-for-byte identical.
    require(migrated['merge_policy']['decisions'] == bundle['merge_policy']['decisions']
        and migrated['overlap_review'] == bundle['overlap_review'], 'review_decisions_must_not_change')
    return migrated


def build_release(root, old, new, commits, notices, modification_date):
    root = Path(root)
    manifest, bundle = load_manifest(root / 'sources-merged.json'), read_json(root / 'merged-policy.json')
    sources = validate_scope(manifest, bundle)
    require(set(old) == set(new) == set(SOURCE_IDS) and set(commits) == set(UPSTREAMS), 'exact_source_set_required')
    for sha in commits.values(): commit_sha(sha)
    for identity in SOURCE_IDS:
        verify_bytes(sources[identity], old[identity]); clean_bytes(new[identity])
    require(old['moyu'] == (root / 'upstream/moyu.source').read_bytes(), 'moyu_snapshot_mismatch')
    require(set(notices) == set(NOTICE_SPECS), 'exact_notice_set_required')
    for guard in manifest['notice_guards']:
        observed = notices[guard['path']]
        verify_bytes(guard, (root / guard['path']).read_bytes())
        require(observed == (root / guard['path']).read_bytes(), 'upstream_notice_changed_requires_review')
    require(notices['notices/moyu-original-header.txt'] == first20lines(new['moyu']), 'moyu_header_notice_mismatch')
    for adapter in bundle['conversion_policy'].get('native_header_adapters', []):
        require(adapter['adapter_url'] == 'https://raw.githubusercontent.com/' + REPOSITORY + '/main/scripts/header-status.js'
            and digest((root / 'scripts/header-status.js').read_bytes()) == adapter['adapter_sha256'], 'native_adapter_hash_changed')
    old_text, _ = build_combined(old, bundle)
    require(old_text.encode() == (root / MODULE_PATH).read_bytes(), 'published_baseline_not_reproducible')
    migrated = migrate_bundle(old, new, bundle, modification_date)
    text, report = build_combined(new, migrated)
    delta = conservative_delta(old_text.encode(), text.encode(), old_text, text)
    updated = deepcopy(manifest)
    for source in updated['sources']:
        identity = source['id']
        if old[identity] != new[identity]:
            source.update(sha256=digest(new[identity]), bytes=len(new[identity]))
            if identity in UPSTREAMS:
                source['immutable_url'] = upstream_url(identity, commits[identity])
    new_sources = {s['id']: s for s in updated['sources']}
    for guard in updated['notice_guards']:
        identity, tail, _ = NOTICE_SPECS[guard['path']]
        if identity in UPSTREAMS:
            guard['url'] = upstream_url(identity, source_commit(new_sources[identity]), tail)
    support = {path: (root / path).read_bytes() for path in SUPPORT_FILES}
    record = {'schema_version': 1, 'scope': 'reviewed-three-source', 'static_only': True,
        'source_sha256': migrated['source_sha256'], 'module_sha256': report['output_sha256'],
        'policy_sha256': digest(json_bytes(migrated)), 'support_sha256': {p: digest(v) for p, v in support.items()},
        'scope_exclusion_count': len(migrated['fmz_policy'].get('scope_exclusions', [])),
        'supplement_scope_exclusion_count': sum(len(p['excluded_entries']) for p in migrated['scope_policies'].values()),
        'conversion_exclusion_count': len(migrated['conversion_policy'].get('excluded_entries', [])),
        'conflict_decision_count': len(migrated['merge_policy']['decisions']),
        'overlap_witness_count': len(migrated['overlap_review']['witnesses']),
        'modification_date': migrated['module_metadata']['modification_date']}
    files = {MODULE_PATH: text.encode(), 'sources-merged.json': json_bytes(updated), 'merged-policy.json': json_bytes(migrated),
        'upstream/moyu.source': new['moyu'], 'reports/merged-build-report.json': json_bytes(report),
        'reports/merged-update.json': json_bytes(record), **support}
    files.update({'notices/' + s + '-source-comments.txt': source_comment_archive(new[s]).encode() for s in SOURCE_IDS})
    require(set(files) == set(PACKAGE_FILES), 'unexpected_release_path')
    changed = [p for p in PUBLIC_FILES if not (root / p).exists() or (root / p).read_bytes() != files[p]]
    return files, {'schema_version': 1, 'status': 'ready' if changed else 'unchanged', 'source_changed': old != new,
        'module_sha256': report['output_sha256'], 'changed_paths': changed,
        'scope_exclusions': record['scope_exclusion_count'], 'overlap_witnesses': record['overlap_witness_count'], **delta}


def write_package(folder, files, base_sha):
    folder = Path(folder)
    commit_sha(base_sha)
    require(not folder.exists(), "package_destination_must_be_new")
    require(set(files) == set(PACKAGE_FILES), "unexpected_release_path")
    # The manifest is written last. A partial folder can never pass verification.
    package = {"schema_version": 1, "repository": REPOSITORY, "base_sha": base_sha,
               "files": {path: {"sha256": digest(data), "bytes": len(data)} for path, data in files.items()}}
    for path, data in files.items():
        atomic_write(folder / path, data)
    encoded = json_bytes(package)
    atomic_write(folder / "package.json", encoded)
    return digest(encoded)


def verify_package(folder, expected_digest, base_sha):
    folder = Path(folder)
    require(isinstance(expected_digest, str) and HEX64.fullmatch(expected_digest), "invalid_package_digest")
    commit_sha(base_sha)
    require(folder.is_dir() and not folder.is_symlink(), "invalid_package_directory")
    files_on_disk = set()
    for path in folder.rglob("*"):
        require(not path.is_symlink(), "package_symlink_forbidden")
        if path.is_file():
            files_on_disk.add(path.relative_to(folder).as_posix())
        else:
            require(path.is_dir(), "package_nonregular_file")
    require(files_on_disk == set(PACKAGE_FILES) | {"package.json"}, "unexpected_package_path")
    require((folder / "package.json").stat().st_size < 16384, "oversized_package_manifest")
    encoded = (folder / "package.json").read_bytes()
    require(digest(encoded) == expected_digest, "package_digest_mismatch")
    package = json.loads(encoded)
    require(set(package) == {"schema_version", "repository", "base_sha", "files"}
            and package["schema_version"] == 1 and package["repository"] == REPOSITORY
            and package["base_sha"] == base_sha and set(package["files"]) == set(PACKAGE_FILES), "package_binding_mismatch")
    result = {}
    for path in PACKAGE_FILES:
        require(0 < (folder / path).stat().st_size <= MAX_BYTES, "invalid_package_file_size")
        data = (folder / path).read_bytes()
        require(package["files"][path] == {"sha256": digest(data), "bytes": len(data)}, "package_file_hash_mismatch")
        clean_bytes(data)
        result[path] = data
    record = json.loads(result["reports/merged-update.json"])
    require(record["module_sha256"] == digest(result[MODULE_PATH])
            and record["policy_sha256"] == digest(result["merged-policy.json"])
            and record["support_sha256"] == {p: digest(result[p]) for p in SUPPORT_FILES}, "release_record_mismatch")
    parse_module(result[MODULE_PATH], "package-self-check")
    manifest, bundle = json.loads(result['sources-merged.json']), json.loads(result['merged-policy.json'])
    sources = validate_scope(manifest, bundle)
    verify_bytes(sources['moyu'], result['upstream/moyu.source'])
    require(record['source_sha256'] == bundle['source_sha256'], 'record_source_lock_mismatch')
    return result



def publish(folder, expected_digest, base_sha, token):
    """Atomic fast-forward only; no PAT, force push, retries, or other repo writes."""
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") in {"schedule", "workflow_dispatch", "push"}, "publish_requires_approved_workflow_context")
    require(isinstance(token, str) and token, "missing_builtin_workflow_token")
    files = verify_package(folder, expected_digest, base_sha)
    api = f"https://api.github.com/repos/{REPOSITORY}/git/"
    request = lambda suffix, **kwargs: github_json(api + suffix, token=token, **kwargs)
    current = request("ref/heads/main")
    require(current.get("object", {}).get("sha") == base_sha, "main_advanced_rebuild_required")
    base = request("commits/" + base_sha)
    base_tree = commit_sha(base["tree"]["sha"])
    tree_entries = []
    for path in PUBLIC_FILES:
        blob = request("blobs", method="POST", payload={"content": base64.b64encode(files[path]).decode(), "encoding": "base64"})
        tree_entries.append({"path": path, "mode": "100644", "type": "blob", "sha": commit_sha(blob["sha"])})
    tree = request("trees", method="POST", payload={"base_tree": base_tree, "tree": tree_entries})
    tree_sha = commit_sha(tree["sha"])
    if tree_sha == base_tree:
        return {"schema_version": 1, "status": "unchanged", "commit": base_sha}
    record = json.loads(files["reports/merged-update.json"])
    commit = request("commits", method="POST", payload={"message": "chore: safely refresh reviewed merged module " + record["module_sha256"][:12],
                     "tree": tree_sha, "parents": [base_sha]})
    sha = commit_sha(commit["sha"])
    # force:false rejects races. An uncertain response is never blindly retried.
    try:
        request("refs/heads/main", method="PATCH", payload={"sha": sha, "force": False})
        verified = request("ref/heads/main")
        require(verified.get("object", {}).get("sha") == sha, "publication_not_confirmed_check_main")
    except Exception as exc:
        # No blind retry: an interrupted PATCH can already have succeeded.
        raise PublicationUncertain("publication_unconfirmed_check_main") from exc
    return {"schema_version": 1, "status": "published", "commit": sha, "module_sha256": record["module_sha256"]}



def prepare(root, folder, base_sha, modification_date=None):
    root = Path(root)
    manifest, bundle = load_manifest(root / 'sources-merged.json'), read_json(root / 'merged-policy.json')
    sources = validate_scope(manifest, bundle)
    old = {s: download(sources[s]['immutable_url']) for s in UPSTREAMS}
    old['moyu'] = (root / 'upstream/moyu.source').read_bytes()
    for s in SOURCE_IDS: verify_bytes(sources[s], old[s])
    commits = {s: resolve_commit(s) for s in UPSTREAMS}
    new = {s: download(upstream_url(s, commits[s])) for s in UPSTREAMS}
    new['moyu'] = download(MOYU_URL)
    notices = {p: (first20lines(new['moyu']) if s == 'moyu' else download(upstream_url(s, commits[s], tail)))
        for p, (s, tail, _) in NOTICE_SPECS.items()}
    day = modification_date or datetime.now(timezone.utc).date().isoformat()
    files, status = build_release(root, old, new, commits, notices, day)
    if status['status'] == 'ready':
        status['package_sha256'] = write_package(folder, files, base_sha)
        verify_package(folder, status['package_sha256'], base_sha)
    return status


def emit_status(status):
    print(status['status'])
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as handle:
            handle.write('### Reviewed three-source update\n\nStatus: ' + status['status'] + '\n\n')
            for key in ('reason', 'module_sha256', 'scope_exclusions', 'overlap_witnesses', 'commit'):
                if key in status: handle.write(f'- {key}: {status[key]}\n')
            handle.write('\nStatic checks only; failures publish nothing. Unconfirmed publication requires checking main before retry.\n')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as handle:
            handle.write('changed=' + str(status['status'] == 'ready').lower() + '\n')
            if 'package_sha256' in status: handle.write('package_sha256=' + status['package_sha256'] + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'verify-package', 'publish'))
    parser.add_argument('--root', default='.')
    parser.add_argument('--package', default='work/merged-auto-package')
    parser.add_argument('--base-sha', required=True)
    parser.add_argument('--package-sha256', default=os.environ.get('EXPECTED_PACKAGE_SHA256', ''))
    parser.add_argument('--report', default='work/merged-auto-status.json')
    args = parser.parse_args(argv)
    previous = None
    try:
        commit_sha(args.base_sha)
        if args.command == 'prepare':
            # Linux runner: bound parser/finite-regex work as well as network waits.
            # No remote JavaScript, jq or shell is executed. Timeout publishes nothing.
            def expired(_signum, _frame): raise Blocked('validation_time_budget_exceeded')
            previous = signal.signal(signal.SIGALRM, expired)
            signal.alarm(180)
            status = prepare(args.root, args.package, args.base_sha)
        elif args.command == 'verify-package':
            verify_package(args.package, args.package_sha256, args.base_sha)
            status = {'schema_version': 1, 'status': 'package_verified'}
        else:
            status = publish(args.package, args.package_sha256, args.base_sha, os.environ.get('GITHUB_TOKEN'))
        result = 0
    except Exception as exc:
        reason = str(exc) if isinstance(exc, Blocked) and re.fullmatch(r'[a-z_]+', str(exc)) else 'fetch_or_validation_failed'
        status = {'schema_version': 1, 'status': 'publication_unconfirmed' if isinstance(exc, PublicationUncertain) else 'blocked', 'reason': reason}
        result = 2
    finally:
        if previous is not None:
            signal.alarm(0); signal.signal(signal.SIGALRM, previous)
    json_write(args.report, status)
    emit_status(status)
    return result


if __name__ == '__main__':
    raise SystemExit(main())
