"""Reproducible, explicitly reviewed three-source assembly; no network or script execution."""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import re
from .core import Invalid, digest, generates_request_response, host_list, merge, parse_module
from .converter import convert_qx
from .pipeline import atomic_write, json_write, read_json
from .scope import filter_native_scope
from .single import optimize_single
from .serialization import repair_serialization

SOURCE_IDS = ('fmz200', 'blackmatrix7', 'moyu')
BEHAVIOR_SECTIONS = {'URL Rewrite', 'Map Local', 'Script', 'Body Rewrite', 'Header Rewrite'}


def active_signature(module):
    return digest(json.dumps([(e.section, e.raw) for e in module.entries], ensure_ascii=False, separators=(',', ':')))


def prepare_modules(source_bytes, bundle):
    """Validate exact source bindings and apply only stored, reviewed transformations."""
    if bundle.get('schema_version') != 1 or set(source_bytes) != set(SOURCE_IDS):
        raise Invalid('combined build requires exactly the three named sources and schema 1')
    if bundle.get('source_sha256') != {s: digest(source_bytes[s]) for s in SOURCE_IDS}:
        raise Invalid('combined source hashes changed; review/migrate exact decisions first')
    base_text, base_report = optimize_single(source_bytes['fmz200'], 'fmz200', bundle['fmz_policy'])
    native, conversion = convert_qx(source_bytes['moyu'], bundle['conversion_policy'])
    if native is None:
        raise Invalid('required QX source has unresolved conversion directives')
    modules = [parse_module(base_text.encode(), 'fmz200-optimized')]
    scope_reports = []
    for source, data in [('blackmatrix7', source_bytes['blackmatrix7']), ('moyu-native', native.encode())]:
        filtered, report = filter_native_scope(data, source, bundle['scope_policies'][source])
        modules.append(parse_module(filtered, source)); scope_reports.append(report)
    return modules, {'fmz': base_report, 'conversion': conversion, 'scope_filters': scope_reports}


def check_finite_witnesses(modules, final, review):
    """Replay finite reviewed examples. This is not the Surge regex engine or a proof."""
    base_ids = {e.id: e for e in modules[0].entries}
    original = {e.id: e for m in modules[1:] for e in m.entries}
    exceptions = {(x['supplement_id'], x['base_id']): x for x in review.get('exceptions', [])}
    witnesses = review.get('witnesses')
    if not isinstance(witnesses, list):
        raise Invalid('finite overlap review requires an explicit witness list')
    active = {e.id: e for e in final.entries}
    failures, used_exceptions = [], set()
    for item in witnesses:
        basis = base_ids.get(item['base_id']); supplement = original.get(item['supplement_id'])
        url = item['witness']
        if (basis is None or supplement is None or not basis.pattern or not supplement.pattern
                or not isinstance(url, str) or len(url) > 4096):
            raise Invalid('stale or malformed overlap witness')
        try:
            if not re.search(basis.pattern, url) or not re.search(supplement.pattern, url):
                raise Invalid('reviewed overlap witness no longer matches both exact entries')
            for entry in final.entries:
                if entry.id in base_ids or not entry.pattern or entry.section not in BEHAVIOR_SECTIONS:
                    continue
                if not re.search(entry.pattern, url):
                    continue
                pair = (entry.id, basis.id)
                if pair in exceptions:
                    used_exceptions.add(pair)
                else:
                    failures.append({'supplement_id': entry.id, 'base_id': basis.id, 'witness': url})
        except re.error as exc:
            raise Invalid('Python cannot replay a reviewed pattern; runtime/regex review required') from exc
    if failures:
        raise Invalid('supplement reintroduced a known baseline overlap: ' + json.dumps(failures[:3]))
    if set(exceptions) - used_exceptions:
        raise Invalid('unused/stale idempotence exception')
    return {'witness_pairs_checked': len(witnesses), 'unexpected_hits': 0,
            'exceptions_used': [exceptions[k] for k in sorted(used_exceptions)],
            'limitation': 'Finite Python-regex examples only; other overlap and Surge/app runtime behavior remain unproved.'}


def _source_header(data):
    result = []
    for line in data.decode('utf-8-sig').splitlines():
        if line.strip() and not line.lstrip().startswith(('#', '//', ';')):
            break
        if line.strip(): result.append(line)
    return result


def source_comment_archive(data):
    """Keep every upstream comment/directive verbatim, including attribution notices."""
    return '\n'.join(line for line in data.decode('utf-8-sig').splitlines()
                     if line.lstrip().startswith(('#', '//', ';'))) + '\n'


def render_module(raw_text, source_bytes, metadata):
    permitted = {'name', 'desc', 'author', 'homepage', 'raw-url', 'category', 'modification_date'}
    if (set(metadata) != permitted or any(not isinstance(v, str) or not v.strip()
            or len(v) > 2048 or any(ord(c) < 32 for c in v) for v in metadata.values())):
        raise Invalid('combined metadata must be bounded, single-line, and complete')
    original = parse_module(raw_text.encode(), 'reviewed-assembly')
    lines = [f'#!{k}={metadata[k]}' for k in ('name', 'desc', 'author', 'homepage', 'raw-url', 'category')]
    lines += [f'#!{k}={v}' for k, v in original.metadata.items()]
    lines += ['', '# Modified ' + metadata['modification_date'] + ' by Xuemq: reviewed conversion, deduplication, parameter repair and conservative conflict selection.',
              '# Original authors and contributors retain their rights. See docs/merged-notice.md and notices/ for exact upstream notices.',
              '# Source licenses are recorded separately; no single license or additional upstream permission is asserted for the combined contents.',
              '# Static and synthetic tests only. Surge/app runtime and arbitrary regex overlap are not verified.',
              '# Requires Surge iOS 5.14+ for jq Body Rewrite; remote scripts may need newer versions.']
    for source in SOURCE_IDS:
        lines += ['', '# Original upstream header: ' + source]
        lines.extend('# ' + line for line in _source_header(source_bytes[source]))
    first_section = next(i for i, line in enumerate(raw_text.splitlines()) if line.startswith('['))
    text = '\n'.join(lines + [''] + raw_text.splitlines()[first_section:]) + '\n'
    final = parse_module(text.encode(), 'merged-release')
    if active_signature(final) != active_signature(original) or final.metadata != original.metadata:
        raise Invalid('release metadata/attribution rendering changed active configuration')
    return text, final


def build_combined(source_bytes, bundle):
    """Return module text and report. No I/O, networking, or implicit conflict choices."""
    modules, stages = prepare_modules(source_bytes, bundle)
    raw, merge_report = merge(modules, bundle['merge_policy'])
    if raw is None:
        raise Invalid('combined build has unresolved exact conflicts')
    text, final = render_module(raw, source_bytes, bundle['module_metadata'])
    guard = check_finite_witnesses(modules, final, bundle['overlap_review'])
    for section in ('Rule', 'URL Rewrite', 'Header Rewrite', 'Body Rewrite', 'Map Local', 'Script'):
        expected = [e.raw for e in modules[0].entries if e.section == section]
        actual = [e.raw for e in final.entries if e.section == section]
        if actual[:len(expected)] != expected:
            raise Invalid('base entry prefix/order changed')
    base_hosts = next((host_list(e.raw.partition('=')[2].strip())[1] for e in modules[0].entries if e.section == 'MITM'), [])
    final_hosts = next((host_list(e.raw.partition('=')[2].strip())[1] for e in final.entries if e.section == 'MITM'), [])
    if final_hosts[:len(base_hosts)] != base_hosts:
        raise Invalid('base MITM hostname ordering changed')
    adapters = bundle['conversion_policy'].get('native_header_adapters', [])
    expected_adapter_ids = {'moyu_native_' + a['line_sha256'][:16] for a in adapters}
    actual_labels = {e.key for e in final.entries if e.section == 'Script'}
    if not expected_adapter_ids <= actual_labels:
        raise Invalid('reviewed native adapter disappeared from final module')
    # Existing source/baseline/overlap guards apply to the reviewed assembly.
    # Exact output-only repairs neither select new rules nor relax those guards.
    text, serialization = repair_serialization(text, bundle.get('serialization_repairs'))
    final = parse_module(text.encode(), 'merged-repaired-release')
    compact_stages = {
        'fmz': {k: stages['fmz'][k] for k in ('source_sha256', 'output_sha256', 'counts_after', 'changes_by_kind')},
        'scope_exclusions': bundle['fmz_policy'].get('scope_exclusions', []),
        'conversion': {k: stages['conversion'][k] for k in ('source_sha256', 'output_sha256', 'converted', 'directives', 'excluded', 'adapted', 'warnings')},
        'scope_filters': stages['scope_filters']}
    compact_merge = {k: merge_report[k] for k in ('base_source', 'source_sha256', 'counts_before', 'counts_after', 'duplicates', 'inherited_conflicts')}
    compact_merge['resolved'] = [{'conflict_id': c['id'], 'kind': c['kind'], 'action': c['decision']['action'], 'entry_ids': c['decision']['entry_ids']} for c in merge_report['resolved']]
    compact_merge['excluded_entries'] = [{k: x[k] for k in ('source', 'line', 'entry_id', 'base_entry_ids')} for x in merge_report['excluded_entries']]
    report = {'schema_version': 1, 'status': 'reviewed_static_build', 'static_only': True,
        'source_sha256': {s: digest(source_bytes[s]) for s in SOURCE_IDS},
        'policy_sha256': digest(json.dumps(bundle, ensure_ascii=False, sort_keys=True, separators=(',', ':'))),
        'reviewed_assembly_sha256': digest(raw), 'output_sha256': digest(text), 'bytes': len(text.encode()),
        'active_entries_sha256': active_signature(final), 'counts': dict(Counter(e.section for e in final.entries)),
        'base_entries_preserved': len(modules[0].entries), 'baseline_mitm_hosts_preserved': len(base_hosts),
        'final_mitm_hosts': len(final_hosts), 'native_adapters_preserved': len(adapters),
        'finite_overlap_review': guard, 'stages': compact_stages, 'merge': compact_merge,
        'serialization_repairs': serialization,
        'base_entries_byte_preserved': len(modules[0].entries) - sum(x['entry_id'] in {e.id for e in modules[0].entries} for x in serialization['applied']),
        'limitations': ['Not tested in Surge or the affected apps.',
            'Finite regex examples are not an exhaustive overlap/equivalence proof.',
            'Remote script/resource contents are not executed or vendored and can change independently.',
            'This technical build report does not grant rights or resolve upstream license/notice interpretation.']}
    return text, report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', default='merged-policy.json')
    parser.add_argument('--cache', default='.cache')
    parser.add_argument('--output-dir', default='work/merged-release')
    args = parser.parse_args(argv)
    sources = {s: (Path(args.cache) / (s + '.source')).read_bytes() for s in SOURCE_IDS}
    bundle = read_json(args.bundle)
    text, report = build_combined(sources, bundle)
    out = Path(args.output_dir)
    # Build/validate everything before the first write; never touch fmz output.
    atomic_write(out / 'modules/merged.optimized.sgmodule', text.encode())
    json_write(out / 'reports/merged-build-report.json', report)
    for source in SOURCE_IDS:
        atomic_write(out / ('notices/' + source + '-source-comments.txt'), source_comment_archive(sources[source]).encode())
    print(json.dumps({k: report[k] for k in ('status', 'output_sha256', 'bytes', 'counts')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
