"""Lossless single-upstream optimizer: no cross-project license mixing."""
from collections import Counter
import base64
import json
import re
from .core import Invalid, clean_bytes, digest, host_list, params, parse_entry, parse_module


def optimize_single(data, source, policy):
    """Keep comments/order and every distinct behavior; record every changed line."""
    text = clean_bytes(data)
    if digest(data) != policy.get('source_sha256'):
        raise Invalid('single-source policy is stale for this exact source hash')
    if source != policy.get('source_id'):
        raise Invalid('single-source policy does not match source ID')
    defaults = policy.get('argument_defaults', {})
    repairs = policy.get('script_argument_repairs', {})
    metadata = policy.get('module_metadata', {})
    if (not isinstance(metadata, dict) or set(metadata) - {'name', 'desc'}
            or any(not isinstance(v, str) or not v.strip() or len(v) > 1024
                   or any(ord(c) < 32 for c in v) for v in metadata.values())):
        raise Invalid('module metadata supports only single-line name and description')
    metadata_written = set()
    used_repairs = set()
    removals = {r['line_sha256']: r for r in policy.get('confirmed_invalid_entries', [])}
    if len(removals) != len(policy.get('confirmed_invalid_entries', [])):
        raise Invalid('duplicate stale-rule removal decision')
    for r in removals.values():
        if not r.get('reason') or not r.get('evidence') or r.get('classification') not in {'confirmed-404', 'confirmed-410', 'upstream-retired', 'invalid-syntax'}:
            raise Invalid('stale-rule removal requires confirmed evidence, not timeout/403/age')
    # Scope selections are separate from claims that a rule is obsolete. Bind
    # each decision to one exact occurrence, never an app-name/domain substring.
    scope_exclusions = {}
    for r in policy.get('scope_exclusions', []):
        if not isinstance(r, dict) or set(r) != {'line', 'section', 'line_sha256', 'classification', 'reason'}:
            raise Invalid('scope exclusion requires only exact target and reason fields')
        if (type(r['line']) is not int or r['line'] < 1
                or r['section'] not in {'Rule', 'URL Rewrite', 'Header Rewrite', 'Body Rewrite', 'Map Local', 'Script'}
                or not isinstance(r['line_sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', r['line_sha256'])
                or r['classification'] != 'manual-scope-exclusion'
                or not isinstance(r['reason'], str) or not r['reason'].strip()
                or len(r['reason']) > 500 or any(c in r['reason'] for c in '\r\n')):
            raise Invalid('scope exclusion requires an exact reviewed rule; MITM/General cannot be excluded')
        if r['line'] in scope_exclusions:
            raise Invalid('duplicate scope exclusion target')
        if r['line_sha256'] in removals or r['line_sha256'] in repairs:
            raise Invalid('scope exclusion conflicts with another modification decision')
        scope_exclusions[r['line']] = r
    used_scope_exclusions = set()
    report = {'schema_version': 1, 'source': source, 'source_sha256': digest(data), 'static_only': True,
              'changes': [], 'removed': [], 'retained_conflicts': [],
              'limitations': ['Not tested inside Surge iOS.', 'No regex equivalence or live ad endpoint tests.', 'Referenced runtime files remain upstream and are not vendored.']}
    # Repair missing declarations only from a reviewed upstream defaults record.
    declared = {}
    for l in text.splitlines():
        if l.startswith('#!arguments='):
            for p in l.split('=', 1)[1].split(','):
                k, _, v = p.partition(':'); declared[k] = v
    used = set(re.findall(r'\{\{\{([^{}]+)\}\}\}', '\n'.join(l for l in text.splitlines() if not l.lstrip().startswith(('#','//',';')))))
    for repair in repairs.values():
        if not repair.get('reason') or not repair.get('evidence') or not isinstance(repair.get('argument'), str) or any(c in repair['argument'] for c in '\n\r'):
            raise Invalid('script argument repair requires exact reviewed evidence')
        used.update(re.findall(r'\{\{\{([^{}]+)\}\}\}', repair['argument']))
    missing = used - set(declared)
    if missing - set(defaults):
        raise Invalid('missing argument defaults have no reviewed source')
    for key in sorted(missing):
        if not re.fullmatch(r'[A-Za-z0-9_]+', key) or not isinstance(defaults[key], str) or any(x in defaults[key] for x in '\n\r,'):
            raise Invalid('invalid reviewed argument default')
        declared[key] = defaults[key]
    section, seen, out, scripts, used_removals, groups = None, {}, [], {}, set(), {}
    argument_written = False
    for n, line in enumerate(text.splitlines(), 1):
        raw = line.strip()
        if raw.startswith('#!name='):
            out.extend(['# Upstream ' + raw, '#!name=' + metadata.get('name', 'fmz200 广告拦截合集（去重修正版）')])
            metadata_written.add('name')
            if 'name' in metadata:
                report['changes'].append({'kind':'module-metadata','line':n,'field':'name','value':metadata['name'],'line_sha256':digest(raw)})
            continue
        if raw.startswith('#!desc=') and 'desc' in metadata:
            out.extend(['# Upstream ' + raw, '#!desc=' + metadata['desc']])
            metadata_written.add('desc')
            report['changes'].append({'kind':'module-metadata','line':n,'field':'desc','value':metadata['desc'],'line_sha256':digest(raw)})
            continue
        if raw.startswith('#!raw-url='):
            out.append('# Upstream ' + raw); continue
        if raw.startswith('#!arguments='):
            out.append('#!arguments=' + ','.join(k + ':' + v for k,v in declared.items())); argument_written = True
            if missing:
                report['changes'].append({'kind':'restore-argument-defaults','line':n,'arguments':sorted(missing),'evidence':policy.get('defaults_evidence'),'additional_evidence':policy.get('additional_defaults_evidence'),'keywos_evidence':policy.get('keywos_defaults_evidence')})
            continue
        if not raw or raw.startswith(('#','//',';')):
            out.append(line);continue
        if raw.startswith('[') and raw.endswith(']'):
            if missing and not argument_written:
                out.append('#!arguments=' + ','.join(k + ':' + v for k,v in declared.items()));argument_written=True
            section=raw[1:-1];out.append(line);continue
        original_hash = digest(raw)
        if n in scope_exclusions:
            selection = scope_exclusions[n]
            if selection['section'] != section or selection['line_sha256'] != original_hash:
                raise Invalid('scope exclusion does not match exact source section/line/hash')
            parse_entry(section, raw, source, n)
            report['removed'].append({'kind': 'scope-exclusion', **selection})
            used_scope_exclusions.add(n)
            out.append(f'# Optimizer: excluded reviewed scope entry at upstream line {n}; see build report.')
            continue
        if original_hash in removals:
            report['removed'].append({'line':n,'line_sha256':original_hash,**removals[original_hash]})
            used_removals.add(original_hash)
            out.append(f'# Optimizer: removed confirmed-invalid entry at upstream line {n}; see build report.')
            continue
        if original_hash in repairs:
            if section != 'Script' or ', argument=' not in raw:
                raise Invalid('argument repair target does not match expected script shape')
            repair=repairs[original_hash]
            raw=re.sub(r',\s*argument=.*?(?=,\s*[a-z][a-z0-9-]*\s*=|$)', '', raw) + ', argument=' + repair['argument']
            used_repairs.add(original_hash)
            report['changes'].append({'kind':'script-argument-object','line':n,'line_sha256':original_hash,'reason':repair['reason'],'evidence':repair['evidence']})
        e=parse_entry(section,raw,source,n)
        if e.safe_dedup and e.id in seen:
            report['changes'].append({'kind':'exact-duplicate','line':n,'line_sha256':original_hash,'kept_line':seen[e.id]})
            continue
        seen[e.id]=n
        groups.setdefault((section,e.key),[]).append(e)
        if section == 'Script':
            name, eq, body=raw.partition('=')
            # Stable name includes definition hash and does not depend on line numbers.
            label=name.strip()
            if label in scripts and scripts[label] != e.id:
                new_label=label + '__' + e.id[:12]
                raw=new_label + ' =' + body
                report['changes'].append({'kind':'unique-script-label','line':n,'line_sha256':original_hash,'old_label':label,'new_label':new_label})
            scripts[label]=e.id
        elif section == 'MITM':
            key,_,value=raw.partition('=');mode,hosts=host_list(value.strip());unique=list(dict.fromkeys(hosts))
            if unique != hosts:
                raw=key.strip()+' = '+(f'%{mode}% ' if mode!='replace' else '')+', '.join(unique)
                report['changes'].append({'kind':'exact-host-duplicate','line':n,'removed_count':len(hosts)-len(unique)})
        elif section == 'Map Local':
            # One observed upstream JSON literal contains unescaped quotes. Encode
            # its exact UTF-8 body as base64 instead of guessing Surge quote rules.
            match=re.search(r'\bdata-type=text\s+data="(\{.*\})"(?=\s+(?:header|status-code)=|$)',raw)
            if match and '"' in match.group(1):
                try:json.loads(match.group(1))
                except json.JSONDecodeError:raise Invalid('embedded JSON mapping is malformed')
                encoded=base64.b64encode(match.group(1).encode()).decode()
                raw=raw[:match.start()]+'data-type=base64 data="'+encoded+'"'+raw[match.end():]
                report['changes'].append({'kind':'json-map-base64','line':n,'line_sha256':original_hash,'body_sha256':digest(match.group(1))})
        out.append(raw)
    if set(repairs)-used_repairs:
        raise Invalid('stale script argument repair decision')
    if set(removals)-used_removals:
        raise Invalid('stale removal decision does not match an active source entry')
    if set(scope_exclusions)-used_scope_exclusions:
        raise Invalid('scope exclusion does not match an active source entry')
    for (sec,key),es in groups.items():
        if len(es)>1 and len({e.id for e in es})>1:
            report['retained_conflicts'].append({'section':sec,'key':key,'lines':[e.line for e in es], 'handling':'Kept original order and distinct bodies; no cross-source choice made.'})
    header=[f'# Modified {policy["modification_date"]} by Xuemq: exact safe deduplication; restored upstream defaults; unique script labels.',
            '# Derived only from fmz200/wool_scripts. Licensed under the upstream GNU GPL v3; see licenses/fmz200-GPL-3.0.txt.',
            '# No blackmatrix7 or ddgksf2013 rule contents have been merged.',
            '# Static validation only. External script/resource URLs retain upstream behavior.',
            '# Requires Surge iOS 5.14+ for jq Body Rewrite; runtime scripts may require a newer version.', '']
    if scope_exclusions:
        header.insert(-1, f'# Explicit scope exclusions: {len(scope_exclusions)} reviewed entries; see build report.')
    for key in sorted(set(metadata) - metadata_written):
        header.insert(-1, f'#!{key}={metadata[key]}')
        report['changes'].append({'kind':'module-metadata','field':key,'value':metadata[key]})
    lines = header + out
    first_section = next(i for i, line in enumerate(lines) if line.startswith('['))
    metadata_lines = [line for line in lines[:first_section] if line.startswith('#!')]
    if metadata_lines:
        # Follow the official module examples: active name/description at byte
        # zero, then other metadata. Attribution and GPL comments remain intact.
        first = [line for key in ('name', 'desc') for line in metadata_lines if line.startswith('#!' + key + '=')]
        first.extend(line for line in metadata_lines if not line.startswith(('#!name=', '#!desc=')))
        lines = first + [''] + [line for line in lines[:first_section] if not line.startswith('#!')] + lines[first_section:]
        report['changes'].append({'kind':'module-header-order',
            'fields':[line[2:].partition('=')[0] for line in first],
            'reason':'Put name/description first, followed by active metadata; preserve attribution and all rule bytes.'})
    result='\n'.join(lines)+'\n'
    parsed=parse_module(result.encode(),source+'-optimized')
    for entry in parsed.entries:
        if entry.section != 'Script':
            continue
        argument = params(entry.raw.partition('=')[2]).get('argument', '')
        if argument and any(argument == repair['argument'][1:-1] for repair in repairs.values()):
            expanded = re.sub(r'\{\{\{([^}]+)\}\}\}', lambda match: declared[match[1]], argument)
            try:
                if not isinstance(json.loads(expanded), dict):
                    raise Invalid('repaired script argument must expand to a JSON object')
            except json.JSONDecodeError as exc:
                raise Invalid('repaired script argument defaults are invalid JSON') from exc
    labels=[e.key for e in parsed.entries if e.section=='Script']
    if len(labels)!=len(set(labels)):
        raise Invalid('script label collision remains after deterministic naming')
    report.update(status='single_source_static_pass',output_sha256=digest(result),counts_after=dict(Counter(e.section for e in parsed.entries)),changes_by_kind=dict(Counter(c['kind'] for c in report['changes'])))
    return result,report
