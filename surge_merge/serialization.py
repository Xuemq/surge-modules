"""Exact, reviewed repairs for legacy Surge profile serialization.

This is not a general Surge parser. No private profile is read or embedded here.
Source selection/overlap review happens before these bounded output repairs.
"""
from __future__ import annotations
import json
import re
from urllib.parse import quote
from .core import Invalid, digest, params, parse_module, unquote, words

ADAPTER_URL = 'https://raw.githubusercontent.com/Xuemq/surge-modules/main/scripts/header-status-v2.js'
KINDS = {'comma-free-host-range', 'uri-header-argument', 'json-string-templates',
         'key-value-template', 'body-token-quotes'}


def _repair(entry, kind, policy):
    raw = entry.raw
    if kind == 'body-token-quotes':
        tokens = words(raw)
        if (entry.section != 'Body Rewrite' or len(tokens) != 4
                or tokens[0] != 'http-response'
                or tokens[2:] != ['offset_ms":\\d+', 'offset_ms":99999999999999']):
            raise Invalid('body serialization repair target shape changed')
        # Same literal regex/replacement as the already working quoted form.
        return ' '.join(tokens[:2] + ["'" + value + "'" for value in tokens[2:]])
    if entry.section != 'Script':
        raise Invalid('script serialization repair requires a script target')
    p = params(raw.partition('=')[2])
    if kind == 'comma-free-host-range':
        old = p['pattern']; fragment = r'(\.[a-zA-Z0-9_-]+){1,4}'
        if old.count(fragment) != 1 or raw.count("pattern='" + old + "'") != 1:
            raise Invalid('host range serialization repair target shape changed')
        atom = r'(?:\.[a-zA-Z0-9_-]+)'
        new = old.replace(fragment, atom + (atom + '?') * 3)
        if any(c in new for c in ",\"' \t\r\n"):
            raise Invalid('host range repair is not delimiter free')
        return raw.replace("pattern='" + old + "'", 'pattern=' + new)
    if kind == 'uri-header-argument':
        value = p.get('argument', '')
        try: spec = json.loads(value)
        except (TypeError, ValueError) as exc: raise Invalid('adapter policy is not JSON') from exc
        if (set(spec) != {'headerNames', 'keywords', 'status'} or spec['status'] != 404
                or p['script-path'] != ADAPTER_URL.replace('-v2.js', '.js')
                or p.get('type') != 'http-response' or p.get('requires-body') != 'false'
                or raw.count("argument='" + value + "'") != 1):
            raise Invalid('native adapter serialization target shape changed')
        encoded = 'uri:' + quote(value, safe='')
        return raw.replace("argument='" + value + "'", 'argument=' + encoded).replace(
            'script-path=' + p['script-path'], 'script-path=' + policy['adapter_url'])
    if kind == 'json-string-templates':
        arg = p.get('argument', '')
        keys = [key for key in ('logLevel', 'displayUpList') if '{{{' + key + '}}}' in arg]
        if not keys or not arg.startswith('{'):
            raise Invalid('JSON template serialization target shape changed')
        for key in keys:
            token = '{{{' + key + '}}}'
            if arg.count(token) != 1 or '\":' + token not in arg:
                raise Invalid('JSON string template target is already quoted or changed')
            raw = raw.replace(token, '"' + token + '"')
        return raw
    if kind == 'key-value-template':
        expected = '[{{{per_filter_video_thread}}}]'
        field = next((value for value in ('argument=' + expected, 'argument="' + expected + '"')
                      if raw.count(value) == 1), None)
        if p.get('argument') != expected or field is None:
            raise Invalid('key/value template serialization target shape changed')
        return raw.replace(field,
                           'argument=per_filter_video_thread={{{per_filter_video_thread}}}')
    raise Invalid('unknown serialization repair kind')


def repair_serialization(text, policy=None):
    """Change only exact entry IDs; missing, duplicated or changed anchors block."""
    if policy is None:
        return text, {'applied': [], 'runtime_verified': False}
    if (not isinstance(policy, dict) or set(policy) != {'schema_version', 'adapter_url', 'adapter_sha256', 'entries'}
            or policy['schema_version'] != 1 or policy['adapter_url'] != ADAPTER_URL
            or not isinstance(policy['adapter_sha256'], str)
            or not re.fullmatch(r'[0-9a-f]{64}', policy['adapter_sha256'])
            or not isinstance(policy['entries'], list) or not policy['entries']):
        raise Invalid('serialization policy requires exact reviewed schema and adapter binding')
    targets = {}
    for selection in policy['entries']:
        if (not isinstance(selection, dict) or set(selection) != {'entry_id', 'kind', 'reason', 'evidence'}
                or not isinstance(selection['entry_id'], str) or not re.fullmatch(r'[0-9a-f]{64}', selection['entry_id'])
                or selection['kind'] not in KINDS
                or any(not isinstance(selection[k], str) or not selection[k].strip()
                       or len(selection[k]) > 1000 or any(c in selection[k] for c in '\r\n') for k in ('reason', 'evidence'))
                or selection['entry_id'] in targets):
            raise Invalid('invalid or duplicate exact serialization repair selection')
        targets[selection['entry_id']] = selection
    original = parse_module(text.encode(), 'pre-serialization')
    lines = text.splitlines(); applied = []
    for entry in original.entries:
        selection = targets.get(entry.id)
        if selection is None: continue
        if any(item['entry_id'] == entry.id for item in applied):
            raise Invalid('serialization repair target is ambiguous')
        new = _repair(entry, selection['kind'], policy)
        if new == entry.raw or any(c in new for c in '\r\n'):
            raise Invalid('serialization repair must change exactly one active line')
        lines[entry.line - 1] = new
        applied.append({'entry_id': entry.id, 'result_entry_id': digest(entry.section + '\0' + new),
                        'section': entry.section, 'line': entry.line, 'kind': selection['kind'],
                        'reason': selection['reason'], 'evidence': selection['evidence']})
    if set(targets) != {item['entry_id'] for item in applied}:
        raise Invalid('serialization repair anchor missing or changed')
    result = '\n'.join(lines) + '\n'; final = parse_module(result.encode(), 'post-serialization')
    if len(original.entries) != len(final.entries) or original.metadata != final.metadata:
        raise Invalid('serialization repair changed entry count or metadata')
    replacements = {x['entry_id']: x['result_entry_id'] for x in applied}
    if [replacements.get(e.id, e.id) for e in original.entries] != [e.id for e in final.entries]:
        raise Invalid('serialization repair changed another entry or order')
    return result, {'applied': applied, 'adapter_url': policy['adapter_url'],
                    'adapter_sha256': policy['adapter_sha256'], 'runtime_verified': False,
                    'limitations': ['Exact format/parameter repairs only; device export and app behavior still require verification.']}
