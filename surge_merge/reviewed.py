"""Exact post-assembly repairs, with fail-closed anchors and coverage witnesses.

Decisions are reviewed policy, never inferred from mutable upstream text.
"""
from .core import Invalid, digest, parse_module, host_list, params


def apply_reviewed(text, policy=None):
    if policy is None:
        return text, {'applied': [], 'added_hosts': [], 'static_only': True}
    if not isinstance(policy, dict) or set(policy) != {'schema_version', 'entries', 'mitm'} or policy['schema_version'] != 1:
        raise Invalid('invalid reviewed repair schema')
    original = parse_module(text.encode(), 'reviewed-input')
    by_id = {}
    for e in original.entries:
        by_id.setdefault(e.id, []).append(e)
    lines = text.splitlines(); used = set(); applied = []
    for item in policy['entries']:
        if not isinstance(item, dict) or set(item) != {'entry_id','replacement','reason','evidence','witnesses','kind'}:
            raise Invalid('invalid reviewed repair entry')
        key = item['entry_id']
        if key in used or len(by_id.get(key, [])) != 1:
            raise Invalid('reviewed repair anchor missing changed or ambiguous')
        e = by_id[key][0]; used.add(key)
        if e.section not in {'Rule','Script','URL Rewrite','Map Local','Body Rewrite','Header Rewrite'}:
            raise Invalid('reviewed repair cannot alter security settings')
        for field in ('reason','evidence'):
            if not isinstance(item[field], str) or not item[field].strip() or '\n' in item[field]:
                raise Invalid('reviewed repair needs single-line evidence')
        witnesses = item['witnesses']
        if not isinstance(witnesses,list) or len(witnesses) != len(set(witnesses)):
            raise Invalid('invalid repair witnesses')
        for w in witnesses:
            if len(by_id.get(w, [])) != 1 or w == key:
                raise Invalid('reviewed witness missing changed or ambiguous')
        replacement = item['replacement']
        if replacement is not None:
            if not isinstance(replacement,str) or not replacement or any(x in replacement for x in '\r\n') or replacement == e.raw:
                raise Invalid('repair replacement must change one active line')
            parsed = parse_module(('['+e.section+']\n'+replacement+'\n').encode(), 'replacement')
            if len(parsed.entries) != 1 or parsed.entries[0].section != e.section or parsed.entries[0].raw != replacement:
                raise Invalid('repair replacement must remain in its section')
        if item['kind'] == 'covered-domain':
            if replacement is not None or e.section != 'Rule' or len(witnesses) != 1:
                raise Invalid('domain redundancy must have one covering witness')
            cover = by_id[witnesses[0]][0]
            parts = [x.strip() for x in e.raw.split(',')]
            cp = [x.strip() for x in cover.raw.split(',')]
            if (cover.section != 'Rule' or cover.line >= e.line or len(parts) != 3 or len(cp) != 3
                or parts[0] not in {'DOMAIN','DOMAIN-SUFFIX'} or cp[0] != 'DOMAIN-SUFFIX'
                or parts[2] != cp[2] or parts[2] != 'REJECT'
                or not (parts[1] == cp[1] or parts[1].endswith('.'+cp[1]))):
                raise Invalid('domain coverage proof does not hold')
        elif item['kind'] not in {'exact-fix','shadowed','disjoint-pattern'}:
            raise Invalid('unrecognized reviewed repair kind')
        lines[e.line-1] = replacement or ''
        applied.append({'entry_id':key,'result_entry_id':digest(e.section+'\0'+replacement) if replacement else None,
                        'kind':item['kind'],'reason':item['reason'],'evidence':item['evidence'],'witnesses':witnesses})
    # Witnesses must survive unchanged. The sole non-semantic witness edit is
    # enabling the required binary representation for the same script/pattern.
    replacements = {i['entry_id']: i['replacement'] for i in policy['entries']}
    for item in policy['entries']:
        for witness in item['witnesses']:
            if witness not in replacements:
                continue
            w = by_id[witness][0]; changed = replacements[witness]
            if w.section != 'Script' or changed is None or item['kind'] == 'covered-domain':
                raise Invalid('reviewed witness must retain its matching behavior')
            before = params(w.raw.partition('=')[2]); after = params(changed.partition('=')[2])
            if after.pop('binary-body-mode', None) != 'true' or 'binary-body-mode' in before or before != after:
                raise Invalid('reviewed witness must retain its matching behavior')
    # Never let a removal depend on a witness that was itself removed.
    deleted = {i['entry_id'] for i in policy['entries'] if i['replacement'] is None}
    if any(w in deleted for i in policy['entries'] for w in i['witnesses']):
        raise Invalid('reviewed witness must remain active')
    mitm = policy['mitm']; added = []
    if mitm is not None:
        if not isinstance(mitm,dict) or set(mitm) != {'entry_id','add_hosts','reason'}:
            raise Invalid('invalid exact MITM addition')
        match = by_id.get(mitm['entry_id'],[])
        if len(match) != 1 or match[0].section != 'MITM':
            raise Invalid('MITM anchor missing changed or ambiguous')
        e=match[0]; _, existing=host_list(e.raw.partition('=')[2].strip())
        import re
        added=mitm['add_hosts']
        if (not isinstance(added,list) or not added or len(added)!=len(set(added))
            or any(not isinstance(h,str) or not re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*\.[a-z]{2,}',h) or h in existing for h in added)
            or not isinstance(mitm['reason'],str) or not mitm['reason'].strip()):
            raise Invalid('MITM additions must be exact new hostnames')
        lines[e.line-1] = e.raw+', '+', '.join(added)
    result='\n'.join(lines)+'\n'; final=parse_module(result.encode(),'reviewed-output')
    expected=[]
    changes={i['entry_id']:i['replacement'] for i in policy['entries']}
    for e in original.entries:
        if e.id in changes:
            if changes[e.id] is not None: expected.append((e.section,changes[e.id]))
        elif mitm and e.id==mitm['entry_id']: expected.append((e.section,e.raw+', '+', '.join(added)))
        else: expected.append((e.section,e.raw))
    if expected != [(e.section,e.raw) for e in final.entries] or original.metadata != final.metadata:
        raise Invalid('reviewed repairs changed unrelated entries/order/metadata')
    return result, {'applied':applied,'added_hosts':added,'static_only':True}
