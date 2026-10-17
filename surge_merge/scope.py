"""Exact, source-bound supplemental scope filtering; never guess app/domain matches."""
import re
from .core import Invalid,digest,parse_module


def filter_native_scope(data, source, policy):
    if (not isinstance(policy,dict) or set(policy)!={'source_id','source_sha256','excluded_entries'}
            or policy['source_id']!=source or policy['source_sha256']!=digest(data)
            or not isinstance(policy['excluded_entries'],list)):
        raise Invalid('supplement scope policy requires exact source identity and hash')
    module=parse_module(data,source)
    by_line={e.line:e for e in module.entries}
    selected={}
    for decision in policy['excluded_entries']:
        if (not isinstance(decision,dict) or set(decision)!={'line','section','line_sha256','classification','reason'}
                or type(decision['line']) is not int or decision['line']<1
                or decision['section'] not in {'Rule','URL Rewrite','Header Rewrite','Body Rewrite','Map Local','Script'}
                or not isinstance(decision['line_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',decision['line_sha256'])
                or decision['classification']!='manual-scope-exclusion'
                or not isinstance(decision['reason'],str) or not decision['reason'].strip()
                or len(decision['reason'])>500 or any(c in decision['reason'] for c in '\r\n')):
            raise Invalid('supplement scope selection requires one exact reviewed active rule')
        target=by_line.get(decision['line'])
        if (target is None or target.section!=decision['section'] or digest(target.raw)!=decision['line_sha256']
                or decision['line'] in selected):
            raise Invalid('supplement scope selection is stale or duplicated')
        selected[decision['line']]=decision
    # Preserve every non-selected source byte, including original line endings.
    lines=data.decode('utf-8').splitlines(keepends=True)
    for number in selected:
        old=lines[number-1]
        ending='\r\n' if old.endswith('\r\n') else ('\n' if old.endswith('\n') else ('\r' if old.endswith('\r') else ''))
        lines[number-1]=f'# Scope: excluded exact reviewed upstream line {number}; see report.'+ending
    output=''.join(lines).encode()
    filtered=parse_module(output,source)
    expected=[(e.section,e.raw) for e in module.entries if e.line not in selected]
    actual=[(e.section,e.raw) for e in filtered.entries]
    if actual!=expected or filtered.metadata!=module.metadata:
        raise Invalid('supplement filter changed an unselected entry or metadata')
    report={'schema_version':1,'status':'scope_filtered_static_pass','source_id':source,'source_sha256':digest(data),
            'output_sha256':digest(output),'removed':[selected[n] for n in sorted(selected)],
            'remaining_entries_identical_in_order':True,'static_only':True}
    return output,report
