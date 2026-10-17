"""Render bounded status metadata for Actions without printing remote content."""
import json
import os
from pathlib import Path
import re
import sys


def summarize(report):
    if report.get('schema_version') != 1 or report.get('status') not in {'unchanged','changed','blocked'} or not isinstance(report.get('sources'),list):
        raise ValueError('invalid update report')
    lines=['# fmz200 upstream check', '', 'Status: ' + report['status'], '',
           'This job is read-only. The published module and approved source lock are unchanged.', '']
    for source in report['sources']:
        identifier=source.get('id','')
        status=source.get('status')
        if not isinstance(identifier,str) or not re.fullmatch(r'[a-z0-9_-]{1,64}',identifier) or status not in {'unchanged','changed','error'}:
            raise ValueError('invalid source status')
        lines.append('- ' + identifier + ': ' + status)
        for key in ('expected_sha256','sha256'):
            value=source.get(key)
            if value is not None:
                if not isinstance(value,str) or not re.fullmatch(r'[a-f0-9]{64}',value):
                    raise ValueError('invalid digest')
                lines.append('  - ' + key + ': ' + value)
    if report['status'] != 'unchanged':
        lines.extend(['','Review the upstream change or fetch failure locally. Do not update the lock merely to make this job pass.'])
    lines.extend(['','This checks the module source, not whether each ad endpoint still matches. Remote script/resource behavior can change independently.'])
    return '\n'.join(lines)+'\n'


def main(argv=None):
    argv=sys.argv[1:] if argv is None else argv
    try:
        if len(argv)!=1:raise ValueError('report path required')
        text=summarize(json.loads(Path(argv[0]).read_text(encoding='utf-8')))
        code=0
    except (OSError,ValueError,TypeError,KeyError):
        text='# fmz200 upstream check\n\nNo valid update report was produced. The published module was not modified.\n'
        code=2
    target=os.environ.get('GITHUB_STEP_SUMMARY')
    if target:
        with open(target,'a',encoding='utf-8') as f:f.write(text)
    else:print(text,end='')
    return code

if __name__=='__main__':raise SystemExit(main())
