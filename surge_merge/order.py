"""Replay exact reviewed ordering only; never add/remove active definitions."""
from .core import Invalid, digest, host_list


def restore_reviewed_order(lines, policy, report):
    if policy is None:
        return lines
    if not isinstance(policy, dict) or set(policy) != {'schema_version', 'moves', 'hostname_order', 'section_order', 'reason'} or policy['schema_version'] != 1 or not isinstance(policy['reason'], str) or not policy['reason']:
        raise Invalid('invalid exact order restoration policy')
    out = list(lines)
    def records():
        sec = None
        result = []
        for i, line in enumerate(out):
            raw = line.strip()
            if raw.startswith('[') and raw.endswith(']'): sec = raw[1:-1]
            elif raw and not raw.startswith(('#', '//', ';')): result.append((sec, digest(raw), i, raw))
        return result
    used = set()
    if not isinstance(policy['moves'], list): raise Invalid('order moves must be a list')
    for move in policy['moves']:
        if not isinstance(move, dict) or set(move) != {'section', 'targets', 'before'} or move['section'] not in {'Rule', 'Map Local', 'Script'} or not isinstance(move['targets'], list) or not move['targets'] or len(set(move['targets'])) != len(move['targets']):
            raise Invalid('invalid exact order move')
        hashes = move['targets'] + [move['before']]
        if len(set(hashes)) != len(hashes) or any(not isinstance(h, str) or len(h) != 64 or any(c not in '0123456789abcdef' for c in h) for h in hashes):
            raise Invalid('invalid order identity')
        targets = []
        for h in hashes:
            rows = [r for r in records() if r[0] == move['section'] and r[1] == h]
            if len(rows) != 1: raise Invalid('order target missing changed or ambiguous')
            targets.append(rows[0])
        if any((move['section'], h) in used for h in move['targets']): raise Invalid('duplicate order selection')
        used.update((move['section'], h) for h in move['targets'])
        removed = {r[2] for r in targets[:-1]}
        out = [l for i,l in enumerate(out) if i not in removed]
        anchor = [r for r in records() if r[0] == move['section'] and r[1] == move['before']]
        pos = anchor[0][2]
        out[pos:pos] = [r[3] for r in targets[:-1]]
        report['changes'].append({'kind': 'reviewed-order-restoration', **move})
    host = policy['hostname_order']
    if not isinstance(host, dict) or set(host) != {'input_sha256', 'raw'} or not isinstance(host['raw'], str) or '\n' in host['raw'] or '\r' in host['raw']:
        raise Invalid('invalid hostname order restoration')
    candidates = [r for r in records() if r[0] == 'MITM' and r[1] == host['input_sha256']]
    if len(candidates) != 1: raise Invalid('hostname order target changed or ambiguous')
    row = candidates[0]
    old_key, _, old_value = row[3].partition('=')
    new_key, sep, new_value = host['raw'].partition('=')
    mode, hosts = host_list(old_value.strip()); new_mode, new_hosts = host_list(new_value.strip())
    if not sep or old_key.strip() != 'hostname' or new_key.strip() != 'hostname' or mode != new_mode or len(hosts) != len(set(hosts)) or len(new_hosts) != len(set(new_hosts)) or set(hosts) != set(new_hosts):
        raise Invalid('hostname restoration must only permute identical unique hosts')
    out[row[2]] = host['raw']
    # Restore the same section order without dropping comments or definitions.
    order = policy['section_order']
    if not isinstance(order, list) or len(order) != len(set(order)) or set(order) != {'Rule', 'URL Rewrite', 'Header Rewrite', 'Body Rewrite', 'Map Local', 'Script', 'MITM', 'General'}:
        raise Invalid('invalid restored section order')
    prefix, blocks, current = [], {}, None
    for line in out:
        raw = line.strip()
        if raw.startswith('[') and raw.endswith(']'):
            current = raw[1:-1]
            if current in blocks: raise Invalid('duplicate section cannot be reordered')
            blocks[current] = []
        if current is None: prefix.append(line)
        else: blocks[current].append(line)
    if set(blocks) != set(order): raise Invalid('restored section set changed')
    return prefix + [line for section in order for line in blocks[section]]
