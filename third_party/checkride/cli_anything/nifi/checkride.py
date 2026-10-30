"""Copyright 2026 FlightDeckAI. Licensed under Apache-2.0.

Read-only analysis of NiFi VersionedFlowSnapshot exports. No network or model.
"""
import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

KINDS = ('processors', 'connections', 'inputPorts', 'outputPorts', 'funnels',
         'controllerServices', 'remoteProcessGroups', 'labels')
COSMETIC = {'position', 'bends', 'labelIndex', 'zIndex', 'instanceIdentifier'}
ZERO = re.compile(r'^0+(?:\.0+)?(?:\s*(?:b|kb|mb|gb|tb|byte[s]?))?$', re.I)


def load(path):
    raw = Path(path).read_bytes()
    if len(raw) > 20 * 1024 * 1024:
        raise ValueError('Export exceeds the 20 MiB limit')
    doc = json.loads(raw)
    if not isinstance(doc, dict) or not isinstance(doc.get('flowContents'), dict):
        raise ValueError('Expected a VersionedFlowSnapshot with flowContents; XML and live API DTOs are unsupported')
    root = doc['flowContents']
    if not isinstance(root.get('identifier'), str) or not root['identifier']:
        raise ValueError('flowContents must have an identifier')
    items = {}

    def add(item, kind):
        if not isinstance(item, dict) or not isinstance(item.get('identifier'), str) or not item['identifier']:
            raise ValueError('Every component must have a nonempty identifier')
        key = item['identifier']
        if key in items:
            raise ValueError('Duplicate component identifier')
        items[key] = (kind, item)

    def visit(group):
        add(group, 'processGroups')
        for kind in KINDS + ('processGroups',):
            entries = group.get(kind, [])
            if not isinstance(entries, list):
                raise ValueError('Component collections must be arrays')
            for item in entries:
                if kind == 'processGroups':
                    visit(item)
                else:
                    add(item, kind)
                    if kind == 'remoteProcessGroups':
                        for port_kind in ('inputPorts', 'outputPorts'):
                            ports = item.get(port_kind, [])
                            if not isinstance(ports, list):
                                raise ValueError('Remote ports must be arrays')
                            for port in ports:
                                add(port, 'remote' + port_kind[0].upper() + port_kind[1:])
    visit(root)
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'items': items, 'document': doc}


def inspect(flow):
    return {'schemaVersion': '1.0', 'operation': 'inspect', 'inputSha256': flow['sha256'],
            'counts': dict(sorted(Counter(k for k, _ in flow['items'].values()).items())),
            'components': [{'id': key, 'kind': kind} for key, (kind, _) in sorted(flow['items'].items())],
            'scope': 'Offline configuration only; no runtime or model evaluation'}


def check(flow):
    findings = []
    def flag(key, rule, severity, message):
        findings.append({'componentId': key, 'rule': rule, 'severity': severity, 'message': message})
    for key, (kind, item) in sorted(flow['items'].items()):
        if kind == 'connections':
            for side in ('source', 'destination'):
                endpoint = item.get(side)
                if not isinstance(endpoint, dict) or endpoint.get('id') not in flow['items']:
                    flag(key, 'unresolved-' + side, 'error', 'Connection endpoint is missing from this export; inspect export completeness')
            count = item.get('backPressureObjectThreshold')
            size = item.get('backPressureDataSizeThreshold')
            if count == 0 and isinstance(size, str) and ZERO.fullmatch(size.strip()):
                flag(key, 'unbounded-queue', 'warning', 'Both explicit backpressure limits are zero; review queue growth risk')
        if kind == 'processors':
            relationships = item.get('autoTerminatedRelationships', [])
            if not isinstance(relationships, list):
                raise ValueError('autoTerminatedRelationships must be an array')
            if any(isinstance(r, str) and r.lower() in ('failure', 'retry') for r in relationships):
                flag(key, 'discarded-failure-path', 'warning', 'Failure or retry is auto-terminated; confirm intentional discard policy')
        if kind in ('processors', 'controllerServices'):
            props = item.get('properties', {})
            if not isinstance(props, dict):
                raise ValueError('properties must be an object')
            # Values are examined locally but never included in output.
            if any(isinstance(v, str) and v.lower().startswith('http://') for v in props.values()):
                flag(key, 'plaintext-http', 'warning', 'A property begins with http://; confirm transport requirements')
    return {'schemaVersion': '1.0', 'operation': 'check', 'inputSha256': flow['sha256'],
            'status': 'review' if findings else 'no-findings', 'findings': findings,
            'scope': 'Heuristic review only; no-findings is not deployment approval'}


def normalize(value):
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items() if k not in COSMETIC}
    if isinstance(value, list):
        values = [normalize(v) for v in value]
        return sorted(values, key=lambda v: v['identifier']) if values and all(isinstance(v, dict) and isinstance(v.get('identifier'), str) for v in values) else values
    return value


def diff(before, after):
    a, b = before['items'], after['items']
    changed = []
    for key in sorted(a.keys() & b.keys()):
        ka, va = a[key]
        kb, vb = b[key]
        # Child component changes are reported once under the child's ID.
        excluded = COSMETIC | (set(KINDS) | {'processGroups'} if ka == kb == 'processGroups' else set())
        fields = [k for k in sorted((va.keys() | vb.keys()) - excluded)
                  if (k in va) != (k in vb) or normalize(va.get(k)) != normalize(vb.get(k))]
        if ka != kb:
            fields.append('componentKind')
        if fields:
            changed.append({'componentId': key, 'fields': fields})
    # Surface non-component changes (e.g. parameter contexts) without their values.
    da, db = before['document'], after['document']
    metadata = [k for k in sorted((da.keys() | db.keys()) - {'flowContents'})
                if (k in da) != (k in db) or normalize(da.get(k)) != normalize(db.get(k))]
    return {'schemaVersion': '1.0', 'operation': 'diff', 'beforeSha256': before['sha256'],
            'afterSha256': after['sha256'], 'added': sorted(b.keys() - a.keys()),
            'removed': sorted(a.keys() - b.keys()), 'changed': changed,
            'snapshotFieldsChanged': metadata,
            'scope': 'Values omitted; layout and collection ordering ignored; review in NiFi before deployment'}


def main(argv=None):
    parser = argparse.ArgumentParser(description='NiFi Flow Checkride: offline, read-only, JSON output')
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('inspect', 'check'):
        p = sub.add_parser(command)
        p.add_argument('export')
        if command == 'check':
            p.add_argument('--fail-on', choices=('error', 'warning'), default='error')
    p = sub.add_parser('diff')
    p.add_argument('before')
    p.add_argument('after')
    args = parser.parse_args(argv)
    try:
        if args.command == 'diff':
            result = diff(load(args.before), load(args.after))
        else:
            result = (inspect if args.command == 'inspect' else check)(load(args.export))
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        # Do not echo untrusted JSON excerpts, file contents, or OS paths.
        print(json.dumps({'error': 'Invalid or unreadable export', 'type': type(exc).__name__}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.command == 'check':
        return int(any(f['severity'] == 'error' or args.fail_on == 'warning' for f in result['findings']))
    return 0

