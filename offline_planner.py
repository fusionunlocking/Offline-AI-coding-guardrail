"""Offline-only fail-closed NEXUS-style dependency and acceptance planner.

No network, subprocess, Git mutation, model invocation or production controls.
This module intentionally reports eligibility, never dispatches work.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

class PlanError(ValueError):
    pass

NODES = tuple(f'N{i}' for i in range(17))
STATES = frozenset({'OPEN', 'BLOCKED', 'CANDIDATE', 'REJECTED', 'CLOSED'})


def _sha(s: Any) -> bool:
    return isinstance(s, str) and len(s) == 40 and all(c in '0123456789abcdef' for c in s)


def validate(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict) or set(doc) != {'schema', 'nodes'} or doc['schema'] != 1:
        raise PlanError('Expected schema 1 with nodes only')
    rows = doc['nodes']
    if not isinstance(rows, dict) or set(rows) != set(NODES):
        raise PlanError('Exactly N0-N16 required; no missing or extra nodes')
    for node in NODES:
        r = rows[node]
        required = {'state', 'parents', 'owner_gate', 'owner_authorised', 'acceptance_required',
                    'acceptance_verdict', 'commit', 'tree', 'quarantined', 'reason'}
        if not isinstance(r, dict) or set(r) != required:
            raise PlanError(f'{node}: invalid fields')
        if r['state'] not in STATES or not isinstance(r['parents'], list):
            raise PlanError(f'{node}: invalid state/parents')
        if len(r['parents']) != len(set(r['parents'])) or any(p not in NODES or p == node for p in r['parents']):
            raise PlanError(f'{node}: invalid parent')
        if any(type(r[k]) is not bool for k in ('owner_gate','owner_authorised','acceptance_required','quarantined')):
            raise PlanError(f'{node}: invalid boolean')
        if r['acceptance_verdict'] not in ('NONE', 'APPROVED', 'REJECTED'):
            raise PlanError(f'{node}: invalid verdict')
        if r['commit'] is not None and not _sha(r['commit']):
            raise PlanError(f'{node}: invalid commit')
        if r['tree'] is not None and not _sha(r['tree']):
            raise PlanError(f'{node}: invalid tree')
        if not isinstance(r['reason'], str) or len(r['reason']) > 1000:
            raise PlanError(f'{node}: invalid reason')
        if r['state'] == 'CLOSED':
            if not (r['commit'] and r['tree']):
                raise PlanError(f'{node}: closed without pinned identity')
            if r['acceptance_required'] and r['acceptance_verdict'] != 'APPROVED':
                raise PlanError(f'{node}: closed without required independent acceptance')
            if r['owner_gate'] and not r['owner_authorised']:
                raise PlanError(f'{node}: closed without owner approval')
        if r['state'] == 'REJECTED' and r['acceptance_verdict'] != 'REJECTED':
            raise PlanError(f'{node}: rejected state requires rejected verdict')
    visiting, visited = set(), set()
    def visit(n: str) -> None:
        if n in visiting:
            raise PlanError('Cycle detected')
        if n in visited:
            return
        visiting.add(n)
        for p in rows[n]['parents']:
            visit(p)
        visiting.remove(n)
        visited.add(n)
    for n in NODES:
        visit(n)
    return doc


def compute(doc: dict[str, Any]) -> dict[str, Any]:
    validate(doc)
    rows = doc['nodes']
    result = {}
    for n in NODES:
        r = rows[n]
        blockers = []
        if r['state'] == 'CLOSED':
            blockers.append('ALREADY_CLOSED')
        if r['state'] == 'REJECTED' or r['acceptance_verdict'] == 'REJECTED':
            blockers.append('REJECTED_CANDIDATE')
        if r['state'] == 'BLOCKED':
            blockers.append('BLOCKED_BY_RECORD')
        if r['quarantined']:
            blockers.append('QUARANTINE_ACTIVE')
        if r['owner_gate'] and not r['owner_authorised']:
            blockers.append('OWNER_APPROVAL_MISSING')
        for p in r['parents']:
            if rows[p]['state'] != 'CLOSED':
                blockers.append(f'PARENT_NOT_CLOSED:{p}')
        if not r['owner_authorised']:
            blockers.append('WORK_AUTHORIZATION_MISSING')
        # Candidate states are awaiting review, not new maker dispatch.
        if r['state'] == 'CANDIDATE':
            blockers.append('CANDIDATE_AWAITING_DISPOSITION')
        result[n] = {'state': r['state'], 'parents': r['parents'],
                     'eligible_for_controller_consideration': not blockers,
                     'blockers': blockers}
    canonical = json.dumps(doc, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return {'schema':1, 'snapshot_sha256':hashlib.sha256(canonical).hexdigest(),
            'closed_count':sum(r['state']=='CLOSED' for r in rows.values()),
            'nodes':result, 'disclaimer':'Planning only. Never authorizes or launches engineering.'}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description='Offline fail-closed N0-N16 planning only')
    ap.add_argument('snapshot', type=Path)
    ap.add_argument('--output', type=Path, help='Optional new file; refuses overwrite')
    args = ap.parse_args(argv)
    try:
        data = json.loads(args.snapshot.read_text(encoding='utf-8-sig'))
        result = compute(data)
        content = json.dumps(result, indent=2, sort_keys=True) + '\n'
        if args.output:
            with args.output.open('x', encoding='utf-8') as f:
                f.write(content)
        else:
            print(content, end='')
    except (OSError, ValueError, TypeError) as e:
        ap.exit(2, f'STOP: {e}\n')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
