"""Offline NEXUS guardrail prototype. NO Claude/Codex/API, Git writes, or test execution.

Not an approved NEXUS controller. Hash chaining detects accidental edits/corruption,
but is NOT an immutable or tamper-proof audit store.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

SCHEMA = 1
ZERO_HASH = '0' * 64
NODE_RE = re.compile(r'N(?:[0-9]|1[0-6])\Z')
SHA_RE = re.compile(r'[0-9a-f]{40}\Z')
HASH_RE = re.compile(r'[0-9a-f]{64}\Z')
EVENT_TYPES = frozenset({'ATTEMPT_PROPOSED', 'ATTEMPT_RESULT', 'LANE_BLOCKED', 'GATE', 'RESOURCE_STOP'})
OUTCOMES = frozenset({'PROPOSED', 'FAILED', 'PASS_INTERNAL', 'PASS_INDEPENDENT', 'BLOCKED', 'NOT_RUN', 'RESOURCE_STOP'})
TEST_STATUSES = frozenset({'PASS', 'FAIL', 'NOT_RUN_QUARANTINED', 'NOT_RUN_OTHER', 'NOT_APPLICABLE'})

class GuardError(Exception):
    pass

class LedgerIntegrityError(GuardError):
    pass

class AttemptBlocked(GuardError):
    pass


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('utf-8')


def digest(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def signature(category: str, test_id: str, error_code: str) -> str:
    """Deterministic stable failure identity; no secret-bearing traceback stored."""
    if not all(isinstance(v, str) and 0 < len(v) <= 180 for v in (category, test_id, error_code)):
        raise GuardError('Invalid signature components')
    return digest({'category': category.strip(), 'test_id': test_id.strip(), 'error_code': error_code.strip()})


def validate_event(payload: Mapping[str, Any]) -> None:
    required = {'event_type', 'node_id', 'source_sha', 'error_signature', 'hypothesis_hash',
                'patch_hash', 'evidence_delta_hash', 'outcome', 'test_status', 'evidence_ref'}
    if set(payload) != required:
        raise GuardError('Event fields must match schema exactly')
    if payload['event_type'] not in EVENT_TYPES or payload['outcome'] not in OUTCOMES:
        raise GuardError('Unknown event type / outcome')
    if payload['test_status'] not in TEST_STATUSES:
        raise GuardError('Unknown test status')
    if not isinstance(payload['node_id'], str) or not NODE_RE.fullmatch(payload['node_id']):
        raise GuardError('Invalid NEXUS node')
    if not isinstance(payload['source_sha'], str) or not SHA_RE.fullmatch(payload['source_sha']):
        raise GuardError('A full 40-hex committed source SHA is required')
    for field in ('error_signature', 'hypothesis_hash', 'patch_hash', 'evidence_delta_hash'):
        value = payload[field]
        if value is not None and (not isinstance(value, str) or not HASH_RE.fullmatch(value)):
            raise GuardError(f'Invalid {field}')
    ref = payload['evidence_ref']
    if ref is not None and (not isinstance(ref, str) or not (1 <= len(ref) <= 256) or '\n' in ref):
        raise GuardError('Invalid evidence reference')
    if payload['outcome'] == 'PASS_INDEPENDENT':
        if payload['test_status'] != 'PASS' or not payload['evidence_ref']:
            raise GuardError('Independent PASS requires PASS test status and a reviewer evidence reference')
    if payload['event_type'] in {'ATTEMPT_PROPOSED', 'ATTEMPT_RESULT'}:
        if not payload['error_signature'] or not payload['hypothesis_hash'] or not payload['patch_hash']:
            raise GuardError('Attempt must identify error, hypothesis and patch')


def event(*, event_type: str, node_id: str, source_sha: str, outcome: str,
          error_signature: str | None = None, hypothesis_hash: str | None = None,
          patch_hash: str | None = None, evidence_delta_hash: str | None = None,
          test_status: str = 'NOT_APPLICABLE', evidence_ref: str | None = None) -> dict[str, Any]:
    payload = dict(event_type=event_type, node_id=node_id, source_sha=source_sha,
                   error_signature=error_signature, hypothesis_hash=hypothesis_hash,
                   patch_hash=patch_hash, evidence_delta_hash=evidence_delta_hash,
                   outcome=outcome, test_status=test_status, evidence_ref=evidence_ref)
    validate_event(payload)
    return payload


class Ledger:
    """Single-writer hash-chained append-only JSONL. Refuses corruption or lock contention."""
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            raw = self.path.read_bytes()
            if raw and not raw.endswith(b'\n'):
                raise LedgerIntegrityError('Incomplete trailing record; manual forensic recovery required')
            result: list[dict[str, Any]] = []
            prev = ZERO_HASH
            for i, line in enumerate(raw.splitlines(), start=1):
                row = json.loads(line.decode('utf-8'))
                if not isinstance(row, dict) or set(row) != {'schema', 'seq', 'prev_hash', 'event_hash', 'payload'}:
                    raise LedgerIntegrityError(f'Bad record shape at line {i}')
                if row['schema'] != SCHEMA or row['seq'] != i or row['prev_hash'] != prev:
                    raise LedgerIntegrityError(f'Broken chain at line {i}')
                validate_event(row['payload'])
                calc = digest({k: v for k, v in row.items() if k != 'event_hash'})
                if row['event_hash'] != calc:
                    raise LedgerIntegrityError(f'Invalid event digest at line {i}')
                result.append(row)
                prev = row['event_hash']
            return result
        except (OSError, ValueError, TypeError, UnicodeError, KeyError, GuardError) as ex:
            raise LedgerIntegrityError(f'Ledger integrity check failed: {type(ex).__name__}: {ex}') from ex

    def append(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        validate_event(payload)
        # O_EXCL lock is intentionally not auto-stale-recovered: stop on ambiguity.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock = Path(str(self.path) + '.lock')
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as ex:
            raise LedgerIntegrityError('Ledger writer lock exists; do not remove automatically') from ex
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(b'guardrail_single_writer\n')
                f.flush()
                os.fsync(f.fileno())
            rows = self.read()
            prev = rows[-1]['event_hash'] if rows else ZERO_HASH
            row = {'schema': SCHEMA, 'seq': len(rows) + 1, 'prev_hash': prev, 'payload': dict(payload)}
            row['event_hash'] = digest(row)
            with self.path.open('ab') as f:
                f.write(canonical(row) + b'\n')
                f.flush()
                os.fsync(f.fileno())
            return row
        finally:
            lock.unlink(missing_ok=True)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def assess_attempt(rows: list[dict[str, Any]], proposal: Mapping[str, Any], *,
                   max_failed_same_signature: int = 2, max_attempts_per_node: int = 5) -> Decision:
    """Check before ANY paid model call. A proposal is then journaled before launch."""
    validate_event(proposal)
    if proposal['event_type'] != 'ATTEMPT_PROPOSED' or proposal['outcome'] != 'PROPOSED':
        return Decision(False, 'A complete ATTEMPT_PROPOSED record is required')
    p = proposal
    if any(r['payload']['event_type'] == 'RESOURCE_STOP' for r in rows):
        return Decision(False, 'Resource/budget stop is binding across all lanes; external reauthorisation required')
    mine = [r['payload'] for r in rows if r['payload']['node_id'] == p['node_id']]
    if any(x['event_type'] == 'LANE_BLOCKED' for x in mine):
        return Decision(False, 'Lane has an unresolved stop; external ruling required')
    attempts = [x for x in mine if x['event_type'] == 'ATTEMPT_PROPOSED']
    if len(attempts) >= max_attempts_per_node:
        return Decision(False, 'Per-node attempt ceiling reached')
    relevant = [x for x in mine if x['event_type'] in {'ATTEMPT_PROPOSED', 'ATTEMPT_RESULT'}
                and x['source_sha'] == p['source_sha'] and x['error_signature'] == p['error_signature']]
    if any(x['hypothesis_hash'] == p['hypothesis_hash'] for x in relevant):
        return Decision(False, 'Repeated hypothesis on same source/failure')
    if any(x['patch_hash'] == p['patch_hash'] for x in mine
           if x['event_type'] in {'ATTEMPT_PROPOSED', 'ATTEMPT_RESULT'} and x['source_sha'] == p['source_sha']):
        return Decision(False, 'Repeated proposed patch on same source')
    if relevant:
        if p['evidence_delta_hash'] is None:
            return Decision(False, 'Same source and failure requires new independently identified evidence')
        if any(x['evidence_delta_hash'] == p['evidence_delta_hash'] for x in relevant):
            return Decision(False, 'Evidence delta already attempted')
    failed = [x for x in relevant if x['event_type'] == 'ATTEMPT_RESULT' and x['outcome'] == 'FAILED']
    if len(failed) >= max_failed_same_signature:
        return Decision(False, 'Failure-signature retry ceiling reached')
    unresolved = [x for x in relevant if x['event_type'] == 'ATTEMPT_PROPOSED'
                  and not any(y['event_type'] == 'ATTEMPT_RESULT' and
                              y['hypothesis_hash'] == x['hypothesis_hash'] and
                              y['patch_hash'] == x['patch_hash'] and
                              y['source_sha'] == x['source_sha'] and
                              y['error_signature'] == x['error_signature'] for y in mine)]
    if unresolved:
        return Decision(False, 'Previous attempt has no result; do not assume it failed or relaunch')
    return Decision(True, 'Distinct attempt permitted by the no-repeat guard ONLY; authorisation/gates separately required')


@dataclass(frozen=True)
class Lane:
    node_id: str
    priority: int
    dependencies: tuple[str, ...]
    authorised: bool
    owner_gate_open: bool
    acceptance_gate_open: bool
    status: str


def select_lane(lanes: list[Lane], *, blocked: set[str] | None = None) -> tuple[str | None, dict[str, str]]:
    """Fail-closed: no inferred authorisation. Depends on independently CLOSED deps."""
    blocked = blocked or set()
    ids = {x.node_id for x in lanes}
    if len(ids) != len(lanes) or any(not NODE_RE.fullmatch(x.node_id) for x in lanes):
        raise GuardError('Invalid/duplicate graph nodes')
    if any(dep not in ids or dep == x.node_id for x in lanes for dep in x.dependencies):
        raise GuardError('Unknown/self dependency; graph verification failed')
    # Detect cycles across the entire graph, including disabled nodes.
    seen: set[str] = set()
    visiting: set[str] = set()
    mapping = {x.node_id: x for x in lanes}
    def visit(n: str) -> None:
        if n in visiting:
            raise GuardError('Dependency cycle detected')
        if n in seen:
            return
        visiting.add(n)
        for d in mapping[n].dependencies:
            visit(d)
        visiting.remove(n)
        seen.add(n)
    for n in ids:
        visit(n)
    reasons: dict[str, str] = {}
    for x in lanes:
        if x.status == 'CLOSED':
            reasons[x.node_id] = 'Already independently closed'
        elif x.node_id in blocked or x.status in {'REJECTED', 'OWNER_WAIT', 'BLOCKED'}:
            reasons[x.node_id] = 'Blocked or awaiting an explicit ruling'
        elif not x.authorised:
            reasons[x.node_id] = 'No verified scope-specific authorisation'
        elif not x.owner_gate_open:
            reasons[x.node_id] = 'Owner gate not open'
        elif not x.acceptance_gate_open:
            reasons[x.node_id] = 'Dependency acceptance gate not open'
        elif any(mapping[d].status != 'CLOSED' for d in x.dependencies):
            reasons[x.node_id] = 'Dependency not independently closed'
        else:
            reasons[x.node_id] = 'ELIGIBLE for scoped work; no API launch implied'
    eligible = [x for x in lanes if reasons[x.node_id].startswith('ELIGIBLE')]
    eligible.sort(key=lambda x: (x.priority, x.node_id))
    return (eligible[0].node_id if eligible else None), reasons


def economic_metrics(usd: float, independently_closed_delta: int, turns: int) -> dict[str, Any]:
    if usd < 0 or turns < 0 or independently_closed_delta < 0:
        raise GuardError('Negative telemetry')
    return {'spent_usd': round(usd, 6), 'turns': turns,
            'independently_closed_delta': independently_closed_delta,
            'usd_per_independently_closed_node': (round(usd / independently_closed_delta, 6)
                                                    if independently_closed_delta else None),
            'zero_verified_progress': independently_closed_delta == 0}
