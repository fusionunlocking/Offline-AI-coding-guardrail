import json
import tempfile
import unittest
from pathlib import Path

from guardrail import (AttemptBlocked, GuardError, Ledger, LedgerIntegrityError, Lane,
                       assess_attempt, digest, economic_metrics, event, select_lane, signature)

SHA = '75b7127a51cacf563ebc6b6e16040aa44a3b1035'
SIG = signature('pytest', 'test_control_case', 'ASSERTION_REFUSAL')
H1, H2, H3 = (digest({'hypothesis': i}) for i in range(3))
P1, P2, P3 = (digest({'diff': i}) for i in range(3))
E1, E2, E3 = (digest({'evidence': i}) for i in range(3))


def proposal(h=H1, p=P1, e=None):
    return event(event_type='ATTEMPT_PROPOSED', node_id='N4', source_sha=SHA,
                 error_signature=SIG, hypothesis_hash=h, patch_hash=p,
                 evidence_delta_hash=e, outcome='PROPOSED')


def failed(h=H1, p=P1, e=None):
    return event(event_type='ATTEMPT_RESULT', node_id='N4', source_sha=SHA,
                 error_signature=SIG, hypothesis_hash=h, patch_hash=p,
                 evidence_delta_hash=e, outcome='FAILED', test_status='FAIL')


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'failures.jsonl'
        self.ledger = Ledger(self.path)

    def test_append_and_verify(self):
        first = self.ledger.append(proposal())
        second = self.ledger.append(failed())
        self.assertEqual(first['seq'], 1)
        self.assertEqual(second['prev_hash'], first['event_hash'])
        self.assertEqual(len(self.ledger.read()), 2)

    def test_modified_record_fails_closed(self):
        self.ledger.append(proposal())
        raw = self.path.read_text()
        self.path.write_text(raw.replace('N4', 'N5'), encoding='utf-8')
        with self.assertRaises(LedgerIntegrityError):
            self.ledger.read()

    def test_truncated_record_fails_closed(self):
        self.ledger.append(proposal())
        self.path.write_bytes(self.path.read_bytes()[:-1])
        with self.assertRaises(LedgerIntegrityError):
            self.ledger.read()

    def test_lock_contention_no_override(self):
        Path(str(self.path) + '.lock').write_text('another writer')
        with self.assertRaises(LedgerIntegrityError):
            self.ledger.append(proposal())
        self.assertFalse(self.path.exists())

    def test_fake_independent_acceptance_without_receipt_rejected(self):
        with self.assertRaises(GuardError):
            event(event_type='GATE', node_id='N2', source_sha=SHA,
                  outcome='PASS_INDEPENDENT', test_status='PASS')

    def test_mock_independent_receipt_needs_pass(self):
        row = event(event_type='GATE', node_id='N2', source_sha=SHA,
                    outcome='PASS_INDEPENDENT', test_status='PASS',
                    evidence_ref='receipt_sha256:example')
        self.assertEqual(row['outcome'], 'PASS_INDEPENDENT')

    def test_bad_sha_rejected(self):
        with self.assertRaises(GuardError):
            event(event_type='GATE', node_id='N2', source_sha='abcd', outcome='NOT_RUN')

    def test_quarantined_not_independent_pass(self):
        with self.assertRaises(GuardError):
            event(event_type='GATE', node_id='N2', source_sha=SHA,
                  outcome='PASS_INDEPENDENT', test_status='NOT_RUN_QUARANTINED')


class DuplicateGuardTests(unittest.TestCase):
    def test_initial_distinct_attempt_allowed(self):
        self.assertTrue(assess_attempt([], proposal()).allowed)

    def test_exact_proposal_repeated_blocked(self):
        rows = [{'payload': proposal()}]
        self.assertFalse(assess_attempt(rows, proposal()).allowed)

    def test_same_patch_with_new_hypothesis_blocked(self):
        rows = [{'payload': proposal()}, {'payload': failed()}]
        self.assertIn('patch', assess_attempt(rows, proposal(H2, P1, E1)).reason)

    def test_same_source_failure_new_words_no_new_evidence_blocked(self):
        rows = [{'payload': proposal()}, {'payload': failed()}]
        self.assertFalse(assess_attempt(rows, proposal(H2, P2)).allowed)

    def test_new_hypothesis_patch_and_evidence_one_more_try(self):
        rows = [{'payload': proposal()}, {'payload': failed()}]
        self.assertTrue(assess_attempt(rows, proposal(H2, P2, E1)).allowed)

    def test_two_failures_at_same_source_signature_stop(self):
        rows = [{'payload': proposal()}, {'payload': failed()},
                {'payload': proposal(H2, P2, E1)}, {'payload': failed(H2, P2, E1)}]
        decision = assess_attempt(rows, proposal(H3, P3, E2))
        self.assertFalse(decision.allowed)
        self.assertIn('ceiling', decision.reason)

    def test_unresolved_prior_api_call_cannot_be_relaunched(self):
        rows = [{'payload': proposal()}]
        d = assess_attempt(rows, proposal(H2, P2, E1))
        self.assertFalse(d.allowed)
        self.assertIn('no result', d.reason)

    def test_budget_resource_stop_global(self):
        rows = [{'payload': event(event_type='RESOURCE_STOP', node_id='N1', source_sha=SHA,
                                  outcome='RESOURCE_STOP', evidence_ref='BATCH_01_RESULT.json')}]
        decision = assess_attempt(rows, proposal())
        self.assertFalse(decision.allowed)
        self.assertIn('budget', decision.reason)

    def test_same_patch_across_different_signature_blocked(self):
        other = signature('pytest', 'another_test', 'OTHER_FAIL')
        rows = [{'payload': proposal()}, {'payload': failed()}]
        p = proposal(H2, P1, E1)
        p['error_signature'] = other
        decision = assess_attempt(rows, p)
        self.assertFalse(decision.allowed)

    def test_prior_lane_block_is_binding(self):
        rows = [{'payload': event(event_type='LANE_BLOCKED', node_id='N4', source_sha=SHA, outcome='BLOCKED')}]
        self.assertFalse(assess_attempt(rows, proposal()).allowed)

    def test_per_node_attempt_budget(self):
        rows = [{'payload': proposal(digest({'h':i}), digest({'p':i}), digest({'e':i}))}
                for i in range(5)]
        self.assertFalse(assess_attempt(rows, proposal(H3, P3, E3)).allowed)


class SchedulerTests(unittest.TestCase):
    def lane(self, node, priority=1, deps=(), auth=True, owner=True, acceptance=True, status='READY'):
        return Lane(node, priority, tuple(deps), auth, owner, acceptance, status)

    def test_blocked_lane_moves_to_authorized_sibling(self):
        lanes = [self.lane('N1', 1, status='BLOCKED'), self.lane('N2', 2)]
        selected, reasons = select_lane(lanes)
        self.assertEqual(selected, 'N2')

    def test_cannot_cross_owner_gate(self):
        chosen, _ = select_lane([self.lane('N2', owner=False)])
        self.assertIsNone(chosen)

    def test_no_inferred_authority(self):
        chosen, _ = select_lane([self.lane('N2', auth=False)])
        self.assertIsNone(chosen)

    def test_requires_accepted_dependency(self):
        lanes = [self.lane('N2', status='CANDIDATE'), self.lane('N5', deps=('N2',))]
        selected, reasons = select_lane(lanes)
        self.assertEqual(selected, 'N2')
        self.assertIn('Dependency', reasons['N5'])

    def test_accepted_dependency_allows_next(self):
        lanes = [self.lane('N2', status='CLOSED'), self.lane('N5', deps=('N2',))]
        self.assertEqual(select_lane(lanes)[0], 'N5')

    def test_unknown_dependency_fails_closed(self):
        with self.assertRaises(GuardError):
            select_lane([self.lane('N5', deps=('N2',))])

    def test_cycle_fails_closed(self):
        with self.assertRaises(GuardError):
            select_lane([self.lane('N1', deps=('N2',)), self.lane('N2', deps=('N1',))])

    def test_acceptance_gate_closed(self):
        self.assertIsNone(select_lane([self.lane('N5', acceptance=False)])[0])


class EconomicTests(unittest.TestCase):
    def test_fable_observed_no_new_acceptance(self):
        metrics = economic_metrics(5.0187005, 0, 74)
        self.assertTrue(metrics['zero_verified_progress'])
        self.assertIsNone(metrics['usd_per_independently_closed_node'])

    def test_verified_closure_cost(self):
        self.assertEqual(economic_metrics(8.0, 2, 8)['usd_per_independently_closed_node'], 4.0)


if __name__ == '__main__':
    unittest.main()
