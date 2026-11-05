import copy
import json
import tempfile
import unittest
from pathlib import Path
from offline_planner import NODES, PlanError, compute, validate, main

SHA = 'a'*40
TREE = 'b'*40

def snapshot():
    nodes = {n: {'state':'OPEN','parents':[],'owner_gate':False,'owner_authorised':False,
                 'acceptance_required':True,'acceptance_verdict':'NONE','commit':None,'tree':None,
                 'quarantined':False,'reason':''} for n in NODES}
    nodes['N6']['parents'] = ['N1','N2','N3','N5']
    nodes['N7']['parents'] = ['N6']
    return {'schema':1,'nodes':nodes}

def close(d,n):
    r=d['nodes'][n]
    r.update(state='CLOSED',commit=SHA,tree=TREE,acceptance_verdict='APPROVED',owner_authorised=True)

class PlannerTests(unittest.TestCase):
    def test_missing_node(self):
        d=snapshot();del d['nodes']['N8'];self.assertRaises(PlanError,validate,d)
    def test_extra_field(self):
        d=snapshot();d['nodes']['N0']['bonus']=True;self.assertRaises(PlanError,validate,d)
    def test_cycle(self):
        d=snapshot();d['nodes']['N1']['parents']=['N6'];self.assertRaises(PlanError,validate,d)
    def test_self_dependency(self):
        d=snapshot();d['nodes']['N0']['parents']=['N0'];self.assertRaises(PlanError,validate,d)
    def test_duplicate_dependency(self):
        d=snapshot();d['nodes']['N6']['parents'].append('N2');self.assertRaises(PlanError,validate,d)
    def test_invalid_boolean(self):
        d=snapshot();d['nodes']['N0']['owner_authorised']='true';self.assertRaises(PlanError,validate,d)
    def test_missing_independent_acceptance(self):
        d=snapshot();close(d,'N1');d['nodes']['N1']['acceptance_verdict']='NONE';self.assertRaises(PlanError,validate,d)
    def test_owner_gate_closed_without_owner(self):
        d=snapshot();close(d,'N1');d['nodes']['N1']['owner_gate']=True;d['nodes']['N1']['owner_authorised']=False;self.assertRaises(PlanError,validate,d)
    def test_quarantine_stops(self):
        d=snapshot();r=d['nodes']['N0'];r['owner_authorised']=True;r['quarantined']=True
        self.assertIn('QUARANTINE_ACTIVE',compute(d)['nodes']['N0']['blockers'])
    def test_rejection_stops(self):
        d=snapshot();r=d['nodes']['N0'];r['state']='REJECTED';r['acceptance_verdict']='REJECTED';r['owner_authorised']=True
        self.assertFalse(compute(d)['nodes']['N0']['eligible_for_controller_consideration'])
    def test_parent_stops(self):
        d=snapshot();d['nodes']['N6']['owner_authorised']=True
        self.assertIn('PARENT_NOT_CLOSED:N2',compute(d)['nodes']['N6']['blockers'])
    def test_parent_release_does_not_authorise(self):
        d=snapshot()
        for n in ('N1','N2','N3','N5'):close(d,n)
        self.assertIn('WORK_AUTHORIZATION_MISSING',compute(d)['nodes']['N6']['blockers'])
    def test_authorised_independent_node(self):
        d=snapshot();d['nodes']['N0']['owner_authorised']=True
        self.assertTrue(compute(d)['nodes']['N0']['eligible_for_controller_consideration'])
    def test_candidate_not_automatically_dispatched(self):
        d=snapshot();r=d['nodes']['N0'];r['state']='CANDIDATE';r['owner_authorised']=True
        self.assertIn('CANDIDATE_AWAITING_DISPOSITION',compute(d)['nodes']['N0']['blockers'])
    def test_deterministic_hash(self):
        d=snapshot();self.assertEqual(compute(d)['snapshot_sha256'],compute(copy.deepcopy(d))['snapshot_sha256'])
    def test_invalid_sha(self):
        d=snapshot();d['nodes']['N0']['commit']='bad';self.assertRaises(PlanError,validate,d)
    def test_output_does_not_overwrite(self):
        d=snapshot()
        with tempfile.TemporaryDirectory() as td:
            inp=Path(td)/'input.json'; out=Path(td)/'out.json'
            inp.write_text(json.dumps(d));out.write_text('keep')
            with self.assertRaises(SystemExit):main([str(inp),'--output',str(out)])
            self.assertEqual(out.read_text(),'keep')
    def test_output_file_created(self):
        d=snapshot()
        with tempfile.TemporaryDirectory() as td:
            inp=Path(td)/'input.json'; out=Path(td)/'out.json'
            inp.write_text(json.dumps(d));self.assertEqual(main([str(inp),'--output',str(out)]),0)
            self.assertEqual(json.loads(out.read_text())['closed_count'],0)

if __name__=='__main__':unittest.main()
