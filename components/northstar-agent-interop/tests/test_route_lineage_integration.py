import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from route_lineage import LineageGraph, RouteLineageEvent, verify_lineage

class LineageVerifierTests(unittest.TestCase):
    def event(self,status='planned',event_id='e1',parent=None,receipt='receipt-1',retryable=False,deadline=90):
        return RouteLineageEvent.from_dict({
            'schema_version':'northstar.route-lineage.v1','event_id':event_id,'route_id':'r1',
            'parent_event_id':parent,'receipt_id':receipt,'status':status,
            'target_agent_id':'codex','provider':'openai','capabilities':['workspace:read'],
            'deadline_at':deadline,'payload_digest':'sha256:'+'a'*64,
            'decision_fingerprint':'sha256:'+'b'*64,'retryable':retryable})
    def route(self):
        return {'selected_agent_id':'codex','selected_provider':'openai','capabilities':['workspace:read'],
                'deadline_at':90,'decision_fingerprint':'sha256:'+'b'*64,'payload_digest':'sha256:'+'a'*64}
    def handoff(self):
        return {'target_agent_id':'codex','provider':'openai','capabilities':['workspace:read'],
                'deadline_at':90,'decision_fingerprint':'sha256:'+'b'*64,'payload_digest':'sha256:'+'a'*64}
    def test_verified_success_requires_matching_handoff_and_receipt(self):
        graph=LineageGraph(); graph.append(self.event()); graph.append(self.event('dispatched','e2','e1')); graph.append(self.event('succeeded','e3','e2'))
        self.assertEqual(verify_lineage(graph,route_record=self.route(),handoff=self.handoff()).verdict,'verified')
    def test_failed_terminal_is_failed_not_success(self):
        graph=LineageGraph(); graph.append(self.event()); graph.append(self.event('dispatched','e2','e1')); graph.append(self.event('failed','e3','e2',retryable=True))
        self.assertEqual(verify_lineage(graph,route_record=self.route(),handoff=self.handoff()).verdict,'failed')
    def test_missing_or_widened_evidence_is_unknown_or_failed(self):
        graph=LineageGraph(); graph.append(self.event()); graph.append(self.event('dispatched','e2','e1'))
        self.assertEqual(verify_lineage(graph,route_record=self.route(),handoff=self.handoff()).verdict,'unknown')
        bad=dict(self.handoff(),deadline_at=101)
        self.assertEqual(verify_lineage(graph,route_record=self.route(),handoff=bad).verdict,'unknown')
    def test_target_mismatch_cannot_verify(self):
        graph=LineageGraph(); graph.append(self.event()); graph.append(self.event('dispatched','e2','e1')); graph.append(self.event('succeeded','e3','e2'))
        bad=dict(self.handoff(),target_agent_id='claude')
        self.assertEqual(verify_lineage(graph,route_record=self.route(),handoff=bad).verdict,'unknown')

if __name__=='__main__': unittest.main()
