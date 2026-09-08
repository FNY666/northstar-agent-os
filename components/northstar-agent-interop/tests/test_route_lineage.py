import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from route_lineage import RouteLineageEvent, LineageGraph, derive_retry, causal_chain

class LineageRedTests(unittest.TestCase):
    def event(self, **overrides):
        value={"schema_version":"northstar.route-lineage.v1","event_id":"e1","route_id":"r1",
               "parent_event_id":None,"receipt_id":"receipt-1","status":"planned",
               "target_agent_id":"codex","provider":"openai","capabilities":["workspace:read"],
               "deadline_at":100,"payload_digest":"sha256:"+"a"*64,
               "decision_fingerprint":"sha256:"+"b"*64,"retryable":False}
        value.update(overrides); return value
    def test_strict_event_rejects_unknown_and_raw_fields(self):
        with self.assertRaises(ValueError): RouteLineageEvent.from_dict({**self.event(),"prompt":"secret"})
    def test_legal_lifecycle_and_illegal_transition(self):
        graph=LineageGraph(); graph.append(RouteLineageEvent.from_dict(self.event()))
        graph.append(RouteLineageEvent.from_dict(self.event(event_id="e2",parent_event_id="e1",status="dispatched")))
        graph.append(RouteLineageEvent.from_dict(self.event(event_id="e3",parent_event_id="e2",status="succeeded")))
        with self.assertRaises(ValueError): graph.append(RouteLineageEvent.from_dict(self.event(event_id="e4",parent_event_id="e3",status="dispatched")))
    def test_retry_can_only_narrow(self):
        failed=RouteLineageEvent.from_dict(self.event(status="failed",retryable=True,receipt_id="receipt-1"))
        retry=derive_retry(failed,event_id="e2",receipt_id="receipt-2",deadline_at=90,capabilities=["workspace:read"])
        self.assertEqual(retry.status,"planned"); self.assertEqual(retry.parent_event_id,"e1")
        with self.assertRaises(ValueError): derive_retry(failed,event_id="e3",receipt_id="receipt-3",deadline_at=110,capabilities=["workspace:read"])
    def test_causal_chain_rejects_cycle(self):
        graph=LineageGraph(); graph.append(RouteLineageEvent.from_dict(self.event()))
        graph.append(RouteLineageEvent.from_dict(self.event(event_id="e2",parent_event_id="e1",status="dispatched")))
        self.assertEqual([e.event_id for e in causal_chain(graph,"e2")],["e1","e2"])

if __name__=='__main__': unittest.main()
