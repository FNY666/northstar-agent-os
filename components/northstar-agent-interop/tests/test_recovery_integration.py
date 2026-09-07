import tempfile
import unittest
from pathlib import Path
from route_lineage import LineageGraph, RouteLineageEvent
from recovery_cursor import LeaseManager, RecoveryError

class FencingIntegrationTests(unittest.TestCase):
    def event(self,sequence,prev,event_id='e1',parent=None,status='planned'):
        return RouteLineageEvent.from_dict({'schema_version':'northstar.route-lineage.v2','sequence':sequence,'prev_event_digest':prev,'event_id':event_id,'route_id':'r1','parent_event_id':parent,'receipt_id':'receipt-'+event_id,'status':status,'target_agent_id':'codex','provider':'openai','capabilities':['workspace:read'],'deadline_at':90,'payload_digest':'sha256:'+'a'*64,'decision_fingerprint':'sha256:'+'b'*64,'retryable':False})
    def test_cursor_and_lease_gate_append(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph=LineageGraph(Path(tmp)/'l.jsonl'); manager=LeaseManager(); lease=manager.acquire('owner-a',now=100,ttl=10)
            cursor=graph.cursor(); first=graph.append_with_lease(self.event(1,'0'*64),cursor,lease,now=101)
            second=graph.append_with_lease(self.event(2,first.event_digest.removeprefix('sha256:'),'e2','e1','dispatched'),first,lease,now=102)
            self.assertEqual(second.sequence,2)
            with self.assertRaises(RecoveryError): graph.append_with_lease(self.event(3,second.event_digest.removeprefix('sha256:'),'e3','e2','succeeded'),cursor,lease,now=103)
    def test_expired_lease_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph=LineageGraph(Path(tmp)/'l.jsonl'); lease=LeaseManager().acquire('owner',now=1,ttl=1)
            with self.assertRaises(RecoveryError): graph.append_with_lease(self.event(1,'0'*64),graph.cursor(),lease,now=2)

if __name__=='__main__': unittest.main()
