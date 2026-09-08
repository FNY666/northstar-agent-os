import tempfile
import unittest
from pathlib import Path
from route_lineage import LineageGraph, RouteLineageEvent, LineageError

class PersistenceTests(unittest.TestCase):
    def event(self,status='planned',event_id='e1',parent=None):
        return RouteLineageEvent.from_dict({
            'schema_version':'northstar.route-lineage.v1','event_id':event_id,'route_id':'r1',
            'parent_event_id':parent,'receipt_id':'receipt-'+event_id,'status':status,
            'target_agent_id':'codex','provider':'openai','capabilities':['workspace:read'],
            'deadline_at':90,'payload_digest':'sha256:'+'a'*64,
            'decision_fingerprint':'sha256:'+'b'*64,'retryable':False})
    def test_restart_recovers_persisted_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'lineage.jsonl'; first=LineageGraph(path)
            first.append(self.event()); first.append(self.event('dispatched','e2','e1'))
            second=LineageGraph.from_path(path)
            self.assertEqual([e.event_id for e in second.read()],['e1','e2'])
            second.append(self.event('succeeded','e3','e2'))
            self.assertEqual([e.event_id for e in second.read()],['e1','e2','e3'])
    def test_truncated_tail_is_skipped_on_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'lineage.jsonl'; path.write_text(self.event().canonical().decode()+'\n{"broken":',encoding='utf-8')
            graph=LineageGraph.from_path(path)
            self.assertEqual([e.event_id for e in graph.read()],['e1'])
    def test_complete_corrupt_line_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'lineage.jsonl'; path.write_text('{bad}\n',encoding='utf-8')
            with self.assertRaises(LineageError): LineageGraph.from_path(path)
    def test_recovery_rejects_sequence_parent_corruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'lineage.jsonl'; path.write_text(self.event().canonical().decode()+'\n'+self.event('succeeded','e3','e1').canonical().decode()+'\n',encoding='utf-8')
            with self.assertRaises(LineageError): LineageGraph.from_path(path)

if __name__=='__main__': unittest.main()
