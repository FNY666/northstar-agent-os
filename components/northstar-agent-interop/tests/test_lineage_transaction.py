import tempfile
import unittest
from pathlib import Path
from lineage_transaction import TransactionCheckpoint, TransactionalLineageStore, TransactionError
from route_lineage import RouteLineageEvent, LineageGraph
from recovery_cursor import PersistentLeaseManager

class TransactionTests(unittest.TestCase):
    def event(self):
        return RouteLineageEvent.from_dict({'schema_version':'northstar.route-lineage.v2','sequence':1,'prev_event_digest':'0'*64,'event_id':'e1','route_id':'r1','parent_event_id':None,'receipt_id':'receipt-e1','status':'planned','target_agent_id':'codex','provider':'openai','capabilities':['workspace:read'],'deadline_at':90,'payload_digest':'sha256:'+'a'*64,'decision_fingerprint':'sha256:'+'b'*64,'retryable':False})
    def test_checkpoint_rejects_unknown_and_bad_fields(self):
        with self.assertRaises(ValueError): TransactionCheckpoint.from_dict({'sequence':0})
    def test_successful_transaction_returns_next_cursor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); store=TransactionalLineageStore(root/'lineage.jsonl',root/'checkpoint.json'); lease=PersistentLeaseManager(root/'lease.json').acquire('a',now=1,ttl=10); graph=LineageGraph.from_path(root/'lineage.jsonl'); cursor=graph.cursor(); next_cursor=store.append(self.event(),cursor,lease,now=2); self.assertEqual(next_cursor.sequence,1)
    def test_stale_cursor_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); store=TransactionalLineageStore(root/'lineage.jsonl',root/'checkpoint.json'); lease=PersistentLeaseManager(root/'lease.json').acquire('a',now=1,ttl=10); graph=LineageGraph.from_path(root/'lineage.jsonl'); cursor=graph.cursor(); store.append(self.event(),cursor,lease,now=2)
            with self.assertRaises(TransactionError): store.append(self.event(),cursor,lease,now=3)
    def test_recovery_detects_checkpoint_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); store=TransactionalLineageStore(root/'lineage.jsonl',root/'checkpoint.json'); lease=PersistentLeaseManager(root/'lease.json').acquire('a',now=1,ttl=10); graph=LineageGraph.from_path(root/'lineage.jsonl'); store.append(self.event(),graph.cursor(),lease,now=2); store.checkpoint.write_text('{"bad":true}')
            with self.assertRaises(TransactionError): store.recover()

    def test_recovery_returns_current_persisted_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); store=TransactionalLineageStore(root/'lineage.jsonl',root/'checkpoint.json'); manager=PersistentLeaseManager(root/'lease.json'); lease=manager.acquire('a',now=1,ttl=10); graph=LineageGraph.from_path(root/'lineage.jsonl'); store.append(self.event(),graph.cursor(),lease,now=2)
            cursor, recovered_lease = store.recover()
            self.assertEqual(cursor.sequence, 1)
            self.assertEqual(recovered_lease, lease)


    def test_fault_after_event_fsync_needs_recovery_evidence(self):
        from lineage_transaction import TransactionError
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); lease=PersistentLeaseManager(root/'lease.json').acquire('a',now=1,ttl=10)
            store=TransactionalLineageStore(root/'lineage.jsonl',root/'checkpoint.json',fault=lambda point: (_ for _ in ()).throw(RuntimeError(point)) if point=='after_event_fsync' else None)
            with self.assertRaises(RuntimeError): store.append(self.event(),LineageGraph.from_path(root/'lineage.jsonl').cursor(),lease,now=2)
            with self.assertRaises(TransactionError): store.recover()

    def test_duplicate_terminal_receipt_is_rejected(self):
        event = self.event()
        succeeded_data = event.to_dict(); succeeded_data["status"] = "succeeded"; succeeded_data.pop("event_digest", None)
        succeeded = RouteLineageEvent.from_dict(succeeded_data)
        duplicate_data = succeeded.to_dict(); duplicate_data["event_id"] = "e2"; duplicate_data.pop("event_digest", None)
        duplicate = RouteLineageEvent.from_dict(duplicate_data)
        graph = LineageGraph()
        graph.append(succeeded)
        with self.assertRaises(Exception):
            graph.append(duplicate)

    def test_transaction_persists_event_for_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); lineage=root/'lineage.jsonl'; store=TransactionalLineageStore(lineage,root/'checkpoint.json')
            lease=PersistentLeaseManager(root/'lease.json').acquire('a',now=1,ttl=10)
            store.append(self.event(),LineageGraph.from_path(lineage).cursor(),lease,now=2)
            restored=LineageGraph.from_path(lineage)
            self.assertEqual([event.event_id for event in restored.read()],['e1'])

if __name__=='__main__': unittest.main()
