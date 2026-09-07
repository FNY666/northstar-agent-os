import multiprocessing
import tempfile
import unittest
from pathlib import Path
from lineage_transaction import TransactionalLineageStore, TransactionError
from route_lineage import LineageGraph, RouteLineageEvent
from recovery_cursor import PersistentLeaseManager


def event(event_id="e1", sequence=1, previous="0" * 64):
    return RouteLineageEvent.from_dict({
        "schema_version": "northstar.route-lineage.v2",
        "sequence": sequence, "prev_event_digest": previous,
        "event_id": event_id, "route_id": "r1", "parent_event_id": None,
        "receipt_id": "receipt-" + event_id, "status": "planned",
        "target_agent_id": "codex", "provider": "openai",
        "capabilities": ["workspace:read"], "deadline_at": 90,
        "payload_digest": "sha256:" + "a" * 64,
        "decision_fingerprint": "sha256:" + "b" * 64,
        "retryable": False,
    })


def append_worker(root: str, lease_dict: dict, connection) -> None:
    from recovery_cursor import Lease
    lease = Lease(**lease_dict)
    store = TransactionalLineageStore(Path(root) / "lineage.jsonl", Path(root) / "checkpoint.json")
    graph = LineageGraph.from_path(Path(root) / "lineage.jsonl")
    try:
        store.append(event(), graph.cursor(), lease, now=2)
        connection.send("won")
    except Exception as exc:
        connection.send(type(exc).__name__)
    finally:
        connection.close()

class TransactionProcessTests(unittest.TestCase):
    def test_two_processes_racing_same_cursor_have_one_winner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lease = PersistentLeaseManager(root / "lease.json").acquire("owner", now=1, ttl=20)
            parent_connections = []
            child_connections = []
            processes = []
            for _ in range(2):
                parent, child = multiprocessing.Pipe(False)
                parent_connections.append(parent); child_connections.append(child)
                processes.append(multiprocessing.Process(target=append_worker,
                              args=(str(root), lease.__dict__, child)))
            for process in processes: process.start()
            for connection in child_connections: connection.close()
            for process in processes: process.join(10)
            self.assertTrue(all(process.exitcode == 0 for process in processes))
            outcomes = sorted(connection.recv() for connection in parent_connections)
            self.assertEqual(outcomes.count("won"), 1)
            self.assertEqual(len(list(LineageGraph.from_path(root / "lineage.jsonl").read())), 1)

    def test_new_fencing_token_invalidates_old_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = PersistentLeaseManager(root / "lease.json")
            old = manager.acquire("old", now=1, ttl=1)
            new = PersistentLeaseManager(root / "lease.json").acquire("new", now=3, ttl=10)
            self.assertGreater(new.fencing_token, old.fencing_token)
            store = TransactionalLineageStore(root / "lineage.jsonl", root / "checkpoint.json")
            with self.assertRaises(TransactionError):
                store.append(event(), LineageGraph.from_path(root / "lineage.jsonl").cursor(), old, now=3)

if __name__ == "__main__":
    unittest.main()
