import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

class RouteJournalRedTests(unittest.TestCase):
    def test_record_rejects_unknown_fields_and_raw_prompt(self):
        from route_journal import RouteJournalRecord
        with self.assertRaises(ValueError):
            RouteJournalRecord.from_dict({"status": "selected", "prompt": "secret"})

    def test_canonical_fingerprint_changes_with_selected_identity(self):
        from route_journal import RouteJournalRecord, decision_fingerprint
        first = RouteJournalRecord.from_dict({
            "schema_version": "northstar.route-journal.v1",
            "idempotency_key": "idem-1", "request_digest": "sha256:" + "a" * 64,
            "policy_revision": "p1", "status": "selected", "failure_class": None,
            "selected_agent_id": "codex", "selected_provider": "openai",
            "deadline_at": 100, "candidate_snapshot": [],
        })
        second = RouteJournalRecord.from_dict({**first.to_dict(), "selected_agent_id": "claude"})
        self.assertNotEqual(decision_fingerprint(first), decision_fingerprint(second))

    def test_append_round_trip_and_truncated_tail(self):
        from route_journal import RouteDecisionJournal
        with tempfile.TemporaryDirectory() as tmp:
            journal = RouteDecisionJournal(Path(tmp) / "route.jsonl")
            self.assertEqual(list(journal.read()), [])
            with journal.path.open("a", encoding="utf-8") as f: f.write('{"broken":')
            self.assertEqual(list(journal.read()), [])

    def test_duplicate_idempotency_conflict_is_rejected(self):
        from route_journal import RouteDecisionJournal, RouteJournalRecord
        with tempfile.TemporaryDirectory() as tmp:
            journal = RouteDecisionJournal(Path(tmp) / "route.jsonl")
            record = RouteJournalRecord.from_dict({
                "schema_version": "northstar.route-journal.v1",
                "idempotency_key": "idem-1", "request_digest": "sha256:" + "a" * 64,
                "policy_revision": "p1", "status": "failed", "failure_class": "no_candidate",
                "selected_agent_id": None, "selected_provider": None, "deadline_at": None,
                "candidate_snapshot": [],
            })
            journal.append(record)
            self.assertEqual(journal.append(record), record)
            conflict = RouteJournalRecord.from_dict({**record.to_dict(), "failure_class": "cooldown"})
            with self.assertRaises(ValueError): journal.append(conflict)

    def test_concurrent_same_idempotency_key_is_written_once(self):
        import multiprocessing
        from route_journal import RouteDecisionJournal, RouteJournalRecord
        record = RouteJournalRecord.from_dict({
            "schema_version": "northstar.route-journal.v1",
            "idempotency_key": "idem-concurrent", "request_digest": "sha256:" + "c" * 64,
            "policy_revision": "p1", "status": "failed", "failure_class": "no_candidate",
            "selected_agent_id": None, "selected_provider": None, "deadline_at": None,
            "candidate_snapshot": [],
        })
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "route.jsonl")
            def writer():
                RouteDecisionJournal(path).append(record)
            processes = [multiprocessing.Process(target=writer) for _ in range(2)]
            for process in processes: process.start()
            for process in processes: process.join(5)
            self.assertTrue(all(process.exitcode == 0 for process in processes))
            self.assertEqual(len(list(RouteDecisionJournal(path).read())), 1)


    def test_stale_lock_file_is_reusable(self):
        from route_journal import RouteDecisionJournal, RouteJournalRecord
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "route.jsonl"
            lock = Path(str(path) + ".lock")
            lock.write_text("stale", encoding="utf-8")
            record = RouteJournalRecord.from_dict({
                "schema_version": "northstar.route-journal.v1",
                "idempotency_key": "idem-stale-lock", "request_digest": "sha256:" + "d" * 64,
                "policy_revision": "p1", "status": "failed", "failure_class": "no_candidate",
                "selected_agent_id": None, "selected_provider": None, "deadline_at": None,
                "candidate_snapshot": [],
            })
            RouteDecisionJournal(path).append(record)
            self.assertEqual(len(list(RouteDecisionJournal(path).read())), 1)
