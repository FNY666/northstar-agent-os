import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from route_replay import ReplayVerdict, ReplayLineage, classify_replay

class ReplayTests(unittest.TestCase):
    def record(self):
        return {"schema_version":"northstar.route-journal.v1","idempotency_key":"route-1",
                "request_digest":"sha256:"+"a"*64,"policy_revision":"p1","status":"selected",
                "failure_class":None,"selected_agent_id":"codex","selected_provider":"openai",
                "deadline_at":100,"candidate_snapshot":[{"agent_id":"codex","provider":"openai",
                "version":"v1","enabled":True,"health":"healthy","cooldown_until":0,
                "priority":1,"capabilities":["workspace:read"]}]}
    def test_exact_match_is_replayable(self):
        result = classify_replay(self.record(), self.record()["candidate_snapshot"], "p1", request_digest="sha256:"+"a"*64,
                                 lineage=ReplayLineage(None, 1, "receipt-1", "initial"))
        self.assertEqual(result.verdict, ReplayVerdict.REPLAYABLE)
    def test_candidate_change_is_stale(self):
        snapshot = [dict(self.record()["candidate_snapshot"][0], health="degraded")]
        result = classify_replay(self.record(), snapshot, "p1", request_digest="sha256:"+"a"*64,
                                 lineage=ReplayLineage(None, 1, "receipt-1", "initial"))
        self.assertEqual(result.verdict, ReplayVerdict.STALE)
    def test_digest_mismatch_is_conflicting(self):
        result = classify_replay(self.record(), self.record()["candidate_snapshot"], "p1", request_digest="sha256:"+"b"*64,
                                 lineage=ReplayLineage(None, 1, "receipt-1", "initial"))
        self.assertEqual(result.verdict, ReplayVerdict.CONFLICTING)
    def test_missing_evidence_is_unverifiable(self):
        record = self.record(); record["candidate_snapshot"] = []
        result = classify_replay(record, [], "p1", request_digest=record["request_digest"],
                                 lineage=ReplayLineage("parent", 2, "receipt-2", "retry"))
        self.assertEqual(result.verdict, ReplayVerdict.UNVERIFIABLE)
        self.assertEqual(result.lineage.parent_id, "parent")

if __name__ == '__main__': unittest.main()
