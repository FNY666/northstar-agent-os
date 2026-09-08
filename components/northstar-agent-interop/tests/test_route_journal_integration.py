import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))

from route_journal import (
    RouteDecisionJournal,
    RouteJournalRecord,
    RouteSelectionError,
    assert_handoff_compatible,
    record_route,
    replay_route,
)

class FakeRouter:
    def __init__(self, result, candidates):
        self.result = result
        self._candidates = candidates
        self.calls = 0
    def snapshot(self, request):
        return self._candidates
    def select(self, request, *, now, policy_revision):
        self.calls += 1
        return self.result

class RouteJournalIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.candidates = [{
            "agent_id": "codex", "provider": "openai", "version": "v1",
            "enabled": True, "health": "healthy", "cooldown_until": 0,
            "priority": 10, "capabilities": ["workspace:read"],
        }, {
            "agent_id": "claude", "provider": "anthropic", "version": "v1",
            "enabled": True, "health": "healthy", "cooldown_until": 0,
            "priority": 20, "capabilities": ["workspace:read"],
        }]
        self.request = {"request_digest": "sha256:" + "b" * 64,
                        "capability": "workspace:read", "preferred_agent_id": "codex"}

    def test_record_captures_selection_without_raw_request(self):
        from route_journal import record_route
        router = FakeRouter({"status": "selected", "agent_id": "codex", "provider": "openai", "deadline_at": 90}, self.candidates)
        with tempfile.TemporaryDirectory() as tmp:
            record = record_route(RouteDecisionJournal(Path(tmp) / "r.jsonl"), router, self.request,
                                  now=10, policy_revision="p1", idempotency_key="route-1")
            self.assertEqual(record.selected_agent_id, "codex")
            self.assertNotIn("capability", record.to_dict())
            self.assertEqual(router.calls, 1)

    def test_router_failure_is_structured_and_replayable(self):
        router = FakeRouter({"status": "failed", "failure_class": "cooldown"}, self.candidates)
        with tempfile.TemporaryDirectory() as tmp:
            journal = RouteDecisionJournal(Path(tmp) / "r.jsonl")
            record = record_route(journal, router, self.request, now=10, policy_revision="p1", idempotency_key="route-2")
            self.assertEqual(record.failure_class, "cooldown")
            replay = replay_route(journal, router, record, self.request, now=10, policy_revision="p1")
            self.assertEqual(replay, record)

    def test_idempotent_record_does_not_call_router_again(self):
        router = FakeRouter({"status": "selected", "agent_id": "codex", "provider": "openai", "deadline_at": 90}, self.candidates)
        with tempfile.TemporaryDirectory() as tmp:
            journal = RouteDecisionJournal(Path(tmp) / "r.jsonl")
            first = record_route(journal, router, self.request, now=10, policy_revision="p1", idempotency_key="route-3")
            second = record_route(journal, router, self.request, now=99, policy_revision="p1", idempotency_key="route-3")
            self.assertEqual(first, second)
            self.assertEqual(router.calls, 1)

    def test_changed_snapshot_fails_replay_closed(self):
        router = FakeRouter({"status": "selected", "agent_id": "codex", "provider": "openai", "deadline_at": 90}, self.candidates)
        with tempfile.TemporaryDirectory() as tmp:
            journal = RouteDecisionJournal(Path(tmp) / "r.jsonl")
            record = record_route(journal, router, self.request, now=10, policy_revision="p1", idempotency_key="route-4")
            router._candidates = [dict(self.candidates[1])]
            with self.assertRaises(RouteSelectionError):
                replay_route(journal, router, record, self.request, now=10, policy_revision="p1")

    def test_handoff_identity_and_deadline_must_narrow_route(self):
        record = RouteJournalRecord.from_dict({
            "schema_version": "northstar.route-journal.v1", "idempotency_key": "route-5",
            "request_digest": "sha256:" + "b" * 64, "policy_revision": "p1",
            "status": "selected", "failure_class": None, "selected_agent_id": "codex",
            "selected_provider": "openai", "deadline_at": 90, "candidate_snapshot": self.candidates,
        })
        assert_handoff_compatible(record, {"target_agent_id": "codex", "provider": "openai", "deadline_at": 80})
        with self.assertRaises(RouteSelectionError):
            assert_handoff_compatible(record, {"target_agent_id": "claude", "provider": "openai", "deadline_at": 80})
        with self.assertRaises(RouteSelectionError):
            assert_handoff_compatible(record, {"target_agent_id": "codex", "provider": "openai", "deadline_at": 100})

if __name__ == "__main__": unittest.main()
