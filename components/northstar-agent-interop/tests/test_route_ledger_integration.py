import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
HOST_ROOT = COMPONENT_ROOT.parent / "northstar-host"
CONTRACT_ROOT = COMPONENT_ROOT.parent / "northstar-run-contract"
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(HOST_ROOT))
sys.path.insert(0, str(CONTRACT_ROOT))

from backend_router import (  # noqa: E402
    BackendRouter,
    RouteRequest,
    assert_route_matches_handoff,
)
from interop_contract import AgentProfile, HandoffRequest  # noqa: E402
from route_ledger import RouteLedger, RouteReceipt  # noqa: E402


class FakeAdapter:
    agent_id = "codex"


ROUTE = {
    "schema_version": "northstar.route-request.v1",
    "task_id": "task-001",
    "thread_id": "thread-001",
    "run_id": "run-001",
    "actor_id": "actor-001",
    "workspace_id": "workspace-001",
    "policy_revision": "policy-1",
    "step_id": "implementation",
    "trace_id": "trace-001",
    "input_digest": "sha256:" + "1" * 64,
    "requested_capabilities": ["workspace:read"],
    "deadline_at": 1_900,
    "preferred_agent_ids": [],
    "excluded_agent_ids": [],
}


class RouteLedgerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.router = BackendRouter()
        self.adapter = FakeAdapter()
        self.router.register(
            AgentProfile.from_dict(
                {
                    "schema_version": "northstar.agent-profile.v1",
                    "agent_id": "codex",
                    "provider": "openai",
                    "version": "cli-v1",
                    "capabilities": ["workspace:read"],
                }
            ),
            self.adapter,
            priority=1,
        )
        self.tempdir = tempfile.TemporaryDirectory()
        self.ledger = RouteLedger(Path(self.tempdir.name) / "route.jsonl")

    def tearDown(self):
        self.tempdir.cleanup()

    def test_select_persist_receipt_replay_and_handoff_deadline_narrowing(self):
        decision = self.router.select(
            RouteRequest.from_dict(ROUTE),
            now=1_001,
            current_policy_revision="policy-1",
        )
        selected = self.ledger.append_decision(
            decision,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        self.assertEqual(selected.event_type, "decision.selected")
        started = self.ledger.append_receipt(
            RouteReceipt.from_decision(
                decision,
                status="started",
                attempt=1,
                latency_ms=5,
                failure_class=None,
                error_code=None,
                retryable=False,
                idempotency_key="route-001-started-1",
                recorded_at=1_002,
            )
        )
        success = self.ledger.append_receipt(
            RouteReceipt.from_decision(
                decision,
                status="succeeded",
                attempt=1,
                latency_ms=25,
                failure_class=None,
                error_code=None,
                retryable=False,
                idempotency_key="route-001-succeeded-1",
                recorded_at=1_010,
            )
        )
        self.assertEqual((started.sequence, success.sequence), (2, 3))
        handoff = HandoffRequest.from_dict(
            {
                "schema_version": "northstar.handoff-request.v1",
                "handoff_id": "handoff-001",
                "task_id": decision.task_id,
                "thread_id": decision.thread_id,
                "run_id": decision.run_id,
                "actor_id": decision.actor_id,
                "workspace_id": decision.workspace_id,
                "policy_revision": decision.policy_revision,
                "source_agent_id": "orchestrator",
                "target_agent_id": decision.target_agent_id,
                "step_id": decision.step_id,
                "trace_id": decision.trace_id,
                "input_digest": decision.input_digest,
                "requested_capabilities": list(decision.requested_capabilities),
                "expected_postconditions": ["tests_pass"],
                "delegation_depth": 1,
                "deadline_at": 1_800,
                "requested_at": 1_000,
                "idempotency_key": "handoff-001-attempt-1",
            }
        )
        assert_route_matches_handoff(decision, handoff)
        replay = self.ledger.replay("run-001")
        self.assertEqual(replay.status, "succeeded")
        self.assertEqual(replay.route_id, decision.route_id)
        self.assertEqual(replay.target_agent_id, "codex")
        self.assertEqual(replay.total_latency_ms, 30)

    def test_stale_route_decision_and_wrong_handoff_identity_are_not_replay_authority(self):
        decision = self.router.select(RouteRequest.from_dict(ROUTE), now=1_001)
        self.ledger.append_decision(
            decision,
            attempt=1,
            idempotency_key="route-001-selected-1",
            recorded_at=1_001,
        )
        with self.assertRaises(ValueError):
            self.router.adapter_for(decision, current_policy_revision="policy-2")
        altered = dict(ROUTE)
        altered["run_id"] = "run-002"
        wrong = RouteRequest.from_dict(altered)
        other_decision = self.router.select(wrong, now=1_002)
        with self.assertRaises(ValueError):
            self.ledger.append_decision(
                other_decision,
                attempt=1,
                idempotency_key="route-002-selected-1",
                recorded_at=1_002,
            )


if __name__ == "__main__":
    unittest.main()
