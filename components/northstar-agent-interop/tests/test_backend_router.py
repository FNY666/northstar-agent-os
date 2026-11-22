import sys
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
HOST_ROOT = COMPONENT_ROOT.parent / "northstar-host"
CONTRACT_ROOT = COMPONENT_ROOT.parent / "northstar-run-contract"
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(HOST_ROOT))
sys.path.insert(0, str(CONTRACT_ROOT))

from handoff import verify_handoff_grant  # noqa: E402
from interop_contract import AgentProfile, HandoffRequest  # noqa: E402
from process_backend import codex_cli_spec  # noqa: E402
from backend_router import (  # noqa: E402
    BackendRouter,
    RouteDecision,
    RouteRequest,
    assert_route_matches_handoff,
)


ROUTE = {
    "schema_version": "northstar.route-request.v1",
    "task_id": "task-route-001",
    "thread_id": "thread-route-001",
    "run_id": "run-route-001",
    "actor_id": "actor-route-001",
    "workspace_id": "workspace-route-001",
    "policy_revision": "policy-route-1",
    "step_id": "implementation",
    "trace_id": "trace-route-001",
    "input_digest": "sha256:" + "1" * 64,
    "requested_capabilities": ["workspace:read"],
    "deadline_at": 1_900,
    "preferred_agent_ids": [],
    "excluded_agent_ids": [],
}


class FakeAdapter:
    def __init__(self, agent_id):
        self.agent_id = agent_id


def profile(agent_id, provider, capabilities):
    return AgentProfile.from_dict(
        {
            "schema_version": "northstar.agent-profile.v1",
            "agent_id": agent_id,
            "provider": provider,
            "version": "router-test-v1",
            "capabilities": capabilities,
        }
    )


def handoff_for(decision):
    return HandoffRequest.from_dict(
        {
            "schema_version": "northstar.handoff-request.v1",
            "handoff_id": "handoff-route-001",
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
            "deadline_at": decision.deadline_at,
            "requested_at": 1_000,
            "idempotency_key": "handoff-route-001-attempt-1",
        }
    )


class RouteRequestTests(unittest.TestCase):
    def test_route_request_round_trips_canonically_and_rejects_unknown_or_duplicate_fields(self):
        request = RouteRequest.from_dict(ROUTE)
        self.assertEqual(request.to_dict(), ROUTE)
        reversed_fields = {key: ROUTE[key] for key in reversed(ROUTE)}
        self.assertEqual(request.canonical_json(), RouteRequest.from_dict(reversed_fields).canonical_json())
        unknown = dict(ROUTE)
        unknown["prompt"] = "must not enter routing"
        with self.assertRaises(ValueError):
            RouteRequest.from_dict(unknown)
        duplicate = dict(ROUTE)
        duplicate["preferred_agent_ids"] = ["codex", "codex"]
        with self.assertRaises(ValueError):
            RouteRequest.from_dict(duplicate)

    def test_route_request_rejects_invalid_identity_capability_and_preference_overlap(self):
        for field, value in (
            ("run_id", "run/001"),
            ("input_digest", "sha256:" + "A" * 64),
            ("requested_capabilities", ["workspace:*"]),
            ("deadline_at", 0),
        ):
            invalid = dict(ROUTE)
            invalid[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    RouteRequest.from_dict(invalid)
        with self.assertRaises(ValueError):
            RouteRequest.from_dict(
                {**ROUTE, "preferred_agent_ids": ["codex"], "excluded_agent_ids": ["codex"]}
            )


class BackendRouterTests(unittest.TestCase):
    def setUp(self):
        self.router = BackendRouter()
        self.claude = FakeAdapter("claude-code")
        self.codex = FakeAdapter("codex")
        self.router.register(
            profile("claude-code", "anthropic", ["workspace:read"]),
            self.claude,
            priority=20,
        )
        self.router.register(
            profile("codex", "openai", ["workspace:read", "workspace:write"]),
            self.codex,
            priority=10,
        )

    def test_preference_is_soft_and_falls_back_when_preferred_backend_is_unavailable(self):
        self.router.set_enabled("claude-code", False)
        request = RouteRequest.from_dict({**ROUTE, "preferred_agent_ids": ["claude-code"]})
        decision = self.router.select(request, now=1_001)
        self.assertEqual(decision.target_agent_id, "codex")

    def test_cooldown_expiry_allows_adapter_lookup(self):
        self.router.set_health("codex", "cooldown", now=1_000, cooldown_seconds=100)
        decision = self.router.select(RouteRequest.from_dict(ROUTE), now=1_100)
        self.assertEqual(self.router.adapter_for(decision), self.codex)

    def test_selection_requires_capability_support_and_prefers_requested_agent(self):
        request = RouteRequest.from_dict({**ROUTE, "preferred_agent_ids": ["claude-code"]})
        decision = self.router.select(request, now=1_001)
        self.assertIsInstance(decision, RouteDecision)
        self.assertEqual(decision.target_agent_id, "claude-code")
        self.assertEqual(decision.requested_capabilities, ("workspace:read",))
        self.assertEqual(self.router.adapter_for(decision), self.claude)

        write_request = RouteRequest.from_dict(
            {**ROUTE, "requested_capabilities": ["workspace:write"]}
        )
        write_decision = self.router.select(write_request, now=1_001)
        self.assertEqual(write_decision.target_agent_id, "codex")

    def test_priority_and_agent_id_make_unpreferred_selection_deterministic(self):
        request = RouteRequest.from_dict(ROUTE)
        decision = self.router.select(request, now=1_001)
        self.assertEqual(decision.target_agent_id, "codex")
        repeated = self.router.select(request, now=1_001)
        self.assertEqual(repeated, decision)
        self.assertEqual(repeated.route_id, decision.route_id)

    def test_disabled_unhealthy_degraded_and_excluded_backends_are_not_selected(self):
        self.router.set_enabled("codex", False)
        request = RouteRequest.from_dict(ROUTE)
        self.assertEqual(self.router.select(request, now=1_001).target_agent_id, "claude-code")

        self.router.set_health("claude-code", "degraded", now=1_002)
        with self.assertRaises(ValueError):
            self.router.select(request, now=1_002)

        self.router.set_health("claude-code", "healthy", now=1_003)
        self.router.set_enabled("claude-code", False)
        excluded = RouteRequest.from_dict({**ROUTE, "excluded_agent_ids": ["claude-code"]})
        with self.assertRaises(ValueError):
            self.router.select(excluded, now=1_003)

    def test_cooldown_blocks_candidate_until_expiry(self):
        self.router.set_health("codex", "cooldown", now=1_000, cooldown_seconds=100)
        request = RouteRequest.from_dict(ROUTE)
        self.assertEqual(self.router.select(request, now=1_001).target_agent_id, "claude-code")
        self.assertEqual(self.router.select(request, now=1_100).target_agent_id, "codex")

    def test_selection_rejects_expired_request_and_unknown_or_invalid_health(self):
        with self.assertRaises(ValueError):
            self.router.select(RouteRequest.from_dict(ROUTE), now=1_900)
        with self.assertRaises(ValueError):
            self.router.set_health("codex", "maybe", now=1_001)
        with self.assertRaises(ValueError):
            self.router.select(RouteRequest.from_dict(ROUTE), now=True)
        with self.assertRaises(ValueError):
            self.router.select(RouteRequest.from_dict(ROUTE), now=1_001, current_policy_revision="policy-other")

    def test_route_decision_is_not_authorization_and_cannot_be_forged_for_adapter_lookup(self):
        decision = self.router.select(RouteRequest.from_dict(ROUTE), now=1_001)
        data = decision.to_dict()
        self.assertNotIn("authorization_token", data)
        self.assertNotIn("secret", data)
        self.assertNotIn("prompt", data)
        forged = RouteDecision.from_dict({**data, "target_agent_id": "claude-code"})
        with self.assertRaises(ValueError):
            self.router.adapter_for(forged)

    def test_route_decision_must_match_handoff_identity_and_selected_target(self):
        decision = self.router.select(RouteRequest.from_dict(ROUTE), now=1_001)
        request = handoff_for(decision)
        self.assertIsNone(assert_route_matches_handoff(decision, request))
        for field, value in (
            ("run_id", "run-other"),
            ("policy_revision", "policy-other"),
            ("target_agent_id", "claude-code"),
            ("input_digest", "sha256:" + "2" * 64),
        ):
            altered = request.to_dict()
            altered[field] = value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    assert_route_matches_handoff(decision, HandoffRequest.from_dict(altered))

    def test_route_decision_rejects_unknown_fields_and_stale_policy_at_lookup(self):
        decision = self.router.select(RouteRequest.from_dict(ROUTE), now=1_001)
        with self.assertRaises(ValueError):
            RouteDecision.from_dict({**decision.to_dict(), "prompt": "no"})
        with self.assertRaises(ValueError):
            self.router.adapter_for(decision, current_policy_revision="policy-other")

    def test_process_spec_registration_requires_enabled_spec_and_binds_adapter_identity(self):
        spec = codex_cli_spec("/opt/codex")
        with self.assertRaises(ValueError):
            self.router.register_process_spec(spec, self.codex)
        enabled = type(spec).from_dict({**spec.to_dict(), "enabled": True})
        with self.assertRaises(ValueError):
            self.router.register_process_spec(enabled, FakeAdapter("other-agent"))
        process_router = BackendRouter()
        process_router.register_process_spec(enabled, self.codex, priority=5)
        request = RouteRequest.from_dict(ROUTE)
        self.assertEqual(process_router.select(request, now=1_001).target_agent_id, "codex")


if __name__ == "__main__":
    unittest.main()
