import sys
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))

from interop_contract import (  # noqa: E402
    AgentAttestation,
    AgentProfile,
    AgentRegistry,
    HandoffGrant,
    HandoffRequest,
    assert_attestation_identity,
    assert_grant_identity,
)


PROFILE = {
    "schema_version": "northstar.agent-profile.v1",
    "agent_id": "claude-code",
    "provider": "anthropic",
    "version": "agent-v1",
    "capabilities": ["workspace:read", "workspace:write"],
}

ATTESTATION = {
    "schema_version": "northstar.agent-attestation.v1",
    "task_id": "task-001",
    "thread_id": "thread-001",
    "run_id": "run-001",
    "actor_id": "actor-001",
    "workspace_id": "workspace-001",
    "policy_revision": "policy-1",
    "agent_id": "claude-code",
    "step_id": "implementation",
    "trace_id": "trace-001",
    "input_digest": "sha256:" + "1" * 64,
    "capabilities": ["workspace:read"],
    "delegation_depth": 0,
    "expires_at": 2_000,
}

REQUEST = {
    "schema_version": "northstar.handoff-request.v1",
    "handoff_id": "handoff-001",
    "task_id": "task-001",
    "thread_id": "thread-001",
    "run_id": "run-001",
    "actor_id": "actor-001",
    "workspace_id": "workspace-001",
    "policy_revision": "policy-1",
    "source_agent_id": "claude-code",
    "target_agent_id": "codex",
    "step_id": "implementation",
    "trace_id": "trace-001",
    "input_digest": "sha256:" + "1" * 64,
    "requested_capabilities": ["workspace:read"],
    "expected_postconditions": ["tests_pass"],
    "delegation_depth": 1,
    "deadline_at": 1_900,
    "requested_at": 1_000,
    "idempotency_key": "handoff-001-attempt-1",
}

GRANT = {
    "schema_version": "northstar.handoff-grant.v1",
    "handoff_id": "handoff-001",
    "task_id": "task-001",
    "thread_id": "thread-001",
    "run_id": "run-001",
    "actor_id": "actor-001",
    "workspace_id": "workspace-001",
    "policy_revision": "policy-1",
    "source_agent_id": "claude-code",
    "target_agent_id": "codex",
    "step_id": "implementation",
    "trace_id": "trace-001",
    "input_digest": "sha256:" + "1" * 64,
    "capabilities": ["workspace:read"],
    "expected_postconditions": ["tests_pass"],
    "delegation_depth": 1,
    "expires_at": 1_500,
    "idempotency_key": "handoff-001-attempt-1",
}


class InteropContractTests(unittest.TestCase):
    def test_agent_profile_round_trips_and_normalizes_capabilities(self):
        profile = AgentProfile.from_dict(PROFILE)
        self.assertEqual(profile.to_dict(), PROFILE)
        self.assertEqual(profile.capabilities, frozenset(PROFILE["capabilities"]))
        registry = AgentRegistry()
        registry.register(profile)
        self.assertIs(registry.get("claude-code"), profile)
        with self.assertRaises(ValueError):
            registry.register(profile)

    def test_agent_profile_rejects_unknown_fields_invalid_ids_and_capabilities(self):
        for field, value in (
            ("unknown", True),
            ("agent_id", "agent/escape"),
            ("provider", ""),
            ("version", "version with space"),
            ("capabilities", "workspace:read"),
            ("capabilities", ["workspace:read", "workspace:read"]),
            ("capabilities", ["workspace/read"]),
        ):
            invalid = dict(PROFILE)
            invalid[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    AgentProfile.from_dict(invalid)

    def test_attestation_round_trips_and_canonicalizes(self):
        attestation = AgentAttestation.from_dict(ATTESTATION)
        self.assertEqual(attestation.to_dict(), ATTESTATION)
        reversed_fields = {key: ATTESTATION[key] for key in reversed(ATTESTATION)}
        self.assertEqual(
            attestation.canonical_json(),
            AgentAttestation.from_dict(reversed_fields).canonical_json(),
        )

    def test_attestation_rejects_unknown_fields_bad_digest_expiry_depth_and_scope(self):
        cases = [
            ("prompt", "must not be embedded"),
            ("input_digest", "sha256:" + "A" * 64),
            ("input_digest", "not-a-digest"),
            ("expires_at", True),
            ("expires_at", 0),
            ("delegation_depth", -1),
            ("delegation_depth", True),
            ("capabilities", ["workspace:read", "workspace:read"]),
        ]
        for field, value in cases:
            invalid = dict(ATTESTATION)
            invalid[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    AgentAttestation.from_dict(invalid)

    def test_handoff_request_round_trips_with_bounded_postconditions(self):
        request = HandoffRequest.from_dict(REQUEST)
        self.assertEqual(request.to_dict(), REQUEST)
        self.assertEqual(request.canonical_json(), HandoffRequest.from_dict(dict(REQUEST)).canonical_json())

    def test_handoff_request_rejects_unknown_fields_invalid_target_and_time_order(self):
        for field, value in (
            ("secret", "do not carry secrets"),
            ("source_agent_id", "claude/code"),
            ("target_agent_id", ""),
            ("requested_capabilities", "workspace:read"),
            ("expected_postconditions", ["tests_pass", "tests_pass"]),
            ("delegation_depth", 0),
            ("deadline_at", 999),
            ("requested_at", True),
            ("idempotency_key", "key with space"),
        ):
            invalid = dict(REQUEST)
            invalid[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    HandoffRequest.from_dict(invalid)

    def test_handoff_grant_round_trips_without_prompt_or_raw_context(self):
        grant = HandoffGrant.from_dict(GRANT)
        self.assertEqual(grant.to_dict(), GRANT)
        self.assertNotIn("prompt", grant.to_dict())
        self.assertNotIn("secret", grant.to_dict())
        self.assertNotIn("context", grant.to_dict())

    def test_handoff_grant_rejects_unknown_fields_invalid_expiry_depth_and_digest(self):
        for field, value in (
            ("prompt", "must not be embedded"),
            ("unexpected", True),
            ("expires_at", 0),
            ("delegation_depth", 0),
            ("input_digest", "sha256:" + "F" * 64),
            ("capabilities", ["workspace:read", "workspace:read"]),
        ):
            invalid = dict(GRANT)
            invalid[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    HandoffGrant.from_dict(invalid)

    def test_capability_lists_are_canonicalized_for_cross_backend_interop(self):
        reversed_attestation = dict(ATTESTATION)
        reversed_attestation["capabilities"] = ["workspace:write", "workspace:read"]
        self.assertEqual(
            AgentAttestation.from_dict(reversed_attestation).to_dict()["capabilities"],
            ["workspace:read", "workspace:write"],
        )
        reversed_request = dict(REQUEST)
        reversed_request["requested_capabilities"] = ["workspace:write", "workspace:read"]
        self.assertEqual(
            HandoffRequest.from_dict(reversed_request).to_dict()["requested_capabilities"],
            ["workspace:read", "workspace:write"],
        )

    def test_grant_identity_includes_policy_revision(self):
        request = HandoffRequest.from_dict(REQUEST)
        grant_data = dict(GRANT)
        grant_data["policy_revision"] = "policy-2"
        with self.assertRaises(ValueError):
            assert_grant_identity(request, HandoffGrant.from_dict(grant_data))

    def test_attestation_identity_must_match_handoff_request(self):
        attestation = AgentAttestation.from_dict(ATTESTATION)
        request = HandoffRequest.from_dict(REQUEST)
        self.assertIsNone(assert_attestation_identity(attestation, request))
        for field, value in (
            ("task_id", "task-002"),
            ("thread_id", "thread-002"),
            ("run_id", "run-002"),
            ("actor_id", "actor-002"),
            ("workspace_id", "workspace-002"),
            ("policy_revision", "policy-2"),
            ("source_agent_id", "other-agent"),
            ("step_id", "other-step"),
            ("trace_id", "trace-002"),
            ("input_digest", "sha256:" + "2" * 64),
        ):
            invalid = dict(REQUEST)
            invalid[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    assert_attestation_identity(attestation, HandoffRequest.from_dict(invalid))

    def test_grant_identity_must_match_handoff_request(self):
        request = HandoffRequest.from_dict(REQUEST)
        grant = HandoffGrant.from_dict(GRANT)
        self.assertIsNone(assert_grant_identity(request, grant))
        for field, value in (
            ("handoff_id", "handoff-002"),
            ("target_agent_id", "other-agent"),
            ("step_id", "other-step"),
            ("expected_postconditions", ["different"]),
            ("idempotency_key", "other-key"),
        ):
            invalid = dict(GRANT)
            invalid[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    assert_grant_identity(request, HandoffGrant.from_dict(invalid))

    def test_cross_identity_helpers_reject_wrong_contract_types(self):
        with self.assertRaises(ValueError):
            assert_attestation_identity(AgentProfile.from_dict(PROFILE), HandoffRequest.from_dict(REQUEST))
        with self.assertRaises(ValueError):
            assert_grant_identity(HandoffRequest.from_dict(REQUEST), AgentProfile.from_dict(PROFILE))


if __name__ == "__main__":
    unittest.main()
