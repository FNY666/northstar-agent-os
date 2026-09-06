import sys
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
HOST_ROOT = COMPONENT_ROOT.parent / "northstar-host"
CONTRACT_ROOT = COMPONENT_ROOT.parent / "northstar-run-contract"
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(HOST_ROOT))
sys.path.insert(0, str(CONTRACT_ROOT))

from authorization import HostPolicy, authorize_run, verify_authorization  # noqa: E402
from binding import sign_binding, verify_binding  # noqa: E402
from handoff import (  # noqa: E402
    HandoffValidation,
    authorize_handoff,
    sign_attestation,
    sign_handoff_grant,
    verify_attestation,
    verify_handoff_grant,
)
from interop_contract import (  # noqa: E402
    AgentAttestation,
    AgentProfile,
    AgentRegistry,
    HandoffGrant,
    HandoffRequest,
)

BINDING_SECRET = b"handoff-binding-secret"
AUTHORIZATION_SECRET = b"handoff-authorization-secret"
ATTESTATION_SECRET = b"handoff-attestation-secret"
HANDOFF_SECRET = b"handoff-grant-secret"


def run_request():
    return {
        "schema_version": "northstar.run.v1",
        "run_id": "run-001",
        "actor_id": "actor-001",
        "workspace_id": "workspace-001",
        "task_kind": "implementation",
        "prompt": "Fix the isolated fixture.",
        "timeout_ms": 10_000,
        "requested_capabilities": ["workspace:read", "workspace:write"],
        "parent_run_id": None,
    }


def root_authorization(*, now=1_000, expires_at=1_900):
    run = run_request()
    binding = {
        "schema_version": run["schema_version"],
        "run_id": run["run_id"],
        "actor_id": run["actor_id"],
        "workspace_id": run["workspace_id"],
        "expires_at": expires_at,
    }
    verified = verify_binding(
        sign_binding(binding, BINDING_SECRET), BINDING_SECRET, now=now
    )
    return authorize_run(
        run,
        verified,
        HostPolicy.from_mapping(
            "policy-1", {"actor-001": ["workspace:read", "workspace:write"]}
        ),
        now=now,
        secret=AUTHORIZATION_SECRET,
        grant_ttl_seconds=500,
    )


def attestation(*, agent_id="claude-code", depth=0, expires_at=1_800, capabilities=None):
    return AgentAttestation.from_dict(
        {
            "schema_version": "northstar.agent-attestation.v1",
            "task_id": "task-001",
            "thread_id": "thread-001",
            "run_id": "run-001",
            "actor_id": "actor-001",
            "workspace_id": "workspace-001",
            "policy_revision": "policy-1",
            "agent_id": agent_id,
            "step_id": "implementation",
            "trace_id": "trace-001",
            "input_digest": "sha256:" + "1" * 64,
            "capabilities": capabilities or ["workspace:read", "workspace:write"],
            "delegation_depth": depth,
            "expires_at": expires_at,
        }
    )


def handoff_request(*, target="codex", capabilities=None, depth=1, deadline=1_700):
    return HandoffRequest.from_dict(
        {
            "schema_version": "northstar.handoff-request.v1",
            "handoff_id": "handoff-001" if depth == 1 else "handoff-002",
            "task_id": "task-001",
            "thread_id": "thread-001",
            "run_id": "run-001",
            "actor_id": "actor-001",
            "workspace_id": "workspace-001",
            "policy_revision": "policy-1",
            "source_agent_id": "claude-code" if depth == 1 else "codex",
            "target_agent_id": target,
            "step_id": "implementation",
            "trace_id": "trace-001",
            "input_digest": "sha256:" + "1" * 64,
            "requested_capabilities": capabilities or ["workspace:read"],
            "expected_postconditions": ["tests_pass"],
            "delegation_depth": depth,
            "deadline_at": deadline,
            "requested_at": 1_000,
            "idempotency_key": "handoff-attempt-1" if depth == 1 else "handoff-attempt-2",
        }
    )


def registry():
    value = AgentRegistry()
    value.register(
        AgentProfile.from_dict(
            {
                "schema_version": "northstar.agent-profile.v1",
                "agent_id": "claude-code",
                "provider": "anthropic",
                "version": "agent-v1",
                "capabilities": ["workspace:read", "workspace:write"],
            }
        )
    )
    value.register(
        AgentProfile.from_dict(
            {
                "schema_version": "northstar.agent-profile.v1",
                "agent_id": "codex",
                "provider": "openai",
                "version": "agent-v1",
                "capabilities": ["workspace:read", "workspace:write"],
            }
        )
    )
    return value


class HandoffAuthorizationTests(unittest.TestCase):
    def test_attestation_signs_and_verifies_without_returning_untrusted_claims(self):
        raw = attestation()
        token = sign_attestation(raw, ATTESTATION_SECRET)
        verified = verify_attestation(token, ATTESTATION_SECRET, now=1_001)
        self.assertTrue(verified.ok, verified.errors)
        self.assertEqual(verified.attestation, raw)
        wrong_secret = verify_attestation(token, b"wrong-secret", now=1_001)
        self.assertFalse(wrong_secret.ok)
        self.assertIsNone(wrong_secret.attestation)

    def test_root_authorization_and_attestation_issue_target_bound_grant(self):
        root = verify_authorization(
            root_authorization(), AUTHORIZATION_SECRET, now=1_000
        )
        source = verify_attestation(
            sign_attestation(attestation(), ATTESTATION_SECRET),
            ATTESTATION_SECRET,
            now=1_000,
        )
        request = handoff_request()
        token = authorize_handoff(
            request,
            parent_authorization=root,
            source_attestation=source,
            registry=registry(),
            now=1_001,
            current_policy_revision="policy-1",
            secret=HANDOFF_SECRET,
            grant_ttl_seconds=300,
        )
        result = verify_handoff_grant(token, HANDOFF_SECRET, now=1_100)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(result.grant.target_agent_id, "codex")
        self.assertEqual(result.grant.capabilities, ("workspace:read",))
        self.assertEqual(result.grant.expires_at, 1_301)

    def test_target_profile_is_capability_support_not_an_authorization_source(self):
        root = verify_authorization(root_authorization(), AUTHORIZATION_SECRET, now=1_000)
        source = verify_attestation(
            sign_attestation(attestation(), ATTESTATION_SECRET),
            ATTESTATION_SECRET,
            now=1_000,
        )
        request = handoff_request(capabilities=["workspace:write"])
        token = authorize_handoff(
            request,
            parent_authorization=root,
            source_attestation=source,
            registry=registry(),
            now=1_001,
            current_policy_revision="policy-1",
            secret=HANDOFF_SECRET,
        )
        self.assertTrue(verify_handoff_grant(token, HANDOFF_SECRET, now=1_002).ok)

        unsupported = handoff_request(target="read-only-agent", capabilities=["workspace:write"])
        with self.assertRaises(ValueError):
            authorize_handoff(
                unsupported,
                parent_authorization=root,
                source_attestation=source,
                registry=registry(),
                now=1_001,
                secret=HANDOFF_SECRET,
            )

    def test_handoff_cannot_widen_parent_capabilities_or_source_attestation(self):
        root = verify_authorization(root_authorization(), AUTHORIZATION_SECRET, now=1_000)
        read_only = verify_attestation(
            sign_attestation(
                attestation(capabilities=["workspace:read"]), ATTESTATION_SECRET
            ),
            ATTESTATION_SECRET,
            now=1_000,
        )
        with self.assertRaises(ValueError):
            authorize_handoff(
                handoff_request(capabilities=["workspace:write"]),
                parent_authorization=root,
                source_attestation=read_only,
                registry=registry(),
                now=1_001,
                secret=HANDOFF_SECRET,
            )

    def test_handoff_rejects_identity_policy_step_digest_and_target_mismatch(self):
        root = verify_authorization(root_authorization(), AUTHORIZATION_SECRET, now=1_000)
        source = verify_attestation(
            sign_attestation(attestation(), ATTESTATION_SECRET),
            ATTESTATION_SECRET,
            now=1_000,
        )
        for field, value in (
            ("task_id", "task-002"),
            ("thread_id", "thread-002"),
            ("run_id", "run-002"),
            ("actor_id", "actor-002"),
            ("workspace_id", "workspace-002"),
            ("policy_revision", "policy-2"),
            ("step_id", "other-step"),
            ("input_digest", "sha256:" + "2" * 64),
            ("target_agent_id", "unknown-agent"),
        ):
            candidate = handoff_request(target="codex")
            candidate_data = candidate.to_dict()
            candidate_data[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    authorize_handoff(
                        HandoffRequest.from_dict(candidate_data),
                        parent_authorization=root,
                        source_attestation=source,
                        registry=registry(),
                        now=1_001,
                        secret=HANDOFF_SECRET,
                    )

    def test_handoff_rejects_expired_parent_attestation_request_and_invalid_time(self):
        expired_root = verify_authorization(
            root_authorization(expires_at=1_500), AUTHORIZATION_SECRET, now=1_000
        )
        source = verify_attestation(
            sign_attestation(attestation(), ATTESTATION_SECRET), ATTESTATION_SECRET, now=1_000
        )
        with self.assertRaises(ValueError):
            authorize_handoff(
                handoff_request(),
                parent_authorization=verify_authorization(root_authorization(expires_at=1_500), AUTHORIZATION_SECRET, now=1_500),
                source_attestation=source,
                registry=registry(),
                now=1_501,
                secret=HANDOFF_SECRET,
            )

        expired_source = verify_attestation(
            sign_attestation(attestation(expires_at=1_000), ATTESTATION_SECRET),
            ATTESTATION_SECRET,
            now=1_000,
        )
        root = verify_authorization(root_authorization(), AUTHORIZATION_SECRET, now=1_000)
        with self.assertRaises(ValueError):
            authorize_handoff(
                handoff_request(),
                parent_authorization=root,
                source_attestation=expired_source,
                registry=registry(),
                now=1_001,
                secret=HANDOFF_SECRET,
            )

        with self.assertRaises(ValueError):
            authorize_handoff(
                handoff_request(deadline=1_000),
                parent_authorization=root,
                source_attestation=source,
                registry=registry(),
                now=1_001,
                secret=HANDOFF_SECRET,
            )

    def test_grant_tampering_expiry_unknown_fields_and_malformed_tokens_fail_closed(self):
        root = verify_authorization(root_authorization(), AUTHORIZATION_SECRET, now=1_000)
        source = verify_attestation(
            sign_attestation(attestation(), ATTESTATION_SECRET), ATTESTATION_SECRET, now=1_000
        )
        request = handoff_request()
        token = authorize_handoff(
            request,
            parent_authorization=root,
            source_attestation=source,
            registry=registry(),
            now=1_001,
            current_policy_revision="policy-1",
            secret=HANDOFF_SECRET,
            grant_ttl_seconds=100,
        )
        payload, signature = token.split(".", 1)
        replacement = "A" if signature[0] != "A" else "B"
        tampered = verify_handoff_grant(
            payload + "." + replacement + signature[1:], HANDOFF_SECRET, now=1_002
        )
        self.assertFalse(tampered.ok)
        self.assertIsNone(tampered.grant)
        expired = verify_handoff_grant(token, HANDOFF_SECRET, now=1_101)
        self.assertFalse(expired.ok)

        invalid = dict(request.to_dict())
        invalid["prompt"] = "must not be accepted"
        with self.assertRaises(ValueError):
            sign_handoff_grant(HandoffGrant.from_dict({**request.to_dict(), "expires_at": 1_500}).to_dict(), HANDOFF_SECRET)
        malformed = verify_handoff_grant("not-a-token", HANDOFF_SECRET, now=1_002)
        self.assertFalse(malformed.ok)

    def test_nested_handoff_can_only_narrow_an_existing_grant(self):
        root = verify_authorization(root_authorization(), AUTHORIZATION_SECRET, now=1_000)
        first_source = verify_attestation(
            sign_attestation(attestation(), ATTESTATION_SECRET), ATTESTATION_SECRET, now=1_000
        )
        first_request = handoff_request(capabilities=["workspace:read"])
        first_token = authorize_handoff(
            first_request,
            parent_authorization=root,
            source_attestation=first_source,
            registry=registry(),
            now=1_001,
            current_policy_revision="policy-1",
            secret=HANDOFF_SECRET,
        )
        first_grant = verify_handoff_grant(first_token, HANDOFF_SECRET, now=1_002)
        nested_source = verify_attestation(
            sign_attestation(attestation(agent_id="codex", depth=1, capabilities=["workspace:read"]), ATTESTATION_SECRET),
            ATTESTATION_SECRET,
            now=1_002,
        )
        nested_request = handoff_request(target="hermes", capabilities=["workspace:read"], depth=2, deadline=1_600)
        nested_registry = registry()
        nested_registry.register(
            AgentProfile.from_dict(
                {
                    "schema_version": "northstar.agent-profile.v1",
                    "agent_id": "hermes",
                    "provider": "community",
                    "version": "agent-v1",
                    "capabilities": ["workspace:read"],
                }
            )
        )
        nested_token = authorize_handoff(
            nested_request,
            parent_handoff=first_grant,
            source_attestation=nested_source,
            registry=nested_registry,
            now=1_003,
            current_policy_revision="policy-1",
            secret=HANDOFF_SECRET,
        )
        nested = verify_handoff_grant(nested_token, HANDOFF_SECRET, now=1_004)
        self.assertTrue(nested.ok, nested.errors)
        self.assertEqual(nested.grant.delegation_depth, 2)

        with self.assertRaises(ValueError):
            authorize_handoff(
                handoff_request(target="hermes", capabilities=["workspace:write"], depth=2),
                parent_handoff=first_grant,
                source_attestation=nested_source,
                registry=nested_registry,
                now=1_003,
                secret=HANDOFF_SECRET,
            )

    def test_nested_handoff_rejects_wrong_source_and_depth_widening(self):
        root = verify_authorization(root_authorization(), AUTHORIZATION_SECRET, now=1_000)
        source = verify_attestation(sign_attestation(attestation(), ATTESTATION_SECRET), ATTESTATION_SECRET, now=1_000)
        first = authorize_handoff(
            handoff_request(),
            parent_authorization=root,
            source_attestation=source,
            registry=registry(),
            now=1_001,
            current_policy_revision="policy-1",
            secret=HANDOFF_SECRET,
        )
        parent = verify_handoff_grant(first, HANDOFF_SECRET, now=1_002)
        wrong_source = verify_attestation(
            sign_attestation(attestation(agent_id="claude-code", depth=1), ATTESTATION_SECRET),
            ATTESTATION_SECRET,
            now=1_002,
        )
        with self.assertRaises(ValueError):
            authorize_handoff(
                handoff_request(target="codex", depth=2),
                parent_handoff=parent,
                source_attestation=wrong_source,
                registry=registry(),
                now=1_003,
                secret=HANDOFF_SECRET,
            )
        with self.assertRaises(ValueError):
            authorize_handoff(
                handoff_request(target="codex", depth=3),
                parent_handoff=parent,
                source_attestation=wrong_source,
                registry=registry(),
                now=1_003,
                secret=HANDOFF_SECRET,
            )

    def test_handoff_verifier_rejects_wrong_secret_malformed_and_unknown_grant_fields(self):
        grant = HandoffGrant.from_dict(
            {
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
                "idempotency_key": "handoff-attempt-1",
            }
        )
        token = sign_handoff_grant(grant, HANDOFF_SECRET)
        self.assertFalse(verify_handoff_grant(token, b"wrong", now=1_001).ok)
        self.assertFalse(verify_handoff_grant("x.y.z", HANDOFF_SECRET, now=1_001).ok)
        self.assertEqual(verify_handoff_grant(token, HANDOFF_SECRET, now=1_001).grant, grant)
    def test_current_policy_revision_is_required_and_must_match_root(self):
        root = verify_authorization(root_authorization(), AUTHORIZATION_SECRET, now=1_000)
        source = verify_attestation(
            sign_attestation(attestation(), ATTESTATION_SECRET),
            ATTESTATION_SECRET,
            now=1_000,
        )
        request = handoff_request()
        with self.assertRaises(ValueError):
            authorize_handoff(
                request,
                parent_authorization=root,
                source_attestation=source,
                registry=registry(),
                now=1_001,
                secret=HANDOFF_SECRET,
            )
        with self.assertRaises(ValueError):
            authorize_handoff(
                request,
                parent_authorization=root,
                source_attestation=source,
                registry=registry(),
                current_policy_revision="policy-2",
                now=1_001,
                secret=HANDOFF_SECRET,
            )
        token = authorize_handoff(
            request,
            parent_authorization=root,
            source_attestation=source,
            registry=registry(),
            current_policy_revision="policy-1",
            now=1_001,
            secret=HANDOFF_SECRET,
        )
        self.assertTrue(verify_handoff_grant(token, HANDOFF_SECRET, now=1_002).ok)

    def test_wildcard_capability_components_are_rejected(self):
        with self.assertRaises(ValueError):
            handoff_request(capabilities=["workspace:*"])


if __name__ == "__main__":
    unittest.main()

