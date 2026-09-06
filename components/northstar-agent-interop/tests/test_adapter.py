import hashlib
import sys
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
HOST_ROOT = COMPONENT_ROOT.parent / "northstar-host"
CONTRACT_ROOT = COMPONENT_ROOT.parent / "northstar-run-contract"
sys.path.insert(0, str(CONTRACT_ROOT))
sys.path.insert(0, str(HOST_ROOT))
sys.path.insert(0, str(COMPONENT_ROOT))

from interop_adapter import (  # noqa: E402
    AdapterExecution,
    AdapterReceipt,
    BackendAdapter,
    ContextEnvelope,
)
from authorization import HostPolicy, authorize_run, verify_authorization  # noqa: E402
from binding import sign_binding, verify_binding  # noqa: E402
from handoff import authorize_handoff, sign_attestation, verify_attestation, verify_handoff_grant  # noqa: E402
from interop_contract import AgentAttestation, AgentProfile, AgentRegistry, HandoffRequest  # noqa: E402

BINDING_SECRET = b"adapter-binding-secret"
AUTH_SECRET = b"adapter-authorization-secret"
ATTESTATION_SECRET = b"adapter-attestation-secret"
HANDOFF_SECRET = b"adapter-handoff-secret"


def run_request():
    return {
        "schema_version": "northstar.run.v1",
        "run_id": "run-001",
        "actor_id": "actor-001",
        "workspace_id": "workspace-001",
        "task_kind": "implementation",
        "prompt": "Fix the isolated fixture.",
        "timeout_ms": 10_000,
        "requested_capabilities": ["workspace:read"],
        "parent_run_id": None,
    }


def root_authorization():
    run = run_request()
    binding = {
        "schema_version": run["schema_version"],
        "run_id": run["run_id"],
        "actor_id": run["actor_id"],
        "workspace_id": run["workspace_id"],
        "expires_at": 1_900,
    }
    verified = verify_binding(sign_binding(binding, BINDING_SECRET), BINDING_SECRET, now=1_000)
    return authorize_run(
        run,
        verified,
        HostPolicy.from_mapping("policy-1", {"actor-001": ["workspace:read"]}),
        now=1_000,
        secret=AUTH_SECRET,
        grant_ttl_seconds=500,
    )


def source_attestation():
    return AgentAttestation.from_dict(
        {
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
            "expires_at": 1_800,
        }
    )


def registry():
    value = AgentRegistry()
    for agent_id, provider in (("claude-code", "anthropic"), ("codex", "openai")):
        value.register(
            AgentProfile.from_dict(
                {
                    "schema_version": "northstar.agent-profile.v1",
                    "agent_id": agent_id,
                    "provider": provider,
                    "version": "agent-v1",
                    "capabilities": ["workspace:read"],
                }
            )
        )
    return value


def grant_token():
    request = HandoffRequest.from_dict(
        {
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
            "deadline_at": 1_700,
            "requested_at": 1_000,
            "idempotency_key": "handoff-attempt-1",
        }
    )
    return authorize_handoff(
        request,
        parent_authorization=verify_authorization(root_authorization(), AUTH_SECRET, now=1_000),
        source_attestation=verify_attestation(
            sign_attestation(source_attestation(), ATTESTATION_SECRET),
            ATTESTATION_SECRET,
            now=1_000,
        ),
        registry=registry(),
        current_policy_revision="policy-1",
        now=1_001,
        secret=HANDOFF_SECRET,
    )


class AdapterBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.executions = []
        self.adapter = BackendAdapter(
            agent_id="codex",
            provider="openai",
            version="adapter-v1",
            executor=self.execute_backend,
        )

    def execute_backend(self, execution):
        self.executions.append(execution)
        return AdapterExecution(
            status="finished",
            output_digest="sha256:" + "2" * 64,
            artifact_refs=("artifact:result",),
            verifier_verdict="verified",
        )

    def test_context_envelope_contains_only_opaque_reference_and_digest(self):
        envelope = ContextEnvelope.from_dict(
            {
                "schema_version": "northstar.context-envelope.v1",
                "context_ref": "ctx-001",
                "input_digest": "sha256:" + "1" * 64,
                "expected_postconditions": ["tests_pass"],
            }
        )
        self.assertEqual(envelope.to_dict()["context_ref"], "ctx-001")
        self.assertNotIn("prompt", envelope.to_dict())
        self.assertNotIn("content", envelope.to_dict())
        with self.assertRaises(ValueError):
            ContextEnvelope.from_dict({**envelope.to_dict(), "prompt": "secret"})
        with self.assertRaises(ValueError):
            ContextEnvelope.from_dict({**envelope.to_dict(), "input_digest": "sha256:" + "A" * 64})

    def test_adapter_verifies_target_bound_grant_and_context_before_execution(self):
        token = grant_token()
        envelope = ContextEnvelope.from_dict(
            {
                "schema_version": "northstar.context-envelope.v1",
                "context_ref": "ctx-001",
                "input_digest": "sha256:" + "1" * 64,
                "expected_postconditions": ["tests_pass"],
            }
        )
        receipt = self.adapter.execute(
            token,
            envelope,
            handoff_secret=HANDOFF_SECRET,
            current_policy_revision="policy-1",
            now=1_002,
        )
        self.assertEqual(receipt.status, "finished")
        self.assertEqual(receipt.target_agent_id, "codex")
        self.assertEqual(receipt.verifier_verdict, "verified")
        self.assertEqual(len(self.executions), 1)
        self.assertEqual(self.executions[0].context_ref, "ctx-001")
        self.assertNotIn("prompt", self.executions[0].to_dict())

    def test_adapter_rejects_wrong_target_policy_expiry_context_and_malformed_backend_result(self):
        token = grant_token()
        envelope = ContextEnvelope.from_dict(
            {
                "schema_version": "northstar.context-envelope.v1",
                "context_ref": "ctx-001",
                "input_digest": "sha256:" + "1" * 64,
                "expected_postconditions": ["tests_pass"],
            }
        )
        for kwargs in (
            {"current_policy_revision": "policy-2"},
            {"now": 1_700},
        ):
            with self.assertRaises(ValueError):
                self.adapter.execute(
                    token,
                    envelope,
                    handoff_secret=HANDOFF_SECRET,
                    current_policy_revision=kwargs.get("current_policy_revision", "policy-1"),
                    now=kwargs.get("now", 1_002),
                )
        wrong_context = ContextEnvelope.from_dict(
            {
                "schema_version": "northstar.context-envelope.v1",
                "context_ref": "ctx-001",
                "input_digest": "sha256:" + "3" * 64,
                "expected_postconditions": ["tests_pass"],
            }
        )
        with self.assertRaises(ValueError):
            self.adapter.execute(
                token,
                wrong_context,
                handoff_secret=HANDOFF_SECRET,
                current_policy_revision="policy-1",
                now=1_002,
            )

        def bad_backend(_execution):
            return {"status": "finished"}

        bad = BackendAdapter(agent_id="codex", provider="openai", version="adapter-v1", executor=bad_backend)
        with self.assertRaises(ValueError):
            bad.execute(
                token,
                envelope,
                handoff_secret=HANDOFF_SECRET,
                current_policy_revision="policy-1",
                now=1_002,
            )
        self.assertEqual(self.executions, [])

    def test_adapter_receipt_requires_verified_postcondition_for_success(self):
        token = grant_token()
        envelope = ContextEnvelope.from_dict(
            {
                "schema_version": "northstar.context-envelope.v1",
                "context_ref": "ctx-001",
                "input_digest": "sha256:" + "1" * 64,
                "expected_postconditions": ["tests_pass"],
            }
        )

        def unverified(_execution):
            return AdapterExecution(
                status="finished",
                output_digest="sha256:" + "2" * 64,
                artifact_refs=(),
                verifier_verdict="unknown",
            )

        adapter = BackendAdapter(
            agent_id="codex", provider="openai", version="adapter-v1", executor=unverified
        )
        receipt = adapter.execute(
            token,
            envelope,
            handoff_secret=HANDOFF_SECRET,
            current_policy_revision="policy-1",
            now=1_002,
        )
        self.assertNotEqual(receipt.status, "finished")
        self.assertEqual(receipt.status, "unknown")
        self.assertEqual(receipt.verifier_verdict, "unknown")

    def test_adapter_receipt_round_trips_and_does_not_carry_raw_output(self):
        receipt = AdapterReceipt.from_dict(
            {
                "schema_version": "northstar.adapter-receipt.v1",
                "handoff_id": "handoff-001",
                "task_id": "task-001",
                "thread_id": "thread-001",
                "run_id": "run-001",
                "step_id": "implementation",
                "target_agent_id": "codex",
                "trace_id": "trace-001",
                "status": "finished",
                "output_digest": "sha256:" + "2" * 64,
                "artifact_refs": ["artifact:result"],
                "verifier_verdict": "verified",
                "error_class": None,
                "idempotency_key": "handoff-attempt-1",
            }
        )
        self.assertEqual(receipt.to_dict()["status"], "finished")
        with self.assertRaises(ValueError):
            AdapterReceipt.from_dict({**receipt.to_dict(), "raw_output": "do not persist"})
        with self.assertRaises(ValueError):
            AdapterReceipt.from_dict({**receipt.to_dict(), "status": "ok"})

    def test_adapter_is_idempotent_for_same_handoff_and_rejects_conflict(self):
        token = grant_token()
        envelope = ContextEnvelope.from_dict(
            {
                "schema_version": "northstar.context-envelope.v1",
                "context_ref": "ctx-001",
                "input_digest": "sha256:" + "1" * 64,
                "expected_postconditions": ["tests_pass"],
            }
        )
        first = self.adapter.execute(
            token, envelope, handoff_secret=HANDOFF_SECRET, current_policy_revision="policy-1", now=1_002
        )
        second = self.adapter.execute(
            token, envelope, handoff_secret=HANDOFF_SECRET, current_policy_revision="policy-1", now=1_003
        )
        self.assertEqual(first, second)
        self.assertEqual(len(self.executions), 1)
        conflict = ContextEnvelope.from_dict(
            {
                "schema_version": "northstar.context-envelope.v1",
                "context_ref": "ctx-002",
                "input_digest": "sha256:" + "1" * 64,
                "expected_postconditions": ["tests_pass"],
            }
        )
        with self.assertRaises(ValueError):
            self.adapter.execute(
                token, conflict, handoff_secret=HANDOFF_SECRET, current_policy_revision="policy-1", now=1_003
            )


if __name__ == "__main__":
    unittest.main()
