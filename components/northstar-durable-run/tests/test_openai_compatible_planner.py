import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from planner_adapter import PlannerModelResponse  # noqa: E402
from openai_compatible_planner import (  # noqa: E402
    OpenAICompatiblePlannerCaller,
    OpenAICompatiblePlannerConfig,
)


def plan_value():
    return {
        "schema_version": "northstar.agent-plan.v1",
        "plan_id": "plan-provider-001",
        "plan_version": 1,
        "task_id": "task-provider-001",
        "thread_id": "thread-provider-001",
        "run_id": "run-provider-001",
        "actor_id": "actor-provider-001",
        "workspace_id": "workspace-provider-001",
        "policy_revision": "policy-1",
        "trace_id": "trace-provider-001",
        "steps": [{
            "schema_version": "northstar.agent-plan-step.v1",
            "step_id": "inspect",
            "action_id": "repo.read",
            "input_payload": {"path": "README.md"},
            "scope_snapshot": ["workspace:read"],
            "expected_postconditions": ["read_ok"],
            "idempotency_key": "provider-read-1",
            "max_attempts": 1,
            "deadline_at": 1_900,
        }],
    }


def provider_response(content):
    return json.dumps({
        "id": "response-1",
        "model": "attacker-model-must-be-ignored",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
    }).encode("utf-8")


class OpenAIPlannerCallerTests(unittest.TestCase):
    def config(self, **overrides):
        value = {
            "endpoint": "https://planner.example/v1/chat/completions",
            "api_key_env": "TEST_PLANNER_API_KEY",
            "model_id": "host-model",
            "provider": "host-provider",
            "model_revision": "host-revision-1",
        }
        value.update(overrides)
        return OpenAICompatiblePlannerConfig(**value)

    def test_request_is_strict_and_metadata_is_host_owned(self):
        captured = []

        def transport(request, timeout):
            captured.append((request, timeout))
            return provider_response(json.dumps({"plan": plan_value()}))

        with mock.patch.dict(os.environ, {"TEST_PLANNER_API_KEY": "fixture-key"}, clear=False):
            caller = OpenAICompatiblePlannerCaller(self.config(), transport=transport)
            response = caller(goal="Inspect the repository", context={"scope": "read-only"}, repair_error=None, attempt=1)

        self.assertIsInstance(response, PlannerModelResponse)
        self.assertEqual(response.model_id, "host-model")
        self.assertEqual(response.provider, "host-provider")
        self.assertEqual(response.model_revision, "host-revision-1")
        self.assertEqual(len(captured), 1)
        request, timeout = captured[0]
        self.assertEqual(request.full_url, "https://planner.example/v1/chat/completions")
        self.assertEqual(request.get_header("Authorization"), "Bearer fixture-key")
        self.assertEqual(timeout, 30.0)
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["model"], "host-model")
        self.assertEqual(body["response_format"], {"type": "json_object"})
        self.assertIn("Inspect the repository", body["messages"][1]["content"])
        self.assertNotIn("fixture-key", request.data.decode("utf-8"))

    def test_endpoint_and_secret_boundaries_fail_closed(self):
        with self.assertRaises(ValueError): self.config(endpoint="http://planner.example/chat")
        with self.assertRaises(ValueError): self.config(endpoint="https://user:pass@planner.example/chat")
        caller = OpenAICompatiblePlannerCaller(self.config(), transport=lambda request, timeout: provider_response("{}"))
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError): caller(goal="x", context={}, repair_error=None, attempt=1)

    def test_provider_response_is_bounded_and_malformed_content_rejected(self):
        config = self.config(max_response_bytes=100)
        oversized = OpenAICompatiblePlannerCaller(config, transport=lambda request, timeout: b"x" * 101)
        with mock.patch.dict(os.environ, {"TEST_PLANNER_API_KEY": "fixture-key"}, clear=False):
            with self.assertRaises(ValueError): oversized(goal="x", context={}, repair_error=None, attempt=1)

        malformed = OpenAICompatiblePlannerCaller(self.config(), transport=lambda request, timeout: provider_response("not-json"))
        with mock.patch.dict(os.environ, {"TEST_PLANNER_API_KEY": "fixture-key"}, clear=False):
            with self.assertRaises(ValueError): malformed(goal="x", context={}, repair_error=None, attempt=1)

    def test_transport_error_does_not_leak_provider_details(self):
        def transport(request, timeout):
            raise RuntimeError("Bearer fixture-key provider-internal-detail")

        caller = OpenAICompatiblePlannerCaller(self.config(), transport=transport)
        with mock.patch.dict(os.environ, {"TEST_PLANNER_API_KEY": "fixture-key"}, clear=False):
            with self.assertRaises(ValueError) as raised: caller(goal="x", context={}, repair_error=None, attempt=1)
        self.assertNotIn("fixture-key", str(raised.exception))
        self.assertNotIn("provider-internal-detail", str(raised.exception))


if __name__ == "__main__": unittest.main()
