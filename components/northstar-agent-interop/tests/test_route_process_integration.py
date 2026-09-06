import json
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
HOST_ROOT = COMPONENT_ROOT.parent / "northstar-host"
CONTRACT_ROOT = COMPONENT_ROOT.parent / "northstar-run-contract"
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(COMPONENT_ROOT / "tests"))
sys.path.insert(0, str(HOST_ROOT))
sys.path.insert(0, str(CONTRACT_ROOT))

from backend_router import BackendRouter, RouteRequest, assert_route_matches_handoff  # noqa: E402
from interop_contract import AgentProfile, AgentRegistry, HandoffRequest  # noqa: E402
from process_adapter import ProcessAgentAdapter  # noqa: E402
from process_backend import ProcessBackendSpec, build_process_adapter  # noqa: E402
from test_process_adapter import _handoff_token  # noqa: E402


class LocalRouteToProcessTests(unittest.TestCase):
    def test_router_decision_can_be_bound_to_process_adapter_without_authorizing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            script = root / "agent.py"
            script.write_text(
                "import json, pathlib, sys\n"
                "sys.stdin.read()\n"
                "pathlib.Path('out.json').write_text('{}')\n"
                "print(json.dumps({'status':'finished','output_digest':'sha256:' + '1' * 64,'artifact_refs':['artifact:out.json'],'verifier_verdict':'verified'}))\n",
                encoding="utf-8",
            )
            spec = ProcessBackendSpec.from_dict(
                {
                    "schema_version": "northstar.process-backend.v1",
                    "agent_id": "codex",
                    "provider": "openai",
                    "version": "cli-v1",
                    "executable": sys.executable,
                    "command_template": ["{executable}", str(script)],
                    "capability_map": {"workspace:read": "workspace:read"},
                    "allowed_env": [],
                    "enabled": True,
                }
            )
            adapter = build_process_adapter(
                spec,
                workspace_resolver=lambda workspace_id: workspace,
                context_loader=lambda context_ref: "opaque-context",
                timeout_seconds=2,
                max_output_bytes=16_384,
            )
            router = BackendRouter()
            router.register_process_spec(spec, adapter, priority=1)
            route = router.select(
                RouteRequest.from_dict(
                    {
                        "schema_version": "northstar.route-request.v1",
                        "task_id": "task-route-001",
                        "thread_id": "thread-route-001",
                        "run_id": "run-process-001",
                        "actor_id": "actor-process-001",
                        "workspace_id": "workspace-process-001",
                        "policy_revision": "policy-1",
                        "step_id": "execute",
                        "trace_id": "trace-route-001",
                        "input_digest": "sha256:" + "a" * 64,
                        "requested_capabilities": ["workspace:read"],
                        "deadline_at": 1_900,
                        "preferred_agent_ids": [],
                        "excluded_agent_ids": [],
                    }
                ),
                now=1_001,
                current_policy_revision="policy-1",
            )
            self.assertEqual(route.target_agent_id, "codex")
            self.assertIs(router.adapter_for(route, current_policy_revision="policy-1"), adapter)
            self.assertNotIn("authorization_token", route.to_dict())

            request = HandoffRequest.from_dict(
                {
                    "schema_version": "northstar.handoff-request.v1",
                    "handoff_id": "handoff-process-001",
                    "task_id": route.task_id,
                    "thread_id": route.thread_id,
                    "run_id": route.run_id,
                    "actor_id": route.actor_id,
                    "workspace_id": route.workspace_id,
                    "policy_revision": route.policy_revision,
                    "source_agent_id": "orchestrator",
                    "target_agent_id": route.target_agent_id,
                    "step_id": route.step_id,
                    "trace_id": route.trace_id,
                    "input_digest": route.input_digest,
                    "requested_capabilities": list(route.requested_capabilities),
                    "expected_postconditions": ["process_receipt"],
                    "delegation_depth": 1,
                    "deadline_at": 1_700,
                    "requested_at": 1_000,
                    "idempotency_key": "handoff-process-001-attempt-1",
                }
            )
            self.assertIsNone(assert_route_matches_handoff(route, request))

            receipt = adapter.execute(
                _handoff_token(),
                context_ref="ctx-process-001",
                handoff_secret=b"process-handoff-secret",
                current_policy_revision="policy-1",
                now=1_010,
            )
            self.assertEqual(receipt.status, "finished")
            self.assertEqual(receipt.target_agent_id, "codex")
            self.assertEqual(json.loads((workspace / "out.json").read_text()), {})


if __name__ == "__main__":
    unittest.main()
