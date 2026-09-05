import hashlib
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

from action_gateway import ActionGateway, ToolCall, ToolSpec, digest_arguments  # noqa: E402
from authorization import HostPolicy, authorize_run  # noqa: E402
from binding import sign_binding, verify_binding  # noqa: E402
from durable_contract import RunContract  # noqa: E402
from event_store import EventStore  # noqa: E402
from runner import DurableRunner, StepPlan  # noqa: E402
from trace_metrics import TraceRecorder  # noqa: E402
from verifier import make_final_receipt, verify_run_completion  # noqa: E402


BINDING_SECRET = b"vertical-binding-secret"
AUTHORIZATION_SECRET = b"vertical-authorization-secret"
APPROVAL_SECRET = b"vertical-approval-secret"
DERIVATION_SECRET = b"vertical-derivation-secret"


class DurableVerticalSliceTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.run = RunContract.from_dict(
            {
                "schema_version": "northstar.durable-run.v1",
                "task_id": "task-vertical-001",
                "thread_id": "thread-vertical-001",
                "run_id": "run-vertical-001",
                "parent_run_id": None,
                "status": "planned",
                "deadline_at": 2_000,
                "scope_snapshot": ["workspace:read", "workspace:write"],
                "trace_id": "trace-vertical-001",
            }
        )
        self.store = EventStore(self.root / "events.jsonl")
        self.runner = DurableRunner(
            self.run,
            self.store,
            lease_path=self.root / "run.lease.json",
            lease_ttl_seconds=20,
        )
        self.trace = TraceRecorder(
            task_id=self.run.task_id,
            thread_id=self.run.thread_id,
            run_id=self.run.run_id,
            trace_id=self.run.trace_id,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def _binding_token(self):
        return sign_binding(
            {
                "schema_version": "northstar.run.v1",
                "run_id": self.run.run_id,
                "actor_id": "actor-vertical-001",
                "workspace_id": "workspace-vertical-001",
                "expires_at": 1_900,
            },
            BINDING_SECRET,
        )

    def test_full_local_slice_requires_independent_verification_for_final_ok(self):
        target = self.workspace / "src" / "main.py"
        target.parent.mkdir(mode=0o700)
        gateway = ActionGateway(approval_secret=APPROVAL_SECRET)
        invocations = []

        def write_file(arguments):
            invocations.append(arguments["path"])
            (self.workspace / arguments["path"]).write_text(
                arguments["content"], encoding="utf-8"
            )
            return {"written": arguments["path"]}

        gateway.register(
            ToolSpec(
                name="workspace.write_file",
                required_capability="workspace:write",
                required_scope="workspace:write",
                resource_kind="workspace",
                risk_level="low",
                executor=write_file,
            )
        )
        run_request = {
            "schema_version": "northstar.run.v1",
            "run_id": self.run.run_id,
            "actor_id": "actor-vertical-001",
            "workspace_id": "workspace-vertical-001",
            "task_kind": "implementation",
            "prompt": "Fix the isolated fixture.",
            "timeout_ms": 10_000,
            "requested_capabilities": ["workspace:write"],
            "parent_run_id": None,
        }
        binding_token = self._binding_token()
        binding = verify_binding(binding_token, BINDING_SECRET, now=1_000)
        grant = authorize_run(
            run_request,
            binding,
            HostPolicy.from_mapping(
                "policy-vertical-1", {"actor-vertical-001": ["workspace:write"]}
            ),
            now=1_000,
            secret=AUTHORIZATION_SECRET,
        )
        arguments = {"path": "src/main.py", "content": "print('fixed')\n"}
        call = ToolCall.from_dict(
            {
                "schema_version": "northstar.tool-call.v1",
                "task_id": self.run.task_id,
                "thread_id": self.run.thread_id,
                "run_id": self.run.run_id,
                "step_id": "edit",
                "actor_id": run_request["actor_id"],
                "workspace_id": run_request["workspace_id"],
                "trace_id": self.run.trace_id,
                "tool_name": "workspace.write_file",
                "resource_id": run_request["workspace_id"],
                "requested_scope": ["workspace:write"],
                "arguments_digest": digest_arguments(arguments),
                "idempotency_key": "vertical-write-1",
                "deadline_at": 1_800,
            }
        )
        action_result = gateway.execute(
            call,
            arguments,
            authorization_token=grant,
            authorization_secret=AUTHORIZATION_SECRET,
            current_policy_revision="policy-vertical-1",
            now=1_001,
            run=run_request,
        )
        self.assertEqual(action_result.status, "ok")
        self.assertEqual(invocations, ["src/main.py"])

        state = self.runner.execute(
            [
                StepPlan(
                    step_id="edit",
                    input_payload=arguments,
                    scope_snapshot=["workspace:write"],
                    expected_postconditions=["tests_pass"],
                    action=lambda key: {"tool": "workspace.write_file", "key": key},
                )
            ],
            owner_id="worker-vertical",
            now=1_002,
        )
        self.assertEqual(state["status"], "finished")
        verification = verify_run_completion(
            self.run,
            self.store,
            workspace=self.workspace,
            required_files={
                "src/main.py": "sha256:" + hashlib.sha256(target.read_bytes()).hexdigest()
            },
            test_exit_code=0,
            now=1_003,
            claimed_status="ok",
        )
        self.assertEqual(verification.verdict, "verified")
        receipt = make_final_receipt(self.run, verification)
        self.assertEqual(receipt["status"], "ok")
        self.assertEqual(receipt["verification"], "verified")

        recorder_span = {
            "schema_version": "northstar.trace-span.v1",
            "span_id": "span-vertical-001",
            "parent_span_id": None,
            "trace_id": self.run.trace_id,
            "task_id": self.run.task_id,
            "thread_id": self.run.thread_id,
            "run_id": self.run.run_id,
            "step_id": "verify",
            "span_kind": "guardrail",
            "name": "postcondition",
            "started_at": 1_003,
            "ended_at": 1_004,
            "attempt": 1,
            "tool_name": None,
            "scope_digest": "sha256:" + "3" * 64,
            "approval_state": "not_required",
            "status": "ok",
            "error_class": None,
            "verifier_verdict": "verified",
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_micros": 0,
        }
        self.assertEqual(self.trace.record(recorder_span).verifier_verdict, "verified")

    def test_runner_success_without_real_artifact_or_test_observation_is_not_ok(self):
        state = self.runner.execute(
            [
                StepPlan(
                    step_id="edit",
                    input_payload={"file": "src/main.py"},
                    scope_snapshot=["workspace:write"],
                    expected_postconditions=["tests_pass"],
                    action=lambda key: {"claimed": "finished"},
                )
            ],
            owner_id="worker-vertical",
            now=1_000,
        )
        self.assertEqual(state["status"], "finished")
        verification = verify_run_completion(
            self.run,
            self.store,
            workspace=self.workspace,
            required_files={"src/main.py": "sha256:" + "0" * 64},
            test_exit_code=None,
            now=1_001,
            claimed_status="ok",
        )
        self.assertNotEqual(verification.verdict, "verified")
        self.assertNotEqual(make_final_receipt(self.run, verification)["status"], "ok")

    def test_event_history_can_rebuild_final_state_after_new_store_instance(self):
        self.runner.execute(
            [
                StepPlan(
                    step_id="inspect",
                    input_payload={"file": "src/main.py"},
                    scope_snapshot=["workspace:read"],
                    expected_postconditions=["inspection_recorded"],
                    action=lambda key: {"key": key},
                )
            ],
            owner_id="worker-vertical",
            now=1_000,
        )
        reopened = EventStore(self.root / "events.jsonl")
        self.assertEqual(
            reopened.replay(self.run.run_id),
            self.store.replay(self.run.run_id),
        )
        self.assertEqual(reopened.restore(self.run.run_id)["status"], "finished")


if __name__ == "__main__":
    unittest.main()
