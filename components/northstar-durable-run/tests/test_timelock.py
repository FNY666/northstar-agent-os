"""Tests for the timelock-delayed execution of irreversible-tier tool calls.

Pure state-machine tests need nothing but the module; the gateway
integration tests reuse the authorization/approval scaffolding pattern
from test_action_gateway.py.
"""
import sys
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = COMPONENT_ROOT.parent / "northstar-run-contract"
HOST_ROOT = COMPONENT_ROOT.parent / "northstar-host"
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(CONTRACT_ROOT))
sys.path.insert(0, str(HOST_ROOT))

from action_gateway import (  # noqa: E402
    ActionGateway,
    ToolCall,
    ToolExecutionResult,
    ToolSpec,
    digest_arguments,
    sign_approval,
)
from authorization import HostPolicy, authorize_run  # noqa: E402
from binding import sign_binding, verify_binding  # noqa: E402
from timelock import (  # noqa: E402
    OPERATION_CANCELLED,
    OPERATION_DONE,
    OPERATION_READY,
    OPERATION_UNSET,
    OPERATION_WAITING,
    Timelock,
    hash_operation,
)

AUTH_SECRET = b"auth-secret-for-timelock-tests-001"
BINDING_SECRET = b"binding-secret-for-timelock-tests-002"
APPROVAL_SECRET = b"approval-secret-for-timelock-tests-003"

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


class HashOperationTests(unittest.TestCase):
    def test_deterministic_and_binding(self):
        first = hash_operation("tool.x", DIGEST_A, "call-1", "nonce-1")
        again = hash_operation("tool.x", DIGEST_A, "call-1", "nonce-1")
        self.assertEqual(first, again)
        self.assertTrue(first.startswith("sha256:"))
        # Any bound parameter change addresses a different operation id.
        self.assertNotEqual(
            first, hash_operation("tool.x", DIGEST_B, "call-1", "nonce-1")
        )
        self.assertNotEqual(
            first, hash_operation("tool.y", DIGEST_A, "call-1", "nonce-1")
        )
        self.assertNotEqual(
            first, hash_operation("tool.x", DIGEST_A, "call-1", "nonce-2")
        )

    def test_rejects_bad_inputs(self):
        with self.assertRaises(ValueError):
            hash_operation("", DIGEST_A, "call-1", "nonce-1")
        with self.assertRaises(ValueError):
            hash_operation("tool.x", "not-a-digest", "call-1", "nonce-1")


class TimelockStateMachineTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.timelock = Timelock(min_delay_s=300, audit=self.events.append)

    def schedule_op(self, **overrides):
        params = {
            "tool_name": "workspace.purge",
            "arguments_digest": DIGEST_A,
            "call_ref": "step-1",
            "delay_s": 3600,
            "now": 1_000,
            "nonce": "nonce-1",
        }
        params.update(overrides)
        return self.timelock.schedule(**params)

    def test_schedule_starts_waiting_and_becomes_ready(self):
        op = self.schedule_op()
        self.assertEqual(op.state, OPERATION_WAITING)
        self.assertEqual(op.ready_at, 4_600)
        self.assertEqual(self.timelock.state(op.operation_id, now=1_001), OPERATION_WAITING)
        self.assertEqual(self.timelock.state(op.operation_id, now=4_599), OPERATION_WAITING)
        self.assertEqual(self.timelock.state(op.operation_id, now=4_600), OPERATION_READY)
        self.assertEqual(self.timelock.state("sha256:" + "0" * 64, now=4_600), OPERATION_UNSET)

    def test_schedule_rejects_short_delay(self):
        with self.assertRaises(ValueError):
            self.schedule_op(delay_s=299)
        self.schedule_op(delay_s=300, nonce="nonce-2")

    def test_schedule_rejects_duplicate_id(self):
        self.schedule_op()
        with self.assertRaises(ValueError):
            self.schedule_op()
        # A different nonce is a different operation and schedules fine.
        self.schedule_op(nonce="nonce-2")

    def test_early_execute_is_blocked(self):
        op = self.schedule_op()
        with self.assertRaises(ValueError):
            self.timelock.authorize_execute(
                op.operation_id,
                tool_name="workspace.purge",
                arguments_digest=DIGEST_A,
                now=1_001,
            )

    def test_happy_path_authorize_then_mark_executed(self):
        op = self.schedule_op()
        authorized = self.timelock.authorize_execute(
            op.operation_id,
            tool_name="workspace.purge",
            arguments_digest=DIGEST_A,
            now=4_600,
        )
        self.assertEqual(authorized.operation_id, op.operation_id)
        done = self.timelock.mark_executed(op.operation_id, now=4_601)
        self.assertEqual(done.state, OPERATION_DONE)
        self.assertEqual(self.timelock.state(op.operation_id, now=4_602), OPERATION_DONE)
        # A second execution of the same operation is blocked: done, not ready.
        with self.assertRaises(ValueError):
            self.timelock.authorize_execute(
                op.operation_id,
                tool_name="workspace.purge",
                arguments_digest=DIGEST_A,
                now=4_603,
            )

    def test_failed_executor_leaves_operation_ready(self):
        # authorize does not change state: if the executor raises, the host
        # simply does not call mark_executed and the operation stays ready.
        op = self.schedule_op()
        self.timelock.authorize_execute(
            op.operation_id,
            tool_name="workspace.purge",
            arguments_digest=DIGEST_A,
            now=4_600,
        )
        self.assertEqual(self.timelock.state(op.operation_id, now=4_601), OPERATION_READY)

    def test_cancel_while_waiting_blocks_execute(self):
        op = self.schedule_op()
        cancelled = self.timelock.cancel(op.operation_id, now=1_500, cancelled_by="host-1")
        self.assertEqual(cancelled.state, OPERATION_CANCELLED)
        with self.assertRaises(ValueError):
            self.timelock.authorize_execute(
                op.operation_id,
                tool_name="workspace.purge",
                arguments_digest=DIGEST_A,
                now=4_600,
            )

    def test_cancel_while_ready_blocks_execute(self):
        op = self.schedule_op()
        self.timelock.cancel(op.operation_id, now=5_000, cancelled_by="host-1")
        self.assertEqual(self.timelock.state(op.operation_id, now=5_001), OPERATION_CANCELLED)
        with self.assertRaises(ValueError):
            self.timelock.authorize_execute(
                op.operation_id,
                tool_name="workspace.purge",
                arguments_digest=DIGEST_A,
                now=5_002,
            )

    def test_cancelled_id_cannot_be_rescheduled(self):
        op = self.schedule_op()
        self.timelock.cancel(op.operation_id, now=1_500, cancelled_by="host-1")
        with self.assertRaises(ValueError):
            self.schedule_op()

    def test_cancel_from_terminal_states_fails(self):
        op = self.schedule_op()
        self.timelock.cancel(op.operation_id, now=1_500, cancelled_by="host-1")
        with self.assertRaises(ValueError):
            self.timelock.cancel(op.operation_id, now=1_501, cancelled_by="host-1")
        with self.assertRaises(ValueError):
            self.timelock.cancel("sha256:" + "0" * 64, now=1_501, cancelled_by="host-1")
        op2 = self.schedule_op(nonce="nonce-9", call_ref="step-9")
        self.timelock.authorize_execute(
            op2.operation_id, tool_name="workspace.purge", arguments_digest=DIGEST_A, now=4_600
        )
        self.timelock.mark_executed(op2.operation_id, now=4_601)
        with self.assertRaises(ValueError):
            self.timelock.cancel(op2.operation_id, now=4_602, cancelled_by="host-1")

    def test_tampered_arguments_are_discovered(self):
        op = self.schedule_op()
        with self.assertRaises(ValueError):
            self.timelock.authorize_execute(
                op.operation_id,
                tool_name="workspace.purge",
                arguments_digest=DIGEST_B,
                now=4_600,
            )

    def test_wrong_tool_name_is_discovered(self):
        op = self.schedule_op()
        with self.assertRaises(ValueError):
            self.timelock.authorize_execute(
                op.operation_id,
                tool_name="workspace.other",
                arguments_digest=DIGEST_A,
                now=4_600,
            )

    def test_mark_executed_rechecks_readiness(self):
        # The _afterCall analog: a cancel landing between authorize and mark
        # must not be papered over into done.
        op = self.schedule_op()
        self.timelock.authorize_execute(
            op.operation_id, tool_name="workspace.purge", arguments_digest=DIGEST_A, now=4_600
        )
        self.timelock.cancel(op.operation_id, now=4_601, cancelled_by="host-1")
        with self.assertRaises(ValueError):
            self.timelock.mark_executed(op.operation_id, now=4_602)
        self.assertEqual(self.timelock.state(op.operation_id, now=4_603), OPERATION_CANCELLED)

    def test_all_transitions_are_audited(self):
        op = self.schedule_op()
        self.timelock.cancel(op.operation_id, now=1_500, cancelled_by="host-1")
        op2 = self.schedule_op(nonce="nonce-7", call_ref="step-7")
        self.timelock.authorize_execute(
            op2.operation_id, tool_name="workspace.purge", arguments_digest=DIGEST_A, now=4_600
        )
        self.timelock.mark_executed(op2.operation_id, now=4_601)
        kinds = [event["event_type"] for event in self.events]
        self.assertEqual(
            kinds,
            [
                "timelock.scheduled",
                "timelock.cancelled",
                "timelock.scheduled",
                "timelock.executed",
            ],
        )
        scheduled = self.events[0]
        self.assertEqual(scheduled["operation_id"], op.operation_id)
        self.assertEqual(scheduled["ready_at"], 4_600)
        self.assertEqual(self.events[1]["cancelled_by"], "host-1")
        self.assertEqual(self.events[3]["executed_at"], 4_601)

    def test_min_delay_is_configurable(self):
        strict = Timelock(min_delay_s=86_400)
        with self.assertRaises(ValueError):
            strict.schedule(
                tool_name="workspace.purge",
                arguments_digest=DIGEST_A,
                call_ref="step-1",
                delay_s=3_600,
                now=1_000,
                nonce="nonce-1",
            )


def valid_run(capability="workspace:write"):
    return {
        "schema_version": "northstar.run.v1",
        "run_id": "run-001",
        "actor_id": "actor-001",
        "workspace_id": "workspace-001",
        "task_kind": "implementation",
        "prompt": "Purge the isolated fixture.",
        "timeout_ms": 10_000,
        "requested_capabilities": [capability],
        "parent_run_id": None,
    }


def auth_token(run, *, now, expires_at=20_000):
    binding = {
        "schema_version": run["schema_version"],
        "run_id": run["run_id"],
        "actor_id": run["actor_id"],
        "workspace_id": run["workspace_id"],
        "expires_at": expires_at,
    }
    verified = verify_binding(sign_binding(binding, BINDING_SECRET), BINDING_SECRET, now=now)
    policy = HostPolicy.from_mapping("policy-1", {run["actor_id"]: run["requested_capabilities"]})
    return authorize_run(run, verified, policy, now=now, secret=AUTH_SECRET, grant_ttl_seconds=300)


def call_for(run, *, args, key="call-001", deadline_at=10_000):
    return ToolCall.from_dict(
        {
            "schema_version": "northstar.tool-call.v1",
            "task_id": "task-001",
            "thread_id": "thread-001",
            "run_id": run["run_id"],
            "step_id": "purge",
            "actor_id": run["actor_id"],
            "workspace_id": run["workspace_id"],
            "trace_id": "trace-001",
            "tool_name": "workspace.purge",
            "resource_id": run["workspace_id"],
            "requested_scope": ["workspace:write"],
            "arguments_digest": digest_arguments(args),
            "idempotency_key": key,
            "deadline_at": deadline_at,
        }
    )


def approval_for(run, call, *, expires_at=20_000):
    return sign_approval(
        {
            "schema_version": "northstar.approval.v3",
            "approval_id": "approval-001",
            "approver_id": "human-001",
            "task_id": call.task_id,
            "thread_id": call.thread_id,
            "run_id": run["run_id"],
            "step_id": call.step_id,
            "actor_id": run["actor_id"],
            "tool_name": call.tool_name,
            "resource_id": call.resource_id,
            "arguments_digest": call.arguments_digest,
            "idempotency_key": call.idempotency_key,
            "decision": "approved",
            "expires_at": expires_at,
        },
        APPROVAL_SECRET,
    )


class GatewayIrreversibleTierTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.timelock = Timelock(min_delay_s=300, audit=self.events.append)
        self.gateway = ActionGateway(approval_secret=APPROVAL_SECRET, timelock=self.timelock)
        self.invocations = []
        self.gateway.register(
            ToolSpec(
                name="workspace.purge",
                required_capability="workspace:write",
                required_scope="workspace:write",
                resource_kind="workspace",
                risk_level="high",
                executor=self.purge,
                irreversible=True,
            )
        )

    def purge(self, arguments):
        self.invocations.append(("purge", arguments))
        return {"status": "purged"}

    def scheduled_op(self, call, *, now=1_000, nonce="nonce-1"):
        return self.timelock.schedule(
            tool_name=call.tool_name,
            arguments_digest=call.arguments_digest,
            call_ref=call.step_id,
            delay_s=3_600,
            now=now,
            nonce=nonce,
        )

    def execute_kwargs(self, run, call, arguments, *, now, operation_id):
        return {
            "authorization_token": auth_token(run, now=now),
            "authorization_secret": AUTH_SECRET,
            "now": now,
            "approval_token": approval_for(run, call),
            "current_policy_revision": "policy-1",
            "timelock_operation_id": operation_id,
        }

    def test_irreversible_requires_high_risk_at_register(self):
        with self.assertRaises(ValueError):
            ToolSpec(
                name="workspace.read_file",
                required_capability="workspace:read",
                required_scope="workspace:read",
                resource_kind="workspace",
                risk_level="low",
                executor=lambda arguments: {},
                irreversible=True,
            )

    def test_irreversible_without_timelock_fails_closed(self):
        gateway = ActionGateway(approval_secret=APPROVAL_SECRET)
        gateway.register(
            ToolSpec(
                name="workspace.purge",
                required_capability="workspace:write",
                required_scope="workspace:write",
                resource_kind="workspace",
                risk_level="high",
                executor=self.purge,
                irreversible=True,
            )
        )
        run = valid_run()
        arguments = {"path": "src/main.py"}
        call = call_for(run, args=arguments)
        with self.assertRaises(ValueError):
            gateway.execute(
                call,
                arguments,
                authorization_token=auth_token(run, now=4_600),
                authorization_secret=AUTH_SECRET,
                now=4_600,
                approval_token=approval_for(run, call),
                current_policy_revision="policy-1",
                timelock_operation_id="sha256:" + "0" * 64,
            )
        self.assertEqual(self.invocations, [])

    def test_irreversible_without_operation_id_fails_closed(self):
        run = valid_run()
        arguments = {"path": "src/main.py"}
        call = call_for(run, args=arguments)
        with self.assertRaises(ValueError):
            self.gateway.execute(
                call,
                arguments,
                authorization_token=auth_token(run, now=4_600),
                authorization_secret=AUTH_SECRET,
                now=4_600,
                approval_token=approval_for(run, call),
                current_policy_revision="policy-1",
            )
        self.assertEqual(self.invocations, [])

    def test_early_execute_blocked_then_ready_executes(self):
        run = valid_run()
        arguments = {"path": "src/main.py"}
        call = call_for(run, args=arguments)
        op = self.scheduled_op(call)
        # Waiting: execution is blocked, no side effect.
        with self.assertRaises(ValueError):
            self.gateway.execute(
                call, arguments, **self.execute_kwargs(run, call, arguments, now=1_001, operation_id=op.operation_id)
            )
        self.assertEqual(self.invocations, [])
        # Ready: execution proceeds, operation is marked done.
        result = self.gateway.execute(
            call, arguments, **self.execute_kwargs(run, call, arguments, now=4_600, operation_id=op.operation_id)
        )
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.output, {"status": "purged"})
        self.assertEqual(result.idempotency_key, "call-001")
        self.assertEqual(self.invocations, [("purge", arguments)])
        self.assertEqual(self.timelock.state(op.operation_id, now=4_601), OPERATION_DONE)
        # The same operation cannot execute twice under a fresh key.
        replay = call_for(run, args=arguments, key="call-002")
        with self.assertRaises(ValueError):
            self.gateway.execute(
                replay,
                arguments,
                authorization_token=auth_token(run, now=4_602),
                authorization_secret=AUTH_SECRET,
                now=4_602,
                approval_token=approval_for(run, replay),
                current_policy_revision="policy-1",
                timelock_operation_id=op.operation_id,
            )
        self.assertEqual(len(self.invocations), 1)

    def test_cancel_blocks_execute(self):
        run = valid_run()
        arguments = {"path": "src/main.py"}
        call = call_for(run, args=arguments)
        op = self.scheduled_op(call)
        self.timelock.cancel(op.operation_id, now=4_700, cancelled_by="host-1")
        with self.assertRaises(ValueError):
            self.gateway.execute(
                call, arguments, **self.execute_kwargs(run, call, arguments, now=4_800, operation_id=op.operation_id)
            )
        self.assertEqual(self.invocations, [])

    def test_tampered_arguments_blocked(self):
        run = valid_run()
        approved_args = {"path": "src/main.py"}
        call = call_for(run, args=approved_args)
        op = self.scheduled_op(call)
        tampered = {"path": "src/other.py"}
        with self.assertRaises(ValueError):
            self.gateway.execute(
                call,
                tampered,
                authorization_token=auth_token(run, now=4_600),
                authorization_secret=AUTH_SECRET,
                now=4_600,
                approval_token=approval_for(run, call),
                current_policy_revision="policy-1",
                timelock_operation_id=op.operation_id,
            )
        self.assertEqual(self.invocations, [])

    def test_reversible_high_risk_tool_needs_no_timelock(self):
        self.gateway.register(
            ToolSpec(
                name="workspace.write_file",
                required_capability="workspace:write",
                required_scope="workspace:write",
                resource_kind="workspace",
                risk_level="high",
                executor=lambda arguments: {"status": "written"},
            )
        )
        run = valid_run()
        arguments = {"path": "src/main.py", "content": "fixed"}
        call = ToolCall.from_dict(
            {
                "schema_version": "northstar.tool-call.v1",
                "task_id": "task-001",
                "thread_id": "thread-001",
                "run_id": run["run_id"],
                "step_id": "write",
                "actor_id": run["actor_id"],
                "workspace_id": run["workspace_id"],
                "trace_id": "trace-001",
                "tool_name": "workspace.write_file",
                "resource_id": run["workspace_id"],
                "requested_scope": ["workspace:write"],
                "arguments_digest": digest_arguments(arguments),
                "idempotency_key": "call-010",
                "deadline_at": 10_000,
            }
        )
        result = self.gateway.execute(
            call,
            arguments,
            authorization_token=auth_token(run, now=1_001),
            authorization_secret=AUTH_SECRET,
            now=1_001,
            approval_token=approval_for(run, call),
            current_policy_revision="policy-1",
        )
        self.assertEqual(result.output, {"status": "written"})


if __name__ == "__main__":
    unittest.main()
