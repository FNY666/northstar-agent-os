import hashlib
import json
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
    ToolSpec,
    digest_arguments,
    sign_approval,
)
from authorization import HostPolicy, authorize_run  # noqa: E402
from binding import sign_binding, verify_binding  # noqa: E402
from tool_receipt import (  # noqa: E402
    TOOL_RECEIPT_SCHEMA_VERSION,
    make_tool_receipt,
    receipt_audit_record,
    verify_tool_receipt,
)

AUTH_SECRET = b"auth-secret-fixture-32-bytes-long!!"
BINDING_SECRET = b"binding-secret-fixture-32bytes!!"
APPROVAL_SECRET = b"approval-secret-fixture-32bytes!"


def valid_run(capability="workspace:write"):
    return {
        "schema_version": "northstar.run.v1",
        "run_id": "run-001",
        "actor_id": "actor-001",
        "workspace_id": "workspace-001",
        "task_kind": "implementation",
        "prompt": "Fix the isolated fixture.",
        "timeout_ms": 10_000,
        "requested_capabilities": [capability],
        "parent_run_id": None,
    }


def auth_token(run, *, capability=None, now=1_000, expires_at=2_000):
    capability = capability or run["requested_capabilities"][0]
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
    policy = HostPolicy.from_mapping("policy-1", {run["actor_id"]: [capability]})
    return authorize_run(
        run,
        verified,
        policy,
        now=now,
        secret=AUTH_SECRET,
        grant_ttl_seconds=300,
    )


def call_for(run, *, tool_name="workspace.write_file", args=None, scope=None,
             risk="high", key="call-001", step="edit"):
    args = args or {"path": "notes.txt", "content": "hi\n"}
    scope = scope or ["workspace:write"]
    return ToolCall.from_dict(
        {
            "schema_version": "northstar.tool-call.v1",
            "task_id": "task-001",
            "thread_id": "thread-001",
            "run_id": run["run_id"],
            "step_id": step,
            "actor_id": run["actor_id"],
            "workspace_id": run["workspace_id"],
            "trace_id": "trace-001",
            "tool_name": tool_name,
            "resource_id": run["workspace_id"],
            "requested_scope": scope,
            "arguments_digest": digest_arguments(args),
            "idempotency_key": key,
            "deadline_at": 1_900,
        }
    )


def approval_dict_for(run, call, *, decision="approved", expires_at=2_000):
    return {
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
        "decision": decision,
        "expires_at": expires_at,
    }


def approval_for(run, call, *, decision="approved", expires_at=2_000):
    return sign_approval(
        approval_dict_for(run, call, decision=decision, expires_at=expires_at),
        APPROVAL_SECRET,
    )


def canonical_hex(value):
    return hashlib.sha256(
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


class ToolReceiptFormatTests(unittest.TestCase):
    """The receipt is recomputable by a third party with no Northstar code."""

    def test_receipt_id_matches_independent_recomputation(self):
        args = {"path": "notes.txt", "content": "hi\n"}
        result = {"status": "written"}
        receipt = make_tool_receipt(
            tool_name="workspace.write_file",
            task_id="task-001",
            thread_id="thread-001",
            run_id="run-001",
            call_id="edit",
            actor_id="actor-001",
            workspace_id="workspace-001",
            idempotency_key="call-001",
            arguments=args,
            result=result,
            approval=None,
            issued_at=1_500,
        )
        self.assertEqual(receipt["schema_version"], TOOL_RECEIPT_SCHEMA_VERSION)
        expected = f"tool:{canonical_hex(args)}:{canonical_hex(result)}"
        self.assertEqual(receipt["receipt_id"], expected)
        # The arguments segment is the same hex the approval digest carries
        # after its "sha256:" prefix — the approval -> receipt link is direct.
        self.assertEqual(
            receipt["arguments_digest"], digest_arguments(args).split(":", 1)[1]
        )
        self.assertTrue(verify_tool_receipt(receipt, args, result))

    def test_approval_link_and_low_risk_absence(self):
        args = {"path": "notes.txt", "content": "hi\n"}
        approval = {
            "schema_version": "northstar.approval.v3",
            "approval_id": "approval-001",
            "approver_id": "human-001",
        }
        receipt = make_tool_receipt(
            tool_name="t",
            task_id="t",
            thread_id="t",
            run_id="r",
            call_id="c",
            actor_id="a",
            workspace_id="w",
            idempotency_key="k",
            arguments=args,
            result={"ok": True},
            approval=approval,
            issued_at=1_500,
        )
        self.assertEqual(receipt["approval_id"], "approval-001")
        self.assertEqual(receipt["approval_digest"], canonical_hex(approval))
        self.assertTrue(
            verify_tool_receipt(receipt, args, {"ok": True}, approval=approval)
        )
        # Absence of an approval is explicit, never implied.
        plain = make_tool_receipt(
            tool_name="t",
            task_id="t",
            thread_id="t",
            run_id="r",
            call_id="c",
            actor_id="a",
            workspace_id="w",
            idempotency_key="k",
            arguments=args,
            result={"ok": True},
            approval=None,
            issued_at=1_500,
        )
        self.assertIsNone(plain["approval_id"])
        self.assertIsNone(plain["approval_digest"])

    def test_tamper_is_always_detected(self):
        args = {"path": "notes.txt", "content": "hi\n"}
        result = {"status": "written"}
        receipt = make_tool_receipt(
            tool_name="t",
            task_id="t",
            thread_id="t",
            run_id="r",
            call_id="c",
            actor_id="a",
            workspace_id="w",
            idempotency_key="k",
            arguments=args,
            result=result,
            approval=None,
            issued_at=1_500,
        )
        with self.assertRaises(ValueError):
            verify_tool_receipt(receipt, {"path": "notes.txt", "content": "EVIL\n"}, result)
        with self.assertRaises(ValueError):
            verify_tool_receipt(receipt, args, {"status": "deleted-everything"})
        tampered = dict(receipt, receipt_id="tool:" + "0" * 64 + ":" + "0" * 64)
        with self.assertRaises(ValueError):
            verify_tool_receipt(tampered, args, result)
        malformed = dict(receipt, receipt_id="not-a-receipt")
        with self.assertRaises(ValueError):
            verify_tool_receipt(malformed, args, result)

    def test_approval_mismatch_is_detected(self):
        args = {"p": "x"}
        approval = {"approval_id": "approval-001"}
        other = {"approval_id": "approval-002"}
        receipt = make_tool_receipt(
            tool_name="t",
            task_id="t",
            thread_id="t",
            run_id="r",
            call_id="c",
            actor_id="a",
            workspace_id="w",
            idempotency_key="k",
            arguments=args,
            result={"ok": True},
            approval=approval,
            issued_at=1_500,
        )
        with self.assertRaises(ValueError):
            verify_tool_receipt(receipt, args, {"ok": True}, approval=other)
        with self.assertRaises(ValueError):
            verify_tool_receipt(receipt, args, {"ok": True}, approval=None)

    def test_audit_record_is_deterministic(self):
        receipt = make_tool_receipt(
            tool_name="t",
            task_id="t",
            thread_id="t",
            run_id="run-001",
            call_id="c",
            actor_id="a",
            workspace_id="w",
            idempotency_key="k",
            arguments={"p": "x"},
            result={"ok": True},
            approval=None,
            issued_at=1_500,
        )
        record = receipt_audit_record(receipt)
        self.assertEqual(record["event"], "tool.receipt")
        self.assertEqual(record["component"], "northstar-durable-run")
        self.assertEqual(record["payload"]["receipt_id"], receipt["receipt_id"])
        self.assertEqual(record["run_id"], "run-001")
        # ts derives from issued_at: two runs of the same fixture agree.
        self.assertEqual(
            receipt_audit_record(receipt)["ts"], record["ts"]
        )


class GatewayReceiptTests(unittest.TestCase):
    def setUp(self):
        self.sink_records = []
        self.gateway = ActionGateway(
            approval_secret=APPROVAL_SECRET,
            audit_sink=self.sink_records.append,
        )
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

    def _execute(self, gateway=None, args=None, key="call-001", now=1_500):
        gateway = gateway or self.gateway
        run = valid_run()
        args = args if args is not None else {"path": "notes.txt", "content": "hi\n"}
        call = call_for(run, args=args, key=key)
        approval = approval_dict_for(run, call)
        token = sign_approval(approval, APPROVAL_SECRET)
        result = gateway.execute(
            call,
            args,
            authorization_token=auth_token(run, now=now),
            authorization_secret=AUTH_SECRET,
            now=now,
            approval_token=token,
            current_policy_revision="policy-1",
            run=run,
        )
        return result, call, args, approval

    def test_successful_call_mints_and_emits_receipt(self):
        result, call, args, approval = self._execute()
        receipt = self.gateway.receipt_for("call-001")
        self.assertIsNotNone(receipt)
        self.assertEqual(
            receipt["receipt_id"],
            f"tool:{canonical_hex(args)}:{canonical_hex(result.output)}",
        )
        self.assertEqual(receipt["approval_id"], "approval-001")
        self.assertEqual(receipt["approval_digest"], canonical_hex(approval))
        self.assertTrue(
            verify_tool_receipt(receipt, args, result.output, approval=approval)
        )
        # One audit record per successful call, carrying the whole receipt.
        self.assertEqual(len(self.sink_records), 1)
        record = self.sink_records[0]
        self.assertEqual(record["event"], "tool.receipt")
        self.assertEqual(record["payload"]["receipt_id"], receipt["receipt_id"])

    def test_receipt_links_the_approving_call_only(self):
        _result, call, args, approval = self._execute(key="call-001")
        receipt = self.gateway.receipt_for("call-001")
        # The receipt's arguments segment is exactly what the approval bound.
        self.assertEqual(
            receipt["arguments_digest"], call.arguments_digest.split(":", 1)[1]
        )
        # A receipt minted for different args would not verify here.
        self.assertTrue(
            verify_tool_receipt(
                receipt, args, {"status": "written"}, approval=approval
            )
        )

    def test_receipts_evict_with_results(self):
        gateway = ActionGateway(
            approval_secret=APPROVAL_SECRET, max_results=2, max_tombstones=10
        )
        gateway.register(
            ToolSpec(
                name="workspace.write_file",
                required_capability="workspace:write",
                required_scope="workspace:write",
                resource_kind="workspace",
                risk_level="high",
                executor=lambda arguments: {"status": "written"},
            )
        )
        for index in range(3):
            self._execute(
                gateway=gateway,
                args={"path": f"f{index}.txt", "content": "x\n"},
                key=f"call-{index:03d}",
            )
        self.assertIsNone(gateway.receipt_for("call-000"))
        self.assertIsNotNone(gateway.receipt_for("call-002"))


if __name__ == "__main__":
    unittest.main()
