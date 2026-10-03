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
)
from authorization import HostPolicy, authorize_run  # noqa: E402
from binding import sign_binding, verify_binding  # noqa: E402
from tool_allowlist import (  # noqa: E402
    EnforcementGate,
    ToolAllowlist,
)

AUTH_SECRET = b"allowlist-authorization-secret"
BINDING_SECRET = b"allowlist-binding-secret"
APPROVAL_SECRET = b"allowlist-approval-secret"

ALLOWLIST_DOC = {
    "version": 1,
    "tools": {
        "workspace.read_file": {"params": {"path": ["src/**", "docs/**"]}},
        "workspace.write_file": {"params": {"path": ["src/**"], "content": ["*"]}},
    },
}


def valid_run(capability="workspace:read"):
    return {
        "schema_version": "northstar.run.v1",
        "run_id": "run-001",
        "actor_id": "actor-001",
        "workspace_id": "workspace-001",
        "task_kind": "implementation",
        "prompt": "Allowlist fixture.",
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


def call_for(run, *, tool_name, args, scope, key, capability=None):
    return ToolCall.from_dict(
        {
            "schema_version": "northstar.tool-call.v1",
            "task_id": "task-001",
            "thread_id": "thread-001",
            "run_id": run["run_id"],
            "step_id": "edit",
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


class ToolAllowlistParsingTests(unittest.TestCase):
    def test_parses_valid_document(self):
        allowlist = ToolAllowlist.from_mapping(ALLOWLIST_DOC)
        self.assertEqual(allowlist.version, 1)
        self.assertEqual(
            allowlist.tools["workspace.read_file"].params["path"],
            ("src/**", "docs/**"),
        )

    def test_rejects_unknown_top_level_field(self):
        doc = dict(ALLOWLIST_DOC, network="oops")
        with self.assertRaises(ValueError):
            ToolAllowlist.from_mapping(doc)

    def test_rejects_unknown_rule_field(self):
        doc = {
            "version": 1,
            "tools": {"t": {"params": {}, "commands": ["*"]}},
        }
        with self.assertRaises(ValueError):
            ToolAllowlist.from_mapping(doc)

    def test_rejects_explicit_empty_tools(self):
        # OpenShell's parse_mcp_versions rejects an explicit empty allowlist
        # as an authoring mistake; mirrored here.
        with self.assertRaises(ValueError):
            ToolAllowlist.from_mapping({"version": 1, "tools": {}})

    def test_rejects_empty_pattern_list(self):
        doc = {"version": 1, "tools": {"t": {"params": {"p": []}}}}
        with self.assertRaises(ValueError):
            ToolAllowlist.from_mapping(doc)

    def test_rejects_bad_version(self):
        for bad in (0, "1", True, None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    ToolAllowlist.from_mapping({"version": bad, "tools": {"t": {}}})


class EnforcementGateTests(unittest.TestCase):
    def setUp(self):
        self.gate = EnforcementGate(ToolAllowlist.from_mapping(ALLOWLIST_DOC))

    def test_allowlisted_call_matches(self):
        decision = self.gate.check(
            "workspace.read_file", {"path": "src/main.py"}
        )
        self.assertEqual(decision.decision, "allow")

    def test_second_glob_branch_matches(self):
        decision = self.gate.check("workspace.read_file", {"path": "docs/api.md"})
        self.assertEqual(decision.decision, "allow")

    def test_param_value_mismatch_denies(self):
        decision = self.gate.check("workspace.read_file", {"path": "/etc/passwd"})
        self.assertEqual(decision.decision, "deny")

    def test_unknown_tool_denies(self):
        decision = self.gate.check("shell.exec", {"command": "id"})
        self.assertEqual(decision.decision, "deny")

    def test_unlisted_param_denies(self):
        decision = self.gate.check(
            "workspace.read_file", {"path": "src/main.py", "mode": "0644"}
        )
        self.assertEqual(decision.decision, "deny")

    def test_missing_ruled_param_denies(self):
        decision = self.gate.check("workspace.write_file", {"content": "x"})
        self.assertEqual(decision.decision, "deny")

    def test_rejects_bad_failure_policy(self):
        with self.assertRaises(ValueError):
            EnforcementGate(
                ToolAllowlist.from_mapping(ALLOWLIST_DOC),
                failure_policy="fail_sometimes",
            )


class ActionGatewayAllowlistTests(unittest.TestCase):
    def setUp(self):
        self.invocations: list[tuple[str, dict]] = []
        self.gateway = ActionGateway(
            approval_secret=APPROVAL_SECRET,
            tool_allowlist=ToolAllowlist.from_mapping(ALLOWLIST_DOC),
        )
        self.gateway.register(
            ToolSpec(
                name="workspace.read_file",
                required_capability="workspace:read",
                required_scope="workspace:read",
                resource_kind="workspace",
                risk_level="low",
                executor=self.read_file,
            )
        )
        self.gateway.register(
            ToolSpec(
                name="shell.exec",
                required_capability="workspace:read",
                required_scope="workspace:read",
                resource_kind="workspace",
                risk_level="low",
                executor=self.shell_exec,
            )
        )

    def read_file(self, arguments):
        self.invocations.append(("read", arguments))
        return {"text": "fixture"}

    def shell_exec(self, arguments):
        self.invocations.append(("shell", arguments))
        return {"status": "ran"}

    def _execute(self, tool_name, args, key):
        run = valid_run("workspace:read")
        call = call_for(
            run,
            tool_name=tool_name,
            args=args,
            scope=["workspace:read"],
            key=key,
        )
        return self.gateway.execute(
            call,
            dict(args),
            authorization_token=auth_token(run),
            authorization_secret=AUTH_SECRET,
            now=1_000,
            current_policy_revision="policy-1",
            run=run,
        )

    def test_allowlisted_call_executes_and_traces_allow(self):
        result = self._execute(
            "workspace.read_file", {"path": "src/main.py"}, "call-allow-1"
        )
        self.assertEqual(result.status, "ok")
        self.assertEqual(len(self.invocations), 1)
        trace = self.gateway.enforcement_trace
        self.assertEqual(len(trace), 1)
        self.assertEqual(trace[0]["decision"], "allow")
        self.assertEqual(trace[0]["tool_name"], "workspace.read_file")
        self.assertEqual(
            trace[0]["arguments_digest"],
            digest_arguments({"path": "src/main.py"}),
        )
        self.assertTrue(trace[0]["reason"])

    def test_non_allowlisted_tool_is_denied_and_never_executes(self):
        with self.assertRaises(ValueError) as ctx:
            self._execute("shell.exec", {"command": "id"}, "call-deny-1")
        self.assertIn("allowlist", str(ctx.exception))
        self.assertEqual(self.invocations, [])
        trace = self.gateway.enforcement_trace
        self.assertEqual(len(trace), 1)
        self.assertEqual(trace[0]["decision"], "deny")

    def test_param_mismatch_denied_and_traced(self):
        with self.assertRaises(ValueError):
            self._execute(
                "workspace.read_file", {"path": "/etc/passwd"}, "call-deny-2"
            )
        self.assertEqual(self.invocations, [])
        self.assertEqual(self.gateway.enforcement_trace[0]["decision"], "deny")

    def test_trace_is_complete_and_ordered(self):
        self._execute("workspace.read_file", {"path": "src/a.py"}, "k1")
        for key, args in (
            ("k2", {"path": "/etc/passwd"}),
            ("k3", {"path": "src/a.py", "extra": "x"}),
        ):
            with self.assertRaises(ValueError):
                self._execute("workspace.read_file", args, key)
        trace = self.gateway.enforcement_trace
        self.assertEqual([e["decision"] for e in trace], ["allow", "deny", "deny"])
        self.assertEqual([e["seq"] for e in trace], [1, 2, 3])
        for event in trace:
            self.assertEqual(event["allowlist_version"], 1)
            self.assertEqual(event["failure_policy"], "fail_closed")
            self.assertTrue(event["reason"])

    def test_no_allowlist_means_no_gate_and_empty_trace(self):
        gateway = ActionGateway(approval_secret=APPROVAL_SECRET)
        gateway.register(
            ToolSpec(
                name="workspace.read_file",
                required_capability="workspace:read",
                required_scope="workspace:read",
                resource_kind="workspace",
                risk_level="low",
                executor=self.read_file,
            )
        )
        run = valid_run("workspace:read")
        call = call_for(
            run,
            tool_name="workspace.read_file",
            args={"path": "src/main.py"},
            scope=["workspace:read"],
            key="call-nogate",
        )
        result = gateway.execute(
            call,
            {"path": "src/main.py"},
            authorization_token=auth_token(run),
            authorization_secret=AUTH_SECRET,
            now=1_000,
            current_policy_revision="policy-1",
            run=run,
        )
        self.assertEqual(result.status, "ok")
        self.assertEqual(gateway.enforcement_trace, ())


if __name__ == "__main__":
    unittest.main()
