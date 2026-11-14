import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
HOST_ROOT = COMPONENT_ROOT.parent / "northstar-host"
CONTRACT_ROOT = COMPONENT_ROOT.parent / "northstar-run-contract"
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(HOST_ROOT))
sys.path.insert(0, str(CONTRACT_ROOT))

from authorization import HostPolicy, authorize_run, verify_authorization  # noqa: E402
from binding import sign_binding, verify_binding  # noqa: E402
from handoff import authorize_handoff, sign_attestation, verify_attestation, verify_handoff_grant  # noqa: E402
from interop_contract import AgentAttestation, AgentProfile, AgentRegistry, HandoffRequest  # noqa: E402
from process_adapter import ProcessAgentAdapter  # noqa: E402

BINDING_SECRET = b"process-binding-secret"
AUTH_SECRET = b"process-authorization-secret"
ATTESTATION_SECRET = b"process-attestation-secret"
HANDOFF_SECRET = b"process-handoff-secret"


def _run_request(capability="workspace:read"):
    return {
        "schema_version": "northstar.run.v1",
        "run_id": "run-process-001",
        "actor_id": "actor-process-001",
        "workspace_id": "workspace-process-001",
        "task_kind": "implementation",
        "prompt": "Run the trusted process fixture.",
        "timeout_ms": 10_000,
        "requested_capabilities": [capability],
        "parent_run_id": None,
    }


def _handoff_token(*, capability="workspace:read", expiry=1_800, deadline=1_700, target="codex", policy="policy-1"):
    run = _run_request(capability)
    binding = {
        "schema_version": run["schema_version"],
        "run_id": run["run_id"],
        "actor_id": run["actor_id"],
        "workspace_id": run["workspace_id"],
        "expires_at": expiry,
    }
    root = authorize_run(
        run,
        verify_binding(sign_binding(binding, BINDING_SECRET), BINDING_SECRET, now=1_000),
        HostPolicy.from_mapping(policy, {run["actor_id"]: [capability]}),
        now=1_000,
        secret=AUTH_SECRET,
        grant_ttl_seconds=500,
    )
    source = AgentAttestation.from_dict(
        {
            "schema_version": "northstar.agent-attestation.v1",
            "task_id": "task-process-001",
            "thread_id": "thread-process-001",
            "run_id": run["run_id"],
            "actor_id": run["actor_id"],
            "workspace_id": run["workspace_id"],
            "policy_revision": policy,
            "agent_id": "orchestrator",
            "step_id": "execute",
            "trace_id": "trace-process-001",
            "input_digest": "sha256:" + "a" * 64,
            "capabilities": [capability],
            "delegation_depth": 0,
            "expires_at": 1_750,
        }
    )
    request = HandoffRequest.from_dict(
        {
            "schema_version": "northstar.handoff-request.v1",
            "handoff_id": "handoff-process-001",
            "task_id": "task-process-001",
            "thread_id": "thread-process-001",
            "run_id": run["run_id"],
            "actor_id": run["actor_id"],
            "workspace_id": run["workspace_id"],
            "policy_revision": policy,
            "source_agent_id": "orchestrator",
            "target_agent_id": target,
            "step_id": "execute",
            "trace_id": "trace-process-001",
            "input_digest": "sha256:" + "a" * 64,
            "requested_capabilities": [capability],
            "expected_postconditions": ["process_receipt"],
            "delegation_depth": 1,
            "deadline_at": deadline,
            "requested_at": 1_000,
            "idempotency_key": "handoff-process-001-attempt-1",
        }
    )
    registry = AgentRegistry()
    registry.register(
        AgentProfile.from_dict(
            {
                "schema_version": "northstar.agent-profile.v1",
                "agent_id": "orchestrator",
                "provider": "northstar",
                "version": "canary-v1",
                "capabilities": [capability],
            }
        )
    )
    registry.register(
        AgentProfile.from_dict(
            {
                "schema_version": "northstar.agent-profile.v1",
                "agent_id": target,
                "provider": "openai",
                "version": "canary-v1",
                "capabilities": [capability],
            }
        )
    )
    return authorize_handoff(
        request,
        parent_authorization=verify_authorization(root, AUTH_SECRET, now=1_001),
        source_attestation=verify_attestation(
            sign_attestation(source, ATTESTATION_SECRET),
            ATTESTATION_SECRET,
            now=1_001,
        ),
        registry=registry,
        current_policy_revision=policy,
        now=1_001,
        secret=HANDOFF_SECRET,
        grant_ttl_seconds=300,
    )


class ProcessAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.script = self.root / "fake_agent.py"
        self.script.write_text(
            "import json, os, pathlib, sys\n"
            "obs = {\n"
            "  'argv': sys.argv[1:],\n"
            "  'cwd': os.getcwd(),\n"
            "  'stdin': sys.stdin.read(),\n"
            "  'context_ref': os.environ.get('NORTHSTAR_CONTEXT_REF'),\n"
            "  'run_id': os.environ.get('NORTHSTAR_RUN_ID'),\n"
            "  'unsafe': os.environ.get('NORTHSTAR_UNSAFE_MARKER'),\n"
            "}\n"
            "pathlib.Path('process-observation.json').write_text(json.dumps(obs), encoding='utf-8')\n"
            "print(json.dumps({'status':'finished','output_digest':'sha256:' + '2' * 64,'artifact_refs':['artifact:process-observation.json'],'verifier_verdict':'verified'}))\n",
            encoding="utf-8",
        )
        self.command = (sys.executable, str(self.script), "--fixed-mode")
        self.adapter = ProcessAgentAdapter(
            agent_id="codex",
            provider="openai",
            version="cli-canary-v1",
            command=self.command,
            workspace_resolver=lambda workspace_id: self.workspace,
            context_loader=lambda context_ref: (
                "trusted context for " + context_ref
                if context_ref == "ctx-process-001"
                else (_ for _ in ()).throw(ValueError("unknown context"))
            ),
            allowed_env=("LANG",),
            supported_capabilities=("workspace:read",),
            timeout_seconds=2.0,
            max_output_bytes=16_384,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_fixed_process_boundary_returns_typed_receipt_and_filters_environment(self):
        token = _handoff_token()
        with mock.patch.dict(os.environ, {"NORTHSTAR_UNSAFE_MARKER": "omit-me"}, clear=False):
            receipt = self.adapter.execute(
                token,
                context_ref="ctx-process-001",
                handoff_secret=HANDOFF_SECRET,
                current_policy_revision="policy-1",
                now=1_010,
            )
        self.assertEqual(receipt.status, "finished")
        self.assertEqual(receipt.target_agent_id, "codex")
        self.assertEqual(receipt.verifier_verdict, "verified")
        observation = json.loads((self.workspace / "process-observation.json").read_text(encoding="utf-8"))
        self.assertEqual(observation["argv"], ["--fixed-mode"])
        self.assertEqual(observation["cwd"], str(self.workspace))
        self.assertEqual(observation["stdin"], "trusted context for ctx-process-001")
        self.assertEqual(observation["context_ref"], "ctx-process-001")
        self.assertEqual(observation["run_id"], "run-process-001")
        self.assertIsNone(observation["unsafe"])
        self.assertNotIn("trusted context", repr(receipt.to_dict()))

    def test_adapter_rejects_granted_capability_it_does_not_explicitly_support(self):
        with self.assertRaises(ValueError):
            ProcessAgentAdapter(
                agent_id="codex",
                provider="openai",
                version="cli-canary-v1",
                command=self.command,
                workspace_resolver=lambda workspace_id: self.workspace,
                context_loader=lambda context_ref: "trusted context",
                allowed_env=(),
                supported_capabilities=(),
                timeout_seconds=2.0,
                max_output_bytes=16_384,
            )

        write_adapter = ProcessAgentAdapter(
            agent_id="codex",
            provider="openai",
            version="cli-canary-v1",
            command=self.command,
            workspace_resolver=lambda workspace_id: self.workspace,
            context_loader=lambda context_ref: "trusted context",
            allowed_env=(),
            supported_capabilities=("workspace:read",),
            timeout_seconds=2.0,
            max_output_bytes=16_384,
        )
        with self.assertRaises(ValueError):
            write_adapter.execute(
                _handoff_token(capability="workspace:write"),
                context_ref="ctx-process-001",
                handoff_secret=HANDOFF_SECRET,
                current_policy_revision="policy-1",
                now=1_010,
            )

    def test_same_handoff_is_idempotent_and_conflicting_context_is_rejected(self):
        token = _handoff_token()
        first = self.adapter.execute(
            token,
            context_ref="ctx-process-001",
            handoff_secret=HANDOFF_SECRET,
            current_policy_revision="policy-1",
            now=1_010,
        )
        second = self.adapter.execute(
            token,
            context_ref="ctx-process-001",
            handoff_secret=HANDOFF_SECRET,
            current_policy_revision="policy-1",
            now=1_011,
        )
        self.assertEqual(first, second)
        with self.assertRaises(ValueError):
            self.adapter.execute(
                token,
                context_ref="ctx-process-002",
                handoff_secret=HANDOFF_SECRET,
                current_policy_revision="policy-1",
                now=1_011,
            )

    def test_wrong_target_policy_expiry_context_and_workspace_are_rejected(self):
        token = _handoff_token(target="claude-code")
        with self.assertRaises(ValueError):
            self.adapter.execute(
                token, context_ref="ctx-process-001", handoff_secret=HANDOFF_SECRET,
                current_policy_revision="policy-1", now=1_010,
            )
        token = _handoff_token()
        with self.assertRaises(ValueError):
            self.adapter.execute(
                token, context_ref="ctx-process-001", handoff_secret=HANDOFF_SECRET,
                current_policy_revision="policy-2", now=1_010,
            )
        with self.assertRaises(ValueError):
            self.adapter.execute(
                token, context_ref="ctx-process-001", handoff_secret=HANDOFF_SECRET,
                current_policy_revision="policy-1", now=1_700,
            )
        with self.assertRaises(ValueError):
            self.adapter.execute(
                token, context_ref="ctx-process-unknown", handoff_secret=HANDOFF_SECRET,
                current_policy_revision="policy-1", now=1_010,
            )

        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o755)
        self.adapter._workspace_resolver = lambda workspace_id: unsafe
        with self.assertRaises(ValueError):
            self.adapter.execute(
                token, context_ref="ctx-process-001", handoff_secret=HANDOFF_SECRET,
                current_policy_revision="policy-1", now=1_010,
            )

    def test_output_limit_and_malformed_backend_output_fail_without_success(self):
        noisy = self.root / "noisy.py"
        noisy.write_text("print('x' * 2000)\n", encoding="utf-8")
        noisy_adapter = ProcessAgentAdapter(
            agent_id="codex", provider="openai", version="cli-canary-v1",
            command=(sys.executable, str(noisy)),
            workspace_resolver=lambda workspace_id: self.workspace,
            context_loader=lambda context_ref: "trusted",
            allowed_env=(),
            supported_capabilities=("workspace:read",),
            timeout_seconds=2.0, max_output_bytes=100,
        )
        result = noisy_adapter.execute(
            _handoff_token(), context_ref="ctx-process-001",
            handoff_secret=HANDOFF_SECRET, current_policy_revision="policy-1", now=1_010,
        )
        self.assertEqual(result.status, "failed")
        self.assertNotEqual(result.verifier_verdict, "verified")

        malformed = self.root / "malformed.py"
        malformed.write_text("print('{\\\"status\\\":\\\"finished\\\"}')\n", encoding="utf-8")
        malformed_adapter = ProcessAgentAdapter(
            agent_id="codex", provider="openai", version="cli-canary-v1",
            command=(sys.executable, str(malformed)),
            workspace_resolver=lambda workspace_id: self.workspace,
            context_loader=lambda context_ref: "trusted",
            allowed_env=(),
            supported_capabilities=("workspace:read",),
            timeout_seconds=2.0, max_output_bytes=16_384,
        )
        result = malformed_adapter.execute(
            _handoff_token(), context_ref="ctx-process-001",
            handoff_secret=HANDOFF_SECRET, current_policy_revision="policy-1", now=1_010,
        )
        self.assertEqual(result.status, "failed")

    def test_timeout_is_structured_failure_and_process_is_not_left_running(self):
        sleeper = self.root / "sleeper.py"
        sleeper.write_text("import time; time.sleep(10)\n", encoding="utf-8")
        sleeper_adapter = ProcessAgentAdapter(
            agent_id="codex", provider="openai", version="cli-canary-v1",
            command=(sys.executable, str(sleeper)),
            workspace_resolver=lambda workspace_id: self.workspace,
            context_loader=lambda context_ref: "trusted",
            allowed_env=(),
            supported_capabilities=("workspace:read",),
            timeout_seconds=0.05, max_output_bytes=16_384,
        )
        started = time.monotonic()
        result = sleeper_adapter.execute(
            _handoff_token(), context_ref="ctx-process-001",
            handoff_secret=HANDOFF_SECRET, current_policy_revision="policy-1", now=1_010,
        )
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.error_class, "timeout")

    def test_constructor_rejects_shell_like_or_unbounded_configuration(self):
        with self.assertRaises(ValueError):
            ProcessAgentAdapter(
                agent_id="codex", provider="openai", version="v1", command=(),
                workspace_resolver=lambda workspace_id: self.workspace,
                context_loader=lambda context_ref: "trusted",
                allowed_env=(),
                supported_capabilities=("workspace:read",),
                timeout_seconds=1, max_output_bytes=100,
            )
        with self.assertRaises(ValueError):
            ProcessAgentAdapter(
                agent_id="codex", provider="openai", version="v1",
                command=("sh", "-c", "unsafe"),
                workspace_resolver=lambda workspace_id: self.workspace,
                context_loader=lambda context_ref: "trusted",
                allowed_env=(),
                supported_capabilities=("workspace:read",),
                timeout_seconds=1, max_output_bytes=100,
            )
        with self.assertRaises(ValueError):
            ProcessAgentAdapter(
                agent_id="codex", provider="openai", version="v1",
                command=self.command,
                workspace_resolver=lambda workspace_id: self.workspace,
                context_loader=lambda context_ref: "trusted",
                allowed_env=(),
                supported_capabilities=("workspace:read",),
                timeout_seconds=0, max_output_bytes=100,
            )


if __name__ == "__main__":
    unittest.main()
