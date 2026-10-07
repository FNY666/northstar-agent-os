import hashlib
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
import process_adapter  # noqa: E402
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


def _handoff_token(*, capability="workspace:read", expiry=1_800, deadline=1_700, target="codex", policy="policy-1",
                   context_content="trusted context for ctx-process-001"):
    input_digest = "sha256:" + hashlib.sha256(context_content.encode("utf-8")).hexdigest()
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
            "input_digest": input_digest,
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
            "input_digest": input_digest,
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


class NonblockingRunnerTests(unittest.TestCase):
    def run_fixture(self, source, payload=b"context"):
        with tempfile.TemporaryDirectory(prefix="interop-io-") as tmp:
            return process_adapter._run_bounded_process(
                (sys.executable, "-c", source), cwd=Path(tmp), input_bytes=payload,
                env={"PATH": os.environ.get("PATH", "")}, timeout_seconds=3, max_output_bytes=8192,
            )

    def test_temporary_stdin_backpressure_retries_the_entire_context(self):
        original = os.write
        blocked = []
        def temporary_block(fd, data):
            if bytes(data) == b"trusted context" and not blocked:
                blocked.append(fd)
                raise BlockingIOError("injected write backpressure")
            return original(fd, data)
        with mock.patch.object(process_adapter.os, "write", side_effect=temporary_block):
            result = self.run_fixture("import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())", b"trusted context")
        self.assertEqual(len(blocked), 1)
        self.assertIsNone(result.error_class)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.output, b"trusted context", "EAGAIN is not permission to truncate context")

    def test_temporary_stdout_unavailability_is_not_eof(self):
        original = os.read
        blocked = []
        def temporary_block(fd, size):
            if size == 65536 and not blocked:
                blocked.append(fd)
                raise BlockingIOError("injected read readiness race")
            return original(fd, size)
        with mock.patch.object(process_adapter.os, "read", side_effect=temporary_block):
            result = self.run_fixture("import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'verified output')")
        self.assertEqual(len(blocked), 1)
        self.assertIsNone(result.error_class)
        self.assertEqual(result.output, b"verified output", "EAGAIN must not discard the real backend output")

    def test_partial_write_then_backpressure_keeps_offset_without_duplication(self):
        original = os.write
        payload = b"unique-context-0123456789"
        state = []
        def partial_then_block(fd, data):
            if bytes(data) == payload and not state:
                state.append("partial")
                return original(fd, data[:5])
            if bytes(data) == payload[5:] and state == ["partial"]:
                state.append("blocked")
                raise BlockingIOError("after partial write")
            return original(fd, data)
        with mock.patch.object(process_adapter.os, "write", side_effect=partial_then_block):
            result = self.run_fixture("import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())", payload)
        self.assertEqual(state, ["partial", "blocked"])
        self.assertEqual(result.output, payload)
        self.assertIsNone(result.error_class)

    def test_actual_eof_with_empty_input_still_finishes(self):
        result = self.run_fixture("import sys;assert sys.stdin.buffer.read() == b'';print('done')", b"")
        self.assertIsNone(result.error_class)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.output, b"done\n")

    def test_permanent_backpressure_is_bounded_by_deadline(self):
        with tempfile.TemporaryDirectory(prefix="interop-blocked-") as tmp:
            with mock.patch.object(process_adapter.os, "write", side_effect=BlockingIOError("retry")):
                result = process_adapter._run_bounded_process(
                    (sys.executable, "-c", "import sys;sys.stdin.buffer.read()"),
                    cwd=Path(tmp), input_bytes=b"context", env={}, timeout_seconds=.2, max_output_bytes=8192,
                )
        self.assertEqual(result.error_class, "timeout")


class ProcessGroupTerminationTests(unittest.TestCase):
    def test_posix_kills_group_even_when_leader_wait_succeeds(self):
        process = mock.MagicMock(pid=12345)
        for code in (None, 0):
            with self.subTest(leader_returncode=code):
                process.returncode = code
                with mock.patch.object(process_adapter.os, "name", "posix"), mock.patch.object(process_adapter.os, "killpg") as killpg:
                    process_adapter._terminate(process)
                self.assertEqual(killpg.call_args_list, [
                    mock.call(12345, process_adapter.signal.SIGTERM),
                    mock.call(12345, process_adapter.signal.SIGKILL),
                ])

    def test_posix_timeout_and_term_failure_still_attempt_group_kill(self):
        import subprocess
        for term_failure in (False, True):
            process = mock.MagicMock(pid=12345)
            process.wait.side_effect = [subprocess.TimeoutExpired("fixture", .25), 0]
            effects = [ProcessLookupError("gone"), None] if term_failure else None
            with self.subTest(term_failure=term_failure), mock.patch.object(process_adapter.os, "name", "posix"), mock.patch.object(process_adapter.os, "killpg", side_effect=effects) as killpg:
                process_adapter._terminate(process)
            self.assertEqual(killpg.call_args_list[-1], mock.call(12345, process_adapter.signal.SIGKILL))

    def test_nonposix_retains_success_and_timeout_behavior(self):
        import subprocess
        for timeout in (False, True):
            process = mock.MagicMock()
            if timeout:
                process.wait.side_effect = [subprocess.TimeoutExpired("fixture", .25), 0]
            with self.subTest(timeout=timeout), mock.patch.object(process_adapter.os, "name", "nt"), mock.patch.object(process_adapter.os, "killpg", create=True) as killpg:
                process_adapter._terminate(process)
            process.terminate.assert_called_once()
            self.assertEqual(process.kill.call_count, int(timeout))
            killpg.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "process groups require POSIX")
    def test_owned_term_ignoring_descendant_stops_after_leader_exit(self):
        import select
        import subprocess
        child_code = (
            "import pathlib,signal,sys,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "p=pathlib.Path(sys.argv[1]);p.write_text('ready');end=time.monotonic()+5\n"
            "while time.monotonic()<end:\n"
            " with p.open('a') as f: f.write('x');f.flush()\n"
            " time.sleep(.01)\n"
        )
        leader_code = (
            "import pathlib,subprocess,sys,time; p=pathlib.Path(sys.argv[2]);"
            "c=subprocess.Popen([sys.executable,'-c',sys.argv[1],str(p)]);"
            "end=time.monotonic()+3\n"
            "while not p.exists():\n"
            " if time.monotonic()>end: raise RuntimeError('child not ready')\n"
            " time.sleep(.01)\n"
            "print(c.pid,flush=True)\n"
            "time.sleep(5) if sys.argv[3]=='alive' else None\n"
        )
        for mode in ("alive", "exited"):
            with self.subTest(leader_mode=mode), tempfile.TemporaryDirectory(prefix="interop-owned-group-") as tmp:
                heartbeat = Path(tmp) / "heartbeat"
                process = subprocess.Popen(
                    (sys.executable, "-c", leader_code, child_code, str(heartbeat), mode),
                    start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                try:
                    self.assertTrue(select.select([process.stdout], [], [], 4)[0], "fixture startup timeout")
                    self.assertTrue(process.stdout.readline().strip().isdigit(), "child readiness missing")
                    first = heartbeat.stat().st_size
                    time.sleep(.06)
                    self.assertGreater(heartbeat.stat().st_size, first, "child must demonstrably run before cleanup")
                    if mode == "exited":
                        self.assertEqual(process.wait(timeout=2), 0)
                    process_adapter._terminate(process)
                    self.assertIsNotNone(process.returncode, "leader must be reaped")
                    # Allow signal delivery to settle, then assert continued stability.
                    time.sleep(.06)
                    stopped = heartbeat.stat().st_size
                    time.sleep(.12)
                    self.assertEqual(heartbeat.stat().st_size, stopped, "owned descendant still executing after group cleanup")
                finally:
                    try:
                        os.killpg(process.pid, process_adapter.signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=3)
                    process.stdout.close()
                    process.stderr.close()


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

    def test_context_bytes_must_match_the_grant_input_digest(self):
        # The grant authorizes one specific input_digest. A context store that
        # changed under the ref (or a loader that lies) must not silently
        # redirect the backend to unauthorized bytes.
        lying_adapter = ProcessAgentAdapter(
            agent_id="codex", provider="openai", version="cli-canary-v1",
            command=self.command,
            workspace_resolver=lambda workspace_id: self.workspace,
            context_loader=lambda context_ref: "attacker-controlled bytes",
            allowed_env=("LANG",),
            supported_capabilities=("workspace:read",),
            timeout_seconds=2.0, max_output_bytes=16_384,
        )
        with self.assertRaises(ValueError) as caught:
            lying_adapter.execute(
                _handoff_token(), context_ref="ctx-process-001",
                handoff_secret=HANDOFF_SECRET,
                current_policy_revision="policy-1", now=1_010,
            )
        self.assertIn("context digest does not match handoff", str(caught.exception))
        # Fail-closed before launch: the backend process never ran.
        self.assertFalse((self.workspace / "process-observation.json").exists())

    def test_changed_context_under_a_live_handoff_is_not_served_stale(self):
        # Same idempotency key, same ref, but the store now resolves to
        # different bytes: the cached receipt must not be returned for input
        # it was never computed from.
        token = _handoff_token()
        first = self.adapter.execute(
            token, context_ref="ctx-process-001",
            handoff_secret=HANDOFF_SECRET,
            current_policy_revision="policy-1", now=1_010,
        )
        self.assertEqual(first.status, "finished")
        self.adapter._context_loader = lambda context_ref: "different bytes under the same ref"
        with self.assertRaises(ValueError) as caught:
            self.adapter.execute(
                token, context_ref="ctx-process-001",
                handoff_secret=HANDOFF_SECRET,
                current_policy_revision="policy-1", now=1_011,
            )
        self.assertIn("context digest does not match handoff", str(caught.exception))

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
            context_loader=lambda context_ref: "trusted context for ctx-process-001",
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
            context_loader=lambda context_ref: "trusted context for ctx-process-001",
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
            context_loader=lambda context_ref: "trusted context for ctx-process-001",
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
