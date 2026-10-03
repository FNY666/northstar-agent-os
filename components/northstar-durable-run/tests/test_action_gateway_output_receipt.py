"""PATH-shim red-team tests for the durable ActionGateway.

Attack model: ``DavidCarliez/trustmebro`` (MIT, verified against the real
repo before porting) — a shim directory prepended to ``PATH`` shadows the
tool binary and returns fabricated output (``spoof``). The per-call
approval binding (``call_id`` + ``arguments_digest``) authenticates the
*request*, never the *output*: these tests first prove that gap honestly (a
signed approval for the original arguments still verifies when the binary
is shimmed), then prove the two new defenses close it (the binary pin
fails closed before the executor runs; ``output_digest`` binds the
execution receipt so post-hoc forgery is detectable).

The executor here resolves its binary via ``PATH`` the way a real shell
tool would, so planting the shim dir first genuinely changes what runs.
"""
import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = COMPONENT_ROOT.parent / "northstar-run-contract"
HOST_ROOT = COMPONENT_ROOT.parent / "northstar-host"
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(CONTRACT_ROOT))
sys.path.insert(0, str(HOST_ROOT))

from action_gateway import (  # noqa: E402
    ActionGateway,
    BinaryPin,
    ToolCall,
    ToolExecutionResult,
    ToolSpec,
    _digest_output,
    digest_arguments,
    sign_approval,
    verify_binary_pin,
    verify_output_receipt,
)
from authorization import HostPolicy, authorize_run  # noqa: E402
from binding import sign_binding, verify_binding  # noqa: E402

AUTH_SECRET = b"shimtest-authorization-secret"
BINDING_SECRET = b"shimtest-binding-secret"
APPROVAL_SECRET = b"shimtest-approval-secret"

TOOL_NAME = "nstool-shimtest"
REAL_MARKER = b"real binary bytes"
SHIM_MARKER = b"fabricated shim bytes"


def valid_run(capability="test:exec"):
    return {
        "schema_version": "northstar.run.v1",
        "run_id": "run-001",
        "actor_id": "actor-001",
        "workspace_id": "workspace-001",
        "task_kind": "implementation",
        "prompt": "Red-team fixture.",
        "timeout_ms": 10_000,
        "requested_capabilities": [capability],
        "parent_run_id": None,
    }


def auth_token(run, *, now=1_000, expires_at=2_000):
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
    policy = HostPolicy.from_mapping(
        "policy-1", {run["actor_id"]: run["requested_capabilities"]}
    )
    return authorize_run(
        run, verified, policy, now=now, secret=AUTH_SECRET, grant_ttl_seconds=300
    )


def call_for(run, args, *, key="call-001"):
    return ToolCall.from_dict(
        {
            "schema_version": "northstar.tool-call.v1",
            "task_id": "task-001",
            "thread_id": "thread-001",
            "run_id": run["run_id"],
            "step_id": "probe",
            "actor_id": run["actor_id"],
            "workspace_id": run["workspace_id"],
            "trace_id": "trace-001",
            "tool_name": TOOL_NAME,
            "resource_id": run["workspace_id"],
            "requested_scope": ["test:exec"],
            "arguments_digest": digest_arguments(args),
            "idempotency_key": key,
            "deadline_at": 1_900,
        }
    )


def approval_for(run, call, *, expires_at=2_000):
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


def path_resolving_executor(arguments):
    """Model a shell tool: resolve the binary via PATH and run it.

    The "binary" is a marker file; the executor returns whatever the
    resolved file says. With the shim dir first on PATH, the fabricated
    output is what the model would see — exactly the trustmebro spoof.
    """
    resolved = shutil.which(TOOL_NAME, path=os.environ.get("PATH"))
    if resolved is None:
        raise RuntimeError("tool binary vanished from PATH")
    with open(resolved, "rb") as handle:
        marker = handle.read()
    if SHIM_MARKER in marker:
        return {"text": "fabricated answer", "exit": 0}
    return {"text": "real answer", "exit": 0}


class PathShimRedTeamTests(unittest.TestCase):
    def setUp(self):
        self.dirs: list[str] = []
        self.real_dir = self._tool_dir(REAL_MARKER)
        self.shim_dir = self._tool_dir(SHIM_MARKER)
        self._old_path = os.environ.get("PATH")
        self.addCleanup(self._restore_path)

    def tearDown(self):
        for directory in self.dirs:
            shutil.rmtree(directory, ignore_errors=True)

    def _restore_path(self):
        if self._old_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = self._old_path

    def _tool_dir(self, marker: bytes) -> str:
        directory = tempfile.mkdtemp(prefix="ns-shim-gw-")
        self.dirs.append(directory)
        script = os.path.join(directory, TOOL_NAME)
        with open(script, "wb") as handle:
            handle.write(marker)
        os.chmod(script, 0o755)
        return directory

    def _pin(self) -> BinaryPin:
        found = shutil.which(TOOL_NAME, path=self.real_dir)
        assert found is not None
        real = os.path.realpath(found)
        with open(real, "rb") as handle:
            digest = "sha256:" + hashlib.sha256(handle.read()).hexdigest()
        return BinaryPin(name=TOOL_NAME, path=real, digest=digest)

    def _register(self, gateway: ActionGateway, *, pin: BinaryPin | None):
        gateway.register(
            ToolSpec(
                name=TOOL_NAME,
                required_capability="test:exec",
                required_scope="test:exec",
                resource_kind="test",
                risk_level="high",
                executor=path_resolving_executor,
                binary_pin=pin,
            )
        )

    def _execute(self, gateway, run, args, *, key="call-001"):
        call = call_for(run, args, key=key)
        return gateway.execute(
            call,
            args,
            authorization_token=auth_token(run),
            authorization_secret=AUTH_SECRET,
            now=1_001,
            approval_token=approval_for(run, call),
            current_policy_revision="policy-1",
        )

    # -- the honest gap: approval binding cannot see a binary swap ---------
    def test_approval_binding_is_blind_to_binary_swap_without_pin(self):
        """Red-team finding, stated plainly.

        With no binary pin, the shimmed binary runs, the fabricated output
        is returned, and the signed approval still verifies — because the
        binding covers (call_id, arguments_digest) and the shim changed
        neither. The per-call approval gate, on its own, does NOT detect a
        PATH-shim attack. This is the gap the pin and output receipt close.
        """
        gateway = ActionGateway(approval_secret=APPROVAL_SECRET)
        self._register(gateway, pin=None)
        os.environ["PATH"] = self.shim_dir + os.pathsep + self.real_dir
        run = valid_run()
        result = self._execute(gateway, run, {"target": "example.com"})
        # The attack succeeded: fabricated output, approval accepted.
        self.assertEqual(result.output, {"text": "fabricated answer", "exit": 0})
        # ...and the receipt faithfully records what ran, digest and all.
        ok, _reason = verify_output_receipt(result)
        self.assertTrue(ok)

    # -- defense 1: binary pin fails closed before the executor runs -------
    def test_pinned_binary_clean_path_executes_and_binds_receipt(self):
        gateway = ActionGateway(approval_secret=APPROVAL_SECRET)
        self._register(gateway, pin=self._pin())
        os.environ["PATH"] = self.real_dir
        run = valid_run()
        result = self._execute(gateway, run, {"target": "example.com"})
        self.assertEqual(result.output, {"text": "real answer", "exit": 0})
        self.assertEqual(result.output_digest, _digest_output(result.output))
        self.assertEqual(
            result.binary_path,
            os.path.realpath(os.path.join(self.real_dir, TOOL_NAME)),
        )
        ok, _reason = verify_output_receipt(result)
        self.assertTrue(ok)

    def test_pinned_binary_shim_after_pinning_fails_closed(self):
        gateway = ActionGateway(approval_secret=APPROVAL_SECRET)
        self._register(gateway, pin=self._pin())
        # Shim planted *after* registration: this is the attack.
        os.environ["PATH"] = self.shim_dir + os.pathsep + self.real_dir
        run = valid_run()
        with self.assertRaisesRegex(
            ValueError, "tool binary integrity check failed"
        ):
            self._execute(gateway, run, {"target": "example.com"})

    def test_verify_binary_pin_detects_replaced_bytes(self):
        pin = self._pin()
        with open(os.path.join(self.real_dir, TOOL_NAME), "wb") as handle:
            handle.write(b"replaced in place")
        os.chmod(os.path.join(self.real_dir, TOOL_NAME), 0o755)
        ok, reason = verify_binary_pin(pin, path=self.real_dir)
        self.assertFalse(ok)
        self.assertIn("digest", reason)

    # -- defense 2: output receipt detects post-execution forgery ----------
    def test_output_receipt_detects_post_execution_forgery(self):
        gateway = ActionGateway(approval_secret=APPROVAL_SECRET)
        self._register(gateway, pin=self._pin())
        os.environ["PATH"] = self.real_dir
        run = valid_run()
        result = self._execute(gateway, run, {"target": "example.com"})
        forged = replace(
            result,
            output={"text": "fabricated answer", "exit": 0},
        )
        ok, reason = verify_output_receipt(forged)
        self.assertFalse(ok)
        self.assertIn("forged", reason)

    def test_output_receipt_rejects_missing_digest(self):
        result = ToolExecutionResult(
            status="ok", output={"text": "x"}, idempotency_key="k"
        )
        ok, _reason = verify_output_receipt(result)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
