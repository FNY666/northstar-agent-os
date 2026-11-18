from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import support  # noqa: F401
from tools.deterministic_kernel import (
    DeterministicKernel,
    EventIntegrityError,
    KernelError,
    PolicyError,
    RecoveryRequired,
    SandboxPolicy,
)


class SandboxPolicyTests(unittest.TestCase):
    def test_plan_is_deterministic_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            policy = SandboxPolicy(workspace=workspace)
            first = policy.plan(("python3", "-c", "print('ok')"))
            second = policy.plan(("python3", "-c", "print('ok')"))
            self.assertEqual(first.as_dict(), second.as_dict())
            self.assertEqual(first.data["network"], "none")
            self.assertEqual(first.data["seccomp"], "required")
            self.assertTrue(first.data["readonly"])

    def test_policy_rejects_escape_and_widening(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            with self.assertRaises(PolicyError):
                SandboxPolicy(workspace=workspace, network="host")
            with self.assertRaises(PolicyError):
                SandboxPolicy(workspace=workspace, rootless=False)
            outside = workspace.parent
            with self.assertRaises(PolicyError):
                SandboxPolicy(workspace=workspace).plan(("true",), cwd=outside)
            with self.assertRaises(PolicyError):
                SandboxPolicy(workspace=workspace).plan(("true",), env_names=("bad-name",))


class DeterministicKernelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "events.ndjson"
        self.kernel = DeterministicKernel(self.path)
        self.kernel.start_run("run-1", "sha256:input")
        self.kernel.plan_step("run-1", "step-1", "effect-1", "sha256:plan")

    def tearDown(self):
        self.tmp.cleanup()

    def test_completed_step_is_replayed_without_effect(self):
        calls = []
        result = self.kernel.run_step("run-1", "step-1", "effect-1", lambda: calls.append(1) or {"ok": True})
        replayed = self.kernel.run_step("run-1", "step-1", "effect-1", lambda: calls.append(2) or {"ok": False})
        self.assertEqual(result, {"ok": True})
        self.assertEqual(replayed, result)
        self.assertEqual(calls, [1])
        self.assertEqual(self.kernel.replay("run-1").steps["step-1"], "completed")

    def test_inflight_step_requires_reconciliation(self):
        self.kernel._append("run-1", "step.started", {"step_id": "step-1", "action_key": "effect-1"})
        with self.assertRaises(RecoveryRequired):
            self.kernel.run_step("run-1", "step-1", "effect-1", lambda: None)

    def test_tampering_breaks_replay(self):
        self.kernel.run_step("run-1", "step-1", "effect-1", lambda: {"ok": True})
        lines = self.path.read_text().splitlines()
        event = json.loads(lines[-1])
        event["payload"]["result"] = {"ok": "tampered"}
        lines[-1] = json.dumps(event, sort_keys=True)
        self.path.write_text("\n".join(lines) + "\n")
        with self.assertRaises(EventIntegrityError):
            self.kernel.replay("run-1")

    def test_invalid_transition_is_rejected(self):
        with self.assertRaises(KernelError):
            self.kernel.run_step("run-1", "unknown", "effect", lambda: None)


if __name__ == "__main__":
    unittest.main()
