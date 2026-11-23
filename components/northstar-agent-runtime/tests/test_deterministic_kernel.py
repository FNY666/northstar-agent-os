from __future__ import annotations

import json
import hashlib
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
from tools.sandbox_evidence import SCHEMA


def evidence_for(plan):
    body = {
        "schema": SCHEMA,
        "plan_digest": plan.digest,
        "backend": "bwrap",
        "runtime_digest": "sha256:runtime",
        "rootless": True,
        "workspace_readonly": True,
        "network_mode": "none",
        "seccomp_loaded": True,
        "seccomp_profile_digest": "sha256:seccomp",
        "cgroup_enforced": True,
        "cgroup_path": "/sys/fs/cgroup/northstar/run-1",
        "effective_memory_max_bytes": plan.data["memory_max_bytes"],
        "effective_pids_max": plan.data["pids_max"],
        "effective_cpu_max_percent": plan.data["cpu_max_percent"],
        "descendant_pids": 0,
    }
    raw = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    body["evidence_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    return body


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
        self.plan = SandboxPolicy(workspace=Path(self.tmp.name)).plan(("true",))
        self.kernel.plan_step("run-1", "step-1", "effect-1", self.plan.digest)

    def tearDown(self):
        self.tmp.cleanup()

    def test_completed_step_is_replayed_without_effect(self):
        calls = []
        result = self.kernel.run_step("run-1", "step-1", "effect-1", lambda: calls.append(1) or {"ok": True}, plan=self.plan, evidence=evidence_for(self.plan))
        replayed = self.kernel.run_step("run-1", "step-1", "effect-1", lambda: calls.append(2) or {"ok": False}, plan=self.plan, evidence=evidence_for(self.plan))
        self.assertEqual(result, {"ok": True})
        self.assertEqual(replayed, result)
        self.assertEqual(calls, [1])
        self.assertEqual(self.kernel.replay("run-1").steps["step-1"], "completed")

    def test_inflight_step_requires_reconciliation(self):
        self.kernel._append("run-1", "step.started", {"step_id": "step-1", "action_key": "effect-1"})
        with self.assertRaises(RecoveryRequired):
            self.kernel.run_step("run-1", "step-1", "effect-1", lambda: None, plan=self.plan, evidence=evidence_for(self.plan))

    def test_tampering_breaks_replay(self):
        self.kernel.run_step("run-1", "step-1", "effect-1", lambda: {"ok": True}, plan=self.plan, evidence=evidence_for(self.plan))
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

    def test_missing_evidence_does_not_start_step(self):
        with self.assertRaises(KernelError):
            self.kernel.run_step("run-1", "step-1", "effect-1", lambda: {"ok": True}, plan=self.plan)
        self.assertEqual(self.kernel.replay("run-1").steps["step-1"], "planned")


if __name__ == "__main__":
    unittest.main()
