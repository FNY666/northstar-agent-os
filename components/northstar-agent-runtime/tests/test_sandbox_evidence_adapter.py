from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import support  # noqa: F401
from tools.deterministic_kernel import SandboxPolicy
from tools.os_sandbox import SandboxRequest, SandboxResult, run_sandboxed
from tools.sandbox_evidence import EvidenceError, verify_evidence
from tools.sandbox_evidence_adapter import (
    SandboxEvidenceAdapterError,
    evidence_from_sandbox_result,
)


class SandboxEvidenceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmp.name)
        self.plan = SandboxPolicy(
            workspace=self.workspace,
            memory_max_bytes=512 * 1024 * 1024,
            pids_max=256,
            cpu_max_percent=100,
        ).plan(("true",))
        self.request = SandboxRequest(
            argv=("true",),
            cwd=self.workspace,
            workspace=self.workspace,
            memory_limit_bytes=512 * 1024 * 1024,
            max_tasks=256,
            seccomp="auto",
            pledges=(),
            aggregate_resource_scope="systemd",
        )
        self.facts = {
            "runtime_digest": "sha256:runtime",
            "seccomp_profile_digest": "sha256:seccomp",
            "rootless": True,
            "workspace_readonly": True,
            "cgroup_path": "/sys/fs/cgroup/northstar/run-1",
            "descendant_pids": 0,
        }

    def tearDown(self):
        self.tmp.cleanup()

    def result(self, *, backend="bwrap", isolation="os", detail=None, **kwargs):
        return SandboxResult(
            argv=("true",),
            backend=backend,
            isolation=isolation,
            exit_code=0,
            timed_out=False,
            stdout="",
            stderr="",
            duration_ms=1,
            detail=detail or "network namespace unshared; seccomp denies network socket creation",
            **kwargs,
        )

    def test_bwrap_result_can_pass_contract(self):
        raw = evidence_from_sandbox_result(self.plan, self.request, self.result(), runtime_facts=self.facts)
        verified = verify_evidence(self.plan, raw, require_os_isolation=True)
        self.assertEqual(verified.backend, "bwrap")
        self.assertTrue(verified.cgroup_enforced)

    def test_process_result_is_recorded_but_refused_as_os_sandbox(self):
        result = self.result(
            backend="process",
            isolation="process",
            detail="process backend; seccomp denies network socket creation",
        )
        raw = evidence_from_sandbox_result(self.plan, self.request, result, runtime_facts=self.facts)
        with self.assertRaises(EvidenceError):
            verify_evidence(self.plan, raw)

    def test_missing_runtime_fact_is_refused(self):
        facts = dict(self.facts)
        facts.pop("rootless")
        with self.assertRaises(SandboxEvidenceAdapterError):
            evidence_from_sandbox_result(self.plan, self.request, self.result(), runtime_facts=facts)

    def test_argv_mismatch_is_refused(self):
        result = self.result()
        result = SandboxResult(**{**result.__dict__, "argv": ("false",)})
        with self.assertRaises(SandboxEvidenceAdapterError):
            evidence_from_sandbox_result(self.plan, self.request, result, runtime_facts=self.facts)

    def test_failed_cgroup_setup_cannot_verify(self):
        result = self.result(aggregate_setup_failed=True)
        raw = evidence_from_sandbox_result(self.plan, self.request, result, runtime_facts=self.facts)
        with self.assertRaises(EvidenceError):
            verify_evidence(self.plan, raw)

    def test_real_process_result_is_adapted_but_not_promoted(self):
        request = SandboxRequest(
            argv=("true",), cwd=self.workspace, workspace=self.workspace,
            memory_limit_bytes=512 * 1024 * 1024, max_tasks=128, seccomp="auto",
            aggregate_resource_scope="off",
        )
        result = run_sandboxed(request, backend="process")
        raw = evidence_from_sandbox_result(
            self.plan, request, result,
            runtime_facts={
                **self.facts,
                "rootless": False,
                "workspace_readonly": False,
                "cgroup_path": "not-enforced",
            },
        )
        self.assertEqual(raw["backend"], "process")
        with self.assertRaises(EvidenceError):
            verify_evidence(self.plan, raw)


if __name__ == "__main__":
    unittest.main()
