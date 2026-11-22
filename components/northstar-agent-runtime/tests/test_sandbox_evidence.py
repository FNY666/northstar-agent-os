from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import support  # noqa: F401
from tools.deterministic_kernel import SandboxPolicy
from tools.sandbox_evidence import EvidenceError, SCHEMA, verify_evidence


def digest(value):
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def evidence_for(plan, **overrides):
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
    body.update(overrides)
    body["evidence_digest"] = digest(body)
    return body


class SandboxEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        workspace = Path(self.tmp.name)
        self.plan = SandboxPolicy(workspace=workspace).plan(("true",))

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_evidence_is_accepted(self):
        evidence = verify_evidence(self.plan, evidence_for(self.plan), require_os_isolation=True)
        self.assertEqual(evidence.plan_digest, self.plan.digest)
        self.assertEqual(evidence.descendant_pids, 0)

    def test_plan_mismatch_is_refused(self):
        other = SandboxPolicy(workspace=Path(self.tmp.name)).plan(("false",))
        with self.assertRaises(EvidenceError):
            verify_evidence(self.plan, evidence_for(other))

    def test_weaker_runtime_limits_are_refused(self):
        for field, value in (
            ("effective_memory_max_bytes", self.plan.data["memory_max_bytes"] + 1),
            ("effective_pids_max", self.plan.data["pids_max"] + 1),
            ("effective_cpu_max_percent", self.plan.data["cpu_max_percent"] + 1),
        ):
            with self.subTest(field=field):
                with self.assertRaises(EvidenceError):
                    verify_evidence(self.plan, evidence_for(self.plan, **{field: value}))

    def test_missing_security_controls_are_refused(self):
        for field, value in (("rootless", False), ("workspace_readonly", False),
                             ("seccomp_loaded", False), ("cgroup_enforced", False),
                             ("descendant_pids", 1)):
            with self.subTest(field=field):
                with self.assertRaises(EvidenceError):
                    verify_evidence(self.plan, evidence_for(self.plan, **{field: value}))

    def test_tampered_evidence_digest_is_refused(self):
        raw = evidence_for(self.plan)
        raw["backend"] = "oci"
        with self.assertRaises(EvidenceError):
            verify_evidence(self.plan, raw)


if __name__ == "__main__":
    unittest.main()
