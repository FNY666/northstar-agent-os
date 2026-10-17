from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SECURITY = Path(__file__).resolve().parents[1]
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))
if str(SECURITY / "tests") not in sys.path:
    sys.path.insert(0, str(SECURITY / "tests"))

from sealing_fixtures import build_scenario  # noqa: E402
from trusted_common import sha, wire  # noqa: E402

_SPEC = importlib.util.spec_from_file_location("programming_security_bridge", SECURITY / "check-programming-security.py")
assert _SPEC is not None and _SPEC.loader is not None
bridge = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = bridge
_SPEC.loader.exec_module(bridge)


def _json_bytes(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _receipt_artifacts(patch: bytes, *, host_exit: int = 0, host_claims_success: bool | None = None) -> dict[str, bytes]:
    start = "a" * 40
    patch_sha = sha(patch)
    checks = ["python -m unittest"]
    task = {
        "goal": "change one local fixture",
        "checks": checks,
        "plan_only": False,
        "network_targets": [],
    }
    snapshot = {
        "schema": "northstar.repository-snapshot.v1",
        "start_commit": start,
        "source_relative": ".",
        "source_status": [],
    }
    transitions = [
        {"sequence": 1, "from": "created", "to": "understanding", "reason": "snapshot", "data": {}, "timestamp_unix_ms": 100},
        {"sequence": 2, "from": "understanding", "to": "planned", "reason": "plan", "data": {}, "timestamp_unix_ms": 101},
        {"sequence": 3, "from": "planned", "to": "executing", "reason": "write", "data": {}, "timestamp_unix_ms": 102},
        {"sequence": 4, "from": "executing", "to": "verifying", "reason": "host checks", "data": {}, "timestamp_unix_ms": 103},
        {"sequence": 5, "from": "verifying", "to": "success", "reason": "done", "data": {}, "timestamp_unix_ms": 106},
    ]
    phases = {
        "schema": "northstar.code-phases.v1",
        "run_id": "code-fixture-001",
        "state": "success",
        "outcome": "success",
        "plan_only": False,
        "plan": {"summary": "fixture", "files": ["app.py"], "steps": ["write"], "risks": [], "check_indices": [0]},
        "transitions": transitions,
        "effect_journal_version": 1,
        "effects": [
            {"effect_id": "effect-1", "sequence": 1, "tool": "Write", "call_id": "write-1", "phase": "executing", "status": "completed", "started_unix_ms": 102, "finished_unix_ms": 102, "error_class": ""},
            {"effect_id": "effect-2", "sequence": 2, "tool": "HostCheck", "call_id": "verification-0", "phase": "verifying", "status": "completed", "started_unix_ms": 104, "finished_unix_ms": 105, "error_class": ""},
        ],
    }
    result_ok = host_exit == 0 if host_claims_success is None else host_claims_success
    verification = {
        "schema": "northstar.code-verification.v1",
        "summaries": [{
            "declared": 1,
            "ran": 1,
            "passed": 1 if result_ok else 0,
            "failed": 0 if result_ok else 1,
            "skipped": 0,
            "ok": result_ok,
            "network": "denied",
            "results": [{
                "index": 0,
                "command": checks[0],
                "exit_code": host_exit,
                "ok": result_ok,
                "timed_out": False,
                "truncated": False,
                "duration_ms": 5,
                "output_sha256": sha(b"fixture host output"),
                "output_excerpt": "fixture host output",
                "error": None,
            }],
        }],
    }
    replay = {
        "schema": "northstar.patch-replay.v1",
        "start_commit": start,
        "patch_bytes": len(patch),
        "patch_sha256": patch_sha,
        "empty": not bool(patch),
        "read_tree_exit_code": 0,
        "apply_exit_code": 0,
        "ok": True,
        "diagnostic": "",
    }
    audit = {
        "schema": "northstar.patch-audit.v1",
        "ok": True,
        "changed_files": 1,
        "patch_bytes": len(patch),
        "patch_sha256": patch_sha,
        "findings": [],
    }
    seal = {
        "schema": "northstar.delivery-seal.v1",
        "start_commit": start,
        "precheck_patch_sha256": patch_sha,
        "patch_sha256": patch_sha,
        "unchanged_during_verification": True,
        "patch_audit_ok": True,
        "ok": True,
    }
    return {
        "task": _json_bytes(task),
        "repository_snapshot": _json_bytes(snapshot),
        "phases": _json_bytes(phases),
        "verification": _json_bytes(verification),
        "patch": patch,
        "patch_replay": _json_bytes(replay),
        "patch_audit": _json_bytes(audit),
        "delivery_seal": _json_bytes(seal),
    }


def make_code_evidence(root: Path, *, patch: bytes = b"patch", status: str = "success", host_exit: int = 0, host_claims_success: bool | None = None) -> Path:
    root.mkdir()
    artifacts = _receipt_artifacts(patch, host_exit=host_exit, host_claims_success=host_claims_success)
    names = {
        "task": "task.json",
        "repository_snapshot": "repository-snapshot.json",
        "phases": "phases.json",
        "verification": "verification.json",
        "patch": "changes.patch",
        "patch_replay": "patch-replay.json",
        "patch_audit": "patch-audit.json",
        "delivery_seal": "delivery-seal.json",
    }
    for field, raw in artifacts.items():
        (root / names[field]).write_bytes(raw)
    manifest = {
        "schema": "northstar.code-evidence.v1",
        "run_id": "code-fixture-001",
        "start_commit": "a" * 40,
        "source_relative": ".",
        "source_status": [],
        "status": status,
        # Intentionally remains zero for success_unverified: this test proves
        # that a zero default exit does not establish verified success.
        "exit_code": 0,
        "patch_bytes": len(patch),
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
        "verification_ok": host_exit == 0 if host_claims_success is None else host_claims_success,
        "patch_replay_ok": True,
        "patch_audit_ok": True,
        "delivery_seal_ok": True,
    }
    for field, name in names.items():
        manifest[field] = name
        manifest[field + "_sha256"] = sha(artifacts[field])
    (root / "manifest.json").write_bytes(_json_bytes(manifest))
    return root


class ProgrammingSecurityBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.scenario = build_scenario(self.root / "signed")
        self.trust = self.root / "external-trust.json"
        self.identity = self.root / "external-identity.json"
        self.trust.write_bytes(wire(self.scenario.trust))
        self.identity.write_bytes(wire(self.scenario.identity))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def report(self, code: Path) -> dict:
        return bridge.inspect(code, self.scenario.produced_dir, self.trust, self.identity)

    def test_consistent_verified_code_delivery_and_signed_produced_pass(self) -> None:
        code = make_code_evidence(self.root / "code-evidence")
        report = self.report(code)
        self.assertTrue(report["read_only"])
        self.assertTrue(report["verified_success"])
        self.assertEqual(report["classification"], "verified_programming_security_bridge")
        self.assertEqual(report["code"]["host_checks"], 1)
        self.assertEqual(report["code"]["patch_sha256"], hashlib.sha256(b"patch").hexdigest())
        self.assertTrue(report["security"]["fresh_gate_passed"])
        self.assertTrue(report["bindings"]["start_commit"])
        self.assertTrue(report["bindings"]["patch_sha256"])
        self.assertFalse(report["bindings"]["candidate_manifest_rebuilt"])

    def test_success_unverified_with_exit_zero_is_not_verified(self) -> None:
        code = make_code_evidence(self.root / "code-evidence", status="success_unverified")
        report = self.report(code)
        self.assertFalse(report["verified_success"])
        code_gate = next(gate for gate in report["gates"] if gate["name"] == "code_verified_success")
        self.assertFalse(code_gate["passed"])

    def test_failed_host_receipt_cannot_be_replaced_by_model_claim(self) -> None:
        code = make_code_evidence(
            self.root / "code-evidence", host_exit=1, host_claims_success=True
        )
        report = self.report(code)
        self.assertFalse(report["verified_success"])
        code_gate = next(gate for gate in report["gates"] if gate["name"] == "code_verified_success")
        self.assertFalse(code_gate["passed"])

    def test_signed_plan_patch_subject_must_match_delivery_patch_bytes(self) -> None:
        code = make_code_evidence(self.root / "code-evidence", patch=b"another patch")
        report = self.report(code)
        self.assertFalse(report["verified_success"])
        binding = next(gate for gate in report["gates"] if gate["name"] == "signed_plan_delivery_binding")
        self.assertFalse(binding["passed"])
        self.assertIn("patch_sha256", binding["reasons"][0])

    def test_tampered_signed_plan_is_rejected_by_fresh_signature_graph(self) -> None:
        code = make_code_evidence(self.root / "code-evidence")
        plan = self.scenario.produced_dir / "plan.dsse.json"
        plan.write_bytes(plan.read_bytes() + b" ")
        report = self.report(code)
        self.assertFalse(report["verified_success"])
        gate = next(gate for gate in report["gates"] if gate["name"] == "signed_produced_fresh_gate")
        self.assertFalse(gate["passed"])

    def test_trust_inside_produced_package_is_not_an_external_root(self) -> None:
        code = make_code_evidence(self.root / "code-evidence")
        embedded = self.scenario.produced_dir / "embedded-trust.json"
        embedded.write_bytes(self.trust.read_bytes())
        report = bridge.inspect(code, self.scenario.produced_dir, embedded, self.identity)
        self.assertFalse(report["verified_success"])
        gate = next(gate for gate in report["gates"] if gate["name"] == "external_trust_identity")
        self.assertFalse(gate["passed"])

    def test_cli_returns_zero_only_for_a_verified_bridge(self) -> None:
        code = make_code_evidence(self.root / "code-evidence")
        command = [
            sys.executable,
            str(SECURITY / "check-programming-security.py"),
            "--code-evidence-dir", str(code),
            "--produced-dir", str(self.scenario.produced_dir),
            "--trust-store", str(self.trust),
            "--identity", str(self.identity),
        ]
        passed = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(passed.returncode, 0, passed.stderr)
        self.assertTrue(json.loads(passed.stdout)["verified_success"])
        failed_code = make_code_evidence(self.root / "unverified", status="success_unverified")
        command[3] = str(failed_code)
        failed = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(failed.returncode, 2, failed.stderr)
        self.assertFalse(json.loads(failed.stdout)["verified_success"])


if __name__ == "__main__":
    unittest.main()
