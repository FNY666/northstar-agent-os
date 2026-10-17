"""Private test fixtures for release sealing; no production key or scanner is used."""
from __future__ import annotations

import base64
import copy
import hashlib
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trusted_common import create_receipt, file_manifest, sha, stamp, wire
from security_evidence import evaluate_bundle

UTC = timezone.utc
COMPONENTS = [
    "northstar_run_contract",
    "northstar_run_evidence",
    "northstar_host",
    "northstar_durable_run",
    "northstar_agent_interop",
    "northstar_agent_runtime",
]


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _key_id(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sha(raw)


def _trust_entry(key: Ed25519PrivateKey, kinds: list[str], repository: str, now: datetime) -> dict[str, Any]:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "public_key": base64.b64encode(raw).decode("ascii"),
        "kinds": kinds,
        "repository": repository,
        "not_before": stamp(now - timedelta(days=1)),
        "not_after": stamp(now + timedelta(days=1)),
        "revoked": False,
    }


def _time(value: datetime) -> str:
    return stamp(value.replace(microsecond=0))


def _artifact(name: str, raw: bytes) -> dict[str, Any]:
    return {"name": name, "sha256": sha(raw), "bytes": len(raw)}


def _write_tree(path: Path, values: dict[str, bytes]) -> None:
    path.mkdir(parents=True, exist_ok=False)
    for name, raw in values.items():
        (path / name).write_bytes(raw)


def make_writable(path: Path) -> None:
    if path.is_dir():
        os.chmod(path, 0o700)
        for child in path.iterdir():
            os.chmod(child, 0o600)
    else:
        os.chmod(path, 0o600)


def snapshot(path: Path) -> list[tuple[str, int, int, str]]:
    result: list[tuple[str, int, int, str]] = []
    for child in sorted(path.iterdir(), key=lambda item: item.name):
        info = child.lstat()
        raw_hash = sha(child.read_bytes()) if stat.S_ISREG(info.st_mode) else ""
        result.append((child.name, stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode), raw_hash))
    return result


@dataclass
class SealingScenario:
    root: Path
    now: datetime
    identity: dict[str, Any]
    trust: dict[str, Any]
    keys: dict[str, Ed25519PrivateKey]
    plan_raw: bytes
    capture_raw: bytes
    expectation_raw: bytes
    producer_gate_raw: bytes
    expectation_receipt_raw: bytes
    capture_files: dict[str, bytes]
    wheels: dict[str, bytes]
    produced_dir: Path
    dist_dir: Path
    build_capture_path: Path

    def write_build_capture(self, *, plan_sha256: str | None = None, files: dict[str, bytes] | None = None) -> bytes:
        selected = self.wheels if files is None else files
        raw = create_receipt(
            "build-capture",
            self.identity,
            {
                "schema": "northstar.build-capture.v1",
                "plan_sha256": sha(self.plan_raw) if plan_sha256 is None else plan_sha256,
                "files": file_manifest(selected),
            },
            self.keys["build"],
            self.trust,
            now=self.now,
        )
        self.build_capture_path.write_bytes(raw)
        return raw

    def rewrite_expectation_receipt(self, gate_raw: bytes) -> None:
        self.producer_gate_raw = gate_raw
        self.expectation_receipt_raw = create_receipt(
            "expectation",
            self.identity,
            {
                "schema": "northstar.expectation-receipt.v1",
                "plan_sha256": sha(self.plan_raw),
                "capture_sha256": sha(self.capture_raw),
                "expectation_sha256": sha(self.expectation_raw),
                "gate_sha256": sha(gate_raw),
            },
            self.keys["expectation"],
            self.trust,
            now=self.now,
        )
        make_writable(self.produced_dir)
        (self.produced_dir / "security-gate.json").write_bytes(gate_raw)
        (self.produced_dir / "expectation.dsse.json").write_bytes(self.expectation_receipt_raw)
        os.chmod(self.produced_dir / "security-gate.json", 0o400)
        os.chmod(self.produced_dir / "expectation.dsse.json", 0o400)
        os.chmod(self.produced_dir, 0o500)


def build_scenario(root: str | Path, *, now: datetime | None = None) -> SealingScenario:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    current = (datetime.now(UTC) if now is None else now.astimezone(UTC)).replace(microsecond=0)
    identity = {
        "repository": "owner/repository",
        "run_id": "trusted-seal-001",
        "run_attempt": 7,
        "source_commit": "a" * 40,
        "nonce": "b" * 64,
    }
    keys = {role: Ed25519PrivateKey.generate() for role in ("plan", "capture", "expectation", "build", "seal")}
    roles = {
        "plan": ["scan-plan"], "capture": ["scan-capture"], "expectation": ["expectation"],
        "build": ["build-capture"], "seal": ["release-seal"],
    }
    trust = {"schema": "northstar.receipt-trust.v1", "keys": {
        _key_id(keys[role]): _trust_entry(keys[role], kinds, identity["repository"], current)
        for role, kinds in roles.items()
    }}

    started, finished = current - timedelta(seconds=90), current - timedelta(seconds=30)
    subject = {"start_commit": identity["source_commit"], "patch_sha256": digest("patch"), "candidate_manifest_sha256": digest("candidate")}
    semgrep_stdout, osv_stdout = wire({"results": [], "tool": "semgrep"}), wire({"results": [], "tool": "osv"})
    files: dict[str, bytes] = {
        "semgrep.stdout.json": semgrep_stdout, "semgrep.stderr.txt": b"",
        "osv.stdout.json": osv_stdout, "osv.stderr.txt": b"",
    }
    sem_view, osv_view = digest("sem-view"), digest("osv-view")
    isolation = {"backend": "oci", "read_only_inputs": True, "network": "denied", "credentials": "none", "project_code_executed": False, "non_root": True}
    execution = {"status": "completed", "started_at": _time(started), "finished_at": _time(finished), "duration_ms": 60000, "exit_code": 0, "timed_out": False, "resource_exhausted": False, "output_truncated": False}
    sem_observed = {"path": "src/app.py", "sha256": digest("app"), "ecosystems": [], "package_count": 0}
    osv_observed = {"path": "requirements.txt", "sha256": digest("requirements"), "ecosystems": ["PyPI"], "package_count": 1}
    records = {
        "semgrep": {
            "schema": "northstar.security-scan.v1", "run_id": identity["run_id"],
            "subject": {**subject, "scan_view_manifest_sha256": sem_view},
            "tool": {"name": "semgrep", "version": "1.0-test", "distribution_sha256": digest("sem-dist"), "normalizer_sha256": digest("sem-norm"), "config_sha256": digest("sem-config"), "rules_sha256": digest("sem-rules"), "database": None},
            "execution": copy.deepcopy(execution), "isolation": copy.deepcopy(isolation),
            "coverage": {"status": "complete", "observed_inputs": [sem_observed], "skipped_inputs": [], "unresolved_inputs": [], "error_count": 0},
            "findings": [], "artifacts": {"stdout": _artifact("semgrep.stdout.json", semgrep_stdout), "stderr": _artifact("semgrep.stderr.txt", b"")},
        },
        "osv-scanner": {
            "schema": "northstar.security-scan.v1", "run_id": identity["run_id"],
            "subject": {**subject, "scan_view_manifest_sha256": osv_view},
            "tool": {"name": "osv-scanner", "version": "2.0-test", "distribution_sha256": digest("osv-dist"), "normalizer_sha256": digest("osv-norm"), "config_sha256": digest("osv-config"), "rules_sha256": None, "database": {"manifest_sha256": digest("osv-db"), "updated_at": _time(current - timedelta(minutes=10)), "ecosystems": ["PyPI"]}},
            "execution": copy.deepcopy(execution), "isolation": copy.deepcopy(isolation),
            "coverage": {"status": "complete", "observed_inputs": [osv_observed], "skipped_inputs": [], "unresolved_inputs": [], "error_count": 0},
            "findings": [], "artifacts": {"stdout": _artifact("osv.stdout.json", osv_stdout), "stderr": _artifact("osv.stderr.txt", b"")},
        },
    }
    files["semgrep-evidence.json"] = wire(records["semgrep"])
    files["osv-evidence.json"] = wire(records["osv-scanner"])
    template = {
        "schema": "northstar.security-expectation.v1", "run_id": identity["run_id"], "subject": subject,
        "policy": {"id": "fixture-policy", "sha256": digest("policy"), "blocking_severities": ["critical", "high"], "unknown_severity": "review", "max_scan_age_seconds": 3600, "max_database_age_seconds": 86400, "max_clock_skew_seconds": 60, "max_duration_ms": 600000},
        "tools": {
            "semgrep": {"required": True, "not_applicable_reason": None, "evidence_file": "semgrep-evidence.json", "version": records["semgrep"]["tool"]["version"], "distribution_sha256": records["semgrep"]["tool"]["distribution_sha256"], "normalizer_sha256": records["semgrep"]["tool"]["normalizer_sha256"], "config_sha256": records["semgrep"]["tool"]["config_sha256"], "rules_sha256": records["semgrep"]["tool"]["rules_sha256"], "database_manifest_sha256": None, "scan_view_manifest_sha256": sem_view, "isolation_backend": "oci", "expected_inputs": [{"path": sem_observed["path"], "sha256": sem_observed["sha256"], "ecosystems": [], "min_packages": 0}]},
            "osv-scanner": {"required": True, "not_applicable_reason": None, "evidence_file": "osv-evidence.json", "version": records["osv-scanner"]["tool"]["version"], "distribution_sha256": records["osv-scanner"]["tool"]["distribution_sha256"], "normalizer_sha256": records["osv-scanner"]["tool"]["normalizer_sha256"], "config_sha256": records["osv-scanner"]["tool"]["config_sha256"], "rules_sha256": None, "database_manifest_sha256": records["osv-scanner"]["tool"]["database"]["manifest_sha256"], "scan_view_manifest_sha256": osv_view, "isolation_backend": "oci", "expected_inputs": [{"path": osv_observed["path"], "sha256": osv_observed["sha256"], "ecosystems": ["PyPI"], "min_packages": 1}]},
        },
    }
    plan_body = {"schema": "northstar.scan-plan.v1", "expectation_template": template, "release_components": COMPONENTS, "release_version": "0.1.0"}
    plan_raw = create_receipt("scan-plan", identity, plan_body, keys["plan"], trust, now=current - timedelta(seconds=120))
    capture_raw = create_receipt("scan-capture", identity, {"schema": "northstar.scan-capture.v1", "plan_sha256": sha(plan_raw), "files": file_manifest(files)}, keys["capture"], trust, now=current)
    expectation = copy.deepcopy(template)
    for tool in ("semgrep", "osv-scanner"):
        name = expectation["tools"][tool]["evidence_file"]
        expectation["tools"][tool]["evidence_sha256"] = sha(files[name])
    expectation_raw = wire(expectation)
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        for name, raw in {**files, "host-expectation.json": expectation_raw}.items():
            (temp / name).write_bytes(raw)
        gate_raw = wire(evaluate_bundle(temp, temp / "host-expectation.json", now=current))
    expectation_receipt_raw = create_receipt("expectation", identity, {"schema": "northstar.expectation-receipt.v1", "plan_sha256": sha(plan_raw), "capture_sha256": sha(capture_raw), "expectation_sha256": sha(expectation_raw), "gate_sha256": sha(gate_raw)}, keys["expectation"], trust, now=current)
    produced_dir = root / "produced"
    _write_tree(produced_dir, {**files, "plan.dsse.json": plan_raw, "capture.dsse.json": capture_raw, "host-expectation.json": expectation_raw, "security-gate.json": gate_raw, "expectation.dsse.json": expectation_receipt_raw})
    dist_dir = root / "dist"
    wheels = {f"{component}-0.1.0-py3-none-any.whl": ("fixture wheel " + component).encode("ascii") for component in COMPONENTS}
    _write_tree(dist_dir, wheels)
    build_capture_path = root / "build-capture.dsse.json"
    scenario = SealingScenario(root, current, identity, trust, keys, plan_raw, capture_raw, expectation_raw, gate_raw, expectation_receipt_raw, files, wheels, produced_dir, dist_dir, build_capture_path)
    scenario.write_build_capture()
    return scenario
