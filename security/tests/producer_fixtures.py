"""Ephemeral, test-only fixtures for ``test_producer``.

Nothing in this module is a scanner or a deployment key.  Each fixture creates
fresh in-memory Ed25519 keys and illustrative normalized records solely to test
the producer's trust-boundary behavior.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trusted_common import create_receipt, file_manifest, sha, stamp, wire

UTC = timezone.utc
COMPONENTS = [
    "northstar_run_contract",
    "northstar_run_evidence",
    "northstar_host",
    "northstar_durable_run",
    "northstar_agent_interop",
    "northstar_agent_runtime",
]


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def key_id(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def trust_entry(private: Ed25519PrivateKey, kinds: list[str], repository: str, now: datetime) -> dict[str, Any]:
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "public_key": base64.b64encode(raw).decode("ascii"),
        "kinds": kinds,
        "repository": repository,
        "not_before": stamp(now - timedelta(days=1)),
        "not_after": stamp(now + timedelta(days=1)),
        "revoked": False,
    }


def timestamp(value: datetime) -> str:
    return stamp(value.replace(microsecond=0))


def artifact(name: str, payload: bytes) -> dict[str, Any]:
    return {"name": name, "sha256": sha(payload), "bytes": len(payload)}


def private_key_pem(private: Ed25519PrivateKey) -> bytes:
    return private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@dataclass
class ProducerScenario:
    root: Path
    now: datetime
    identity: dict[str, Any]
    trust: dict[str, Any]
    keys: dict[str, Ed25519PrivateKey]
    plan_body: dict[str, Any]
    files: dict[str, bytes]
    records: dict[str, dict[str, Any]]
    plan_path: Path
    capture_path: Path
    evidence_dir: Path

    def write_plan(self, issued_at: datetime | None = None) -> bytes:
        raw = create_receipt(
            "scan-plan",
            self.identity,
            self.plan_body,
            self.keys["plan"],
            self.trust,
            now=self.now - timedelta(seconds=120) if issued_at is None else issued_at,
        )
        self.plan_path.write_bytes(raw)
        return raw

    def sync_record(self, tool: str) -> None:
        self.files[self.plan_body["expectation_template"]["tools"][tool]["evidence_file"]] = wire(self.records[tool])

    def write_evidence(self) -> None:
        if self.evidence_dir.exists():
            shutil.rmtree(self.evidence_dir)
        self.evidence_dir.mkdir()
        for name, payload in self.files.items():
            (self.evidence_dir / name).write_bytes(payload)

    def write_capture(self, issued_at: datetime | None = None) -> bytes:
        self.write_evidence()
        plan_raw = self.plan_path.read_bytes()
        raw = create_receipt(
            "scan-capture",
            self.identity,
            {
                "schema": "northstar.scan-capture.v1",
                "plan_sha256": sha(plan_raw),
                "files": file_manifest(self.files),
            },
            self.keys["capture"],
            self.trust,
            now=self.now if issued_at is None else issued_at,
        )
        self.capture_path.write_bytes(raw)
        return raw

    def reseal_capture(self, tool: str | None = None, issued_at: datetime | None = None) -> None:
        if tool is not None:
            self.sync_record(tool)
        self.write_capture(issued_at)

    def write_cli_inputs(self) -> tuple[Path, Path]:
        trust_path = self.root / "trust-store.json"
        identity_path = self.root / "identity.json"
        key_path = self.root / "expectation-private.pem"
        trust_path.write_bytes(wire(self.trust))
        identity_path.write_bytes(wire(self.identity))
        key_path.write_bytes(private_key_pem(self.keys["expectation"]))
        os.chmod(key_path, 0o600)
        return trust_path, identity_path


def build_scenario(root: str | Path, *, now: datetime | None = None) -> ProducerScenario:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    current = (datetime.now(UTC) if now is None else now.astimezone(UTC)).replace(microsecond=0)
    identity = {
        "repository": "owner/repository",
        "run_id": "trusted-run-001",
        "run_attempt": 1,
        "source_commit": "a" * 40,
        "nonce": "b" * 64,
    }
    keys = {name: Ed25519PrivateKey.generate() for name in ("plan", "capture", "expectation")}
    trust = {
        "schema": "northstar.receipt-trust.v1",
        "keys": {
            key_id(keys["plan"]): trust_entry(keys["plan"], ["scan-plan"], identity["repository"], current),
            key_id(keys["capture"]): trust_entry(keys["capture"], ["scan-capture"], identity["repository"], current),
            key_id(keys["expectation"]): trust_entry(keys["expectation"], ["expectation"], identity["repository"], current),
        },
    }
    started = current - timedelta(seconds=90)
    finished = current - timedelta(seconds=30)
    subject = {
        "start_commit": identity["source_commit"],
        "patch_sha256": digest("patch"),
        "candidate_manifest_sha256": digest("candidate-manifest"),
    }
    semgrep_stdout = wire({"errors": [], "results": [], "tool": "semgrep"})
    osv_stdout = wire({"results": [], "tool": "osv-scanner"})
    files: dict[str, bytes] = {
        "semgrep.stdout.json": semgrep_stdout,
        "semgrep.stderr.txt": b"",
        "osv.stdout.json": osv_stdout,
        "osv.stderr.txt": b"",
    }
    semgrep_view, osv_view = digest("semgrep-view"), digest("osv-view")
    isolation = {
        "backend": "oci",
        "read_only_inputs": True,
        "network": "denied",
        "credentials": "none",
        "project_code_executed": False,
        "non_root": True,
    }
    execution = {
        "status": "completed",
        "started_at": timestamp(started),
        "finished_at": timestamp(finished),
        "duration_ms": 60000,
        "exit_code": 0,
        "timed_out": False,
        "resource_exhausted": False,
        "output_truncated": False,
    }
    semgrep_observed = {"path": "src/service.py", "sha256": digest("src/service.py"), "ecosystems": [], "package_count": 0}
    osv_observed = {"path": "requirements.txt", "sha256": digest("requirements.txt"), "ecosystems": ["PyPI"], "package_count": 2}
    records = {
        "semgrep": {
            "schema": "northstar.security-scan.v1",
            "run_id": identity["run_id"],
            "subject": {**subject, "scan_view_manifest_sha256": semgrep_view},
            "tool": {
                "name": "semgrep",
                "version": "1.80.0-test",
                "distribution_sha256": digest("semgrep-distribution"),
                "normalizer_sha256": digest("semgrep-normalizer"),
                "config_sha256": digest("semgrep-config"),
                "rules_sha256": digest("semgrep-rules"),
                "database": None,
            },
            "execution": copy.deepcopy(execution),
            "isolation": copy.deepcopy(isolation),
            "coverage": {"status": "complete", "observed_inputs": [semgrep_observed], "skipped_inputs": [], "unresolved_inputs": [], "error_count": 0},
            "findings": [],
            "artifacts": {"stdout": artifact("semgrep.stdout.json", semgrep_stdout), "stderr": artifact("semgrep.stderr.txt", b"")},
        },
        "osv-scanner": {
            "schema": "northstar.security-scan.v1",
            "run_id": identity["run_id"],
            "subject": {**subject, "scan_view_manifest_sha256": osv_view},
            "tool": {
                "name": "osv-scanner",
                "version": "2.0.0-test",
                "distribution_sha256": digest("osv-distribution"),
                "normalizer_sha256": digest("osv-normalizer"),
                "config_sha256": digest("osv-config"),
                "rules_sha256": None,
                "database": {"manifest_sha256": digest("osv-db"), "updated_at": timestamp(current - timedelta(minutes=15)), "ecosystems": ["PyPI"]},
            },
            "execution": copy.deepcopy(execution),
            "isolation": copy.deepcopy(isolation),
            "coverage": {"status": "complete", "observed_inputs": [osv_observed], "skipped_inputs": [], "unresolved_inputs": [], "error_count": 0},
            "findings": [],
            "artifacts": {"stdout": artifact("osv.stdout.json", osv_stdout), "stderr": artifact("osv.stderr.txt", b"")},
        },
    }
    template = {
        "schema": "northstar.security-expectation.v1",
        "run_id": identity["run_id"],
        "subject": subject,
        "policy": {
            "id": "test-policy-v1",
            "sha256": digest("test-policy"),
            "blocking_severities": ["critical", "high"],
            "unknown_severity": "review",
            "max_scan_age_seconds": 3600,
            "max_database_age_seconds": 86400,
            "max_clock_skew_seconds": 60,
            "max_duration_ms": 600000,
        },
        "tools": {
            "semgrep": {
                "required": True,
                "not_applicable_reason": None,
                "evidence_file": "semgrep-evidence.json",
                "version": records["semgrep"]["tool"]["version"],
                "distribution_sha256": records["semgrep"]["tool"]["distribution_sha256"],
                "normalizer_sha256": records["semgrep"]["tool"]["normalizer_sha256"],
                "config_sha256": records["semgrep"]["tool"]["config_sha256"],
                "rules_sha256": records["semgrep"]["tool"]["rules_sha256"],
                "database_manifest_sha256": None,
                "scan_view_manifest_sha256": semgrep_view,
                "isolation_backend": "oci",
                "expected_inputs": [{"path": semgrep_observed["path"], "sha256": semgrep_observed["sha256"], "ecosystems": [], "min_packages": 0}],
            },
            "osv-scanner": {
                "required": True,
                "not_applicable_reason": None,
                "evidence_file": "osv-evidence.json",
                "version": records["osv-scanner"]["tool"]["version"],
                "distribution_sha256": records["osv-scanner"]["tool"]["distribution_sha256"],
                "normalizer_sha256": records["osv-scanner"]["tool"]["normalizer_sha256"],
                "config_sha256": records["osv-scanner"]["tool"]["config_sha256"],
                "rules_sha256": None,
                "database_manifest_sha256": records["osv-scanner"]["tool"]["database"]["manifest_sha256"],
                "scan_view_manifest_sha256": osv_view,
                "isolation_backend": "oci",
                "expected_inputs": [{"path": osv_observed["path"], "sha256": osv_observed["sha256"], "ecosystems": ["PyPI"], "min_packages": 2}],
            },
        },
    }
    scenario = ProducerScenario(
        root=root,
        now=current,
        identity=identity,
        trust=trust,
        keys=keys,
        plan_body={"schema": "northstar.scan-plan.v1", "expectation_template": template, "release_components": COMPONENTS, "release_version": "0.1.0"},
        files=files,
        records=records,
        plan_path=root / "plan-input.dsse.json",
        capture_path=root / "capture-input.dsse.json",
        evidence_dir=root / "captured-evidence",
    )
    scenario.sync_record("semgrep")
    scenario.sync_record("osv-scanner")
    scenario.write_plan()
    scenario.write_capture()
    return scenario
