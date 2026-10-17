#!/usr/bin/env python3
"""Create a self-contained, illustrative security-evidence v1 pass fixture.

The files produced here are contract fixtures, not records of a real Semgrep or
OSV execution.  ``build_fixture`` is deliberately importable so validator tests
can start from a correctly pinned bundle and alter one property at a time.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


UTC = timezone.utc


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _wire(value: Any) -> bytes:
    """The deterministic JSON representation used for evidence-byte pins."""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _timestamp(value: datetime) -> str:
    value = value.astimezone(UTC).replace(microsecond=0)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalise_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(UTC)
    if now.tzinfo is None:
        return now.replace(tzinfo=UTC)
    return now.astimezone(UTC)


def _write_bytes(root: Path, name: str, payload: bytes) -> dict[str, Any]:
    (root / name).write_bytes(payload)
    return {"name": name, "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}


def build_fixture(root: str | Path, now: datetime | None = None) -> dict[str, Any]:
    """Build a pinned two-tool pass bundle in *root* and return its objects.

    The timestamps are anchored to the supplied UTC clock (or the current UTC
    clock), rather than being hard-coded.  Therefore a newly generated fixture
    remains fresh under the host policy.  Returned ``context`` and ``records``
    are ordinary mutable dictionaries to make focused test mutations simple;
    callers must re-pin a changed record in the returned context themselves.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    now_utc = _normalise_now(now).replace(microsecond=0)
    started_at = now_utc - timedelta(seconds=90)
    finished_at = now_utc - timedelta(seconds=30)

    # These source-output blobs are small, recognizable JSON objects.  They
    # are illustrative raw blobs only; this script does not run either scanner.
    semgrep_stdout = _write_bytes(
        root,
        "semgrep.stdout.json",
        _wire({"errors": [], "results": [], "tool": "semgrep"}),
    )
    semgrep_stderr = _write_bytes(root, "semgrep.stderr.txt", b"")
    osv_stdout = _write_bytes(
        root,
        "osv.stdout.json",
        _wire({"results": [], "tool": "osv-scanner"}),
    )
    osv_stderr = _write_bytes(root, "osv.stderr.txt", b"")

    subject = {
        "start_commit": _sha("fixture start commit"),
        "patch_sha256": _sha("fixture candidate patch"),
        "candidate_manifest_sha256": _sha("fixture candidate manifest"),
    }
    semgrep_view = _sha("fixture semgrep scan view manifest")
    osv_view = _sha("fixture osv scan view manifest")
    semgrep_input = {
        "path": "src/service.py",
        "sha256": _sha("fixture src/service.py"),
        "ecosystems": [],
        "package_count": 0,
    }
    osv_input = {
        "path": "requirements.txt",
        "sha256": _sha("fixture requirements.txt"),
        "ecosystems": ["PyPI"],
        "package_count": 2,
    }

    shared_isolation = {
        "backend": "oci",
        "read_only_inputs": True,
        "network": "denied",
        "credentials": "none",
        "project_code_executed": False,
        "non_root": True,
    }
    completed = {
        "status": "completed",
        "started_at": _timestamp(started_at),
        "finished_at": _timestamp(finished_at),
        "duration_ms": 60000,
        "exit_code": 0,
        "timed_out": False,
        "resource_exhausted": False,
        "output_truncated": False,
    }
    clean_coverage = lambda observed: {
        "status": "complete",
        "observed_inputs": [observed],
        "skipped_inputs": [],
        "unresolved_inputs": [],
        "error_count": 0,
    }

    records: dict[str, dict[str, Any]] = {
        "semgrep": {
            "schema": "northstar.security-scan.v1",
            "run_id": "fixture-run-001",
            "subject": {**subject, "scan_view_manifest_sha256": semgrep_view},
            "tool": {
                "name": "semgrep",
                "version": "1.80.0-fixture",
                "distribution_sha256": _sha("semgrep distribution 1.80.0-fixture"),
                "normalizer_sha256": _sha("semgrep normalizer v1"),
                "config_sha256": _sha("semgrep config v1"),
                "rules_sha256": _sha("semgrep rules v1"),
                "database": None,
            },
            "execution": dict(completed),
            "isolation": dict(shared_isolation),
            "coverage": clean_coverage(semgrep_input),
            "findings": [],
            "artifacts": {"stdout": semgrep_stdout, "stderr": semgrep_stderr},
        },
        "osv-scanner": {
            "schema": "northstar.security-scan.v1",
            "run_id": "fixture-run-001",
            "subject": {**subject, "scan_view_manifest_sha256": osv_view},
            "tool": {
                "name": "osv-scanner",
                "version": "2.0.0-fixture",
                "distribution_sha256": _sha("osv-scanner distribution 2.0.0-fixture"),
                "normalizer_sha256": _sha("osv-scanner normalizer v1"),
                "config_sha256": _sha("osv-scanner config v1"),
                "rules_sha256": None,
                "database": {
                    "manifest_sha256": _sha("osv database snapshot v1"),
                    "updated_at": _timestamp(now_utc - timedelta(minutes=15)),
                    "ecosystems": ["PyPI"],
                },
            },
            "execution": dict(completed),
            "isolation": dict(shared_isolation),
            "coverage": clean_coverage(osv_input),
            "findings": [],
            "artifacts": {"stdout": osv_stdout, "stderr": osv_stderr},
        },
    }

    evidence_names = {"semgrep": "semgrep-evidence.json", "osv-scanner": "osv-evidence.json"}
    evidence_hashes: dict[str, str] = {}
    for tool, record in records.items():
        encoded = _wire(record)
        (root / evidence_names[tool]).write_bytes(encoded)
        evidence_hashes[tool] = hashlib.sha256(encoded).hexdigest()

    context = {
        "schema": "northstar.security-expectation.v1",
        "run_id": "fixture-run-001",
        "subject": subject,
        "policy": {
            "id": "fixture-security-policy-v1",
            "sha256": _sha("fixture security policy v1"),
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
                "evidence_file": evidence_names["semgrep"],
                "evidence_sha256": evidence_hashes["semgrep"],
                "version": records["semgrep"]["tool"]["version"],
                "distribution_sha256": records["semgrep"]["tool"]["distribution_sha256"],
                "normalizer_sha256": records["semgrep"]["tool"]["normalizer_sha256"],
                "config_sha256": records["semgrep"]["tool"]["config_sha256"],
                "rules_sha256": records["semgrep"]["tool"]["rules_sha256"],
                "database_manifest_sha256": None,
                "scan_view_manifest_sha256": semgrep_view,
                "isolation_backend": "oci",
                "expected_inputs": [
                    {
                        "path": semgrep_input["path"],
                        "sha256": semgrep_input["sha256"],
                        "ecosystems": semgrep_input["ecosystems"],
                        "min_packages": 0,
                    }
                ],
            },
            "osv-scanner": {
                "required": True,
                "not_applicable_reason": None,
                "evidence_file": evidence_names["osv-scanner"],
                "evidence_sha256": evidence_hashes["osv-scanner"],
                "version": records["osv-scanner"]["tool"]["version"],
                "distribution_sha256": records["osv-scanner"]["tool"]["distribution_sha256"],
                "normalizer_sha256": records["osv-scanner"]["tool"]["normalizer_sha256"],
                "config_sha256": records["osv-scanner"]["tool"]["config_sha256"],
                "rules_sha256": None,
                "database_manifest_sha256": records["osv-scanner"]["tool"]["database"]["manifest_sha256"],
                "scan_view_manifest_sha256": osv_view,
                "isolation_backend": "oci",
                "expected_inputs": [
                    {
                        "path": osv_input["path"],
                        "sha256": osv_input["sha256"],
                        "ecosystems": osv_input["ecosystems"],
                        "min_packages": 2,
                    }
                ],
            },
        },
    }
    (root / "host-expectation.json").write_bytes(_wire(context))
    return {"context": context, "records": records}


def main() -> int:
    parser = argparse.ArgumentParser(description="build an illustrative security-evidence pass fixture")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "pass",
        help="directory to populate (default: examples/pass)",
    )
    args = parser.parse_args()
    build_fixture(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
