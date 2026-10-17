from __future__ import annotations

import copy

import pytest

from native_contract import EvidenceError, sha, wire
from osv_normalizer import normalize_osv


HASH = "a" * 64
REQUIREMENTS = b"Demo_Pkg==1.2.3\nrequests==2.32.3\n"
INPUT = {"requirements.txt": REQUIREMENTS}


def _template(*, min_packages: int = 2) -> dict:
    common = {
        "required": True,
        "not_applicable_reason": None,
        "evidence_file": "evidence.json",
        "version": "2.7.0",
        "distribution_sha256": HASH,
        "normalizer_sha256": "b" * 64,
        "config_sha256": "c" * 64,
        "scan_view_manifest_sha256": "d" * 64,
        "isolation_backend": "bwrap",
    }
    return {
        "schema": "northstar.security-expectation.v1",
        "run_id": "osv-package-binding-unit",
        "subject": {
            "start_commit": "e" * 40,
            "patch_sha256": "f" * 64,
            "candidate_manifest_sha256": "1" * 64,
        },
        "policy": {
            "id": "test-policy",
            "sha256": "2" * 64,
            "blocking_severities": ["critical", "high"],
            "unknown_severity": "block",
            "max_scan_age_seconds": 3600,
            "max_database_age_seconds": 3600,
            "max_clock_skew_seconds": 60,
            "max_duration_ms": 60000,
        },
        "tools": {
            "semgrep": {
                **common,
                "evidence_file": "semgrep-evidence.json",
                "rules_sha256": "3" * 64,
                "database_manifest_sha256": None,
                "expected_inputs": [
                    {"path": "app.py", "sha256": sha(b"pass\n"), "ecosystems": [], "min_packages": 0}
                ],
            },
            "osv-scanner": {
                **common,
                "evidence_file": "osv-evidence.json",
                "rules_sha256": None,
                "database_manifest_sha256": "4" * 64,
                "expected_inputs": [
                    {
                        "path": "requirements.txt",
                        "sha256": sha(REQUIREMENTS),
                        "ecosystems": ["PyPI"],
                        "min_packages": min_packages,
                    }
                ],
            },
        },
    }


def _execution(exit_code: int) -> dict:
    return {
        "status": "completed",
        "started_at": "2026-01-02T03:04:05Z",
        "finished_at": "2026-01-02T03:04:06Z",
        "duration_ms": 1000,
        "exit_code": exit_code,
        "timed_out": False,
        "resource_exhausted": False,
        "output_truncated": False,
    }


def _isolation() -> dict:
    return {
        "backend": "bwrap",
        "read_only_inputs": True,
        "network": "denied",
        "credentials": "none",
        "project_code_executed": False,
        "non_root": True,
    }


def _database() -> dict:
    return {"manifest_sha256": "4" * 64, "updated_at": "2026-01-02T03:00:00Z", "ecosystems": ["PyPI"]}


def _package(name: str, version: str, *, vulnerable: bool = False) -> dict:
    result = {"package": {"name": name, "version": version, "ecosystem": "PyPI"}, "vulnerabilities": []}
    if vulnerable:
        result["vulnerabilities"] = [
            {"id": "GHSA-package-binding", "databaseSpecific": {"severity": "HIGH"}}
        ]
        result["groups"] = [{"ids": ["GHSA-package-binding"], "aliases": [], "max_severity": "HIGH"}]
    return result


def _output(*, vulnerable: bool = False) -> dict:
    return {
        "results": [
            {
                "source": {"path": "/input/requirements.txt", "type": "lockfile"},
                # Demo.Pkg and the declared Demo_Pkg share the PEP 503 form demo-pkg.
                "packages": [_package("Demo.Pkg", "1.2.3", vulnerable=vulnerable), _package("requests", "2.32.3")],
            }
        ],
        "experimental_config": {"licenses": {"summary": False, "allowlist": None}},
    }


def _normalize(raw: dict, *, exit_code: int, template: dict | None = None) -> dict:
    return normalize_osv(
        wire(raw),
        template=_template() if template is None else template,
        execution=_execution(exit_code),
        isolation=_isolation(),
        input_bytes=INPUT,
        database=_database(),
    )


def test_requirements_pypi_binding_accepts_pep503_name_alias_for_clean_and_vulnerable_scans() -> None:
    clean = _normalize(_output(), exit_code=0)
    dangerous = _normalize(_output(vulnerable=True), exit_code=1)

    assert clean["coverage"]["observed_inputs"][0]["package_count"] == 2
    assert clean["findings"] == []
    assert dangerous["findings"][0]["package"] == {
        "name": "Demo.Pkg",
        "version": "1.2.3",
        "ecosystem": "PyPI",
    }


@pytest.mark.parametrize(
    "bypass",
    ["missing", "same_count_substitution", "version_drift", "extra_package", "normalized_name_repeat"],
)
def test_requirements_pypi_binding_rejects_identity_bypasses_even_with_low_minimum_package_count(bypass: str) -> None:
    # The good paired inventory still succeeds when min_packages is lower than its size.
    template = _template(min_packages=1)
    assert _normalize(_output(), exit_code=0, template=template)["findings"] == []

    raw = copy.deepcopy(_output())
    packages = raw["results"][0]["packages"]
    if bypass == "missing":
        packages.pop()
    elif bypass == "same_count_substitution":
        packages[1] = _package("substituted-package", "2.32.3")
    elif bypass == "version_drift":
        packages[0]["package"]["version"] = "1.2.4"
    elif bypass == "extra_package":
        packages.append(_package("unexpected-package", "9.9.9"))
    elif bypass == "normalized_name_repeat":
        # This evades the existing literal package-key duplicate check, but not PEP 503 binding.
        packages[1] = _package("demo-pkg", "1.2.3")
    else:
        raise AssertionError("unhandled test case")

    with pytest.raises(EvidenceError):
        _normalize(raw, exit_code=0, template=template)
