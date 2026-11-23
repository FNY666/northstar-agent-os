from __future__ import annotations

import copy

import pytest

from native_contract import EvidenceError, sha, wire
from osv_normalizer import normalize_osv


HASH = "a" * 64
INPUT = {"poetry.lock": b"[[package]]\nname = 'demo'\nversion = '1.0.0'\n"}


def _template() -> dict:
    osv_input_hash = sha(INPUT["poetry.lock"])
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
        "run_id": "osv-normalizer-unit",
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
                    {"path": "poetry.lock", "sha256": osv_input_hash, "ecosystems": ["PyPI"], "min_packages": 2}
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


def _output(*, vulnerable: bool = True, packages: int = 2) -> dict:
    entries = []
    for number in range(packages):
        package = {
            "package": {"name": "pkg" + str(number), "version": "1.0." + str(number), "ecosystem": "PyPI"},
            "vulnerabilities": [],
        }
        if vulnerable and number == 0:
            package["vulnerabilities"] = [
                {
                    "id": "GHSA-unit-test",
                    "summary": "fixture advisory",
                    "databaseSpecific": {"severity": "HIGH"},
                }
            ]
            package["groups"] = [{"ids": ["GHSA-unit-test"], "aliases": [], "max_severity": "HIGH"}]
        entries.append(package)
    return {
        "results": [
            {"source": {"path": "/input/poetry.lock", "type": "lockfile"}, "packages": entries}
        ],
        "experimental_config": {"licenses": {"summary": False, "allowlist": None}},
    }


def _normalize(raw: dict, *, exit_code: int = 1, template: dict | None = None, database: dict | None = None) -> dict:
    return normalize_osv(
        wire(raw),
        template=_template() if template is None else template,
        execution=_execution(exit_code),
        isolation=_isolation(),
        input_bytes=INPUT,
        database=_database() if database is None else database,
    )


def test_normalizes_all_packages_and_database_specific_severity_without_changing_host_metadata() -> None:
    execution = _execution(1)
    isolation = _isolation()
    record = normalize_osv(
        wire(_output()),
        template=_template(),
        execution=execution,
        isolation=isolation,
        input_bytes=INPUT,
        database=_database(),
    )

    assert record["coverage"] == {
        "status": "complete",
        "observed_inputs": [
            {"path": "poetry.lock", "sha256": sha(INPUT["poetry.lock"]), "ecosystems": ["PyPI"], "package_count": 2}
        ],
        "skipped_inputs": [],
        "unresolved_inputs": [],
        "error_count": 0,
    }
    assert record["execution"] == execution
    assert record["isolation"] == isolation
    assert len(record["findings"]) == 1
    finding = record["findings"][0]
    assert finding["severity"] == "high"
    assert finding["advisory_id"] == "GHSA-unit-test"
    assert finding["location"] == {"path": "poetry.lock", "line": None}
    assert finding["package"] == {"name": "pkg0", "version": "1.0.0", "ecosystem": "PyPI"}


def test_normalizes_complete_advisory_free_package_inventory_with_exit_zero() -> None:
    record = _normalize(_output(vulnerable=False), exit_code=0)

    assert record["coverage"]["status"] == "complete"
    assert record["coverage"]["observed_inputs"][0]["package_count"] == 2
    assert record["findings"] == []


def test_cvss_vector_without_official_text_rating_remains_unknown_not_low() -> None:
    raw = _output()
    vulnerability = raw["results"][0]["packages"][0]["vulnerabilities"][0]
    vulnerability.pop("databaseSpecific")
    vulnerability["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]

    record = _normalize(raw)
    assert record["findings"][0]["severity"] == "unknown"


def test_official_snake_case_database_specific_is_supported_for_compatibility() -> None:
    raw = _output()
    vulnerability = raw["results"][0]["packages"][0]["vulnerabilities"][0]
    vulnerability["database_specific"] = vulnerability.pop("databaseSpecific")

    assert _normalize(raw)["findings"][0]["severity"] == "high"


@pytest.mark.parametrize(
    ("name", "raw", "exit_code"),
    [
        ("missing_non_vulnerable_package", _output(packages=1), 1),
        ("exit_zero_with_finding", _output(), 0),
        ("exit_one_without_finding", _output(vulnerable=False), 1),
        ("raw_error_field", {**_output(), "errors": ["fixture failure"]}, 1),
        ("missing_advisory_group", _output(), 1),
        ("extra_source", _output(), 1),
        ("conflicting_severity_spellings", _output(), 1),
    ],
)
def test_rejects_fixture_bypass_or_raw_record_contradiction(name: str, raw: dict, exit_code: int) -> None:
    raw = copy.deepcopy(raw)
    if name == "missing_advisory_group":
        raw["results"][0]["packages"][0].pop("groups")
    elif name == "extra_source":
        raw["results"].append(
            {"source": {"path": "/input/unplanned.lock", "type": "lockfile"}, "packages": []}
        )
    elif name == "conflicting_severity_spellings":
        vulnerability = raw["results"][0]["packages"][0]["vulnerabilities"][0]
        vulnerability["database_specific"] = {"severity": "LOW"}

    with pytest.raises(EvidenceError):
        _normalize(raw, exit_code=exit_code)


def test_rejects_mismatched_database_coverage_and_unclean_execution() -> None:
    database = _database()
    database["ecosystems"] = []
    with pytest.raises(EvidenceError):
        _normalize(_output(), database=database)

    execution = _execution(1)
    execution["output_truncated"] = True
    with pytest.raises(EvidenceError):
        normalize_osv(
            wire(_output()),
            template=_template(),
            execution=execution,
            isolation=_isolation(),
            input_bytes=INPUT,
            database=_database(),
        )


def test_rejects_a_signed_osv_version_other_than_v2_7_0() -> None:
    template = _template()
    template["tools"]["osv-scanner"]["version"] = "2.7.1"

    with pytest.raises(EvidenceError):
        _normalize(_output(), template=template)


def test_rejects_scope_ecosystem_laundering_and_duplicate_package_count_inflation() -> None:
    raw = _output()
    raw["results"][0]["packages"][1]["package"]["ecosystem"] = "npm"
    with pytest.raises(EvidenceError):
        _normalize(raw)

    raw = _output()
    raw["results"][0]["packages"].append(copy.deepcopy(raw["results"][0]["packages"][1]))
    with pytest.raises(EvidenceError):
        _normalize(raw)
