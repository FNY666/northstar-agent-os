"""将 OSV Scanner v2.7.0 machine JSON 严格规范化为 Northstar 扫描证据。

本模块不执行扫描器、不读取路径或环境，也不从 stdout 推导宿主执行或隔离
元数据。所有覆盖声明均由固定的 expectation_template 与 OSV 的逐锁文件包
清单共同约束；任何无法完整解释的 machine JSON 都以 EvidenceError 失败关闭。
"""
from __future__ import annotations

import re
from typing import Any

from freeze_inputs import validate_requirements
from native_contract import (
    EvidenceError,
    make_record,
    normalize_path,
    sha,
    strict_json_loads,
    validate_record,
    validated_inputs,
    wire,
)


_MAX_CAPTURE_BYTES = 2 * 1024 * 1024
_MAX_STDERR_BYTES = 1024 * 1024
_MAX_TEXT = 256
_OSV_SCANNER_VERSION = "2.7.0"
_PEP503_NORMALIZED_NAME = re.compile(r"[-_.]+")

# These names deliberately mirror pkg/models/results.go at osv-scanner v2.7.0.
_TOP_LEVEL_KEYS = frozenset(
    {
        "results",
        "experimental_config",
        "experimental_generic_findings",
        "image_metadata",
        "license_summary",
    }
)
_PACKAGE_SOURCE_KEYS = frozenset({"source", "experimental_pes", "packages"})
_SOURCE_KEYS = frozenset({"path", "type"})
_PACKAGE_VULNS_KEYS = frozenset(
    {"package", "dependency_groups", "vulnerabilities", "groups", "licenses", "license_violations"}
)
_PACKAGE_INFO_KEYS = frozenset(
    {"name", "os_package_name", "version", "ecosystem", "purl", "commit", "deprecated", "image_origin_details"}
)
_GROUP_KEYS = frozenset({"ids", "aliases", "experimental_analysis", "max_severity"})

# OSV database_specific values are textual labels, not a numeric CVSS parser.
_TEXT_SEVERITIES = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "unknown",
}


def _error(message: str) -> None:
    raise EvidenceError("OSV machine JSON is not contract-safe: " + message)


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        _error(label + " must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if type(value) is not list:
        _error(label + " must be an array")
    return value


def _bounded_text(value: Any, label: str, maximum: int = _MAX_TEXT) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        _error(label + " must be a non-empty bounded string")
    # The scan schema permits Unicode, but controls cannot safely identify a package,
    # advisory, or ecosystem in a generated evidence record.
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        _error(label + " contains a control character")
    return value


def _only_keys(value: dict[str, Any], allowed: frozenset[str], label: str) -> None:
    unexpected = set(value).difference(allowed)
    if unexpected:
        _error(label + " has unsupported fields: " + ", ".join(sorted(unexpected)))


def _validate_string_array(value: Any, label: str, *, allow_none: bool = False) -> list[str]:
    if value is None and allow_none:
        return []
    items = _array(value, label)
    return [_bounded_text(item, label + " item") for item in items]


def _validate_experimental_config(value: Any) -> None:
    """Accept the non-optional v2.7.0 field only in the contracted no-license mode."""
    config = _mapping(value, "experimental_config")
    if set(config) != {"licenses"}:
        _error("experimental_config does not match v2.7.0 output")
    licenses = _mapping(config["licenses"], "experimental_config.licenses")
    if set(licenses) != {"summary", "allowlist"} or type(licenses["summary"]) is not bool:
        _error("experimental_config.licenses is malformed")
    _validate_string_array(licenses["allowlist"], "experimental_config.licenses.allowlist", allow_none=True)
    if licenses["summary"] or licenses["allowlist"] not in (None, []):
        _error("license analysis is outside the contracted advisory result format")


def _validate_database(template: dict[str, Any], expected: list[dict[str, Any]], database: Any) -> None:
    """Bind database metadata before parsing stdout, rather than deferring to the gate."""
    database_value = _mapping(database, "database")
    plan = template["tools"]["osv-scanner"]
    if database_value.get("manifest_sha256") != plan["database_manifest_sha256"]:
        _error("database manifest does not match the signed OSV plan")
    ecosystems = database_value.get("ecosystems")
    if type(ecosystems) is not list or any(type(item) is not str for item in ecosystems):
        _error("database ecosystems are malformed")
    expected_ecosystems = {ecosystem for item in expected for ecosystem in item["ecosystems"]}
    if not expected_ecosystems.issubset(set(ecosystems)):
        _error("database does not cover every planned ecosystem")


def _validate_execution(execution: Any) -> None:
    """Only a clean completed OSV run can make a complete coverage assertion."""
    value = _mapping(execution, "execution")
    # make_record validates the complete schema. These are the semantic conditions
    # needed to reconcile OSV's documented result exit codes with raw findings.
    if value.get("status") != "completed":
        _error("execution was not completed")
    if value.get("exit_code") not in (0, 1):
        _error("completed OSV execution must have exit code 0 or 1")
    if value.get("timed_out") is not False or value.get("resource_exhausted") is not False:
        _error("timed out or resource-exhausted execution cannot be normalized as complete")
    if value.get("output_truncated") is not False:
        _error("truncated stdout cannot support complete coverage")


def _normalize_pypi_name(name: str) -> str:
    """Return the PEP 503 comparison form of a validated requirement name."""
    return _PEP503_NORMALIZED_NAME.sub("-", name).lower()


def _validate_requirements_package_binding(
    *, path: str, raw: bytes, allowed_ecosystems: set[str], packages: list[dict[str, str]]
) -> None:
    """Bind the restricted requirements.txt grammar to OSV package identities.

    This is deliberately limited to the first-version ``requirements.txt`` PyPI
    profile.  Other lockfile formats retain generic machine-JSON validation, whose
    package count and ecosystem checks do not independently prove package identity.
    """
    if path.rsplit("/", 1)[-1] != "requirements.txt":
        return
    if allowed_ecosystems != {"PyPI"}:
        _error("requirements.txt identity binding requires the PyPI-only profile")

    declared = validate_requirements(raw)
    expected_identities = {
        (_normalize_pypi_name(item["name"]), item["version"], "PyPI") for item in declared
    }
    observed_identities = {
        (_normalize_pypi_name(item["name"]), item["version"], item["ecosystem"]) for item in packages
    }
    # Set comparison alone would hide a repeated OSV package or a duplicate alias.
    if (
        len(packages) != len(declared)
        or len(observed_identities) != len(packages)
        or observed_identities != expected_identities
    ):
        _error("OSV packages do not exactly match requirements.txt pinned package identities")


def _severity_from_vulnerability(vulnerability: dict[str, Any]) -> str:
    """Use only an official textual database severity; CVSS vectors remain unknown.

    OSV's protobuf JSON serializes ``database_specific`` as ``databaseSpecific``.
    The underscore spelling is accepted as a compatibility input only when it is the
    sole spelling, which keeps a conflicting crafted raw result from being accepted.
    """
    camel_present = "databaseSpecific" in vulnerability
    snake_present = "database_specific" in vulnerability
    if camel_present and snake_present:
        _error("vulnerability has conflicting database severity spellings")
    database_specific = vulnerability.get("databaseSpecific" if camel_present else "database_specific")
    if database_specific is not None:
        database_specific = _mapping(database_specific, "vulnerability database_specific")
        value = database_specific.get("severity")
        if value is not None:
            text = _bounded_text(value, "database_specific.severity", 64).strip().lower()
            return _TEXT_SEVERITIES.get(text, "unknown")

    # Validate the modeled CVSS field when present, but never infer an unsafe
    # low/medium/etc. rating from a vector in this normalizer.
    if "severity" in vulnerability:
        for index, item in enumerate(_array(vulnerability["severity"], "vulnerability.severity")):
            severity = _mapping(item, "vulnerability.severity[" + str(index) + "]")
            if type(severity.get("type")) is not str or type(severity.get("score")) is not str:
                _error("vulnerability.severity entry is malformed")
    return "unknown"


def _validate_groups(groups_value: Any, advisory_ids: list[str]) -> None:
    """Require OSV's alias groups to account for every raw advisory exactly once."""
    if not advisory_ids:
        if groups_value is not None and _array(groups_value, "groups"):
            _error("a package without vulnerabilities has non-empty advisory groups")
        return
    if groups_value is None:
        _error("a package with vulnerabilities is missing OSV advisory groups")
    seen: set[str] = set()
    for number, item in enumerate(_array(groups_value, "groups")):
        group = _mapping(item, "groups[" + str(number) + "]")
        _only_keys(group, _GROUP_KEYS, "groups[" + str(number) + "]")
        ids = _validate_string_array(group.get("ids"), "groups[" + str(number) + "].ids")
        if not ids:
            _error("an advisory group has no ids")
        if len(ids) != len(set(ids)):
            _error("an advisory group repeats an id")
        aliases = group.get("aliases")
        if aliases is not None:
            _validate_string_array(aliases, "groups[" + str(number) + "].aliases")
        analysis = group.get("experimental_analysis")
        if analysis not in (None, {}):
            _error("call-analysis output is outside the contracted no-call-analysis mode")
        if "max_severity" in group and type(group["max_severity"]) is not str:
            _error("groups max_severity is malformed")
        for advisory_id in ids:
            if advisory_id not in advisory_ids:
                _error("an advisory group refers to a vulnerability not present on its package")
            if advisory_id in seen:
                _error("OSV advisory appears in more than one group")
            seen.add(advisory_id)
    if seen != set(advisory_ids) or len(advisory_ids) != len(set(advisory_ids)):
        _error("OSV groups do not account for each raw vulnerability exactly once")


def _parse_package(
    value: Any, *, path: str, allowed_ecosystems: set[str]
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    package_result = _mapping(value, "package result")
    _only_keys(package_result, _PACKAGE_VULNS_KEYS, "package result")
    package_info = _mapping(package_result.get("package"), "package")
    _only_keys(package_info, _PACKAGE_INFO_KEYS, "package")
    package = {
        "name": _bounded_text(package_info.get("name"), "package.name"),
        "version": _bounded_text(package_info.get("version"), "package.version"),
        "ecosystem": _bounded_text(package_info.get("ecosystem"), "package.ecosystem"),
    }
    if package["ecosystem"] not in allowed_ecosystems:
        _error("package ecosystem is outside this lockfile's planned ecosystems")
    for optional_key in ("os_package_name", "purl", "commit"):
        if optional_key in package_info and type(package_info[optional_key]) is not str:
            _error("package." + optional_key + " is malformed")
    if package_info.get("deprecated") is True:
        _error("deprecated-package output cannot be represented as an advisory finding")
    if "deprecated" in package_info and type(package_info["deprecated"]) is not bool:
        _error("package.deprecated is malformed")
    if package_info.get("image_origin_details") is not None:
        _error("image package output is outside the lockfile contract")
    if "dependency_groups" in package_result:
        _validate_string_array(package_result["dependency_groups"], "dependency_groups")
    for field in ("licenses", "license_violations"):
        if field in package_result and _validate_string_array(package_result[field], field):
            _error(field + " cannot be represented as an advisory finding")

    vulnerabilities_value = package_result.get("vulnerabilities", [])
    vulnerabilities = _array(vulnerabilities_value, "vulnerabilities")
    advisory_ids: list[str] = []
    findings: list[dict[str, Any]] = []
    for number, raw in enumerate(vulnerabilities):
        vulnerability = _mapping(raw, "vulnerabilities[" + str(number) + "]")
        advisory_id = _bounded_text(vulnerability.get("id"), "vulnerability.id")
        severity = _severity_from_vulnerability(vulnerability)
        advisory_ids.append(advisory_id)
        descriptor = {"path": path, "advisory_id": advisory_id, "package": package}
        findings.append(
            {
                "id": "osv-" + sha(wire(descriptor)),
                "kind": "advisory",
                "rule_id": None,
                "advisory_id": advisory_id,
                "severity": severity,
                "location": {"path": path, "line": None},
                "package": dict(package),
                "message": "OSV advisory " + advisory_id + " affects " + package["name"] + "@" + package["version"] + " (" + package["ecosystem"] + ")",
            }
        )
    _validate_groups(package_result.get("groups"), advisory_ids)
    return package, findings


def _parse_results(
    raw: dict[str, Any], expected: list[dict[str, Any]], input_bytes: dict[str, bytes]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    _only_keys(raw, _TOP_LEVEL_KEYS, "top-level OSV output")
    if "results" not in raw or "experimental_config" not in raw:
        _error("v2.7.0 output is missing results or experimental_config")
    _validate_experimental_config(raw["experimental_config"])
    if raw.get("experimental_generic_findings") not in (None, []):
        _error("generic findings cannot be represented as advisory findings")
    if raw.get("image_metadata") is not None:
        _error("image metadata is outside the lockfile contract")
    if raw.get("license_summary") not in (None, []):
        _error("license summary is outside the advisory contract")

    expected_by_path = {item["path"]: item for item in expected}
    sources: dict[str, tuple[int, list[dict[str, Any]]]] = {}
    for source_number, item in enumerate(_array(raw["results"], "results")):
        result = _mapping(item, "results[" + str(source_number) + "]")
        _only_keys(result, _PACKAGE_SOURCE_KEYS, "results[" + str(source_number) + "]")
        source = _mapping(result.get("source"), "results[" + str(source_number) + "].source")
        _only_keys(source, _SOURCE_KEYS, "source")
        path = normalize_path(source.get("path"))
        if source.get("type") != "lockfile":
            _error("result source is not a lockfile")
        if path not in expected_by_path:
            _error("OSV reported a source outside the signed input scope")
        if path in sources:
            _error("OSV reported an input source more than once")
        if result.get("experimental_pes") not in (None, []):
            _error("exploitability analysis output is outside the contracted no-call-analysis mode")
        package_records = _array(result.get("packages"), "source packages")
        package_keys: set[tuple[str, str, str]] = set()
        parsed_packages: list[dict[str, str]] = []
        findings: list[dict[str, Any]] = []
        allowed_ecosystems = set(expected_by_path[path]["ecosystems"])
        for package_record in package_records:
            package, package_findings = _parse_package(
                package_record, path=path, allowed_ecosystems=allowed_ecosystems
            )
            key = (package["ecosystem"], package["name"], package["version"])
            if key in package_keys:
                _error("OSV repeated a package identity in one lockfile")
            package_keys.add(key)
            parsed_packages.append(package)
            findings.extend(package_findings)
        observed_ecosystems = {key[0] for key in package_keys}
        if observed_ecosystems != allowed_ecosystems:
            _error("lockfile package ecosystems do not exactly match the signed plan")
        if len(package_records) < expected_by_path[path]["min_packages"]:
            _error("OSV identified fewer packages than required for a lockfile")
        _validate_requirements_package_binding(
            path=path,
            raw=input_bytes[path],
            allowed_ecosystems=allowed_ecosystems,
            packages=parsed_packages,
        )
        sources[path] = (len(package_records), findings)

    if set(sources) != set(expected_by_path):
        _error("one or more signed lockfiles were not represented in OSV results")

    observed = [
        {
            "path": item["path"],
            "sha256": item["sha256"],
            "ecosystems": list(item["ecosystems"]),
            "package_count": sources[item["path"]][0],
        }
        for item in expected
    ]
    all_findings = [finding for item in expected for finding in sources[item["path"]][1]]
    all_findings.sort(
        key=lambda finding: (
            finding["location"]["path"],
            finding["package"]["ecosystem"],
            finding["package"]["name"],
            finding["package"]["version"],
            finding["advisory_id"],
        )
    )
    if len({finding["id"] for finding in all_findings}) != len(all_findings):
        _error("distinct raw vulnerabilities normalized to the same finding id")
    return observed, all_findings


def normalize_osv(
    stdout: bytes,
    *,
    template: dict,
    execution: dict,
    isolation: dict,
    input_bytes: dict[str, bytes],
    database: dict,
    stderr: bytes = b"",
) -> dict:
    """Return a complete OSV evidence record or fail closed with ``EvidenceError``.

    ``execution`` and ``isolation`` are copied verbatim by ``make_record``.  This
    function neither synthesizes those host facts nor accepts a partial/errored run.
    It intentionally supports only OSV Scanner v2.7.0's lockfile machine-JSON form.
    """
    if type(stdout) is not bytes or type(stderr) is not bytes:
        raise EvidenceError("OSV stdout and stderr must be bytes")
    if len(stdout) > _MAX_CAPTURE_BYTES or len(stderr) > _MAX_STDERR_BYTES:
        raise EvidenceError("OSV capture exceeds the native parsing budget")

    # Validate the signed plan and frozen bytes before inspecting untrusted stdout.
    expected = validated_inputs(template, "osv-scanner", input_bytes)
    if template["tools"]["osv-scanner"]["version"] != _OSV_SCANNER_VERSION:
        _error("signed OSV plan must require osv-scanner v2.7.0")
    _validate_database(template, expected, database)
    record = make_record("osv-scanner", template, execution, isolation, input_bytes, stdout, stderr, database)
    _validate_execution(execution)
    raw = strict_json_loads(stdout)
    observed, findings = _parse_results(raw, expected, input_bytes)

    exit_code = execution["exit_code"]
    if exit_code == 0 and findings:
        _error("exit code 0 contradicts raw OSV advisory findings")
    if exit_code == 1 and not findings:
        _error("exit code 1 contradicts an advisory-free raw result")

    record["coverage"] = {
        "status": "complete",
        "observed_inputs": observed,
        "skipped_inputs": [],
        "unresolved_inputs": [],
        "error_count": 0,
    }
    record["findings"] = findings
    validate_record(record)
    return record
