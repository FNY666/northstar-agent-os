"""Deterministic SARIF 2.1.0 export for Northstar security findings."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from hashlib import sha256
from typing import Any
from urllib.parse import quote


_LEVELS = {
    "critical": ("error", "9.5"),
    "high": ("error", "8.0"),
    "medium": ("warning", "5.0"),
    "low": ("note", "2.0"),
    "none": ("note", "0.0"),
}


def _baseline_counts(report: Mapping[str, Any]) -> dict[tuple[str, str, str, str], int]:
    if not isinstance(report, Mapping):
        raise ValueError("baseline SARIF document must be an object")
    if report.get("version") != "2.1.0":
        raise ValueError("baseline SARIF version must be 2.1.0")
    runs = report.get("runs")
    if not isinstance(runs, Sequence) or isinstance(runs, (str, bytes)) or len(runs) != 1:
        raise ValueError("baseline must contain exactly one SARIF run")
    run = runs[0]
    if not isinstance(run, Mapping):
        raise ValueError("baseline SARIF run must be an object")
    tool = run.get("tool")
    if not isinstance(tool, Mapping):
        raise ValueError("baseline SARIF tool must be an object")
    driver = tool.get("driver")
    if not isinstance(driver, Mapping) or driver.get("name") != "Northstar SecurityScan":
        raise ValueError("baseline must come from Northstar SecurityScan")
    results = run.get("results", ())
    if not isinstance(results, Sequence) or isinstance(results, (str, bytes)):
        raise ValueError("baseline SARIF results must be an array")

    counts: dict[tuple[str, str, str, str], int] = {}
    for result in results:
        if not isinstance(result, Mapping):
            raise ValueError("baseline SARIF result must be an object")
        rule_id = result.get("ruleId")
        message_value = result.get("message")
        message = message_value.get("text") if isinstance(message_value, Mapping) else None
        properties = result.get("properties", {})
        severity = properties.get("severity") if isinstance(properties, Mapping) else None
        locations = result.get("locations")
        if not isinstance(locations, Sequence) or isinstance(locations, (str, bytes)) or not locations:
            raise ValueError("baseline SARIF result must include a location")
        location = locations[0]
        if not isinstance(location, Mapping):
            raise ValueError("baseline SARIF location must be an object")
        physical = location.get("physicalLocation")
        if not isinstance(physical, Mapping):
            raise ValueError("baseline SARIF physical location must be an object")
        artifact = physical.get("artifactLocation")
        if not isinstance(artifact, Mapping):
            raise ValueError("baseline SARIF artifact location must be an object")
        uri = artifact.get("uri")
        if not all(isinstance(value, str) and value for value in (rule_id, uri, message, severity)):
            raise ValueError("baseline SARIF result is missing rule, path, message, or severity")
        if severity not in _LEVELS:
            raise ValueError("baseline SARIF result has an unsupported severity")
        identity = (rule_id, uri, message, severity)
        counts[identity] = counts.get(identity, 0) + 1
    return counts


def validate_baseline_sarif(report: Any) -> int:
    """Validate a Northstar SARIF baseline and return its finding count."""
    return sum(_baseline_counts(report).values())


def is_complete_baseline_sarif(report: Any) -> bool:
    """Return whether a validated baseline represents a complete workspace scan."""
    _baseline_counts(report)
    run = report["runs"][0]
    properties = run.get("properties")
    if not isinstance(properties, Mapping):
        return False
    results = run.get("results")
    findings_count = properties.get("findingsCount")
    return (
        properties.get("fileLimitReached") is False
        and properties.get("findingsTruncated") is False
        and type(properties.get("filesSkipped")) is int
        and properties["filesSkipped"] == 0
        and type(findings_count) is int
        and isinstance(results, Sequence)
        and not isinstance(results, (str, bytes))
        and findings_count == len(results)
    )


def count_new_findings_by_severity(
    findings: Sequence[Mapping[str, Any]],
    baseline_sarif: Mapping[str, Any],
) -> dict[str, int]:
    """Count all new scan findings by severity, including detail-truncated findings."""
    baseline_remaining = _baseline_counts(baseline_sarif)
    new_counts: dict[str, int] = {}
    for item in findings:
        if not isinstance(item, Mapping):
            raise TypeError("each grouped finding must be a mapping")
        tool = item.get("tool")
        rule = item.get("rule")
        severity = item.get("severity")
        message = item.get("message")
        path = item.get("path")
        count = item.get("count", 1)
        if not all(isinstance(value, str) and value for value in (tool, rule, severity, message, path)):
            raise ValueError("grouped finding is missing rule, path, message, or severity")
        if severity not in _LEVELS:
            raise ValueError("grouped finding has an unsupported severity")
        if type(count) is not int or count < 1:
            raise ValueError("grouped finding count must be a positive integer")
        uri = quote(path.replace("\\", "/"), safe="/-._~")
        identity = (f"{tool}:{rule}", uri, message, severity)
        remaining = baseline_remaining.get(identity, 0)
        matched = min(count, remaining)
        if matched:
            baseline_remaining[identity] = remaining - matched
        new_counts[severity] = new_counts.get(severity, 0) + count - matched
    return new_counts


def build_sarif(
    summary: Mapping[str, Any],
    *,
    tool_version: str,
    baseline_sarif: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert a bounded scan summary to a SARIF 2.1.0 document.

    Finding text comes from the scanner's sanitized messages and remediation
    guidance; source snippets and secret values are never added to the report.
    """
    findings = summary.get("findings", ())
    if not isinstance(findings, Sequence) or isinstance(findings, (str, bytes)):
        raise TypeError("summary.findings must be a sequence")

    rules: dict[tuple[str, str], dict[str, Any]] = {}
    normalized: list[tuple[str, str, dict[str, Any]]] = []
    for item in findings:
        if not isinstance(item, Mapping):
            raise TypeError("each finding must be a mapping")
        tool = str(item["tool"])
        rule = str(item["rule"])
        rule_id = f"{tool}:{rule}"
        severity = str(item["severity"])
        if severity not in _LEVELS:
            raise ValueError(f"unsupported finding severity: {severity}")
        key = (tool, rule)
        if key not in rules:
            rules[key] = {
                "id": rule_id,
                "name": rule,
                "shortDescription": {"text": str(item["message"])},
                "help": {"text": str(item["remediation"])},
                "properties": {
                    "tags": ["security"],
                    "security-severity": _LEVELS[severity][1],
                    "northstarTool": tool,
                    "northstarSeverity": severity,
                },
            }
        normalized.append((tool, rule, dict(item)))

    ordered_rules = sorted(rules.values(), key=lambda item: item["id"])
    rule_indices = {item["id"]: index for index, item in enumerate(ordered_rules)}
    results: list[dict[str, Any]] = []
    baseline_counts = _baseline_counts(baseline_sarif) if baseline_sarif is not None else None
    baseline_remaining = dict(baseline_counts) if baseline_counts is not None else None
    baseline_result_count = sum(baseline_counts.values()) if baseline_counts is not None else 0
    baseline_finding_count = baseline_result_count
    if baseline_sarif is not None:
        baseline_run = baseline_sarif["runs"][0]
        baseline_properties = baseline_run.get("properties")
        reported_count = baseline_properties.get("findingsCount") if isinstance(baseline_properties, Mapping) else None
        if type(reported_count) is int and reported_count >= 0:
            baseline_finding_count = reported_count
    baseline_new_count = 0
    baseline_unchanged_count = 0
    occurrence_counts: dict[tuple[str, str, str, str], int] = {}
    for tool, rule, item in normalized:
        rule_id = f"{tool}:{rule}"
        level, _security_severity = _LEVELS[str(item["severity"])]
        path = quote(str(item["path"]).replace("\\", "/"), safe="/-._~")
        region = {
            "startLine": max(1, int(item["line"])),
            "startColumn": max(1, int(item.get("column", 1))),
        }
        message = str(item["message"])
        severity = str(item["severity"])
        identity = (rule_id, path, message, severity)
        occurrence = occurrence_counts.get(identity, 0)
        occurrence_counts[identity] = occurrence + 1
        fingerprint_source = "\0".join((*identity, str(occurrence))).encode("utf-8")
        result = {
            "ruleId": rule_id,
            "ruleIndex": rule_indices[rule_id],
            "level": level,
            "kind": "fail",
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": path,
                        "uriBaseId": "NORTHSTAR_SRCROOT",
                    },
                    "region": region,
                },
            }],
            "properties": {
                "tool": tool,
                "rule": rule,
                "severity": str(item["severity"]),
                "remediation": str(item["remediation"]),
            },
            "partialFingerprints": {
                "northstar/v1": sha256(fingerprint_source).hexdigest(),
            },
        }
        if baseline_remaining is not None:
            remaining = baseline_remaining.get(identity, 0)
            if remaining:
                result["baselineState"] = "unchanged"
                baseline_remaining[identity] = remaining - 1
                baseline_unchanged_count += 1
            else:
                result["baselineState"] = "new"
                baseline_new_count += 1
        results.append(result)

    notifications: list[dict[str, Any]] = []
    if summary.get("file_limit_reached"):
        notifications.append({
            "level": "warning",
            "message": {"text": "The file scan limit was reached; results cover only part of the workspace."},
        })
    if summary.get("findings_truncated"):
        notifications.append({
            "level": "warning",
            "message": {"text": "Finding details were truncated; see run properties for the full finding count."},
        })
    if int(summary.get("files_skipped", 0)):
        notifications.append({
            "level": "note",
            "message": {"text": f"{int(summary['files_skipped'])} file(s) were skipped because they were unreadable, oversized, or outside the accepted text format."},
        })

    invocation: dict[str, Any] = {"executionSuccessful": True}
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

    report = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Northstar SecurityScan",
                    "version": tool_version,
                    "rules": ordered_rules,
                },
            },
            "automationDetails": {"id": "northstar/security-scan"},
            "originalUriBaseIds": {"NORTHSTAR_SRCROOT": {"uri": "./"}},
            "invocations": [invocation],
            "results": results,
            "properties": {
                "filesScanned": int(summary.get("files_scanned", 0)),
                "filesSkipped": int(summary.get("files_skipped", 0)),
                "findingsCount": int(summary.get("findings_count", len(findings))),
                "findingsTruncated": bool(summary.get("findings_truncated", False)),
                "fileLimitReached": bool(summary.get("file_limit_reached", False)),
                "failOn": str(summary.get("fail_on", "none")),
                "thresholdScope": "new" if summary.get("new_findings_only") else "all",
                "thresholdFindings": int(summary.get("threshold_findings", 0)),
                "limitations": list(summary.get("limitations", ())),
            },
        }],
    }
    if baseline_remaining is not None:
        report["runs"][0]["properties"]["baselineComparison"] = {
            "baselineFindingCount": baseline_finding_count,
            "baselineResultCount": baseline_result_count,
            "newFindingCount": baseline_new_count,
            "unchangedFindingCount": baseline_unchanged_count,
            "comparedFindingCount": len(results),
            "comparisonComplete": bool(
                not summary.get("file_limit_reached")
                and not summary.get("files_skipped")
                and not summary.get("findings_truncated")
                and baseline_sarif is not None
                and is_complete_baseline_sarif(baseline_sarif)
            ),
        }
    return report


__all__ = [
    "build_sarif",
    "count_new_findings_by_severity",
    "is_complete_baseline_sarif",
    "validate_baseline_sarif",
]
