"""Deterministic SARIF 2.1.0 export for Northstar security findings."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import quote


_LEVELS = {
    "critical": ("error", "9.5"),
    "high": ("error", "8.0"),
    "medium": ("warning", "5.0"),
    "low": ("note", "2.0"),
    "none": ("note", "0.0"),
}


def build_sarif(summary: Mapping[str, Any], *, tool_version: str) -> dict[str, Any]:
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
    for tool, rule, item in normalized:
        rule_id = f"{tool}:{rule}"
        level, _security_severity = _LEVELS[str(item["severity"])]
        path = quote(str(item["path"]).replace("\\", "/"), safe="/-._~")
        region = {
            "startLine": max(1, int(item["line"])),
            "startColumn": max(1, int(item.get("column", 1))),
        }
        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_indices[rule_id],
            "level": level,
            "kind": "fail",
            "message": {"text": str(item["message"])},
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
        })

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

    return {
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
                "thresholdFindings": int(summary.get("threshold_findings", 0)),
                "limitations": list(summary.get("limitations", ())),
            },
        }],
    }


__all__ = ["build_sarif"]
