"""纯数据接口；模板必须由调用方验签，执行/隔离数据必须由实际宿主取得。"""
from __future__ import annotations

import copy
from typing import Any

from trusted_common import EvidenceError, _context_semantics, _validators, clock, sha, stamp, strict_json_loads, wire
from security_evidence import _repo_path

TOOLS = ("semgrep", "osv-scanner")


def normalize_path(value: Any) -> str:
    if type(value) is not str or len(value) > 1024 or "\\" in value:
        raise EvidenceError("native path is invalid")
    if value.startswith("/input/"):
        value = value[len("/input/"):]
    while value.startswith("./"):
        value = value[2:]
    if not _repo_path(value):
        raise EvidenceError("native path is outside the contracted input view")
    return value


def validate_template(template: dict) -> None:
    if type(template) is not dict or type(template.get("tools")) is not dict or set(template["tools"]) != set(TOOLS):
        raise EvidenceError("native host template must contain both contracted tools")
    context = copy.deepcopy(template)
    for name in TOOLS:
        tool = context["tools"][name]
        if type(tool) is not dict or "evidence_sha256" in tool:
            raise EvidenceError("native template must be pre-scan, without evidence hashes")
        tool["evidence_sha256"] = "0" * 64
    _, validator = _validators()
    if any(validator.iter_errors(context)) or _context_semantics(context):
        raise EvidenceError("native host template fails the expectation contract")


def validated_inputs(template: dict, tool: str, input_bytes: dict[str, bytes]) -> list[dict]:
    validate_template(template)
    if tool not in TOOLS or type(input_bytes) is not dict:
        raise EvidenceError("native input type is invalid")
    expected = template["tools"][tool]["expected_inputs"]
    if set(input_bytes) != {item["path"] for item in expected}:
        raise EvidenceError("native input view differs from the signed scope")
    for item in expected:
        name = normalize_path(item["path"])
        if name != item["path"] or type(input_bytes[name]) is not bytes or sha(input_bytes[name]) != item["sha256"]:
            raise EvidenceError("native input bytes differ from the signed plan")
    return copy.deepcopy(expected)


def make_record(tool: str, template: dict, execution: dict, isolation: dict, input_bytes: dict[str, bytes],
                stdout: bytes, stderr: bytes, database: dict | None = None) -> dict:
    expected = validated_inputs(template, tool, input_bytes)
    if type(stdout) is not bytes or type(stderr) is not bytes or len(stdout) > 2097152 or len(stderr) > 1048576:
        raise EvidenceError("native capture exceeds the strict parsing budget")
    plan = template["tools"][tool]
    if not plan["required"]:
        raise EvidenceError("native execution cannot invent an applicable scan")
    prefix = "semgrep" if tool == "semgrep" else "osv"
    result = {
        "schema": "northstar.security-scan.v1",
        "run_id": template["run_id"],
        "subject": {**copy.deepcopy(template["subject"]), "scan_view_manifest_sha256": plan["scan_view_manifest_sha256"]},
        "tool": {"name": tool, **{key: plan[key] for key in ("version", "distribution_sha256", "normalizer_sha256", "config_sha256", "rules_sha256")}, "database": copy.deepcopy(database)},
        "execution": copy.deepcopy(execution),
        "isolation": copy.deepcopy(isolation),
        "coverage": {"status": "incomplete", "observed_inputs": [], "skipped_inputs": [], "unresolved_inputs": [item["path"] for item in expected], "error_count": 0},
        "findings": [],
        "artifacts": {stream: {"name": prefix + (".stdout.json" if stream == "stdout" else ".stderr.txt"), "sha256": sha(raw), "bytes": len(raw)} for stream, raw in (("stdout", stdout), ("stderr", stderr))},
    }
    validate_record(result)
    return result


def validate_record(record: dict) -> None:
    validator, _ = _validators()
    if type(record) is not dict or any(validator.iter_errors(record)):
        raise EvidenceError("normalizer output fails the closed scan schema")
