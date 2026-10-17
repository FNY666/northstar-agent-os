#!/usr/bin/env python3
"""将固定版本 Semgrep JSON 严格归一化为 Northstar 扫描证据。

该模块只读取已冻结的 stdout/stderr bytes 和受信宿主提供的 template、
execution、isolation、input_bytes、severity_map。它不执行 Semgrep、候选代码、
网络请求或文件系统扫描。
"""
from __future__ import annotations

from typing import Any

from native_contract import EvidenceError, make_record, normalize_path, sha, strict_json_loads, validate_record, validated_inputs, wire

SEMGREP_VERSION = "1.181.0"
MAX_STDOUT_BYTES = 2 * 1024 * 1024
MAX_STDERR_BYTES = 1024 * 1024
MAX_FINDINGS = 2000
MAX_PATHS = 4000

# This is the deliberately narrow, canonical ``semgrep scan --json`` envelope
# used by the fixed local runner.  Noncanonical output is evidence failure, not
# an opportunity to guess at Semgrep extensions.
_OUTPUT_REQUIRED = frozenset({"version", "results", "errors", "paths", "skipped_rules"})
_OUTPUT_ALLOWED = _OUTPUT_REQUIRED | frozenset({"time", "engine_kind", "engine_requested", "profiling_results"})
_PATHS_REQUIRED = frozenset({"scanned"})
_PATHS_ALLOWED = _PATHS_REQUIRED | frozenset({"skipped"})
_RESULT_FIELDS = frozenset({"check_id", "path", "start", "end", "extra"})
_EXTRA_REQUIRED = frozenset({"message", "metadata", "severity", "fingerprint", "lines"})
_EXTRA_ALLOWED = _EXTRA_REQUIRED | frozenset(
    {
        "metavars",
        "fix",
        "fixed_lines",
        "is_ignored",
        "sca_info",
        "validation_state",
        "historical_info",
        "dataflow_trace",
        "engine_kind",
        "extra_extra",
    }
)
_RAW_SEVERITIES = frozenset(
    {"ERROR", "WARNING", "EXPERIMENT", "INVENTORY", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
)
_RECORD_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_DIRECTIONAL = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def _fail(message: str) -> None:
    raise EvidenceError("Semgrep normalizer: " + message)


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(label + " 必须是对象")
    return value


def _list(value: Any, label: str, maximum: int) -> list[Any]:
    if type(value) is not list or len(value) > maximum:
        _fail(label + " 必须是受限数组")
    return value


def _keys(value: dict[str, Any], *, required: frozenset[str], allowed: frozenset[str], label: str) -> None:
    missing = required - set(value)
    unknown = set(value) - allowed
    if missing or unknown:
        _fail(label + " 结构未知、不完整或含额外字段")


def _bounded_text(value: Any, label: str, maximum: int, *, safe_identifier: bool = False) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        _fail(label + " 必须是非空有界字符串")
    if safe_identifier and any(ord(char) < 32 or ord(char) == 127 or char in _DIRECTIONAL for char in value):
        _fail(label + " 含不安全控制字符")
    return value


def _position(value: Any, label: str) -> dict[str, int]:
    item = _mapping(value, label)
    _keys(item, required=frozenset({"line", "col"}), allowed=frozenset({"line", "col", "offset"}), label=label)
    line, column = item["line"], item["col"]
    if type(line) is not int or not 1 <= line <= 10_000_000:
        _fail(label + ".line 无效")
    # Semgrep positions are 1-based in normal CLI findings; accept zero only
    # for compatibility with a parser-produced range while retaining bounds.
    if type(column) is not int or not 0 <= column <= 10_000_000:
        _fail(label + ".col 无效")
    if "offset" in item and (type(item["offset"]) is not int or not -1 <= item["offset"] <= 2**63 - 1):
        _fail(label + ".offset 无效")
    return item  # type: ignore[return-value]


def _validate_optional_extra(extra: dict[str, Any]) -> None:
    """Validate optional documented fields without allowing them to affect risk."""
    if "metavars" in extra and type(extra["metavars"]) is not dict:
        _fail("result.extra.metavars 结构未知")
    if "fix" in extra and type(extra["fix"]) is not str:
        _fail("result.extra.fix 结构未知")
    if "fixed_lines" in extra:
        lines = _list(extra["fixed_lines"], "result.extra.fixed_lines", 100_000)
        if any(type(line) is not str for line in lines):
            _fail("result.extra.fixed_lines 结构未知")
    if "is_ignored" in extra:
        if type(extra["is_ignored"]) is not bool:
            _fail("result.extra.is_ignored 结构未知")
        if extra["is_ignored"]:
            _fail("结果被行内抑制，覆盖不完整")
    if "sca_info" in extra and type(extra["sca_info"]) is not dict:
        _fail("result.extra.sca_info 结构未知")
    if "validation_state" in extra and type(extra["validation_state"]) is not str:
        _fail("result.extra.validation_state 结构未知")
    if "historical_info" in extra and type(extra["historical_info"]) is not dict:
        _fail("result.extra.historical_info 结构未知")
    if "dataflow_trace" in extra and type(extra["dataflow_trace"]) is not dict:
        _fail("result.extra.dataflow_trace 结构未知")
    if "engine_kind" in extra:
        engine = extra["engine_kind"]
        if engine not in ("OSS", "PRO"):
            # The official schema also permits a bounded PRO_REQUIRED tuple.
            if not (
                type(engine) is list
                and len(engine) == 2
                and engine[0] == "PRO_REQUIRED"
                and type(engine[1]) is dict
            ):
                _fail("result.extra.engine_kind 结构未知")


def _trusted_severity_map(value: Any) -> dict[str, str]:
    mapping = _mapping(value, "severity_map")
    if len(mapping) > MAX_FINDINGS:
        _fail("severity_map 条目过多")
    result: dict[str, str] = {}
    for rule_id, severity in mapping.items():
        checked_id = _bounded_text(rule_id, "severity_map rule id", 256, safe_identifier=True)
        if type(severity) is not str or severity not in _RECORD_SEVERITIES:
            _fail("severity_map 含未知或不允许的严重度")
        result[checked_id] = severity
    return result


def _parse_paths(value: Any, expected_paths: set[str]) -> list[str]:
    paths = _mapping(value, "paths")
    _keys(paths, required=_PATHS_REQUIRED, allowed=_PATHS_ALLOWED, label="paths")
    scanned = _list(paths["scanned"], "paths.scanned", MAX_PATHS)
    if "skipped" in paths:
        skipped = _list(paths["skipped"], "paths.skipped", MAX_PATHS)
        if skipped:
            _fail("Semgrep 报告跳过输入")

    observed: list[str] = []
    for raw_path in scanned:
        if type(raw_path) is not str:
            _fail("paths.scanned 含非字符串路径")
        path = normalize_path(raw_path)
        if path in observed:
            _fail("paths.scanned 含重复路径")
        observed.append(path)
    if set(observed) != expected_paths:
        _fail("paths.scanned 与签名 expected_inputs 不完全一致")
    return observed


def _parse_finding(value: Any, severity_map: dict[str, str], seen_fingerprints: set[tuple],
                   seen_ids: set[str]) -> dict[str, Any]:
    match = _mapping(value, "result")
    _keys(match, required=_RESULT_FIELDS, allowed=_RESULT_FIELDS, label="result")
    rule_id = _bounded_text(match["check_id"], "result.check_id", 256, safe_identifier=True)
    path_raw = match["path"]
    if type(path_raw) is not str:
        _fail("result.path 必须是字符串")
    path = normalize_path(path_raw)
    start = _position(match["start"], "result.start")
    end = _position(match["end"], "result.end")
    extra = _mapping(match["extra"], "result.extra")
    _keys(extra, required=_EXTRA_REQUIRED, allowed=_EXTRA_ALLOWED, label="result.extra")
    message = _bounded_text(extra["message"], "result.extra.message", 2000)
    if type(extra["metadata"]) is not dict:
        _fail("result.extra.metadata 结构未知")
    raw_severity = extra["severity"]
    if type(raw_severity) is not str or raw_severity not in _RAW_SEVERITIES:
        _fail("result.extra.severity 未知")
    fingerprint = _bounded_text(extra["fingerprint"], "result.extra.fingerprint", 4096)
    if type(extra["lines"]) is not str:
        _fail("result.extra.lines 结构未知")
    _validate_optional_extra(extra)

    # ``extra.severity`` and user-authored metadata are deliberately not used
    # for the emitted risk.  Only the caller-provided, policy-pinned map may
    # assign a severity to the fixed check id.
    if rule_id not in severity_map:
        _fail("finding 未在受信 severity_map 中声明")
    # Native OSS prints the same "requires login" fingerprint for distinct
    # findings. Authenticated location, not that placeholder, identifies a hit.
    duplicate_key = (rule_id, path, start["line"], start["col"], end["line"], end["col"])
    if duplicate_key in seen_fingerprints:
        _fail("Semgrep finding rule/location 重复")
    seen_fingerprints.add(duplicate_key)

    identity = wire(
        {
            "check_id": rule_id,
            "end": {key: end[key] for key in sorted(end)},
            "fingerprint": fingerprint,
            "path": path,
            "start": {key: start[key] for key in sorted(start)},
        }
    )
    finding_id = sha(identity)
    if finding_id in seen_ids:
        _fail("Semgrep finding id 重复")
    seen_ids.add(finding_id)
    return {
        "id": finding_id,
        "kind": "rule",
        "rule_id": rule_id,
        "advisory_id": None,
        "severity": severity_map[rule_id],
        "location": {"path": path, "line": start["line"]},
        "package": None,
        "message": message,
    }


def _validate_execution(execution: Any, finding_count: int) -> None:
    item = _mapping(execution, "execution")
    if item.get("status") != "completed":
        _fail("execution 不是 completed")
    if item.get("timed_out") is not False or item.get("resource_exhausted") is not False or item.get("output_truncated") is not False:
        _fail("execution 指示超时、资源耗尽或截断")
    exit_code = item.get("exit_code")
    if type(exit_code) is not int or exit_code not in (0, 1):
        _fail("execution.exit_code 不是 Semgrep 成功扫描状态")
    required_code = 1 if finding_count else 0
    if exit_code != required_code:
        _fail("Semgrep 退出码与 findings 数量矛盾")


def normalize_semgrep(stdout: bytes, *, template: dict, execution: dict, isolation: dict,
                      input_bytes: dict[str, bytes], severity_map: dict[str, str], stderr: bytes = b"") -> dict:
    """Return a closed v1 scan record or raise ``EvidenceError`` fail-closed.

    The function binds input bytes to ``template.tools.semgrep.expected_inputs``
    before interpreting stdout.  Its artifact names are supplied exclusively by
    ``make_record`` and cannot be selected by scanner data.
    """
    if type(stdout) is not bytes or len(stdout) > MAX_STDOUT_BYTES:
        _fail("stdout 必须是预算内 bytes")
    if type(stderr) is not bytes or len(stderr) > MAX_STDERR_BYTES:
        _fail("stderr 必须是预算内 bytes")

    expected = validated_inputs(template, "semgrep", input_bytes)
    plan = template["tools"]["semgrep"]
    if plan["version"] != SEMGREP_VERSION:
        _fail("模板没有固定 Semgrep 1.181.0")
    trusted_severities = _trusted_severity_map(severity_map)

    raw = strict_json_loads(stdout)
    _keys(raw, required=_OUTPUT_REQUIRED, allowed=_OUTPUT_ALLOWED, label="Semgrep stdout")
    if raw["version"] != SEMGREP_VERSION:
        _fail("stdout raw version 与固定 Semgrep 1.181.0 不一致")
    results = _list(raw["results"], "results", MAX_FINDINGS)
    errors = _list(raw["errors"], "errors", 100_000)
    skipped_rules = _list(raw["skipped_rules"], "skipped_rules", 100_000)
    if errors:
        _fail("Semgrep stdout 含 errors")
    if skipped_rules:
        _fail("Semgrep stdout 含 skipped_rules")
    if "time" in raw and type(raw["time"]) is not dict:
        _fail("time 结构未知")
    if "engine_kind" in raw and raw["engine_kind"] not in ("OSS", "PRO"):
        _fail("engine_kind 结构未知")
    if "engine_requested" in raw and raw["engine_requested"] != "OSS":
        _fail("native profile 只允许 OSS engine_requested")
    if "profiling_results" in raw and (type(raw["profiling_results"]) is not list or raw["profiling_results"]):
        _fail("native profile 不允许额外 profiling_results")

    expected_by_path = {item["path"]: item for item in expected}
    observed_paths = _parse_paths(raw["paths"], set(expected_by_path))
    findings: list[dict[str, Any]] = []
    seen_fingerprints: set[tuple[str, str]] = set()
    seen_ids: set[str] = set()
    for value in results:
        finding = _parse_finding(value, trusted_severities, seen_fingerprints, seen_ids)
        if finding["location"]["path"] not in expected_by_path:
            _fail("finding 定位逃离 expected_inputs")
        findings.append(finding)

    _validate_execution(execution, len(findings))
    record = make_record("semgrep", template, execution, isolation, input_bytes, stdout, stderr)
    record["coverage"] = {
        "status": "complete",
        "observed_inputs": [
            {
                "path": path,
                "sha256": sha(input_bytes[path]),
                "ecosystems": [],
                "package_count": 0,
            }
            for path in observed_paths
        ],
        "skipped_inputs": [],
        "unresolved_inputs": [],
        "error_count": 0,
    }
    record["findings"] = findings
    validate_record(record)
    return record
