#!/usr/bin/env python3
"""只读校验 Semgrep/OSV 规范证据；不执行扫描器、代码或网络请求。"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_STDOUT_BYTES = 16 * 1024 * 1024
MAX_STDERR_BYTES = 1024 * 1024
TOOLS = ("semgrep", "osv-scanner")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
DIRECTIONAL = set("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


class EvidenceError(ValueError):
    """数据无法安全读取、解析或校验。"""


def strict_json_loads(raw: bytes, *, max_depth: int = 64, max_nodes: int = 100_000) -> dict[str, Any]:
    """有界、拒绝重复键和非有限数的 JSON 解析；不解释任何外部引用。"""
    if not isinstance(raw, bytes):
        raise EvidenceError("JSON 输入必须是 bytes")
    if type(max_depth) is not int or max_depth < 0 or type(max_nodes) is not int or max_nodes < 1:
        raise EvidenceError("JSON 解析预算无效")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in values:
            if key in obj:
                raise EvidenceError("JSON 含重复键")
            obj[key] = value
        return obj

    def constant(_: str) -> Any:
        raise EvidenceError("JSON 含非有限数字")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise EvidenceError(f"无法解析 JSON：{type(error).__name__}") from error
    if not isinstance(value, dict):
        raise EvidenceError("JSON 顶层必须是对象")
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > max_depth or nodes > max_nodes:
            raise EvidenceError("JSON 超过深度或节点预算")
        if isinstance(item, float) and not math.isfinite(item):
            raise EvidenceError("JSON 数字溢出或非有限")
        children = list(item.values()) if isinstance(item, dict) else item if isinstance(item, list) else ()
        if len(children) > max_nodes - nodes:
            raise EvidenceError("JSON 超过节点预算")
        stack.extend((child, depth + 1) for child in children)
    return value


def _repo_path(value: str) -> bool:
    if not value or len(value) > 1024 or value.startswith("/") or "\\" in value or ":" in value:
        return False
    if any(ord(char) < 32 or ord(char) == 127 or char in DIRECTIONAL for char in value):
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def _time(value: str) -> datetime:
    if not isinstance(value, str) or not TIME.fullmatch(value):
        raise EvidenceError("时间必须是有界 UTC RFC3339")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise EvidenceError("时间不是有效日期") from error


class _Directory:
    """逐级以目录 FD 打开，父目录与末级文件都不能是符号链接。"""
    def __init__(self, path: str | Path) -> None:
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise EvidenceError("平台缺少安全 no-follow 读取能力")
        absolute = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(absolute.anchor, flags)
        try:
            for part in absolute.parts[1:]:
                next_fd = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = next_fd
        except BaseException:
            os.close(fd)
            raise
        self.fd = fd

    def __enter__(self) -> _Directory:
        return self

    def __exit__(self, *_: Any) -> None:
        os.close(self.fd)

    def read(self, name: str, maximum: int) -> bytes:
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise EvidenceError("证据引用必须是安全单文件名")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=self.fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise EvidenceError("证据必须是没有硬链接的普通文件")
            if before.st_size > maximum:
                raise EvidenceError("证据文件超过字节预算")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, min(65_536, maximum + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise EvidenceError("读取期间文件超过字节预算")
                chunks.append(chunk)
            after = os.fstat(fd)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
            if identity(before) != identity(after) or total != after.st_size:
                raise EvidenceError("证据文件读取期间发生变化")
            return b"".join(chunks)
        finally:
            os.close(fd)


def _read_path(path: str | Path, maximum: int = MAX_JSON_BYTES) -> bytes:
    target = Path(os.path.expanduser(os.fspath(path)))
    with _Directory(target.parent) as parent:
        return parent.read(target.name, maximum)


def _validators() -> tuple[Any, Any]:
    try:
        from jsonschema import Draft202012Validator, validators
        from referencing import Registry
        from referencing.exceptions import NoSuchResource
    except ImportError as error:
        raise EvidenceError("缺少固定版本依赖；请安装 requirements.txt") from error

    def integer(_: Any, instance: Any) -> bool:
        return type(instance) is int

    strict = validators.extend(Draft202012Validator, type_checker=Draft202012Validator.TYPE_CHECKER.redefine("integer", integer))

    def refuse(uri: str) -> Any:
        raise NoSuchResource(ref=uri)

    built = []
    for filename in ("security-scan.v1.schema.json", "security-expectation.v1.schema.json"):
        schema = strict_json_loads(_read_path(Path(__file__).parent / "schemas" / filename))
        todo: list[Any] = [schema]
        while todo:
            item = todo.pop()
            if isinstance(item, dict):
                for key in ("$ref", "$dynamicRef"):
                    if key in item and (not isinstance(item[key], str) or not item[key].startswith("#")):
                        raise EvidenceError("本包 Schema 禁止外部引用")
                todo.extend(item.values())
            elif isinstance(item, list):
                todo.extend(item)
        strict.check_schema(schema)
        built.append(strict(schema, registry=Registry(retrieve=refuse)))
    return built[0], built[1]


def _shape_errors(validator: Any, value: Any) -> list[str]:
    errors = []
    for error in validator.iter_errors(value):
        location = "/".join(str(part) for part in error.absolute_path)
        errors.append(f"{location[:180] or '$'}：违反 {error.validator}")
        if len(errors) >= 40:
            errors.append("结构错误达到报告上限")
            break
    return errors


class _Result:
    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []
        self.reason_codes: list[str] = []
        self.invalid = False
        self.incomplete = False
        self.blocking = 0
        self.unknown_review = 0
        self.findings = 0
        self.context: dict[str, Any] | None = None
        self.context_sha256: str | None = None
        self.checked_at: str | None = None

    def add(self, name: str, passed: bool, reasons: list[str], *, invalid: bool = False) -> None:
        self.checks.append({"id": name, "passed": bool(passed), "reasons": reasons})
        if not passed:
            if name not in self.reason_codes:
                self.reason_codes.append(name)
            if invalid:
                self.invalid = True
            else:
                self.incomplete = True

    def finish(self) -> dict[str, Any]:
        decision = "invalid" if self.invalid else "review" if self.incomplete else "block" if self.blocking else "review" if self.unknown_review else "pass"
        return {
            "schema": "northstar.security-gate.v1",
            "run_id": self.context["run_id"] if self.context else None,
            "subject": dict(self.context["subject"]) if self.context else None,
            "policy": {key: self.context["policy"][key] for key in ("id", "sha256")} if self.context else None,
            "host_expectation_sha256": self.context_sha256,
            "checked_at": self.checked_at,
            "evidence_valid": not self.invalid,
            "eligible_for_delivery": decision == "pass",
            "decision": decision,
            "exit_code": 0 if decision == "pass" else 1 if decision == "block" else 2,
            "finding_count": self.findings,
            "blocking_finding_count": self.blocking,
            "unknown_review_count": self.unknown_review,
            "reason_codes": self.reason_codes,
            "checks": self.checks,
            "limitations": [
                "宿主期望、程序及Schema的真实性由调用者的可信部署保证；hash不是身份认证。",
                "JSON和隔离元数据不能独立证明实际内核隔离，需受信执行器及其独立验证。",
                "校验器不重新执行原生结果归一化，正确性仍依赖已固定的受信normalizer。",
                "通过只覆盖声明的扫描范围；不证明不存在未知漏洞，也不代替既有Northstar交付证据门。",
            ],
        }


def _context_semantics(context: dict[str, Any]) -> list[str]:
    errors = []
    names = []
    for name in TOOLS:
        plan = context["tools"][name]
        names.append(plan["evidence_file"])
        inputs = plan["expected_inputs"]
        if plan["required"]:
            if not inputs or plan["not_applicable_reason"] is not None or plan["isolation_backend"] == "none":
                errors.append(f"{name} 的必需扫描计划不完整")
        elif inputs or not plan["not_applicable_reason"]:
            errors.append(f"{name} 不适用必须由宿主给出理由且输入为空")
        paths = [item["path"] for item in inputs]
        if len(paths) != len(set(paths)) or any(not _repo_path(path) for path in paths):
            errors.append(f"{name} 的宿主输入路径无效或重复")
        if name == "semgrep":
            if plan["rules_sha256"] is None or plan["database_manifest_sha256"] is not None:
                errors.append("Semgrep 必须绑定规则，且不应绑定 OSV 数据库")
            if any(item["ecosystems"] or item["min_packages"] != 0 for item in inputs):
                errors.append("Semgrep 输入不能声明依赖包")
        else:
            if plan["rules_sha256"] is not None or (plan["required"] and plan["database_manifest_sha256"] is None):
                errors.append("OSV 必需扫描必须绑定数据库且不绑定 Semgrep 规则")
            if any(not item["ecosystems"] or item["min_packages"] < 1 for item in inputs):
                errors.append("OSV 必扫锁文件应声明生态和最小包数量")
    if len(set(names)) != len(names):
        errors.append("两工具不能引用同一证据文件")
    return errors


def _check_record(result: _Result, record: dict[str, Any], context: dict[str, Any], name: str,
                  root: _Directory, reserved: set[str], used_artifacts: set[str], now: datetime) -> None:
    plan, policy = context["tools"][name], context["policy"]
    prefix = name + "."
    binding = []
    if record["run_id"] != context["run_id"]:
        binding.append("run_id 不匹配")
    for key in ("start_commit", "patch_sha256", "candidate_manifest_sha256"):
        if record["subject"][key] != context["subject"][key]:
            binding.append(f"subject.{key} 不匹配")
    if record["subject"]["scan_view_manifest_sha256"] != plan["scan_view_manifest_sha256"]:
        binding.append("扫描视图清单不匹配")
    tool = record["tool"]
    if tool["name"] != name:
        binding.append("工具名称与宿主计划不匹配")
    for key in ("version", "distribution_sha256", "normalizer_sha256", "config_sha256", "rules_sha256"):
        if tool[key] != plan[key]:
            binding.append(f"tool.{key} 不匹配")
    database = tool["database"]
    if (database["manifest_sha256"] if database else None) != plan["database_manifest_sha256"]:
        binding.append("数据库清单不匹配")
    if name == "semgrep" and database is not None:
        binding.append("Semgrep 不应声明 OSV 数据库")
    result.add(prefix + "BINDINGS", not binding, binding, invalid=True)

    execution, coverage = record["execution"], record["coverage"]
    if not plan["required"]:
        valid = (execution["status"] == "not_applicable" and execution["started_at"] is None
                 and execution["finished_at"] is None and execution["duration_ms"] == 0
                 and execution["exit_code"] is None and not execution["timed_out"]
                 and not execution["resource_exhausted"] and not execution["output_truncated"]
                 and coverage["status"] == "not_applicable" and not coverage["observed_inputs"]
                 and not coverage["skipped_inputs"] and not coverage["unresolved_inputs"]
                 and coverage["error_count"] == 0 and not record["findings"]
                 and record["artifacts"]["stdout"] is None and record["artifacts"]["stderr"] is None)
        result.add(prefix + "HOST_NOT_APPLICABLE", valid,
                   [] if valid else ["不适用证据不能绕过宿主范围或伪装已经执行"], invalid=True)
        return
    if execution["status"] == "not_applicable" or coverage["status"] == "not_applicable":
        result.add(prefix + "UNAUTHORIZED_NOT_APPLICABLE", False, ["宿主声明必扫，不能自行豁免"], invalid=True)

    expected = {item["path"]: item for item in plan["expected_inputs"]}
    observed: dict[str, Any] = {}
    scope_errors = []
    for item in coverage["observed_inputs"]:
        path = item["path"]
        if not _repo_path(path) or path in observed or path not in expected:
            scope_errors.append("观测路径不安全、重复或不属于宿主输入")
        else:
            observed[path] = item
            if item["sha256"] != expected[path]["sha256"] or set(item["ecosystems"]) != set(expected[path]["ecosystems"]):
                scope_errors.append("观测文件字节或生态与宿主输入不一致")
            if name == "semgrep" and (item["ecosystems"] or item["package_count"] != 0):
                scope_errors.append("Semgrep 观测不能伪装成依赖扫描")
    for path in coverage["unresolved_inputs"] + [item["path"] for item in coverage["skipped_inputs"]]:
        if not _repo_path(path) or path not in expected:
            scope_errors.append("跳过或未解析路径不属于宿主输入")
    if len(set(coverage["unresolved_inputs"])) != len(coverage["unresolved_inputs"]):
        scope_errors.append("未解析输入重复")
    skipped_paths = [item["path"] for item in coverage["skipped_inputs"]]
    if len(set(skipped_paths)) != len(skipped_paths):
        scope_errors.append("跳过输入重复")
    result.add(prefix + "INPUT_SCOPE", not scope_errors, scope_errors, invalid=True)

    missing = set(expected) - set(observed)
    package_missing = any(item["package_count"] < expected[path]["min_packages"] for path, item in observed.items())
    coverage_ok = (not missing and not package_missing and not coverage["skipped_inputs"]
                   and not coverage["unresolved_inputs"] and coverage["error_count"] == 0 and not scope_errors)
    result.add(prefix + "COVERAGE", coverage["status"] == "complete" and coverage_ok,
               [] if coverage["status"] == "complete" and coverage_ok else ["必扫范围缺失、跳过、未解析、错误或依赖识别不足"])
    result.add(prefix + "COVERAGE_CLAIM", coverage["status"] != "complete" or coverage_ok,
               [] if coverage["status"] != "complete" or coverage_ok else ["complete 声明与覆盖事实矛盾"], invalid=True)

    findings_errors = []
    ids: set[str] = set()
    for finding in record["findings"]:
        path = finding["location"]["path"]
        if finding["id"] in ids or not _repo_path(path) or path not in observed or path not in expected:
            findings_errors.append("finding id 重复或定位不在已观测必扫输入中")
        ids.add(finding["id"])
        package = finding["package"]
        if name == "semgrep":
            if finding["kind"] != "rule" or not finding["rule_id"] or finding["advisory_id"] is not None or package is not None:
                findings_errors.append("Semgrep finding 类型不符合规则合同")
        elif (finding["kind"] != "advisory" or not finding["advisory_id"] or finding["rule_id"] is not None
              or package is None or package["ecosystem"] not in observed.get(path, {}).get("ecosystems", [])):
            findings_errors.append("OSV finding 类型或包生态不符合合同")
        severity = finding["severity"]
        result.findings += 1
        if severity in policy["blocking_severities"] or (severity == "unknown" and policy["unknown_severity"] == "block"):
            result.blocking += 1
        elif severity == "unknown":
            result.unknown_review += 1
    result.add(prefix + "FINDING_SCOPE", not findings_errors, findings_errors, invalid=True)

    semantic_errors = []
    started = finished = None
    try:
        if execution["started_at"] is not None:
            started = _time(execution["started_at"])
        if execution["finished_at"] is not None:
            finished = _time(execution["finished_at"])
    except EvidenceError:
        semantic_errors.append("执行时间无效")
    if started and finished and finished < started:
        semantic_errors.append("执行时间倒序")
    if execution["status"] == "completed" and (started is None or finished is None or execution["exit_code"] not in (0, 1)):
        semantic_errors.append("completed 应有有效起止时间和扫描器退出码 0/1")
    if execution["status"] == "completed" and execution["exit_code"] == 1 and not record["findings"]:
        semantic_errors.append("退出码 1 却没有保留任何发现")
    if execution["status"] == "timed_out" and not execution["timed_out"]:
        semantic_errors.append("timed_out 状态与标志矛盾")
    if execution["status"] == "resource_exhausted" and not execution["resource_exhausted"]:
        semantic_errors.append("resource_exhausted 状态与标志矛盾")
    result.add(prefix + "EXECUTION_CONTRACT", not semantic_errors, semantic_errors, invalid=True)
    duration_ok = (execution["duration_ms"] <= policy["max_duration_ms"]
                   and (not started or not finished or (finished - started).total_seconds() * 1000 <= policy["max_duration_ms"]))
    execution_ok = (execution["status"] == "completed" and execution["exit_code"] in (0, 1)
                    and not execution["timed_out"] and not execution["resource_exhausted"]
                    and not execution["output_truncated"] and duration_ok and not semantic_errors)
    result.add(prefix + "EXECUTION_COMPLETE", execution_ok, [] if execution_ok else ["扫描未完成、超限、输出截断或执行合同不满足"])
    skew = timedelta(seconds=policy["max_clock_skew_seconds"])
    time_ok = (finished is not None and started is not None and finished <= now + skew and started <= now + skew
               and now - finished <= timedelta(seconds=policy["max_scan_age_seconds"]))
    result.add(prefix + "SCAN_FRESHNESS", time_ok, [] if time_ok else ["扫描时间缺失、来自未来或已过期"])

    if name == "osv-scanner":
        db_errors = []
        if not database:
            db_errors.append("必需 OSV 数据库缺失")
        else:
            try:
                updated = _time(database["updated_at"])
                if updated > now + skew or now - updated > timedelta(seconds=policy["max_database_age_seconds"]):
                    db_errors.append("数据库来自未来或已过期")
            except EvidenceError:
                db_errors.append("数据库时间无效")
            needed = set().union(*(set(item["ecosystems"]) for item in plan["expected_inputs"]))
            if not needed.issubset(set(database["ecosystems"])):
                db_errors.append("数据库未覆盖全部必扫生态")
        result.add(prefix + "DATABASE_FRESHNESS_COVERAGE", not db_errors, db_errors)

    isolation = record["isolation"]
    isolation_ok = (isolation["backend"] == plan["isolation_backend"] and isolation["backend"] in {"oci", "bwrap", "vm"}
                    and isolation["read_only_inputs"] and isolation["network"] == "denied" and isolation["credentials"] == "none"
                    and not isolation["project_code_executed"] and isolation["non_root"])
    result.add(prefix + "ISOLATION_METADATA", isolation_ok, [] if isolation_ok else ["隔离元数据不满足宿主只读、禁网、无凭据和非特权要求"])

    artifact_errors = []
    for stream, limit in (("stdout", MAX_STDOUT_BYTES), ("stderr", MAX_STDERR_BYTES)):
        artifact = record["artifacts"][stream]
        if artifact is None:
            if execution["status"] == "completed":
                artifact_errors.append(f"completed 缺少 {stream} 捕获")
            continue
        filename = artifact["name"]
        if filename in reserved or filename in used_artifacts:
            artifact_errors.append("产物与证据/context/其它产物文件冲突")
            continue
        used_artifacts.add(filename)
        try:
            raw = root.read(filename, limit)
            if len(raw) != artifact["bytes"] or hashlib.sha256(raw).hexdigest() != artifact["sha256"]:
                artifact_errors.append(f"{stream} 原始产物字节数或摘要不匹配")
            if stream == "stdout" and execution["status"] == "completed":
                strict_json_loads(raw)
        except (OSError, EvidenceError) as error:
            artifact_errors.append(f"{stream} 缺失、不安全或不可解析：{type(error).__name__}")
    result.add(prefix + "ARTIFACT_INTEGRITY", not artifact_errors, artifact_errors, invalid=True)


def evaluate_bundle(evidence_dir: str | Path, expectation_path: str | Path, *, now: datetime | None = None) -> dict[str, Any]:
    """需要独立受信的宿主期望；返回门禁结果，不写入任何输入或文件。"""
    result = _Result()
    try:
        scan_validator, expectation_validator = _validators()
        context_raw = _read_path(expectation_path)
        context = strict_json_loads(context_raw)
        errors = _shape_errors(expectation_validator, context)
        result.add("HOST_EXPECTATION_SCHEMA", not errors, errors, invalid=True)
        if errors:
            return result.finish()
        errors = _context_semantics(context)
        result.add("HOST_EXPECTATION_CONTRACT", not errors, errors, invalid=True)
        if errors:
            return result.finish()
        clock = now if now is not None else datetime.now(timezone.utc)
        if not isinstance(clock, datetime) or clock.tzinfo is None or clock.utcoffset() is None:
            raise EvidenceError("宿主时钟必须是有时区 datetime")
        clock = clock.astimezone(timezone.utc)
        result.context = context
        result.context_sha256 = hashlib.sha256(context_raw).hexdigest()
        result.checked_at = clock.isoformat(timespec="microseconds").replace("+00:00", "Z")
        result.add("HOST_CLOCK", True, [])
        reserved = {context["tools"][name]["evidence_file"] for name in TOOLS}
        reserved.add(Path(expectation_path).name)
        used_artifacts: set[str] = set()
        with _Directory(evidence_dir) as root:
            for name in TOOLS:
                plan = context["tools"][name]
                try:
                    raw = root.read(plan["evidence_file"], MAX_JSON_BYTES)
                    match = hashlib.sha256(raw).hexdigest() == plan["evidence_sha256"]
                    result.add(name + ".HOST_EVIDENCE_PIN", match, [] if match else ["最终证据字节与宿主独立 pin 不一致"], invalid=True)
                    record = strict_json_loads(raw)
                    errors = _shape_errors(scan_validator, record)
                    result.add(name + ".SCHEMA", not errors, errors, invalid=True)
                    if not errors:
                        _check_record(result, record, context, name, root, reserved, used_artifacts, clock)
                except (OSError, EvidenceError) as error:
                    result.add(name + ".SAFE_READ_PARSE", False, [f"无法安全读取证据：{type(error).__name__}"], invalid=True)
        if result.blocking:
            result.reason_codes.append("POLICY_BLOCKING_FINDINGS")
        if result.unknown_review:
            result.reason_codes.append("POLICY_UNKNOWN_SEVERITY_REVIEW")
    except Exception as error:
        result.add("VALIDATION_ERROR", False, [f"校验无法完成：{type(error).__name__}"], invalid=True)
    return result.finish()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="只读校验 Semgrep/OSV 统一证据；必须提供可信宿主期望。")
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--expectation", required=True)
    args = parser.parse_args(argv)
    answer = evaluate_bundle(args.evidence_dir, args.expectation)
    print(json.dumps(answer, ensure_ascii=True, indent=2, allow_nan=False))
    return answer["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
