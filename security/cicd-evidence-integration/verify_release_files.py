#!/usr/bin/env python3
"""只读核对已发布 wheel、发布绑定清单及 Semgrep/OSV 门禁结论。

本工具不会运行扫描器、normalizer、项目代码或发布动作，也不会修改任何输入。
所有 expected_* 参数必须由受信的上游封装/审计任务或独立签名验证提供；尤其
expected_binding_sha256 不能从待下载的 binding 文件重新计算后再传入。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

# 只能从本工具相邻的、受信部署的合同实现导入；绝不从 dist_dir、binding 或 gate
# 所在目录（或任何候选代码目录）导入模块。security_evidence 的 jsonschema 路径只在
# 调用其 _validators 时触发；本工具仅复用其标准库严格解析和 no-follow 读取原语。
_CONTRACT_DIRECTORY = Path(__file__).resolve().parent / "security-evidence-contract"
if str(_CONTRACT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(_CONTRACT_DIRECTORY))
from security_evidence import EvidenceError, _Directory, _read_path, strict_json_loads  # noqa: E402


MAX_BINDING_BYTES = 2 * 1024 * 1024
MAX_GATE_BYTES = 2 * 1024 * 1024
MAX_WHEEL_BYTES = 64 * 1024 * 1024
MAX_DECLARED_WHEEL_BYTES = 512 * 1024 * 1024
MAX_FILES = 64

_SHA256 = re.compile(r"[0-9A-Fa-f]{64}\Z")
_COMMIT = re.compile(r"(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})\Z")
_RUN_ID = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
# 单文件名、ASCII、有限长度；禁止 /、\\、控制字符和以 . 开头的歧义名称。
_WHEEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.whl\Z")


class _Outcome:
    """保留稳定、无重复的失败码；任一失败均为 fail-closed。"""

    def __init__(self) -> None:
        self.reason_codes: list[str] = []

    def fail(self, code: str) -> None:
        if code not in self.reason_codes:
            self.reason_codes.append(code)

    def finish(self) -> dict[str, Any]:
        eligible = not self.reason_codes
        return {
            "schema": "northstar.release-files-gate.v1",
            "eligible_for_publish": eligible,
            "exit_code": 0 if eligible else 2,
            "reason_codes": self.reason_codes,
            "limitations": [
                "本校验只核对受信上游提供的 pin、门禁结论与制品字节一致性；不重新运行扫描器或 normalizer。",
                "binding、gate 和摘要本身不证明其来源；expected_* 参数必须来自受信上游任务或独立签名验证。",
                "通过不证明源码到制品的真实性、构建可复现性或不存在未知安全问题。",
            ],
        }


def _safe_run_id(value: Any) -> bool:
    return type(value) is str and _RUN_ID.fullmatch(value) is not None


def _safe_sha256(value: Any) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _safe_commit(value: Any) -> bool:
    return type(value) is str and _COMMIT.fullmatch(value) is not None


def _safe_wheel_name(value: Any) -> bool:
    return type(value) is str and len(value) <= 128 and _WHEEL_NAME.fullmatch(value) is not None


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _same_digest(left: str, right: str) -> bool:
    """在两端都已严格验证为 hex64 后，不因 hex 大小写造成伪失败。"""
    return left.lower() == right.lower()


def _trusted_arguments_valid(
    expected_binding_sha256: Any,
    expected_source_commit: Any,
    expected_run_id: Any,
    expected_gate_sha256: Any,
) -> bool:
    return (
        _safe_sha256(expected_binding_sha256)
        and _safe_commit(expected_source_commit)
        and _safe_run_id(expected_run_id)
        and _safe_sha256(expected_gate_sha256)
    )


def _read_safely(path: str | Path, maximum: int, outcome: _Outcome, failure_code: str) -> bytes | None:
    """用合同实现的逐级 no-follow 读取，任何异常均作为不可发布处理。"""
    try:
        return _read_path(path, maximum)
    except (OSError, EvidenceError, TypeError, ValueError):
        outcome.fail(failure_code)
        return None
    except Exception:
        outcome.fail(failure_code)
        return None


def _parse_binding(value: Any) -> dict[str, Any] | None:
    """验证 northstar.release-binding.v1 的全部、封闭结构。"""
    if type(value) is not dict:
        return None
    required = {"schema", "run_id", "source_commit", "security_gate_sha256", "files"}
    if set(value) != required or value.get("schema") != "northstar.release-binding.v1":
        return None
    if not _safe_run_id(value["run_id"]) or not _safe_commit(value["source_commit"]):
        return None
    if not _safe_sha256(value["security_gate_sha256"]):
        return None

    files = value["files"]
    if type(files) is not list or not 1 <= len(files) <= MAX_FILES:
        return None
    names: set[str] = set()
    declared_total = 0
    for item in files:
        if type(item) is not dict or set(item) != {"name", "sha256", "bytes"}:
            return None
        name, digest, size = item["name"], item["sha256"], item["bytes"]
        # type(True) is bool rather than int: explicitly reject bool and float.
        if not _safe_wheel_name(name) or not _safe_sha256(digest) or type(size) is not int:
            return None
        if not 0 <= size <= MAX_WHEEL_BYTES or name in names:
            return None
        names.add(name)
        declared_total += size
        if declared_total > MAX_DECLARED_WHEEL_BYTES:
            return None
    return value


def _validate_gate(value: Any, binding: dict[str, Any] | None, expected_run_id: Any, outcome: _Outcome) -> None:
    """只验证已固定 gate JSON 的 pass 结论和运行绑定，不解释其来源。"""
    if type(value) is not dict:
        outcome.fail("GATE_CONTRACT_INVALID")
        return

    if value.get("schema") != "northstar.security-gate.v1":
        outcome.fail("GATE_SCHEMA_INVALID")
    if value.get("decision") != "pass":
        outcome.fail("GATE_DECISION_NOT_PASS")
    if type(value.get("exit_code")) is not int or value.get("exit_code") != 0:
        outcome.fail("GATE_EXIT_CODE_INVALID")
    if type(value.get("eligible_for_delivery")) is not bool or value.get("eligible_for_delivery") is not True:
        outcome.fail("GATE_DELIVERY_INELIGIBLE")
    if type(value.get("evidence_valid")) is not bool or value.get("evidence_valid") is not True:
        outcome.fail("GATE_EVIDENCE_INVALID")

    gate_run_id = value.get("run_id")
    if not _safe_run_id(gate_run_id):
        outcome.fail("GATE_RUN_ID_INVALID")
        return
    if _safe_run_id(expected_run_id) and gate_run_id != expected_run_id:
        outcome.fail("GATE_RUN_ID_MISMATCH")
    if binding is not None and gate_run_id != binding["run_id"]:
        outcome.fail("GATE_BINDING_RUN_ID_MISMATCH")


def _check_artifacts(dist_dir: str | Path, binding: dict[str, Any], outcome: _Outcome) -> None:
    """核对 dist 目录恰好包含声明的 wheel，并逐个以 no-follow FD 读取。"""
    expected = {item["name"]: item for item in binding["files"]}
    try:
        with _Directory(dist_dir) as directory:
            # 目录描述符已逐级 no-follow 打开。先后两次列目录可发现校验过程中的
            # 常见文件树变动；每个声明文件由 _Directory.read 继续执行 regular/nlink=1
            # 和实际字节上限检查。
            before = set(os.listdir(directory.fd))
            if before != set(expected):
                outcome.fail("ARTIFACT_SET_MISMATCH")

            for name, item in expected.items():
                try:
                    raw = directory.read(name, item["bytes"])
                except Exception:
                    outcome.fail("ARTIFACT_READ_ERROR")
                    continue
                if len(raw) != item["bytes"] or not _same_digest(_digest(raw), item["sha256"]):
                    outcome.fail("ARTIFACT_INTEGRITY_MISMATCH")

            after = set(os.listdir(directory.fd))
            if after != before:
                outcome.fail("ARTIFACT_TREE_CHANGED")
            if after != set(expected):
                outcome.fail("ARTIFACT_SET_MISMATCH")
    except Exception:
        outcome.fail("ARTIFACT_DIRECTORY_ERROR")


def verify_release_files(
    dist_dir: str | Path,
    binding_path: str | Path,
    gate_path: str | Path,
    *,
    expected_binding_sha256: str,
    expected_source_commit: str,
    expected_run_id: str,
    expected_gate_sha256: str,
) -> dict[str, Any]:
    """只读验证发布文件是否可交给发布步骤。

    expected_binding_sha256、expected_source_commit、expected_run_id 和
    expected_gate_sha256 均是调用方从受信上游获得的输入。函数不会把任何候选文件
    的内容升级为可信 pin，不会写入 dist、binding 或 gate，也不会执行扫描器、
    项目代码、normalizer 或发布操作。
    """
    outcome = _Outcome()
    try:
        trusted_valid = _trusted_arguments_valid(
            expected_binding_sha256,
            expected_source_commit,
            expected_run_id,
            expected_gate_sha256,
        )
        if not trusted_valid:
            outcome.fail("TRUSTED_ARGUMENT_INVALID")

        # 即使 binding 不可解析，仍尝试实际读取 gate；这样不会只检查 manifest 而
        # 忽略门禁本体。两个读取均使用受信合同模块的 actual-byte cap/no-follow 原语。
        binding_raw = _read_safely(binding_path, MAX_BINDING_BYTES, outcome, "BINDING_SAFE_READ_FAILED")
        gate_raw = _read_safely(gate_path, MAX_GATE_BYTES, outcome, "GATE_SAFE_READ_FAILED")

        binding: dict[str, Any] | None = None
        if binding_raw is not None:
            if trusted_valid and not _same_digest(_digest(binding_raw), expected_binding_sha256):
                outcome.fail("BINDING_PIN_MISMATCH")
            try:
                binding = _parse_binding(strict_json_loads(binding_raw))
            except Exception:
                binding = None
            if binding is None:
                outcome.fail("BINDING_CONTRACT_INVALID")
            else:
                if trusted_valid and binding["source_commit"] != expected_source_commit:
                    outcome.fail("SOURCE_COMMIT_MISMATCH")
                if trusted_valid and binding["run_id"] != expected_run_id:
                    outcome.fail("RUN_ID_MISMATCH")
                if trusted_valid and not _same_digest(binding["security_gate_sha256"], expected_gate_sha256):
                    outcome.fail("BINDING_GATE_SHA256_MISMATCH")

        if gate_raw is not None:
            actual_gate_sha256 = _digest(gate_raw)
            if trusted_valid and not _same_digest(actual_gate_sha256, expected_gate_sha256):
                outcome.fail("GATE_TRUSTED_SHA256_MISMATCH")
            if binding is not None and not _same_digest(actual_gate_sha256, binding["security_gate_sha256"]):
                outcome.fail("GATE_BINDING_SHA256_MISMATCH")
            try:
                gate = strict_json_loads(gate_raw)
            except Exception:
                outcome.fail("GATE_JSON_INVALID")
            else:
                _validate_gate(gate, binding, expected_run_id, outcome)

        if binding is not None:
            _check_artifacts(dist_dir, binding, outcome)
    except Exception:
        # 不向调用方泄露输入内容或异常细节；任何未预期异常均不可发布。
        outcome.fail("VALIDATION_ERROR")
    return outcome.finish()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="只读核对 Northstar 发布 binding、已固定安全门禁及 wheel 字节；所有 expected 参数须由受信上游提供。"
    )
    parser.add_argument("--dist-dir", required=True, help="只包含待发布 wheel 的目录")
    parser.add_argument("--binding", required=True, help="release-binding JSON 文件")
    parser.add_argument("--gate", required=True, help="已固定的 security gate JSON 文件")
    parser.add_argument("--expected-binding-sha256", required=True, help="受信上游记录的 binding 原始字节 SHA-256")
    parser.add_argument("--expected-source-commit", required=True, help="受信上游记录的 40 或 64 位源码提交")
    parser.add_argument("--expected-run-id", required=True, help="受信上游记录的运行 ID")
    parser.add_argument("--expected-gate-sha256", required=True, help="受信上游记录的 gate 原始字节 SHA-256")
    args = parser.parse_args(argv)
    answer = verify_release_files(
        args.dist_dir,
        args.binding,
        args.gate,
        expected_binding_sha256=args.expected_binding_sha256,
        expected_source_commit=args.expected_source_commit,
        expected_run_id=args.expected_run_id,
        expected_gate_sha256=args.expected_gate_sha256,
    )
    print(json.dumps(answer, ensure_ascii=True, separators=(",", ":"), allow_nan=False))
    return answer["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
