#!/usr/bin/env python3
"""CI 安全门禁包装器：只读评估，并对照受信上游提供的独立身份 pin。"""
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any

# 此路径来自可信发布包；绝不能替换为 PR 输入、下载产物或候选工作树路径。
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "security-evidence-contract"))
from security_evidence import evaluate_bundle

HEX64 = re.compile(r"[a-f0-9]{64}\Z")
COMMIT = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})\Z")
RUN_ID = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")


def bind_gate(result: dict[str, Any], expected: dict[str, str]) -> dict[str, Any]:
    """只供可信 evaluate_bundle 的即时返回值使用；本函数不认证外部 gate JSON。"""
    answer = copy.deepcopy(result)
    errors = []
    formats = {
        "host_expectation_sha256": HEX64,
        "run_id": RUN_ID,
        "start_commit": COMMIT,
        "patch_sha256": HEX64,
        "candidate_manifest_sha256": HEX64,
        "policy_sha256": HEX64,
    }
    observed = {
        "host_expectation_sha256": result.get("host_expectation_sha256"),
        "run_id": result.get("run_id"),
        "start_commit": (result.get("subject") or {}).get("start_commit"),
        "patch_sha256": (result.get("subject") or {}).get("patch_sha256"),
        "candidate_manifest_sha256": (result.get("subject") or {}).get("candidate_manifest_sha256"),
        "policy_sha256": (result.get("policy") or {}).get("sha256"),
    }
    for key, pattern in formats.items():
        value = expected.get(key)
        if not isinstance(value, str) or not pattern.fullmatch(value):
            errors.append(f"受信 CI 参数 {key} 格式无效")
        elif observed[key] != value:
            errors.append(f"CI {key} 与本次证据不匹配")
    if result.get("schema") != "northstar.security-gate.v1":
        errors.append("安全门禁结果 Schema 不匹配")
    answer["ci_binding"] = {
        "passed": not errors,
        "reasons": errors,
        "note": "期望 pin 的来源必须由固定可信工作流/宿主认证，本工具不验证签名。",
    }
    answer.setdefault("checks", []).append({"id": "CI_INDEPENDENT_BINDING", "passed": not errors, "reasons": errors})
    if errors:
        answer["evidence_valid"] = False
        answer["eligible_for_delivery"] = False
        answer["decision"] = "invalid"
        answer["exit_code"] = 2
        answer.setdefault("reason_codes", []).append("CI_INDEPENDENT_BINDING")
    elif (result.get("decision") == "pass" and result.get("eligible_for_delivery") is True
          and result.get("evidence_valid") is True and type(result.get("exit_code")) is int
          and result["exit_code"] == 0):
        answer["exit_code"] = 0
    else:
        # CI 只把真正的 pass 放行；保留原有 block/review/invalid 的含义和诊断。
        answer["eligible_for_delivery"] = False
        answer["exit_code"] = 1 if result.get("decision") == "block" else 2
    return answer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="只读安全证据 CI 门禁；所有 expected 参数必须来自可信上游。")
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--expectation", required=True)
    parser.add_argument("--expected-expectation-sha256", required=True)
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument("--expected-start-commit", required=True)
    parser.add_argument("--expected-patch-sha256", required=True)
    parser.add_argument("--expected-candidate-manifest-sha256", required=True)
    parser.add_argument("--expected-policy-sha256", required=True)
    args = parser.parse_args(argv)
    result = evaluate_bundle(args.evidence_dir, args.expectation)
    expected = {
        "host_expectation_sha256": args.expected_expectation_sha256,
        "run_id": args.expected_run_id,
        "start_commit": args.expected_start_commit,
        "patch_sha256": args.expected_patch_sha256,
        "candidate_manifest_sha256": args.expected_candidate_manifest_sha256,
        "policy_sha256": args.expected_policy_sha256,
    }
    answer = bind_gate(result, expected)
    print(json.dumps(answer, ensure_ascii=True, indent=2, allow_nan=False))
    return answer["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
