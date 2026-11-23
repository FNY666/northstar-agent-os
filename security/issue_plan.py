#!/usr/bin/env python3
"""签发已由受信控制面准备的预扫描计划；不从normalized结果或PR生成计划。"""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from produce_expectation import _validated_plan_body
from trusted_common import EvidenceError, _read_path, create_receipt, load_private_key, load_trust_store, publish_directory, sha, strict_json_loads, validate_identity


def issue_plan(body_path, output_dir, trust_store, expected_identity, signing_key, *, now: datetime | None = None) -> dict:
    # body_path必须为固定部署的planner从真实冻结输入与受保护profile生成的数据。
    # 本入口能验证结构和签名授权，但不能证明body路径本身来源，更不会猜测scope。
    validate_identity(expected_identity)
    body = strict_json_loads(_read_path(body_path))
    _validated_plan_body(body, expected_identity)
    raw = create_receipt("scan-plan", expected_identity, body, signing_key, trust_store, now=now)
    publish_directory(output_dir, {"plan.dsse.json": raw})
    return {"exit_code": 0, "plan_sha256": sha(raw), "output_dir": str(Path(output_dir).absolute())}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="为受信预扫描plan签发回执；不得使用候选上传的plan-body。")
    parser.add_argument("--plan-body", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--trust-store", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--signing-key-file", required=True)
    args = parser.parse_args(argv)
    try:
        identity = strict_json_loads(_read_path(args.identity))
        result = issue_plan(args.plan_body, args.output, load_trust_store(args.trust_store), identity, load_private_key(args.signing_key_file))
    except (EvidenceError, OSError, ValueError, TypeError) as error:
        result = {"exit_code": 2, "error": type(error).__name__}
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
