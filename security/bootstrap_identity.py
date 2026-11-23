#!/usr/bin/env python3
"""受保护bootstrap job使用；从当前GitHub运行生成控制面身份，nonce不是密钥。"""
from __future__ import annotations

import argparse
import json
import os
import secrets
from collections.abc import Mapping
from pathlib import Path

from trusted_common import EvidenceError, publish_directory, validate_identity, wire


def build_identity(environment: Mapping[str, str]) -> dict:
    names = ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA")
    if any(type(environment.get(name)) is not str or not environment[name] for name in names):
        raise EvidenceError("缺少当前受信GitHub控制面身份")
    run_id, attempt = environment["GITHUB_RUN_ID"], environment["GITHUB_RUN_ATTEMPT"]
    if not run_id.isascii() or not run_id.isdigit() or len(run_id) > 32:
        raise EvidenceError("GitHub run id格式无效")
    if not attempt.isascii() or not attempt.isdigit() or len(attempt) > 7:
        raise EvidenceError("GitHub run attempt格式无效")
    identity = {"repository": environment["GITHUB_REPOSITORY"], "run_id": "gh-" + run_id, "run_attempt": int(attempt), "source_commit": environment["GITHUB_SHA"], "nonce": secrets.token_hex(32)}
    validate_identity(identity)
    return identity


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="在受保护bootstrap job生成当前运行身份；不导入下载证据。")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        identity = build_identity(os.environ)
        publish_directory(Path(args.output), {"identity.json": wire(identity)})
        result = {"exit_code": 0, "identity": identity, "output_dir": str(Path(args.output).absolute())}
    except (EvidenceError, OSError, ValueError) as error:
        result = {"exit_code": 2, "error": type(error).__name__}
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
