#!/usr/bin/env python3
"""仅演示契约互操作：fake扫描输出/fake wheel，绝不用于生产，私钥不写磁盘。"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from producer_fixtures import build_scenario, key_id, trust_entry
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from trusted_common import create_receipt, file_manifest, sha, wire
from produce_expectation import produce_expectation
from seal_release import seal_release
from consume_release import consume_release


def demo(root: Path) -> dict:
    root.mkdir(parents=True, mode=0o700, exist_ok=False)
    s = build_scenario(root / "fixture")
    # 补丁起点不是最终commit：这个场景特意验证二者可以不相同。
    base = "c" * 40
    s.plan_body["expectation_template"]["subject"]["start_commit"] = base
    for tool in s.records:
        s.records[tool]["subject"]["start_commit"] = base
        s.sync_record(tool)
    s.write_plan()
    s.write_capture()
    for role, kind in (("build", "build-capture"), ("seal", "release-seal")):
        s.keys[role] = Ed25519PrivateKey.generate()
        s.trust["keys"][key_id(s.keys[role])] = trust_entry(s.keys[role], [kind], s.identity["repository"], s.now)
    produced = root / "produced"
    result = produce_expectation(s.plan_path, s.capture_path, s.evidence_dir, produced, s.trust, s.identity, s.keys["expectation"], now=s.now)
    wheels = {component + "-0.1.0-py3-none-any.whl": ("TEST FIXTURE NOT AN INSTALLABLE WHEEL " + component).encode() for component in s.plan_body["release_components"]}
    dist = root / "dist"
    dist.mkdir()
    for name, raw in wheels.items(): (dist / name).write_bytes(raw)
    build = create_receipt("build-capture", s.identity, {"schema": "northstar.build-capture.v1", "plan_sha256": sha(s.plan_path.read_bytes()), "files": file_manifest(wheels)}, s.keys["build"], s.trust, now=s.now)
    build_path = root / "build-capture.dsse.json"
    build_path.write_bytes(build)
    sealed = root / "sealed"
    seal = seal_release(produced, build_path, dist, sealed, s.trust, s.identity, s.keys["seal"], now=s.now + timedelta(seconds=5))
    consumed = consume_release(sealed, s.trust, s.identity, now=s.now + timedelta(seconds=10))
    # 仅保留测试public roots；它们位于sealed包外，绝不能作为生产信任根安装。
    (root / "demo-trust-store.json").write_bytes(wire(s.trust))
    (root / "demo-identity.json").write_bytes(wire(s.identity))
    result = {"test_fixture_only": True, "private_keys_persisted": False, "real_scanners_executed": False, "real_build_executed": False, "source_and_start_commits_differ": True, "producer_exit_code": result["exit_code"], "seal_exit_code": seal["exit_code"], "consumer": consumed}
    (root / "demo-summary.json").write_bytes(wire(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="仅运行无真实扫描/构建的协议demo，不生成生产私钥。")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = demo(Path(args.output))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return result["consumer"]["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
