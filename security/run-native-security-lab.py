#!/usr/bin/env python3
"""固定、本地的 Northstar 原生安全证据攻防实验室。

本程序只构造临时测试 fixture，调用既有签名、证据、密封和消费核心。
它没有目标、命令、URL、凭据或输出路径参数；不会运行扫描器、项目代码或构建。
每一个攻击都有独立的正常 pair，所有 Ed25519 测试私钥仅由 fixture 在内存中生成。
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent
LEGACY = ROOT / "cicd-evidence-integration" / "security-evidence-contract"
for _directory in (ROOT, ROOT / "tests", LEGACY):
    if str(_directory) not in sys.path:
        sys.path.insert(0, str(_directory))

from consume_release import consume_release
from produce_expectation import produce_expectation
from seal_release import seal_release
from sealing_fixtures import build_scenario, make_writable
from trusted_common import EvidenceError, create_receipt, file_manifest, sha, strict_json_loads, wire

LAB_SCHEMA = "northstar.native-security-lab.v1"
_CAPTURE_SCHEMA = "northstar.scan-capture.v1"
_EXPECTATION_SCHEMA = "northstar.expectation-receipt.v1"


# This catalog is deliberately closed.  Its IDs are the only experiments the CLI can invoke.
EXPERIMENTS: tuple[tuple[str, str], ...] = (
    ("scope-laundering", "将观测输入改成签名范围之外的路径"),
    ("fake-success", "伪造完成状态：exit=1 却声称无发现且使用伪造 pass gate"),
    ("replay-nonce", "将旧密封包重放到 nonce 已变更的当前可信身份"),
    ("replay-attempt", "将旧密封包重放到 run_attempt 已变更的当前可信身份"),
    ("wheel-swap", "在密封之后替换一个已认证的 fixture wheel"),
    ("old-gate-tamper", "篡改历史 producer gate"),
    ("new-gate-tamper", "篡改密封时新鲜 gate"),
    ("context-tamper", "篡改 host expectation 上下文"),
    ("source-mismatch", "以不同 source_commit 作为当前可信身份消费密封包"),
)


def list_experiments() -> list[dict[str, str]]:
    """Return static catalog metadata without creating a fixture or key."""
    return [{"id": case_id, "description": description} for case_id, description in EXPERIMENTS]


def _private_key_files(root: Path) -> list[Path]:
    """Fixture keys must remain memory-only; no private-key file is permitted."""
    forbidden_suffixes = (".pem", ".key", ".private")
    return [path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in forbidden_suffixes]


def _normal_pair(root: Path) -> dict[str, Any]:
    """Build a benign fixture, seal it, then consume it through the old core."""
    scenario = build_scenario(root / "fixture")
    sealed = root / "sealed"
    sealed_result = seal_release(
        scenario.produced_dir,
        scenario.build_capture_path,
        scenario.dist_dir,
        sealed,
        scenario.trust,
        scenario.identity,
        scenario.keys["seal"],
        now=scenario.now,
    )
    consumed = consume_release(sealed, scenario.trust, scenario.identity, now=scenario.now)
    passed = (
        sealed_result.get("exit_code") == 0
        and sealed_result.get("eligible_for_publish") is True
        and consumed.get("exit_code") == 0
        and consumed.get("eligible_for_publish") is True
    )
    return {
        "passed": passed,
        "seal_exit_code": sealed_result.get("exit_code"),
        "consume_exit_code": consumed.get("exit_code"),
        "eligible_for_publish": consumed.get("eligible_for_publish") is True,
        "private_keys_persisted": bool(_private_key_files(root)),
    }


def _producer_rejection(attempt: Callable[[], Any], output_dir: Path, *, mutation_kind: str) -> dict[str, Any]:
    """Record a fail-closed producer/sealer rejection and no output publication."""
    caught = False
    try:
        attempt()
    except EvidenceError:
        caught = True
    blocked = caught and not output_dir.exists()
    return {
        "detected": caught,
        "blocked": blocked,
        "mutation_applied": True,
        "mutation_kind": mutation_kind,
        "artifact_mutated": mutation_kind == "artifact_bytes",
        "trusted_context_mutated": False,
        "verification": "producer_rejected_without_publication" if blocked else "producer_not_fail_closed",
    }


def _consumer_rejection(
    consumed: dict[str, Any], *, mutation_kind: str, artifact_mutated: bool, trusted_context_mutated: bool
) -> dict[str, Any]:
    """Record a completed consumer verification that made the attacked artifact ineligible."""
    detected = consumed.get("eligible_for_publish") is False and consumed.get("exit_code") == 2
    return {
        "detected": detected,
        "blocked": detected,
        "mutation_applied": True,
        "mutation_kind": mutation_kind,
        "artifact_mutated": artifact_mutated,
        "trusted_context_mutated": trusted_context_mutated,
        "verification": "consumer_marked_package_ineligible" if detected else "consumer_unexpectedly_accepted",
    }


def _write_scope_laundering_capture(root: Path) -> tuple[Any, Path, Path, Path]:
    """Create a locally re-signed fixture capture with an off-scope observed path.

    The fresh test capture signature is intentional: it proves the signed *plan*
    still constrains the record, rather than merely proving a stale hash mismatch.
    """
    scenario = build_scenario(root / "fixture")
    altered_files = dict(scenario.capture_files)
    record = strict_json_loads(altered_files["semgrep-evidence.json"])
    record["coverage"]["observed_inputs"][0]["path"] = "src/other.py"
    altered_files["semgrep-evidence.json"] = wire(record)

    plan_path = root / "plan.dsse.json"
    capture_path = root / "capture.dsse.json"
    evidence_dir = root / "evidence"
    plan_path.write_bytes(scenario.plan_raw)
    evidence_dir.mkdir()
    for name, raw in altered_files.items():
        (evidence_dir / name).write_bytes(raw)
    capture_path.write_bytes(
        create_receipt(
            "scan-capture",
            scenario.identity,
            {
                "schema": _CAPTURE_SCHEMA,
                "plan_sha256": sha(scenario.plan_raw),
                "files": file_manifest(altered_files),
            },
            scenario.keys["capture"],
            scenario.trust,
            now=scenario.now,
        )
    )
    return scenario, plan_path, capture_path, evidence_dir


def _attack_scope_laundering(root: Path) -> dict[str, Any]:
    scenario, plan_path, capture_path, evidence_dir = _write_scope_laundering_capture(root)
    output_dir = root / "produced"
    return _producer_rejection(
        lambda: produce_expectation(
            plan_path,
            capture_path,
            evidence_dir,
            output_dir,
            scenario.trust,
            scenario.identity,
            scenario.keys["expectation"],
            now=scenario.now,
        ),
        output_dir,
        mutation_kind="artifact_bytes",
    )


def _replace_produced_with_fake_success(scenario: Any) -> None:
    """Stage a test-only graph that gets past historical pins but not fresh evaluation."""
    files = dict(scenario.capture_files)
    record = strict_json_loads(files["semgrep-evidence.json"])
    record["execution"]["exit_code"] = 1
    # The normal fixture has no findings, so this violates the execution contract.
    files["semgrep-evidence.json"] = wire(record)
    capture_raw = create_receipt(
        "scan-capture",
        scenario.identity,
        {"schema": _CAPTURE_SCHEMA, "plan_sha256": sha(scenario.plan_raw), "files": file_manifest(files)},
        scenario.keys["capture"],
        scenario.trust,
        now=scenario.now,
    )

    expectation = strict_json_loads(scenario.expectation_raw)
    for tool in ("semgrep", "osv-scanner"):
        evidence_name = expectation["tools"][tool]["evidence_file"]
        expectation["tools"][tool]["evidence_sha256"] = sha(files[evidence_name])
    expectation_raw = wire(expectation)

    # The gate is deliberately made to look passable only to ensure sealing invokes
    # its independently recomputed fresh gate.  This is a local in-memory-key fixture.
    fake_gate = strict_json_loads(scenario.producer_gate_raw)
    fake_gate["host_expectation_sha256"] = sha(expectation_raw)
    fake_gate["subject"] = expectation["subject"]
    fake_gate["policy"] = {key: expectation["policy"][key] for key in ("id", "sha256")}
    fake_gate_raw = wire(fake_gate)
    expectation_receipt = create_receipt(
        "expectation",
        scenario.identity,
        {
            "schema": _EXPECTATION_SCHEMA,
            "plan_sha256": sha(scenario.plan_raw),
            "capture_sha256": sha(capture_raw),
            "expectation_sha256": sha(expectation_raw),
            "gate_sha256": sha(fake_gate_raw),
        },
        scenario.keys["expectation"],
        scenario.trust,
        now=scenario.now,
    )

    make_writable(scenario.produced_dir)
    for name, raw in files.items():
        (scenario.produced_dir / name).write_bytes(raw)
    (scenario.produced_dir / "capture.dsse.json").write_bytes(capture_raw)
    (scenario.produced_dir / "host-expectation.json").write_bytes(expectation_raw)
    (scenario.produced_dir / "security-gate.json").write_bytes(fake_gate_raw)
    (scenario.produced_dir / "expectation.dsse.json").write_bytes(expectation_receipt)


def _attack_fake_success(root: Path) -> dict[str, Any]:
    scenario = build_scenario(root / "fixture")
    _replace_produced_with_fake_success(scenario)
    output_dir = root / "sealed"
    return _producer_rejection(
        lambda: seal_release(
            scenario.produced_dir,
            scenario.build_capture_path,
            scenario.dist_dir,
            output_dir,
            scenario.trust,
            scenario.identity,
            scenario.keys["seal"],
            now=scenario.now,
        ),
        output_dir,
        mutation_kind="artifact_bytes",
    )


def _sealed_fixture(root: Path) -> tuple[Any, Path]:
    scenario = build_scenario(root / "fixture")
    sealed = root / "sealed"
    result = seal_release(
        scenario.produced_dir,
        scenario.build_capture_path,
        scenario.dist_dir,
        sealed,
        scenario.trust,
        scenario.identity,
        scenario.keys["seal"],
        now=scenario.now,
    )
    if result.get("exit_code") != 0 or result.get("eligible_for_publish") is not True:
        raise AssertionError("benign local fixture did not seal")
    return scenario, sealed


def _attack_replay_nonce(root: Path) -> dict[str, Any]:
    scenario, sealed = _sealed_fixture(root)
    identity = copy.deepcopy(scenario.identity)
    identity["nonce"] = "c" * 64
    return _consumer_rejection(
        consume_release(sealed, scenario.trust, identity, now=scenario.now),
        mutation_kind="trusted_identity",
        artifact_mutated=False,
        trusted_context_mutated=True,
    )


def _attack_replay_attempt(root: Path) -> dict[str, Any]:
    scenario, sealed = _sealed_fixture(root)
    identity = copy.deepcopy(scenario.identity)
    identity["run_attempt"] += 1
    return _consumer_rejection(
        consume_release(sealed, scenario.trust, identity, now=scenario.now),
        mutation_kind="trusted_identity",
        artifact_mutated=False,
        trusted_context_mutated=True,
    )


def _tamper_sealed_file(root: Path, filename: str) -> tuple[Any, Path]:
    scenario, sealed = _sealed_fixture(root)
    make_writable(sealed)
    target = sealed / filename
    target.write_bytes(target.read_bytes() + b"\nfixture-tamper")
    return scenario, sealed


def _attack_wheel_swap(root: Path) -> dict[str, Any]:
    scenario, sealed = _sealed_fixture(root)
    make_writable(sealed)
    wheel = next(path for path in sealed.iterdir() if path.name.endswith(".whl"))
    wheel.write_bytes(b"local-fixture-wheel-replacement")
    return _consumer_rejection(
        consume_release(sealed, scenario.trust, scenario.identity, now=scenario.now),
        mutation_kind="artifact_bytes",
        artifact_mutated=True,
        trusted_context_mutated=False,
    )


def _attack_old_gate_tamper(root: Path) -> dict[str, Any]:
    scenario, sealed = _tamper_sealed_file(root, "producer-gate.json")
    return _consumer_rejection(
        consume_release(sealed, scenario.trust, scenario.identity, now=scenario.now),
        mutation_kind="artifact_bytes",
        artifact_mutated=True,
        trusted_context_mutated=False,
    )


def _attack_new_gate_tamper(root: Path) -> dict[str, Any]:
    scenario, sealed = _tamper_sealed_file(root, "security-gate.json")
    return _consumer_rejection(
        consume_release(sealed, scenario.trust, scenario.identity, now=scenario.now),
        mutation_kind="artifact_bytes",
        artifact_mutated=True,
        trusted_context_mutated=False,
    )


def _attack_context_tamper(root: Path) -> dict[str, Any]:
    scenario, sealed = _tamper_sealed_file(root, "host-expectation.json")
    return _consumer_rejection(
        consume_release(sealed, scenario.trust, scenario.identity, now=scenario.now),
        mutation_kind="artifact_bytes",
        artifact_mutated=True,
        trusted_context_mutated=False,
    )


def _attack_source_mismatch(root: Path) -> dict[str, Any]:
    scenario, sealed = _sealed_fixture(root)
    identity = copy.deepcopy(scenario.identity)
    identity["source_commit"] = "c" * 40
    return _consumer_rejection(
        consume_release(sealed, scenario.trust, identity, now=scenario.now),
        mutation_kind="trusted_identity",
        artifact_mutated=False,
        trusted_context_mutated=True,
    )


_ATTACKS: dict[str, Callable[[Path], dict[str, Any]]] = {
    "scope-laundering": _attack_scope_laundering,
    "fake-success": _attack_fake_success,
    "replay-nonce": _attack_replay_nonce,
    "replay-attempt": _attack_replay_attempt,
    "wheel-swap": _attack_wheel_swap,
    "old-gate-tamper": _attack_old_gate_tamper,
    "new-gate-tamper": _attack_new_gate_tamper,
    "context-tamper": _attack_context_tamper,
    "source-mismatch": _attack_source_mismatch,
}


def _run_case(case_id: str, description: str) -> dict[str, Any]:
    """Run exactly one benign/attack pair in a new private temporary directory."""
    with tempfile.TemporaryDirectory(prefix="northstar-native-attacklab-") as temporary:
        root = Path(temporary)
        private_keys_persisted = False
        try:
            benign = _normal_pair(root / "benign")
            private_keys_persisted = bool(benign["private_keys_persisted"])
            attack = _ATTACKS[case_id](root / "attack")
            private_keys_persisted = private_keys_persisted or bool(_private_key_files(root))
            passed = benign["passed"] and attack["detected"] and attack["blocked"] and not private_keys_persisted
            return {
                "id": case_id,
                "description": description,
                "benign": benign,
                "attack": attack,
                "private_keys_persisted": private_keys_persisted,
                "passed": passed,
            }
        except Exception as error:  # preserve a complete laboratory report without exposing fixture internals.
            private_keys_persisted = private_keys_persisted or bool(_private_key_files(root))
            return {
                "id": case_id,
                "description": description,
                "benign": {"passed": False},
                "attack": {
                    "detected": False,
                    "blocked": False,
                    "mutation_applied": False,
                    "mutation_kind": "not_completed",
                    "artifact_mutated": False,
                    "trusted_context_mutated": False,
                    "verification": "laboratory_execution_error",
                },
                "private_keys_persisted": private_keys_persisted,
                "passed": False,
                "error_type": type(error).__name__,
            }


def run_lab() -> dict[str, Any]:
    """Run all closed experiments and return machine-readable, non-secret aggregates."""
    cases = [_run_case(case_id, description) for case_id, description in EXPERIMENTS]
    benign_passed = sum(case["benign"].get("passed") is True for case in cases)
    detected = sum(case["attack"].get("detected") is True for case in cases)
    blocked = sum(case["attack"].get("blocked") is True for case in cases)
    mutated = sum(case["attack"].get("mutation_applied") is True for case in cases)
    artifact_mutated = sum(case["attack"].get("artifact_mutated") is True for case in cases)
    context_mutated = sum(case["attack"].get("trusted_context_mutated") is True for case in cases)
    failures = [case["id"] for case in cases if not case["passed"]]
    return {
        "schema": LAB_SCHEMA,
        "lab": {
            "fixture_only": True,
            "real_scanners_executed": False,
            "project_code_executed": False,
            "real_build_executed": False,
            "private_keys_persisted": False,
            "external_targets_accepted": False,
        },
        "summary": {
            "paired_cases": len(cases),
            "benign_passed": benign_passed,
            "attacks_detected": detected,
            "attacks_blocked": blocked,
            "mutations_applied": mutated,
            "artifact_mutations_applied": artifact_mutated,
            "trusted_context_mutations_applied": context_mutated,
            "failed_cases": failures,
        },
        "cases": cases,
        "passed": not failures,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run only the fixed local Northstar attack-defense laboratory.")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--json", action="store_true", help="run every fixed benign/attack pair and emit JSON")
    actions.add_argument("--list", action="store_true", help="list fixed experiment IDs without creating fixtures")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.list:
        answer: dict[str, Any] = {"schema": LAB_SCHEMA, "experiments": list_experiments()}
        print(json.dumps(answer, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False))
        return 0
    answer = run_lab()
    print(json.dumps(answer, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0 if answer["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
