#!/usr/bin/env python3
"""Read-only bridge between Northstar code-task evidence and signed security evidence.

A passing result requires both (1) an internally consistent *verified* code
completion with independent HostCheck receipts and delivery bytes, and (2) the
fresh signed-produced validation performed by :func:`seal_release._read_produced`.
It neither seals nor publishes any directory, executes project code, runs a
scanner, or obtains a trust root from a candidate-controlled package.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# These imports resolve only relative to this deployed bridge, never relative
# to either directory being checked.
from seal_release import _read_produced  # noqa: E402
from trusted_common import (  # noqa: E402
    EvidenceError,
    MAX_JSON_BYTES,
    _read_path,
    clock,
    load_trust_store,
    parse_time,
    strict_json_loads,
    validate_identity,
)

SCHEMA = "northstar.programming-security-bridge.v1"
MAX_PATCH_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
_HEX64 = re.compile(r"[a-f0-9]{64}\Z")
_COMMIT40 = re.compile(r"[a-f0-9]{40}\Z")
_CODE_TERMINALS = frozenset(
    {
        "success",
        "success_unverified",
        "error_max_turns",
        "error_max_tool_calls",
        "error_max_budget_usd",
        "error_during_execution",
        "error_permission_denied",
        "error_postconditions_failed",
        "error_session_busy",
    }
)
_FORWARD = {
    "created": frozenset({"understanding"}),
    "understanding": frozenset({"planned"}),
    "planned": frozenset({"executing", "verifying"}),
    "executing": frozenset({"verifying"}),
    "verifying": frozenset(),
}
_ARTIFACTS = {
    "task": ("task.json", MAX_ARTIFACT_BYTES),
    "phases": ("phases.json", MAX_ARTIFACT_BYTES),
    "verification": ("verification.json", MAX_ARTIFACT_BYTES),
    "repository_snapshot": ("repository-snapshot.json", MAX_ARTIFACT_BYTES),
    "patch": ("changes.patch", MAX_PATCH_BYTES),
    "patch_replay": ("patch-replay.json", MAX_ARTIFACT_BYTES),
    "patch_audit": ("patch-audit.json", MAX_ARTIFACT_BYTES),
    "delivery_seal": ("delivery-seal.json", MAX_ARTIFACT_BYTES),
}


class BridgeError(ValueError):
    """One supplied local artifact cannot establish a bridge gate."""


def _fail(message: str) -> None:
    raise BridgeError(message)


def _digest(value: Any) -> bool:
    return type(value) is str and _HEX64.fullmatch(value) is not None


def _integer(value: Any) -> bool:
    return type(value) is int


def _boolean(value: Any) -> bool:
    return type(value) is bool


def _safe_name(value: Any, expected: str) -> bool:
    return type(value) is str and value == expected


def _safe_command(value: Any) -> bool:
    return type(value) is str and 0 < len(value) <= 4096 and value == value.strip()


def _parse_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = strict_json_loads(raw)
    except Exception as error:
        raise BridgeError(f"{label} is not strict JSON") from error
    if type(value) is not dict:
        _fail(f"{label} must be a JSON object")
    return value


def _directory(value: str | Path, label: str) -> Path:
    supplied = Path(value).expanduser()
    try:
        if supplied.is_symlink():
            _fail(f"{label} must not be a symlink")
        root = supplied.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise BridgeError(f"{label} cannot be resolved") from error
    if not root.is_dir():
        _fail(f"{label} is not a directory")
    return root


def _file_outside(value: str | Path, label: str, protected: tuple[Path, ...]) -> Path:
    supplied = Path(value).expanduser()
    try:
        if supplied.is_symlink():
            _fail(f"{label} must not be a symlink")
        resolved = supplied.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise BridgeError(f"{label} cannot be resolved") from error
    if not resolved.is_file():
        _fail(f"{label} is not a regular file")
    for root in protected:
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        _fail(f"{label} must be supplied outside candidate and evidence directories")
    return supplied


def _read(root: Path, name: str, maximum: int) -> bytes:
    try:
        return _read_path(root / name, maximum)
    except (OSError, EvidenceError, TypeError, ValueError) as error:
        raise BridgeError(f"cannot safely read {name}") from error


def _sealed_artifacts(root: Path, manifest: dict[str, Any]) -> dict[str, bytes]:
    artifacts: dict[str, bytes] = {}
    for field, (name, maximum) in _ARTIFACTS.items():
        if not _safe_name(manifest.get(field), name):
            _fail(f"manifest {field} must name {name}")
        expected = manifest.get(field + "_sha256")
        if not _digest(expected):
            _fail(f"manifest {field}_sha256 is invalid")
        raw = _read(root, name, maximum)
        actual = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(str(expected), actual):
            _fail(f"manifest digest does not bind {name}")
        artifacts[field] = raw
    return artifacts


def _validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("schema") != "northstar.code-evidence.v1":
        _fail("unsupported code evidence schema")
    if not isinstance(manifest.get("run_id"), str) or not manifest["run_id"]:
        _fail("code evidence run_id is invalid")
    if not isinstance(manifest.get("start_commit"), str) or _COMMIT40.fullmatch(manifest["start_commit"]) is None:
        _fail("code evidence start_commit must be a full lowercase Git commit")
    if manifest.get("status") != "success" or manifest.get("exit_code") != 0 or type(manifest.get("exit_code")) is not int:
        _fail("only terminal status success with exit_code 0 can be verified")
    if manifest.get("status") not in _CODE_TERMINALS:
        _fail("code evidence terminal status is unknown")
    if not _integer(manifest.get("patch_bytes")) or manifest["patch_bytes"] < 0:
        _fail("manifest patch_bytes is invalid")
    if not _digest(manifest.get("patch_sha256")):
        _fail("manifest patch_sha256 is invalid")
    for key in ("verification_ok", "patch_replay_ok", "patch_audit_ok", "delivery_seal_ok"):
        if manifest.get(key) is not True:
            _fail(f"manifest {key} must be true for verified success")


def _validate_task(task: dict[str, Any]) -> list[str]:
    if set(task) != {"goal", "checks", "plan_only", "network_targets"}:
        _fail("task receipt has an unexpected structure")
    goal = task.get("goal")
    if not isinstance(goal, str) or not goal or goal != goal.strip() or len(goal) > 65536:
        _fail("task goal is invalid")
    if task.get("plan_only") is not False:
        _fail("plan-only code task cannot establish delivered programming success")
    checks = task.get("checks")
    if not isinstance(checks, list) or not 1 <= len(checks) <= 32 or any(not _safe_command(item) for item in checks):
        _fail("task must declare one to 32 bounded host checks")
    if len(set(checks)) != len(checks):
        _fail("task host checks must be unique")
    targets = task.get("network_targets")
    if not isinstance(targets, list) or len(targets) > 128 or any(not isinstance(item, str) or not item for item in targets):
        _fail("task network target declaration is invalid")
    return checks


def _validate_snapshot(snapshot: dict[str, Any], manifest: dict[str, Any]) -> None:
    if snapshot.get("schema") != "northstar.repository-snapshot.v1":
        _fail("repository snapshot schema is invalid")
    for key in ("start_commit", "source_relative", "source_status"):
        if snapshot.get(key) != manifest.get(key):
            _fail(f"repository snapshot does not bind manifest {key}")


def _validate_phases(phases: dict[str, Any], manifest: dict[str, Any]) -> tuple[list[dict[str, Any]], int, int]:
    required = {"schema", "run_id", "state", "outcome", "plan_only", "plan", "transitions", "effect_journal_version", "effects"}
    if set(phases) != required or phases.get("schema") != "northstar.code-phases.v1":
        _fail("phase journal has an unexpected structure")
    if phases.get("run_id") != manifest.get("run_id"):
        _fail("phase journal run_id does not match manifest")
    if phases.get("state") != "success" or phases.get("outcome") != "success" or phases.get("plan_only") is not False:
        _fail("phase journal is not a non-plan-only success terminal")
    if phases.get("effect_journal_version") != 1 or type(phases.get("plan")) is not dict:
        _fail("phase journal lacks a structured plan or effect journal v1")
    transitions = phases.get("transitions")
    if not isinstance(transitions, list) or not transitions:
        _fail("phase journal has no transition chain")
    previous, previous_time, verifying_at, terminal_at = "created", -1, None, None
    for index, row in enumerate(transitions):
        if type(row) is not dict or set(row) != {"sequence", "from", "to", "reason", "data", "timestamp_unix_ms"}:
            _fail(f"phase transition {index + 1} structure is invalid")
        target, when = row.get("to"), row.get("timestamp_unix_ms")
        if row.get("sequence") != index + 1 or row.get("from") != previous:
            _fail(f"phase transition {index + 1} breaks the sequence")
        if not _integer(when) or when < 0 or when < previous_time:
            _fail(f"phase transition {index + 1} timestamp is invalid")
        if not isinstance(row.get("reason"), str) or not row["reason"] or type(row.get("data")) is not dict:
            _fail(f"phase transition {index + 1} receipt is invalid")
        allowed = _FORWARD.get(previous, frozenset())
        if not isinstance(target, str) or (target not in allowed and not (previous in _FORWARD and target in _CODE_TERMINALS)):
            _fail(f"phase transition {index + 1} is not allowed")
        if target == "verifying":
            verifying_at = when
        if target in _CODE_TERMINALS:
            terminal_at = when
        previous, previous_time = target, when
    if previous != "success" or verifying_at is None or terminal_at is None:
        _fail("phase journal did not reach success through verifying")
    effects = phases.get("effects")
    if not isinstance(effects, list):
        _fail("phase effects must be an array")
    for index, effect in enumerate(effects):
        required_effect = {"effect_id", "sequence", "tool", "call_id", "phase", "status", "started_unix_ms", "finished_unix_ms", "error_class"}
        if type(effect) is not dict or set(effect) != required_effect:
            _fail(f"effect {index + 1} structure is invalid")
        started, finished = effect.get("started_unix_ms"), effect.get("finished_unix_ms")
        if effect.get("effect_id") != f"effect-{index + 1}" or effect.get("sequence") != index + 1:
            _fail(f"effect {index + 1} identity is invalid")
        if not _integer(started) or started < 0 or not _integer(finished) or finished < started:
            _fail(f"effect {index + 1} completion receipt is invalid")
        if effect.get("status") not in {"completed", "denied"}:
            _fail(f"effect {index + 1} is unresolved or failed")
        if effect.get("tool") == "HostCheck" and (
            effect.get("phase") != "verifying" or started < verifying_at or finished > terminal_at
        ):
            _fail(f"HostCheck effect {index + 1} is outside the verifying interval")
    return effects, verifying_at, terminal_at


def _validate_verification(verification: dict[str, Any], manifest: dict[str, Any], checks: list[str], effects: list[dict[str, Any]]) -> int:
    if set(verification) != {"schema", "summaries"} or verification.get("schema") != "northstar.code-verification.v1":
        _fail("verification receipt has an unexpected structure")
    summaries = verification.get("summaries")
    if not isinstance(summaries, list) or len(summaries) != 1 or type(summaries[0]) is not dict:
        _fail("verification requires exactly one independent summary")
    summary = summaries[0]
    declared, ran = summary.get("declared"), summary.get("ran")
    passed, failed, skipped = summary.get("passed"), summary.get("failed"), summary.get("skipped")
    if any(not _integer(value) or value < 0 for value in (declared, ran, passed, failed, skipped)):
        _fail("verification summary counts are invalid")
    if (declared, ran, passed, failed, skipped) != (len(checks), len(checks), len(checks), 0, 0):
        _fail("every declared host check must run and pass")
    if summary.get("network") != "denied" or summary.get("ok") is not True or manifest.get("verification_ok") is not True:
        _fail("verification summary is not a successful network-denied host receipt")
    results = summary.get("results")
    if not isinstance(results, list) or len(results) != len(checks):
        _fail("verification result receipts do not match declared checks")
    for index, result in enumerate(results):
        required_result = {"index", "command", "exit_code", "ok", "timed_out", "truncated", "duration_ms", "output_sha256", "output_excerpt", "error"}
        if type(result) is not dict or set(result) != required_result:
            _fail(f"verification result {index} structure is invalid")
        if result.get("index") != index or result.get("command") != checks[index]:
            _fail(f"verification result {index} is not bound to its declared host check")
        if result.get("exit_code") != 0 or type(result.get("exit_code")) is not int or result.get("ok") is not True or result.get("timed_out") is not False:
            _fail(f"verification result {index} is not an actual successful host receipt")
        if not _boolean(result.get("truncated")) or not _integer(result.get("duration_ms")) or result["duration_ms"] < 0:
            _fail(f"verification result {index} metadata is invalid")
        if not _digest(result.get("output_sha256")) or not isinstance(result.get("output_excerpt"), str) or len(result["output_excerpt"]) > 8192:
            _fail(f"verification result {index} output receipt is invalid")
        if result.get("error") is not None and not isinstance(result.get("error"), str):
            _fail(f"verification result {index} error receipt is invalid")
    host_checks = [effect for effect in effects if effect.get("tool") == "HostCheck"]
    if len(host_checks) != len(results):
        _fail("HostCheck effects do not correspond one-for-one with verification receipts")
    for index, effect in enumerate(host_checks):
        if effect.get("call_id") != f"verification-{index}" or effect.get("status") != "completed":
            _fail(f"HostCheck effect {index} lacks its completed independent receipt")
    return len(results)


def _validate_delivery(manifest: dict[str, Any], artifacts: dict[str, bytes]) -> tuple[str, int]:
    patch = artifacts["patch"]
    patch_hash = hashlib.sha256(patch).hexdigest()
    if manifest.get("patch_bytes") != len(patch) or not hmac.compare_digest(manifest["patch_sha256"], patch_hash):
        _fail("manifest does not bind actual changes.patch bytes")
    replay = _parse_object(artifacts["patch_replay"], "patch replay")
    required_replay = {"schema", "start_commit", "patch_bytes", "patch_sha256", "empty", "read_tree_exit_code", "apply_exit_code", "ok", "diagnostic"}
    if set(replay) != required_replay or replay.get("schema") != "northstar.patch-replay.v1":
        _fail("patch replay receipt has an unexpected structure")
    if replay.get("start_commit") != manifest["start_commit"] or replay.get("patch_bytes") != len(patch) or replay.get("patch_sha256") != patch_hash:
        _fail("patch replay does not bind actual patch bytes and start commit")
    if replay.get("empty") is not (not bool(patch)) or replay.get("read_tree_exit_code") != 0 or replay.get("apply_exit_code") != 0 or replay.get("ok") is not True:
        _fail("patch replay is not an actual successful replay receipt")
    audit = _parse_object(artifacts["patch_audit"], "patch audit")
    required_audit = {"schema", "ok", "changed_files", "patch_bytes", "patch_sha256", "findings"}
    if set(audit) != required_audit or audit.get("schema") != "northstar.patch-audit.v1":
        _fail("patch audit receipt has an unexpected structure")
    if audit.get("patch_bytes") != len(patch) or audit.get("patch_sha256") != patch_hash or audit.get("ok") is not True or audit.get("findings") != []:
        _fail("patch audit does not approve actual patch bytes")
    if not _integer(audit.get("changed_files")) or audit["changed_files"] < 0:
        _fail("patch audit changed_files is invalid")
    seal = _parse_object(artifacts["delivery_seal"], "delivery seal")
    required_seal = {"schema", "start_commit", "precheck_patch_sha256", "patch_sha256", "unchanged_during_verification", "patch_audit_ok", "ok"}
    if set(seal) != required_seal or seal.get("schema") != "northstar.delivery-seal.v1":
        _fail("delivery seal receipt has an unexpected structure")
    if seal.get("start_commit") != manifest["start_commit"] or seal.get("precheck_patch_sha256") != patch_hash or seal.get("patch_sha256") != patch_hash:
        _fail("delivery seal does not bind actual patch bytes and start commit")
    if seal.get("unchanged_during_verification") is not True or seal.get("patch_audit_ok") is not True or seal.get("ok") is not True:
        _fail("delivery seal does not prove an unchanged audited patch")
    return patch_hash, len(patch)


def _validate_code_evidence(code_evidence_dir: str | Path) -> dict[str, Any]:
    root = _directory(code_evidence_dir, "code evidence directory")
    manifest = _parse_object(_read(root, "manifest.json", MAX_ARTIFACT_BYTES), "manifest")
    _validate_manifest(manifest)
    artifacts = _sealed_artifacts(root, manifest)
    task = _parse_object(artifacts["task"], "task")
    snapshot = _parse_object(artifacts["repository_snapshot"], "repository snapshot")
    phases = _parse_object(artifacts["phases"], "phase journal")
    verification = _parse_object(artifacts["verification"], "verification")
    checks = _validate_task(task)
    _validate_snapshot(snapshot, manifest)
    effects, _verifying_at, _terminal_at = _validate_phases(phases, manifest)
    host_checks = _validate_verification(verification, manifest, checks, effects)
    patch_sha256, patch_bytes = _validate_delivery(manifest, artifacts)
    return {
        "run_id": manifest["run_id"],
        "start_commit": manifest["start_commit"],
        "patch_sha256": patch_sha256,
        "patch_bytes": patch_bytes,
        "host_checks": host_checks,
        "terminal_status": manifest["status"],
    }


def _trusted_inputs(
    produced_dir: str | Path,
    code_evidence_dir: str | Path,
    trust_store_path: str | Path,
    identity_path: str | Path,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    produced = _directory(produced_dir, "produced directory")
    code_evidence = _directory(code_evidence_dir, "code evidence directory")
    trust_path = _file_outside(trust_store_path, "trust store", (produced, code_evidence))
    identity_file = _file_outside(identity_path, "identity", (produced, code_evidence))
    try:
        trust = load_trust_store(trust_path)
        identity = _parse_object(_read_path(identity_file, MAX_JSON_BYTES), "identity")
        validate_identity(identity)
    except (OSError, EvidenceError, TypeError, ValueError, BridgeError) as error:
        raise BridgeError("externally supplied trust store or identity is invalid") from error
    return produced, trust, identity


def _validate_signed_produced(
    produced_dir: Path,
    trust: dict[str, Any],
    identity: dict[str, Any],
    now: datetime | None,
) -> dict[str, Any]:
    try:
        files, plan_payload, _capture, _expectation, _capture_manifest = _read_produced(
            produced_dir, trust, identity, clock(now)
        )
        plan = plan_payload["body"]
        subject = plan["expectation_template"]["subject"]
        gate = _parse_object(files["security-gate.json"], "security gate")
    except (OSError, EvidenceError, KeyError, TypeError, ValueError, BridgeError) as error:
        raise BridgeError("signed produced directory failed fresh signature-graph and gate validation") from error
    if type(subject) is not dict or not _COMMIT40.fullmatch(subject.get("start_commit", "")) or not _digest(subject.get("patch_sha256")) or not _digest(subject.get("candidate_manifest_sha256")):
        _fail("signed plan subject lacks contracted start_commit, patch_sha256, or candidate_manifest_sha256")
    if gate.get("decision") != "pass" or gate.get("exit_code") != 0 or gate.get("eligible_for_delivery") is not True or gate.get("evidence_valid") is not True:
        _fail("fresh security gate is not an eligible pass")
    return {
        "run_id": identity["run_id"],
        "start_commit": subject["start_commit"],
        "patch_sha256": subject["patch_sha256"],
        "candidate_manifest_sha256": subject["candidate_manifest_sha256"],
        "fresh_gate_passed": True,
    }


def _reason(error: BaseException) -> str:
    detail = str(error).replace("\n", " ").strip()
    return (detail or type(error).__name__)[:300]


def inspect(
    code_evidence_dir: str | Path,
    produced_dir: str | Path,
    trust_store_path: str | Path,
    identity_path: str | Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Read both chains and return a fail-closed bridge report without writing.

    ``trust_store_path`` and ``identity_path`` are required external control-plane
    inputs.  The bridge rejects either if it resolves inside the produced package
    or code-evidence directory.  ``now`` is exposed only for deterministic local
    tests; production callers should leave it as ``None`` for the host UTC clock.
    """
    gates: list[dict[str, Any]] = []
    code: dict[str, Any] | None = None
    security: dict[str, Any] | None = None
    produced: Path | None = None
    trust: dict[str, Any] | None = None
    identity: dict[str, Any] | None = None

    try:
        code = _validate_code_evidence(code_evidence_dir)
        gates.append({"name": "code_verified_success", "passed": True, "reasons": []})
    except (BridgeError, OSError, ValueError) as error:
        gates.append({"name": "code_verified_success", "passed": False, "reasons": [_reason(error)]})

    try:
        produced, trust, identity = _trusted_inputs(produced_dir, code_evidence_dir, trust_store_path, identity_path)
        gates.append({"name": "external_trust_identity", "passed": True, "reasons": []})
    except (BridgeError, OSError, ValueError) as error:
        gates.append({"name": "external_trust_identity", "passed": False, "reasons": [_reason(error)]})

    if produced is not None and trust is not None and identity is not None:
        try:
            security = _validate_signed_produced(produced, trust, identity, now)
            gates.append({"name": "signed_produced_fresh_gate", "passed": True, "reasons": []})
        except (BridgeError, OSError, ValueError) as error:
            gates.append({"name": "signed_produced_fresh_gate", "passed": False, "reasons": [_reason(error)]})
    else:
        gates.append({"name": "signed_produced_fresh_gate", "passed": False, "reasons": ["external trust and identity gate failed"]})

    binding: dict[str, Any] = {"start_commit": False, "patch_sha256": False, "candidate_manifest_rebuilt": False}
    if code is not None and security is not None:
        binding["start_commit"] = hmac.compare_digest(code["start_commit"], security["start_commit"])
        binding["patch_sha256"] = hmac.compare_digest(code["patch_sha256"], security["patch_sha256"])
        binding["candidate_manifest_sha256"] = security["candidate_manifest_sha256"]
        if not binding["start_commit"] or not binding["patch_sha256"]:
            missing = []
            if not binding["start_commit"]:
                missing.append("start_commit")
            if not binding["patch_sha256"]:
                missing.append("patch_sha256")
            gates.append({"name": "signed_plan_delivery_binding", "passed": False, "reasons": ["signed plan subject mismatch: " + ", ".join(missing)]})
        else:
            gates.append({"name": "signed_plan_delivery_binding", "passed": True, "reasons": []})
    else:
        gates.append({"name": "signed_plan_delivery_binding", "passed": False, "reasons": ["code or signed produced validation failed"]})

    verified = all(gate["passed"] for gate in gates)
    return {
        "schema": SCHEMA,
        "read_only": True,
        "verified_success": verified,
        "classification": "verified_programming_security_bridge" if verified else "invalid_or_incomplete_programming_security_bridge",
        "code": code,
        "security": security,
        "bindings": binding,
        "gates": gates,
        "limitations": [
            "本桥仅以现有本地 code_task 回执和外部提供的受信 trust/identity 验证一致性；本地证据摘要不是对恶意宿主或证据生产者的独立认证。",
            "candidate_manifest_sha256 仅从已验签计划 subject 读取；当前接口没有独立候选清单及从源码/构建输入重建它的能力，因此 candidate_manifest_rebuilt 始终为 false。",
            "本桥不运行扫描器、normalizer、项目代码或宿主检查；也不 seal、publish、写入或提升任何候选文件的信任。",
            "通过不证明源码到制品的可复现性、物理隔离已实现、未知漏洞不存在，或可自动发布。",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only bridge for code-task verified success and signed security produced evidence.")
    parser.add_argument("--code-evidence-dir", required=True)
    parser.add_argument("--produced-dir", required=True)
    parser.add_argument("--trust-store", required=True, help="externally deployed trust-store JSON, outside both checked directories")
    parser.add_argument("--identity", required=True, help="externally supplied current CI identity JSON, outside both checked directories")
    parser.add_argument("--now", help="strict UTC RFC3339 test clock; omit to use current host UTC time")
    args = parser.parse_args(argv)
    try:
        now = parse_time(args.now) if args.now is not None else None
        result = inspect(args.code_evidence_dir, args.produced_dir, args.trust_store, args.identity, now=now)
    except (BridgeError, EvidenceError, OSError, ValueError) as error:
        result = {
            "schema": SCHEMA,
            "read_only": True,
            "verified_success": False,
            "classification": "invalid_or_incomplete_programming_security_bridge",
            "code": None,
            "security": None,
            "bindings": {"start_commit": False, "patch_sha256": False, "candidate_manifest_rebuilt": False},
            "gates": [{"name": "bridge_invocation", "passed": False, "reasons": [_reason(error)]}],
            "limitations": ["bridge invocation failed before any write, seal, publish, scan, or project-code execution"],
        }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False))
    # Deliberately never treat a default successful process exit as delivery
    # success: callers get zero only for the complete verified bridge result.
    return 0 if result["verified_success"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
