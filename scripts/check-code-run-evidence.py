#!/usr/bin/env python3
"""Read-only hard gates for Northstar ``code`` run evidence.

This intentionally does not import the runtime.  It validates the on-disk v1
contract and reports what local artifacts can, and cannot, establish.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

SCHEMA = "northstar.code-evidence-gates.v1"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 128
MAX_JSON_NODES = 100_000
MAX_PATCH_BYTES = 8 * 1024 * 1024
MAX_OTHER_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_ENTRIES = 10_000
MAX_PATH_CHARS = 4096
MAX_TEXT_CHARS = 65_536
MAX_COMMAND_CHARS = 4096
MAX_SNAPSHOT_FILES = 8_000
MAX_DELIVERY_FILES = 200
TERMINALS = {
    "success", "success_unverified", "error_max_turns", "error_max_tool_calls",
    "error_max_budget_usd", "error_during_execution", "error_permission_denied",
    "error_postconditions_failed", "error_session_busy",
}
EXIT_CODES = {
    "success": 0, "success_unverified": 0, "error_during_execution": 1,
    "error_max_turns": 2, "error_max_tool_calls": 3, "error_max_budget_usd": 4,
    "error_permission_denied": 5, "error_postconditions_failed": 6,
    "error_session_busy": 7,
}
ACTIVE = {"created", "understanding", "planned", "executing", "verifying"}
FORWARD = {
    "created": {"understanding"}, "understanding": {"planned"},
    "planned": {"executing", "verifying"}, "executing": {"verifying"},
    "verifying": set(),
}
EFFECT_STATUSES = {"in_flight", "completed", "denied", "failed", "unknown"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class EvidenceError(ValueError):
    """A local file cannot be safely parsed as evidence."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    answer: dict[str, Any] = {}
    for key, value in pairs:
        if key in answer:
            raise EvidenceError(f"duplicate JSON key {key!r}")
        answer[key] = value
    return answer


def _bad_constant(value: str) -> None:
    raise EvidenceError(f"non-finite JSON number {value!r}")


def _check_finite(value: Any, where: str = "$") -> None:
    """Bound JSON shape and reject non-finite values without recursion.

    ``json.loads`` creates an acyclic tree, so an explicit stack both avoids a
    Python recursion crash and bounds validation work for adversarial input.
    """
    nodes = 1
    stack: list[tuple[Any, str, int]] = [(value, where, 0)]
    while stack:
        item, location, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise EvidenceError(f"JSON exceeds nesting depth {MAX_JSON_DEPTH} at {location}")
        if isinstance(item, float) and not math.isfinite(item):
            raise EvidenceError(f"non-finite JSON number at {location}")
        if isinstance(item, list):
            if len(item) > MAX_JSON_NODES - nodes:
                raise EvidenceError(f"JSON exceeds {MAX_JSON_NODES} nodes")
            nodes += len(item)
            stack.extend((child, f"{location}[{index}]", depth + 1) for index, child in enumerate(item))
        elif isinstance(item, dict):
            if len(item) > MAX_JSON_NODES - nodes:
                raise EvidenceError(f"JSON exceeds {MAX_JSON_NODES} nodes")
            nodes += len(item)
            stack.extend((child, f"{location}.{key}", depth + 1) for key, child in item.items())


def _parse_json(raw: bytes, name: str) -> dict[str, Any]:
    try:
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_strict_object, parse_constant=_bad_constant
        )
        _check_finite(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, EvidenceError, RecursionError) as error:
        raise EvidenceError(f"{name}: malformed JSON: {error}") from error
    if not isinstance(payload, dict):
        raise EvidenceError(f"{name}: top level must be a JSON object")
    return payload


def _is_int(value: Any) -> bool:
    return type(value) is int


def _is_bool(value: Any) -> bool:
    return type(value) is bool


def _string(value: Any, *, max_chars: int = MAX_TEXT_CHARS, nonempty: bool = False) -> bool:
    return isinstance(value, str) and len(value) <= max_chars and (not nonempty or bool(value))


def _digest(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX64.fullmatch(value))


def _safe_single_file(value: Any) -> bool:
    return isinstance(value, str) and bool(ARTIFACT_NAME.fullmatch(value)) and "/" not in value and "\\" not in value


def _safe_repo_path(value: Any, *, dot_ok: bool = False) -> bool:
    if not _string(value, max_chars=MAX_PATH_CHARS, nonempty=True):
        return False
    if value == ".":
        return dot_ok
    if value.startswith(("/", "\\")) or "\\" in value or "\x00" in value:
        return False
    parts = value.split("/")
    return all(part not in {"", ".", ".."} and not any(ord(c) < 32 for c in part) for part in parts)


def _commands(value: Any, prefix: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or len(value) > 32:
        errors.append(f"{prefix} must be an array of at most 32 commands")
        return []
    answer: list[str] = []
    seen: set[str] = set()
    for index, command in enumerate(value):
        if not _string(command, max_chars=MAX_COMMAND_CHARS, nonempty=True) or command != command.strip():
            errors.append(f"{prefix}[{index}] is not bounded, non-empty trimmed text")
            continue
        if command in seen:
            errors.append(f"{prefix}[{index}] duplicates an earlier command")
        seen.add(command)
        answer.append(command)
    return answer


def _bounded_strings(value: Any, prefix: str, errors: list[str], maximum: int, *, paths: bool = False) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        errors.append(f"{prefix} must be an array of at most {maximum} values")
        return []
    answer: list[str] = []
    for index, item in enumerate(value):
        valid = _safe_repo_path(item) if paths else _string(item, nonempty=True)
        if not valid:
            errors.append(f"{prefix}[{index}] has an invalid {'relative path' if paths else 'text value'}")
        elif isinstance(item, str):
            answer.append(item)
    return answer


class Checker:
    def __init__(self, evidence_dir: str | Path) -> None:
        self.input = Path(evidence_dir).expanduser()
        self.root: Path | None = None
        self.integrity: list[str] = []
        self.trajectory: list[str] = []
        self.completion: list[str] = []
        self.gates: list[dict[str, Any]] = []
        self.manifest: dict[str, Any] = {}
        self.artifacts: dict[str, tuple[dict[str, Any] | None, bytes]] = {}
        self.task: dict[str, Any] = {}
        self.task_checks: list[str] = []
        self.task_plan_only = False
        self.phase_effects: list[dict[str, Any]] = []
        self.verification_summary: dict[str, Any] | None = None
        self.delivery_complete = False

    def gate(self, name: str, layer: str, passed: bool, reasons: list[str]) -> None:
        self.gates.append({"name": name, "layer": layer, "passed": passed, "reasons": reasons})

    def _root(self) -> bool:
        if self.input.is_symlink():
            self.integrity.append("evidence directory is a symlink")
            self.gate("evidence_root", "evidence_integrity", False, [self.integrity[-1]])
            return False
        try:
            root = self.input.resolve(strict=True)
        except OSError as error:
            self.integrity.append(f"cannot resolve evidence directory: {error}")
            self.gate("evidence_root", "evidence_integrity", False, [self.integrity[-1]])
            return False
        if not root.is_dir():
            self.integrity.append("evidence path is not a directory")
            self.gate("evidence_root", "evidence_integrity", False, [self.integrity[-1]])
            return False
        self.root = root
        unsafe: list[str] = []
        try:
            entries = 0
            for parent, directories, files in os.walk(root, followlinks=False):
                for name in [*directories, *files]:
                    entries += 1
                    if entries > MAX_EVIDENCE_ENTRIES:
                        unsafe.append(f"evidence tree exceeds {MAX_EVIDENCE_ENTRIES} entries")
                        directories[:] = []
                        break
                    entry = Path(parent) / name
                    mode = entry.lstat().st_mode
                    relative = entry.relative_to(root).as_posix()
                    if stat.S_ISLNK(mode):
                        unsafe.append(f"{relative}: symlink")
                    elif not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                        unsafe.append(f"{relative}: special file")
                    elif stat.S_ISREG(mode) and entry.stat().st_size > MAX_OTHER_BYTES:
                        unsafe.append(f"{relative}: exceeds {MAX_OTHER_BYTES} bytes")
        except OSError as error:
            unsafe.append(f"cannot safely enumerate evidence: {error}")
        self.integrity.extend(unsafe)
        self.gate("evidence_root", "evidence_integrity", not unsafe, unsafe)
        return True

    def _read_raw(self, name: str, maximum: int) -> bytes | None:
        assert self.root is not None
        if not _safe_single_file(name):
            self.integrity.append(f"unsafe artifact name {name!r}")
            return None
        path = self.root / name
        descriptor: int | None = None
        try:
            nofollow = getattr(os, "O_NOFOLLOW", None)
            if nofollow is None:
                raise EvidenceError("platform does not support no-follow file opens")
            descriptor = os.open(
                path,
                os.O_RDONLY | os.O_NONBLOCK | nofollow | getattr(os, "O_CLOEXEC", 0),
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise EvidenceError("not a regular file")
            if metadata.st_size > maximum:
                raise EvidenceError(f"exceeds {maximum} bytes")
            chunks: list[bytes] = []
            total = 0
            # The fstat size is advisory only: a writer can grow a regular file
            # after open. Read no more than the cap plus one byte from this FD.
            while True:
                chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise EvidenceError(f"exceeds {maximum} bytes")
                chunks.append(chunk)
            return b"".join(chunks)
        except (OSError, EvidenceError) as error:
            self.integrity.append(f"{name}: missing, special, unreadable, or oversized ({error})")
            return None
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _load_named_json(self, name: str) -> tuple[dict[str, Any] | None, bytes]:
        raw = self._read_raw(name, MAX_JSON_BYTES)
        if raw is None:
            return None, b""
        try:
            return _parse_json(raw, name), raw
        except EvidenceError as error:
            self.integrity.append(str(error))
            return None, raw

    def _manifest_field(self, key: str, expected: str, *, required: bool) -> bool:
        value = self.manifest.get(key)
        digest = self.manifest.get(f"{key}_sha256")
        issue: list[str] = []
        if value is None and digest is None and not required:
            return False
        if value != expected or not _safe_single_file(value):
            issue.append(f"manifest {key!r} must be the single file {expected!r}")
        if not _digest(digest):
            issue.append(f"manifest {key}_sha256 must be a lowercase SHA-256 digest")
        if issue:
            self.integrity.extend(issue)
            return False
        return True

    def _artifact_json(self, key: str, expected: str, *, required: bool) -> dict[str, Any] | None:
        present = self._manifest_field(key, expected, required=required)
        if not present:
            return None
        payload, raw = self._load_named_json(expected)
        if payload is None:
            return None
        expected_digest = self.manifest.get(f"{key}_sha256")
        if hashlib.sha256(raw).hexdigest() != expected_digest:
            self.integrity.append(f"{key} digest does not match the manifest")
        self.artifacts[key] = (payload, raw)
        return payload

    def _artifact_raw(self, key: str, expected: str, *, required: bool, maximum: int) -> bytes | None:
        present = self._manifest_field(key, expected, required=required)
        if not present:
            return None
        raw = self._read_raw(expected, maximum)
        if raw is None:
            return None
        if hashlib.sha256(raw).hexdigest() != self.manifest.get(f"{key}_sha256"):
            self.integrity.append(f"{key} digest does not match the manifest")
        self.artifacts[key] = (None, raw)
        return raw

    def _validate_manifest(self) -> None:
        payload, _raw = self._load_named_json("manifest.json")
        if payload is None:
            self.gate("manifest_contract", "evidence_integrity", False, ["manifest.json cannot be parsed safely"])
            return
        self.manifest = payload
        errors: list[str] = []
        if payload.get("schema") != "northstar.code-evidence.v1":
            errors.append("unsupported manifest schema")
        if not _string(payload.get("run_id"), max_chars=256, nonempty=True):
            errors.append("manifest run_id is invalid")
        if not isinstance(payload.get("start_commit"), str) or not COMMIT.fullmatch(payload["start_commit"]):
            errors.append("manifest start_commit is not a full lowercase Git object id")
        if not _safe_repo_path(payload.get("source_relative"), dot_ok=True):
            errors.append("manifest source_relative is not a safe relative path")
        if not isinstance(payload.get("source_status"), list) or len(payload["source_status"]) > MAX_SNAPSHOT_FILES:
            errors.append("manifest source_status is invalid")
        elif any(not _string(item, max_chars=MAX_PATH_CHARS) for item in payload["source_status"]):
            errors.append("manifest source_status contains invalid text")
        for key in ("repository", "source_branch"):
            if payload.get(key) is not None and not _string(payload.get(key), max_chars=MAX_PATH_CHARS):
                errors.append(f"manifest {key} is neither null nor bounded text")
        if payload.get("worktree") is not None and not _string(payload.get("worktree"), max_chars=MAX_PATH_CHARS, nonempty=True):
            errors.append("manifest worktree is neither null nor bounded text")
        status = payload.get("status")
        if not isinstance(status, str) or status not in TERMINALS:
            errors.append("manifest status is not a terminal code outcome")
        elif not _is_int(payload.get("exit_code")) or payload["exit_code"] != EXIT_CODES[status]:
            errors.append("manifest exit_code does not match its terminal status")
        if "worktree_removed" in payload and not _is_bool(payload["worktree_removed"]):
            errors.append("manifest worktree_removed must be boolean")
        self.integrity.extend(errors)
        self.gate("manifest_contract", "evidence_integrity", not errors, errors)

    def _validate_task(self, task: dict[str, Any] | None) -> None:
        errors: list[str] = []
        if task is None:
            self.gate("task_contract", "evidence_integrity", False, ["task artifact unavailable"])
            return
        self.task = task
        if not _string(task.get("goal"), max_chars=MAX_TEXT_CHARS, nonempty=True) or task.get("goal") != str(task.get("goal", "")).strip():
            errors.append("task goal must be bounded, non-empty trimmed text")
        self.task_checks = _commands(task.get("checks"), "task checks", errors)
        if not _is_bool(task.get("plan_only")):
            errors.append("task plan_only must be boolean")
        else:
            self.task_plan_only = task["plan_only"]
        targets = task.get("network_targets")
        if not isinstance(targets, list) or len(targets) > 128 or any(not _string(item, max_chars=253, nonempty=True) for item in targets):
            errors.append("task network_targets must be a bounded array of host text")
        self.integrity.extend(errors)
        self.gate("task_contract", "evidence_integrity", not errors, errors)

    def _validate_snapshot(self, snapshot: dict[str, Any] | None) -> None:
        errors: list[str] = []
        if snapshot is None:
            self.gate("snapshot_contract", "evidence_integrity", False, ["repository snapshot unavailable"])
            return
        if snapshot.get("schema") != "northstar.repository-snapshot.v1":
            errors.append("unsupported repository snapshot schema")
        if snapshot.get("start_commit") != self.manifest.get("start_commit"):
            errors.append("repository snapshot start_commit does not match manifest")
        if snapshot.get("source_relative") != self.manifest.get("source_relative") or not _safe_repo_path(snapshot.get("source_relative"), dot_ok=True):
            errors.append("repository snapshot source_relative does not match manifest")
        if not _is_bool(snapshot.get("source_dirty")):
            errors.append("repository snapshot source_dirty must be boolean")
        if snapshot.get("source_status") != self.manifest.get("source_status"):
            errors.append("repository snapshot source_status does not match manifest")
        count = snapshot.get("file_count")
        files = _bounded_strings(snapshot.get("files"), "snapshot files", errors, MAX_SNAPSHOT_FILES, paths=True)
        if not _is_int(count) or count < 0:
            errors.append("repository snapshot file_count is invalid")
        truncated = snapshot.get("files_truncated")
        if not _is_bool(truncated):
            errors.append("repository snapshot files_truncated must be boolean")
        elif truncated and len(files) != MAX_SNAPSHOT_FILES:
            errors.append("truncated repository snapshot must retain exactly the file cap")
        elif not truncated and _is_int(count) and count != len(files):
            errors.append("untruncated repository snapshot file_count does not match files")
        for key, maximum in (("file_types", 64), ("top_level", 128)):
            value = snapshot.get(key)
            if not isinstance(value, dict) or len(value) > maximum or any(not _string(k, nonempty=True) or not _is_int(v) or v < 0 for k, v in value.items()):
                errors.append(f"repository snapshot {key} is invalid")
        _bounded_strings(snapshot.get("landmarks"), "snapshot landmarks", errors, 64, paths=True)
        self.integrity.extend(errors)
        self.gate("snapshot_contract", "evidence_integrity", not errors, errors)

    def _validate_plan(self, plan: Any, errors: list[str]) -> None:
        if not isinstance(plan, dict):
            errors.append("phase plan is missing or not an object")
            return
        if not _string(plan.get("summary"), max_chars=MAX_TEXT_CHARS, nonempty=True):
            errors.append("phase plan summary is invalid")
        _bounded_strings(plan.get("files"), "phase plan files", errors, 64, paths=True)
        _bounded_strings(plan.get("steps"), "phase plan steps", errors, 32)
        _bounded_strings(plan.get("risks"), "phase plan risks", errors, 32)
        indices = plan.get("check_indices")
        if not isinstance(indices, list) or len(indices) > 32:
            errors.append("phase plan check_indices is invalid")
        else:
            seen: set[int] = set()
            for index, value in enumerate(indices):
                if not _is_int(value) or value < 0 or value >= len(self.task_checks):
                    errors.append(f"phase plan check_indices[{index}] is not a declared check")
                elif value in seen:
                    errors.append(f"phase plan check_indices[{index}] duplicates an earlier index")
                else:
                    seen.add(value)

    def _validate_phases(self, phases: dict[str, Any] | None) -> None:
        errors: list[str] = []
        if phases is None:
            self.gate("phase_trajectory", "trajectory", False, ["phase journal unavailable"])
            return
        if phases.get("schema") != "northstar.code-phases.v1":
            errors.append("unsupported phase journal schema")
        if phases.get("run_id") != self.manifest.get("run_id"):
            errors.append("phase journal run_id does not match manifest")
        if phases.get("plan_only") is not self.task_plan_only:
            errors.append("phase journal plan_only does not match task")
        if phases.get("effect_journal_version") != 1:
            errors.append("phase journal lacks effect_journal_version 1")
        transitions = phases.get("transitions")
        state = phases.get("state")
        outcome = phases.get("outcome")
        previous = "created"
        previous_time = -1
        executing_at: int | None = None
        executing_until: int | None = None
        verifying_at: int | None = None
        terminal_at: int | None = None
        terminal_seen = False
        if not isinstance(transitions, list):
            errors.append("phase transitions must be an array")
            transitions = []
        for index, transition in enumerate(transitions):
            if not isinstance(transition, dict):
                errors.append(f"transition {index + 1} is not an object")
                continue
            target = transition.get("to")
            timestamp = transition.get("timestamp_unix_ms")
            if transition.get("sequence") != index + 1 or transition.get("from") != previous:
                errors.append(f"transition {index + 1} breaks the phase sequence")
            if not _is_int(timestamp) or timestamp < 0 or timestamp < previous_time:
                errors.append(f"transition {index + 1} has an invalid timestamp")
            else:
                previous_time = timestamp
            if not _string(transition.get("reason"), max_chars=MAX_TEXT_CHARS, nonempty=True) or not isinstance(transition.get("data"), dict):
                errors.append(f"transition {index + 1} has invalid reason or data")
            allowed = FORWARD.get(previous, set())
            if not isinstance(target, str) or not (target in allowed or (previous in ACTIVE and target in TERMINALS)):
                errors.append(f"transition {index + 1} is not allowed ({previous!r} -> {target!r})")
            if isinstance(target, str) and target in TERMINALS:
                if terminal_seen:
                    errors.append("phase journal contains more than one terminal transition")
                terminal_seen = True
            if isinstance(target, str) and _is_int(timestamp):
                if target == "executing":
                    executing_at = timestamp
                elif target == "verifying":
                    verifying_at = timestamp
                    if previous == "executing":
                        executing_until = timestamp
                elif target in TERMINALS:
                    terminal_at = timestamp
                    if previous == "executing":
                        executing_until = timestamp
            previous = target if isinstance(target, str) else ""
        if state != previous:
            errors.append("phase state does not match its transition chain")
        if isinstance(state, str) and state in TERMINALS:
            if outcome != state or not terminal_seen:
                errors.append("terminal phase state and outcome are inconsistent")
        elif not isinstance(state, str) or state not in ACTIVE or outcome is not None:
            errors.append("active phase state or outcome is inconsistent")
        if self.manifest.get("phase") != state or self.manifest.get("phase_outcome") != outcome:
            errors.append("manifest phase fields do not match phase journal")
        if self.manifest.get("status") != outcome:
            errors.append("manifest status does not match phase outcome")
        needs_plan = any(isinstance(item, dict) and item.get("to") == "planned" for item in transitions)
        if needs_plan:
            self._validate_plan(phases.get("plan"), errors)
        elif phases.get("plan") is not None:
            errors.append("phase journal has a plan without a planned transition")
        elif isinstance(state, str) and state in {"planned", "executing", "verifying"}:
            errors.append("terminal or post-understanding phase has no SubmitPlan receipt")

        raw_effects = phases.get("effects")
        self.phase_effects = []
        if not isinstance(raw_effects, list):
            errors.append("phase effects must be an array")
            raw_effects = []
        if not needs_plan and raw_effects:
            errors.append("effects exist without a prior SubmitPlan transition")
        seen_ids: set[str] = set()
        for index, effect in enumerate(raw_effects):
            if not isinstance(effect, dict):
                errors.append(f"effect {index + 1} is not an object")
                continue
            effect_id = effect.get("effect_id")
            status = effect.get("status")
            started, finished = effect.get("started_unix_ms"), effect.get("finished_unix_ms")
            if not isinstance(effect_id, str) or effect_id != f"effect-{index + 1}" or effect_id in seen_ids:
                errors.append(f"effect {index + 1} has an invalid or duplicate id")
            if isinstance(effect_id, str):
                seen_ids.add(effect_id)
            if effect.get("sequence") != index + 1:
                errors.append(f"effect {index + 1} has an invalid sequence")
            if not _string(effect.get("tool"), max_chars=256, nonempty=True) or not _string(effect.get("call_id"), max_chars=256):
                errors.append(f"effect {index + 1} has an invalid tool or call_id")
            if not isinstance(status, str) or status not in EFFECT_STATUSES:
                errors.append(f"effect {index + 1} has an invalid status")
            if not _is_int(started) or started < 0:
                errors.append(f"effect {index + 1} has an invalid start timestamp")
            if status == "in_flight":
                if finished is not None:
                    errors.append(f"effect {index + 1} has completion data while in flight")
            elif not _is_int(finished) or (isinstance(started, int) and finished < started):
                errors.append(f"effect {index + 1} has an invalid completion timestamp")
            if not _string(effect.get("error_class"), max_chars=200):
                errors.append(f"effect {index + 1} has an invalid error_class")
            phase = effect.get("phase")
            if terminal_at is not None:
                if _is_int(started) and started > terminal_at:
                    errors.append(f"effect {index + 1} begins after the terminal transition")
                if _is_int(finished) and finished > terminal_at:
                    errors.append(f"effect {index + 1} completes after the terminal transition")
            if effect.get("tool") == "HostCheck":
                if (
                    phase != "verifying"
                    or verifying_at is None
                    or not _is_int(started)
                    or started < verifying_at
                    or (terminal_at is not None and started > terminal_at)
                ):
                    errors.append(f"HostCheck effect {index + 1} is not in the verifying phase interval")
                if _is_int(finished) and terminal_at is not None and finished > terminal_at:
                    errors.append(f"HostCheck effect {index + 1} completion is outside the verifying phase interval")
            elif (
                phase != "executing"
                or executing_at is None
                or not _is_int(started)
                or started < executing_at
                or (executing_until is not None and started > executing_until)
            ):
                errors.append(f"effect {index + 1} is not after SubmitPlan in the executing phase interval")
            elif _is_int(finished) and executing_until is not None and finished > executing_until:
                errors.append(f"effect {index + 1} completion is outside the executing phase interval")
            self.phase_effects.append(effect)
        if self.manifest.get("status") == "success":
            unresolved = [
                str(index + 1)
                for index, effect in enumerate(self.phase_effects)
                if isinstance(effect.get("status"), str)
                and effect["status"] in {"in_flight", "unknown", "failed"}
            ]
            if unresolved:
                errors.append(
                    "success terminal contains in_flight, unknown, or failed effects: "
                    + ", ".join(unresolved)
                )
        self.trajectory.extend(errors)
        self.gate("phase_trajectory", "trajectory", not errors, errors)

    def _validate_verification(self, verification: dict[str, Any] | None) -> None:
        errors: list[str] = []
        if verification is None:
            self.gate("verification_receipts", "trajectory", False, ["verification artifact unavailable"])
            return
        if verification.get("schema") != "northstar.code-verification.v1":
            errors.append("unsupported verification schema")
        summaries = verification.get("summaries")
        if not isinstance(summaries, list) or len(summaries) > 1:
            errors.append("verification must contain at most one independent summary")
            summaries = []
        elif not summaries and self.task_checks:
            errors.append("declared task checks have no independent verification summary")
        summary = summaries[0] if summaries else None
        if isinstance(summary, dict):
            self.verification_summary = summary
            declared, ran = summary.get("declared"), summary.get("ran")
            passed, failed, skipped = summary.get("passed"), summary.get("failed"), summary.get("skipped")
            if any(not _is_int(value) or value < 0 for value in (declared, ran, passed, failed, skipped)):
                errors.append("verification summary counts must be non-negative integers")
            elif (declared != len(self.task_checks) or ran > declared or passed + failed != ran or skipped != declared - ran):
                errors.append("verification summary counts do not match declared task checks")
            if summary.get("network") != "denied":
                errors.append("verification summary does not record network denied")
            results = summary.get("results")
            if not isinstance(results, list) or (_is_int(ran) and len(results) != ran):
                errors.append("verification results do not match ran count")
                results = []
            result_ok_values: list[bool] = []
            for index, result in enumerate(results):
                if not isinstance(result, dict):
                    errors.append(f"verification result {index} is not an object")
                    continue
                if result.get("index") != index or result.get("command") != (self.task_checks[index] if index < len(self.task_checks) else None):
                    errors.append(f"verification result {index} does not bind its declared command")
                exit_code = result.get("exit_code")
                if exit_code is not None and (not _is_int(exit_code) or exit_code < 0):
                    errors.append(f"verification result {index} has invalid exit_code")
                for key in ("ok", "timed_out", "truncated"):
                    if not _is_bool(result.get(key)):
                        errors.append(f"verification result {index} {key} must be boolean")
                if not _is_int(result.get("duration_ms")) or result["duration_ms"] < 0:
                    errors.append(f"verification result {index} duration_ms is invalid")
                if not _digest(result.get("output_sha256")) or not _string(result.get("output_excerpt"), max_chars=8192):
                    errors.append(f"verification result {index} output receipt is invalid")
                if result.get("error") is not None and not _string(result.get("error"), max_chars=MAX_TEXT_CHARS):
                    errors.append(f"verification result {index} error is invalid")
                expected_ok = result.get("exit_code") == 0 and result.get("timed_out") is False
                if _is_bool(result.get("ok")) and result["ok"] != expected_ok:
                    errors.append(f"verification result {index} ok conflicts with its exit code or timeout")
                if _is_bool(result.get("ok")):
                    result_ok_values.append(result["ok"])
            expected_summary_ok = bool(declared == ran and failed == 0) if all(_is_int(v) for v in (declared, ran, failed)) else False
            if not _is_bool(summary.get("ok")) or summary.get("ok") != expected_summary_ok:
                errors.append("verification summary ok is inconsistent with counts")
            if _is_int(passed) and _is_int(failed) and (passed != sum(result_ok_values) or failed != len(result_ok_values) - sum(result_ok_values)):
                errors.append("verification summary counts do not match result receipts")
            host_checks = [effect for effect in self.phase_effects if effect.get("tool") == "HostCheck"]
            if len(host_checks) != len(results):
                errors.append("HostCheck effects do not correspond one-for-one with verification receipts")
            else:
                for index, effect in enumerate(host_checks):
                    if effect.get("call_id") != f"verification-{index}" or effect.get("status") != "completed":
                        errors.append(f"HostCheck effect {index} lacks a completed matching receipt")
            if self.manifest.get("verification_ok") is not summary.get("ok"):
                errors.append("manifest verification_ok does not match the independent summary")
        elif not self.task_checks:
            host_checks = [effect for effect in self.phase_effects if effect.get("tool") == "HostCheck"]
            if host_checks:
                errors.append("empty verification plan has HostCheck effects")
            if self.manifest.get("verification_ok") is not False:
                errors.append("empty verification plan must record verification_ok false")
        else:
            errors.append("verification summary is not an object")
        self.trajectory.extend(errors)
        self.gate("verification_receipts", "trajectory", not errors, errors)

    def _validate_delivery(self, patch: bytes | None, replay: dict[str, Any] | None, audit: dict[str, Any] | None, seal: dict[str, Any] | None, required: bool) -> None:
        errors: list[str] = []
        if patch is None or replay is None or audit is None or seal is None:
            if required:
                errors.append("successful delivery is missing patch, replay, audit, or seal evidence")
            self.completion.extend(errors)
            self.gate("delivery_chain", "verified_completion", not errors and not required, errors or (["delivery receipts were not captured for this non-success terminal"] if not required else []))
            return
        patch_sha = hashlib.sha256(patch).hexdigest()
        if self.manifest.get("patch_bytes") != len(patch):
            errors.append("manifest patch_bytes does not match changes.patch")
        if self.manifest.get("patch_sha256") != patch_sha:
            errors.append("manifest patch_sha256 does not match changes.patch")
        if replay.get("schema") != "northstar.patch-replay.v1":
            errors.append("unsupported patch replay schema")
        if replay.get("start_commit") != self.manifest.get("start_commit") or replay.get("patch_bytes") != len(patch) or replay.get("patch_sha256") != patch_sha:
            errors.append("patch replay does not bind the manifest commit and patch")
        if not _is_bool(replay.get("empty")) or replay["empty"] != (not bool(patch)):
            errors.append("patch replay empty marker conflicts with patch")
        for key in ("read_tree_exit_code", "apply_exit_code"):
            if not _is_int(replay.get(key)):
                errors.append(f"patch replay {key} is invalid")
        replay_ok = replay.get("read_tree_exit_code") == 0 and replay.get("apply_exit_code") == 0
        if not _is_bool(replay.get("ok")) or replay["ok"] != replay_ok:
            errors.append("patch replay ok is inconsistent with exit codes")
        if not _string(replay.get("diagnostic"), max_chars=4000):
            errors.append("patch replay diagnostic is invalid")
        if audit.get("schema") != "northstar.patch-audit.v1":
            errors.append("unsupported patch audit schema")
        if audit.get("patch_bytes") != len(patch) or audit.get("patch_sha256") != patch_sha:
            errors.append("patch audit does not bind changes.patch")
        if not _is_int(audit.get("changed_files")) or audit["changed_files"] < 0 or audit["changed_files"] > MAX_DELIVERY_FILES:
            errors.append("patch audit changed_files is invalid or exceeds delivery cap")
        findings = audit.get("findings")
        if not isinstance(findings, list) or len(findings) > 256:
            errors.append("patch audit findings are invalid")
            findings = []
        else:
            for index, finding in enumerate(findings):
                if not isinstance(finding, dict) or any(not _string(finding.get(key), max_chars=MAX_PATH_CHARS, nonempty=True) for key in ("code", "path", "detail")):
                    errors.append(f"patch audit finding {index} is invalid")
        if not _is_bool(audit.get("ok")) or audit.get("ok") != (not findings):
            errors.append("patch audit ok is inconsistent with findings")
        if seal.get("schema") != "northstar.delivery-seal.v1":
            errors.append("unsupported delivery seal schema")
        if seal.get("start_commit") != self.manifest.get("start_commit"):
            errors.append("delivery seal start_commit does not match manifest")
        if seal.get("precheck_patch_sha256") != patch_sha or seal.get("patch_sha256") != patch_sha:
            errors.append("delivery seal patch digests do not match final patch")
        unchanged = seal.get("unchanged_during_verification")
        if not _is_bool(unchanged) or unchanged != (seal.get("precheck_patch_sha256") == seal.get("patch_sha256")):
            errors.append("delivery seal unchanged marker is inconsistent")
        if seal.get("patch_audit_ok") != audit.get("ok") or not _is_bool(seal.get("patch_audit_ok")):
            errors.append("delivery seal audit marker does not match patch audit")
        expected_seal_ok = bool(unchanged) and audit.get("ok") is True
        if not _is_bool(seal.get("ok")) or seal.get("ok") != expected_seal_ok:
            errors.append("delivery seal ok is inconsistent")
        for key, actual in (("patch_replay_ok", replay.get("ok")), ("patch_audit_ok", audit.get("ok")), ("delivery_seal_ok", seal.get("ok"))):
            if self.manifest.get(key) is not actual:
                errors.append(f"manifest {key} does not match its receipt")
        self.completion.extend(errors)
        self.delivery_complete = not errors
        self.gate("delivery_chain", "verified_completion", not errors, errors)

    def run(self) -> dict[str, Any]:
        if not self._root():
            return self.report()
        self._validate_manifest()
        if not self.manifest:
            return self.report()
        status = self.manifest.get("status")
        successish = isinstance(status, str) and status in {"success", "success_unverified"}
        phases = self._artifact_json("phases", "phases.json", required=True)
        task = self._artifact_json("task", "task.json", required=True)
        verification = self._artifact_json("verification", "verification.json", required=True)
        snapshot = self._artifact_json("repository_snapshot", "repository-snapshot.json", required=True)
        self._validate_task(task)
        self._validate_snapshot(snapshot)
        self._validate_phases(phases)
        self._validate_verification(verification)
        patch = self._artifact_raw("patch", "changes.patch", required=successish and not self.task_plan_only, maximum=MAX_PATCH_BYTES)
        replay = self._artifact_json("patch_replay", "patch-replay.json", required=successish and not self.task_plan_only)
        audit = self._artifact_json("patch_audit", "patch-audit.json", required=successish and not self.task_plan_only)
        seal = self._artifact_json("delivery_seal", "delivery-seal.json", required=successish and not self.task_plan_only)
        if self.task_plan_only:
            self.completion.append("plan-only task does not establish a delivered, verified code change")
            self.gate("plan_only_delivery", "verified_completion", False, [self.completion[-1]])
        self._validate_delivery(patch, replay, audit, seal, required=successish and not self.task_plan_only)
        return self.report()

    def report(self) -> dict[str, Any]:
        status = self.manifest.get("status") if self.manifest else None
        declared = self.verification_summary.get("declared") if isinstance(self.verification_summary, dict) else None
        verification_ok = bool(
            isinstance(self.verification_summary, dict)
            and self.verification_summary.get("ok") is True
            and _is_int(declared)
            and declared > 0
        )
        delivery_ok = self.delivery_complete and not self.task_plan_only
        verified = not self.integrity and not self.trajectory and not self.completion and status == "success" and verification_ok and delivery_ok
        completion_reasons = list(self.completion)
        if status != "success":
            completion_reasons.append(f"terminal status is {status!r}, not 'success'")
        if status == "success_unverified":
            completion_reasons.append("success_unverified is never a verified success")
        if not verification_ok:
            completion_reasons.append("no successful receipt for every declared host check")
        if not delivery_ok:
            completion_reasons.append("patch replay/audit/seal chain is incomplete or inconsistent")
        # The named completion gate should show its actual final determination too.
        self.gate("verified_success", "verified_completion", verified, list(dict.fromkeys(completion_reasons)))
        integrity_ok = not self.integrity
        trajectory_ok = not self.trajectory
        complete = integrity_ok and trajectory_ok and self.delivery_complete
        if verified:
            classification = "verified_success"
        elif integrity_ok and trajectory_ok and self.task_plan_only and isinstance(status, str) and status in TERMINALS:
            classification = "valid_plan_only_terminal"
        elif integrity_ok and trajectory_ok and status == "success_unverified" and self.delivery_complete:
            classification = "complete_unverified_success"
        elif integrity_ok and trajectory_ok and isinstance(status, str) and status in TERMINALS and status != "success":
            classification = "valid_non_success_terminal"
        else:
            classification = "invalid_or_incomplete_evidence"
        return {
            "schema": SCHEMA,
            "evidence_dir": str(self.root) if self.root is not None else str(self.input),
            "read_only": True,
            "classification": classification,
            "terminal_status": status,
            "plan_only": self.task_plan_only,
            "complete_evidence": complete,
            "verified_success": verified,
            "layers": {
                "evidence_integrity": {"passed": integrity_ok, "reasons": self.integrity},
                "trajectory": {"passed": trajectory_ok, "reasons": self.trajectory},
                "verified_completion": {"passed": verified, "reasons": list(dict.fromkeys(completion_reasons))},
            },
            "hard_gates": self.gates,
            "limitations": {
                "hashes": "Hashes establish consistency with this local manifest; they are not signatures and do not authenticate a malicious host or evidence producer.",
                "network_isolation": "unknown: these artifacts do not contain sufficient host-attestation data to verify actual network isolation.",
                "scope": "A local verified_success means only that the supplied declared-host-check and delivery chain is internally consistent. It is not hidden benchmark acceptance, real-model success-rate evidence, or a release-eligibility decision.",
            },
        }


def inspect(evidence_dir: str | Path) -> dict[str, Any]:
    """Inspect evidence without importing the runtime or writing any file."""
    return Checker(evidence_dir).run()


def _text(report: dict[str, Any]) -> str:
    lines = [
        f"classification={report['classification']} status={report['terminal_status']!r} verified_success={report['verified_success']}",
        f"evidence_dir={report['evidence_dir']} read_only=true",
    ]
    for gate in report["hard_gates"]:
        status = "PASS" if gate["passed"] else "FAIL"
        reason = "; ".join(gate["reasons"]) or "ok"
        lines.append(f"{status} [{gate['layer']}] {gate['name']}: {reason}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only hard gates for Northstar code-run evidence")
    parser.add_argument("evidence_dir", help="one Northstar code-run evidence directory")
    parser.add_argument("--json", action="store_true", help="emit one machine-readable JSON result")
    parser.add_argument("--require-verified", action="store_true", help="fail unless the result is a verified success")
    args = parser.parse_args(argv)
    report = inspect(args.evidence_dir)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True) if args.json else _text(report))
    integrity_ok = report["layers"]["evidence_integrity"]["passed"]
    trajectory_ok = report["layers"]["trajectory"]["passed"]
    terminal = report["terminal_status"]
    # A claimed success without the hard proof is a failure even without the optional policy.
    failed = (
        not integrity_ok
        or not trajectory_ok
        or terminal is None
        or (terminal == "success" and not report["plan_only"] and not report["verified_success"])
    )
    if args.require_verified and not report["verified_success"]:
        failed = True
    return 0 if not failed else 2


if __name__ == "__main__":
    raise SystemExit(main())
