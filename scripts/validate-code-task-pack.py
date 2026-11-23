#!/usr/bin/env python3
"""Validate and project the frozen Northstar offline coding task manifest."""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "benchmarks" / "code-tasks" / "v1" / "manifest.json"
SCHEMA = "northstar.code-task-pack.v1"
EXPECTED_LANGUAGES = {"python": 12, "typescript": 12}
EXPECTED_CATEGORIES = {
    "bugfix": 8,
    "feature": 6,
    "refactor": 4,
    "build_test": 3,
    "security": 3,
}
AGENT_FIELDS = ("id", "title", "language", "category", "prompt", "acceptance")
PUBLIC_FIELDS = (*AGENT_FIELDS, "public_checks")
TASK_ID = re.compile(r"^(py|ts)-(bug|feat|refactor|build|sec)-\d{3}-[a-z0-9-]+$")


def load_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("manifest root must be an object")
    return payload


def fingerprint(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def tree_fingerprint(root: Path) -> str:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"tree does not exist: {root}")
    rows: list[bytes] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if path.is_symlink():
            raise ValueError(f"tree contains a symlink: {relative.as_posix()}")
        if any(part in {".git", "__pycache__", "node_modules"} for part in relative.parts):
            continue
        if not path.is_file() or path.suffix == ".pyc":
            continue
        content = path.read_bytes()
        rows.append(
            relative.as_posix().encode("utf-8")
            + b"\0"
            + str(len(content)).encode("ascii")
            + b"\0"
            + hashlib.sha256(content).hexdigest().encode("ascii")
            + b"\n"
        )
    return hashlib.sha256(b"".join(rows)).hexdigest()


def _safe_pack_path(pack_root: Path, value: Any, label: str, errors: list[str]) -> Path | None:
    if not isinstance(value, str) or not value:
        errors.append(f"{label} must be a non-empty relative path")
        return None
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        errors.append(f"{label} must stay inside the pack")
        return None
    target = pack_root / path
    try:
        target.resolve().relative_to(pack_root.resolve())
    except ValueError:
        errors.append(f"{label} resolves outside the pack")
        return None
    return target


def validate(payload: dict[str, Any], *, pack_root: Path | None = None) -> list[str]:
    errors: list[str] = []
    pack_root = (pack_root or DEFAULT_MANIFEST.parent).resolve()
    if payload.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA!r}")
    tasks = payload.get("tasks")
    if not isinstance(tasks, list):
        return errors + ["tasks must be an array"]
    if len(tasks) != 24:
        errors.append(f"task count must be 24, got {len(tasks)}")
    ids: list[str] = []
    languages: collections.Counter[str] = collections.Counter()
    categories: collections.Counter[str] = collections.Counter()
    statuses: collections.Counter[str] = collections.Counter()
    for index, task in enumerate(tasks):
        label = f"tasks[{index}]"
        if not isinstance(task, dict):
            errors.append(f"{label} must be an object")
            continue
        missing = [field for field in (*AGENT_FIELDS, "fixture_status", "evaluator_suite") if field not in task]
        if missing:
            errors.append(f"{label} missing fields: {', '.join(missing)}")
            continue
        task_id = task["id"]
        if not isinstance(task_id, str) or not TASK_ID.fullmatch(task_id):
            errors.append(f"{label}.id is malformed")
        else:
            ids.append(task_id)
        language = task["language"]
        category = task["category"]
        if not isinstance(language, str) or language not in EXPECTED_LANGUAGES:
            errors.append(f"{label}.language is invalid")
        else:
            languages[language] += 1
        if not isinstance(category, str) or category not in EXPECTED_CATEGORIES:
            errors.append(f"{label}.category is invalid")
        else:
            categories[category] += 1
        status = task["fixture_status"]
        if not isinstance(status, str) or status not in {"spec_frozen", "materialized"}:
            errors.append(f"{label}.fixture_status is invalid")
            continue
        statuses[status] += 1
        for field in ("title", "prompt"):
            if not isinstance(task[field], str) or not task[field].strip():
                errors.append(f"{label}.{field} must be a non-empty string")
        if not isinstance(task["acceptance"], list) or len(task["acceptance"]) < 3:
            errors.append(f"{label}.acceptance needs at least three public checks")
        elif any(not isinstance(item, str) or not item.strip() for item in task["acceptance"]):
            errors.append(f"{label}.acceptance must contain non-empty strings")
        suite = task["evaluator_suite"]
        if not isinstance(suite, str) or not suite.startswith("hidden/"):
            errors.append(f"{label}.evaluator_suite must be under hidden/")
        if status == "materialized":
            for field in ("fixture_path", "fixture_sha256", "evaluator_sha256", "public_checks"):
                if field not in task:
                    errors.append(f"{label} materialized task missing {field}")
            fixture = _safe_pack_path(pack_root, task.get("fixture_path"), f"{label}.fixture_path", errors)
            evaluator = _safe_pack_path(pack_root, suite, f"{label}.evaluator_suite", errors)
            for name, path, expected in (
                ("fixture", fixture, task.get("fixture_sha256")),
                ("evaluator", evaluator, task.get("evaluator_sha256")),
            ):
                if path is None:
                    continue
                try:
                    actual = tree_fingerprint(path)
                except (OSError, ValueError) as error:
                    errors.append(f"{label} {name}: {error}")
                else:
                    if actual != expected:
                        errors.append(f"{label} {name} digest mismatch: expected {expected}, got {actual}")
            checks = task.get("public_checks")
            if not isinstance(checks, list) or not checks or any(
                not isinstance(command, list)
                or not command
                or any(not isinstance(part, str) or not part for part in command)
                for command in checks
            ):
                errors.append(f"{label}.public_checks must be a non-empty array of argv arrays")
        else:
            unexpected = sorted(
                field
                for field in ("fixture_path", "fixture_sha256", "evaluator_sha256", "public_checks")
                if field in task
            )
            if unexpected:
                errors.append(f"{label} spec_frozen task has artifact fields: {', '.join(unexpected)}")
    duplicates = sorted(item for item, count in collections.Counter(ids).items() if count > 1)
    if duplicates:
        errors.append(f"duplicate task ids: {', '.join(duplicates)}")
    if dict(languages) != EXPECTED_LANGUAGES:
        errors.append(f"language allocation must be {EXPECTED_LANGUAGES}, got {dict(languages)}")
    if dict(categories) != EXPECTED_CATEGORIES:
        errors.append(f"category allocation must be {EXPECTED_CATEGORIES}, got {dict(categories)}")
    defaults = payload.get("defaults", {})
    if not isinstance(defaults, dict):
        return errors + ["defaults must be an object"]
    if defaults.get("network") != "disabled":
        errors.append("default network policy must be disabled")
    if defaults.get("agent_visible") != list(PUBLIC_FIELDS):
        errors.append("agent_visible must exactly match the public projection")
    if defaults.get("evaluator_only") != ["evaluator_suite"]:
        errors.append("evaluator_only must contain evaluator_suite")
    for field, upper in (("wall_time_seconds", 3_600), ("max_patch_bytes", 8 * 1024 * 1024)):
        value = defaults.get(field)
        if type(value) is not int or not 0 < value <= upper:
            errors.append(f"defaults.{field} must be a positive integer no larger than {upper}")
    return errors


def agent_view(
    payload: dict[str, Any], task_id: str, *, pack_root: Path | None = None,
) -> dict[str, Any]:
    errors = validate(payload, pack_root=pack_root)
    if errors:
        raise ValueError("invalid manifest: " + "; ".join(errors))
    for task in payload["tasks"]:
        if task["id"] == task_id:
            return {field: task[field] for field in PUBLIC_FIELDS if field in task}
    raise KeyError(task_id)


def summary(payload: dict[str, Any]) -> dict[str, Any]:
    tasks = payload.get("tasks", [])
    return {
        "pack_id": payload.get("pack_id"),
        "tasks": len(tasks),
        "languages": dict(collections.Counter(task.get("language") for task in tasks)),
        "categories": dict(collections.Counter(task.get("category") for task in tasks)),
        "fixture_status": dict(collections.Counter(task.get("fixture_status") for task in tasks)),
        "manifest_sha256": fingerprint(payload),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--agent-view", metavar="TASK_ID")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    manifest_path = args.manifest.expanduser().resolve()
    try:
        payload = load_manifest(manifest_path)
    except (OSError, ValueError) as error:
        print(f"error: cannot read manifest: {error}")
        return 1
    errors = validate(payload, pack_root=manifest_path.parent)
    if errors:
        for error in errors:
            print(f"error: {error}")
        return 1
    if args.agent_view:
        try:
            result = agent_view(payload, args.agent_view, pack_root=manifest_path.parent)
        except KeyError:
            print(f"error: unknown task id: {args.agent_view}")
            return 1
    else:
        result = summary(payload)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) if args.json or args.agent_view else " ".join(f"{key}={value}" for key, value in result.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
