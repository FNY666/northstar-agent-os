#!/usr/bin/env python3
"""Prove frozen fixtures reject their baseline and accept reference patches.

This is a fixture-quality control, not a real-model benchmark. References and
hidden suites remain outside every agent-visible prepared repository.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "scripts" / "run-code-task-pack.py"
SPEC = importlib.util.spec_from_file_location("code_task_pack_runner", RUNNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {RUNNER_PATH}")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def _require_node24(version: str) -> None:
    """Reject unsupported TypeScript control environments before running fixtures."""
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", version.strip())
    if match is None:
        raise ValueError("Node toolchain probe returned an invalid version")
    if int(match.group(1)) < 24:
        raise ValueError(
            f"TypeScript fixture controls require Node.js >=24; found {version.strip()}"
        )


def check_task(task_id: str) -> dict[str, Any]:
    payload, task, pack_root = RUNNER._load_task(task_id)
    short = Path(task["evaluator_suite"]).name
    reference_path = pack_root / "references" / f"{short}.json"
    raw = reference_path.read_bytes()
    repairs = json.loads(raw)
    if not isinstance(repairs, dict) or not repairs:
        raise ValueError("reference repair must be a non-empty path-to-text object")
    baseline = RUNNER.evaluate_patch(task_id, b"")
    baseline_receipts = [*baseline["public"], baseline["hidden"]]
    baseline_rejected = not baseline["ok"] and all(
        type(receipt["exit_code"]) is int
        and receipt["exit_code"] >= 0
        and receipt["exit_code"] not in {124, 125}
        and not receipt["timed_out"]
        and not receipt["output_limited"]
        for receipt in baseline_receipts
    )
    with tempfile.TemporaryDirectory(prefix=f"northstar-reference-{short}-") as directory:
        candidate = Path(directory) / "candidate"
        RUNNER.prepare(task_id, candidate, git_repository=True)
        for filename, content in repairs.items():
            relative = Path(filename)
            if (
                relative.is_absolute() or ".." in relative.parts or not relative.parts
                or relative.parts[0] in {".git", ".northstar", RUNNER.EVALUATOR_DIR}
                or filename == "NORTHSTAR_TASK.json"
                or not isinstance(content, str)
            ):
                raise ValueError("reference repair contains an unsafe path or non-text content")
            target = candidate / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        RUNNER._git(candidate, "add", "--intent-to-add", "--all")
        patch = RUNNER._git(candidate, "diff", "--binary", "HEAD").stdout
        reference = RUNNER.evaluate_patch(task_id, patch)
    ok = baseline_rejected and reference["ok"] and baseline["start_commit"] == reference["start_commit"]
    return {
        "task_id": task_id,
        "language": task["language"],
        "category": task["category"],
        "ok": bool(ok),
        "baseline_rejected": baseline_rejected,
        "reference_passed": bool(reference["ok"]),
        "reference_sha256": hashlib.sha256(raw).hexdigest(),
        "baseline": baseline,
        "reference": reference,
    }


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def summarize_controls(report: dict[str, Any]) -> dict[str, Any]:
    """Create a portable success snapshot only from complete passing controls."""
    if not report.get("complete") or not report.get("ok") or report.get("failed") != 0:
        raise ValueError("cannot freeze incomplete or failing fixture controls")
    tasks = report.get("tasks", [])
    declared = report.get("declared")
    if (
        type(declared) is not int or declared <= 0
        or len(tasks) != declared or report.get("checked") != declared or report.get("passed") != declared
        or len({row["task_id"] for row in tasks}) != declared
        or any(
            not row.get("ok") or not row.get("baseline_rejected") or not row.get("reference_passed")
            or row["baseline"]["ok"] or not row["reference"]["ok"]
            or row["reference"]["manifest_sha256"] != report["manifest_sha256"]
            or row["baseline"]["start_commit"] != row["reference"]["start_commit"]
            for row in tasks
        )
    ):
        raise ValueError("fixture control rows do not support the declared success summary")
    rows = []
    for row in tasks:
        reference = row["reference"]
        rows.append({
            "task_id": row["task_id"], "language": row["language"], "category": row["category"],
            "baseline_rejected": row["baseline_rejected"], "reference_passed": row["reference_passed"],
            "start_commit": reference["start_commit"], "fixture_sha256": reference["fixture_sha256"],
            "evaluator_sha256": reference["evaluator_sha256"], "reference_sha256": row["reference_sha256"],
            "patch_sha256": reference["patch_sha256"],
        })
    return {
        "schema": "northstar.code-task-controls-summary.v1",
        "pack_id": report["pack_id"], "manifest_sha256": report["manifest_sha256"],
        "measurement": "fixture_reference_controls", "real_model_evaluated": False,
        "release_eligible": False, "checked": report["checked"], "passed": report["passed"],
        "failed": 0, "toolchain": report.get("toolchain", {}), "tasks": rows,
    }


def run_controls(
    task_ids: list[str] | None = None,
    *,
    write: Path | None = None,
    progress: bool = False,
) -> dict[str, Any]:
    payload = RUNNER.VALIDATOR.load_manifest(RUNNER.MANIFEST)
    errors = RUNNER.VALIDATOR.validate(payload, pack_root=RUNNER.MANIFEST.parent)
    if errors:
        raise ValueError("invalid pack: " + "; ".join(errors))
    available = {task["id"] for task in payload["tasks"]}
    selected = task_ids or [task["id"] for task in payload["tasks"]]
    if len(selected) != len(set(selected)) or set(selected) - available:
        raise ValueError("task selection contains duplicates or unknown ids")
    node_version = None
    if any(task["language"] == "typescript" and task["id"] in selected for task in payload["tasks"]):
        probe = RUNNER._run(["node", "--version"], ROOT, 15)
        if probe["exit_code"] != 0:
            raise ValueError("Node toolchain probe failed or timed out")
        node_version = probe["output"].strip()
        _require_node24(node_version)
    rows: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "schema": "northstar.code-task-controls.v1",
        "pack_id": payload["pack_id"],
        "manifest_sha256": RUNNER.VALIDATOR.fingerprint(payload),
        "measurement": "fixture_reference_controls",
        "real_model_evaluated": False,
        "release_eligible": False,
        "toolchain": {"python": platform.python_version(), "node": node_version},
        "declared": len(selected),
        "checked": 0,
        "passed": 0,
        "failed": 0,
        "complete": False,
        "ok": False,
        "tasks": rows,
    }
    for task_id in selected:
        row = check_task(task_id)
        rows.append(row)
        report.update({
            "checked": len(rows),
            "passed": sum(bool(item["ok"]) for item in rows),
            "failed": sum(not item["ok"] for item in rows),
            "complete": len(rows) == len(selected),
        })
        report["ok"] = report["complete"] and report["failed"] == 0
        if write is not None:
            _write_report(write, report)
        if progress:
            print(
                f"{task_id}: baseline_rejected={row['baseline_rejected']} "
                f"reference_passed={row['reference_passed']}", flush=True,
            )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", action="append", dest="tasks")
    parser.add_argument("--write", type=Path)
    parser.add_argument("--write-summary", type=Path, help="freeze a portable summary after all selected controls pass")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        report = run_controls(args.tasks, write=args.write, progress=not args.json)
        if args.write_summary is not None and report["ok"]:
            _write_report(args.write_summary, summarize_controls(report))
    except (KeyError, OSError, ValueError) as error:
        print(json.dumps({"ok": False, "error": f"{type(error).__name__}: {error}"}))
        return 2
    if args.json:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(
            f"checked={report['checked']} passed={report['passed']} failed={report['failed']} "
            f"complete={report['complete']} real_model_evaluated=False"
        )
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
