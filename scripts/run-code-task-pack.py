#!/usr/bin/env python3
"""Prepare agent-visible fixtures and evaluate candidates with hidden checks."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate-code-task-pack.py"
SPEC = importlib.util.spec_from_file_location("validate_code_task_pack", VALIDATOR_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError(f"cannot load {VALIDATOR_PATH}")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)
MANIFEST = VALIDATOR.DEFAULT_MANIFEST
EVALUATOR_DIR = ".northstar_evaluator"
MAX_OUTPUT_BYTES = 1_048_576
RETAINED_OUTPUT_BYTES = 16_000
MAX_CANDIDATE_FILES = 2_000
MAX_CANDIDATE_BYTES = 64 * 1024 * 1024


def _environment(cwd: Path) -> dict[str, str]:
    # Evaluated code receives no provider keys or other caller credentials.
    return {
        "PATH": os.environ.get("PATH", os.defpath),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONPATH": str(cwd),
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }


def _git(cwd: Path, *arguments: str, patch: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    environment = _environment(cwd)
    environment.update({
        "GIT_AUTHOR_NAME": "Northstar Fixture",
        "GIT_COMMITTER_NAME": "Northstar Fixture",
        "GIT_AUTHOR_EMAIL": "fixture@northstar.invalid",
        "GIT_COMMITTER_EMAIL": "fixture@northstar.invalid",
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+0000",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+0000",
    })
    result = subprocess.run(
        ["git", "-C", str(cwd), *arguments], input=patch,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
        timeout=30, check=False,
    )
    if result.returncode:
        raise ValueError("git operation failed: " + result.stderr.decode("utf-8", errors="replace")[:2_000])
    return result


def _load_task(task_id: str) -> tuple[dict[str, Any], dict[str, Any], Path]:
    payload = VALIDATOR.load_manifest(MANIFEST)
    pack_root = MANIFEST.parent
    errors = VALIDATOR.validate(payload, pack_root=pack_root)
    if errors:
        raise ValueError("invalid task pack: " + "; ".join(errors))
    task = next((row for row in payload["tasks"] if row["id"] == task_id), None)
    if task is None:
        raise KeyError(task_id)
    if task["fixture_status"] != "materialized":
        raise ValueError(f"task {task_id} has no runnable fixture")
    return payload, task, pack_root


def prepare(task_id: str, destination: Path, *, git_repository: bool = False) -> dict[str, Any]:
    payload, task, pack_root = _load_task(task_id)
    if destination.exists() and any(destination.iterdir() if destination.is_dir() else [destination]):
        raise ValueError(f"destination is not empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copytree(pack_root / task["fixture_path"], destination, dirs_exist_ok=True)
    public = VALIDATOR.agent_view(payload, task_id, pack_root=pack_root)
    (destination / "NORTHSTAR_TASK.json").write_text(
        json.dumps(public, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    if git_repository:
        _git(destination, "init", "--initial-branch=main", "--object-format=sha1")
        _git(destination, "add", "--all")
        _git(destination, "-c", "commit.gpgsign=false", "commit", "-m", f"fixture: {task_id}")
    return public


def _run(command: list[str], cwd: Path, timeout: float) -> dict[str, Any]:
    environment = _environment(cwd)
    if timeout <= 0:
        return {
            "argv": command, "exit_code": 124, "output": "", "timed_out": True,
            "output_limited": False, "output_bytes": 0,
        }
    deadline = time.monotonic() + max(0, timeout)
    timed_out = False
    output_limited = False
    retained = bytearray()
    output_bytes = 0
    process = subprocess.Popen(
        command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
    )

    def kill_group() -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    try:
        assert process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    kill_group()
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 16_384)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output_bytes += len(chunk)
                    retained.extend(chunk)
                    if len(retained) > RETAINED_OUTPUT_BYTES:
                        del retained[:-RETAINED_OUTPUT_BYTES]
                    if output_bytes > MAX_OUTPUT_BYTES:
                        output_limited = True
                        kill_group()
                        break
                if output_limited:
                    break
        if not timed_out and not output_limited:
            try:
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
                kill_group()
        process.wait(timeout=5)
        exit_code = 124 if timed_out else (125 if output_limited else process.returncode)
    finally:
        # A command cannot leave a detached child in its original process group.
        kill_group()
        process.wait(timeout=5)
        if process.stdout is not None:
            process.stdout.close()
    return {
        "argv": command, "exit_code": exit_code,
        "output": retained.decode("utf-8", errors="replace"),
        "timed_out": timed_out, "output_limited": output_limited,
        "output_bytes": output_bytes,
    }


def _check_candidate(candidate: Path) -> None:
    files = 0
    total_bytes = 0
    for directory, subdirs, filenames in os.walk(candidate, followlinks=False):
        for name in (*subdirs, *filenames):
            path = Path(directory) / name
            mode = path.lstat().st_mode
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise ValueError(f"candidate contains a special file: {path.relative_to(candidate)}")
            if stat.S_ISREG(mode):
                files += 1
                total_bytes += path.stat().st_size
        subdirs[:] = [name for name in subdirs if name not in {".git", "__pycache__", "node_modules"}]
        if files > MAX_CANDIDATE_FILES or total_bytes > MAX_CANDIDATE_BYTES:
            raise ValueError("candidate exceeds the file or byte limit")


def _evaluate_checkout(
    payload: dict[str, Any], task: dict[str, Any], pack_root: Path, checkout: Path,
) -> dict[str, Any]:
    deadline = time.monotonic() + int(payload["defaults"]["wall_time_seconds"])
    public = []
    for command in task["public_checks"]:
        receipt = _run(command, checkout, deadline - time.monotonic())
        public.append(receipt)
        if receipt["timed_out"] or receipt["output_limited"]:
            break
    evaluator = checkout / EVALUATOR_DIR
    if evaluator.exists() or evaluator.is_symlink():
        raise ValueError(f"candidate created reserved path {EVALUATOR_DIR}")
    # Public commands cannot rewrite hidden checks before they are mounted.
    shutil.copytree(pack_root / task["evaluator_suite"], evaluator)
    suite = json.loads((evaluator / "suite.json").read_text(encoding="utf-8"))
    hidden = _run(
        suite["command"], checkout,
        min(int(suite.get("timeout_seconds", 30)), max(0, deadline - time.monotonic())),
    )
    ok = (
        len(public) == len(task["public_checks"])
        and all(row["exit_code"] == 0 for row in public)
        and hidden["exit_code"] == 0
    )
    return {
        "schema": "northstar.code-task-evaluation.v1",
        "task_id": task["id"], "ok": ok, "public": public, "hidden": hidden,
        "manifest_sha256": VALIDATOR.fingerprint(payload),
        "fixture_sha256": task["fixture_sha256"],
        "evaluator_sha256": task["evaluator_sha256"],
        "network_enforced": False, "release_eligible": False,
    }


def evaluate(task_id: str, candidate: Path) -> dict[str, Any]:
    payload, task, pack_root = _load_task(task_id)
    if not candidate.is_dir():
        raise ValueError(f"candidate does not exist: {candidate}")
    if (candidate / EVALUATOR_DIR).exists():
        raise ValueError(f"candidate contains reserved path {EVALUATOR_DIR}")
    _check_candidate(candidate)
    with tempfile.TemporaryDirectory(prefix=f"northstar-eval-{task_id}-") as directory:
        checkout = Path(directory) / "candidate"
        shutil.copytree(candidate, checkout, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules"))
        receipt = _evaluate_checkout(payload, task, pack_root, checkout)
        receipt["evaluation_mode"] = "candidate_copy"
        return receipt


def evaluate_patch(task_id: str, patch: bytes) -> dict[str, Any]:
    """Apply only the delivered patch to a clean, pinned fixture before checking."""
    payload, task, pack_root = _load_task(task_id)
    if len(patch) > int(payload["defaults"]["max_patch_bytes"]):
        raise ValueError("patch exceeds the task pack byte limit")
    with tempfile.TemporaryDirectory(prefix=f"northstar-patch-eval-{task_id}-") as directory:
        checkout = Path(directory) / "checkout"
        prepare(task_id, checkout, git_repository=True)
        start_commit = _git(checkout, "rev-parse", "HEAD").stdout.decode().strip()
        if patch:
            _git(checkout, "apply", "--check", "--index", "--binary", "-", patch=patch)
            _git(checkout, "apply", "--index", "--binary", "-", patch=patch)
        changed = [
            name.decode("utf-8", errors="strict")
            for name in _git(checkout, "diff", "--cached", "--name-only", "-z").stdout.split(b"\0")
            if name
        ]
        if any(
            Path(name).parts[0] in {".git", ".northstar", EVALUATOR_DIR}
            or name == "NORTHSTAR_TASK.json" for name in changed
        ):
            raise ValueError("patch modifies reserved evaluator or task paths")
        for entry in _git(checkout, "ls-files", "--stage", "-z").stdout.split(b"\0"):
            if entry and entry.split(b" ", 1)[0] not in {b"100644", b"100755"}:
                raise ValueError("patch introduces a symlink or submodule")
        _check_candidate(checkout)
        receipt = _evaluate_checkout(payload, task, pack_root, checkout)
        receipt.update({
            "evaluation_mode": "patch_replay", "start_commit": start_commit,
            "patch_sha256": hashlib.sha256(patch).hexdigest(),
            "patch_bytes": len(patch), "changed_files": changed,
        })
        return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("task_id")
    prepare_parser.add_argument("destination", type=Path)
    prepare_parser.add_argument("--git", action="store_true", help="create a deterministic initial Git commit")
    evaluate_parser = subparsers.add_parser("evaluate")
    evaluate_parser.add_argument("task_id")
    evaluate_parser.add_argument("candidate", type=Path)
    patch_parser = subparsers.add_parser("evaluate-patch")
    patch_parser.add_argument("task_id")
    patch_parser.add_argument("patch_path", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare(args.task_id, args.destination.expanduser().resolve(), git_repository=args.git)
            exit_code = 0
        elif args.command == "evaluate":
            result = evaluate(args.task_id, args.candidate.expanduser().resolve())
            exit_code = 0 if result["ok"] else 1
        else:
            patch_path = args.patch_path.expanduser().resolve()
            payload = VALIDATOR.load_manifest(MANIFEST)
            if patch_path.stat().st_size > int(payload["defaults"]["max_patch_bytes"]):
                raise ValueError("patch exceeds the task pack byte limit")
            result = evaluate_patch(args.task_id, patch_path.read_bytes())
            exit_code = 0 if result["ok"] else 1
    except (KeyError, OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        result = {"ok": False, "error": f"{type(error).__name__}: {error}"}
        exit_code = 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
