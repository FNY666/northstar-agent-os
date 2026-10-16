"""Independent, bounded evidence of net Git workspace changes during a coding run.

This module only reads Git metadata and regular files. It never invokes a shell,
repository hook, formatter, test runner, or model-provided command. The report is
deliberately a net before/after view: it does not claim which actor made a change.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_STATUS_BYTES = 16 * 1024 * 1024
MAX_STATUS_PATHS = 2_048
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 5


@dataclass(frozen=True)
class WorkspaceSnapshot:
    workspace: Path
    repository: str | None
    head: str | None
    index_digest: str | None
    states: dict[str, str]
    fingerprints: dict[str, str | None]
    index_entries: dict[str, str]
    unverifiable: tuple[str, ...]
    error: str | None = None

    @property
    def available(self) -> bool:
        return self.error is None and self.repository is not None


def _git(workspace: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    """Run a fixed, read-only Git command with ambient Git overrides disabled."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }
    return subprocess.run(
        [
            "git",
            "-C",
            str(workspace),
            "-c",
            "core.fsmonitor=false",
            "-c",
            "status.relativePaths=true",
            *arguments,
        ],
        cwd=workspace,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )


def _parse_status(data: bytes) -> dict[str, str]:
    """Parse porcelain v1 -z records; --no-renames keeps one path per record."""
    states: dict[str, str] = {}
    for record in data.split(b"\0"):
        if not record:
            continue
        if len(record) < 4 or record[2:3] != b" ":
            raise ValueError("Git returned an invalid porcelain status record")
        state = record[:2].decode("ascii", errors="replace")
        path = os.fsdecode(record[3:])
        if not path or path.startswith("/") or ".." in Path(path).parts:
            raise ValueError("Git returned a path outside the workspace")
        states[path] = state
    return states


def _parse_index_diff(data: bytes) -> dict[str, str]:
    """Parse Git's NUL-delimited raw diff records into path-bound index states."""
    fields = data.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 2:
        raise ValueError("Git returned an invalid index diff record")
    entries: dict[str, str] = {}
    for index in range(0, len(fields), 2):
        metadata = fields[index].decode("ascii", errors="replace")
        path = os.fsdecode(fields[index + 1])
        if not metadata.startswith(":") or not path or path.startswith("/") or ".." in Path(path).parts:
            raise ValueError("Git returned an index path outside the workspace")
        entries[path] = metadata
    return entries


def _fingerprint(root: Path, relative: str, remaining: int) -> tuple[str | None, int]:
    """Hash one path beneath root, refusing symlinks in every path component."""
    parts = Path(relative).parts
    if not parts or relative.startswith("/") or ".." in parts:
        return None, 0
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow_flag:
        return None, 0
    directory_fd = -1
    try:
        directory_fd = os.open(root, os.O_RDONLY | directory_flag | nofollow_flag | getattr(os, "O_CLOEXEC", 0))
        for component in parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | directory_flag | nofollow_flag | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        name = parts[-1]
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            target = os.fsencode(os.readlink(name, dir_fd=directory_fd))
            return "symlink:" + hashlib.sha256(target).hexdigest(), 0
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES or info.st_size > remaining:
            return None, 0

        flags = os.O_RDONLY | nofollow_flag | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_ino != info.st_ino or opened.st_dev != info.st_dev:
                return None, 0
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(descriptor, min(64 * 1024, remaining - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_FILE_BYTES or size > remaining:
                    return None, 0
                digest.update(chunk)
            return "file:" + digest.hexdigest(), size
        finally:
            os.close(descriptor)
    except OSError:
        return None, 0
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)


def snapshot_workspace(workspace: str | os.PathLike[str]) -> WorkspaceSnapshot:
    """Capture Git status and bounded fingerprints for its changed paths."""
    try:
        root = Path(workspace).resolve(strict=True)
        if not root.is_dir():
            raise OSError("workspace is not a directory")
    except OSError as error:
        return WorkspaceSnapshot(Path(workspace), None, None, None, {}, {}, {}, (), str(error))

    try:
        repository_result = _git(root, "rev-parse", "--show-toplevel")
        if repository_result.returncode != 0:
            return WorkspaceSnapshot(root, None, None, None, {}, {}, {}, (), "workspace is not inside a Git worktree")
        repository_path = Path(
            repository_result.stdout.decode("utf-8", errors="replace").strip()
        ).resolve(strict=True)
        if not root.is_relative_to(repository_path):
            return WorkspaceSnapshot(
                root,
                None,
                None,
                None,
                {},
                {},
                {},
                (),
                "Git worktree does not contain the workspace",
            )
        repository = str(repository_path)
        head_result = _git(root, "rev-parse", "--verify", "HEAD")
        head = head_result.stdout.decode("ascii", errors="replace").strip() if head_result.returncode == 0 else None
        status_result = _git(
            root,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--no-renames",
            "--",
            ".",
        )
        if status_result.returncode != 0:
            return WorkspaceSnapshot(
                root, repository, head, None, {}, {}, {}, (), "Git could not read workspace status"
            )
        if len(status_result.stdout) > MAX_STATUS_BYTES:
            return WorkspaceSnapshot(
                root, repository, head, None, {}, {}, {}, (), "Git status exceeded the evidence size limit"
            )
        states = _parse_status(status_result.stdout)
        if len(states) > MAX_STATUS_PATHS:
            return WorkspaceSnapshot(
                root, repository, head, None, {}, {}, {}, (), "Git status exceeded the path count limit"
            )
        index_result = _git(
            root,
            "diff",
            "--cached",
            "--raw",
            "--no-abbrev",
            "--no-renames",
            "-z",
            "--no-ext-diff",
            "--no-textconv",
            "--root",
            "--relative",
            "--",
            ".",
        )
        if index_result.returncode != 0 or len(index_result.stdout) > MAX_STATUS_BYTES:
            index_digest = None
            index_entries = {}
        else:
            index_digest = hashlib.sha256(index_result.stdout).hexdigest()
            try:
                index_entries = _parse_index_diff(index_result.stdout)
            except ValueError:
                index_digest = None
                index_entries = {}
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        message = (
            "Git evidence collection failed"
            if isinstance(error, (OSError, subprocess.TimeoutExpired))
            else str(error)
        )
        return WorkspaceSnapshot(root, None, None, None, {}, {}, {}, (), message)

    fingerprints: dict[str, str | None] = {}
    unverifiable: list[str] = []
    remaining = MAX_TOTAL_BYTES
    for relative in sorted(states):
        fingerprint, consumed = _fingerprint(root, relative, remaining)
        fingerprints[relative] = fingerprint
        remaining -= consumed
        if fingerprint is None:
            unverifiable.append(relative)

    return WorkspaceSnapshot(
        root,
        repository,
        head,
        index_digest,
        states,
        fingerprints,
        index_entries,
        tuple(unverifiable),
    )


def _committed_changes(
    before: WorkspaceSnapshot,
    after: WorkspaceSnapshot,
) -> tuple[dict[str, str], bool]:
    """Return changed paths between two recorded HEADs, if both commits exist."""
    if before.head == after.head:
        return {}, True
    if before.head is None or after.head is None:
        return {}, False
    try:
        result = _git(
            after.workspace,
            "diff",
            "--name-status",
            "-z",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--relative",
            before.head,
            after.head,
            "--",
            ".",
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}, False
    if result.returncode != 0 or len(result.stdout) > MAX_STATUS_BYTES:
        return {}, False
    fields = result.stdout.split(b"\0")
    changes: dict[str, str] = {}
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 2:
        return {}, False
    for index in range(0, len(fields), 2):
        status = fields[index].decode("ascii", errors="replace")
        path = os.fsdecode(fields[index + 1])
        if not path or path.startswith("/") or ".." in Path(path).parts:
            return {}, False
        changes[path] = "added" if status == "A" else "deleted" if status == "D" else "modified"
        if len(changes) > MAX_STATUS_PATHS:
            return {}, False
    return changes, True


def compare_snapshots(before: WorkspaceSnapshot, after: WorkspaceSnapshot) -> dict[str, Any]:
    """Return a JSON-safe summary of net changes, preserving incomplete coverage."""
    if not before.available or not after.available:
        return {
            "type": "coding_evidence",
            "status": "unavailable",
            "reason": before.error or after.error or "Git worktree changed during the run",
            "changed_files": [],
            "coverage": "unavailable",
        }
    if before.repository != after.repository or before.workspace != after.workspace:
        return {
            "type": "coding_evidence",
            "status": "unavailable",
            "reason": "Git worktree identity changed during the run",
            "changed_files": [],
            "coverage": "unavailable",
        }

    changed_by_path: dict[str, dict[str, Any]] = {}
    unverifiable = set(before.unverifiable) | set(after.unverifiable)
    paths = set(before.states) | set(after.states)
    for path in sorted(paths):
        old_state = before.states.get(path, "")
        new_state = after.states.get(path, "")
        old_fingerprint = before.fingerprints.get(path)
        new_fingerprint = after.fingerprints.get(path)
        if old_state == new_state and old_fingerprint == new_fingerprint and path not in unverifiable:
            continue
        if path in unverifiable and old_state == new_state and old_fingerprint == new_fingerprint:
            continue
        if "D" in new_state or (path in before.states and path not in after.states and new_state == ""):
            change = "deleted"
        elif (
            "A" in new_state
            or "?" in new_state
            or (path not in before.states and path in after.states and not old_state)
        ):
            change = "added"
        else:
            change = "modified"
        item: dict[str, Any] = {"path": path, "change": change}
        if old_state:
            item["before_status"] = old_state
        if new_state:
            item["after_status"] = new_state
        changed_by_path[path] = item

    committed, commit_coverage = _committed_changes(before, after)
    for path, change in committed.items():
        item = changed_by_path.setdefault(path, {"path": path, "change": change})
        item["committed"] = True
    for path in set(before.index_entries) | set(after.index_entries):
        if before.index_entries.get(path) == after.index_entries.get(path):
            continue
        state = after.states.get(path, "")
        if "A" in state or "?" in state:
            change = "added"
        elif "D" in state or (path in before.index_entries and path not in after.index_entries):
            change = "deleted"
        else:
            change = "modified"
        item = changed_by_path.setdefault(path, {"path": path, "change": change})
        item["staged"] = True
    changed = [changed_by_path[path] for path in sorted(changed_by_path)]
    coverage_notes = []
    if before.index_digest is None or after.index_digest is None:
        coverage_notes.append("staged-index diff could not be read completely")
    if not commit_coverage:
        coverage_notes.append("committed path diff could not be read completely")

    # A clean tracked file deleted during the run appears as " D" after the run,
    # so it is covered above. Git HEAD is included separately for commits made mid-run.
    return {
        "type": "coding_evidence",
        "status": "available",
        "repository": os.path.relpath(before.repository, str(before.workspace)),
        "head_before": before.head,
        "head_after": after.head,
        "head_changed": before.head != after.head,
        "index_changed": (
            before.index_digest != after.index_digest
            if before.index_digest is not None and after.index_digest is not None
            else None
        ),
        "changed_files": changed,
        "unverifiable_paths": sorted(unverifiable),
        "coverage_notes": coverage_notes,
        "coverage": "partial" if unverifiable or coverage_notes else "complete",
    }


_SHELL_EXIT_LINE = re.compile(r"^exit=(n/a|-?\d+)(?: timed_out=(true|false))?$")
_SHELL_BACKEND_LINE = re.compile(r"^backend=([^\s]+) isolation=([^\s]+)$")


def shell_execution_evidence(run_report: Any) -> list[dict[str, Any]]:
    """Summarize reported Shell outcomes without copying command or output text."""
    if run_report is None:
        return []
    results: dict[str, Any] = {}
    for event in getattr(run_report, "events", ()):
        if type(event).__name__ != "UserMessage":
            continue
        for block in getattr(event, "content", ()):
            if type(block).__name__ == "ToolResultBlock":
                results[str(getattr(block, "tool_use_id", ""))] = block

    evidence: list[dict[str, Any]] = []
    calls = [call for call in getattr(run_report, "tool_calls", ()) if getattr(call, "name", "") == "Shell"]
    for call in sorted(calls, key=lambda item: (item.turn_index, item.call_id)):
        result = results.get(call.call_id)
        result_text = result.text() if result is not None and callable(getattr(result, "text", None)) else ""
        lines = result_text.splitlines()
        exit_match = _SHELL_EXIT_LINE.fullmatch(lines[0]) if lines else None
        backend_match = _SHELL_BACKEND_LINE.fullmatch(lines[1]) if len(lines) > 1 else None
        executed = exit_match is not None and backend_match is not None
        if call.denied:
            status = "denied"
        elif executed:
            status = "executed"
        elif call.is_error:
            status = "error"
        else:
            status = "unconfirmed"
        exit_text = exit_match.group(1) if exit_match else "n/a"
        timeout_text = exit_match.group(2) if exit_match else None
        record: dict[str, Any] = {
            "call_id": call.call_id,
            "turn_index": call.turn_index,
            "agent": call.agent,
            "execution_scope": "top_level",
            "agent_path": [],
            "status": status,
            "executed": executed,
            "denied": bool(call.denied),
            "permission_source": call.permission_source,
            "tool_error": bool(call.is_error),
            "duration_ms": call.duration_ms,
            "truncated": bool(call.truncated),
        }
        if exit_match:
            record["exit_code"] = int(exit_text) if exit_text != "n/a" else None
            record["timed_out"] = timeout_text == "true"
        if backend_match:
            record["backend"] = backend_match.group(1)
            record["isolation"] = backend_match.group(2)
        evidence.append(record)

    # Child runs retain only this bounded, sanitized evidence, not their full
    # tool inputs or output. Prefix the delegation path as the child receipts
    # are folded into the parent report.
    for subagent in getattr(run_report, "subagents", ()):
        name = str(getattr(subagent, "agent", "") or "unknown")
        for item in getattr(subagent, "shell_executions", ()):
            if not isinstance(item, dict):
                continue
            relative_path = item.get("agent_path", ())
            if not isinstance(relative_path, (list, tuple)):
                relative_path = ()
            safe_item = {
                key: item[key]
                for key in (
                    "call_id", "turn_index", "agent", "status", "executed",
                    "denied", "permission_source", "tool_error", "duration_ms",
                    "truncated", "exit_code", "timed_out", "backend", "isolation",
                )
                if key in item
            }
            evidence.append({
                **safe_item,
                "execution_scope": "subagent",
                "agent_path": [name, *(str(part) for part in relative_path)],
            })
    return evidence


def postcondition_evidence(run_report: Any) -> dict[str, Any]:
    """Summarize host-evaluated checks without copying expected text."""
    empty = {
        "source": "runtime_postconditions",
        "status": "unknown",
        "configured": 0,
        "checked": 0,
        "passed": 0,
        "failed": 0,
        "structural_checked": 0,
        "structural_passed": 0,
        "structural_failed": 0,
        "results": [],
    }
    if run_report is None:
        return {**empty, "status": "unavailable"}
    initialized = False
    configured: int | None = None
    verdict_data: dict[str, Any] | None = None
    for event in getattr(run_report, "events", ()):
        if type(event).__name__ != "SystemMessage":
            continue
        data = getattr(event, "data", {})
        if not isinstance(data, dict):
            return {**empty, "status": "unavailable"}
        subtype = getattr(event, "subtype", "")
        if subtype == "init":
            initialized = True
            conditions = data.get("postconditions", ())
            if not isinstance(conditions, (list, tuple)):
                return {**empty, "status": "unavailable"}
            configured = len(conditions)
        elif subtype == "postconditions":
            verdict_data = data

    if verdict_data is None:
        if not initialized or configured is None:
            return empty
        if configured == 0:
            return {**empty, "status": "not_configured"}
        return {**empty, "status": "not_evaluated", "configured": configured}

    data = verdict_data
    raw_results = data.get("results", ())
    if not isinstance(raw_results, (list, tuple)):
        return {**empty, "status": "unavailable"}
    results: list[dict[str, Any]] = []
    for item in raw_results:
        if not isinstance(item, dict):
            continue
        # The full event may contain the expected ``contains`` text. Keep
        # the check identity and verdict, never the user-supplied needle.
        result = {
            key: item[key]
            for key in (
                "kind", "path", "ok", "detail", "structural",
                "digest_before", "digest_after",
            )
            if key in item
        }
        if isinstance(result.get("ok"), bool):
            results.append(result)
    declared_checked = data.get("checked", len(results))
    if isinstance(declared_checked, bool) or not isinstance(declared_checked, int) or declared_checked != len(results):
        return {**empty, "status": "unavailable"}
    if configured is not None and configured != declared_checked:
        return {**empty, "status": "unavailable"}
    passed = sum(item["ok"] for item in results)
    failed = len(results) - passed
    structural_checked = sum(bool(item.get("structural", False)) for item in results)
    structural_passed = sum(item["ok"] and item.get("structural", False) for item in results)
    return {
        "source": "runtime_postconditions",
        "status": "passed" if failed == 0 and declared_checked else "failed" if failed else "not_configured",
        "configured": configured if configured is not None else declared_checked,
        "checked": declared_checked,
        "passed": passed,
        "failed": failed,
        "structural_checked": structural_checked,
        "structural_passed": structural_passed,
        "structural_failed": structural_checked - structural_passed,
        "results": results,
    }


def workspace_check_evidence(run_report: Any) -> dict[str, Any]:
    """Summarize repository Stop checks, retaining only bounded verdict metadata."""
    empty = {
        "source": "workspace_stop_hooks",
        "status": "unknown",
        "configured": 0,
        "checked": 0,
        "passed": 0,
        "failed": 0,
        "results": [],
    }
    if run_report is None:
        return {**empty, "status": "unavailable"}

    configured: int | None = None
    for event in getattr(run_report, "events", ()):
        if type(event).__name__ != "SystemMessage" or getattr(event, "subtype", "") != "init":
            continue
        data = getattr(event, "data", {})
        hook_counts = data.get("hooks", {}) if isinstance(data, dict) else {}
        raw_count = hook_counts.get("Stop") if isinstance(hook_counts, dict) else None
        if isinstance(raw_count, int) and not isinstance(raw_count, bool) and raw_count >= 0:
            configured = raw_count
        break

    latest: dict[tuple[str, str], dict[str, Any]] = {}
    attempts: dict[tuple[str, str], int] = {}
    for event in getattr(run_report, "hook_fires", ()):
        if not isinstance(event, dict) or event.get("event") != "Stop":
            continue
        data = event.get("data", {})
        if not isinstance(data, dict):
            continue
        checks = data.get("workspace_checks", ())
        if not isinstance(checks, (list, tuple)):
            # Accept an individual record emitted by an older runtime.
            check = data.get("workspace_check")
            checks = [check] if isinstance(check, dict) else []
        for check in checks:
            if not isinstance(check, dict):
                continue
            name = check.get("name")
            script = check.get("script")
            status = check.get("status")
            if not isinstance(name, str) or not isinstance(script, str) or status not in {"passed", "failed"}:
                continue
            check_id = check.get("id")
            key = (str(check_id) if isinstance(check_id, str) else name, script)
            attempts[key] = attempts.get(key, 0) + 1
            result = {"name": name, "script": script, "status": status}
            if isinstance(check_id, str):
                result["id"] = check_id
            exit_code = check.get("exit_code")
            if isinstance(exit_code, int) and not isinstance(exit_code, bool):
                result["exit_code"] = exit_code
            if isinstance(check.get("timed_out"), bool):
                result["timed_out"] = check["timed_out"]
            duration_ms = check.get("duration_ms")
            if isinstance(duration_ms, int) and not isinstance(duration_ms, bool) and duration_ms >= 0:
                result["duration_ms"] = duration_ms
            latest[key] = result

    results = [
        {**latest[key], "attempts": attempts[key]}
        for key in sorted(latest)
    ]
    checked = len(results)
    passed = sum(item["status"] == "passed" for item in results)
    failed = checked - passed
    if configured is None and checked == 0:
        status = "unknown"
    elif configured == 0:
        status = "not_configured"
    elif checked == 0:
        status = "not_evaluated"
    elif failed:
        status = "failed"
    elif configured is not None and checked < configured:
        status = "partial"
    else:
        status = "passed"
    return {
        "source": "workspace_stop_hooks",
        "status": status,
        "configured": configured if configured is not None else checked,
        "checked": checked,
        "passed": passed,
        "failed": failed,
        "results": results,
    }
