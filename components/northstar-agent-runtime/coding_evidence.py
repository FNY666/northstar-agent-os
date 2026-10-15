"""Independent, bounded evidence of net Git workspace changes during a coding run.

This module only reads Git metadata and regular files. It never invokes a shell,
repository hook, formatter, test runner, or model-provided command. The report is
deliberately a net before/after view: it does not claim which actor made a change.
"""
from __future__ import annotations

import hashlib
import os
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
