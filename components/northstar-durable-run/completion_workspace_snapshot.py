"""Test-only host-side workspace observation for the completion contract.

The agent-facing listing tool is deliberately metadata-only. A completion
decision needs more: it must bind artifact bytes to host observation rather
than to a report. This module therefore reads content, while mirroring the same
posture as the listing tool: a host-owned root, ``O_NOFOLLOW`` reads, bounded
depth and entry counts, and no symlink following or reporting.

Observation is fail-closed. A symlink, an unreadable special file, or a tree
that exceeds the declared bounds refuses the whole observation instead of
silently producing a partial snapshot that a completion decision might trust.
"""
from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from completion_contract_v2 import WorkspaceSnapshot

_MAX_PATH = 1024
_DIGEST_PREFIX = "sha256:"
_CHUNK = 65536


class WorkspaceObservationRefused(Exception):
    """Raised when the workspace cannot be observed without ambiguity."""


@dataclass(frozen=True)
class SnapshotPolicy:
    """Host-declared observation bounds.

    Text at or below ``max_text_bytes`` is retained so semantic fields can be
    parsed; anything larger, non-UTF-8, or empty is reduced to a digest.
    """

    max_text_bytes: int = 65536
    max_entries: int = 4096
    max_depth: int = 8
    ignore_names: tuple[str, ...] = (".git", "__pycache__")

    def __post_init__(self) -> None:
        if self.max_text_bytes < 1 or self.max_entries < 1 or self.max_depth < 1:
            raise ValueError("snapshot policy bounds must be positive")


def _sha256(raw: bytes) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(raw).hexdigest()


def _digest_file(fd: int) -> str:
    hasher = hashlib.sha256()
    while True:
        chunk = os.read(fd, _CHUNK)
        if not chunk:
            break
        hasher.update(chunk)
    return _DIGEST_PREFIX + hasher.hexdigest()


def _read_regular_file(path: Path, policy: SnapshotPolicy) -> str:
    """Return retained text, or a digest when content must not be held."""
    try:
        size = path.stat(follow_symlinks=False).st_size
    except OSError as error:
        raise WorkspaceObservationRefused(f"cannot stat {path.name}") from error
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise WorkspaceObservationRefused(f"cannot open {path.name}") from error
    try:
        if size > policy.max_text_bytes:
            return _digest_file(fd)
        raw = b""
        while len(raw) <= policy.max_text_bytes:
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(fd)
    if len(raw) > policy.max_text_bytes:
        return _sha256(raw)
    if not raw:
        # The contract requires non-empty snapshot values; an empty file is
        # represented by its digest so absence and emptiness stay distinct.
        return _sha256(raw)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return _sha256(raw)


def _walk(
    directory: Path,
    prefix: str,
    policy: SnapshotPolicy,
    files: dict[str, str],
    *,
    depth: int,
) -> None:
    if depth > policy.max_depth:
        raise WorkspaceObservationRefused("workspace depth exceeds policy")
    try:
        entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
    except OSError as error:
        raise WorkspaceObservationRefused(f"cannot list {prefix or '.'}") from error
    for entry in entries:
        if entry.name in policy.ignore_names:
            continue
        name = f"{prefix}/{entry.name}" if prefix else entry.name
        if len(name) > _MAX_PATH or "\\" in name or "\x00" in name:
            raise WorkspaceObservationRefused("workspace path is not representable")
        if entry.is_symlink():
            raise WorkspaceObservationRefused(f"symlink refused: {name}")
        if entry.is_dir(follow_symlinks=False):
            _walk(Path(entry.path), name, policy, files, depth=depth + 1)
            continue
        if entry.is_file(follow_symlinks=False):
            if len(files) >= policy.max_entries:
                raise WorkspaceObservationRefused("workspace entry count exceeds policy")
            files[name] = _read_regular_file(Path(entry.path), policy)
            continue
        raise WorkspaceObservationRefused(f"unsupported entry kind: {name}")


def observe_workspace(root: str | Path, policy: SnapshotPolicy | None = None) -> WorkspaceSnapshot:
    """Observe a real workspace directory into a contract snapshot."""
    policy = policy or SnapshotPolicy()
    root_path = Path(root)
    try:
        info = root_path.stat(follow_symlinks=False)
    except OSError as error:
        raise WorkspaceObservationRefused("workspace root is not readable") from error
    if not stat.S_ISDIR(info.st_mode):
        raise WorkspaceObservationRefused("workspace root is not a directory")
    files: dict[str, str] = {}
    _walk(root_path, "", policy, files, depth=1)
    return WorkspaceSnapshot.from_files(files)


def materialize_workspace(dest: str | Path, files: Mapping[str, str]) -> Path:
    """Write declared files into ``dest`` so real observation can be exercised."""
    root = Path(dest)
    root.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(files.items()):
        if not isinstance(name, str) or not isinstance(content, str):
            raise ValueError("materialized entries must be text")
        parts = name.split("/")
        if name.startswith("/") or any(part in {"", ".", ".."} or "\\" in part for part in parts):
            raise ValueError("materialized path must be safe and relative")
        target = root.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return root
