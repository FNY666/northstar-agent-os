"""Content-addressed workspace checkpoints for reversible agent runs.

A transcript tells us *what* an agent did; a checkpoint records a bounded,
content-addressed view of the workspace so an operator can compare or rewind
that state without guessing. This module is intentionally conservative:

* snapshots contain regular files only; symlinks and protected trees are never
  followed;
* package limits bound file count, per-file size and total bytes;
* manifests carry SHA-256 digests and are verified before a rewind;
* ``rewind`` requires an explicit force flag and never deletes files unless
  ``delete_added`` is also explicit;
* restore writes a fresh safety checkpoint before changing the workspace.

This is a local reversible-run kernel, not a production filesystem snapshot or
VM rollback. It is useful for CLI/SDK integration and gives a future worker a
stable checkpoint contract without pretending to provide OS-level isolation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

CHECKPOINT_SCHEMA_VERSION = "northstar.checkpoint.v1"
CHECKPOINT_DIRECTORY = "checkpoints"
MAX_CHECKPOINT_FILES = 10_000
MAX_CHECKPOINT_FILE_BYTES = 8 * 1024 * 1024
MAX_CHECKPOINT_TOTAL_BYTES = 64 * 1024 * 1024
MAX_LABEL_CHARS = 200
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_CHECKPOINT_ID_RE = re.compile(r"^cp-[A-Za-z0-9TZ_.-]+$")
_IGNORED_DIRECTORIES = frozenset({".git", "__pycache__", "node_modules", ".venv"})


@dataclass(frozen=True)
class CheckpointPolicy:
    """Opt-in automatic checkpoint boundaries for a governed runtime.

    ``every_turns`` creates a snapshot at a deterministic turn interval;
    ``after_mutation`` also creates one after a successfully admitted mutating
    tool turn. Automatic snapshots are retained separately from operator/manual
    checkpoints by ``label_prefix``. The policy never changes workspace
    permissions or bypasses the explicit rewind/restore controls.
    """

    enabled: bool = False
    every_turns: int = 1
    after_mutation: bool = True
    max_checkpoints: int = 32
    label_prefix: str = "auto"

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("checkpoint policy enabled must be a boolean")
        if isinstance(self.every_turns, bool) or not isinstance(self.every_turns, int) or self.every_turns < 1:
            raise ValueError("checkpoint policy every_turns must be a positive integer")
        if not isinstance(self.after_mutation, bool):
            raise ValueError("checkpoint policy after_mutation must be a boolean")
        if isinstance(self.max_checkpoints, bool) or not isinstance(self.max_checkpoints, int) or self.max_checkpoints < 1:
            raise ValueError("checkpoint policy max_checkpoints must be a positive integer")
        if not isinstance(self.label_prefix, str) or not self.label_prefix or len(self.label_prefix) > MAX_LABEL_CHARS:
            raise ValueError("checkpoint policy label_prefix is invalid")
        if any(ord(char) < 0x20 for char in self.label_prefix):
            raise ValueError("checkpoint policy label_prefix contains a control character")

    def should_checkpoint(self, *, turn_index: int, mutated: bool) -> bool:
        """Return whether the completed turn crosses an automatic boundary."""
        if not self.enabled:
            return False
        if isinstance(turn_index, bool) or not isinstance(turn_index, int) or turn_index < 1:
            raise ValueError("turn_index must be a positive integer")
        return (self.after_mutation and mutated) or turn_index % self.every_turns == 0

    def label(self, *, turn_index: int, mutated: bool) -> str:
        kind = "mutation" if mutated else "turn"
        return f"{self.label_prefix}:{kind}-{turn_index}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "every_turns": self.every_turns,
            "after_mutation": self.after_mutation,
            "max_checkpoints": self.max_checkpoints,
            "label_prefix": self.label_prefix,
        }


class CheckpointError(ValueError):
    """A checkpoint cannot be created, verified, compared or restored safely."""


@dataclass(frozen=True)
class CheckpointFile:
    """One regular file in a checkpoint manifest."""

    path: str
    sha256: str
    bytes: int
    mode: int

    def as_dict(self) -> dict[str, Any]:
        return {"path": self.path, "sha256": self.sha256, "bytes": self.bytes, "mode": self.mode}


@dataclass(frozen=True)
class Checkpoint:
    """Validated manifest plus its on-disk snapshot directory."""

    checkpoint_id: str
    session_id: str
    workspace: str
    created_at: str
    label: str
    parent_checkpoint_id: str | None
    session_index: int
    workspace_digest: str
    files: tuple[CheckpointFile, ...]
    directory: Path

    @property
    def manifest_path(self) -> Path:
        return self.directory / "manifest.json"

    @property
    def snapshot_root(self) -> Path:
        return self.directory / "files"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "checkpoint_id": self.checkpoint_id,
            "session_id": self.session_id,
            "workspace": self.workspace,
            "created_at": self.created_at,
            "label": self.label,
            "parent_checkpoint_id": self.parent_checkpoint_id,
            "session_index": self.session_index,
            "workspace_digest": self.workspace_digest,
            "file_count": len(self.files),
            "total_bytes": sum(item.bytes for item in self.files),
            "manifest": str(self.manifest_path),
            "files": [item.as_dict() for item in self.files],
        }


@dataclass(frozen=True)
class FileState:
    """Pre/post metadata for one path touched by a mutating tool."""

    path: str
    exists: bool
    kind: str = "missing"
    sha256: str | None = None
    bytes: int = 0
    mode: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "exists": self.exists,
            "kind": self.kind,
            "sha256": self.sha256,
            "bytes": self.bytes,
            "mode": self.mode,
        }


@dataclass(frozen=True)
class FileChange:
    """One difference between a checkpoint and the current workspace."""

    path: str
    status: str  # added | modified | deleted
    checkpoint_sha256: str | None = None
    current_sha256: str | None = None
    bytes: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status,
            "checkpoint_sha256": self.checkpoint_sha256,
            "current_sha256": self.current_sha256,
            "bytes": self.bytes,
        }


@dataclass(frozen=True)
class ForkResult:
    """Result of materialising a new workspace/session from a checkpoint."""

    source_session_id: str
    source_checkpoint_id: str
    session_id: str
    workspace: str
    checkpoint_id: str
    copied_files: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_session_id": self.source_session_id,
            "source_checkpoint_id": self.source_checkpoint_id,
            "session_id": self.session_id,
            "workspace": self.workspace,
            "checkpoint_id": self.checkpoint_id,
            "copied_files": self.copied_files,
        }


@dataclass(frozen=True)
class CheckpointDiff:
    """Digest comparison used by ``sessions diff`` and the rewind guard."""

    checkpoint_id: str
    workspace_digest: str
    current_digest: str
    changes: tuple[FileChange, ...]

    @property
    def clean(self) -> bool:
        return not self.changes

    def as_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "clean": self.clean,
            "workspace_digest": self.workspace_digest,
            "current_digest": self.current_digest,
            "changes": [change.as_dict() for change in self.changes],
        }


def checkpoint_root(session_dir: str | os.PathLike[str], session_id: str) -> Path:
    """Return the private checkpoint directory for one session."""
    _validate_session_id(session_id)
    return Path(session_dir) / CHECKPOINT_DIRECTORY / session_id


def create_checkpoint(
    workspace: str | os.PathLike[str],
    session_dir: str | os.PathLike[str],
    session_id: str,
    *,
    label: str = "",
    parent_checkpoint_id: str | None = None,
    session_index: int | None = None,
    ignored_directories: Iterable[str] = (),
) -> Checkpoint:
    """Atomically snapshot bounded regular files under ``workspace``.

    ``ignored_directories`` is additive to the conservative built-in ignores.
    The snapshot is first written to a sibling temporary directory and becomes
    visible only after its manifest and all file copies are complete.
    """
    root = _workspace_root(workspace)
    label = _validate_label(label)
    _validate_optional_checkpoint_id(parent_checkpoint_id)
    parent = _checkpoint_parent(session_dir, session_id)
    existing = list_checkpoints(session_dir, session_id)
    if session_index is None:
        session_index = _read_session_index(session_dir, session_id)
    _validate_session_index(session_index)
    if parent_checkpoint_id is None and existing:
        parent_checkpoint_id = existing[-1].checkpoint_id
    elif parent_checkpoint_id is not None and parent_checkpoint_id not in {item.checkpoint_id for item in existing}:
        raise CheckpointError(f"parent checkpoint does not belong to session {session_id}: {parent_checkpoint_id}")
    ignored = _IGNORED_DIRECTORIES | frozenset(ignored_directories)
    transcript_path = Path(session_dir).expanduser() / f"{session_id}.jsonl"
    records = _scan_workspace(
        root,
        ignored=ignored,
        ignored_roots=(parent,),
        ignored_files=(transcript_path,),
    )
    checkpoint_id = _new_checkpoint_id()
    try:
        parent.mkdir(parents=True, exist_ok=True)
        os.chmod(parent, 0o700)
    except OSError as error:
        raise CheckpointError(f"cannot prepare checkpoint storage {parent}: {error}") from error
    final = parent / checkpoint_id
    try:
        staging = Path(tempfile.mkdtemp(prefix=f".{checkpoint_id}-", dir=str(parent)))
    except OSError as error:
        raise CheckpointError(f"cannot create checkpoint staging directory in {parent}: {error}") from error
    try:
        snapshot_root = staging / "files"
        snapshot_root.mkdir(parents=True, exist_ok=True)
        files: list[CheckpointFile] = []
        for record in records:
            relative = record["path"]
            source = root / relative
            destination = snapshot_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            _copy_regular_file(source, destination)
            copied_size, copied_digest = _hash_file(destination)
            if copied_size != int(record["bytes"]) or copied_digest != record["sha256"]:
                raise CheckpointError(f"workspace changed while checkpointing: {relative}")
            files.append(
                CheckpointFile(
                    path=relative,
                    sha256=record["sha256"],
                    bytes=int(record["bytes"]),
                    mode=int(record["mode"]),
                )
            )
        files_tuple = tuple(files)
        digest = _workspace_digest(files_tuple)
        manifest = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "checkpoint_id": checkpoint_id,
            "session_id": session_id,
            "workspace": str(root),
            "created_at": _timestamp(),
            "label": label,
            "parent_checkpoint_id": parent_checkpoint_id,
            "session_index": session_index,
            "workspace_digest": digest,
            "files": [item.as_dict() for item in files_tuple],
        }
        _write_json(staging / "manifest.json", manifest)
        if final.exists() or final.is_symlink():
            raise CheckpointError(f"checkpoint id collision: {checkpoint_id}")
        os.replace(staging, final)
        staging = None  # type: ignore[assignment]
        _fsync_directory(parent)
    except CheckpointError:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        raise
    except OSError as error:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        raise CheckpointError(f"cannot persist checkpoint {checkpoint_id}: {error}") from error
    return Checkpoint(
        checkpoint_id=checkpoint_id,
        session_id=session_id,
        workspace=str(root),
        created_at=manifest["created_at"],
        label=label,
        parent_checkpoint_id=parent_checkpoint_id,
        session_index=session_index,
        workspace_digest=digest,
        files=files_tuple,
        directory=final,
    )


def list_checkpoints(session_dir: str | os.PathLike[str], session_id: str) -> tuple[Checkpoint, ...]:
    """Load checkpoints in creation order; malformed entries fail closed."""
    root = _checkpoint_parent(session_dir, session_id)
    if not root.exists():
        return ()
    if not root.is_dir() or root.is_symlink():
        raise CheckpointError(f"checkpoint root is not a private directory: {root}")
    checkpoints: list[Checkpoint] = []
    for manifest in root.glob("cp-*/manifest.json"):
        checkpoints.append(load_checkpoint(manifest.parent, expected_session_id=session_id))
    checkpoints.sort(key=lambda item: (item.created_at, item.checkpoint_id))
    return tuple(checkpoints)


def prune_checkpoints(
    session_dir: str | os.PathLike[str],
    session_id: str,
    *,
    max_checkpoints: int,
    label_prefix: str = "auto",
) -> tuple[str, ...]:
    """Remove old automatic checkpoints while preserving manual checkpoints.

    If a retained checkpoint pointed at an evicted automatic ancestor, its
    parent pointer is atomically rebased to the nearest retained/manual
    ancestor. The workspace digest and snapshot bytes are untouched.
    """
    if isinstance(max_checkpoints, bool) or not isinstance(max_checkpoints, int) or max_checkpoints < 1:
        raise CheckpointError("max_checkpoints must be a positive integer")
    if not isinstance(label_prefix, str) or not label_prefix or len(label_prefix) > MAX_LABEL_CHARS:
        raise CheckpointError("label_prefix is invalid")
    checkpoints = list(list_checkpoints(session_dir, session_id))
    automatic = [item for item in checkpoints if item.label.startswith(label_prefix + ":")]
    if len(automatic) <= max_checkpoints:
        return ()
    retained_automatic = automatic[-max_checkpoints:]
    removed = automatic[:-max_checkpoints]
    removed_ids = {item.checkpoint_id for item in removed}
    by_id = {item.checkpoint_id: item for item in checkpoints}
    for item in removed:
        directory = item.directory
        if directory.parent != _checkpoint_parent(session_dir, session_id) or directory.is_symlink():
            raise CheckpointError(f"refusing to prune checkpoint outside session root: {directory}")
        try:
            shutil.rmtree(directory)
        except OSError as error:
            raise CheckpointError(f"cannot prune checkpoint {item.checkpoint_id}: {error}") from error

    first = retained_automatic[0]
    if first.parent_checkpoint_id in removed_ids:
        parent_id = first.parent_checkpoint_id
        visited: set[str] = set()
        while parent_id in removed_ids:
            if parent_id in visited:
                raise CheckpointError("checkpoint parent chain contains a cycle")
            visited.add(parent_id)
            ancestor = by_id.get(parent_id)
            parent_id = ancestor.parent_checkpoint_id if ancestor is not None else None
        manifest_path = first.manifest_path
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("manifest is not an object")
            raw["parent_checkpoint_id"] = parent_id
            _atomic_write_json(manifest_path, raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise CheckpointError(f"cannot rebase retained checkpoint {first.checkpoint_id}: {error}") from error
    _fsync_directory(_checkpoint_parent(session_dir, session_id))
    return tuple(item.checkpoint_id for item in removed)


def load_checkpoint(
    directory: str | os.PathLike[str],
    *,
    expected_session_id: str | None = None,
) -> Checkpoint:
    """Load and validate one checkpoint manifest and its snapshot tree."""
    path = Path(directory)
    if path.is_symlink() or not path.is_dir():
        raise CheckpointError(f"checkpoint directory is not a real directory: {path}")
    manifest_path = path / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise CheckpointError(f"checkpoint manifest is not a regular file: {manifest_path}")
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CheckpointError(f"checkpoint manifest is missing: {manifest_path}") from None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CheckpointError(f"cannot read checkpoint manifest {manifest_path}: {error}") from error
    if not isinstance(raw, dict) or raw.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
        raise CheckpointError(f"unsupported or missing checkpoint schema in {manifest_path}")
    checkpoint_id = raw.get("checkpoint_id")
    session_id = raw.get("session_id")
    if not isinstance(checkpoint_id, str) or not _CHECKPOINT_ID_RE.fullmatch(checkpoint_id):
        raise CheckpointError(f"invalid checkpoint id in {manifest_path}")
    if not isinstance(session_id, str):
        raise CheckpointError(f"invalid session id in {manifest_path}")
    _validate_session_id(session_id)
    if expected_session_id is not None and session_id != expected_session_id:
        raise CheckpointError(f"checkpoint {checkpoint_id} belongs to session {session_id}, not {expected_session_id}")
    workspace = raw.get("workspace")
    created_at = raw.get("created_at")
    label = raw.get("label", "")
    parent_checkpoint_id = raw.get("parent_checkpoint_id")
    session_index = raw.get("session_index")
    workspace_digest = raw.get("workspace_digest")
    entries = raw.get("files")
    if not isinstance(workspace, str) or not isinstance(created_at, str) or not isinstance(label, str):
        raise CheckpointError(f"invalid checkpoint metadata in {manifest_path}")
    _validate_optional_checkpoint_id(parent_checkpoint_id)
    _validate_session_index(session_index)
    if not isinstance(workspace_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", workspace_digest):
        raise CheckpointError(f"invalid workspace digest in {manifest_path}")
    if not isinstance(entries, list) or len(entries) > MAX_CHECKPOINT_FILES:
        raise CheckpointError(f"invalid file list in {manifest_path}")
    files: list[CheckpointFile] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise CheckpointError(f"invalid file entry in {manifest_path}")
        relative = entry.get("path")
        sha256 = entry.get("sha256")
        size = entry.get("bytes")
        mode = entry.get("mode")
        _validate_relative_path(relative, field="checkpoint file")
        if relative in seen:
            raise CheckpointError(f"duplicate checkpoint file {relative!r}")
        seen.add(relative)
        if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise CheckpointError(f"invalid file digest for {relative!r}")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > MAX_CHECKPOINT_FILE_BYTES:
            raise CheckpointError(f"invalid file size for {relative!r}")
        if isinstance(mode, bool) or not isinstance(mode, int):
            raise CheckpointError(f"invalid file mode for {relative!r}")
        files.append(CheckpointFile(relative, sha256, size, mode))
    files_tuple = tuple(files)
    if _workspace_digest(files_tuple) != workspace_digest:
        raise CheckpointError(f"manifest digest does not match file entries: {manifest_path}")
    checkpoint = Checkpoint(
        checkpoint_id=checkpoint_id,
        session_id=session_id,
        workspace=workspace,
        created_at=created_at,
        label=label,
        parent_checkpoint_id=parent_checkpoint_id,
        session_index=session_index,
        workspace_digest=workspace_digest,
        files=files_tuple,
        directory=path,
    )
    verify_checkpoint(checkpoint)
    return checkpoint


def verify_checkpoint(checkpoint: Checkpoint) -> None:
    """Verify snapshot bytes and tree shape before they can be restored."""
    snapshot_root = checkpoint.snapshot_root
    if snapshot_root.is_symlink() or not snapshot_root.is_dir():
        raise CheckpointError(f"checkpoint snapshot root is missing or not a directory: {snapshot_root}")
    total = 0
    expected = {entry.path for entry in checkpoint.files}
    for entry in checkpoint.files:
        path = _safe_snapshot_path(snapshot_root, entry.path)
        if not path.is_file() or path.is_symlink():
            raise CheckpointError(f"checkpoint file is missing or not regular: {entry.path}")
        size, digest = _hash_file(path)
        total += size
        if size != entry.bytes or digest != entry.sha256:
            raise CheckpointError(f"checkpoint file digest mismatch: {entry.path}")
    for directory, dirnames, filenames in os.walk(snapshot_root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        for name in dirnames:
            if (directory_path / name).is_symlink():
                raise CheckpointError(f"checkpoint snapshot contains a symlink: {directory_path / name}")
        for name in filenames:
            path = directory_path / name
            if path.is_symlink():
                raise CheckpointError(f"checkpoint snapshot contains a symlink: {path}")
            relative = path.relative_to(snapshot_root).as_posix()
            if path.is_file() and relative not in expected:
                raise CheckpointError(f"checkpoint contains an unmanifested file: {relative}")
    if total > MAX_CHECKPOINT_TOTAL_BYTES:
        raise CheckpointError("checkpoint exceeds the total byte limit")


def capture_file_states(
    workspace: str | os.PathLike[str],
    relative_paths: Iterable[str],
) -> tuple[FileState, ...]:
    """Hash selected workspace paths for a mutating-action pre/post receipt.

    This is intentionally narrower than a checkpoint: it records metadata and
    digests, not file bytes. The checkpoint/rewind API remains the recovery
    mechanism; these states make an individual action auditable in the session.
    """
    root = _workspace_root(workspace)
    states: list[FileState] = []
    for relative in sorted(set(relative_paths)):
        target = _safe_target_path(root, relative)
        if target.is_symlink():
            raise CheckpointError(f"refusing to hash symlinked mutation path: {relative}")
        if not target.exists():
            states.append(FileState(path=relative, exists=False))
            continue
        if target.is_dir():
            mode = stat.S_IMODE(target.stat().st_mode)
            states.append(FileState(path=relative, exists=True, kind="directory", mode=mode))
            continue
        if not target.is_file():
            states.append(FileState(path=relative, exists=True, kind="other"))
            continue
        size, digest = _hash_file(target)
        states.append(
            FileState(
                path=relative,
                exists=True,
                kind="file",
                sha256=digest,
                bytes=size,
                mode=stat.S_IMODE(target.stat().st_mode),
            )
        )
    return tuple(states)


def diff_checkpoint(checkpoint: Checkpoint, workspace: str | os.PathLike[str]) -> CheckpointDiff:
    """Compare a verified checkpoint with the current workspace."""
    verify_checkpoint(checkpoint)
    root = _workspace_root(workspace)
    session_base = checkpoint.directory.parent.parent.parent
    current_records = _scan_workspace(
        root,
        ignored=_IGNORED_DIRECTORIES,
        ignored_roots=(checkpoint.directory.parent,),
        ignored_files=(session_base / f"{checkpoint.session_id}.jsonl",),
    )
    current = {record["path"]: record for record in current_records}
    saved = {entry.path: entry for entry in checkpoint.files}
    changes: list[FileChange] = []
    for relative in sorted(set(saved) | set(current)):
        old = saved.get(relative)
        new = current.get(relative)
        if old is None and new is not None:
            changes.append(FileChange(relative, "added", current_sha256=new["sha256"], bytes=int(new["bytes"])))
        elif old is not None and new is None:
            changes.append(FileChange(relative, "deleted", checkpoint_sha256=old.sha256, bytes=old.bytes))
        elif old is not None and new is not None and old.sha256 != new["sha256"]:
            changes.append(
                FileChange(
                    relative,
                    "modified",
                    checkpoint_sha256=old.sha256,
                    current_sha256=new["sha256"],
                    bytes=int(new["bytes"]),
                )
            )
    return CheckpointDiff(checkpoint.checkpoint_id, checkpoint.workspace_digest, _workspace_digest_from_records(current_records), tuple(changes))


def rewind_checkpoint(
    checkpoint: Checkpoint,
    workspace: str | os.PathLike[str],
    *,
    force: bool = False,
    delete_added: bool = False,
    safety_session_dir: str | os.PathLike[str] | None = None,
    safety_session_id: str | None = None,
) -> dict[str, Any]:
    """Restore files from a checkpoint after an explicit ``force`` decision.

    A safety checkpoint is created automatically when a session directory/id is
    supplied. Files added after the checkpoint remain by default; deleting them
    requires the separate ``delete_added`` opt-in.
    """
    if not force:
        raise CheckpointError("rewind is destructive; pass force=True after reviewing sessions diff")
    verify_checkpoint(checkpoint)
    root = _workspace_root(workspace)
    comparison = diff_checkpoint(checkpoint, root)
    safety: Checkpoint | None = None
    if safety_session_dir is not None and safety_session_id is not None:
        safety = create_checkpoint(root, safety_session_dir, safety_session_id, label=f"before-rewind:{checkpoint.checkpoint_id}")
    restored = 0
    for entry in checkpoint.files:
        source = _safe_snapshot_path(checkpoint.snapshot_root, entry.path)
        target = _safe_target_path(root, entry.path)
        target.parent.mkdir(parents=True, exist_ok=True)
        _copy_atomic(source, target, mode=entry.mode)
        restored += 1
    deleted = 0
    if delete_added:
        for change in comparison.changes:
            if change.status != "added":
                continue
            target = _safe_target_path(root, change.path)
            if target.exists() and target.is_file() and not target.is_symlink():
                target.unlink()
                deleted += 1
    after = diff_checkpoint(checkpoint, root)
    if any(change.status != "added" for change in after.changes) or (delete_added and after.changes):
        raise CheckpointError("rewind verification failed; workspace was not restored to the checkpoint")
    return {
        "checkpoint_id": checkpoint.checkpoint_id,
        "restored_files": restored,
        "deleted_added_files": deleted,
        "remaining_added_files": sum(change.status == "added" for change in after.changes),
        "safety_checkpoint_id": safety.checkpoint_id if safety else None,
        "workspace_digest": checkpoint.workspace_digest,
    }


def fork_checkpoint(
    checkpoint: Checkpoint,
    target_workspace: str | os.PathLike[str],
    session_dir: str | os.PathLike[str],
    new_session_id: str,
    *,
    label: str = "fork base",
) -> ForkResult:
    """Materialise a checkpoint into a new, previously absent workspace.

    The target is assembled in a sibling temporary directory and atomically
    renamed into place. A new initial checkpoint is recorded for the fork and a
    small lineage manifest preserves the source session/checkpoint relation.
    """
    _validate_session_id(new_session_id)
    verify_checkpoint(checkpoint)
    requested = Path(os.path.abspath(os.fspath(Path(target_workspace).expanduser())))
    if requested.is_symlink() or requested.exists():
        raise CheckpointError(f"fork target already exists; refusing to overwrite: {requested}")
    parent = requested.parent
    if parent.exists() and (parent.is_symlink() or not parent.is_dir()):
        raise CheckpointError(f"fork target parent is not a real directory: {parent}")
    parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{requested.name}.fork-", dir=str(parent)))
    try:
        for entry in checkpoint.files:
            source = _safe_snapshot_path(checkpoint.snapshot_root, entry.path)
            destination = _safe_target_path(staging, entry.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            _copy_regular_file(source, destination)
        os.replace(staging, requested)
        staging = None  # type: ignore[assignment]
        _fsync_directory(parent)
    except Exception:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        raise
    try:
        fork_checkpoint_record = create_checkpoint(
            requested,
            session_dir,
            new_session_id,
            label=label,
            session_index=-1,
        )
        lineage = {
            "schema_version": "northstar.fork.v1",
            "source_session_id": checkpoint.session_id,
            "source_checkpoint_id": checkpoint.checkpoint_id,
            "session_id": new_session_id,
            "workspace": str(requested.resolve()),
            "created_at": _timestamp(),
            "checkpoint_id": fork_checkpoint_record.checkpoint_id,
        }
        _write_json(_checkpoint_parent(session_dir, new_session_id) / "fork.json", lineage)
    except Exception:
        # The workspace is intentionally not removed after materialisation: it
        # may be useful for recovery even when checkpoint storage is damaged.
        raise
    return ForkResult(
        source_session_id=checkpoint.session_id,
        source_checkpoint_id=checkpoint.checkpoint_id,
        session_id=new_session_id,
        workspace=str(requested.resolve()),
        checkpoint_id=fork_checkpoint_record.checkpoint_id,
        copied_files=len(checkpoint.files),
    )


def _checkpoint_parent(session_dir: str | os.PathLike[str], session_id: str) -> Path:
    base = Path(session_dir).expanduser()
    if base.is_symlink() or (base.exists() and not base.is_dir()):
        raise CheckpointError(f"session directory is not a real directory: {base}")
    checkpoints = base / CHECKPOINT_DIRECTORY
    if checkpoints.is_symlink() or (checkpoints.exists() and not checkpoints.is_dir()):
        raise CheckpointError(f"checkpoint directory is not a real directory: {checkpoints}")
    parent = checkpoints / session_id
    if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
        raise CheckpointError(f"session checkpoint directory is not a real directory: {parent}")
    return parent


def _scan_workspace(
    root: Path,
    *,
    ignored: frozenset[str],
    ignored_roots: Sequence[Path] = (),
    ignored_files: Sequence[Path] = (),
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    total = 0
    ignored_paths = tuple(path.absolute() for path in ignored_roots)
    ignored_file_paths = tuple(path.absolute() for path in ignored_files)
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        if any(directory_path.absolute() == ignored or ignored in directory_path.absolute().parents for ignored in ignored_paths):
            dirnames[:] = []
            continue
        kept_dirs: list[str] = []
        for name in sorted(dirnames):
            path = directory_path / name
            if name in ignored:
                continue
            if path.is_symlink():
                raise CheckpointError(f"workspace contains a symlinked directory: {path}")
            kept_dirs.append(name)
        dirnames[:] = kept_dirs
        for name in sorted(filenames):
            if name == ".git":
                continue
            path = directory_path / name
            if path.absolute() in ignored_file_paths:
                continue
            if path.is_symlink():
                raise CheckpointError(f"workspace contains a symlinked file: {path}")
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            size, digest = _hash_file(path)
            if size > MAX_CHECKPOINT_FILE_BYTES:
                raise CheckpointError(
                    f"file {relative!r} is {size} bytes; checkpoint limit is {MAX_CHECKPOINT_FILE_BYTES}"
                )
            total += size
            if total > MAX_CHECKPOINT_TOTAL_BYTES:
                raise CheckpointError(f"workspace exceeds the checkpoint limit of {MAX_CHECKPOINT_TOTAL_BYTES} bytes")
            records.append({"path": relative, "sha256": digest, "bytes": size, "mode": stat.S_IMODE(path.stat().st_mode)})
            if len(records) > MAX_CHECKPOINT_FILES:
                raise CheckpointError(f"workspace contains more than {MAX_CHECKPOINT_FILES} checkpointable files")
    return records


def _workspace_digest(files: Sequence[CheckpointFile]) -> str:
    hasher = hashlib.sha256()
    for entry in sorted(files, key=lambda item: item.path):
        hasher.update(entry.path.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(entry.sha256.encode("ascii"))
        hasher.update(b"\0")
        hasher.update(str(entry.bytes).encode("ascii"))
        hasher.update(b"\0")
    return hasher.hexdigest()


def _workspace_digest_from_records(records: Sequence[dict[str, Any]]) -> str:
    return _workspace_digest(
        tuple(CheckpointFile(str(item["path"]), str(item["sha256"]), int(item["bytes"]), int(item["mode"])) for item in records)
    )


def _hash_file(path: Path) -> tuple[int, str]:
    hasher = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                hasher.update(chunk)
    except OSError as error:
        raise CheckpointError(f"cannot read workspace file {path}: {error}") from error
    return size, hasher.hexdigest()


def _copy_regular_file(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise CheckpointError(f"refusing to snapshot non-regular file: {source}")
    with source.open("rb") as input_handle, destination.open("wb") as output_handle:
        shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
        output_handle.flush()
        os.fsync(output_handle.fileno())
    # Preserve ordinary rwx bits, but never reproduce setuid/setgid bits from a
    # workspace into a rewind snapshot or restored file.
    os.chmod(destination, stat.S_IMODE(source.stat().st_mode) & 0o777)


def _copy_atomic(source: Path, target: Path, *, mode: int) -> None:
    if target.exists() and target.is_symlink():
        raise CheckpointError(f"refusing to overwrite symlink during rewind: {target}")
    temporary = tempfile.NamedTemporaryFile(prefix=f".{target.name}.rewind-", dir=str(target.parent), delete=False)
    temporary_path = Path(temporary.name)
    try:
        with source.open("rb") as input_handle:
            shutil.copyfileobj(input_handle, temporary, length=1024 * 1024)
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary.close()
        os.chmod(temporary_path, mode & 0o777)
        os.replace(temporary_path, target)
    except Exception:
        try:
            temporary.close()
        except Exception:
            pass
        temporary_path.unlink(missing_ok=True)
        raise


def _safe_snapshot_path(root: Path, relative: str) -> Path:
    _validate_relative_path(relative, field="snapshot path")
    if root.is_symlink():
        raise CheckpointError(f"checkpoint snapshot root is a symlink: {root}")
    path = root / relative
    try:
        path.relative_to(root)
    except ValueError:
        raise CheckpointError(f"snapshot path escapes checkpoint root: {relative!r}") from None
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise CheckpointError(f"checkpoint snapshot contains a symlink: {relative!r}")
    return path


def _safe_target_path(root: Path, relative: str) -> Path:
    _validate_relative_path(relative, field="workspace path")
    path = root / relative
    try:
        path.relative_to(root)
    except ValueError:
        raise CheckpointError(f"workspace path escapes workspace root: {relative!r}") from None
    current = root
    for part in Path(relative).parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise CheckpointError(f"refusing to traverse symlink during rewind: {current}")
        if current.exists() and not current.is_dir():
            raise CheckpointError(f"workspace path component is not a directory: {current}")
    return path


def _workspace_root(workspace: str | os.PathLike[str]) -> Path:
    requested = Path(workspace).expanduser()
    if requested.is_symlink():
        raise CheckpointError(f"workspace must not be a symlink: {workspace}")
    root = requested.resolve()
    if not root.is_dir() or root.is_symlink():
        raise CheckpointError(f"workspace must be a real directory: {workspace}")
    return root


def _validate_relative_path(value: Any, *, field: str) -> None:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise CheckpointError(f"invalid {field}: {value!r}")
    parts = Path(value).parts
    if any(part in {"", ".", ".."} for part in parts) or "\\" in value or "\x00" in value:
        raise CheckpointError(f"invalid {field}: {value!r}")


def _validate_session_id(session_id: str) -> None:
    if not isinstance(session_id, str) or not session_id or not _SESSION_ID_RE.fullmatch(session_id):
        raise CheckpointError(f"invalid session id for checkpoint storage: {session_id!r}")


def _validate_label(label: str) -> str:
    if not isinstance(label, str):
        raise CheckpointError("checkpoint label must be text")
    label = label.strip()
    if len(label) > MAX_LABEL_CHARS:
        raise CheckpointError(f"checkpoint label is longer than {MAX_LABEL_CHARS} characters")
    return label


def _validate_optional_checkpoint_id(checkpoint_id: Any) -> None:
    if checkpoint_id is not None and (
        not isinstance(checkpoint_id, str) or not _CHECKPOINT_ID_RE.fullmatch(checkpoint_id)
    ):
        raise CheckpointError(f"invalid parent checkpoint id: {checkpoint_id!r}")


def _validate_session_index(session_index: Any) -> None:
    if isinstance(session_index, bool) or not isinstance(session_index, int) or session_index < -1:
        raise CheckpointError(f"invalid session index: {session_index!r}")


def _read_session_index(session_dir: str | os.PathLike[str], session_id: str) -> int:
    """Return the last durable transcript index, or -1 for a new session."""
    path = Path(session_dir) / f"{session_id}.jsonl"
    if path.is_symlink():
        raise CheckpointError(f"session transcript is not a regular file: {path}")
    if not path.exists():
        return -1
    if not path.is_file():
        raise CheckpointError(f"session transcript is not a regular file: {path}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise CheckpointError(f"cannot read session transcript {path}: {error}") from error
    nonempty = [number for number, line in enumerate(lines, 1) if line.strip()]
    last_line = nonempty[-1] if nonempty else 0
    last_index = -1
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            # The session writer permits a torn final line after a crash, but
            # a damaged earlier line must not be guessed at.
            if line_number == last_line:
                break
            raise CheckpointError(f"cannot read session transcript {path}: {error}") from error
        index = record.get("index") if isinstance(record, dict) else None
        if isinstance(index, int) and not isinstance(index, bool):
            last_index = max(last_index, index)
    return last_index


def _new_checkpoint_id() -> str:
    return "cp-{}-{}".format(time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()), uuid.uuid4().hex[:8])


def _timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int((time.time() % 1) * 1000):03d}Z"


def _write_json(path: Path, value: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    """Replace one JSON file atomically and fsync its containing directory."""
    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex[:8]}")
    try:
        _write_json(temporary, value)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink(missing_ok=True)


def _fsync_directory(path: Path) -> None:
    """Make an atomic directory rename durable on POSIX filesystems."""
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(str(path), flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "CHECKPOINT_DIRECTORY",
    "CHECKPOINT_SCHEMA_VERSION",
    "Checkpoint",
    "CheckpointDiff",
    "CheckpointError",
    "CheckpointFile",
    "CheckpointPolicy",
    "FileChange",
    "FileState",
    "ForkResult",
    "capture_file_states",
    "checkpoint_root",
    "create_checkpoint",
    "diff_checkpoint",
    "list_checkpoints",
    "load_checkpoint",
    "prune_checkpoints",
    "rewind_checkpoint",
    "verify_checkpoint",
]
