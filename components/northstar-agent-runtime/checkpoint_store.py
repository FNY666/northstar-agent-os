"""Atomic, path-safe checkpoint storage.

A checkpoint that is half-written is worse than no checkpoint: a resume from a
torn file inherits counters nobody can vouch for.  So this module gives the
checkpoint layer the file discipline the transcript layer never had:

* **One file per checkpoint id, written atomically.**  The payload goes to a
  uniquely named temporary file in the *destination directory* (so the final
  ``os.replace`` stays on one filesystem and is therefore atomic), the file is
  fsynced, and only then renamed over the destination.  A crash leaves either
  the old content or the new content - never a mixture.
* **A path that cannot escape the store.**  ``_validate_file_path`` resolves the
  id against the storage directory and refuses anything that lands outside it:
  ``..`` segments, absolute paths, and symlinks that point out.
* **One writer per destination.**  Concurrent saves to the same id are
  serialised by a per-destination queue, so two writers cannot interleave and
  the last one to arrive wins cleanly.
* **A restricted loader.**  Payloads are read back through an explicit
  allowlist: a type that was never registered is refused, not instantiated.

This is the shape of Microsoft Agent Framework's ``FileCheckpointStorage``
(``python/packages/core/agent_framework/_workflows/_checkpoint.py``): the same
``_validate_file_path`` / ``_write_atomic`` discipline, the same per-destination
write queue, the same ``"module:qualname"`` allowlist.  The payload here is
Northstar's own: the dict shape of :meth:`checkpoints.Checkpoint.as_dict`.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any, Iterable, Mapping

#: The types a payload may carry, by ``"module:qualname"``.
#:
#: The payload is JSON, so only the plain JSON shapes are allowed.  A payload
#: that wants a Python object must register it here first; an unregistered type
#: is refused on load rather than reconstructed.
_ALLOWED_TYPES: frozenset[str] = frozenset(
    {
        "builtins:bool",
        "builtins:dict",
        "builtins:float",
        "builtins:int",
        "builtins:list",
        "builtins:NoneType",
        "builtins:str",
        "builtins:tuple",
    }
)

#: Types registered at runtime with :func:`register_checkpoint_type`.
_registered_types: set[str] = set()


def register_checkpoint_type(cls: type[Any]) -> None:
    """Allow one more type to be restored from a checkpoint payload.

    The type is named by ``"module:qualname"`` - the same spelling Microsoft
    Agent Framework uses - and the name is what the loader checks.  Registering
    a type is an explicit statement that restoring it is safe.
    """
    if not isinstance(cls, type):
        raise TypeError("checkpoint types must be classes")
    _registered_types.add(f"{cls.__module__}:{cls.__qualname__}")


def allowed_types() -> frozenset[str]:
    """Every type name the loader will accept right now."""
    return _ALLOWED_TYPES | frozenset(_registered_types)


class CheckpointStoreError(ValueError):
    """A checkpoint id, payload, or stored file the store refuses."""


class _WriteQueue:
    """A FIFO hand-off of ownership for one destination path.

    Threads take the destination in arrival order, so two concurrent saves to
    the same checkpoint id cannot interleave their writes.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending = 0
        self._tail: threading.Event | None = None

    def acquire(self) -> tuple[threading.Event | None, threading.Event]:
        """Take the destination.

        Returns ``(predecessor_event, own_event)``: the predecessor's event is
        ``None`` when the destination was free, and the caller must wait on it
        before writing and signal ``own_event`` afterwards.
        """
        with self._lock:
            predecessor = self._tail
            own = threading.Event()
            self._tail = own
            self._pending += 1
            return predecessor, own

    def release(self, own: threading.Event) -> None:
        """Hand the destination to the next writer."""
        with self._lock:
            self._pending -= 1
            own.set()


class FileCheckpointStorage:
    """Checkpoints on disk: one file per id, written atomically.

    Usage::

        store = FileCheckpointStorage("/var/lib/northstar/checkpoints")
        store.save("ck-000001", checkpoint.as_dict())
        payload = store.load("ck-000001")
    """

    def __init__(self, storage_path: str | Path, *, allowed_checkpoint_types: Iterable[str] = ()) -> None:
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._allowed_types = frozenset(allowed_checkpoint_types) | allowed_types()
        self._queues: dict[Path, _WriteQueue] = {}
        self._queues_guard = threading.Lock()

    # -- paths -----------------------------------------------------------

    def _validate_file_path(self, checkpoint_id: str) -> Path:
        """The file an id names, or a refusal when the id leaves the store.

        The check is on the *resolved* path: ``..`` segments, an absolute path,
        and a symlink pointing outside the store all resolve somewhere else,
        and all are refused.
        """
        if not isinstance(checkpoint_id, str) or not checkpoint_id:
            raise CheckpointStoreError("checkpoint id must be a non-empty string")
        if "\x00" in checkpoint_id:
            raise CheckpointStoreError(f"invalid checkpoint id: {checkpoint_id!r}")
        # The id names a *file* inside the store, never a path: a separator,
        # a parent segment or an absolute path is refused before it is joined.
        if "/" in checkpoint_id or "\\" in checkpoint_id or checkpoint_id in {".", ".."}:
            raise CheckpointStoreError(f"invalid checkpoint id: {checkpoint_id!r}")
        if os.path.isabs(checkpoint_id):
            raise CheckpointStoreError(f"invalid checkpoint id: {checkpoint_id!r}")
        candidate = self.storage_path / f"{checkpoint_id}.json"
        try:
            resolved = candidate.resolve()
        except OSError as error:  # pragma: no cover - platform dependent
            raise CheckpointStoreError(f"invalid checkpoint id: {checkpoint_id!r}") from error
        root = self.storage_path.resolve()
        if not resolved.is_relative_to(root):
            raise CheckpointStoreError(f"invalid checkpoint id: {checkpoint_id!r}")
        return resolved

    def _queue_for(self, path: Path) -> _WriteQueue:
        with self._queues_guard:
            queue = self._queues.get(path)
            if queue is None:
                queue = _WriteQueue()
                self._queues[path] = queue
            return queue

    # -- writing ---------------------------------------------------------

    def _write_atomic(self, file_path: Path, payload: Mapping[str, Any]) -> None:
        """Write the payload so the destination is never seen half-written.

        The temporary file is created with ``O_CREAT | O_EXCL`` so two writers
        can never share one, it lives in the destination directory so the
        rename stays on one filesystem, and it is fsynced before the rename so
        the rename publishes the *content*, not just the name.
        """
        tmp_path: Path | None = None
        try:
            tmp_name = f".northstar-ckpt-{uuid.uuid4().hex}.tmp"
            tmp_path = file_path.parent / tmp_name
            fd = os.open(tmp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                handle = os.fdopen(fd, "w", encoding="utf-8")
            except BaseException:
                os.close(fd)
                raise
            with handle:
                json.dump(payload, handle, sort_keys=True, ensure_ascii=False, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, file_path)
            tmp_path = None
        finally:
            if tmp_path is not None and tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:  # pragma: no cover - best-effort cleanup
                    pass

    def save(self, checkpoint_id: str, payload: Mapping[str, Any]) -> str:
        """Store ``payload`` under ``checkpoint_id``; returns the id."""
        if not isinstance(payload, Mapping):
            raise CheckpointStoreError("checkpoint payload must be a mapping")
        file_path = self._validate_file_path(checkpoint_id)
        queue = self._queue_for(file_path)
        predecessor, own = queue.acquire()
        if predecessor is not None:
            predecessor.wait()
        try:
            self._write_atomic(file_path, dict(payload))
        finally:
            queue.release(own)
        return checkpoint_id

    # -- reading ---------------------------------------------------------

    def load(self, checkpoint_id: str) -> dict[str, Any]:
        """Read the payload stored under ``checkpoint_id``."""
        file_path = self._validate_file_path(checkpoint_id)
        if not file_path.exists():
            raise CheckpointStoreError(f"no checkpoint stored under {checkpoint_id!r}")
        try:
            raw = json.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise CheckpointStoreError(f"checkpoint {checkpoint_id!r} is unreadable") from error
        return self._decode(raw, checkpoint_id)

    def list_ids(self) -> tuple[str, ...]:
        """Every stored checkpoint id, sorted."""
        ids: list[str] = []
        for entry in self.storage_path.iterdir():
            if not entry.name.endswith(".json") or entry.name.startswith("."):
                continue
            ids.append(entry.name[: -len(".json")])
        return tuple(sorted(ids))

    # -- decoding --------------------------------------------------------

    def _decode(self, raw: Any, checkpoint_id: str) -> dict[str, Any]:
        """Decode a payload, refusing types that are not on the allowlist."""
        decoded = self._decode_value(raw, checkpoint_id)
        if not isinstance(decoded, dict):
            raise CheckpointStoreError(f"checkpoint {checkpoint_id!r} does not hold a mapping")
        return decoded

    def _decode_value(self, value: Any, checkpoint_id: str) -> Any:
        if isinstance(value, dict):
            marker = value.get("__type__")
            if marker is not None:
                if not isinstance(marker, str) or marker not in self._allowed_types:
                    raise CheckpointStoreError(
                        f"checkpoint {checkpoint_id!r} carries an unregistered type {marker!r}: "
                        "register it with register_checkpoint_type before restoring it"
                    )
            return {str(key): self._decode_value(item, checkpoint_id) for key, item in value.items()}
        if isinstance(value, list):
            return [self._decode_value(item, checkpoint_id) for item in value]
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        raise CheckpointStoreError(
            f"checkpoint {checkpoint_id!r} carries a value of unsupported type {type(value).__name__}"
        )


__all__ = [
    "CheckpointStoreError",
    "FileCheckpointStorage",
    "allowed_types",
    "register_checkpoint_type",
]
