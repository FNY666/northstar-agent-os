"""Workspace memory integrity manifest, outside the agent-writable carve-out.

The manifest detects content changes made after a tool-mediated memory write.
It is not a signature: a host actor able to rewrite both memory and this file can
replace the baseline too. Its purpose is to make ordinary out-of-band edits
visible and to keep the agent's Write/Edit tools from silently rewriting trust.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

try:  # Windows does not ship fcntl; report a deliberate capability error below.
    import fcntl
except ImportError:  # pragma: no cover - exercised by the simulated portability test
    fcntl = None  # type: ignore[assignment]

SCHEMA = "northstar.memory-integrity.v1"
MANIFEST_NAME = "memory-integrity.json"
MAX_MANIFEST_BYTES = 1024 * 1024
DEFAULT_MEMORY_WRITE_LOCK_TIMEOUT_SECONDS = 5.0


class MemoryIntegrityError(ValueError):
    """The baseline is malformed or memory no longer matches its pinned bytes."""


def _require_secure_update_support() -> None:
    """Reject hosts missing the descriptor and lock primitives this writer needs."""
    # os.replace has src/dst dir_fd support on POSIX but is not listed in
    # os.supports_dir_fd on some CPython builds; os.rename is its advertised
    # equivalent capability probe there.
    dir_fd_calls = (os.open, os.rename, os.unlink)
    if (
        fcntl is None
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or any(call not in os.supports_dir_fd for call in dir_fd_calls)
    ):
        raise MemoryIntegrityError(
            "secure memory integrity updates require POSIX directory descriptors, "
            "O_NOFOLLOW, O_DIRECTORY, and flock on this host"
        )


def _manifest_path(workspace: str | Path) -> Path:
    return Path(workspace).resolve() / ".northstar" / MANIFEST_NAME


@contextmanager
def memory_write_lock(
    workspace: str | Path,
    *,
    timeout_seconds: float = DEFAULT_MEMORY_WRITE_LOCK_TIMEOUT_SECONDS,
) -> Iterator[None]:
    """Serialize managed-memory transactions with a bounded wait."""
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise ValueError("memory write lock timeout must be a positive number of seconds")
    try:
        timeout = float(timeout_seconds)
    except OverflowError as error:
        raise ValueError("memory write lock timeout must be finite") from error
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("memory write lock timeout must be a finite positive number of seconds")
    _require_secure_update_support()
    parent = Path(workspace).resolve() / ".northstar"
    if parent.is_symlink():
        raise MemoryIntegrityError("refusing a symlinked .northstar directory")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if parent.is_symlink():
        raise MemoryIntegrityError("refusing a symlinked .northstar directory")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        dir_fd = os.open(parent, flags)
    except OSError as error:
        raise MemoryIntegrityError(f"cannot safely open .northstar for memory write: {error}") from error
    lock_fd: int | None = None
    try:
        try:
            lock_fd = os.open(
                ".memory-write.lock",
                os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=dir_fd,
            )
        except OSError as error:
            raise MemoryIntegrityError(f"cannot safely open managed-memory write lock: {error}") from error
        if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
            raise MemoryIntegrityError("memory write lock is not a regular file")
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise MemoryIntegrityError(
                        f"timed out after {timeout:g}s waiting for managed-memory write lock"
                    )
                time.sleep(min(0.01, remaining))
            except OSError as error:
                raise MemoryIntegrityError(f"cannot acquire managed-memory write lock: {error}") from error
        yield
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(dir_fd)


def _load(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        dir_fd = os.open(path.parent, directory_flags)
    except FileNotFoundError:
        return {"schema": SCHEMA, "entries": {}}
    except OSError as error:
        raise MemoryIntegrityError(f"cannot safely open .northstar for memory integrity: {error}") from error
    try:
        try:
            fd = os.open(path.name, flags, dir_fd=dir_fd)
        except FileNotFoundError:
            return {"schema": SCHEMA, "entries": {}}
        except OSError as error:
            raise MemoryIntegrityError(f"cannot safely open memory integrity manifest: {error}") from error
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_MANIFEST_BYTES:
                raise MemoryIntegrityError("memory integrity manifest is not a bounded regular file")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_MANIFEST_BYTES + 1)
        finally:
            os.close(fd)
    finally:
        os.close(dir_fd)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise MemoryIntegrityError("memory integrity manifest exceeds its size limit")
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON constant {value}")

    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise MemoryIntegrityError(f"memory integrity manifest is not valid UTF-8 JSON: {error}") from error
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA or not isinstance(payload.get("entries"), dict):
        raise MemoryIntegrityError(f"memory integrity manifest must use {SCHEMA}")
    from memory import is_memory_write_path

    for relative, entry in payload["entries"].items():
        if not isinstance(relative, str) or not isinstance(entry, dict):
            raise MemoryIntegrityError("memory integrity manifest contains a malformed entry")
        entry_path = Path(relative)
        if entry_path.is_absolute() or ".." in entry_path.parts or not is_memory_write_path(entry_path.parts):
            raise MemoryIntegrityError(f"memory integrity entry {relative!r} is outside the memory carve-out")
        digest = entry.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise MemoryIntegrityError(f"memory integrity entry {relative!r} has an invalid SHA-256")
    return payload


def verify_memory_bytes(workspace: str | Path, relative_path: str, raw: bytes | None) -> str:
    """Return ``verified`` or ``unverified``; raise when a pinned file differs."""
    from memory import is_memory_write_path

    relative = Path(relative_path)
    normalized = relative.as_posix()
    if ".." in relative.parts or not is_memory_write_path(relative.parts):
        raise MemoryIntegrityError("integrity checks only accept workspace memory paths")
    entries = _load(_manifest_path(workspace))["entries"]
    entry = entries.get(normalized)
    if entry is None:
        return "unverified"
    if raw is None:
        raise MemoryIntegrityError(f"pinned memory file {normalized} is missing")
    actual = hashlib.sha256(raw).hexdigest()
    if actual != entry["sha256"]:
        raise MemoryIntegrityError(f"memory integrity check failed for {normalized}; restore or review it outside the agent")
    return "verified"


def record_memory_bytes(
    workspace: str | Path,
    relative_path: str,
    raw: bytes,
    *,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Atomically stage the expected bytes in the protected side manifest."""
    _require_secure_update_support()
    from memory import is_memory_write_path

    relative = Path(relative_path)
    normalized = relative.as_posix()
    if not is_memory_write_path(relative.parts) or ".." in relative.parts:
        raise MemoryIntegrityError("integrity records only accept workspace memory paths")
    target = _manifest_path(workspace)
    parent = target.parent
    if parent.is_symlink():
        raise MemoryIntegrityError("refusing a symlinked .northstar directory")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if parent.is_symlink():
        raise MemoryIntegrityError("refusing a symlinked .northstar directory")
    entry: dict[str, Any] = {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}
    if provenance:
        entry["provenance"] = provenance

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        dir_fd = os.open(parent, flags)
    except OSError as error:
        raise MemoryIntegrityError(f"cannot safely open .northstar: {error}") from error
    temp = f".{MANIFEST_NAME}.{uuid.uuid4().hex}.tmp"
    lock_fd: int | None = None
    try:
        lock_fd = os.open(
            ".memory-integrity.lock",
            os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=dir_fd,
        )
        if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
            raise MemoryIntegrityError("memory integrity lock is not a regular file")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        payload = _load(target)
        payload["entries"][normalized] = entry
        try:
            serialized = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
        except (TypeError, ValueError) as error:
            raise MemoryIntegrityError(f"memory integrity entry is not strict JSON: {error}") from error
        encoded = (serialized + "\n").encode("utf-8")
        if len(encoded) > MAX_MANIFEST_BYTES:
            raise MemoryIntegrityError("memory integrity manifest would exceed its size limit")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=dir_fd)
        try:
            remaining = memoryview(encoded)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError("short write while updating memory integrity manifest")
                remaining = remaining[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temp, MANIFEST_NAME, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        os.fsync(dir_fd)
    except OSError as error:
        try:
            os.unlink(temp, dir_fd=dir_fd)
        except OSError:
            pass
        raise MemoryIntegrityError(f"cannot atomically update memory integrity manifest: {error}") from error
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(dir_fd)
    return entry


__all__ = [
    "MANIFEST_NAME",
    "MemoryIntegrityError",
    "SCHEMA",
    "DEFAULT_MEMORY_WRITE_LOCK_TIMEOUT_SECONDS",
    "memory_write_lock",
    "record_memory_bytes",
    "verify_memory_bytes",
]
