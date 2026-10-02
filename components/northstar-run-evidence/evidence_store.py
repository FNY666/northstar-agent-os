"""Private, atomic local persistence for Northstar evidence hash chains.

The store is deliberately local and POSIX-only in this first implementation.
Each append rewrites the bounded ledger to a same-directory temporary file,
fsyncs it, then atomically replaces ``ledger.jsonl`` while holding an advisory
cross-process lock. This is O(n) per append but avoids exposing a torn JSONL
record: after a crash readers see the previous complete ledger or the new one.
Persisted appends require ``source_id`` so a caller can safely retry after an
uncertain post-rename durability result. A valid chain does not authenticate
its producer or prevent replacement of the complete ledger.
"""
from __future__ import annotations

import errno
import json
import os
import secrets
import stat
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

try:  # Keep imports available elsewhere; constructor rejects unsupported systems.
    import fcntl
except ImportError:  # pragma: no cover - exercised only on non-POSIX platforms
    fcntl = None  # type: ignore[assignment]

from evidence_chain import ChainVerification, EvidenceChain, verify_chain
from evidence_contract import EvidenceEntry, EvidenceRef, _identifier

MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_LEDGER_ENTRY_BYTES = 128 * 1024
MAX_JSON_DEPTH = 64
LEDGER_FILENAME = "ledger.jsonl"
_LOCK_FILENAME = ".ledger.lock"
_TEMP_PREFIX = ".ledger-"
_TEMP_SUFFIX = ".tmp"


class EvidenceStoreError(RuntimeError):
    """Operational error while accessing the local evidence store."""


class EvidenceIntegrityError(EvidenceStoreError):
    """Stored ledger is malformed, non-canonical, or fails chain validation."""

    def __init__(
        self,
        message: str,
        *,
        entries_checked: int = 0,
        head_digest: str | None = None,
    ) -> None:
        super().__init__(message)
        self.entries_checked = entries_checked
        self.head_digest = head_digest


class EvidenceCommitUncertainError(EvidenceStoreError):
    """Rename succeeded, but directory fsync failed and crash durability is unknown."""


class EvidenceStore:
    """Persist one run's ledger under ``root/<run_id>/ledger.jsonl``.

    ``root`` must be owned by the current user and not group/world writable. The
    per-run directory is pinned and accessed through a directory file descriptor;
    it is forced to mode 0700. Lock, ledger, and temporary files use mode 0600.
    The caller must use a local POSIX filesystem that honors ``flock``, ``fsync``,
    and same-directory atomic ``os.replace`` semantics.
    """

    def __init__(self, root: str | Path, run_id: str) -> None:
        if fcntl is None or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise EvidenceStoreError("evidence store requires POSIX flock, O_NOFOLLOW, and O_DIRECTORY")
        self.run_id = _identifier(run_id, "run_id")
        if self.run_id in {".", ".."}:
            raise ValueError("run_id must not be a dot path component")
        self.root = Path(os.path.abspath(os.path.expanduser(os.fspath(root))))
        self.run_dir = self.root / self.run_id
        self.ledger_path = self.run_dir / LEDGER_FILENAME
        # Validate/create the hierarchy once. Each later operation reopens it
        # with no-follow directory-relative calls and keeps the run fd pinned.
        run_fd = self._open_run_directory()
        os.close(run_fd)

    @staticmethod
    def _directory_flags() -> int:
        return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)

    @classmethod
    def _open_or_create_directory(cls, parent_fd: int, name: str) -> int:
        flags = cls._directory_flags()
        try:
            return os.open(name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            try:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                # Another cooperating process may have created it; the no-follow
                # open and ownership checks below remain authoritative.
                pass
            return os.open(name, flags, dir_fd=parent_fd)

    def _open_run_directory(self) -> int:
        root_fd = -1
        run_fd = -1
        try:
            root_fd = os.open(os.sep, self._directory_flags())
            for part in self.root.parts[1:]:
                next_fd = self._open_or_create_directory(root_fd, part)
                os.close(root_fd)
                root_fd = next_fd

            root_info = os.fstat(root_fd)
            if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.geteuid():
                raise EvidenceStoreError("evidence root must be a directory owned by the current user")
            if root_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise EvidenceStoreError("evidence root must not be group/world writable")

            run_fd = self._open_or_create_directory(root_fd, self.run_id)
            run_info = os.fstat(run_fd)
            if not stat.S_ISDIR(run_info.st_mode) or run_info.st_uid != os.geteuid():
                raise EvidenceStoreError("run directory must be owned by the current user")
            os.fchmod(run_fd, 0o700)
            result = run_fd
            run_fd = -1
            return result
        except EvidenceStoreError:
            raise
        except OSError as error:
            raise EvidenceStoreError(
                "evidence directory hierarchy contains a symlink/non-directory or could not be opened safely"
            ) from error
        finally:
            if run_fd >= 0:
                os.close(run_fd)
            if root_fd >= 0:
                os.close(root_fd)

    @contextmanager
    def _locked(self) -> Iterator[int]:
        run_fd = self._open_run_directory()
        lock_fd = -1
        acquired = False
        try:
            flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            try:
                lock_fd = os.open(_LOCK_FILENAME, flags, 0o600, dir_fd=run_fd)
                info = os.fstat(lock_fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != os.geteuid()
                ):
                    raise EvidenceStoreError("evidence lock must be a single-link regular file owned by the current user")
                os.fchmod(lock_fd, 0o600)
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                acquired = True
            except EvidenceStoreError:
                raise
            except OSError as error:
                raise EvidenceStoreError("evidence store lock could not be opened safely") from error

            self._cleanup_stale_temps_locked(run_fd)
            yield run_fd
        finally:
            if acquired:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
                    os.close(run_fd)
            else:
                if lock_fd >= 0:
                    os.close(lock_fd)
                os.close(run_fd)

    def _cleanup_stale_temps_locked(self, run_fd: int) -> None:
        try:
            names = os.listdir(run_fd)
            for name in names:
                if not name.startswith(_TEMP_PREFIX) or not name.endswith(_TEMP_SUFFIX):
                    continue
                try:
                    info = os.stat(name, dir_fd=run_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    os.unlink(name, dir_fd=run_fd)
        except OSError as error:
            raise EvidenceStoreError("stale ledger temporary files could not be inspected") from error

    def _read_ledger_bytes_locked(self, run_fd: int) -> bytes | None:
        try:
            info = os.stat(LEDGER_FILENAME, dir_fd=run_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise EvidenceStoreError("ledger metadata could not be read") from error
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
        ):
            raise EvidenceIntegrityError("ledger must be a single-link regular file owned by the current user")
        if info.st_size > MAX_LEDGER_BYTES:
            raise EvidenceIntegrityError(f"ledger exceeds the {MAX_LEDGER_BYTES}-byte limit")

        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(LEDGER_FILENAME, flags, dir_fd=run_fd)
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOENT}:
                raise EvidenceIntegrityError("ledger changed while being opened safely") from error
            raise EvidenceStoreError("ledger could not be opened") from error
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_uid != os.geteuid()
                or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
            ):
                raise EvidenceIntegrityError("ledger changed or is not a single-link regular file")
            os.fchmod(descriptor, 0o600)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, MAX_LEDGER_BYTES - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_LEDGER_BYTES:
                    raise EvidenceIntegrityError(f"ledger exceeds the {MAX_LEDGER_BYTES}-byte limit")
                chunks.append(chunk)
            current = os.stat(LEDGER_FILENAME, dir_fd=run_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise EvidenceIntegrityError("ledger changed while it was being read")
            return b"".join(chunks)
        except EvidenceIntegrityError:
            raise
        except OSError as error:
            raise EvidenceStoreError("ledger could not be read") from error
        finally:
            os.close(descriptor)

    @staticmethod
    def _check_json_depth(line: bytes) -> None:
        depth = 0
        in_string = False
        escaped = False
        for byte in line:
            if in_string:
                if escaped:
                    escaped = False
                elif byte == 0x5C:  # backslash
                    escaped = True
                elif byte == 0x22:  # quote
                    in_string = False
                continue
            if byte == 0x22:
                in_string = True
            elif byte in (0x7B, 0x5B):  # { [
                depth += 1
                if depth > MAX_JSON_DEPTH:
                    raise ValueError(f"JSON nesting exceeds the {MAX_JSON_DEPTH}-level limit")
            elif byte in (0x7D, 0x5D):  # } ]
                depth -= 1
                if depth < 0:
                    raise ValueError("JSON nesting is malformed")

    def _read_snapshot_locked(self, run_fd: int) -> tuple[tuple[EvidenceEntry, ...], bytes | None]:
        raw = self._read_ledger_bytes_locked(run_fd)
        if raw is None:
            return (), None
        if raw == b"":
            raise EvidenceIntegrityError("ledger file is empty; refusing to treat it as a new chain")
        if not raw.endswith(b"\n"):
            raise EvidenceIntegrityError("ledger is missing its final newline")

        entries: list[EvidenceEntry] = []
        for line_number, line in enumerate(raw[:-1].split(b"\n"), start=1):
            if not line:
                raise EvidenceIntegrityError(
                    f"ledger contains a blank line at line {line_number}",
                    entries_checked=len(entries),
                )
            if len(line) > MAX_LEDGER_ENTRY_BYTES:
                raise EvidenceIntegrityError(
                    f"ledger line {line_number} exceeds the {MAX_LEDGER_ENTRY_BYTES}-byte limit",
                    entries_checked=len(entries),
                )
            try:
                self._check_json_depth(line)
                value = json.loads(line.decode("utf-8"))
                entry = EvidenceEntry.from_dict(value)
                if entry.canonical_json() != line:
                    raise ValueError("entry is not encoded as canonical JSON")
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError) as error:
                raise EvidenceIntegrityError(
                    f"ledger line {line_number} is invalid: {error}",
                    entries_checked=len(entries),
                ) from error
            entries.append(entry)

        report = verify_chain(entries, expected_run_id=self.run_id)
        if not report.ok:
            raise EvidenceIntegrityError(
                "ledger hash chain is invalid: " + "; ".join(report.errors),
                entries_checked=report.entries_checked,
                head_digest=report.head_digest,
            )
        return tuple(entries), raw

    def _replace_ledger_locked(
        self,
        entries: Iterable[EvidenceEntry],
        *,
        run_fd: int,
        expected_previous: bytes | None,
    ) -> None:
        payload = b"".join(entry.canonical_json() + b"\n" for entry in entries)
        if len(payload) > MAX_LEDGER_BYTES:
            raise EvidenceStoreError(f"new ledger would exceed the {MAX_LEDGER_BYTES}-byte limit")
        actual_previous = self._read_ledger_bytes_locked(run_fd)
        if actual_previous != expected_previous:
            raise EvidenceIntegrityError("ledger changed while append was being prepared")

        temporary_name: str | None = None
        temporary_fd = -1
        replaced = False
        try:
            for _ in range(10):
                candidate = f"{_TEMP_PREFIX}{secrets.token_hex(12)}{_TEMP_SUFFIX}"
                try:
                    temporary_fd = os.open(
                        candidate,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                        0o600,
                        dir_fd=run_fd,
                    )
                    temporary_name = candidate
                    break
                except FileExistsError:
                    continue
            if temporary_fd < 0 or temporary_name is None:
                raise EvidenceStoreError("a unique ledger temporary file could not be created")

            os.fchmod(temporary_fd, 0o600)
            view = memoryview(payload)
            while view:
                written = os.write(temporary_fd, view)
                if written <= 0:
                    raise OSError("short write while persisting ledger")
                view = view[written:]
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = -1

            os.replace(
                temporary_name,
                LEDGER_FILENAME,
                src_dir_fd=run_fd,
                dst_dir_fd=run_fd,
            )
            temporary_name = None
            replaced = True
            try:
                os.fsync(run_fd)
            except OSError as error:
                raise EvidenceCommitUncertainError(
                    "ledger rename succeeded but directory fsync failed; retry using the same source_id"
                ) from error
        except EvidenceStoreError:
            raise
        except OSError as error:
            if replaced:
                raise EvidenceCommitUncertainError(
                    "ledger was replaced but post-rename durability is uncertain; retry using the same source_id"
                ) from error
            raise EvidenceStoreError("ledger replacement failed before rename; previous ledger is unchanged") from error
        finally:
            if temporary_fd >= 0:
                os.close(temporary_fd)
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=run_fd)
                except FileNotFoundError:
                    pass
                except OSError:
                    pass

    def load(self) -> tuple[EvidenceEntry, ...]:
        """Load a fully parsed and verified immutable snapshot of this run's ledger."""
        with self._locked() as run_fd:
            return self._read_snapshot_locked(run_fd)[0]

    def verify(self) -> ChainVerification:
        """Return structural integrity results; malformed bytes fail closed."""
        with self._locked() as run_fd:
            try:
                entries, _ = self._read_snapshot_locked(run_fd)
            except EvidenceIntegrityError as error:
                return ChainVerification(
                    ok=False,
                    run_id=self.run_id,
                    entries_checked=error.entries_checked,
                    head_digest=error.head_digest,
                    errors=(str(error),),
                )
            return verify_chain(entries, expected_run_id=self.run_id)

    def append(
        self,
        *,
        source: str,
        kind: str,
        occurred_at: int,
        subject: Mapping[str, Any] | bytes,
        source_id: str,
        refs: Iterable[EvidenceRef] = (),
    ) -> EvidenceEntry:
        """Create and atomically persist an entry; ``source_id`` is required for safe retries."""
        if source_id is None:
            raise ValueError("source_id is required for durable append and retry safety")
        with self._locked() as run_fd:
            current, previous_bytes = self._read_snapshot_locked(run_fd)
            chain = EvidenceChain(self.run_id, current)
            entry = chain.append(
                source=source,
                kind=kind,
                occurred_at=occurred_at,
                subject=subject,
                refs=refs,
                source_id=source_id,
            )
            updated = chain.entries
            if len(updated) != len(current):
                self._replace_ledger_locked(
                    updated,
                    run_fd=run_fd,
                    expected_previous=previous_bytes,
                )
            return entry

    def append_entry(self, entry: EvidenceEntry | Mapping[str, Any]) -> EvidenceEntry:
        """Atomically append a prebuilt entry with a stable idempotency ``source_id``."""
        if isinstance(entry, EvidenceEntry):
            source_id = entry.source_id
        elif isinstance(entry, Mapping):
            source_id = entry.get("source_id")
        else:
            source_id = None
        if source_id is None:
            raise ValueError("prebuilt entry must include source_id for durable retry safety")

        with self._locked() as run_fd:
            current, previous_bytes = self._read_snapshot_locked(run_fd)
            chain = EvidenceChain(self.run_id, current)
            appended = chain.append_entry(entry)
            updated = chain.entries
            if len(updated) != len(current):
                self._replace_ledger_locked(
                    updated,
                    run_fd=run_fd,
                    expected_previous=previous_bytes,
                )
            return appended
