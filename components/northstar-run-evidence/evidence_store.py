"""File-backed evidence store: durable appends, tamper-evident reload, sealed manifests.

This is the persistence layer the in-memory :class:`EvidenceChain` deliberately
left out. One JSONL file holds one run's chain: each line is the canonical JSON
of an :class:`EvidenceEntry`, validated on every open. A store detects
modification of *its own* file; it does not stop an attacker who can replace
the whole file *and* every copy of the sealed manifest - authenticity comes
from a trusted signer's seal over the manifest, verified separately.

Honest limits, stated up front:

- **Local POSIX filesystem required.** ``flock`` serializes cooperating writers;
  each append rewrites the bounded ledger to a same-directory temporary file,
  fsyncs it, and atomically replaces the prior snapshot. This is O(n) per append.
- **No confidentiality.** The file is plaintext JSONL. Secrets do not belong in
  evidence subjects.
- **Signatures are only as trustworthy as the key resolver.** The bundled
  :class:`HmacTestSigner` is a *test* signer: a shared-secret MAC proves nothing
  about non-repudiation, and test keys must never sign anything real. Production
  deployments inject their own :class:`SealSigner` (HSM, KMS, age, Sigstore -
  the host's choice) and resolve ``key_id`` through infrastructure they trust.
  An unknown ``key_id`` verifies as *unknown authenticity*, never as ok.
- **No trusted timestamp.** ``sealed_at`` is a caller-supplied Unix epoch; it is
  covered by the signature so it cannot be altered afterwards, but it is not an
  independent proof of *when* sealing happened.
"""
from __future__ import annotations

import base64
import errno
import binascii
import hashlib
import hmac
import json
import os
import secrets
import stat
import time
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from contextlib import contextmanager
from pathlib import Path

from evidence_chain import ChainVerification, EvidenceChain, verify_chain
from evidence_contract import (
    EvidenceEntry,
    EvidenceRef,
    canonical_json,
    _digest as _check_digest,
    _identifier,
)

MANIFEST_SCHEMA_VERSION = "northstar.evidence-manifest.v1"
_SEALED_AT_MAX = (1 << 53) - 1


class SealSigner(Protocol):
    """Something the host trusts to attest to a sealed manifest's bytes."""

    @property
    def key_id(self) -> str: ...
    @property
    def algorithm(self) -> str: ...
    def sign(self, data: bytes) -> bytes: ...


class SealVerifier(Protocol):
    """The checking half of a seal; resolved from ``key_id`` by the host."""

    @property
    def key_id(self) -> str: ...
    @property
    def algorithm(self) -> str: ...
    def verify(self, data: bytes, signature: bytes) -> bool: ...


class HmacTestSigner:
    """Shared-secret HMAC signer for tests and local diagnostics only.

    A MAC authenticates to whoever holds the same secret - it is *not*
    non-repudiation, and a test key must never seal real evidence. Production
    signers are injected by the host; see the module docstring.
    """

    algorithm = "hmac-sha256-test"

    def __init__(self, key_id: str, secret: bytes) -> None:
        self._key_id = _identifier(key_id, "key_id")
        if not isinstance(secret, bytes) or len(secret) < 16:
            raise ValueError("secret must be bytes of at least 16 bytes")
        self._secret = bytes(secret)

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, data: bytes) -> bytes:
        return hmac.new(self._secret, data, hashlib.sha256).digest()

    def verifier(self) -> "HmacTestVerifier":
        return HmacTestVerifier(self._key_id, self._secret)


class HmacTestVerifier:
    """Checking half of :class:`HmacTestSigner`; test-only, same caveats."""

    algorithm = HmacTestSigner.algorithm

    def __init__(self, key_id: str, secret: bytes) -> None:
        self._key_id = _identifier(key_id, "key_id")
        self._secret = bytes(secret)

    @property
    def key_id(self) -> str:
        return self._key_id

    def verify(self, data: bytes, signature: bytes) -> bool:
        expected = hmac.new(self._secret, data, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)


def _manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    """Canonical bytes covered by a seal: everything except ``signature``."""
    body = {key: value for key, value in manifest.items() if key != "signature"}
    return canonical_json(body)


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"manifest {field} must be a non-empty base64 string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as error:
        raise ValueError(f"manifest {field} is not valid base64") from error


@dataclass(frozen=True)
class ManifestVerification:
    """Machine-readable result of checking a sealed manifest."""

    ok: bool
    authenticity: str  # "verified" | "unknown-key" | "bad-signature" | "malformed"
    key_id: str | None
    head_digest: str | None
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "authenticity": self.authenticity,
            "key_id": self.key_id,
            "head_digest": self.head_digest,
            "errors": list(self.errors),
        }


def verify_manifest(
    manifest: Any,
    key_resolver: Mapping[str, SealVerifier],
) -> ManifestVerification:
    """Check a sealed manifest's shape and signature. Never trusts blindly.

    Unknown ``key_id`` yields ``authenticity="unknown-key"`` (``ok=False``):
    an unrecognized signer is *not* a verified seal. This function checks the
    seal over the manifest bytes only; binding the manifest to actual store
    contents (head digest, entry count) is :meth:`EvidenceStore.verify_seal`.
    """
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ManifestVerification(False, "malformed", None, None,
                                    ("manifest must be an object",))
    expected = {
        "schema_version", "run_id", "head_digest", "entry_count",
        "sealed_at", "signer", "signature",
    }
    if set(manifest) != expected:
        missing = sorted(expected - set(manifest))
        unknown = sorted(set(manifest) - expected)
        if missing:
            errors.append(f"missing fields: {', '.join(missing)}")
        if unknown:
            errors.append(f"unknown fields: {', '.join(unknown)}")
    head_digest = manifest.get("head_digest")
    if errors:
        return ManifestVerification(False, "malformed", None,
                                    head_digest if isinstance(head_digest, str) else None,
                                    tuple(errors))
    try:
        if manifest["schema_version"] != MANIFEST_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {MANIFEST_SCHEMA_VERSION}")
        _identifier(manifest["run_id"], "run_id")
        entry_count = manifest["entry_count"]
        if not isinstance(entry_count, int) or isinstance(entry_count, bool) or entry_count <= 0:
            raise ValueError("entry_count must be a positive integer")
        sealed_at = manifest["sealed_at"]
        if not isinstance(sealed_at, int) or isinstance(sealed_at, bool):
            raise ValueError("sealed_at must be an integer Unix epoch")
        if not 0 < sealed_at <= _SEALED_AT_MAX:
            raise ValueError("sealed_at is out of range")
        signer = manifest["signer"]
        if not isinstance(signer, dict) or set(signer) != {"key_id", "algorithm"}:
            raise ValueError("signer must be an object with key_id and algorithm")
        key_id = _identifier(signer["key_id"], "signer.key_id")
        if not isinstance(signer["algorithm"], str) or not signer["algorithm"]:
            raise ValueError("signer.algorithm must be a non-empty string")
        _check_digest(head_digest, "head_digest")
        signature = _b64decode(manifest["signature"], "signature")
        signed = _manifest_bytes(manifest)
    except (ValueError, TypeError, AttributeError, RecursionError) as error:
        return ManifestVerification(False, "malformed", None,
                                    head_digest if isinstance(head_digest, str) else None,
                                    (f"malformed manifest: {error}",))

    verifier = key_resolver.get(key_id)
    if verifier is None:
        return ManifestVerification(False, "unknown-key", key_id, head_digest,
                                    (f"key_id {key_id!r} is not trusted by this resolver",))
    try:
        if verifier.key_id != key_id:
            return ManifestVerification(False, "bad-signature", key_id, head_digest,
                                        ("resolved verifier key_id does not match signer.key_id",))
        if verifier.algorithm != signer["algorithm"]:
            return ManifestVerification(False, "bad-signature", key_id, head_digest,
                                        ("resolved verifier algorithm does not match signer.algorithm",))
        valid = verifier.verify(signed, signature)
    except Exception as error:  # a hostile verifier must not crash the check
        return ManifestVerification(False, "bad-signature", key_id, head_digest,
                                    (f"verifier raised: {error}",))
    if not valid:
        return ManifestVerification(False, "bad-signature", key_id, head_digest,
                                    ("signature does not match manifest content",))
    return ManifestVerification(True, "verified", key_id, head_digest, ())



try:  # POSIX-only persistence; constructor rejects unsupported systems.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None  # type: ignore[assignment]

MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_LEDGER_ENTRY_BYTES = 128 * 1024
MAX_JSON_DEPTH = 64
LEDGER_FILENAME = "ledger.jsonl"  # compatibility constant; instances use their configured path name
_LOCK_FILENAME = ".ledger.lock"
_TEMP_PREFIX = ".ledger-"
_TEMP_SUFFIX = ".tmp"

class EvidenceStoreError(ValueError):
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
    """Persist one run's ledger at the configured path.

    The parent directory must be owned by the current user and not group/world
    writable. It is pinned and accessed through a directory file descriptor.
    Lock, ledger, and temporary files use mode 0600.
    The caller must use a local POSIX filesystem that honors ``flock``, ``fsync``,
    and same-directory atomic ``os.replace`` semantics.
    """

    def __init__(self, path: str | os.PathLike[str], run_id: str) -> None:
        if fcntl is None or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise EvidenceStoreError("evidence store requires POSIX flock, O_NOFOLLOW, and O_DIRECTORY")
        self.run_id = _identifier(run_id, "run_id")
        if self.run_id in {".", ".."}:
            raise ValueError("run_id must not be a dot path component")
        raw_path = os.fsdecode(os.fspath(path))
        self._path = Path(os.path.abspath(os.path.expanduser(raw_path)))
        self._ledger_name = self._path.name
        if not self._ledger_name or self._ledger_name in {".", ".."}:
            raise ValueError("path must name an evidence ledger file")
        self.root = self._path.parent
        self.run_dir = self.root  # pinned storage directory; retained for diagnostics/tests
        self.ledger_path = self._path
        # Validate/create the hierarchy once. Each later operation reopens it
        # with no-follow directory-relative calls and pins the final directory FD.
        run_fd = self._open_run_directory()
        os.close(run_fd)
        # Preserve fail-closed-on-open behavior for any existing ledger.
        self.load()

    @property
    def path(self) -> str:
        """Absolute path to the configured evidence JSONL file."""
        return str(self._path)

    @property
    def entries(self) -> tuple[EvidenceEntry, ...]:
        return self.load()

    @property
    def entry_count(self) -> int:
        return len(self.load())

    @property
    def head_digest(self) -> str | None:
        entries = self.load()
        return entries[-1].entry_digest if entries else None

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

            result = root_fd
            root_fd = -1
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
            info = os.stat(self._ledger_name, dir_fd=run_fd, follow_symlinks=False)
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
            descriptor = os.open(self._ledger_name, flags, dir_fd=run_fd)
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
            current = os.stat(self._ledger_name, dir_fd=run_fd, follow_symlinks=False)
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
                    f"ledger line {line_number} is not a valid entry: {error}",
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
                self._ledger_name,
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

    def seal(self, signer: SealSigner, *, sealed_at: int | None = None) -> dict[str, Any]:
        """Sign a manifest bound to one verified snapshot of this chain."""
        entries = self.load()
        if not entries:
            raise ValueError("cannot seal an empty evidence chain")
        if sealed_at is None:
            sealed_at = int(time.time())
        if not isinstance(sealed_at, int) or isinstance(sealed_at, bool):
            raise ValueError("sealed_at must be an integer Unix epoch")
        if not 0 < sealed_at <= _SEALED_AT_MAX:
            raise ValueError("sealed_at is out of range")
        key_id = _identifier(signer.key_id, "signer.key_id")
        algorithm = signer.algorithm
        if not isinstance(algorithm, str) or not algorithm:
            raise ValueError("signer.algorithm must be a non-empty string")
        manifest: dict[str, Any] = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "run_id": self.run_id,
            "head_digest": entries[-1].entry_digest,
            "entry_count": len(entries),
            "sealed_at": sealed_at,
            "signer": {"key_id": key_id, "algorithm": algorithm},
        }
        manifest["signature"] = _b64encode(signer.sign(_manifest_bytes(manifest)))
        return manifest

    def verify_seal(
        self,
        manifest: Mapping[str, Any],
        key_resolver: Mapping[str, SealVerifier],
    ) -> ManifestVerification:
        """Verify signature and bind it to one intact snapshot of this store."""
        result = verify_manifest(manifest, key_resolver)
        if not result.ok:
            return result
        entries = self.load()
        head = entries[-1].entry_digest if entries else None
        mismatches: list[str] = []
        if manifest.get("run_id") != self.run_id:
            mismatches.append("manifest run_id does not match this store")
        if manifest.get("head_digest") != head:
            mismatches.append("manifest head_digest does not match this store's head")
        if manifest.get("entry_count") != len(entries):
            mismatches.append("manifest entry_count does not match this store")
        if mismatches:
            return ManifestVerification(False, "bad-signature", result.key_id,
                                        result.head_digest, tuple(mismatches))
        return result
