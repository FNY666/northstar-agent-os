"""One writer per session file, using the durable-run lease envelope.

Why this exists
---------------
:class:`~sessions.SessionStore` writes with ``O_APPEND`` and fsync, which makes a
*single* process crash-safe. It says nothing about two processes. Before this module,
starting a run with ``--resume <id>`` in two shells at once - or a CI job resuming a
session an operator is still watching - produced one transcript with both runs' records
interleaved, and nothing anywhere said so. The session file is the audit trail; an audit
trail with two uncoordinated writers is not an audit trail, and appending is not the
same thing as *agreeing*.

What is unified with ``northstar-durable-run``
----------------------------------------------
The on-disk envelope is deliberately the same one :class:`runner.LeaseManager` persists:
a private (0600) JSON object with exactly ``owner_id`` and ``expires_at``, the same id
rule, and ttl bounds in seconds. A host that keeps both artefacts reads one shape. The
*arbitration* differs, and the difference is the point:

- the durable runner runs work that can outlive a request, so it declares a lease by
  timestamp and lets expiry reclaim it;
- a runtime process appends to a local file, so it declares a lease by **holding an
  ``flock`` on it**, which the kernel releases when the process dies - no timer, no
  reaping job, and no window in which two live writers both believe they own the file.

Consequences worth stating plainly: a lease **cannot be stolen from a live process**,
however stale its ``expires_at`` looks (kill the holder, or its host, and the lock is
gone); ``expires_at`` is therefore a *promise about liveness* that a reader may use to
judge a run that vanished without releasing, not a reclamation deadline; and the JSON
beside the lock is advisory metadata - the lock is the fact. A reader that parses a
half-written envelope must treat it as "owner unknown", which :func:`inspect_lease` does.

Non-POSIX hosts
---------------
``flock`` is the mechanism. Where ``fcntl`` is unavailable this module **refuses**
rather than degrading to the timestamp dance: a lease that is enforced on one platform
and advisory on another is worse than no lease, because the transcript looks protected.
Callers that genuinely do not need the guarantee pass ``required=False`` (or the CLI's
``--no-session-lease``), and the refusal to hold one is then explicit and reported.
"""
from __future__ import annotations

import errno
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:  # POSIX only; the fallback is a refusal, not a weaker promise
    import fcntl
except ImportError:  # pragma: no cover - platform dependent
    fcntl = None  # type: ignore[assignment]

#: Suffix for the lock file. It sits beside the transcript it protects.
LEASE_SUFFIX = ".lease"

#: "someone else holds it" is EAGAIN on Linux and EWOULDBLOCK on the BSDs; some libcs
#: define them to the same number and some do not, so both spellings are always accepted.
_BUSY_ERRNOS = frozenset({errno.EAGAIN, errno.EWOULDBLOCK})

#: Mirrored from ``northstar-durable-run/runner.py::LeaseManager`` (its ``_read`` requires
#: exactly these two keys and a positive-integer ``expires_at``). The pin lives in
#: ``tests/test_session_lease.py::test_a_durable_reader_would_parse_what_we_write``, which
#: has durable write one and this module read it, rather than a second literal here.
LEASE_FIELDS: frozenset[str] = frozenset({"owner_id", "expires_at"})

#: Same id rule as the durable contract: no whitespace, no path separators. A lease
#: owner has to survive being embedded in a log line and an error message.
MAX_ID_CHARS = 128
ID_RE = re.compile(r"^[^\s/\\]+$")

#: ``LeaseManager``'s rule is only "a positive integer", which is too weak to be useful:
#: a one-second promise expires during any tool call, and a reader then learns nothing
#: except that the holder stopped renewing. The floor is where "expired" still carries
#: information; the ceiling is what nobody should hold a local file claim for.
MIN_LEASE_SECONDS = 5
MAX_LEASE_SECONDS = 24 * 3600
DEFAULT_LEASE_SECONDS = 900

_PRIVATE_MODE = 0o600


class LeaseError(ValueError):
    """The lease could not be used as asked (bad owner id, unusable directory, ...)."""


class SessionBusyError(RuntimeError):
    """Another live process holds this session.

    A :class:`RuntimeError` and not a ``ValueError`` on purpose: "configuration error"
    is the exit-64 family, and this is not a bad request - it is a correct request for a
    session somebody else is writing. A run must not exit as though the operator had
    mistyped a flag.
    """

    def __init__(self, message: str, *, owner_id: str = "", expires_at: int = 0) -> None:
        super().__init__(message)
        self.owner_id = owner_id
        self.expires_at = expires_at


def validate_owner_id(value: Any) -> str:
    """The durable contract's id rule, applied to a lease owner."""
    if not isinstance(value, str) or not value:
        raise LeaseError("owner_id must be a non-empty string")
    if len(value) > MAX_ID_CHARS:
        raise LeaseError(f"owner_id is longer than {MAX_ID_CHARS} characters")
    if not ID_RE.fullmatch(value):
        raise LeaseError("owner_id must not contain whitespace, /, or \\")
    return value


def validate_ttl(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LeaseError("ttl_seconds must be an integer number of seconds")
    if not MIN_LEASE_SECONDS <= value <= MAX_LEASE_SECONDS:
        raise LeaseError(
            f"ttl_seconds must be between {MIN_LEASE_SECONDS} and {MAX_LEASE_SECONDS} "
            f"(got {value}); pass --no-session-lease (lock_session=False) to run without a lease"
        )
    return value


@dataclass(frozen=True)
class LeaseStatus:
    """What can be said about one lease path *right now*, without owning it."""

    path: str
    owner_id: str = ""
    expires_at: int = 0
    locked: bool = False
    kernel_lock_available: bool = True
    metadata_readable: bool = True
    #: False when ``locked`` was never tested (a viewer that reads claims only).
    probed: bool = True

    @property
    def free(self) -> bool:
        """Nothing is *known* to hold it. ``probed=False`` means "unverified", not "free"."""
        return not self.locked

    @property
    def expired(self) -> bool:
        """The holder stopped promising liveness. This never makes it stealable."""
        return bool(self.expires_at) and self.expires_at <= int(time.time())

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "owner_id": self.owner_id,
            "expires_at": self.expires_at,
            "locked": self.locked,
            "expired": self.expired,
            "kernel_lock_available": self.kernel_lock_available,
            "metadata_readable": self.metadata_readable,
            "probed": self.probed,
        }

    def human(self) -> str:
        if not self.probed:
            # A view that took no lock cannot report "free" - it can only repeat the
            # holder's claim and label it as a claim. Conflating the two is how a
            # read-only tool ends up authorising a second writer.
            if not self.owner_id:
                return "no lease recorded"
            claim = f"claims {self.owner_id!r}"
            if self.expires_at:
                claim += f" until {self.expires_at}"
            return f"{claim} (unverified: the lock was not probed)"
        if not self.locked:
            if not self.owner_id:
                return "free"
            tail = " (released, or the holder died without releasing)"
            if self.expired:
                tail = f" (its lease expired at {self.expires_at}{tail})"
            return f"not held{tail} - last owner {self.owner_id!r}"
        return f"held by {self.owner_id!r} until {self.expires_at}"


def _read_metadata(path: Path) -> tuple[str, int, bool]:
    """Best-effort ``(owner_id, expires_at, readable)``; a torn read is not an error."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return "", 0, False
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return "", 0, False
    if not isinstance(value, dict):
        return "", 0, False
    owner = value.get("owner_id")
    expires = value.get("expires_at")
    return (
        owner if isinstance(owner, str) else "",
        expires if isinstance(expires, int) and not isinstance(expires, bool) else 0,
        True,
    )


def _probe_locked(path: Path) -> tuple[bool, bool, bool]:
    """``(locked, kernel_lock_available, metadata_readable)`` for a lease we do not own.

    The probe takes ``LOCK_EX|LOCK_NB`` and drops it immediately. That is safe: a
    successful probe proves no *other* process holds it, and the release happens before
    this returns, so at worst a holder is briefly delayed. On a host without ``fcntl``
    there is no kernel lock to ask about, and callers must learn that rather than assume
    the file's own word.
    """
    if fcntl is None:
        return False, False, True
    try:
        fd = os.open(path, os.O_RDWR)
    except OSError:
        return False, True, False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True, True, True
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False, True, True
    finally:
        os.close(fd)


def inspect_lease(path: str | Path, *, probe: bool = True) -> LeaseStatus:
    """Read-only report on one lease file (never creates it, never steals anything).

    ``probe=False`` reads only what the holder claimed and takes no lock at all, which is
    what a *viewer* should do: briefly holding ``LOCK_EX`` to answer a question could make
    an unrelated run refuse to start. ``locked`` is then reported as ``False`` with the
    meaning "not verified", so callers must present it as a claim rather than a fact -
    which is what :attr:`LeaseStatus.probed` exists to say.
    """
    file_path = Path(path)
    owner, expires, readable = _read_metadata(file_path) if file_path.exists() else ("", 0, True)
    if probe and file_path.exists():
        locked, kernel_available, probe_readable = _probe_locked(file_path)
    else:
        locked, kernel_available, probe_readable = False, fcntl is not None, True
    return LeaseStatus(
        path=str(file_path),
        owner_id=owner,
        expires_at=expires,
        locked=locked,
        kernel_lock_available=kernel_available,
        metadata_readable=readable and probe_readable,
        probed=probe and file_path.exists(),
    )


def _busy_message(path: Path, *, owner_id: str, expires_at: int) -> str:
    """Why the run will not start, with whatever the holder chose to say about itself."""
    session = path.name[: -len(LEASE_SUFFIX)] if path.name.endswith(LEASE_SUFFIX) else path.name
    who = f" (owner {owner_id!r}" if owner_id else " (owner unknown - the holder never finished writing its lease"
    if expires_at:
        who += f", lease renewed until {expires_at}"
    who += ")"
    return (
        f"session {session!r} is being written by another run{who}; wait for it to finish, "
        "or resume from a copy (see --resume-from) - a transcript is append-only so that "
        "forking is cheap, which is not the same as saying two writers may share one file"
    )


def lease_path_for(directory: str | Path, session_id: str) -> Path:
    """``<directory>/<session_id>.lease`` - the sibling of the transcript it guards."""
    validate_owner_id(session_id)
    return Path(directory) / f"{session_id}{LEASE_SUFFIX}"


class SessionLease:
    """An exclusive, kernel-enforced claim on one session file's write path.

    Lifecycle: :meth:`acquire` (fail fast if someone else is live), :meth:`heartbeat`
    once per turn boundary (this is what makes ``expires_at`` meaningful),
    :meth:`release` on the way out. A process that never reaches ``release`` still
    cannot block the world: the lock dies with the descriptor.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        owner_id: str,
        ttl_seconds: int = DEFAULT_LEASE_SECONDS,
        required: bool = True,
        now: int | None = None,
    ) -> None:
        self.path = Path(path)
        self.owner_id = validate_owner_id(owner_id)
        self.ttl_seconds = validate_ttl(ttl_seconds)
        self.required = bool(required)
        self._now = now
        self._fd: int | None = None

    # -- state ------------------------------------------------------------
    @property
    def held(self) -> bool:
        return self._fd is not None

    @property
    def kernel_lock_available(self) -> bool:
        return fcntl is not None

    def status(self) -> LeaseStatus:
        owner, expires, readable = _read_metadata(self.path) if self.path.exists() else ("", 0, True)
        return LeaseStatus(
            path=str(self.path),
            # Parenthesised deliberately: `owner or self.owner_id if self.held else owner`
            # parses as `owner or (self.owner_id if self.held else owner)`, which reports
            # the file's own word even when this object is the one holding the lock.
            owner_id=(owner or self.owner_id) if self.held else owner,
            expires_at=expires or (self._expiry() if self.held else 0),
            locked=True if self.held else self.path.exists() and _probe_locked(self.path)[0],
            kernel_lock_available=self.kernel_lock_available,
            metadata_readable=readable,
            # "we tested the kernel" - which on a host without flock nobody can do, and a
            # status that implied otherwise would be the one lie this struct must never
            # tell (callers read `free` as "unverified" only when `probed` says so).
            probed=fcntl is not None and (self.held or self.path.exists()),
        )

    def _clock(self) -> int:
        """``now`` as whole seconds. A callable is treated as a clock, a number as a fixed reading.

        Both spellings exist so a test can advance time without sleeping and a caller can
        pin one reading for two calls; the durable component's own lease API takes ``now``
        per call, which is the same idea with the state kept outside the object.
        """
        value = self._now() if callable(self._now) else self._now
        return int(value) if value is not None else int(time.time())

    def _expiry(self) -> int:
        return self._clock() + self.ttl_seconds

    # -- lifecycle --------------------------------------------------------
    def acquire(self) -> LeaseStatus:
        if self.held:
            raise LeaseError("this lease is already held")
        if fcntl is None:
            if self.required:
                raise LeaseError(
                    "session leases require fcntl.flock, which this platform does not provide; "
                    "run with --no-session-lease to say that an unprotected transcript is intended"
                )
            return self.status()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise LeaseError(f"cannot create the lease directory: {error}") from error
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, _PRIVATE_MODE)
        except OSError as error:
            raise LeaseError(f"cannot open the lease file {self.path}: {error}") from error
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            # Closed here and nowhere else: a second close in an outer handler could
            # quietly drop an unrelated descriptor, which is a nastier bug than the one
            # it would be "fixing".
            os.close(fd)
            if error.errno not in _BUSY_ERRNOS:
                raise LeaseError(f"cannot lock {self.path}: {error}") from error
            owner, expires, _readable = _read_metadata(self.path)
            raise SessionBusyError(
                _busy_message(self.path, owner_id=owner, expires_at=expires),
                owner_id=owner,
                expires_at=expires,
            ) from error
        self._fd = fd
        try:
            self._write_locked()
        except BaseException:
            self.release()
            raise
        return self.status()

    def _write_locked(self) -> None:
        """Write the envelope on the held descriptor.

        Deliberately in place, with no ``tempfile`` + ``os.replace``: a replace would
        point our lock at an unlinked inode and silently drop mutual exclusion, which is
        the one thing this file exists to provide. A concurrent *reader* can therefore
        catch a partial line, and :func:`_read_metadata` is built for exactly that.
        """
        if self._fd is None:
            return
        body = json.dumps(
            {"owner_id": self.owner_id, "expires_at": self._expiry()},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            os.ftruncate(self._fd, 0)
            os.lseek(self._fd, 0, os.SEEK_SET)
            os.write(self._fd, body + b"\n")
            os.fchmod(self._fd, _PRIVATE_MODE)
            os.fsync(self._fd)
        except OSError as error:
            raise LeaseError(f"cannot persist the lease: {error}") from error

    def heartbeat(self, *, ttl_seconds: int | None = None) -> LeaseStatus:
        """Extend the promise. A no-op when the lease is not held, so the loop can call
        it from a boundary that a refused run never reached."""
        if self._fd is None:
            return self.status()
        if ttl_seconds is not None:
            self.ttl_seconds = validate_ttl(ttl_seconds)
        self._write_locked()
        return self.status()

    def close(self) -> None:
        """Alias for :meth:`release`, so the lease works with ``with``."""
        self.release()

    def __enter__(self) -> "SessionLease":
        self.acquire()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        # Released even when the body raised, which is the whole reason to write it this
        # way: a claim that outlives a crashed ``with`` block is worse than no claim.
        self.release()

    def release(self) -> None:
        """Drop the lock. The envelope is left in place as a trace of the last writer.

        Deleting it would race a waiter that had already opened the path (it would lock a
        file the next creator is about to replace), and the metadata is genuinely useful:
        "who last wrote this session, and until when did it claim to be alive".
        """
        if self._fd is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            try:
                os.close(self._fd)
            finally:
                self._fd = None

    # -- context manager --------------------------------------------------
    def __enter__(self) -> "SessionLease":
        if not self.held:
            self.acquire()
        return self

    def __exit__(self, *exc_info: Any) -> bool:
        self.release()
        return False


def owner_id_for(run_id: str | None, *, session_id: str = "") -> str:
    """The lease owner: the run's own correlation id when it has one.

    Attributing a lock to a ``run_id`` means the error a second operator sees names the
    run that is holding the file, so "who is writing this?" is answerable from the audit
    trail rather than from ``ps``. Without one, a process-unique id is minted: a lease
    with no identifiable holder is how a lock becomes folklore.
    """
    candidate = (run_id or "").strip()
    if candidate and ID_RE.fullmatch(candidate) and len(candidate) <= MAX_ID_CHARS:
        return candidate
    import uuid

    suffix = f"-{session_id}" if session_id and ID_RE.fullmatch(session_id) else ""
    return f"pid{os.getpid()}{suffix}-{uuid.uuid4().hex[:8]}"[:MAX_ID_CHARS]


__all__ = [
    "DEFAULT_LEASE_SECONDS",
    "LEASE_FIELDS",
    "LEASE_SUFFIX",
    "MAX_LEASE_SECONDS",
    "MIN_LEASE_SECONDS",
    "LeaseError",
    "LeaseStatus",
    "SessionBusyError",
    "SessionLease",
    "inspect_lease",
    "lease_path_for",
    "owner_id_for",
    "validate_owner_id",
    "validate_ttl",
]
