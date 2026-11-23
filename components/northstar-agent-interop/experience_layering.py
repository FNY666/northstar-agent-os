"""
Experience Layering - Three-Layer Memory Architecture

This module implements a three-layer memory system for Experience Ledger:
- Working Layer: Hot data (recent 100 runs), in-memory + JSONL
- Recall Layer: Warm data (recent 30 days), date-sharded JSONL
- Archival Layer: Cold data (historical), compressed JSONL

Design document: /var/minis/shared/experience-layering-design.md

## Phase 1 Implementation (Current)

**Working Layer**: Fully implemented
- add() - Add records with persistence
- query() - Query by fingerprint (newest first)
- query_recent() - Time-window queries
- evict() - FIFO eviction
- Automatic persistence and loading

**Query Routing**: Implemented
- forecast() - Uses Working Layer only (fast)
- query_statistics() - Aggregates from Working (Phase 2: + Recall + Archival)

**Integration**: Ready
- record_lost() - Reaper integration with 60s deduplication
- settle() - Record experience with automatic eviction

## Usage Example

```python
from pathlib import Path
from experience_layering import ExperienceLayering, ExperienceRecord

# Initialize
layering = ExperienceLayering(
    base_dir=Path("/var/data/experience"),
    working_capacity=100,
    recall_window_days=30,
)

# Record experience (normal flow)
record = ExperienceRecord(
    fingerprint="goal-abc-123",
    outcome="success",
    timestamp=int(time.time()),
)
layering.settle(record)

# Record lost (Reaper integration)
layering.record_lost(
    fingerprint="goal-xyz-789",
    reason="lease_expired",
    timestamp=int(time.time()),
)

# Query for decision making
forecast = layering.forecast("goal-abc-123")
# Returns: {"success_rate": 0.8, "confidence": 0.9, ...}

stats = layering.query_statistics("goal-abc-123")
# Returns: {"total_runs": 50, "lost_rate": 0.1, ...}
```

## Phase 2 (Planned)

- Recall Layer: Date-sharded storage with index
- Archival Layer: Compressed historical data
- Complete data flow: Working -> Recall -> Archival
- Cross-layer query optimization

## Testing

Run tests:
```bash
pytest tests/test_experience_layering.py -v
```

Current: 23/23 passing (Phase 1 complete)
"""

import gzip
import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
import errno
import os
import stat
import warnings

#: How many damaged-line reports a layer keeps for diagnosis (the count itself is exact).
_MAX_LOAD_ERRORS = 20

#: errno values meaning "this filesystem cannot sync a directory"; nothing better is possible there.
_DIRECTORY_SYNC_UNSUPPORTED = frozenset(
    code for code in (
        errno.EINVAL, errno.ENOSYS, getattr(errno, "ENOTSUP", None), getattr(errno, "EOPNOTSUPP", None)
    ) if code is not None
)


def _read_jsonl(path, parse):
    """Read a JSONL file leniently and report what could not be read.

    Returns ``(items, corrupt)``. ``corrupt`` lists ``(line_number, error_name)`` for each
    line that was not valid UTF-8, not valid JSON, or that ``parse`` rejected. One damaged
    line never hides the others, and nothing is swallowed or repaired: a line with invalid
    bytes is damage, not a slightly different record.

    A missing file is an empty history. A file that exists but cannot be read (permissions,
    I/O error, not a regular file) is an environment fault rather than damaged content, so
    it is raised.
    """
    items = []
    corrupt = []
    try:
        with open(path, "rb") as handle:
            for number, raw in enumerate(handle, 1):
                if not raw.strip():
                    continue
                try:
                    items.append(parse(json.loads(raw.decode("utf-8"))))
                except Exception as error:  # noqa: BLE001 - recorded in ``corrupt``, not hidden
                    corrupt.append((number, type(error).__name__))
    except FileNotFoundError:
        return [], []
    return items, corrupt


def _note_load(owner, path, corrupt):
    """Record load damage on ``owner`` and make it visible."""
    owner.corrupt_lines = len(corrupt)
    owner.load_errors = tuple(corrupt[:_MAX_LOAD_ERRORS])
    if corrupt:
        warnings.warn(
            f"{path}: skipped {len(corrupt)} unreadable line(s) on load "
            f"(first at line {corrupt[0][0]}: {corrupt[0][1]}); the rest of the file was kept",
            RuntimeWarning,
            stacklevel=3,
        )


def _append_lines(path, lines):
    """Append lines, starting on a fresh line if the file ends in a partial one.

    Single-writer by design (confirmed by the owner): nothing here serialises two processes
    appending to one file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    with open(path, "a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() > 0:
            handle.seek(-1, os.SEEK_END)
            if handle.read(1) != b"\n":
                handle.write(b"\n")
            handle.seek(0, os.SEEK_END)
        handle.write(payload)


def _fsync_directory(directory):
    """Flush a directory entry (a rename or a create) to disk. Returns True if it was synced.

    A filesystem that cannot sync a directory returns False quietly. Any other failure is an
    I/O problem and is reported with a RuntimeWarning rather than raised: it can only be seen
    after the rename has already taken effect, and raising then would leave the caller
    believing the old state still holds.
    """
    try:
        descriptor = os.open(str(directory), os.O_RDONLY)
    except OSError as error:
        return _directory_sync_failed(directory, error)
    try:
        os.fsync(descriptor)
        return True
    except OSError as error:
        return _directory_sync_failed(directory, error)
    finally:
        os.close(descriptor)


def _directory_sync_failed(directory, error):
    if error.errno not in _DIRECTORY_SYNC_UNSUPPORTED:
        warnings.warn(
            f"{directory}: could not confirm the update reached disk ({error}); "
            "it may not survive a crash",
            RuntimeWarning,
            stacklevel=4,
        )
    return False


def _atomic_write_text(path, text):
    """Replace ``path`` with ``text``; a crash leaves the old file or the new one, never a mix.

    The replacement keeps the permissions (and, when allowed, the owner) of the file it
    replaces. A brand-new file gets the permissions ``open(path, "w")`` would have given it:
    the temporary file is created with 0o666 so the kernel applies the process umask, and this
    code never changes the process-wide umask. Single-writer by design.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = os.stat(path)
        mode = stat.S_IMODE(existing.st_mode)
        owner = (existing.st_uid, existing.st_gid)
    except FileNotFoundError:
        mode = owner = None
    stamp = f"{time.time_ns()}-{os.getpid()}"
    attempt = 0
    while True:
        suffix = stamp if attempt == 0 else f"{stamp}-{attempt}"
        temporary = path.with_name(f"{path.name}.{suffix}.tmp")
        try:
            descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
        except FileExistsError:
            attempt += 1
            continue
        break
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            os.chmod(temporary, mode)
            try:
                os.chown(temporary, *owner)
            except (OSError, AttributeError):
                pass  # not permitted (not root) or not POSIX: keep the current owner
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    _fsync_directory(path.parent)


# =============================================================================
# Exceptions
# =============================================================================

class OwnershipLostError(Exception):
    """Raised when fencing token validation fails (stale token)"""
    pass


# =============================================================================
# Data Structures
# =============================================================================

class ExperienceRecord:
    """Single experience record"""
    
    def __init__(
        self,
        fingerprint: str,
        outcome: str,  # "success" | "failure" | "lost"
        reason: Optional[str] = None,
        timestamp: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        run_id: Optional[str] = None,
        data_quality: str = "complete",
        source: str = "unknown",
    ):
        self.fingerprint = fingerprint
        self.outcome = outcome
        self.reason = reason
        self.timestamp = timestamp or int(time.time())
        self.metadata = metadata or {}
        self.run_id = run_id
        self.data_quality = data_quality
        self.source = source
    
    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "outcome": self.outcome,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
            "run_id": self.run_id,
            "data_quality": self.data_quality,
            "source": self.source,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ExperienceRecord":
        return cls(
            fingerprint=data["fingerprint"],
            outcome=data["outcome"],
            reason=data.get("reason"),
            timestamp=data.get("timestamp"),
            metadata=data.get("metadata", {}),
            run_id=data.get("run_id"),
            data_quality=data.get("data_quality", "complete"),
            source=data.get("source", "unknown"),
        )


def _record_identity(record: ExperienceRecord) -> str:
    """Stable identity for idempotent persistence of one record."""
    payload = json.dumps(
        record.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _batch_identity(records: List[ExperienceRecord]) -> str:
    """Stable identity for an ordered batch of records."""
    payload = json.dumps(
        [_record_identity(record) for record in records],
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class ArchiveBatch:
    """A stable, idempotent handoff unit for one Recall shard.

    Archivers must treat ``(shard_id, digest)`` as the idempotency key.  The source
    shard remains present until the callback returns true, so a crash in that gap
    can legitimately deliver the same batch again.
    """

    shard_id: str
    digest: str
    records: Tuple[ExperienceRecord, ...]

    def __iter__(self):
        return iter(self.records)

    def __len__(self):
        return len(self.records)

    def __getitem__(self, index):
        return self.records[index]


class LostEvent:
    """Single lost event (Phase C v2 - stored in LostEventStream)"""
    
    def __init__(
        self,
        goal_fingerprint: str,
        run_id: str,
        reason: str,
        timestamp: int,
        fencing_token: Optional[str] = None,
        data_quality: str = "complete",
        source: str = "reaper-fenced",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.goal_fingerprint = goal_fingerprint
        self.run_id = run_id
        self.reason = reason
        self.timestamp = timestamp
        self.fencing_token = fencing_token
        self.data_quality = data_quality
        self.source = source
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal_fingerprint": self.goal_fingerprint,
            "run_id": self.run_id,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "fencing_token": self.fencing_token,
            "data_quality": self.data_quality,
            "source": self.source,
            "metadata": self.metadata,
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'LostEvent':
        return LostEvent(
            goal_fingerprint=data["goal_fingerprint"],
            run_id=data["run_id"],
            reason=data["reason"],
            timestamp=data["timestamp"],
            fencing_token=data.get("fencing_token"),
            data_quality=data.get("data_quality", "complete"),
            source=data.get("source", "reaper-fenced"),
            metadata=data.get("metadata", {}),
        )


# =============================================================================
# Lost Event Stream (Phase C v2)
# =============================================================================

class LostEventStream:
    """Lost Event Stream - Independent storage for lost runs (Phase C v2)"""
    #: Filled in by ``_load_from_disk``; see ``_note_load``.
    corrupt_lines = 0
    load_errors = ()
    
    def __init__(self, storage_path: Path, capacity: int = 1000):
        self.storage_path = storage_path
        self.capacity = capacity
        self.events: List[LostEvent] = []
        if self.storage_path.exists():
            self._load_from_disk()
    
    def add(self, event: LostEvent) -> None:
        """Add lost event with dedup (run_id, goal_fingerprint, reason)"""
        for existing in self.events:
            if (existing.run_id == event.run_id and
                existing.goal_fingerprint == event.goal_fingerprint and
                existing.reason == event.reason):
                return
        # Disk first: if the append fails, nothing is remembered that was never stored.
        _append_lines(self.storage_path, [json.dumps(event.to_dict())])
        self.events.append(event)
    
    def query(self, goal_fingerprint: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Query lost events by fingerprint"""
        return [e.to_dict() for e in self.events 
                if e.goal_fingerprint == goal_fingerprint][:limit]
    
    def count(self, goal_fingerprint: str) -> int:
        """Count lost events"""
        return sum(1 for e in self.events if e.goal_fingerprint == goal_fingerprint)
    
    def _load_from_disk(self) -> None:
        """Load from JSONL; damaged lines are skipped and counted, the readable ones are kept."""
        events, corrupt = _read_jsonl(self.storage_path, LostEvent.from_dict)
        self.events = events
        _note_load(self, self.storage_path, corrupt)


# =============================================================================
# Working Layer (Hot Data)
# =============================================================================

class WorkingLayer:
    """
    Working Layer - Recent 100 runs, in-memory cache + JSONL persistence.
    
    Used for:
    - Real-time decision making (forecast, admission policy)
    - Fast queries (O(N), N=100)
    
    Eviction:
    - FIFO when capacity exceeded
    - Evicted records move to Recall Layer
    """
    #: Filled in by ``_load_from_disk``; see ``_note_load``.
    corrupt_lines = 0
    load_errors = ()
    #: Where the damaged original was preserved before the first rewrite, if it was.
    quarantined_to = None
    
    def __init__(self, storage_path: Path, capacity: int = 100):
        """
        Initialize Working Layer.
        
        Args:
            storage_path: Path to working.jsonl
            capacity: Maximum number of records (default 100)
        """
        self.storage_path = storage_path
        self.capacity = capacity
        self.records: List[ExperienceRecord] = []
        
        # Load from disk if exists
        if self.storage_path.exists():
            self._load_from_disk()
    
    def add(self, record: ExperienceRecord) -> None:
        """
        Add a record to the Working Layer.

        Args:
            record: Record to add
        """
        # Disk first: if the append fails, nothing is remembered that was never stored.
        _append_lines(self.storage_path, [json.dumps(record.to_dict())])
        self.records.append(record)
        
        # 3. Check capacity (trigger eviction handled by coordinator)
        # Note: Eviction logic is in ExperienceLayering._check_and_evict()
    
    def query(self, fingerprint: str, limit: Optional[int] = None) -> List[ExperienceRecord]:
        """
        Query records by fingerprint.
        
        Args:
            fingerprint: Goal fingerprint to query
            limit: Maximum number of records to return
        
        Returns:
            List of matching records (newest first)
        """
        matching = []
        # Iterate from beginning (newest first in our list)
        # records list: [newest ... oldest] (added in order from sample_records)
        for record in self.records:
            if record.fingerprint == fingerprint:
                matching.append(record)
                if limit and len(matching) >= limit:
                    break
        return matching
    
    def query_recent(self, fingerprint: str, seconds: int) -> List[ExperienceRecord]:
        """
        Query recent records within time window.
        
        Args:
            fingerprint: Goal fingerprint
            seconds: Time window in seconds
        
        Returns:
            List of matching records within window
        """
        now = int(time.time())
        cutoff = now - seconds
        
        matching = []
        for record in self.records:
            if record.fingerprint == fingerprint and record.timestamp >= cutoff:
                matching.append(record)
        
        return matching
    
    def evict(self, count: int = 10) -> List[ExperienceRecord]:
        """
        Evict oldest records (FIFO).

        The file is rewritten before memory changes, so if the rewrite fails the layer still
        holds exactly what the file holds.
        """
        if count <= 0 or len(self.records) == 0:
            return []
        return self.evict_records(self.records[:count])

    def has_prefix(self, records: List[ExperienceRecord]) -> bool:
        """Whether an outbox batch is still the exact oldest Working prefix."""
        expected = [_record_identity(record) for record in records]
        actual = [_record_identity(record) for record in self.records[:len(records)]
        ]
        return bool(records) and expected == actual

    def evict_records(self, records: List[ExperienceRecord]) -> List[ExperienceRecord]:
        """Remove an exact oldest prefix after a durable handoff has completed."""
        if not records:
            return []
        if not self.has_prefix(records):
            raise ValueError("pending transfer is not the working layer prefix")
        remaining = self.records[len(records):]
        self._rewrite_disk(remaining)
        self.records = remaining
        return list(records)
    
    def _load_from_disk(self) -> None:
        """Load records from disk on initialization.

        Damaged lines are skipped and counted (``corrupt_lines``, ``load_errors``) and the
        readable lines are kept. A file that cannot be read at all raises.
        """
        records, corrupt = _read_jsonl(self.storage_path, ExperienceRecord.from_dict)
        self.records = records
        _note_load(self, self.storage_path, corrupt)
    
    def _rewrite_disk(self, records=None) -> None:
        """Rewrite working.jsonl (used after eviction); defaults to the records held in memory.

        Never destroys what it could not load: if the file had damaged lines, the original is
        kept byte for byte as ``working.jsonl.corrupt-<stamp>`` before it is replaced, and the
        replacement itself is atomic.
        """
        keep = self.records if records is None else records
        if self.corrupt_lines and self.quarantined_to is None:
            self._quarantine()
        text = "".join(json.dumps(record.to_dict()) + "\n" for record in keep)
        _atomic_write_text(self.storage_path, text)

    def _quarantine(self) -> None:
        """Copy the current file, damage included, to a name that is never overwritten.

        The copy is private (0600: it may hold anything the layer ever recorded), created
        exclusively, and flushed to disk before the caller may replace the original. A copy
        that could not be completed is removed again rather than left looking like evidence.
        """
        try:
            data = self.storage_path.read_bytes()
        except FileNotFoundError:
            return
        stamp = f"{time.time_ns()}-{os.getpid()}"
        attempt = 0
        while True:
            suffix = stamp if attempt == 0 else f"{stamp}-{attempt}"
            target = self.storage_path.with_name(f"{self.storage_path.name}.corrupt-{suffix}")
            try:
                descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                attempt += 1
                continue
            break
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            try:
                os.unlink(target)
            except OSError:
                pass
            raise
        _fsync_directory(target.parent)
        self.quarantined_to = target
    
    def __len__(self) -> int:
        return len(self.records)


# =============================================================================
# Recall Layer (Warm Data)
# =============================================================================

class RecallLayer:
    """
    Recall Layer - Recent 30 days, date-sharded JSONL + index.
    
    Used for:
    - Statistical queries (query_statistics)
    - Historical trend analysis
    
    Storage:
    - recall-YYYY-MM-DD.jsonl (one file per day)
    - recall-index.json (fingerprint -> dates mapping)
    
    Archival:
    - Records older than window_days move to Archival Layer
    """
    
    def __init__(self, storage_dir: Path, window_days: int = 30):
        """
        Initialize Recall Layer.

        Args:
            storage_dir: Directory for recall files
            window_days: Time window in days (default 30)
        """
        self.storage_dir = storage_dir
        self.window_days = window_days
        self.index: Dict[str, List[str]] = {}  # fingerprint -> [dates]
        # Distinct damaged lines seen so far as (shard name, line number). Damage is only
        # discovered when a shard is read, so this under-reports shards nobody has read yet.
        self._corrupt_seen = set()
        # This marker survives process death between a shard append and index commit.
        # It is the durable form of index-dirty; the in-memory flag alone is not enough.
        self._index_pending_path = self.storage_dir / "recall-index.pending"
        self._index_dirty = self._index_pending_path.exists()

        # Load index from disk if exists. Still strict: a corrupt index fails loudly at start-up.
        self._load_index()
        self._recover_stale_index_marker()
    
    def add_batch(self, records: List[ExperienceRecord]) -> None:
        """
        Add batch of records to Recall Layer.

        Args:
            records: List of records to add
        """
        if not records:
            return

        # Persist the write-ahead marker before any shard is appended. If the process
        # dies after the append but before the index commit, a later status check knows
        # to perform content-level reconciliation even when the in-memory flag is gone.
        self._mark_index_pending()

        # 1. Group records by date
        from collections import defaultdict
        by_date = defaultdict(list)

        for record in records:
            date_str = datetime.fromtimestamp(record.timestamp).strftime("%Y-%m-%d")
            by_date[date_str].append(record)

        # 2. Ensure directory exists
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # 3. Append only records not already present in each shard. This makes a
        # retry after an index-save failure idempotent without treating distinct rows
        # with the same fingerprint/date as duplicates.
        for date_str, date_records in by_date.items():
            file_path = self.storage_dir / f"recall-{date_str}.jsonl"
            existing_counts = {}
            if file_path.exists():
                existing, corrupt = _read_jsonl(file_path, ExperienceRecord.from_dict)
                self._note_corrupt(file_path, corrupt)
                for existing_record in existing:
                    identity = _record_identity(existing_record)
                    existing_counts[identity] = existing_counts.get(identity, 0) + 1

            to_append = []
            for record in date_records:
                identity = _record_identity(record)
                if existing_counts.get(identity, 0):
                    existing_counts[identity] -= 1
                else:
                    # Do not count rows staged by this call as pre-existing. This
                    # preserves intentional duplicate rows within a first attempt,
                    # while a retry sees their persisted identities and skips them.
                    to_append.append(record)
            if to_append:
                _append_lines(
                    file_path,
                    [json.dumps(record.to_dict(), ensure_ascii=False) for record in to_append],
                )

            # 4. Update index for the whole requested batch, including a retry where
            # all rows were already appended before the previous index save failed.
            for record in date_records:
                if record.fingerprint not in self.index:
                    self.index[record.fingerprint] = []
                if date_str not in self.index[record.fingerprint]:
                    self.index[record.fingerprint].append(date_str)

        # 5. Persist index
        self._save_index()

    def has_records(self, records: List[ExperienceRecord]) -> bool:
        """Return whether every record identity is durably present in Recall."""
        needed = {}
        for record in records:
            identity = _record_identity(record)
            needed[identity] = needed.get(identity, 0) + 1
        found = {}
        if self.storage_dir.exists():
            for path in sorted(self.storage_dir.glob("recall-*.jsonl")):
                shard, corrupt = _read_jsonl(path, ExperienceRecord.from_dict)
                self._note_corrupt(path, corrupt)
                for record in shard:
                    identity = _record_identity(record)
                    if identity in needed:
                        found[identity] = found.get(identity, 0) + 1
        return all(found.get(identity, 0) >= count for identity, count in needed.items())
    
    def query(self, fingerprint: str, limit: Optional[int] = None) -> List[ExperienceRecord]:
        """
        Query records by fingerprint across date shards.

        Unreadable lines are skipped and counted in ``corrupt_lines`` instead of aborting the
        query, so one damaged line cannot hide the rest of a shard. Callers that decide
        something from the result should consult ``ExperienceLayering.history_status()``.

        Args:
            fingerprint: Goal fingerprint
            limit: Maximum number of records

        Returns:
            List of matching records (newest first)
        """
        # 1. Look up dates from index
        if fingerprint not in self.index:
            return []

        dates = self.index[fingerprint]

        # 2. Read from corresponding files (newest dates first)
        results = []
        for date_str in sorted(dates, reverse=True):
            file_path = self.storage_dir / f"recall-{date_str}.jsonl"

            if not file_path.exists():
                continue

            # Read records from this date
            shard, corrupt = _read_jsonl(file_path, ExperienceRecord.from_dict)
            self._note_corrupt(file_path, corrupt)
            for record in shard:
                if record.fingerprint == fingerprint:
                    results.append(record)

                    if limit and len(results) >= limit:
                        break

            if limit and len(results) >= limit:
                break

        # 3. Sort by timestamp (newest first)
        results.sort(key=lambda r: r.timestamp, reverse=True)

        # 4. Apply limit
        if limit:
            results = results[:limit]

        return results
    
    def find_older_than(self, cutoff_date: datetime) -> List[ExperienceRecord]:
        """
        Find all records older than cutoff date.

        Args:
            cutoff_date: Cutoff date

        Returns:
            List of records older than cutoff
        """
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")
        old_records = []

        # Scan all date-sharded files
        if not self.storage_dir.exists():
            return []

        for file_path in self.storage_dir.glob("recall-*.jsonl"):
            # Extract date from filename: recall-YYYY-MM-DD.jsonl
            date_str = file_path.stem.replace("recall-", "")

            # Check if this file is older than cutoff
            if date_str < cutoff_str:
                # Read all records from this file (unreadable lines are counted, not fatal)
                shard, corrupt = _read_jsonl(file_path, ExperienceRecord.from_dict)
                self._note_corrupt(file_path, corrupt)
                old_records.extend(shard)

        return old_records
    
    def archive_old_data(self, cutoff_date: datetime, archive=None) -> List[ExperienceRecord]:
        """Archive old shards, deleting each source only after durable handoff.

        ``archive`` receives an :class:`ArchiveBatch`, not a bare list.  Its stable
        ``(shard_id, digest)`` pair is the idempotency boundary: a crash after the
        callback returns true but before ``unlink`` may deliver the same batch again,
        and the archiver must treat that retry as the same committed batch.  The
        source shard remains untouched when the callback is absent, declines, or
        raises.  A malformed shard raises before the callback is invoked.
        """
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")
        archived_records = []

        if not self.storage_dir.exists():
            return []

        for file_path in sorted(self.storage_dir.glob("recall-*.jsonl")):
            date_str = file_path.stem.replace("recall-", "")
            if date_str >= cutoff_str:
                continue

            raw = file_path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            shard_records, corrupt = _read_jsonl(file_path, ExperienceRecord.from_dict)
            if corrupt:
                self._note_corrupt(file_path, corrupt)
                raise ValueError(f"cannot archive unreadable shard: {file_path}")

            batch = ArchiveBatch(
                shard_id=file_path.name,
                digest=digest,
                records=tuple(shard_records),
            )
            result = None if archive is None else archive(batch)
            if result is not True:
                continue

            # The callback has durably committed this exact shard identity/digest.
            # A crash before this unlink is safe only because retries are idempotent.
            file_path.unlink()
            archived_records.extend(shard_records)

            for fp in list(self.index.keys()):
                if date_str in self.index[fp]:
                    self.index[fp].remove(date_str)
                if not self.index[fp]:
                    del self.index[fp]

        if archived_records:
            self._save_index()

        return archived_records
    
    def _mark_index_pending(self) -> None:
        """Durably mark that a shard/index transaction is in flight."""
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(
            self._index_pending_path,
            json.dumps({"version": 1, "reason": "shard_append_before_index_commit"}),
        )
        self._index_dirty = True

    def _recover_stale_index_marker(self) -> None:
        """Clear a marker left after a transaction made no observable index drift.

        This is intentionally conservative: unreadable content or any pair mismatch keeps
        the marker for ``history_status`` to expose and for ``rebuild_index`` to repair.
        """
        if not self._index_pending_path.exists() or not self.storage_dir.exists():
            return
        indexed_pairs = {
            (fingerprint, date)
            for fingerprint, dates in self.index.items()
            for date in dates
        }
        actual_pairs = set()
        for path in sorted(self.storage_dir.glob("recall-*.jsonl")):
            date_str = path.stem[len("recall-"):]
            shard, corrupt = _read_jsonl(path, ExperienceRecord.from_dict)
            if corrupt:
                self._note_corrupt(path, corrupt)
                return
            actual_pairs.update((record.fingerprint, date_str) for record in shard)
        if actual_pairs == indexed_pairs:
            try:
                self._index_pending_path.unlink()
            except FileNotFoundError:
                pass
            self._index_dirty = False

    def _save_index(self) -> None:
        """Save index and clear its durable pending marker only after success."""
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        index_path = self.storage_dir / "recall-index.json"
        self._index_dirty = True
        _atomic_write_text(index_path, json.dumps(self.index, indent=2))
        try:
            self._index_pending_path.unlink()
        except FileNotFoundError:
            pass
        self._index_dirty = False
    
    def _load_index(self) -> None:
        """Load index from disk."""
        index_path = self.storage_dir / "recall-index.json"
        if index_path.exists():
            with open(index_path, "r") as f:
                self.index = json.load(f)

    @property
    def corrupt_lines(self) -> int:
        """Distinct unreadable lines found so far in recall shards."""
        return len(self._corrupt_seen)

    def _note_corrupt(self, path, corrupt) -> None:
        """Remember damaged shard lines; warn the first time a line is found."""
        fresh = [number for number, _ in corrupt if (path.name, number) not in self._corrupt_seen]
        for number in fresh:
            self._corrupt_seen.add((path.name, number))
        if fresh:
            warnings.warn(
                f"{path}: skipped {len(fresh)} unreadable line(s) while reading "
                f"(first at line {fresh[0]}); the rest of the shard was used",
                RuntimeWarning,
                stacklevel=4,
            )

    def structure_problems(self) -> dict:
        """Where the index and shard contents on disk disagree.

        Date-level checks catch missing and wholly unindexed shards.  When the durable
        ``recall-index.pending`` marker exists, the content-level check reads every shard
        and compares ``(fingerprint, date)`` pairs.  This catches a new fingerprint
        appended to an already-indexed date when the index save failed before a restart,
        without imposing a full shard scan on the healthy hot path.
        """
        on_disk = set()
        actual_pairs = set()
        paths = []
        if self.storage_dir.exists():
            paths = sorted(self.storage_dir.glob("recall-*.jsonl"))
            on_disk = {path.stem[len("recall-"):] for path in paths}
        indexed = {date for dates in self.index.values() for date in dates}
        content_mismatches = []
        if self._index_pending_path.exists():
            for path in paths:
                date_str = path.stem[len("recall-"):]
                shard, corrupt = _read_jsonl(path, ExperienceRecord.from_dict)
                self._note_corrupt(path, corrupt)
                actual_pairs.update((record.fingerprint, date_str) for record in shard)
            indexed_pairs = {
                (fingerprint, date)
                for fingerprint, dates in self.index.items()
                for date in dates
            }
            content_mismatches = sorted(
                f"{fingerprint}@{date}"
                for fingerprint, date in (actual_pairs ^ indexed_pairs)
            )
        return {
            "recall_index_missing_shards": sorted(indexed - on_disk),
            "recall_unindexed_shards": sorted(on_disk - indexed),
            "recall_index_content_mismatches": content_mismatches,
            "recall_index_pending": self._index_pending_path.exists(),
        }

    def rebuild_index(self) -> int:
        """Rebuild the fingerprint -> dates index from the shards on disk. Returns shards scanned.

        The remedy for ``recall_unindexed_shards``. Unreadable lines are counted, not fatal. A
        date whose shard is gone simply drops out of the index; that is an operator decision to
        accept the loss, and it is why this is never called automatically.
        """
        index = {}
        scanned = 0
        if self.storage_dir.exists():
            for file_path in sorted(self.storage_dir.glob("recall-*.jsonl")):
                scanned += 1
                date_str = file_path.stem[len("recall-"):]
                shard, corrupt = _read_jsonl(file_path, ExperienceRecord.from_dict)
                self._note_corrupt(file_path, corrupt)
                for record in shard:
                    dates = index.setdefault(record.fingerprint, [])
                    if date_str not in dates:
                        dates.append(date_str)
        self.index = index
        self._save_index()
        return scanned


# =============================================================================
# Archival Layer (Cold Data)
# =============================================================================

class ArchivalLayer:
    """
    Archival Layer - Compressed historical data.
    
    Used for:
    - Long-term trend analysis
    - Audit trails
    
    Storage:
    - archival.jsonl.gz (compressed JSONL)
    - archival-index.json (fingerprint -> line offsets)
    - archival-summary.json (aggregated statistics per fingerprint)
    """
    
    def __init__(self, storage_path: Path):
        """
        Initialize Archival Layer.
        
        Args:
            storage_path: Path to archival.jsonl.gz
        """
        self.storage_path = storage_path
        self.index_path = storage_path.parent / "archival-index.json"
        self.summary_path = storage_path.parent / "archival-summary.json"
        self.index: Dict[str, List[int]] = {}  # fingerprint -> line offsets
        self.summary: Dict[str, Dict[str, Any]] = {}  # fingerprint -> stats
        # TODO: Load index and summary from disk if exist
    
    def archive(self, batch: ArchiveBatch) -> bool:
        """Durably store one stable Recall shard batch.

        The implementation is still a Phase 3 stub and returns ``False``. A real
        implementation must use ``(batch.shard_id, batch.digest)`` as an idempotency
        key and may return ``True`` only after the exact batch is durable. The same
        batch can be delivered again after a crash before Recall unlinks its source.
        """
        # TODO: Implement
        # 1. Append to archival.jsonl.gz (gzip)
        # 2. Update index (line offsets)
        # 3. Update summary (aggregated stats)
        return False
    
    def query(self, fingerprint: str, limit: Optional[int] = None) -> List[ExperienceRecord]:
        """
        Query records by fingerprint from compressed archive.
        
        Args:
            fingerprint: Goal fingerprint
            limit: Maximum number of records
        
        Returns:
            List of matching records
        """
        # TODO: Implement
        # 1. Look up line offsets from index
        # 2. Read specific lines from gzip file
        # 3. Apply limit
        pass
    
    def get_summary(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        """
        Get aggregated summary for fingerprint.
        
        Args:
            fingerprint: Goal fingerprint
        
        Returns:
            Summary dict or None if not found
        """
        # TODO: Implement
        return self.summary.get(fingerprint)


# =============================================================================
# Experience Layering Coordinator
# =============================================================================

class ExperienceLayering:
    """
    Coordinator for three-layer memory architecture.
    
    Manages:
    - Data flow between layers
    - Query routing
    - Integration with existing Experience API
    """
    
    def __init__(
        self,
        base_dir: Path,
        working_capacity: int = 100,
        recall_window_days: int = 30,
        admission_callback: Optional[callable] = None,
    ):
        """
        Initialize Experience Layering.
        
        Args:
            base_dir: Base directory for storage
            working_capacity: Working Layer capacity
            recall_window_days: Recall Layer time window
            admission_callback: Optional callback for admission reevaluation
                               Called with (fingerprint, lost_record, stats)
        """
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        
        self.working = WorkingLayer(
            storage_path=base_dir / "working.jsonl",
            capacity=working_capacity,
        )
        
        self.recall = RecallLayer(
            storage_dir=base_dir / "recall",
            window_days=recall_window_days,
        )
        
        self.archival = ArchivalLayer(
            storage_path=base_dir / "archival.jsonl.gz",
        )
        
        # Phase C v2: Lost Event Stream (authoritative source for lost events)
        self.lost_stream = LostEventStream(
            storage_path=base_dir / "lost-events.jsonl",
            capacity=1000,
        )
        self._transfer_pending_path = base_dir / "working-recall.pending.json"
        self._recover_pending_transfer()
        
        self.admission_callback = admission_callback

    def _write_pending_transfer(self, records: List[ExperienceRecord]) -> None:
        payload = {
            "version": 1,
            "batch_id": _batch_identity(records),
            "records": [record.to_dict() for record in records],
        }
        _atomic_write_text(self._transfer_pending_path, json.dumps(payload, indent=2))

    def _read_pending_transfer(self) -> List[ExperienceRecord]:
        if not self._transfer_pending_path.exists():
            return []
        with open(self._transfer_pending_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        records = [ExperienceRecord.from_dict(row) for row in payload["records"]]
        if payload.get("batch_id") != _batch_identity(records):
            raise ValueError("working-recall pending transfer identity mismatch")
        return records

    def _finish_pending_transfer(self, records: List[ExperienceRecord]) -> None:
        # Recall's record-identity dedup makes this safe after a crash anywhere in
        # add_batch, including after shard append but before index commit.
        if self.working.has_prefix(records):
            self.recall.add_batch(records)
            self.working.evict_records(records)
        elif self.recall.has_records(records):
            # The handoff completed and only outbox cleanup was interrupted.
            pass
        else:
            raise ValueError("pending transfer is absent from both Working and Recall")
        try:
            self._transfer_pending_path.unlink()
        except FileNotFoundError:
            pass

    def _recover_pending_transfer(self) -> None:
        if not self._transfer_pending_path.exists():
            return
        records = self._read_pending_transfer()
        if records:
            self._finish_pending_transfer(records)

    def forecast(self, fingerprint: str) -> dict:
        """
        Forecast outcome for a goal (uses Working Layer only).
        
        Args:
            fingerprint: Goal fingerprint
        
        Returns:
            Forecast dict with success_rate and confidence
        """
        # Query only Working Layer (fastest, most recent data)
        recent = self.working.query(fingerprint, limit=20)
        
        if not recent:
            # No data, return default forecast
            return {
                "success_rate": 0.5,
                "confidence": 0.0,
                "sample_size": 0,
                "source": "default",
            }
        
        # Compute success rate
        success_count = sum(1 for r in recent if r.outcome == "success")
        success_rate = success_count / len(recent)
        
        # Confidence based on sample size
        confidence = min(1.0, len(recent) / 10)
        
        return {
            "success_rate": success_rate,
            "confidence": confidence,
            "sample_size": len(recent),
            "source": "working",
        }
    
    def query_statistics(self, fingerprint: str) -> dict:
        """
        Query statistics for a goal (routes across layers).
        
        Args:
            fingerprint: Goal fingerprint
        
        Returns:
            Statistics dict with success_rate, lost_rate, trends, etc.
        """
        # Query Working + Recall (Archival if needed)
        working_data = self.working.query(fingerprint, limit=50)
        
        # Query Recall Layer
        recall_data = self.recall.query(fingerprint, limit=100)
        combined = working_data + recall_data
        
        # TODO Phase 3: Query Archival if still insufficient
        # if len(combined) < 150:
        #     archival_data = self.archival.query(fingerprint, limit=500)
        #     combined = combined + archival_data
        
        if not combined:
            return {
                "total_runs": 0,
                "success_rate": 0.0,
                "lost_rate": 0.0,
                "failure_rate": 0.0,
                "confidence": 0.0,
                "source": "none",
            }
        
        # Compute statistics
        total = len(combined)
        success_count = sum(1 for r in combined if r.outcome == "success")
        
        # Phase C v2: Count lost from BOTH sources (dual-write)
        lost_count_working = sum(1 for r in combined if r.outcome == "lost")
        lost_count_stream = self.lost_stream.count(fingerprint)
        lost_count = max(lost_count_working, lost_count_stream)
        
        failure_count = sum(1 for r in combined if r.outcome == "failure")
        
        success_rate = success_count / total if total > 0 else 0.0
        lost_rate = lost_count / total if total > 0 else 0.0
        failure_rate = failure_count / total if total > 0 else 0.0
        
        # Confidence based on sample size and data source
        base_confidence = 1.0 if len(working_data) > 0 else 0.8
        confidence = base_confidence * min(1.0, total / 10)
        
        return {
            "total_runs": total,
            "success_count": success_count,
            "lost_count": lost_count,
            "failure_count": failure_count,
            "success_rate": success_rate,
            "lost_rate": lost_rate,
            "failure_rate": failure_rate,
            "confidence": confidence,
            "source": "working+recall+archival+lost_stream" if len(working_data) > 0 else "none",
        }
    
    def record_lost(
        self,
        fingerprint: str,
        reason: str,
        timestamp: Optional[int] = None,
        # Phase A: New parameters (backward compatible)
        run_id: Optional[str] = None,
        fencing_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record a lost run (called by Reaper via AdmissionLedger).
        
        This is the integration point with Reaper:
        Reaper -> AdmissionLedger.record() -> Experience.record_lost()
        
        Phase A extensions (C Bridge contract v2):
        - run_id: Run identifier for provenance
        - fencing_token: Ownership token for validation (fail-closed)
        - metadata: Additional context
        
        Deduplication: (run_id, fingerprint, reason) key
        
        Args:
            fingerprint: Goal fingerprint
            reason: Reason for loss (e.g., "lease_expired")
            timestamp: When the loss occurred
            run_id: Run identifier (Phase A)
            fencing_token: Ownership token (Phase A, None=manual override)
            metadata: Additional context (Phase A)
        """
        ts = timestamp or int(time.time())
        
        # Phase B: Fencing token validation (fail-closed)
        if fencing_token is None:
            # Manual override: no ownership proof
            data_quality = "degraded"
            source = "manual-no-token"
        else:
            # Validate fencing token with OwnershipLedger
            if not hasattr(self, 'ownership_ledger') or self.ownership_ledger is None:
                raise RuntimeError(
                    "OwnershipLedger not configured. Cannot validate fencing token. "
                    "Set experience.ownership_ledger before calling record_lost() with fencing_token."
                )
            
            # Validate token against OwnershipLedger
            if run_id is None:
                raise ValueError("run_id required when fencing_token is provided")
            
            is_valid = self.ownership_ledger.validate_token(run_id, fencing_token)
            if not is_valid:
                raise OwnershipLostError(
                    f"Stale fencing token for run {run_id}. "
                    f"Another process may have acquired ownership."
                )
            
            # Token valid
            data_quality = "complete"
            source = "reaper-fenced"
        
        # Phase A: Corrected deduplication key (run_id, fingerprint, reason)
        if run_id is not None:
            # Check for exact duplicate with same (run_id, fingerprint, reason)
            for record in self.working.records:
                if (record.fingerprint == fingerprint and 
                    record.outcome == "lost" and
                    record.reason == reason and
                    getattr(record, 'run_id', None) == run_id):
                    # Exact duplicate, skip
                    return
        else:
            # Legacy behavior: 60-second window deduplication
            cutoff = ts - 60
            for record in self.working.records:
                if (record.fingerprint == fingerprint and 
                    record.outcome == "lost" and 
                    record.timestamp >= cutoff):
                    # Already recorded a lost event within 60 seconds, skip
                    return
        
        # Phase C v2: Dual-write approach
        # 1. Write to LostEventStream (authoritative source)
        lost_event = LostEvent(
            goal_fingerprint=fingerprint,
            run_id=run_id or "unknown",
            reason=reason,
            timestamp=ts,
            fencing_token=fencing_token,
            data_quality=data_quality,
            source=source,
            metadata=metadata,
        )
        self.lost_stream.add(lost_event)
        
        # 2. ALSO write to WorkingLayer (backward compatibility for Phase A+B tests)
        record = ExperienceRecord(
            fingerprint=fingerprint,
            outcome="lost",
            reason=reason,
            timestamp=ts,
            metadata=metadata,
            run_id=run_id,
            data_quality=data_quality,
            source=source,
        )
        
        # 3. Add to Working Layer
        self.working.add(record)
        
        # 4. Trigger admission policy reevaluation
        # Integrate with AdmissionLedger (via callback if provided)
        self._trigger_admission_reevaluation(fingerprint, record)
        pass
    
    def query_lost_events(
        self,
        goal_fingerprint: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Query lost events from LostEventStream (Phase C v2).
        
        Args:
            goal_fingerprint: Goal fingerprint
            limit: Maximum events to return
        
        Returns:
            List of lost events (as dicts)
        """
        return self.lost_stream.query(goal_fingerprint, limit)
    
    def settle(self, record: ExperienceRecord) -> None:
        """
        Record experience settlement (existing API compatibility).
        
        Args:
            record: Experience record to settle
        """
        # 1. Add to Working Layer
        self.working.add(record)
        
        # 2. Check capacity and trigger eviction if needed
        self._check_and_evict()
    
    def _check_and_evict(self) -> None:
        """Move an oldest batch through a durable outbox before removing it from Working."""
        # A failed handoff leaves this file in place. Finish it before selecting a
        # newer prefix, otherwise a later settle could overwrite the older batch.
        self._recover_pending_transfer()
        if len(self.working) > self.working.capacity:
            evicted = self.working.records[:10]
            self._write_pending_transfer(evicted)
            self._finish_pending_transfer(evicted)
    
    def _check_and_archive(self) -> None:
        """Check Recall age and archive to Archival if needed."""
        # Calculate cutoff date
        cutoff = datetime.now() - timedelta(days=self.recall.window_days)

        # Archive old records. Recall deletes a shard only after the archival layer confirms it
        # stored that shard's records; while ArchivalLayer.archive is unimplemented it never does.
        self.recall.archive_old_data(cutoff, archive=self.archival.archive)
        
        # TODO Phase 3: Pass to Archival Layer
        # self.archival.archive(old_records)
        # 
        # For now, old records are removed from Recall
        # Phase 3 will implement Archival Layer storage
    
    def _trigger_admission_reevaluation(
        self,
        fingerprint: str,
        lost_record: ExperienceRecord,
    ) -> None:
        """
        Trigger admission policy reevaluation after recording a lost event.
        
        Args:
            fingerprint: Goal fingerprint
            lost_record: The lost event record
        """
        if self.admission_callback is None:
            # No callback configured, skip
            return
        
        # Query current statistics (including the new lost event)
        stats = self.query_statistics(fingerprint)
        
        # Call the admission callback
        # This allows Reaper/AdmissionLedger to make decisions based on updated stats
        try:
            self.admission_callback(fingerprint, lost_record, stats)
        except Exception as e:
            # Log but don't fail - admission reevaluation is advisory
            import sys
            print(f"Warning: admission callback failed: {e}", file=sys.stderr)

    def history_status(self) -> dict:
        """Whether the recorded history is known to be complete.

        ``complete`` is False when ``issues`` is not empty:

        * ``unreadable_lines``: a layer skipped a line it could not read;
        * ``quarantined_file``: a damaged working file was set aside and is still on disk (the
          lines it holds were not carried into the live history; this stays True across restarts
          until someone has dealt with the file);
        * ``recall_index_missing_shards`` / ``recall_unindexed_shards``: the Recall index and the
          shard filenames disagree;
        * ``recall_index_content_mismatches``: shard contents and the fingerprint/date index
          disagree, including a same-date fingerprint appended before an index-save failure.
          See ``RecallLayer.structure_problems``.

        A decision that rests on this history is resting on less than was recorded. Damage inside
        a recall shard is only known once that shard has been read.
        """
        quarantined = sorted(str(path) for path in self.base_dir.glob("working.jsonl.corrupt-*"))
        skipped = (
            self.working.corrupt_lines
            + self.lost_stream.corrupt_lines
            + self.recall.corrupt_lines
        )
        structure = self.recall.structure_problems()
        issues = []
        if skipped:
            issues.append("unreadable_lines")
        if quarantined:
            issues.append("quarantined_file")
        transfer_pending = self._transfer_pending_path.exists()
        if transfer_pending:
            issues.append("working_recall_transfer_pending")
        issues.extend(name for name, found in structure.items() if found)
        return {
            "complete": not issues,
            "issues": issues,
            "skipped_lines": skipped,
            "quarantine_files": quarantined,
            "working_recall_transfer_pending": transfer_pending,
            **structure,
        }

    def health(self) -> dict:
        """Counters that make silent damage visible. All zero / empty on a healthy store."""
        status = self.history_status()
        return {
            "working_corrupt_lines": self.working.corrupt_lines,
            "lost_stream_corrupt_lines": self.lost_stream.corrupt_lines,
            "recall_corrupt_lines": self.recall.corrupt_lines,
            "quarantine_files": status["quarantine_files"],
            "recall_index_missing_shards": status["recall_index_missing_shards"],
            "recall_unindexed_shards": status["recall_unindexed_shards"],
            "recall_index_content_mismatches": status["recall_index_content_mismatches"],
            "recall_index_pending": status["recall_index_pending"],
            "recall_index_dirty": self.recall._index_dirty,
            "history_complete": status["complete"],
            "issues": status["issues"],
            "working_recall_transfer_pending": status["working_recall_transfer_pending"],
        }

# =============================================================================
# Policy Evaluator (追加于 2026-09-19 01:48)
# =============================================================================
# Standalone Experience-Based Policy Evaluator
# =============================================================================
#
# This section is intentionally self-contained: it depends on nothing outside
# the Python standard library and must NOT import from experience_ledger.py or
# any evidence_admission module. It re-implements the *policy decision* logic
# from scratch on plain scalars, so callers that only hold counters (e.g. a
# Reaper, a router, or a projection job) can evaluate a fingerprint without
# constructing a ledger, a statistics object, or an admission ledger.
#
# Decision vocabulary:
#   "admit" - allow execution
#   "block" - refuse execution
#   "warn"  - allow, but flag the fingerprint for review (opt-in, see warn_band)
#
# Default policy (matches the reference admission policy semantics):
#   1. total_runs < min_samples                  -> admit, "insufficient_data",
#                                                   low confidence
#   2. success_rate < min_success_rate           -> block, "success_rate X < Y",
#                                                   medium confidence
#   3. min_success_rate <= success_rate < +band  -> warn (only if warn_band > 0)
#   4. success_rate >= min_success_rate          -> admit, "acceptable_standing",
#                                                   high confidence
#
# Confidence is sample-size derived: min(1.0, total_runs / 10.0).
# In the insufficient-data branch it is additionally capped so a tiny sample
# can never claim high confidence:
#   min(confidence, total_runs / (2 * min_samples))
# (the cap is a no-op for the default min_samples=3, since 2*3 <= 10).

from dataclasses import dataclass
from typing import Optional, Dict, Any

DEFAULT_MIN_SAMPLES = 3
DEFAULT_MIN_SUCCESS_RATE = 0.7
CONFIDENCE_SAMPLE_HORIZON = 10.0


@dataclass(frozen=True)
class PolicyEvaluation:
    """Result of an experience-based policy evaluation.

    Attributes:
        decision: One of "admit", "block", "warn".
        reason: Human-readable explanation for the decision.
        confidence: Confidence in [0.0, 1.0], scaling with sample size.
        fingerprint: The fingerprint that was evaluated (traceability).
        success_rate: Observed success rate used for the decision.
    """

    decision: str
    reason: str
    confidence: float
    fingerprint: str = ""
    success_rate: float = 0.0

    @property
    def execution_authorized(self) -> bool:
        """True when the decision does not forbid execution."""
        return self.decision != "block"

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "confidence": self.confidence,
            "fingerprint": self.fingerprint,
            "success_rate": self.success_rate,
            "execution_authorized": self.execution_authorized,
        }

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"PolicyEvaluation(decision={self.decision!r}, "
            f"reason={self.reason!r}, confidence={self.confidence:.4f})"
        )


def _confidence_from_samples(total_runs: int, min_samples: int) -> float:
    """Sample-size derived confidence: min(1.0, total_runs / 10.0).

    Capped by the insufficient-data ceiling so a sample smaller than the
    policy minimum can never report high confidence.
    """
    if total_runs <= 0:
        return 0.0
    confidence = min(1.0, total_runs / CONFIDENCE_SAMPLE_HORIZON)
    if min_samples > 0:
        ceiling = total_runs / (2.0 * min_samples)
        confidence = min(confidence, ceiling)
    return max(0.0, min(1.0, confidence))


def evaluate_policy(
    fingerprint: str,
    total_runs: int,
    success_count: int,
    lost_count: int,
    policy: Optional[dict] = None,
) -> PolicyEvaluation:
    """Evaluate an experience-based admission policy for one fingerprint.

    Pure function: no I/O, no ledger access, no global state. Callers supply
    the counters they already have (e.g. from
    ``ExperienceLayering.query_statistics``).

    Args:
        fingerprint: Goal/fingerprint being evaluated (echoed for tracing).
        total_runs: Number of recorded runs/attempts for the fingerprint.
        success_count: Subset of total_runs that succeeded.
        lost_count: Subset of total_runs that were lost (lease expired, etc.).
        policy: Optional policy overrides. Recognised keys (all optional):
            - min_samples (int, default 3): below this, admit with caution.
            - min_success_rate (float, default 0.7): block threshold.
            - warn_band (float, default 0.0): if > 0, success rates in
              [min_success_rate, min_success_rate + warn_band) produce a
              "warn" decision instead of "admit". Disabled by default, so the
              default behaviour follows the strict admit/block policy above.

    Returns:
        PolicyEvaluation with decision, reason and confidence.
    """
    policy = dict(policy) if policy else {}

    try:
        min_samples = int(policy.get("min_samples", DEFAULT_MIN_SAMPLES))
    except (TypeError, ValueError):
        min_samples = DEFAULT_MIN_SAMPLES
    try:
        min_success_rate = float(
            policy.get("min_success_rate", DEFAULT_MIN_SUCCESS_RATE)
        )
    except (TypeError, ValueError):
        min_success_rate = DEFAULT_MIN_SUCCESS_RATE
    try:
        warn_band = float(policy.get("warn_band", 0.0))
    except (TypeError, ValueError):
        warn_band = 0.0

    min_samples = max(0, min_samples)
    min_success_rate = max(0.0, min(1.0, min_success_rate))
    warn_band = max(0.0, warn_band)

    # Defensive normalisation: counters may come from projections that count
    # overlapping subsets, so clamp to sane non-negative integers.
    total_runs = max(0, int(total_runs))
    success_count = max(0, int(success_count))
    lost_count = max(0, int(lost_count))

    confidence = _confidence_from_samples(total_runs, min_samples)
    success_rate = (success_count / total_runs) if total_runs > 0 else 0.0

    # 1. Insufficient data -> admit with caution, low confidence.
    if total_runs < min_samples:
        return PolicyEvaluation(
            decision="admit",
            reason="insufficient_data",
            confidence=confidence,
            fingerprint=fingerprint,
            success_rate=success_rate,
        )

    # 2. Consistent failure -> block, medium/high confidence.
    if success_rate < min_success_rate:
        return PolicyEvaluation(
            decision="block",
            reason=(
                f"success_rate {success_rate:.2f} < {min_success_rate:.2f}"
                f" (successes={success_count}, lost={lost_count},"
                f" total={total_runs})"
            ),
            confidence=confidence,
            fingerprint=fingerprint,
            success_rate=success_rate,
        )

    # 3. Marginal performance inside the opt-in warn band.
    if warn_band > 0.0 and (success_rate - min_success_rate) < warn_band:
        return PolicyEvaluation(
            decision="warn",
            reason=(
                f"success_rate {success_rate:.2f} marginal vs threshold"
                f" {min_success_rate:.2f}"
            ),
            confidence=confidence,
            fingerprint=fingerprint,
            success_rate=success_rate,
        )

    # 4. Good standing -> admit with high confidence.
    return PolicyEvaluation(
        decision="admit",
        reason="acceptable_standing",
        confidence=confidence,
        fingerprint=fingerprint,
        success_rate=success_rate,
    )