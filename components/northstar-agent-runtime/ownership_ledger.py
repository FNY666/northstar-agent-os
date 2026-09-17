"""
OwnershipLedger — append-only JSONL ledger tracking "who owns this run."

Each run has at most one active owner at a time.  Ownership is protected by:
  • generation counter (monotonic, increments on every acquire)
  • fencing token (SHA-256 of run_id + generation + owner_id + acquired_at)
  • digest chain (each record carries the SHA-256 of the previous record)
  • flock + fsync for concurrent-process safety
"""
from __future__ import annotations

import fcntl
import json
import os
import time
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any


# ── Exceptions ──────────────────────────────────────────────────────────────

class OwnershipError(Exception):
    """Base class for ownership errors."""
    pass


class OwnershipConflictError(OwnershipError):
    """Another owner holds the active lease."""
    pass


class OwnershipLostError(OwnershipError):
    """Lease expired or generation mismatch — stop immediately."""
    pass


class OwnershipViolationError(OwnershipError):
    """Invalid fencing token — caller is not the current owner."""
    pass


# ── Data classes ────────────────────────────────────────────────────────────

@dataclass
class RunOwnership:
    run_id: str
    generation: int          # Increments on each acquire
    owner_id: str            # Process / session identifier
    acquired_at: int         # Unix timestamp
    lease_ttl: int           # Seconds
    fencing_token: str       # SHA256(run_id ‖ generation ‖ owner_id ‖ acquired_at)
    # Mutable metadata -------------------------------------------------------
    state: str = "active"    # "active" | "released" | "lost"
    lost_reason: str = ""    # Only meaningful when state == "lost"
    prev_digest: str = ""    # Digest of previous JSONL record (chain)
    record_digest: str = ""  # Digest of this record (integrity)

    # ── Convenience ─────────────────────────────────────────────────────

    def is_expired(self, now: int | None = None) -> bool:
        """Return True if the lease has passed its TTL."""
        if now is None:
            now = int(time.time())
        return now >= self.acquired_at + self.lease_ttl

    def computed_token(self) -> str:
        """Recompute fencing token for verification."""
        return _fencing_token(self.run_id, self.generation, self.owner_id, self.acquired_at)

    @property
    def computed_digest(self) -> str:
        """Canonical digest of this record (excluding record_digest itself)."""
        return _record_digest(self)

    # ── Serialisation ───────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "generation": self.generation,
            "owner_id": self.owner_id,
            "acquired_at": self.acquired_at,
            "lease_ttl": self.lease_ttl,
            "fencing_token": self.fencing_token,
            "state": self.state,
            "lost_reason": self.lost_reason,
            "prev_digest": self.prev_digest,
            "record_digest": self.record_digest,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RunOwnership:
        return cls(
            run_id=data["run_id"],
            generation=data["generation"],
            owner_id=data["owner_id"],
            acquired_at=data["acquired_at"],
            lease_ttl=data["lease_ttl"],
            fencing_token=data["fencing_token"],
            state=data.get("state", "active"),
            lost_reason=data.get("lost_reason", ""),
            prev_digest=data.get("prev_digest", ""),
            record_digest=data.get("record_digest", ""),
        )


# ── Helpers ─────────────────────────────────────────────────────────────────

def _fencing_token(run_id: str, generation: int, owner_id: str, acquired_at: int) -> str:
    """SHA-256 of the canonical ownership fields."""
    payload = f"{run_id}|{generation}|{owner_id}|{acquired_at}"
    return sha256(payload.encode()).hexdigest()


def _record_digest(ownership: RunOwnership) -> str:
    """Digest of the record's mutable content, excluding record_digest."""
    draft = {
        "run_id": ownership.run_id,
        "generation": ownership.generation,
        "owner_id": ownership.owner_id,
        "acquired_at": ownership.acquired_at,
        "lease_ttl": ownership.lease_ttl,
        "fencing_token": ownership.fencing_token,
        "state": ownership.state,
        "lost_reason": ownership.lost_reason,
        "prev_digest": ownership.prev_digest,
    }
    return sha256(json.dumps(draft, sort_keys=True).encode()).hexdigest()


# ── Ledger ──────────────────────────────────────────────────────────────────

class OwnershipLedger:
    """Append-only JSONL ledger with CAS semantics for run ownership."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    # ── Public API ──────────────────────────────────────────────────────

    def acquire(self, run_id: str, owner_id: str, ttl: int = 300) -> RunOwnership:
        """Acquire ownership of *run_id* with CAS semantics.

        1. Read the latest active ownership for *run_id*.
        2. If the lease is still valid → OwnershipConflictError (fail-closed).
        3. Compute generation + 1, create a new record, append atomically.
        4. Re-read to verify the digest chain (no concurrent overwrite).
        """
        if not isinstance(run_id, str) or not run_id:
            raise OwnershipError("run_id must be a non-empty string")
        if not isinstance(owner_id, str) or not owner_id:
            raise OwnershipError("owner_id must be a non-empty string")
        if not isinstance(ttl, int) or ttl <= 0:
            raise OwnershipError("ttl must be a positive integer")

        now = int(time.time())

        # --- CAS phase: read → check → write → verify ---
        self._ensure_file()
        records = self._read_all_locked()

        # Find latest record for this run_id
        current = self._latest_for_run(records, run_id)

        if current is not None and not current.is_expired(now) and current.state == "active":
            raise OwnershipConflictError(
                f"run_id={run_id!r} is currently owned by {current.owner_id!r} "
                f"(gen={current.generation}, expires in {current.acquired_at + current.lease_ttl - now}s)"
            )

        # Compute next generation
        gen = (current.generation + 1) if current is not None else 1

        acquired_at = now
        token = _fencing_token(run_id, gen, owner_id, acquired_at)
        
        # prev_digest is the LAST record in the entire ledger (chain tail)
        prev_digest = records[-1].record_digest if records else ""

        ownership = RunOwnership(
            run_id=run_id,
            generation=gen,
            owner_id=owner_id,
            acquired_at=acquired_at,
            lease_ttl=ttl,
            fencing_token=token,
            state="active",
            lost_reason="",
            prev_digest=prev_digest,
        )
        ownership.record_digest = ownership.computed_digest

        self._append_and_verify(ownership, records, expected_gen=gen)
        return ownership

    def renew(self, ownership: RunOwnership) -> RunOwnership:
        """Renew an active lease.  Returns a fresh ownership with updated acquired_at.

        Raises OwnershipViolationError if the fencing token is invalid.
        Raises OwnershipLostError if the generation no longer matches or lease expired.
        """
        if not isinstance(ownership, RunOwnership):
            raise OwnershipError("ownership must be a RunOwnership instance")

        now = int(time.time())

        # Token must be valid at time of call
        if ownership.computed_token() != ownership.fencing_token:
            raise OwnershipViolationError("fencing token mismatch (forged ownership?)")

        records = self._read_all_locked()
        current = self._latest_for_run(records, ownership.run_id)

        if current is None:
            raise OwnershipLostError(f"run_id={ownership.run_id!r} has no ownership record")

        if current.generation != ownership.generation:
            raise OwnershipLostError(
                f"generation mismatch: caller has {ownership.generation}, "
                f"current is {current.generation}"
            )

        if current.state != "active":
            raise OwnershipLostError(
                f"run_id={ownership.run_id!r} is in state={current.state!r}, cannot renew"
            )

        # Check if lease expired
        if current.is_expired(now):
            raise OwnershipLostError(
                f"run_id={ownership.run_id!r} lease expired at "
                f"{current.acquired_at + current.lease_ttl}, cannot renew"
            )

        if current.is_expired(now):
            raise OwnershipLostError(
                f"run_id={ownership.run_id!r} lease expired "
                f"(expired {now - current.acquired_at - current.lease_ttl}s ago)"
            )

        # Build renewed ownership — bump acquired_at, keep generation
        renewed = RunOwnership(
            run_id=ownership.run_id,
            generation=ownership.generation,
            owner_id=ownership.owner_id,
            acquired_at=now,
            lease_ttl=ownership.lease_ttl,
            fencing_token=_fencing_token(
                ownership.run_id, ownership.generation, ownership.owner_id, now
            ),
            state="active",
            lost_reason="",
            prev_digest=records[-1].record_digest,
        )
        renewed.record_digest = renewed.computed_digest

        self._append_and_verify(renewed, records, expected_gen=ownership.generation + 0)
        return renewed

    def release(self, ownership: RunOwnership) -> None:
        """Explicitly release ownership.  Requires a valid fencing token."""
        if not isinstance(ownership, RunOwnership):
            raise OwnershipError("ownership must be a RunOwnership instance")

        if ownership.computed_token() != ownership.fencing_token:
            raise OwnershipViolationError("fencing token mismatch")

        records = self._read_all_locked()
        current = self._latest_for_run(records, ownership.run_id)

        if current is None:
            raise OwnershipLostError(f"run_id={ownership.run_id!r} has no ownership record")
        if current.generation != ownership.generation:
            raise OwnershipLostError("generation mismatch — stale ownership")
        if current.state != "active":
            raise OwnershipLostError(f"run_id={ownership.run_id!r} is already {current.state!r}")

        released = RunOwnership(
            run_id=ownership.run_id,
            generation=ownership.generation,
            owner_id=ownership.owner_id,
            acquired_at=ownership.acquired_at,
            lease_ttl=ownership.lease_ttl,
            fencing_token=ownership.fencing_token,
            state="released",
            lost_reason="",
            prev_digest=records[-1].record_digest,
        )
        released.record_digest = released.computed_digest

        self._append_and_verify(released, records, expected_gen=ownership.generation)

    def query(self, run_id: str) -> RunOwnership | None:
        """Return the latest ownership record for *run_id*, or None.

        Returns None if:
        - no record exists, or
        - the latest record is an expired active lease.
        Lost/released records are still returned.
        """
        records = self._read_all()
        current = self._latest_for_run(records, run_id)

        if current is None:
            return None

        # Expired active leases are treated as non-existent (fail-closed)
        if current.state == "active" and current.is_expired():
            return None

        return current

    def validate_token(self, run_id: str, fencing_token: str) -> bool:
        """Validate *fencing_token* against the current ownership of *run_id*."""
        current = self.query(run_id)
        if current is None:
            return False
        return current.fencing_token == fencing_token

    def mark_lost(self, run_id: str, reason: str = "lease_expired") -> None:
        """Record an explicit 'lost' entry.  Idempotent if already lost with same reason."""
        records = self._read_all()
        current = self._latest_for_run(records, run_id)

        if current is None:
            raise OwnershipError(f"run_id={run_id!r} has no ownership record to mark lost")
        if current.state == "lost" and current.lost_reason == reason:
            return  # Already marked with the same reason — idempotent

        lost = RunOwnership(
            run_id=run_id,
            generation=current.generation,
            owner_id=current.owner_id,
            acquired_at=current.acquired_at,
            lease_ttl=current.lease_ttl,
            fencing_token=current.fencing_token,
            state="lost",
            lost_reason=reason,
            prev_digest=records[-1].record_digest,
        )
        lost.record_digest = lost.computed_digest

        self._append_and_verify(lost, records, expected_gen=current.generation)

    def list_all(self, states: list[str] | None = None) -> list[RunOwnership]:
        """Return the latest record for every run_id (for Reaper scans).
        
        Args:
            states: Optional list of states to filter by (e.g. ["active"]).
                    If None, returns all states.
                    Default None for backward compatibility.
        
        Returns:
            List of RunOwnership records, one per run_id, optionally filtered by state.
        
        Performance note:
            For Reaper scans, pass states=["active"] to avoid processing
            already-lost or released leases.
        """
        records = self._read_all()
        latest: dict[str, RunOwnership] = {}
        for rec in records:
            latest[rec.run_id] = rec
        
        result = list(latest.values())
        
        # Filter by states if specified
        if states is not None:
            result = [r for r in result if r.state in states]
        
        return result

    # ── Internal helpers ────────────────────────────────────────────────

    def _ensure_file(self) -> None:
        """Touch the file if it doesn't exist."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()

    def _read_all_locked(self) -> list[RunOwnership]:
        """Read all records under a shared flock."""
        self._ensure_file()
        import fcntl as _fcntl
        with open(self.path, "r") as f:
            _fcntl.flock(f.fileno(), _fcntl.LOCK_SH)
            try:
                return self._parse_lines(f.read())
            finally:
                _fcntl.flock(f.fileno(), _fcntl.LOCK_UN)

    def _read_all(self) -> list[RunOwnership]:
        """Read all records (no lock — for internal use after lock held, or
        in contexts where the caller controls concurrency)."""
        self._ensure_file()
        with open(self.path, "r") as f:
            return self._parse_lines(f.read())

    def _parse_lines(self, text: str) -> list[RunOwnership]:
        """Parse JSONL text into RunOwnership list with digest verification.

        Raises OwnershipError on corruption (fail-closed).
        """
        records: list[RunOwnership] = []
        prev_digest = ""

        for line_num, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                raise OwnershipError(
                    f"corrupted ledger at line {line_num}: invalid JSON ({exc})"
                )

            rec = RunOwnership.from_dict(data)

            # Verify digest chain
            if rec.prev_digest != prev_digest:
                raise OwnershipError(
                    f"digest chain broken at line {line_num}: "
                    f"expected prev_digest={prev_digest!r}, got {rec.prev_digest!r}"
                )

            # Verify record integrity
            if rec.record_digest != rec.computed_digest:
                raise OwnershipError(
                    f"record digest mismatch at line {line_num}: "
                    f"stored={rec.record_digest[:16]}… computed={rec.computed_digest[:16]}…"
                )

            prev_digest = rec.record_digest
            records.append(rec)

        return records

    def _latest_for_run(self, records: list[RunOwnership], run_id: str) -> RunOwnership | None:
        """Find the most recent record for *run_id* (linear scan, last match wins)."""
        latest: RunOwnership | None = None
        for rec in records:
            if rec.run_id == run_id:
                latest = rec
        return latest

    def _append_and_verify(
        self,
        record: RunOwnership,
        existing: list[RunOwnership],
        *,
        expected_gen: int,
    ) -> None:
        """Append a record atomically, then re-read to confirm no concurrent write.

        Uses exclusive flock + fsync.  After writing, verifies:
        1. The generation matches expectations.
        2. The digest chain is intact.
        """
        self._ensure_file()
        import fcntl as _fcntl

        line = json.dumps(record.to_dict()) + "\n"

        with open(self.path, "a") as f:
            _fcntl.flock(f.fileno(), _fcntl.LOCK_EX)
            try:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            finally:
                _fcntl.flock(f.fileno(), _fcntl.LOCK_UN)

        # Post-write verification: re-read and confirm our record landed correctly
        verify_records = self._read_all()
        latest = self._latest_for_run(verify_records, record.run_id)
        if latest is None:
            raise OwnershipError("post-append verification failed: record not found")
        if latest.generation != expected_gen:
            raise OwnershipError(
                f"post-append verification failed: expected gen={expected_gen}, "
                f"got gen={latest.generation}"
            )
