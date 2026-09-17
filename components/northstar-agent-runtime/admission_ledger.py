"""
Persistent ledger for continuation admission decisions.
"""
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from hashlib import sha256


class AdmissionLedgerError(ValueError):
    """Raised when admission ledger operations fail."""
    pass


@dataclass(frozen=True)
class AdmissionConflict:
    """A detected conflict between two admission decisions."""
    earlier_sequence: int
    later_sequence: int
    checkpoint_digest: str
    earlier_state: str
    later_state: str
    conflict_type: str  # "admit-vs-block" | "block-vs-admit" | "state-change"
    time_delta_seconds: int


@dataclass(frozen=True)
class AdmissionRecord:
    """A recorded admission decision."""
    sequence: int
    session_id: str
    admission_digest: str
    state: str
    observed_at: int
    checkpoint_digest: str = ""  # Added for conflict detection
    goal_fingerprint: str = ""  # Added for fingerprint-based queries
    record_digest: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "session_id": self.session_id,
            "admission_digest": self.admission_digest,
            "state": self.state,
            "observed_at": self.observed_at,
            "checkpoint_digest": self.checkpoint_digest,
            "goal_fingerprint": self.goal_fingerprint,
            "record_digest": self.record_digest,
        }
    
    @property
    def computed_digest(self) -> str:
        """Canonical digest of this record (excluding record_digest itself)."""
        draft = {
            "sequence": self.sequence,
            "session_id": self.session_id,
            "admission_digest": self.admission_digest,
            "state": self.state,
            "observed_at": self.observed_at,
        }
        # Only include checkpoint_digest if present (backward compatible)
        if self.checkpoint_digest:
            draft["checkpoint_digest"] = self.checkpoint_digest
        # Only include goal_fingerprint if present (backward compatible)
        if self.goal_fingerprint:
            draft["goal_fingerprint"] = self.goal_fingerprint
        return sha256(json.dumps(draft, sort_keys=True).encode()).hexdigest()


class AdmissionLedger:
    """Append-only log of admission decisions."""
    
    def __init__(self, path: Path | str):
        self.path = Path(path)
    
    def record(
        self,
        session_id: str,
        admission: Any,
        observed_at: int,
        goal_fingerprint: str = "",
    ) -> AdmissionRecord:
        """
        Persist an admission decision.
        
        Returns the recorded entry with sequence number.
        Thread-safe via flock.
        """
        if not isinstance(session_id, str) or not session_id:
            raise AdmissionLedgerError("session_id invalid")
        if not isinstance(observed_at, int) or observed_at < 0:
            raise AdmissionLedgerError("observed_at invalid")
        if goal_fingerprint and (not isinstance(goal_fingerprint, str) or len(goal_fingerprint) != 64):
            raise AdmissionLedgerError("goal_fingerprint invalid")
        
        # Read existing records to determine next sequence
        existing = self._read_all()
        sequence = len(existing) + 1
        
        # Create record
        record = AdmissionRecord(
            sequence=sequence,
            session_id=session_id,
            admission_digest=admission.admission_digest,
            state=admission.state,
            observed_at=observed_at,
            checkpoint_digest=admission.checkpoint_digest,
            goal_fingerprint=goal_fingerprint,
        )
        
        # Finalize with computed digest
        record = AdmissionRecord(
            record.sequence,
            record.session_id,
            record.admission_digest,
            record.state,
            record.observed_at,
            record.checkpoint_digest,  # Must preserve checkpoint_digest
            record.goal_fingerprint,  # Must preserve goal_fingerprint
            record.computed_digest,
        )
        
        # Append to file with flock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        
        # Use flock for concurrent write safety
        import fcntl
        with open(self.path, 'a') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(json.dumps(record.to_dict()) + '\n')
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        
        return record
    
    def query(
        self,
        session_id: str,
        checkpoint_digest: str | None = None,
    ) -> list[AdmissionRecord]:
        """
        Query admission history.
        
        Returns chronologically ordered list of admission records.
        """
        records = self._read_all()
        
        # Filter by session_id
        matches = [r for r in records if r.session_id == session_id]
        
        # Optionally filter by checkpoint_digest (requires parsing admission)
        # For now, just return session matches
        # TODO: add checkpoint_digest filter if needed
        
        return matches
    
    def query_by_fingerprint(
        self,
        fingerprint: str,
        *,
        session_id: str | None = None,
        since: int | None = None,
        until: int | None = None,
    ) -> list[AdmissionRecord]:
        """
        Query admission history by goal fingerprint.
        
        Args:
            fingerprint: SHA256 hex digest of goal (64 chars)
            session_id: Optional session filter
            since: Optional minimum observed_at timestamp (inclusive)
            until: Optional maximum observed_at timestamp (inclusive)
        
        Returns:
            Chronologically ordered list of admission records.
        """
        # Validate fingerprint format (accept any non-empty string)
        if not isinstance(fingerprint, str) or not fingerprint:
            raise ValueError("fingerprint must be non-empty string")
        
        records = self._read_all()
        
        # Filter by fingerprint
        matches = [r for r in records if r.goal_fingerprint == fingerprint]
        
        # Optional session filter
        if session_id is not None:
            matches = [r for r in matches if r.session_id == session_id]
        
        # Optional time window filters
        if since is not None:
            matches = [r for r in matches if r.observed_at >= since]
        if until is not None:
            matches = [r for r in matches if r.observed_at <= until]
        
        # Sort by observed_at (chronological order)
        matches.sort(key=lambda r: r.observed_at)
        
        return matches
    
    def detect_conflicts(
        self,
        session_id: str,
        *,
        window_seconds: int | None = None,
    ) -> list[AdmissionConflict]:
        """
        Detect conflicting admission decisions for same checkpoint.
        
        Returns chronologically ordered conflicts.
        """
        records = self.query(session_id)
        
        if len(records) < 2:
            return []
        
        conflicts = []
        
        # Group by checkpoint_digest
        by_checkpoint: dict[str, list[AdmissionRecord]] = {}
        for record in records:
            if record.checkpoint_digest:
                by_checkpoint.setdefault(record.checkpoint_digest, []).append(record)
        
        # Compare pairs within each checkpoint group
        for checkpoint_digest, group in by_checkpoint.items():
            if len(group) < 2:
                continue
            
            # Compare chronologically ordered pairs
            for i, earlier in enumerate(group):
                for later in group[i+1:]:
                    time_delta = later.observed_at - earlier.observed_at
                    
                    # Apply window filter
                    if window_seconds is not None and time_delta > window_seconds:
                        continue
                    
                    # Detect conflict type
                    conflict_type = self._classify_conflict(earlier.state, later.state)
                    
                    if conflict_type:
                        conflicts.append(AdmissionConflict(
                            earlier_sequence=earlier.sequence,
                            later_sequence=later.sequence,
                            checkpoint_digest=checkpoint_digest,
                            earlier_state=earlier.state,
                            later_state=later.state,
                            conflict_type=conflict_type,
                            time_delta_seconds=time_delta,
                        ))
        
        return conflicts
    
    def _classify_conflict(self, earlier_state: str, later_state: str) -> str | None:
        """Classify conflict type between two states."""
        earlier_is_admit = earlier_state.startswith("admit")
        later_is_admit = later_state.startswith("admit")
        
        if earlier_is_admit and not later_is_admit:
            return "admit-vs-block"
        elif not earlier_is_admit and later_is_admit:
            return "block-vs-admit"
        elif earlier_state != later_state:
            return "state-change"
        else:
            # Same state, no conflict
            return None
    
    def _read_all(self) -> list[AdmissionRecord]:
        """Read all records from ledger. Fail-closed on corruption."""
        if not self.path.exists():
            return []
        
        records = []
        try:
            with open(self.path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError as e:
                        raise AdmissionLedgerError(f"corrupted ledger at line {line_num}: {e}")
                    
                    # Reconstruct record
                    record = AdmissionRecord(
                        sequence=data.get("sequence"),
                        session_id=data.get("session_id"),
                        admission_digest=data.get("admission_digest"),
                        state=data.get("state"),
                        observed_at=data.get("observed_at"),
                        checkpoint_digest=data.get("checkpoint_digest", ""),  # Backward compatible
                        goal_fingerprint=data.get("goal_fingerprint", ""),  # Backward compatible
                        record_digest=data.get("record_digest"),
                    )
                    
                    # Verify digest
                    if record.record_digest != record.computed_digest:
                        raise AdmissionLedgerError(f"digest mismatch at sequence {record.sequence}")
                    
                    records.append(record)
        except (OSError, IOError) as e:
            raise AdmissionLedgerError(f"failed to read ledger: {e}")
        
        return records
