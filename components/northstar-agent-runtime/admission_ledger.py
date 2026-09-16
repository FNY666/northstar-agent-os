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
class AdmissionRecord:
    """A recorded admission decision."""
    sequence: int
    session_id: str
    admission_digest: str
    state: str
    observed_at: int
    record_digest: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "session_id": self.session_id,
            "admission_digest": self.admission_digest,
            "state": self.state,
            "observed_at": self.observed_at,
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
        )
        
        # Finalize with computed digest
        record = AdmissionRecord(
            record.sequence,
            record.session_id,
            record.admission_digest,
            record.state,
            record.observed_at,
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
                        record_digest=data.get("record_digest"),
                    )
                    
                    # Verify digest
                    if record.record_digest != record.computed_digest:
                        raise AdmissionLedgerError(f"digest mismatch at sequence {record.sequence}")
                    
                    records.append(record)
        except (OSError, IOError) as e:
            raise AdmissionLedgerError(f"failed to read ledger: {e}")
        
        return records
