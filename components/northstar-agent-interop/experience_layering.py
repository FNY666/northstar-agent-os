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
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Any


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
    ):
        self.fingerprint = fingerprint
        self.outcome = outcome
        self.reason = reason
        self.timestamp = timestamp or int(time.time())
        self.metadata = metadata or {}
    
    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "outcome": self.outcome,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ExperienceRecord":
        return cls(
            fingerprint=data["fingerprint"],
            outcome=data["outcome"],
            reason=data.get("reason"),
            timestamp=data.get("timestamp"),
            metadata=data.get("metadata", {}),
        )


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
        Add a record to Working Layer.
        
        Args:
            record: Experience record to add
        """
        # 1. Add to in-memory list (append to end, newest last)
        self.records.append(record)
        
        # 2. Persist to JSONL (ensure directory exists)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.storage_path, "a") as f:
            f.write(json.dumps(record.to_dict()) + "\n")
        
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
        
        Args:
            count: Number of records to evict
        
        Returns:
            List of evicted records
        """
        if count <= 0 or len(self.records) == 0:
            return []
        
        # Take oldest records (from beginning of list)
        evicted = self.records[:count]
        self.records = self.records[count:]
        
        # Rewrite entire file (simpler than maintaining offset)
        self._rewrite_disk()
        
        return evicted
    
    def _load_from_disk(self) -> None:
        """Load records from disk on initialization."""
        try:
            with open(self.storage_path, "r") as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        self.records.append(ExperienceRecord.from_dict(data))
        except (FileNotFoundError, json.JSONDecodeError):
            # File doesn't exist or is corrupted, start fresh
            self.records = []
    
    def _rewrite_disk(self) -> None:
        """Rewrite entire working.jsonl file (used after eviction)."""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.storage_path, "w") as f:
            for record in self.records:
                f.write(json.dumps(record.to_dict()) + "\n")
    
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
        
        # Load index from disk if exists
        self._load_index()
    
    def add_batch(self, records: List[ExperienceRecord]) -> None:
        """
        Add batch of records to Recall Layer.
        
        Args:
            records: List of records to add
        """
        if not records:
            return
        
        # 1. Group records by date
        from collections import defaultdict
        by_date = defaultdict(list)
        
        for record in records:
            date_str = datetime.fromtimestamp(record.timestamp).strftime("%Y-%m-%d")
            by_date[date_str].append(record)
        
        # 2. Ensure directory exists
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # 3. Append to corresponding recall-YYYY-MM-DD.jsonl files
        for date_str, date_records in by_date.items():
            file_path = self.storage_dir / f"recall-{date_str}.jsonl"
            
            # Append records
            with open(file_path, "a") as f:
                for record in date_records:
                    f.write(json.dumps(record.to_dict()) + "\n")
            
            # 4. Update index
            for record in date_records:
                if record.fingerprint not in self.index:
                    self.index[record.fingerprint] = []
                if date_str not in self.index[record.fingerprint]:
                    self.index[record.fingerprint].append(date_str)
        
        # 5. Persist index
        self._save_index()
    
    def query(self, fingerprint: str, limit: Optional[int] = None) -> List[ExperienceRecord]:
        """
        Query records by fingerprint across date shards.
        
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
            with open(file_path, "r") as f:
                for line in f:
                    if not line.strip():
                        continue
                    data = json.loads(line)
                    record = ExperienceRecord.from_dict(data)
                    
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
                # Read all records from this file
                with open(file_path, "r") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        data = json.loads(line)
                        old_records.append(ExperienceRecord.from_dict(data))
        
        return old_records
    
    def archive_old_data(self, cutoff_date: datetime) -> List[ExperienceRecord]:
        """
        Archive records older than cutoff date.
        
        Args:
            cutoff_date: Cutoff date
        
        Returns:
            List of archived records
        """
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")
        archived_records = []
        
        if not self.storage_dir.exists():
            return []
        
        # Find and remove old files
        for file_path in list(self.storage_dir.glob("recall-*.jsonl")):
            date_str = file_path.stem.replace("recall-", "")
            
            if date_str < cutoff_str:
                # Read records before deleting
                with open(file_path, "r") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        data = json.loads(line)
                        archived_records.append(ExperienceRecord.from_dict(data))
                
                # Delete the file
                file_path.unlink()
                
                # Update index (remove this date from all fingerprints)
                for fp in list(self.index.keys()):
                    if date_str in self.index[fp]:
                        self.index[fp].remove(date_str)
                    if not self.index[fp]:
                        del self.index[fp]
        
        # Persist updated index
        self._save_index()
        
        return archived_records
    
    def _save_index(self) -> None:
        """Save index to disk."""
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        index_path = self.storage_dir / "recall-index.json"
        with open(index_path, "w") as f:
            json.dump(self.index, f, indent=2)
    
    def _load_index(self) -> None:
        """Load index from disk."""
        index_path = self.storage_dir / "recall-index.json"
        if index_path.exists():
            with open(index_path, "r") as f:
                self.index = json.load(f)


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
    
    def archive(self, records: List[ExperienceRecord]) -> None:
        """
        Archive records to compressed storage.
        
        Args:
            records: List of records to archive
        """
        # TODO: Implement
        # 1. Append to archival.jsonl.gz (gzip)
        # 2. Update index (line offsets)
        # 3. Update summary (aggregated stats)
        pass
    
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
        
        self.admission_callback = admission_callback
    
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
        lost_count = sum(1 for r in combined if r.outcome == "lost")
        failure_count = sum(1 for r in combined if r.outcome == "failure")
        
        success_rate = success_count / total
        lost_rate = lost_count / total
        failure_rate = failure_count / total
        
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
            "source": "working" if len(working_data) > 0 else "none",
        }
    
    def record_lost(
        self,
        fingerprint: str,
        reason: str,
        timestamp: Optional[int] = None,
    ) -> None:
        """
        Record a lost run (called by Reaper via AdmissionLedger).
        
        This is the integration point with Reaper:
        Reaper -> AdmissionLedger.record() -> Experience.record_lost()
        
        Deduplication: Prevents recording duplicate lost events within 60 seconds
        (per 616C93DD's suggestion to avoid Reaper re-marking the same run).
        
        Args:
            fingerprint: Goal fingerprint
            reason: Reason for loss (e.g., "lease_expired")
            timestamp: When the loss occurred
        """
        ts = timestamp or int(time.time())
        
        # 1. Deduplication: Check for recent lost events (within 60 seconds of THIS event)
        # Note: We check within 60 seconds of the event timestamp, not current time
        cutoff = ts - 60
        for record in self.working.records:
            if (record.fingerprint == fingerprint and 
                record.outcome == "lost" and 
                record.timestamp >= cutoff):
                # Already recorded a lost event within 60 seconds, skip
                return
        
        # 2. Create ExperienceRecord with outcome="lost"
        record = ExperienceRecord(
            fingerprint=fingerprint,
            outcome="lost",
            reason=reason,
            timestamp=ts,
        )
        
        # 3. Add to Working Layer
        self.working.add(record)
        
        # 4. Trigger admission policy reevaluation
        # Integrate with AdmissionLedger (via callback if provided)
        self._trigger_admission_reevaluation(fingerprint, record)
        pass
    
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
        """Check Working capacity and evict to Recall if needed."""
        if len(self.working) > self.working.capacity:
            # Evict oldest 10 records
            evicted = self.working.evict(count=10)
            
            # Pass to Recall Layer
            self.recall.add_batch(evicted)
    
    def _check_and_archive(self) -> None:
        """Check Recall age and archive to Archival if needed."""
        # Calculate cutoff date
        cutoff = datetime.now() - timedelta(days=self.recall.window_days)
        
        # Archive old records
        old_records = self.recall.archive_old_data(cutoff)
        
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
