"""
Experience Layering - Three-Layer Memory Architecture

This module implements a three-layer memory system for Experience Ledger:
- Working Layer: Hot data (recent 100 runs), in-memory + JSONL
- Recall Layer: Warm data (recent 30 days), date-sharded JSONL
- Archival Layer: Cold data (historical), compressed JSONL

Design document: /var/minis/shared/experience-layering-design.md
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
        # TODO: Load index from disk if exists
    
    def add_batch(self, records: List[ExperienceRecord]) -> None:
        """
        Add batch of records to Recall Layer.
        
        Args:
            records: List of records to add
        """
        # TODO: Implement
        # 1. Group records by date
        # 2. Append to corresponding recall-YYYY-MM-DD.jsonl
        # 3. Update index
        pass
    
    def query(self, fingerprint: str, limit: Optional[int] = None) -> List[ExperienceRecord]:
        """
        Query records by fingerprint across date shards.
        
        Args:
            fingerprint: Goal fingerprint
            limit: Maximum number of records
        
        Returns:
            List of matching records (newest first)
        """
        # TODO: Implement
        # 1. Look up dates from index
        # 2. Read from corresponding files
        # 3. Sort by timestamp (newest first)
        # 4. Apply limit
        pass
    
    def find_older_than(self, cutoff_date: datetime) -> List[ExperienceRecord]:
        """
        Find all records older than cutoff date.
        
        Args:
            cutoff_date: Cutoff date
        
        Returns:
            List of records older than cutoff
        """
        # TODO: Implement
        # 1. Scan date-sharded files
        # 2. Collect records from files older than cutoff
        pass
    
    def archive_old_data(self, cutoff_date: datetime) -> List[ExperienceRecord]:
        """
        Archive records older than cutoff date.
        
        Args:
            cutoff_date: Cutoff date
        
        Returns:
            List of archived records
        """
        # TODO: Implement
        # 1. Find records older than cutoff
        # 2. Remove corresponding files
        # 3. Update index
        # 4. Return archived records (to be passed to Archival Layer)
        pass


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
    ):
        """
        Initialize Experience Layering.
        
        Args:
            base_dir: Base directory for storage
            working_capacity: Working Layer capacity
            recall_window_days: Recall Layer time window
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
        
        # TODO: Query Recall when implemented
        # recall_data = self.recall.query(fingerprint, limit=100)
        # combined = working_data + recall_data
        
        combined = working_data
        
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
        # TODO: Call admission policy reevaluation
        # self._reevaluate_admission(fingerprint)
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
            # TODO: self.recall.add_batch(evicted) when Recall is implemented
            # For now, evicted records are just removed
    
    def _check_and_archive(self) -> None:
        """Check Recall age and archive to Archival if needed."""
        # TODO: Implement when Recall Layer is ready
        # cutoff = datetime.now() - timedelta(days=self.recall.window_days)
        # old_records = self.recall.archive_old_data(cutoff)
        # self.archival.archive(old_records)
        pass
