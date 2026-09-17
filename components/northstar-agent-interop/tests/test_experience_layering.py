"""
Experience Layering Tests

Tests for the three-layer memory architecture:
- Working Layer (hot data, recent 100 runs)
- Recall Layer (warm data, recent 30 days)
- Archival Layer (cold data, compressed historical)
"""

import json
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

import pytest


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def temp_dir():
    """Temporary directory for test data"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_experience_record():
    """Factory for creating mock ExperienceRecord"""
    def _factory(
        fingerprint: str = "test-fp",
        outcome: str = "success",
        reason: Optional[str] = None,
        timestamp: Optional[int] = None,
    ) -> dict:
        return {
            "fingerprint": fingerprint,
            "outcome": outcome,
            "reason": reason,
            "timestamp": timestamp or int(time.time()),
        }
    return _factory


@pytest.fixture
def sample_records(mock_experience_record):
    """Sample experience records for testing"""
    records = []
    base_time = int(time.time())
    
    # 10 success records
    for i in range(10):
        records.append(mock_experience_record(
            fingerprint="test-fp-1",
            outcome="success",
            timestamp=base_time - i * 3600,
        ))
    
    # 5 failure records
    for i in range(5):
        records.append(mock_experience_record(
            fingerprint="test-fp-1",
            outcome="failure",
            reason="timeout",
            timestamp=base_time - (10 + i) * 3600,
        ))
    
    # 3 lost records
    for i in range(3):
        records.append(mock_experience_record(
            fingerprint="test-fp-1",
            outcome="lost",
            reason="lease_expired",
            timestamp=base_time - (15 + i) * 3600,
        ))
    
    return records


# =============================================================================
# Working Layer Tests
# =============================================================================

class TestWorkingLayer:
    """Tests for Working Layer (hot data)"""
    
    def test_add_record(self, temp_dir, mock_experience_record):
        """Test adding a record to Working Layer"""
        from experience_layering import WorkingLayer, ExperienceRecord
        
        layer = WorkingLayer(storage_path=temp_dir / "working.jsonl")
        record = ExperienceRecord(**mock_experience_record())
        
        layer.add(record)
        
        assert len(layer) == 1
        assert layer.records[0].fingerprint == "test-fp"
    
    def test_query_by_fingerprint(self, temp_dir, sample_records):
        """Test querying records by fingerprint"""
        from experience_layering import WorkingLayer, ExperienceRecord
        
        layer = WorkingLayer(storage_path=temp_dir / "working.jsonl")
        
        # Add records (sample_records[0] is newest, sample_records[-1] is oldest)
        for rec_data in sample_records[:10]:
            layer.add(ExperienceRecord(**rec_data))
        
        # Query
        results = layer.query("test-fp-1", limit=5)
        
        assert len(results) == 5
        assert all(r.fingerprint == "test-fp-1" for r in results)
        # Should be newest first (query returns reversed)
        # records are added oldest-to-newest in list
        # reversed() returns newest-to-oldest
        assert results[0].timestamp >= results[-1].timestamp
    
    def test_capacity_limit(self, temp_dir, mock_experience_record):
        """Test Working Layer capacity limit (default 100)"""
        from experience_layering import WorkingLayer, ExperienceRecord
        
        layer = WorkingLayer(storage_path=temp_dir / "working.jsonl", capacity=100)
        
        # Add 150 records
        for i in range(150):
            layer.add(ExperienceRecord(**mock_experience_record(fingerprint=f"fp-{i}")))
        
        # Layer should have all 150 (eviction handled by coordinator)
        assert len(layer) == 150
    
    def test_fifo_eviction(self, temp_dir, sample_records):
        """Test FIFO eviction when capacity exceeded"""
        from experience_layering import WorkingLayer, ExperienceRecord
        
        layer = WorkingLayer(storage_path=temp_dir / "working.jsonl")
        
        # Add all records (18 total from fixture)
        for rec_data in sample_records:
            layer.add(ExperienceRecord(**rec_data))
        
        initial_count = len(layer)
        oldest_timestamps = [layer.records[i].timestamp for i in range(5)]
        
        # Evict 5
        evicted = layer.evict(count=5)
        
        assert len(evicted) == 5
        assert len(layer) == initial_count - 5
        # Evicted should be oldest (first 5 in list)
        assert [e.timestamp for e in evicted] == oldest_timestamps
    
    def test_persistence(self, temp_dir, sample_records):
        """Test persistence to working.jsonl"""
        from experience_layering import WorkingLayer, ExperienceRecord
        
        path = temp_dir / "working.jsonl"
        
        # Create layer and add records
        layer1 = WorkingLayer(storage_path=path)
        for rec_data in sample_records[:10]:
            layer1.add(ExperienceRecord(**rec_data))
        
        # Create new layer (should load from disk)
        layer2 = WorkingLayer(storage_path=path)
        
        assert len(layer2) == 10
        assert layer2.records[0].fingerprint == sample_records[0]["fingerprint"]


# =============================================================================
# Recall Layer Tests
# =============================================================================

class TestRecallLayer:
    """Tests for Recall Layer (warm data)"""
    
    def test_add_batch(self, temp_dir, sample_records):
        """Test adding batch of records to Recall Layer"""
        # TODO: Implement
        pass
    
    def test_date_sharding(self, temp_dir, sample_records):
        """Test records are sharded by date"""
        # TODO: Implement
        pass
    
    def test_query_by_fingerprint(self, temp_dir, sample_records):
        """Test querying across date shards"""
        # TODO: Implement
        pass
    
    def test_find_older_than(self, temp_dir, sample_records):
        """Test finding records older than cutoff date"""
        # TODO: Implement
        pass
    
    def test_index_update(self, temp_dir, sample_records):
        """Test index is updated when adding records"""
        # TODO: Implement
        pass


# =============================================================================
# Archival Layer Tests
# =============================================================================

class TestArchivalLayer:
    """Tests for Archival Layer (cold data)"""
    
    def test_archive(self, temp_dir, sample_records):
        """Test archiving records"""
        # TODO: Implement
        pass
    
    def test_compression(self, temp_dir, sample_records):
        """Test records are compressed"""
        # TODO: Implement
        pass
    
    def test_query_by_index(self, temp_dir, sample_records):
        """Test querying through index"""
        # TODO: Implement
        pass
    
    def test_summary_stats(self, temp_dir, sample_records):
        """Test aggregated summary statistics"""
        # TODO: Implement
        pass


# =============================================================================
# Data Flow Tests
# =============================================================================

class TestDataFlow:
    """Tests for data flow between layers"""
    
    def test_working_to_recall_flow(self, temp_dir, sample_records):
        """Test automatic eviction from Working to Recall"""
        # TODO: Implement
        pass
    
    def test_recall_to_archival_flow(self, temp_dir, sample_records):
        """Test automatic archiving from Recall to Archival"""
        # TODO: Implement
        pass
    
    def test_end_to_end_flow(self, temp_dir, mock_experience_record):
        """Test complete data flow through all three layers"""
        # TODO: Implement
        pass


# =============================================================================
# Query Routing Tests
# =============================================================================

class TestQueryRouting:
    """Tests for query routing across layers"""
    
    def test_forecast_uses_working_only(self, temp_dir, sample_records):
        """Test forecast() only queries Working Layer"""
        from experience_layering import ExperienceLayering, ExperienceRecord
        
        layering = ExperienceLayering(base_dir=temp_dir)
        
        # Add records to Working
        for rec_data in sample_records[:10]:
            layering.working.add(ExperienceRecord(**rec_data))
        
        # Forecast
        result = layering.forecast("test-fp-1")
        
        assert result["source"] == "working"
        assert result["sample_size"] == 10
        assert 0.0 <= result["success_rate"] <= 1.0
        assert 0.0 <= result["confidence"] <= 1.0
    
    def test_statistics_routing(self, temp_dir, sample_records):
        """Test query_statistics() routes to appropriate layers"""
        from experience_layering import ExperienceLayering, ExperienceRecord
        
        layering = ExperienceLayering(base_dir=temp_dir)
        
        # Add records (10 success, 5 failure, 3 lost = 18 total)
        for rec_data in sample_records:
            layering.working.add(ExperienceRecord(**rec_data))
        
        # Query statistics
        stats = layering.query_statistics("test-fp-1")
        
        assert stats["total_runs"] == 18
        assert stats["success_count"] == 10
        assert stats["failure_count"] == 5
        assert stats["lost_count"] == 3
        assert abs(stats["success_rate"] - 10/18) < 0.01
        assert abs(stats["lost_rate"] - 3/18) < 0.01
        assert stats["source"] == "working"
    
    def test_cross_layer_consistency(self, temp_dir, sample_records):
        """Test queries return consistent results across layers"""
        from experience_layering import ExperienceLayering, ExperienceRecord
        
        layering = ExperienceLayering(base_dir=temp_dir)
        
        # Add same data
        for rec_data in sample_records[:10]:
            layering.working.add(ExperienceRecord(**rec_data))
        
        # forecast and statistics should be consistent
        forecast = layering.forecast("test-fp-1")
        stats = layering.query_statistics("test-fp-1")
        
        assert forecast["success_rate"] == stats["success_rate"]
        assert forecast["sample_size"] == stats["total_runs"]


# =============================================================================
# record_lost() Integration Tests
# =============================================================================

class TestRecordLost:
    """Tests for record_lost() integration with Reaper"""
    
    def test_record_lost_basic(self, temp_dir):
        """Test basic record_lost() functionality"""
        from experience_layering import ExperienceLayering
        
        # Initialize layering
        layering = ExperienceLayering(base_dir=temp_dir)
        
        # Record a lost event
        layering.record_lost(
            fingerprint="test-fp",
            reason="lease_expired",
            timestamp=int(time.time()),
        )
        
        # Verify record was added to Working Layer
        assert len(layering.working) == 1
        record = layering.working.records[0]
        assert record.fingerprint == "test-fp"
        assert record.outcome == "lost"
        assert record.reason == "lease_expired"
    
    def test_record_lost_deduplication(self, temp_dir):
        """Test record_lost() deduplicates recent lost events"""
        from experience_layering import ExperienceLayering
        
        # Initialize layering
        layering = ExperienceLayering(base_dir=temp_dir)
        
        # Record first lost event
        ts = int(time.time())
        layering.record_lost(
            fingerprint="test-fp",
            reason="lease_expired",
            timestamp=ts,
        )
        
        # Try to record duplicate within 60 seconds (should be deduplicated)
        layering.record_lost(
            fingerprint="test-fp",
            reason="lease_expired",
            timestamp=ts + 30,  # 30 seconds later
        )
        
        # Should still have only 1 record
        assert len(layering.working) == 1
        
        # Record another lost event after 60+ seconds (should be added)
        layering.record_lost(
            fingerprint="test-fp",
            reason="lease_expired",
            timestamp=ts + 70,  # 70 seconds later
        )
        
        # Should now have 2 records
        assert len(layering.working) == 2
    
    def test_record_lost_triggers_reevaluation(self, temp_dir, mock_experience_record):
        """Test record_lost() triggers admission policy reevaluation"""
        # TODO: Implement
        pass


# =============================================================================
# Helper Assertions
# =============================================================================

def assert_record_in_layer(record: dict, layer_path: Path):
    """Assert a record exists in the given layer"""
    # TODO: Implement
    pass


def assert_layer_count(layer_path: Path, expected_count: int):
    """Assert layer contains expected number of records"""
    # TODO: Implement
    pass


def assert_eviction_order(evicted: List[dict], expected_order: str = "fifo"):
    """Assert evicted records follow expected order (FIFO)"""
    # TODO: Implement
    pass
