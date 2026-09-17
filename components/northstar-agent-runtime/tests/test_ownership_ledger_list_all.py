"""
Test OwnershipLedger.list_all() with states parameter

测试新增的 states 过滤功能
"""
import tempfile
from pathlib import Path
import pytest

from ownership_ledger import OwnershipLedger


def test_list_all_without_states_returns_all():
    """list_all() 不传参数应该返回所有状态"""
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = OwnershipLedger(Path(tmpdir) / "ownership.jsonl")
        
        # 创建 3 个 lease：active, lost, released
        ledger.acquire("run-1", "owner-1", ttl=300)
        ledger.acquire("run-2", "owner-2", ttl=300)
        ownership_3 = ledger.acquire("run-3", "owner-3", ttl=300)
        
        ledger.mark_lost("run-2", "test")
        ledger.release(ownership_3)
        
        # 不传参数应该返回全部 3 个
        all_records = ledger.list_all()
        assert len(all_records) == 3
        
        states = {r.state for r in all_records}
        assert states == {"active", "lost", "released"}


def test_list_all_with_states_active_only():
    """list_all(states=["active"]) 应该只返回 active"""
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = OwnershipLedger(Path(tmpdir) / "ownership.jsonl")
        
        # 创建 3 个 lease
        ledger.acquire("run-1", "owner-1", ttl=300)
        ledger.acquire("run-2", "owner-2", ttl=300)
        ownership_3 = ledger.acquire("run-3", "owner-3", ttl=300)
        
        ledger.mark_lost("run-2", "test")
        ledger.release(ownership_3)
        
        # 只返回 active
        active_records = ledger.list_all(states=["active"])
        assert len(active_records) == 1
        assert active_records[0].run_id == "run-1"
        assert active_records[0].state == "active"


def test_list_all_with_multiple_states():
    """list_all(states=["active", "lost"]) 应该返回多个状态"""
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = OwnershipLedger(Path(tmpdir) / "ownership.jsonl")
        
        ledger.acquire("run-1", "owner-1", ttl=300)
        ledger.acquire("run-2", "owner-2", ttl=300)
        ownership_3 = ledger.acquire("run-3", "owner-3", ttl=300)
        
        ledger.mark_lost("run-2", "test")
        ledger.release(ownership_3)
        
        # 返回 active + lost
        records = ledger.list_all(states=["active", "lost"])
        assert len(records) == 2
        
        states = {r.state for r in records}
        assert states == {"active", "lost"}


def test_list_all_empty_states_returns_empty():
    """list_all(states=[]) 应该返回空列表"""
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = OwnershipLedger(Path(tmpdir) / "ownership.jsonl")
        
        ledger.acquire("run-1", "owner-1", ttl=300)
        
        # 空 states 列表应该返回空
        records = ledger.list_all(states=[])
        assert records == []


def test_list_all_empty_ledger():
    """空 ledger 应该返回空列表（不论 states 参数）"""
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger = OwnershipLedger(Path(tmpdir) / "ownership.jsonl")
        
        # 无参数
        assert ledger.list_all() == []
        
        # 带 states
        assert ledger.list_all(states=["active"]) == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
