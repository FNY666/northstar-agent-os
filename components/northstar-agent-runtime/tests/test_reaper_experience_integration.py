"""
集成测试：Reaper ↔ Experience

测试端到端流程：
1. Reaper 发现过期 lease
2. Reaper 标记 lost
3. Experience 接收 lost 事件
4. Experience 更新统计
5. Experience 影响准入决策
"""

import time
import tempfile
from pathlib import Path
import pytest

from ownership_ledger import OwnershipLedger
from reaper import Reaper


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def temp_dir():
    """临时目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def ownership_ledger(temp_dir):
    """OwnershipLedger 实例"""
    return OwnershipLedger(temp_dir / "ownership.jsonl")


@pytest.fixture
def mock_experience():
    """Mock Experience（记录 record_lost 调用）"""
    class MockExperience:
        def __init__(self):
            self.lost_records = []
        
        def record_lost(self, fingerprint, reason, timestamp):
            """记录 lost 事件"""
            self.lost_records.append({
                "fingerprint": fingerprint,
                "reason": reason,
                "timestamp": timestamp,
            })
        
        def query_statistics(self, fingerprint):
            """返回统计（含 lost_rate）"""
            total = len([r for r in self.lost_records if r["fingerprint"] == fingerprint])
            return {
                "total_runs": total,
                "lost_rate": 1.0 if total > 0 else 0.0,
            }
    
    return MockExperience()


@pytest.fixture
def mock_admission_ledger(mock_experience):
    """Mock AdmissionLedger（桥接到 Experience）"""
    class MockAdmissionLedger:
        def __init__(self, experience):
            self.experience = experience
            self.records = []
        
        def record(self, session_id, admission, observed_at, goal_fingerprint):
            """记录准入决策，并通知 Experience"""
            self.records.append({
                "session_id": session_id,
                "admission": admission,
                "observed_at": observed_at,
                "goal_fingerprint": goal_fingerprint,
            })
            
            # 如果是 lost 事件，通知 Experience
            if admission.get("state") == "lost-lease-expired":
                self.experience.record_lost(
                    fingerprint=goal_fingerprint,
                    reason=admission.get("reason", "lease_expired"),
                    timestamp=observed_at,
                )
    
    return MockAdmissionLedger(mock_experience)


@pytest.fixture
def reaper(ownership_ledger, mock_admission_ledger):
    """Reaper 实例（连接 mock）"""
    return Reaper(ownership_ledger, mock_admission_ledger)


# ============================================================
# 集成测试
# ============================================================

class TestReaperExperienceIntegration:
    """Reaper ↔ Experience 集成测试"""
    
    def test_reaper_marks_lost_triggers_experience(
        self, reaper, ownership_ledger, mock_admission_ledger, mock_experience
    ):
        """Reaper 标记 lost 应该触发 Experience 记录"""
        # 1. 创建并等待过期
        ownership_ledger.acquire("run-1", "owner-1", ttl=1)
        time.sleep(2)
        
        # 2. Reaper 扫描并标记
        result = reaper.reap(grace_period=0)
        assert result.marked_lost == 1
        
        # 3. 验证 AdmissionLedger 有记录（Phase 2 完整集成）
        assert len(mock_admission_ledger.records) == 1
        record = mock_admission_ledger.records[0]
        assert record["admission"]["state"] == "lost-lease-expired"
        assert record["session_id"] == "owner-1"
        
        # 4. 验证 Experience 收到通知（通过 mock_admission_ledger 桥接）
        assert len(mock_experience.lost_records) == 1
        lost = mock_experience.lost_records[0]
        assert lost["reason"] == "lease_expired"
    
    def test_lost_rate_affects_statistics(
        self, reaper, ownership_ledger, mock_experience
    ):
        """lost 事件应该影响统计查询"""
        # 模拟多次 lost
        for i in range(3):
            mock_experience.record_lost(
                fingerprint="test-goal",
                reason="lease_expired",
                timestamp=int(time.time()),
            )
        
        # 查询统计
        stats = mock_experience.query_statistics("test-goal")
        assert stats["total_runs"] == 3
        assert stats["lost_rate"] == 1.0
    
    def test_end_to_end_flow(
        self, reaper, ownership_ledger, mock_admission_ledger, mock_experience
    ):
        """端到端完整流程"""
        # 1. 创建 3 个 lease
        for i in range(3):
            ownership_ledger.acquire(f"run-{i}", f"owner-{i}", ttl=1)
        
        # 2. 等待过期
        time.sleep(2)
        
        # 3. Reaper 扫描并标记
        result = reaper.reap(grace_period=0)
        assert result.scanned == 3
        assert result.marked_lost == 3
        
        # 4. 验证所有 lease 都是 lost
        for i in range(3):
            ownership = ownership_ledger.query(f"run-{i}")
            assert ownership.state == "lost"
        
        # TODO: 验证 Experience 统计
        # 等待完整集成后启用


# ============================================================
# 运行测试
# ============================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
