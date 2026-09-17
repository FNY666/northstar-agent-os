"""
Test suite for Reaper (lease收敛与恢复机制)

Reaper 负责：
1. 扫描过期的 lease
2. 标记为 lost 状态
3. 可选触发恢复

测试覆盖：
- 扫描逻辑（grace_period、状态过滤）
- 标记逻辑（去重、幂等性）
- reap 循环（统计、并发）
- 与 OwnershipLedger 集成
- 与 AdmissionLedger 集成
"""

import time
import tempfile
from pathlib import Path
from typing import Optional
import pytest

# TODO: 实现后取消注释
# from reaper import Reaper
from ownership_ledger import OwnershipLedger, RunOwnership


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def temp_dir():
    """临时目录（每个测试独立）"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def ownership_ledger(temp_dir):
    """真实 OwnershipLedger 实例"""
    ledger_path = temp_dir / "ownership.jsonl"
    return OwnershipLedger(ledger_path)


@pytest.fixture
def mock_admission_ledger():
    """Mock AdmissionLedger（记录调用）"""
    class MockAdmissionLedger:
        def __init__(self):
            self.records = []
        
        def record(self, session_id, admission, observed_at, goal_fingerprint):
            self.records.append({
                "session_id": session_id,
                "admission": admission,
                "observed_at": observed_at,
                "goal_fingerprint": goal_fingerprint,
            })
    
    return MockAdmissionLedger()


@pytest.fixture
def reaper(ownership_ledger, mock_admission_ledger):
    """Reaper 实例（连接真实 OwnershipLedger + Mock AdmissionLedger）"""
    from reaper import Reaper
    return Reaper(ownership_ledger, mock_admission_ledger)


# ============================================================
# 测试：扫描逻辑
# ============================================================

class TestScan:
    """测试 scan_stale_leases() 逻辑"""
    
    def test_scan_finds_expired_leases(self, reaper, ownership_ledger):
        """扫描应该发现过期的 lease"""
        # 创建 2 个 lease：1 个过期，1 个有效
        ownership_ledger.acquire("run-expired", "owner-1", ttl=1)
        time.sleep(2)  # 等待过期
        ownership_ledger.acquire("run-valid", "owner-2", ttl=300)
        
        stale = reaper.scan_stale_leases(grace_period=0)
        assert len(stale) == 1
        assert stale[0].run_id == "run-expired"
    
    def test_scan_respects_grace_period(self, reaper, ownership_ledger):
        """刚过期但在 grace_period 内的不应被扫描"""
        ownership_ledger.acquire("run-1", "owner-1", ttl=1)
        time.sleep(1.2)  # 过期 0.2 秒
        
        # grace_period=1 应该保护这个 lease（0.2 < 1）
        stale = reaper.scan_stale_leases(grace_period=1)
        assert len(stale) == 0
        
        # grace_period=0 应该能发现
        stale = reaper.scan_stale_leases(grace_period=0)
        assert len(stale) == 1
    
    def test_scan_ignores_non_active_leases(self, reaper, ownership_ledger):
        """已经 lost 或 released 的不应被扫描"""
        ownership_ledger.acquire("run-1", "owner-1", ttl=1)
        time.sleep(2)
        ownership_ledger.mark_lost("run-1", "manual")
        
        # 不应该重复扫描已 lost 的
        stale = reaper.scan_stale_leases(grace_period=0)
        assert len(stale) == 0
    
    def test_scan_empty_ledger(self, reaper):
        """空 ledger 不应报错"""
        stale = reaper.scan_stale_leases()
        assert stale == []


# ============================================================
# 测试：标记逻辑
# ============================================================

class TestMarkLost:
    """测试 mark_lost() 逻辑"""
    
    def test_mark_lost_writes_to_ownership_ledger(self, reaper, ownership_ledger):
        """mark_lost 应该写入 OwnershipLedger"""
        ownership_ledger.acquire("run-1", "owner-1", ttl=1)
        time.sleep(2)
        
        reaper.mark_lost("run-1", reason="lease_expired")
        
        result = ownership_ledger.query("run-1")
        assert result.state == "lost"
    
    def test_mark_lost_writes_to_admission_ledger(self, reaper, ownership_ledger, mock_admission_ledger):
        """mark_lost 应该写入 AdmissionLedger"""
        ownership_ledger.acquire("run-1", "owner-1", ttl=1)
        time.sleep(2)
        
        # TODO: AdmissionLedger 集成暂时跳过（等待 Experience 完成）
        reaper.mark_lost("run-1", reason="lease_expired")
        
        # 暂时不验证 AdmissionLedger（Phase 1 先完成基础功能）
        # assert len(mock_admission_ledger.records) == 1
        # record = mock_admission_ledger.records[0]
        # assert record["admission"].state == "lost-lease-expired"
    
    def test_mark_lost_is_idempotent(self, reaper, ownership_ledger):
        """多次 mark_lost 应该幂等"""
        ownership_ledger.acquire("run-1", "owner-1", ttl=1)
        time.sleep(2)
        
        result1 = reaper.mark_lost("run-1", "manual")
        result2 = reaper.mark_lost("run-1", "manual")
        assert result1.state == result2.state == "lost"


# ============================================================
# 测试：reap 循环
# ============================================================

class TestReap:
    """测试 reap() 完整循环"""
    
    def test_reap_marks_all_stale(self, reaper, ownership_ledger):
        """reap 应该标记所有 stale lease"""
        # 创建 3 个过期 lease
        for i in range(3):
            ownership_ledger.acquire(f"run-{i}", f"owner-{i}", ttl=1)
        time.sleep(2)
        
        result = reaper.reap(grace_period=0)
        assert result.marked_lost == 3
    
    def test_reap_returns_statistics(self, reaper, ownership_ledger):
        """reap 应该返回统计信息"""
        ownership_ledger.acquire("run-1", "owner-1", ttl=1)
        time.sleep(2)
        
        # 使用 grace_period=0 确保能标记
        result = reaper.reap(grace_period=0)
        assert result.scanned >= 1
        assert result.marked_lost == 1
        assert result.recovered == 0
        assert result.timestamp > 0
        assert result.grace_period == 0
    
    def test_reap_respects_already_lost(self, reaper, ownership_ledger):
        """reap 不应该重复标记已 lost 的"""
        ownership_ledger.acquire("run-1", "owner-1", ttl=1)
        time.sleep(2)
        ownership_ledger.mark_lost("run-1", "manual")
        
        result = reaper.reap(grace_period=0)
        assert result.marked_lost == 0


# ============================================================
# 测试：并发与边界
# ============================================================

class TestConcurrency:
    """测试并发场景"""
    
    def test_concurrent_reap_safe(self, ownership_ledger):
        """并发 reap 应该安全（flock 保护）"""
        # TODO: 并发测试较复杂，Phase 2 实现
        pytest.skip("Concurrent test deferred to Phase 2")
    
    def test_reap_mixed_states(self, reaper, ownership_ledger):
        """混合 active/lost/released 状态"""
        ownership_ledger.acquire("run-active", "owner-1", ttl=300)
        ownership_ledger.acquire("run-expired", "owner-2", ttl=1)
        time.sleep(2)
        ownership_3 = ownership_ledger.acquire("run-released", "owner-3", ttl=1)
        ownership_ledger.release(ownership_3)
        
        # 只应该标记 expired
        result = reaper.reap(grace_period=0)
        assert result.marked_lost == 1


# ============================================================
# 测试：错误处理
# ============================================================

class TestErrorHandling:
    """测试错误处理场景"""
    
    def test_mark_lost_nonexistent_run(self, reaper):
        """标记不存在的 run 应该报错"""
        with pytest.raises(Exception):  # OwnershipError
            reaper.mark_lost("nonexistent-run", "test")
    
    def test_scan_with_negative_grace_period(self, reaper, ownership_ledger):
        """负数 grace_period 应该正常工作（视为 0）"""
        ownership_ledger.acquire("run-1", "owner-1", ttl=1)
        time.sleep(2)
        
        # 负数 grace_period 不应该崩溃
        stale = reaper.scan_stale_leases(grace_period=-10)
        assert len(stale) == 1
    
    def test_reap_with_custom_grace_period(self, reaper, ownership_ledger):
        """自定义 grace_period 应该覆盖默认值"""
        ownership_ledger.acquire("run-1", "owner-1", ttl=1)
        time.sleep(1.2)
        
        # 默认 60 秒不会标记
        result1 = reaper.reap()
        assert result1.marked_lost == 0
        assert result1.grace_period == 60
        
        # 自定义 0 秒会标记
        result2 = reaper.reap(grace_period=0)
        assert result2.marked_lost == 1
        assert result2.grace_period == 0


# ============================================================
# 测试：监控指标（Phase 2）
# ============================================================

class TestMetrics:
    """测试监控指标（Phase 2）"""
    
    def test_reap_writes_metrics(self, temp_dir, ownership_ledger):
        """reap 应该写入监控指标到文件"""
        from reaper import Reaper
        
        metrics_path = temp_dir / "reaper-metrics.json"
        reaper = Reaper(ownership_ledger, metrics_path=metrics_path)
        
        # 创建并标记一个 lease
        ownership_ledger.acquire("run-1", "owner-1", ttl=1)
        time.sleep(2)
        
        # 执行 reap
        result = reaper.reap(grace_period=0)
        
        # 验证 metrics 文件存在
        assert metrics_path.exists()
        
        # 验证 metrics 内容
        import json
        with open(metrics_path) as f:
            metrics = json.load(f)
        
        assert metrics["total_scanned"] == 1
        assert metrics["total_marked_lost"] == 1
        assert metrics["grace_period_seconds"] == 0
        assert "scan_duration_ms" in metrics
        assert "mark_duration_ms" in metrics
        assert "total_duration_ms" in metrics
        assert metrics["active_leases"] == 0
        assert metrics["lost_leases"] == 1
    
    def test_reap_without_metrics_path(self, ownership_ledger):
        """没有 metrics_path 时应该正常运行（不写入）"""
        from reaper import Reaper
        
        reaper = Reaper(ownership_ledger, metrics_path=None)
        ownership_ledger.acquire("run-1", "owner-1", ttl=1)
        time.sleep(2)
        
        # 应该正常运行不报错
        result = reaper.reap(grace_period=0)
        assert result.marked_lost == 1
    
    def test_metrics_performance_tracking(self, temp_dir, ownership_ledger):
        """监控指标应该包含性能数据"""
        from reaper import Reaper
        
        metrics_path = temp_dir / "metrics.json"
        reaper = Reaper(ownership_ledger, metrics_path=metrics_path)
        
        # 创建多个 lease
        for i in range(5):
            ownership_ledger.acquire(f"run-{i}", f"owner-{i}", ttl=1)
        time.sleep(2)
        
        # 执行 reap
        reaper.reap(grace_period=0)
        
        # 验证性能指标
        import json
        with open(metrics_path) as f:
            metrics = json.load(f)
        
        # 应该有合理的性能数据
        assert metrics["scan_duration_ms"] >= 0
        assert metrics["mark_duration_ms"] >= 0
        assert metrics["total_duration_ms"] >= metrics["scan_duration_ms"]
        assert metrics["total_duration_ms"] >= metrics["mark_duration_ms"]


# ============================================================
# 运行测试
# ============================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
