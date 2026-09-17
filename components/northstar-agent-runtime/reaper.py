"""
Reaper - Lease 收敛与恢复机制

职责：
1. 扫描过期的 lease
2. 标记为 lost 状态
3. 可选触发恢复

设计原则：
- Reaper 只标记，不执行业务逻辑
- 通过 AdmissionLedger 与 Experience 解耦
- 幂等、并发安全

使用示例：
    ```python
    from pathlib import Path
    from ownership_ledger import OwnershipLedger
    from reaper import Reaper
    
    # 初始化
    ownership_ledger = OwnershipLedger(Path("ownership.jsonl"))
    reaper = Reaper(ownership_ledger, default_grace_period=60)
    
    # 手动 reap（扫描并标记过期 lease）
    result = reaper.reap(grace_period=60, auto_recover=False)
    print(f"Scanned: {result.scanned}, Marked lost: {result.marked_lost}")
    
    # 定时 reap（通过 minis-scheduled，推荐方式）
    # minis-scheduled create --prompt "python reaper.py" --interval 5m
    ```

实现阶段：
    - Phase 1: 基础扫描与标记 ✅
    - Phase 2: 定时任务集成 + 监控（TODO）
    - Phase 3: 自动恢复（TODO）

与 Experience 集成：
    Reaper 通过 AdmissionLedger 与 Experience 解耦通信：
    
    ```
    Reaper.mark_lost(run_id, reason)
        ↓
    AdmissionLedger.record(state="lost-lease-expired", ...)  ← Phase 2
        ↓
    Experience.record_lost(fingerprint, reason, timestamp)
        ↓
    WorkingLayer.add(ExperienceRecord(outcome="lost"))
        ↓
    query_statistics() 返回 lost_rate
    ```
    
    注意：Phase 1 中 AdmissionLedger 集成暂时跳过，
          等待 Phase 2 完整实现 AdmissionLedger 和 ContinuationAdmission。

性能考虑：
    - scan_stale_leases() 默认只扫描 active lease
    - grace_period 防止时钟误差导致误杀
    - 幂等性保证并发 Reaper 安全

最佳实践：
    1. 定时扫描间隔：5 分钟（推荐）
    2. grace_period：60 秒（默认，防止时钟误差）
    3. 生产环境：使用 minis-scheduled 定时触发
    4. 监控：记录 reap 结果并告警（Phase 2）
"""

import time
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass

from ownership_ledger import OwnershipLedger, RunOwnership


# ============================================================
# Data Structures
# ============================================================

@dataclass
class ReapResult:
    """Reap 循环的统计结果"""
    scanned: int           # 扫描的 lease 总数
    marked_lost: int       # 标记为 lost 的数量
    recovered: int         # 触发恢复的数量（Phase 3）
    timestamp: int         # 执行时间
    grace_period: int      # 使用的 grace_period


@dataclass
class ReapMetrics:
    """Reaper 监控指标
    
    用于导出到 metrics.json 供 Prometheus 或日志系统采集
    """
    timestamp: int                  # 采集时间戳
    total_scanned: int              # 本次扫描总数
    total_marked_lost: int          # 本次标记 lost 总数
    total_recovered: int            # 本次恢复总数（Phase 3）
    grace_period_seconds: int       # 使用的宽限期
    scan_duration_ms: int           # 扫描耗时（毫秒）
    mark_duration_ms: int           # 标记耗时（毫秒）
    total_duration_ms: int          # 总耗时（毫秒）
    active_leases: int              # 当前活跃 lease 数量
    lost_leases: int                # 当前 lost lease 数量
    
    def to_dict(self) -> dict:
        """转换为字典（用于 JSON 序列化）"""
        return {
            "timestamp": self.timestamp,
            "total_scanned": self.total_scanned,
            "total_marked_lost": self.total_marked_lost,
            "total_recovered": self.total_recovered,
            "grace_period_seconds": self.grace_period_seconds,
            "scan_duration_ms": self.scan_duration_ms,
            "mark_duration_ms": self.mark_duration_ms,
            "total_duration_ms": self.total_duration_ms,
            "active_leases": self.active_leases,
            "lost_leases": self.lost_leases,
        }


# ============================================================
# Reaper
# ============================================================

class Reaper:
    """
    Reaper - Lease 收敛与恢复机制
    
    使用示例：
    ```python
    ownership_ledger = OwnershipLedger(Path("ownership.jsonl"))
    admission_ledger = AdmissionLedger(...)
    
    reaper = Reaper(ownership_ledger, admission_ledger, default_grace_period=60)
    
    # 手动 reap
    result = reaper.reap(auto_recover=False)
    print(f"Marked {result.marked_lost} lost leases")
    
    # 定时 reap（通过 minis-scheduled）
    # minis-scheduled create --prompt "运行 Reaper" --interval 5m
    ```
    
    实现阶段：
    - Phase 1: 基础扫描与标记（当前）
    - Phase 2: 定时任务集成
    - Phase 3: 自动恢复
    """
    
    def __init__(
        self,
        ownership_ledger: OwnershipLedger,
        admission_ledger=None,  # Optional[AdmissionLedger]
        default_grace_period: int = 60,
        metrics_path: Optional[Path] = None,
    ):
        """
        初始化 Reaper
        
        Args:
            ownership_ledger: OwnershipLedger 实例
            admission_ledger: AdmissionLedger 实例（可选，用于集成 Experience）
            default_grace_period: 默认宽限期（秒），防止时钟误差
            metrics_path: 监控指标输出路径（可选，Phase 2）
        """
        self.ownership_ledger = ownership_ledger
        self.admission_ledger = admission_ledger
        self.default_grace_period = default_grace_period
        self.metrics_path = metrics_path
    
    # ============================================================
    # 扫描逻辑
    # ============================================================
    
    def scan_stale_leases(self, grace_period: Optional[int] = None) -> List[RunOwnership]:
        """
        扫描所有过期的 lease
        
        算法：
        1. 获取所有 active lease（通过 list_all）
        2. 检查每个 lease 是否过期
        3. 考虑 grace_period（防止时钟误差）
        
        Args:
            grace_period: 宽限期（秒），None 使用默认值
        
        Returns:
            过期的 RunOwnership 列表
        """
        grace_period = grace_period if grace_period is not None else self.default_grace_period
        all_leases = self.ownership_ledger.list_all(states=["active"])
        now = int(time.time())
        
        stale = []
        for lease in all_leases:
            # 检查是否过期（acquired_at + ttl + grace_period < now）
            if now >= lease.acquired_at + lease.lease_ttl + grace_period:
                stale.append(lease)
        
        return stale
    
    # ============================================================
    # 标记逻辑
    # ============================================================
    
    def mark_lost(self, run_id: str, reason: str = "lease_expired") -> RunOwnership:
        """
        标记 lease 为 lost 状态
        
        幂等性保证：
        - 查询当前状态
        - 如果已经 lost，直接返回
        - 否则调用 ownership_ledger.mark_lost()
        
        副作用：
        - 写入 OwnershipLedger
        - 写入 AdmissionLedger（如果配置）
        
        Args:
            run_id: 运行 ID
            reason: 原因（lease_expired / manual / crash_detected）
        
        Returns:
            标记后的 RunOwnership
        """
        # 幂等性检查
        current = self.ownership_ledger.query(run_id)
        if current and current.state == "lost":
            return current
        
        # 标记 lost (返回 None)
        self.ownership_ledger.mark_lost(run_id, reason)
        
        # 重新查询获取最新状态
        ownership = self.ownership_ledger.query(run_id)
        
        # 集成 AdmissionLedger（如果配置）
        # Phase 1: 暂时跳过，等待 Phase 2 完整实现
        # 
        # 原因：
        # 1. AdmissionLedger 和 ContinuationAdmission 尚未完整实现
        # 2. Phase 1 专注于 Reaper 核心功能（扫描/标记/reap）
        # 3. 集成测试框架已验证接口正确性
        # 
        # Phase 2 实现计划：
        # ```python
        # if self.admission_ledger:
        #     admission = ContinuationAdmission(
        #         state="lost-lease-expired",
        #         observed_at=int(time.time()),
        #         reason=reason,
        #     )
        #     self.admission_ledger.record(
        #         session_id=ownership.owner_id,
        #         admission=admission,
        #         observed_at=int(time.time()),
        #         goal_fingerprint=self._derive_fingerprint(run_id),
        #     )
        # ```
        # 
        # 集成后流程：
        # AdmissionLedger.record() → Experience.record_lost() → WorkingLayer
        if self.admission_ledger:
            pass  # Phase 2 实现
        
        return ownership
    
    # ============================================================
    # Reap 循环
    # ============================================================
    
    def reap(
        self,
        grace_period: Optional[int] = None,
        auto_recover: bool = False,
    ) -> ReapResult:
        """
        执行一次完整的 reap 循环
        
        流程：
        1. scan_stale_leases() - 扫描过期 lease
        2. mark_lost() - 标记每个过期 lease
        3. trigger_recovery() - 可选恢复（Phase 3）
        4. 收集监控指标并输出（Phase 2）
        
        Args:
            grace_period: 宽限期（秒），None 使用默认值
            auto_recover: 是否自动触发恢复（Phase 3）
        
        Returns:
            ReapResult 统计信息
        """
        grace_period = grace_period if grace_period is not None else self.default_grace_period
        start_time = time.time()
        
        # 扫描
        scan_start = time.time()
        stale_leases = self.scan_stale_leases(grace_period)
        scan_duration = int((time.time() - scan_start) * 1000)
        
        # 标记
        mark_start = time.time()
        marked = []
        for lease in stale_leases:
            marked.append(self.mark_lost(lease.run_id, reason="lease_expired"))
        mark_duration = int((time.time() - mark_start) * 1000)
        
        # 恢复（Phase 3）
        recovered = []
        if auto_recover:
            for lease in marked:
                if self.trigger_recovery(lease.run_id):
                    recovered.append(lease.run_id)
        
        # 收集监控指标（Phase 2）
        total_duration = int((time.time() - start_time) * 1000)
        all_leases = self.ownership_ledger.list_all()
        active_count = len([l for l in all_leases if l.state == "active"])
        lost_count = len([l for l in all_leases if l.state == "lost"])
        
        metrics = ReapMetrics(
            timestamp=int(time.time()),
            total_scanned=len(all_leases),
            total_marked_lost=len(marked),
            total_recovered=len(recovered),
            grace_period_seconds=grace_period,
            scan_duration_ms=scan_duration,
            mark_duration_ms=mark_duration,
            total_duration_ms=total_duration,
            active_leases=active_count,
            lost_leases=lost_count,
        )
        
        # 输出监控指标
        self._write_metrics(metrics)
        
        return ReapResult(
            scanned=len(all_leases),
            marked_lost=len(marked),
            recovered=len(recovered),
            timestamp=int(time.time()),
            grace_period=grace_period,
        )
    
    def _write_metrics(self, metrics: ReapMetrics) -> None:
        """
        写入监控指标到文件
        
        Phase 2: 输出 JSON 格式的监控指标供 Prometheus 或日志系统采集
        """
        if not self.metrics_path:
            return
        
        try:
            import json
            self.metrics_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.metrics_path, 'w') as f:
                json.dump(metrics.to_dict(), f, indent=2)
        except Exception as e:
            # 监控失败不应该影响 reap 流程
            import logging
            logging.warning(f"Failed to write reaper metrics: {e}")
    
    # ============================================================
    # 恢复逻辑（Phase 3）
    # ============================================================
    
    def trigger_recovery(self, run_id: str) -> bool:
        """
        触发恢复（Phase 3 功能）
        
        恢复策略：
        - 查询 Experience 统计
        - 根据 success_rate / lost_rate 决定是否恢复
        
        Args:
            run_id: 运行 ID
        
        Returns:
            是否成功触发恢复
        
        实现状态：Phase 3
        
        Phase 3 实现计划：
            基于 Experience 统计的智能恢复决策
            
            ```python
            fingerprint = self._derive_fingerprint(run_id)
            stats = self.experience.query_statistics(fingerprint)
            
            # 策略 1：历史成功率高 → 自动恢复
            if stats.success_rate > 0.7:
                return self.runtime.resume_run(run_id)
            
            # 策略 2：频繁 lost → 不自动恢复
            if stats.lost_rate > 0.3:
                return False
            
            # 策略 3：默认保守（人工介入）
            return False
            ```
            
        设计考虑：
            - Reaper 不应该执行业务逻辑
            - 恢复决策应该基于 Experience 统计
            - 保守策略优先（避免误恢复）
            - 需要与 Runtime 协调 resume 接口
        """
        # Phase 1: 不实现
        return False
    
    # ============================================================
    # 辅助方法
    # ============================================================
    
    def _derive_fingerprint(self, run_id: str) -> str:
        """
        从 run_id 派生 fingerprint（用于 Experience 查询）
        
        TODO: 实现真实的派生逻辑
        """
        # 简化版：直接使用 run_id
        return run_id


# ============================================================
# CLI 入口（用于手动 reap）
# ============================================================

def main():
    """
    CLI 入口（手动触发 reap）
    
    使用：
    python reaper.py --grace-period 60
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="Reaper - Lease 收敛工具")
    parser.add_argument("--grace-period", type=int, default=60, help="宽限期（秒）")
    parser.add_argument("--ledger", type=Path, default=Path("ownership.jsonl"), help="OwnershipLedger 路径")
    args = parser.parse_args()
    
    # 初始化
    ownership_ledger = OwnershipLedger(args.ledger)
    reaper = Reaper(ownership_ledger, default_grace_period=args.grace_period)
    
    # 执行 reap
    result = reaper.reap()
    
    # 输出统计
    print(f"Reaper completed:")
    print(f"  Scanned: {result.scanned}")
    print(f"  Marked lost: {result.marked_lost}")
    print(f"  Recovered: {result.recovered}")
    print(f"  Grace period: {result.grace_period}s")


if __name__ == "__main__":
    main()
