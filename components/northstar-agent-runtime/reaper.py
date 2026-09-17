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
    ):
        """
        初始化 Reaper
        
        Args:
            ownership_ledger: OwnershipLedger 实例
            admission_ledger: AdmissionLedger 实例（可选，用于集成 Experience）
            default_grace_period: 默认宽限期（秒），防止时钟误差
        """
        self.ownership_ledger = ownership_ledger
        self.admission_ledger = admission_ledger
        self.default_grace_period = default_grace_period
    
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
        if self.admission_ledger:
            # TODO: 等待 AdmissionLedger 和 ContinuationAdmission 实现
            # admission = ContinuationAdmission(
            #     state="lost-lease-expired",
            #     observed_at=int(time.time()),
            #     reason=reason,
            # )
            # self.admission_ledger.record(
            #     session_id=ownership.owner_id,
            #     admission=admission,
            #     observed_at=int(time.time()),
            #     goal_fingerprint=self._derive_fingerprint(run_id),
            # )
            pass
        
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
        
        Args:
            grace_period: 宽限期（秒），None 使用默认值
            auto_recover: 是否自动触发恢复（Phase 3）
        
        Returns:
            ReapResult 统计信息
        """
        grace_period = grace_period if grace_period is not None else self.default_grace_period
        
        # 扫描
        stale_leases = self.scan_stale_leases(grace_period)
        
        # 标记
        marked = []
        for lease in stale_leases:
            marked.append(self.mark_lost(lease.run_id, reason="lease_expired"))
        
        # 恢复（Phase 3）
        recovered = []
        if auto_recover:
            for lease in marked:
                if self.trigger_recovery(lease.run_id):
                    recovered.append(lease.run_id)
        
        return ReapResult(
            scanned=len(self.ownership_ledger.list_all()),
            marked_lost=len(marked),
            recovered=len(recovered),
            timestamp=int(time.time()),
            grace_period=grace_period,
        )
    
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
        """
        # Phase 1: 不实现
        return False
        
        # TODO: Phase 3 实现
        # fingerprint = self._derive_fingerprint(run_id)
        # stats = self.experience.query_statistics(fingerprint)
        # 
        # # 策略 1：历史成功率高 → 自动恢复
        # if stats.success_rate > 0.7:
        #     return self.runtime.resume_run(run_id)
        # 
        # # 策略 2：频繁 lost → 不自动恢复
        # if stats.lost_rate > 0.3:
        #     return False
        # 
        # # 策略 3：默认保守（人工介入）
        # return False
    
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
