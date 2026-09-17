#!/usr/bin/env python3
"""
Reaper 定时任务包装脚本

使用方法：
    # 通过 minis-scheduled 定时运行
    minis-scheduled create \
        --prompt "python3 /path/to/reaper_scheduled.py" \
        --interval 5m \
        --repeat continuous

环境变量：
    OWNERSHIP_LEDGER_PATH: OwnershipLedger 文件路径（默认：./ownership.jsonl）
    REAPER_GRACE_PERIOD: 宽限期（秒，默认：60）
    REAPER_METRICS_PATH: 监控指标输出路径（可选）
"""

import os
import sys
import logging
from pathlib import Path

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def main():
    """定时任务入口"""
    # 读取环境变量
    ledger_path = Path(os.environ.get(
        'OWNERSHIP_LEDGER_PATH',
        './ownership.jsonl'
    ))
    grace_period = int(os.environ.get('REAPER_GRACE_PERIOD', '60'))
    metrics_path_str = os.environ.get('REAPER_METRICS_PATH')
    metrics_path = Path(metrics_path_str) if metrics_path_str else None
    
    logger.info(f"Starting Reaper scheduled task")
    logger.info(f"  Ledger: {ledger_path}")
    logger.info(f"  Grace period: {grace_period}s")
    logger.info(f"  Metrics: {metrics_path or 'disabled'}")
    
    try:
        # 导入 Reaper
        from ownership_ledger import OwnershipLedger
        from reaper import Reaper
        
        # 初始化
        ownership_ledger = OwnershipLedger(ledger_path)
        reaper = Reaper(
            ownership_ledger,
            default_grace_period=grace_period,
            metrics_path=metrics_path,
        )
        
        # 执行 reap
        result = reaper.reap()
        
        # 记录结果
        logger.info(f"Reap completed successfully")
        logger.info(f"  Scanned: {result.scanned}")
        logger.info(f"  Marked lost: {result.marked_lost}")
        logger.info(f"  Recovered: {result.recovered}")
        
        # 告警检查（如果标记了 lost）
        if result.marked_lost > 0:
            logger.warning(f"⚠️  {result.marked_lost} leases marked as lost")
        
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"Reaper failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
