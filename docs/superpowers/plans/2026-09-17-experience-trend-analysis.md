# Experience Trend Analysis (代际 7)

**Goal**: 分析 experience 历史的时间序列趋势，检测性能变化和异常模式。

**当前缺口**：
- `query_statistics()` 只提供简单的 recent_trend（improving/declining/stable）
- 趋势检测基于固定窗口（前半 vs 后半）
- 无法检测：渐进式退化、周期性波动、突变点

**提议功能**：

## 1. 趋势分析 API

```python
@dataclass(frozen=True)
class ExperienceTrend:
    """Time-series trend analysis of experience history."""
    
    fingerprint: str
    window_size: int  # 分析窗口大小
    
    # 趋势方向
    trend_direction: str  # "improving" / "declining" / "stable" / "volatile"
    trend_strength: float  # 0.0-1.0，趋势强度
    
    # 统计指标
    mean_success_rate: float
    variance: float
    recent_volatility: float  # 近期波动性
    
    # 异常检测
    has_degradation: bool  # 是否检测到性能退化
    has_breakthrough: bool  # 是否检测到突破性改进
    change_points: tuple[int, ...]  # 突变点位置（run 索引）
    
    # 预测
    predicted_next_success_rate: float  # 基于趋势预测下一次成功率

def analyze_trend(
    ledger: ExperienceLedger,
    fingerprint: str,
    *,
    window_size: int = 20,  # 分析窗口
    min_samples: int = 5,  # 最小样本数
) -> ExperienceTrend:
    """Analyze time-series trend of experience history."""
```

## 2. 趋势检测算法

**方向检测**：
- 线性回归斜率（正 = improving，负 = declining）
- Mann-Kendall 趋势检测（非参数方法）

**强度量化**：
- R² 决定系数（拟合优度）
- 趋势显著性 p-value

**波动性**：
- 滑动窗口标准差
- 变异系数（CV = std / mean）

**突变点检测**：
- CUSUM（累积和控制图）
- 简单阈值法（连续 N 次失败 → 突变）

**预测**：
- 简单线性外推
- 指数平滑

## 3. 使用场景

**A. 性能监控**：
```python
trend = analyze_trend(ledger, fingerprint)
if trend.has_degradation:
    alert("Performance degradation detected")
```

**B. 改进验证**：
```python
# 部署新策略后
trend = analyze_trend(ledger, fingerprint, window_size=10)
if trend.trend_direction == "improving" and trend.trend_strength > 0.7:
    confirm("Improvement confirmed")
```

**C. 稳定性评估**：
```python
if trend.recent_volatility > 0.3:
    warn("Unstable performance, investigate")
```

**D. 决策支持**：
```python
exp_state = project_state(ledger, fingerprint)
trend = analyze_trend(ledger, fingerprint)

if exp_state.standing == "consistent-success" and trend.has_degradation:
    # 历史成功但正在退化 → 谨慎准入
    decision = "admit-with-caution"
```

## 4. 实现步骤

**Phase 1（MVP）**：
- 线性回归斜率
- 简单波动性（滑动窗口 std）
- 阈值突变检测
- 测试：10+ 用例

**Phase 2（完整）**：
- Mann-Kendall 检验
- CUSUM 突变检测
- 指数平滑预测

## 5. 非目标（defer）

- 多变量分析（experience + 资源使用 + 延迟）
- 季节性分解
- 自相关分析

---

**Timeline**: 1-1.5 小时（MVP）  
**Author**: 96942423  
**Date**: 2026-09-17  
**Status**: 代际 7 规划
