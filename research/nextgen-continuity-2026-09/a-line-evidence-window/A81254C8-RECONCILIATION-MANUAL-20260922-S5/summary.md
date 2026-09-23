# S5 摘要

## 核心结论

- `event_time`（来源事件/请求时间）、`observed_at`（消费者收到并持久化时间）和 source watermark（来源已追平边界）必须分列；CloudTrail 明确事件可延迟交付，不能把 eventTime 当实时观测点。
- Kubernetes `resourceVersion`/bookmark、AWS Step Functions `nextToken`、GitHub `Link: rel="next"` 各是来源专属完整性机制，不构成统一跨源 watermark。
- 分页读完不代表跨页一致快照，也不代表外部副作用完成。
- Step Functions STANDARD 同 name+input 的运行中执行可按官方幂等语义核对；EXPRESS 不幂等。Temporal history/replay 只说明工作流层历史恢复/确定性，不证明 Activity 外部效果 exactly-once。
- 写响应丢失、游标 gap/410、输入冲突、不可逆外部副作用无法核对时：UNKNOWN，先只读核对和幂等键查证；无法排除已发生效果时人工升级，禁止盲目重试。

## 最小决策口诀

**先判读/写 → 再判幂等键 → 再判服务端可查询状态 → 再判来源游标/水位完整性 → 最后才重试。**

纯读可按官方分页协议重试但要去重；Kubernetes 410 先从头 LIST 再 WATCH；Temporal 让 history 恢复但核对 Activity；无服务端幂等/唯一 ID 的写入超时一律 UNKNOWN。

## 明确不声称

本摘要不声称 production 事实、exactly-once、无重复副作用、跨源实时性或最终一致读已解决。所有跨源重试规则是 inferred 的保守控制建议；平台事实见 `sources.md`。
