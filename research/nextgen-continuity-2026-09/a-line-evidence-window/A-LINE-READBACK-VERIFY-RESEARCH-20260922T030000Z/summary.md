# Summary

## 一句话结论

Temporal 的 Event History、LangGraph 的 checkpoint/store、OpenAI Agents SDK 的 result/session/trace 都能提供有价值的平台内执行证据，但都不能单独证明外部 production 效果；可迁移闭环必须是：**dispatch → 平台回执 → 外部 authoritative read-back → 版本化验收 predicate → 证据分层与 reconciliation**。

## 对比

| 平台 | 官方明确提供 | 适合放在闭环的哪里 | 不能替代 |
|---|---|---|---|
| Temporal | Service 生成并持久化 workflow Event History；Activity 生命周期事件 | 长生命周期编排、重试/超时/恢复；把外部写与 read-back 做成明确 Activity | 外部系统提交/可见性/业务最终效果 |
| LangGraph | checkpointer 持久化 thread graph state；store 保存应用定义的跨 thread 数据；支持 interrupt/resume/failure recovery | 图式状态、HITL、验证节点和恢复 | 外部 authoritative state、审计不可变性、exactly-once |
| OpenAI Agents SDK | final_output/new_items/raw_responses/to_state；session；tracing/flush；明确 session ACK 与 provider-delivery 边界 | agent/tool/handoff/approval、运行审计线索、外部 read-back 工具 | provider delivery 和外部 production 效果 |

## 最小证据分层

- **L0**：intent、目标、幂等键、验收规则。
- **L1**：dispatch 尝试与请求摘要。
- **L2**：平台 receipt（event/checkpoint/result/session/trace），只证明内部状态。
- **L3**：外部协议 response（status/resource ID/job ID），不必然是完成。
- **L4**：外部独立 GET/query 的 authoritative read-back。
- **L5**：在时间窗内按 predicate 得出 VERIFIED/FAIL/UNKNOWN。

硬规则：L2 不能跳过 L4/L5；只有“平台 success”而无外部 read-back，业务判定必须是 **UNKNOWN**。平台回执、checkpoint、trace、benchmark 均不写成外部 production 效果。

## 实操验收

对于任何外部写入，至少保存：`intent_id`、稳定 `idempotency_key`、平台 receipt reference、外部 resource/job ID、独立 read-back 时间和 authoritative source、版本/ETag、观察字段摘要、predicate version、verdict、reason、证据 SHA-256。若超时/取消/ACK 丢失/读回延迟/身份冲突，先按幂等键 read-back，再 reconcile；不要盲目重复写入。

## 证据状态

- **verified**：来源直接写出的平台行为与规范定义。
- **inferred**：据此设计的跨平台闭环和工程建议。
- **unknown**：官方未承诺的外部效果；缺少 read-back 时保持 UNKNOWN。

完整 URL、访问日期（2026-09-22）及每个来源的能证明/不能证明边界见 `sources.md`；详细论证见 `report.md`。
