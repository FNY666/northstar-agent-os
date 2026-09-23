# Summary

## 一句话
取消/超时/断连只说明客户端没有得到确定答复，不说明外部副作用没有发生；恢复前必须用原始 operation_id/幂等键 read-back/reconcile，把不确定结果维持为 UNKNOWN。

## 结论卡

- **取消请求已发出但无响应**：UNKNOWN；按原 Workflow ID/Run ID 或业务 operation_id 查询；Temporal 的取消传播、heartbeat 和清理能力不等于业务取消已确认。
- **超时/断连**：UNKNOWN；RFC 9110 的幂等性只支持同一语义请求安全重试，不把 timeout/504 当作未执行证明。
- **恢复**：checkpoint/RunState 恢复编排状态，不恢复外部世界的事实；LangGraph 节点可能从头重跑，所以 interrupt 前副作用必须幂等。
- **新 key**：只有在明确意图是第二次独立操作时才可使用；在未知状态中盲目新 key 会双写、双扣、双发或双重删除。
- **补偿**：补偿是新的副作用，也会 UNKNOWN；需要独立 compensation_operation_id、同 key 重试、read-back 和审计。
- **人工边界**：read-back 不可用/矛盾、不可逆高价值动作、补偿未知、超出重试窗口时暂停并人工裁决；人工不得靠猜测结案。

## 最小恢复顺序

`UNKNOWN` → 原 key read-back → 目标资源/版本核对 → 明确终态则收敛 → 仍未知则退避重查/人工；只有同 key 去重语义明确时才重试。平台回执、benchmark、checkpoint、trace 不能冒充外部生产效果。

## 覆盖与限制

覆盖 Temporal cancellation/reset、LangGraph persistence/interrupt、OpenAI Agents running/HITL、RFC 9110 幂等与超时响应。官方资料未证明统一的跨平台 UNKNOWN 状态机、Idempotency-Key 标准、Saga 补偿协议或超时后的外部执行事实；这些部分在报告中明确标为 inferred/unknown。

## Protected-target declaration

未触碰：shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line、systemd、凭据、真实服务、production 或任何共享目标。仅使用公开官方资料与本隔离目录。
