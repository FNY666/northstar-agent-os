# C 线信任连续性 S60：最终证据决策门、UNKNOWN 隔离、人工复核与补偿闭环

## 结论（离线合成、推断）

最终判定不能由单个 receipt、日志或工具成功消息直接升级为 RECOVERED。只有 evidence window、source set、claim scope、precondition/postcondition、独立 verifier、decision policy、RECOVERED/UNKNOWN/REJECT 规则、UNKNOWN quarantine、escalation owner、manual review、review evidence、remediation action/idempotency、retry reconciliation、最终 revalidation、decision immutability、audit 和 conflict resolution 全部闭合时，才可判 `RECOVERED`。跨身份合并或同一目标不可调和的最终决策冲突判 `REJECT`；证据窗口、后置条件、独立验证、隔离、人工复核、补偿、重试对账或最终状态未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S59 产物。

## 判定门

1. `identity_conflict` 或 `decision_conflict` 任一为真，输出 `REJECT`。
2. evidence/source/claim范围、前后置条件、独立验证、决策规则、UNKNOWN隔离/升级/人工复核、修复/幂等/重试、最终复验、不可变审计或冲突解决任一门未闭合，输出 `UNKNOWN`。
3. 只有证据决策规则、隔离升级、人工审核、补偿和最终收敛全部闭合，才输出 `RECOVERED`。
4. 平台完成、输出成功、补偿请求或人工结论本身不能证明最终目标状态；必须独立 read-back/reconciliation，未知状态不得继续下游。
5. `RECOVERED` 仅表示本片夹具中的 final-decision evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。

## 覆盖与确定性验证

- 28 个定向 cases：最终证据门、quarantine/escalation、manual review、remediation/idempotency、retry reconciliation、revalidation、decision immutability、audit/conflict，以及各边界缺口、身份冲突和决策冲突。
- 24 个布尔门执行完整 `2^24 = 16,777,216` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产人工审核、补偿、重试、隔离或最终状态机的验证。
- 未证明真实系统的 UNKNOWN quarantine、escalation、人工复核、补偿幂等、重试对账、决策不可变性或外部效果语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实操作、人工决策或目标系统副作用；生产接入必须独立 read-back、保留冲突并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
