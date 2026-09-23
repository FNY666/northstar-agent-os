# C-NEXTGEN-TRUST-CONTINUITY-20260922-S29

## 研究边界
本切片完全 synthetic-only=true、production_verified=false，仅在本地执行确定性合成 harness；没有网络、真实服务、SDK 或凭据，也不读取 S1-S28。问题是 epoch/fence 跨 crash 边界的撤销水位单调性与 bounded replay 截断。

## 判定契约
三态互斥：RECOVERED / UNKNOWN / REJECT，采用 fail-closed。RECOVERED 仅在以下条件全部成立时产生：跨 crash 水位单调；epoch/fence 连续；有可审计 fence 证据；bounded replay 完整且无分页/查询缺口、截断或 retention expired；日志无分叉；crash/restart 已对账；平台 receipt、持久日志、外部效果三类证据一致。乱序和完全相同的重复事件先按 event_id 去重，不误拒。丢失、未知提交或证据不能判定时为 UNKNOWN。分叉、水位回退、旧 epoch 迟到事件、旧 fence token 重放为 REJECT。

## 合成场景与结果
共 13 cases：RECOVERED=2，UNKNOWN=7，REJECT=4。

- C01：连续 epoch/fence、水位、完整 replay、三类证据齐全，重复 receipt 可去重 → RECOVERED。
- C02：乱序且重复但 event_id/payload 一致 → RECOVERED。
- C03：NO_EVENT → UNKNOWN，不能把没有事件误推为提交。
- C04：crash 前提交但 receipt 丢失 → UNKNOWN。
- C05：DROPPED / bounded replay 截断 → UNKNOWN。
- C06：EXPORTER_FAILURE / 外部效果证据缺失 → UNKNOWN。
- C07：QUERY_GAP → UNKNOWN。
- C08：RETENTION_EXPIRED → UNKNOWN。
- C09：日志分叉 → REJECT。
- C10：撤销水位回退 → REJECT。
- C11：旧 epoch 迟到事件/旧 token → REJECT。
- C12：fence 令牌重放 → REJECT。
- C13：未知提交且 crash/restart 未对账 → UNKNOWN。

覆盖标签：NO_EVENT、DELAYED、DROPPED、EXPORTER_FAILURE、QUERY_GAP、RETENTION_EXPIRED、VERIFIED_CONTINUITY、UNKNOWN。

## 验证
harness.py 连续运行两次并对 outputs/results.json 做字节 cmp；本地 validator.py、manifest_validator.py、官方 validate_research.py、SHA256SUMS 校验均应通过。property sweep：256 组合，违规 0。minimizer：8 个单门最小反例找到，未解析 0。

## 结论与限制
该切片支持一个合成规则性推断：在严格连续性与三类证据齐全时可恢复，否则保守地 UNKNOWN，明确冲突则 REJECT。claims 全部 status=inferred 且 sources=[]。这不能证明生产耐久性、exactly-once、回滚、外部效果真实性或 production readiness；完成本切片不代表停线。

## 下一独立切片建议
建议启动“跨分区 fence 证据合并与 bounded replay 分页重叠”的全新切片：仅离线合成，专门测试分页游标跳跃、重叠页、跨分区同一 event_id payload 冲突与 retention 边界，保持同一三态 fail-closed 契约；不得复用或读取本切片目录及 S1-S28。
