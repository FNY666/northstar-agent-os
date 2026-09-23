# Summary — S4

## 结论

审计断流判断必须区分：未生成、延迟、采集/导出丢弃、查询缺口、保留期过期和真实连续性。下游没有记录不能单独证明任何一种原因。

## 最小规则

- `NO_EVENT`：只有生成前提独立成立、完整查询范围/分页/分区已验证、保留期覆盖、exporter/ingestion 健康、允许延迟已过且仍无事件时才允许。
- `DELAYED`：需要源端发生 witness 和后续 observation/ingestion witness，且两者时间戳可计算延迟。
- `DROPPED`：需要显式 drop/reject 或完整序列/checkpoint gap，且没有 query/retention gap。
- `EXPORTER_FAILURE`：需要 exporter timeout、retry exhaustion、queue/endpoint failure 或显式 disabled/error 证据。
- `QUERY_GAP`：分页、分区、scope、region/account/namespace、权限或查询完整性不明。
- `RETENTION_EXPIRED`：只有 retention/TTL cutoff 已知且事件在区间外时使用。
- `VERIFIED_CONTINUITY`：有界窗口、完整查询、稳定范围、sequence/checkpoint/count/heartbeat 连续且无未解决缺口。
- 其他情况一律 `UNKNOWN`。

## 关键边界

OTel 时间戳可区分 source occurrence 与 collector observation，但不证明 backend durable storage；CloudTrail Event History 受 90 天、region 和事件类别限制；Step Functions Standard/Express 语义不同；Kubernetes Event 非永久归档；Temporal Continue-As-New 会产生新的 Run ID；Claude Code client telemetry 不等于 backend receipt；Codex 官方公开材料当前不足以建立稳定审计/保留契约。

上述结论只处理日志/事件连续性，不等于平台完成、外部效果或业务 postcondition。外部效果仍需要目标权威 read-back。