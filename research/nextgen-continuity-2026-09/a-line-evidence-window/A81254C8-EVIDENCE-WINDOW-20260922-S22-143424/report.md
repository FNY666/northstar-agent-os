# S22 跨云审计窗口

访问日期：2026-09-22。范围：只读官方资料，未访问生产。

## 结论
GCP Audit Logs、AWS CloudTrail、Azure Activity Log 都是平台审计信号，不是统一的业务效果证明。跨云 schema 必须保留 provider、event_id、event_time、ingest_time、query_time、window_start/end、source_scope、coverage、integrity、retention 和 outcome。事件时间与到达/查询时间分离；查询空结果若覆盖、保留、权限或分页未知，不得判定 NO_EVENT。

## 确定性向量
- S22-1：事件已生成且完整查询可见 → `VERIFIED_CONTINUITY` 仅在独立 postcondition 也通过时成立，否则仅 `DELAYED`/平台证据。
- S22-2：event_time 在窗口、ingest_time 超过截止 → `DELAYED`。
- S22-3：审计配置未覆盖资源/类别 → `UNKNOWN`，不能 `NO_EVENT`。
- S22-4：CloudTrail/GCP/Azure 查询权限不足、分页未耗尽或过滤条件不全 → `QUERY_GAP`。
- S22-5：超过官方保留期或日志已删除 → `RETENTION_EXPIRED`。
- S22-6：同一 event_id 内容冲突 → `UNKNOWN`/integrity failure，不覆盖冲突。
- S22-7：在完整覆盖窗口内明确没有匹配事件，并完成所有分页/权限/保留检查 → `NO_EVENT`。

## 不能证明
官方审计文档不能证明所有业务事件都生成、日志未丢失、第三方副作用已提交、跨云时钟完全同步或生产连续性通过。