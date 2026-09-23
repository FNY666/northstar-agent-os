# S4 摘要

## 结论

把 durable reconciliation 做成“证据包 + 状态机”，而不是把请求返回值当成功。最小闭环需要分离：`correlation_id`（跨步骤关联）、业务域内 `idempotency_key`（重试去重）、`attempt_no`（尝试）、`expected/observed generation` 与平台 `resourceVersion`（版本/并发）、`event_time` 与 `observed_at`（发生/观察时钟）、source freshness/watermark/completeness（证据新鲜度和完整性）、显式空查询语义、冲突列表、人工批准记录及关单证据。

## 三个必须坚持的语义

1. **ACCEPTED_UNKNOWN ≠ APPLIED**：编排历史中有 accepted/queued/completed，只能证明编排事实；没有目标对象可定位的 effect proof，就不能声称外部效果已发生。
2. **空结果 ≠ 不存在**：`result_count=0` 必须同时声明 query 是否完整、窗口/snapshot/watermark 和 `empty_meaning`（no_match、not_found_in_window、not_observed、source_incomplete、unknown）。
3. **完整 schema ≠ 外部效果证明**：有齐字段只是接口完整性门槛，不推出 production、exactly-once 或无重复副作用。

## 推荐最小状态

`RECEIVED → ACCEPTED_UNKNOWN → RECONCILING → APPLIED | REJECTED | CONFLICT | EXPIRED → CLOSED`。
`CLOSED` 仅表示关单证据齐全；`EXPIRED` 不是成功。任何重复、旧版本、意图漂移、来源冲突、审批范围不匹配或缺失证据都应显式记录并阻断静默覆盖。

## 交付物

- `report.md`：完整契约、状态机、JSON Schema/实例、平台映射、冲突/空查询语义、unknown/conflict 与检查清单。
- `sources.md`：官方一手来源和逐项直接核验点。
- `research-manifest.json`：可验证证据清单。
- `next-slice-dispatch.md`：下一独立切片建议。

验证：见最终回报中的 validator 与 SHA256 输出。研究目录：`/tmp/A81254C8-RECONCILIATION-MANUAL-20260922-S4/`。
