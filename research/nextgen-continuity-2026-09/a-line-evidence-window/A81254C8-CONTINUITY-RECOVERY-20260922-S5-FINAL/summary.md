# S5 Summary

访问日期：2026-09-22；仅官方/一手公开资料；非 production 验收。

## 结论

- OpenTelemetry Collector：队列、重试和 WAL 可支撑有界恢复；队列溢出、磁盘故障和 retry expiry 仍可能丢失，不能证明 lossless 或 exactly-once。
- CloudTrail：digest 链和 `validate-logs` 可证明被覆盖文件的完整性，并暴露未验证时间段；不能证明源事件一定生成或覆盖链外区间。
- GitHub Actions：run/job/log/artifact 分离，分页、1000 条搜索上限、短期日志重定向和 artifact 过期使“无结果”不等于“无事件”。
- Kubernetes：list/continue/resourceVersion/watch/410 Gone 形成恢复闭环；Events 是有限保留的 best-effort 补充，不是 durable audit ledger。
- Temporal：Event History/replay 是单 execution 的主要连续性证据；Visibility 异步、可能陈旧、count 近似，应使用 Describe/Event History 做权威核验。
- Claude Code：telemetry 批量发送，强制终止可能丢 pending 数据，exporter 错误默认静默；CLI 完成不等于 telemetry 完整。

## 统一判定

`NO_EVENT` 需独立 generation precondition、完整查询范围/分页、retention 覆盖、exporter 健康和延迟边界结束；否则为 `UNKNOWN`。

恢复验收必须独立验证：平台恢复路径、证据序列连续、外部效果 read-back、业务 postcondition。官方文档支持设计测试，不支持声称任何部署 production 通过、无中断、无损或历史完整。
