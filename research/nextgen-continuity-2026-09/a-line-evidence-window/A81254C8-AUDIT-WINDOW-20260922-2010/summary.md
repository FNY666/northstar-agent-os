# Summary

## Question
在只依赖公开官方资料的前提下，审计时间窗、日志覆盖、断流检测和验证闭环分别能证明什么？取消/超时/断流、重试与补偿如何保持 UNKNOWN 边界？

## Findings

- Temporal Event History 是编排/replay 事实，不是外部效果证据；retry 可能扩大外部副作用不确定窗口。
- GitHub Actions 日志可查看/下载/删除，重跑按 attempt 分离；平台日志不能证明远端 postcondition。
- Step Functions Standard 历史有 90-day completed-execution 窗口；Express 依赖 CloudWatch Logs，默认控制台窗口三小时；CloudWatch delivery best-effort 且 logging level 可省略正常事件。
- CloudTrail Event History 是按 Region 的近 90 天 management-event 记录，不是所有 data-plane 事件的全量审计。
- Kubernetes Job 的 Complete/Failed/DeadlineExceeded 是控制面状态；TTL-after-finished 会清理对象，造成 API 证据窗口。
- Claude Code OTLP 是可选导出，官方提供 prompt/event 探针和 exporter failure 诊断；retention sweep 删除旧会话数据。未证明所有事件必达或外部动作完成。
- Codex CLI 官方仓库可作为源码/文档入口，但本切片未从入口得到统一 audit/retention/external-read-back 保证。

## Required closure rule

任何 timeout/cancel/disconnect/日志缺失，在没有目标权威 read-back、幂等键/唯一约束或独立对账前，保持 `UNKNOWN_NEEDS_RECONCILE`。平台 SUCCESS 只能先记 `SUCCEEDED_UNVERIFIED`；只有目标 read-back 与业务 postcondition 一致时才升级 `VERIFIED_EFFECT`。

## Evidence labels

- verified：官方页面直接支持的平台机制。
- inferred：由机制边界抽象出的审计设计建议。
- unknown：官方资料未证明或本切片未访问的部署/外部事实。

## Scope boundary

只读官方公开资料；不接触真实服务、凭据或受保护目录；不声称 production 通过。
