# Sources

访问日期：2026-09-22。以下均为公开官方/一手来源，具体证据窗口、边界和状态见 report.md。

1. Temporal Documentation — Events and Event History
   URL: https://docs.temporal.io/workflow-execution/event
   Publisher: Temporal Technologies
   Accessed: 2026-09-22
   Use: Event History、replay、workflow event 记录边界。

2. Temporal Documentation — Retry Policies
   URL: https://docs.temporal.io/encyclopedia/retry-policies
   Publisher: Temporal Technologies
   Accessed: 2026-09-22
   Use: initial interval、backoff、maximum attempts、non-retryable error。

3. GitHub Docs — Using workflow run logs
   URL: https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/using-workflow-run-logs
   Publisher: GitHub
   Accessed: 2026-09-22
   Use: 查看、搜索、下载、删除日志；不同 run attempt 的日志边界。

4. GitHub Docs — Re-running workflows and jobs
   URL: https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-workflow-runs/re-running-workflows-and-jobs
   Publisher: GitHub
   Accessed: 2026-09-22
   Use: 30-day rerun window、rerun 粒度、actor 权限和 attempt 风险。

5. AWS Step Functions Documentation — View execution details
   URL: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-view-execution-details.html
   Publisher: Amazon Web Services
   Accessed: 2026-09-22
   Use: Standard 90-day execution history；Express CloudWatch history，默认三小时可视查询窗口。

6. AWS Step Functions Documentation — Using CloudWatch Logs to log execution history
   URL: https://docs.aws.amazon.com/step-functions/latest/dg/cw-logs.html
   Publisher: Amazon Web Services
   Accessed: 2026-09-22
   Use: optional logging、best-effort delivery、ALL/ERROR/FATAL/OFF levels 和事件覆盖差异。

7. AWS Step Functions API Reference — GetExecutionHistory
   URL: https://docs.aws.amazon.com/step-functions/latest/apireference/API_GetExecutionHistory.html
   Publisher: Amazon Web Services
   Accessed: 2026-09-22
   Use: Standard execution history API 查询面和分页/平台历史边界。

8. AWS CloudTrail User Guide — Working with CloudTrail event history
   URL: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html
   Publisher: Amazon Web Services
   Accessed: 2026-09-22
   Use: Region-scoped、management events、90-day event history、查询/下载边界。

9. Kubernetes Documentation — Jobs
   URL: https://kubernetes.io/docs/concepts/workloads/controllers/job/
   Publisher: Kubernetes project
   Accessed: 2026-09-22
   Use: Job status、backoffLimit、activeDeadlineSeconds、Failed/DeadlineExceeded 和终止边界。

10. Kubernetes Documentation — TTL-after-finished controller
    URL: https://kubernetes.io/docs/concepts/workloads/controllers/ttlafterfinished/
    Publisher: Kubernetes project
    Accessed: 2026-09-22
    Use: Complete/Failed Job 的 TTL 清理与证据保留边界。

11. Anthropic Claude Code Documentation — Monitor Claude Code usage and activity
    URL: https://docs.anthropic.com/en/docs/claude-code/monitoring-usage
    Publisher: Anthropic
    Accessed: 2026-09-22
    Use: OTLP logs/events/traces、user_prompt 验证探针、exporter error、retention sweep。

12. OpenAI Codex CLI official repository
    URL: https://github.com/openai/codex
    Publisher: OpenAI
    Accessed: 2026-09-22
    Use: 官方源码/文档入口；未将未明确保证的审计、保留、断流或外部效果语义当作事实。

## Source handling note

- 研究只使用以上官方公开页面/仓库入口；没有使用私人账号、真实服务、凭据或受保护本地目录。
- 对页面明确写出的平台行为标记 verified；跨平台归纳标记 inferred；官方材料未证明的完整性、零丢失、外部效果和 exactly-once 标记 unknown。
- URL 可访问性、页面当前文本和发布日期可能随平台更新变化；本包只声明访问日，不伪造源文档发布日期。
