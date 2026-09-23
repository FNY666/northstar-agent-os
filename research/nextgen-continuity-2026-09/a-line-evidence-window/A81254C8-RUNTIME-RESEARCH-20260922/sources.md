# 来源清单

访问日期统一：2026-09-22

1. Temporal Workflow Execution — https://docs.temporal.io/workflow-execution.md — verified：持久执行、Event History、Replay、Open/Closed/Paused；边界：平台事件不证明外部副作用。
2. Temporal Activity Definition — https://docs.temporal.io/activity-definition.md — verified：Activity 幂等、重复执行、worker 崩溃窗口、服务侧 idempotency key；边界：幂等不等于 postcondition。
3. Temporal Retry Policies — https://docs.temporal.io/encyclopedia/retry-policies.md — verified：Activity 默认重试、Workflow 默认不按同一策略重试、失败外部交互应放 Activity；边界：不自动解决业务永久失败。
4. Temporal Cancellation — https://docs.temporal.io/workflow-execution/cancellation.md — verified：取消是生命周期控制；边界：不证明所有远端副作用已停止。
5. Anthropic Claude Code Permissions — https://code.claude.com/docs/en/permissions — verified：宿主层权限模式、人工批准、规则不由模型执行；边界：批准不证明目标效果。
6. Anthropic Claude Code Hooks — https://code.claude.com/docs/en/hooks — verified：SessionStart、PreToolUse、PermissionRequest、PostToolUseFailure、StopFailure 等事件及 deny/retry 决策；边界：未证明不可变完整审计或自动 read-back。
7. GitHub Actions Re-running Workflows and Jobs — https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-workflow-runs/re-running-workflows-and-jobs — verified：重跑窗口/次数、原始 SHA/ref、原触发者权限；边界：不证明外部部署目标状态。
8. GitHub Actions Reviewing Deployments — https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/reviewing-deployments — verified：required reviewer 的 approve/reject、批准后 job 继续并可访问 environment secrets；边界：批准不等于部署健康。
9. SWE-bench Evaluation Guide — https://www.swebench.com/SWE-bench/guides/evaluation/ — verified：run_id+instance_id 缓存、换 patch 必须换 run_id、日志/失败分类和重判定边界；边界：benchmark 不等于 production。
10. OpenAI Codex CLI README — https://github.com/openai/codex/blob/main/README.md — verified：官方仓库/安装入口；unknown：该 README 本身未提供足够的任务生命周期、失败恢复、幂等或最终验证规范。

资料范围说明：仅使用公开官方文档、官方源码/仓库和官方评测文档；没有访问私有账号、凭据、真实服务或共享目标。