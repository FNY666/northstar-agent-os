# A81254C8：优秀 Agent/CLI 任务生命周期、失败恢复与验证闭环研究

- 研究日期：2026-09-22
- 资料范围：公开官方一手文档、官方源码/仓库、官方评测文档
- 研究对象：Temporal、Claude Code、GitHub Actions、SWE-bench harness
- 隔离目录：`/tmp/A81254C8-RUNTIME-RESEARCH-20260922/`
- 证据标签：`verified`=官方材料直接支持；`inferred`=由 verified 事实推导；`unknown`=公开材料未证明

## 1. 结论

没有一个对象单独提供完整的“任务生命周期安全闭环”。可迁移的最小闭环是：

```text
任务身份/输入绑定
  → 明确状态与暂停点
  → 工具前授权/人工批准
  → 外部副作用隔离为可重试步骤
  → 失败分类与有限重试
  → 取消/超时后保守处理 unknown
  → 独立读取外部状态（read-back）
  → 最终不变量/测试验证
  → 保留逐步日志、输入、输出、版本和决策证据
```

比较结论：

1. **Temporal 的持久执行与事件历史最完整**：能证明平台状态可恢复、Workflow 可 replay、Activity 可重试，并明确警告 Activity 必须幂等；但平台事件历史不自动证明第三方系统副作用已经完成。
2. **Claude Code 的权限与 hook 边界最接近交互式 Agent 控制面**：权限由宿主工具执行而不是模型提示决定，PreToolUse 可阻断工具，PermissionRequest/StopFailure/PostToolUseFailure 等事件能暴露生命周期节点；但公开文档没有证明其 hook 或会话记录是不可篡改、全量持久化的审计证据，也没有证明外部 read-back。
3. **GitHub Actions 的人工审批与 rerun 语义明确**：部署环境可以要求 reviewer，批准后 job 才继续并可能获得 environment secrets；rerun 保留原始 SHA/ref 和原触发者权限；但 run conclusion、approval 或 job success 只是 GitHub 平台状态，不等于目标部署系统已达到期望状态。
4. **SWE-bench harness 的评测复核边界最清楚**：用 `run_id + instance_id` 缓存，换 patch 必须换 run_id；`report`/`submit verify` 只对已保存日志和测试输出重新判定，不是 Docker 端到端重跑；其 infrastructure/ambiguous failure 分类对 benchmark 有帮助，但 benchmark 通过不能外推 production。

推荐的通用设计：将“平台执行状态”“工具返回”“外部目标状态”“最终业务不变量”分成四级，任何取消、超时、连接断开、worker 崩溃或无响应都进入 `UNKNOWN_NEEDS_RECONCILE`，不得无条件盲重试；重试前使用 operation/idempotency key，并对目标系统做独立 read-back/reconcile。

## 2. 生命周期与状态模型比较

| 对象 | 官方可直接证明的状态/生命周期 | 失败恢复 | 人工批准 | 外部 read-back / 最终验证 | 证据边界 |
|---|---|---|---|---|---|
| Temporal | Workflow Execution 有 Open/Closed；Paused 仍是 Open 且不派发新的 Workflow Task；Closed 包括 Completed、Failed、Canceled、Timed Out、Terminated 等状态；Event History 记录事件，Replay 从最后记录事件恢复 | Activity 默认 Retry Policy；Workflow 本身默认不按 Retry Policy 重试；Activity 可能在副作用完成但 worker 未报告前崩溃，随后重复执行 | 官方有取消/消息/handler 等机制，但本组来源未证明一个通用人工批准闸门 | Event History 能证明 Temporal 已记录的事件；不能单独证明支付、部署、远端资源等第三方状态；应用需自行幂等、查询和对账 | verified + inferred；外部副作用最终状态 unknown，除非应用另行提供 read-back |
| Claude Code | SessionStart 可在会话开始或恢复时触发；PermissionRequest、PreToolUse、PostToolUse、PostToolUseFailure、Stop、StopFailure、TaskCompleted 等 hook 事件形成可观察生命周期 | PreToolUse hook 可 deny；PermissionDenied hook 可通过 `retry: true` 告知模型可重试；权限拒绝不等于工具已执行；StopFailure 表示 turn 因 API error 结束 | Manual/acceptEdits/plan/auto/dontAsk/bypassPermissions 等模式；工具级权限规则和人工提示；权限由 Claude Code 执行而非模型提示 | Hook 可检查工具输入/输出并作决定，但官方未证明平台自动对外部资源做 read-back 或对整个会话形成不可变审计 | verified：权限/事件；unknown：不可变证据、外部效果和最终业务状态 |
| GitHub Actions | Workflow run/job/step 及 success/failure/cancelled 等平台结论；可 rerun 全部、失败 job 或指定 job；部署 job 可等待 environment protection review | rerun 可保留原始 SHA/ref 和原触发者权限；最多 30 天内重跑、一个 run 最多 50 次；取消/并发策略需按 workflow 配置 | Environment required reviewers 可 approve/reject；批准后 job 才继续，且可能访问环境 secrets；可禁止发起者自批准 | workflow/job 状态与日志是平台侧证据；官方本组来源未证明 deployment target 的独立 postcondition read-back | verified：平台生命周期/批准/rerun；inferred：不能把平台结论扩大为目标状态 |
| SWE-bench | 每次 run 产生 run 目录、逐实例日志、report/results；评测 harness 以 `run_id + instance_id` 缓存；有 resolved/unresolved、likely infrastructure failure、ambiguous failure 等评测分类 | 更换 prediction diff 必须换 run_id，否则可能复用旧结果；`report` 与 `submit verify` 可重计分，但不启动 Docker/测试 | 官方提交/人工核验机制存在，但本组评测文档不证明一个运行中的人工 approval 状态 | 测试输出和报告验证的是 benchmark 判分；不证明真实生产目标或用户环境状态 | verified：benchmark 评测闭环；unknown：production 外部效果 |

## 3. 逐源证据

### S1 — Temporal Workflow Execution

- URL：<https://docs.temporal.io/workflow-execution.md>
- 页面入口：<https://docs.temporal.io/workflow-execution>
- 访问日期：2026-09-22
- 状态：`verified`

官方材料称 Workflow Execution 是 durable、reliable、scalable 的执行单元；其状态持久化于 Event History，Worker 通过 Replay 根据已有事件恢复进度。页面列出 Open/Closed 状态，并说明 Paused 仍为 Open，但 Temporal Service 不再派发新的 Workflow Task，直到 Unpaused。

**能证明：** Temporal 平台为 Workflow 维护事件历史、状态和可恢复执行；暂停在平台语义上不是完成；状态可以通过查询观察。

**不能证明：** Replay 不是恢复任意 Worker 进程内存；Event History 也不能单独证明外部 API、数据库、支付、部署或文件系统副作用已成功持久化。

### S2 — Temporal Activity Definition / Idempotency

- URL：<https://docs.temporal.io/activity-definition.md>
- 页面入口：<https://docs.temporal.io/activity-definition>
- 访问日期：2026-09-22
- 状态：`verified`

官方明确建议 Activity 幂等。文档说明：Activity 如果完成了外部副作用但 Worker 在通知 Temporal Service 前崩溃，Event History 不会反映完成，Activity 可能再次执行；文档建议使用由被调用服务执行的 idempotency key。文档还说明 Activity 内部多个步骤中途失败时，整个 Activity 可能重试，因此可把步骤拆成更细粒度的 Activity。

**能证明：** 平台重试可能导致同一 Activity 代码执行多次；幂等性必须在业务/目标服务侧设计，不能由 Temporal 平台自动替应用保证。

**不能证明：** 使用 idempotency key 自动证明目标服务已提交、已可见或满足业务不变量；仍需目标侧结果查询/对账。

### S3 — Temporal Retry Policies

- URL：<https://docs.temporal.io/encyclopedia/retry-policies.md>
- 页面入口：<https://docs.temporal.io/encyclopedia/retry-policies>
- 访问日期：2026-09-22
- 状态：`verified`

官方说明 Activity 默认自动重试失败任务，Retry Policy 可配置；Workflow Execution 默认不关联 Retry Policy，Workflow Task 失败通过 replay/任务机制处理。官方建议将 API 调用、LLM 调用等易失败或非确定性操作放进 Activity；不建议简单重试整个 Workflow，因为可能重复相同逻辑而不解决外部依赖问题。

**能证明：** 失败分类和重试粒度应落在 Activity/外部交互步骤，而不是无条件重跑整个 Workflow；Retry Policy 是显式策略，不应把所有错误都当作可重试。

**不能证明：** Temporal 的默认 retry 就能识别所有业务永久失败；目标服务的幂等、补偿、read-back 仍需应用实现。

### S4 — Temporal Cancellation

- URL：<https://docs.temporal.io/workflow-execution/cancellation.md>
- 页面入口：<https://docs.temporal.io/workflow-execution/cancellation>
- 访问日期：2026-09-22
- 状态：`verified`

官方页面说明取消请求是 Workflow Execution 生命周期的一部分，并区分 cancellation 与 termination 等控制操作。

**能证明：** “请求取消”是平台状态转换/控制事件的一部分。

**不能证明：** 取消请求已让所有外部 Activity、远端进程、网络请求或第三方副作用停止；取消后的实际资源状态需要独立检查。

### S5 — Claude Code Permissions

- URL：<https://docs.anthropic.com/en/docs/claude-code/permissions>
- 当前文档入口：<https://code.claude.com/docs/en/permissions>
- 访问日期：2026-09-22
- 状态：`verified`

官方文档列出 Manual、acceptEdits、plan、auto、dontAsk、bypassPermissions 等权限模式及工具级规则。文档明确：权限规则由 Claude Code 执行，不是由模型执行；prompt 或 CLAUDE.md 可以影响模型尝试什么，但不能改变 Claude Code 允许什么。文档还区分只读读取、Bash、文件修改、WebFetch 等工具的审批行为。

**能证明：** Agent 的授权边界可以放在宿主工具层，而不是依赖模型是否“听话”；人工批准、拒绝、一次性允许和持久规则是不同状态。

**不能证明：** 规则通过不证明目标写入成功；人工批准也不证明命令产生了期望外部状态；公开页面没有证明权限提示历史是不可篡改的完整审计日志。

### S6 — Claude Code Hooks

- URL：<https://docs.anthropic.com/en/docs/claude-code/hooks>
- 当前文档入口：<https://code.claude.com/docs/en/hooks>
- 访问日期：2026-09-22
- 状态：`verified`

官方文档列出 SessionStart（含 session resume）、PreToolUse、PermissionRequest、PermissionDenied、PostToolUse、PostToolUseFailure、TaskCompleted、Stop、StopFailure 等事件。PreToolUse hook 可返回 deny 以阻断工具；PermissionDenied hook 可返回 `retry: true`，告知模型可能重试；文档特别说明 hook 沉默不代表批准，正常权限流程仍继续。

**能证明：** 可以在工具执行前做策略检查，在工具成功/失败后以及会话停止/失败时进行自动处理；权限拒绝、工具失败和 API turn 失败具有不同事件入口。

**不能证明：** hook 自身不会失败、不会被绕过或一定持久保存所有输入输出；也不能证明 hook 已读取外部系统确认结果。Hook 返回决策不是外部效果证明。

### S7 — GitHub Actions Re-running Workflows and Jobs

- URL：<https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-workflow-runs/re-running-workflows-and-jobs>
- 访问日期：2026-09-22
- 状态：`verified`

官方文档说明 workflow run、全部 jobs、失败 jobs 或单个 job 可重跑；初次运行后 30 天内可重跑，每个 run 最多 50 次。重跑使用最初触发者的权限，并继续使用原始事件的 GITHUB_SHA 和 GITHUB_REF；可开启 runner/step debug logging。

**能证明：** rerun 不是任意新提交；它保留原始代码引用和权限语义，并有明确次数/时间边界。

**不能证明：** 同一 SHA/ref 的重跑等于同一 runner、依赖、外部服务或目标状态；重跑成功不证明第一次失败没有留下副作用，也不证明部署目标最终正确。

### S8 — GitHub Actions Reviewing Deployments

- URL：<https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/reviewing-deployments>
- 访问日期：2026-09-22
- 状态：`verified`

官方文档说明，job 等待 review 时可 approve 或 reject；批准后且其他保护规则通过，job 才继续；此时 job 可以访问该 environment 中存储的 secrets。若环境禁止 self-approval，启动 workflow 的人不能批准自己的 deployment。

**能证明：** 人工批准是 workflow 状态的闸门，且批准可能改变可用秘密/权限范围；拒绝与批准不是模型文本中的建议，而是平台控制面状态。

**不能证明：** reviewer 批准不等于目标部署已健康；environment secrets 可访问不等于秘密被正确使用；仍需 deployment target read-back、健康检查和回滚/补偿。

### S9 — SWE-bench Evaluation Guide

- URL：<https://www.swebench.com/SWE-bench/guides/evaluation/>
- 官方仓库对应入口：<https://github.com/SWE-bench/SWE-bench/blob/main/docs/guides/evaluation.md>
- 访问日期：2026-09-22
- 状态：`verified`

官方评测指南说明 Docker cache level，并明确 harness 按 `run_id` 和 `instance_id` 缓存结果；如果相同实例重复使用相同 run_id，即使 prediction diff 不同，也会复用首次结果而不重新评测，因此改变 patch 时必须使用新的 run_id。指南同时展示评测日志和 resolved/unresolved、likely infrastructure failures、ambiguous failures 等分类。`report`/提交核验属于对既有评测日志/输出的重新判定，不是自动重新执行 Docker 测试。

**能证明：** 评测系统区分 patch 身份、运行身份、测试输出与基础设施/歧义失败；缓存键错误会造成假重跑，因此 run identity 必须唯一化。

**不能证明：** resolved 证明的是 benchmark 测试集合在评测容器内通过，不是 production 业务正确；日志重判定不证明测试曾在当前环境重新执行；benchmark harness 也不替代生产 read-back、监控、回滚或安全审核。

## 4. 跨对象可迁移控制

### 4.1 四级事实链

每个副作用至少记录四种事实，不可合并：

1. **调用层**：请求是否发出/被客户端接受；
2. **平台层**：Temporal Event、Claude hook、GitHub run/job、SWE-bench log 是否记录；
3. **工具层**：工具返回成功/失败/超时/拒绝；
4. **目标层**：外部系统 read-back 是否显示期望状态及版本/operation_id。

只有第 4 级能进入“外部效果已确认”；第 1–3 级最多证明执行过程的一部分。

### 4.2 失败分类建议

采用至少以下互斥/可组合字段：

- `rejected_before_execution`：人工/策略拒绝，不能写成执行失败；
- `tool_failed_before_effect_known`：工具返回失败，但外部效果 unknown；
- `timeout_or_disconnect`：是否执行未知，默认按可能执行处理；
- `platform_recorded_failure`：平台有失败事件，但目标状态仍未知；
- `infrastructure_failure`：运行环境/依赖/网络导致无法判定；
- `ambiguous`：日志不足或矛盾；
- `target_verified_failure`：独立 read-back 确认目标未满足；
- `target_verified_success`：独立 read-back + postcondition 满足；
- `compensated`：补偿动作已执行且补偿结果另经验证。

### 4.3 重试/幂等/补偿原则

- 每次副作用绑定 `operation_id`、目标指纹、规范化参数哈希、策略版本和 attempt；
- 让目标服务执行幂等键，而不是只在 Agent 本地去重；
- 将大 Activity 拆为较小步骤，缩小重试重复范围；
- timeout/disconnect 后先查询目标状态，再决定 retry、resume、compensate 或人工介入；
- 非幂等目标没有 read-back 时，不得自动盲重试；
- “平台成功”“人工批准”“日志存在”“benchmark resolved”均不能直接升级为外部效果成功；
- 证据保全至少包括输入摘要、授权决策、版本/环境、每次 attempt、工具返回、目标 read-back、最终不变量和 hash。

以上是 `inferred` 设计建议，不是四个对象均已实现的共同官方承诺。

## 5. 未解决问题

- Claude Code 公开文档没有证明会话/hook 日志的不可变性、完整性保护、跨崩溃恢复和外部 read-back 语义。
- GitHub Actions 公开 rerun/approval 文档没有在本研究范围内证明部署目标的统一 postcondition API 或自动补偿协议。
- SWE-bench 的 infrastructure/ambiguous 分类用于 benchmark 结果解释，但不能替代生产级目标对账；公开指南不构成 production 操作规范。
- Temporal 的 Event History 是平台执行证据，不等同于第三方系统的权威状态；是否有目标侧幂等、条件写、审计和 read-back 取决于应用。
- 本报告没有把任何 benchmark、平台状态或官方文档解释为 production pass。

## 6. 最终判定

最强的可迁移组合不是“选择某个 Agent 框架”，而是组合四类机制：

1. **Temporal 式持久事件/恢复**：保存可 replay 的平台状态；
2. **Claude Code 式宿主授权与工具前后 hook**：在模型之外执行权限和阻断；
3. **GitHub Actions 式显式人工批准与固定 rerun 身份**：高风险动作在闸门前暂停，重跑不悄悄改变提交/权限；
4. **SWE-bench 式唯一 run identity、失败分类和日志重判定边界**：避免假重跑、区分基础设施失败与任务失败。

但四者仍需应用自建最后一公里：`目标状态 read-back + postcondition + 对账/补偿 + 不可变证据保全`。没有这一层，只能声称平台执行或评测过程发生，不能声称外部副作用完成。
