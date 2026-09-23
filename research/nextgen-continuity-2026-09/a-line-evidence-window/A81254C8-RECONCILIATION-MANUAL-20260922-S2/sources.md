# Sources

仅列公开、官方、一手资料；访问/核验日期：2026-09-22。以下摘录为支持范围摘要，不把页面扩展为未声明的保证。

1. **Temporal — Activity Definition**
   - URL: https://docs.temporal.io/activity-definition.md
   - Publisher: Temporal Technologies, Inc.；类型：官方文档；tier: primary
   - 直接支持：Activity 是单一动作；若 Activity 未向 server 报告会重试；Activity 可能执行多次；文档定义 idempotent 为多次 Activity Task Execution 不产生超出第一次的状态变化，并建议设计幂等。
   - 用途：C1、幂等与重试/补偿推导。
   - 限制：没有证明任意外部系统 exactly-once，也没有给出本项目的重试阈值。

2. **Temporal — Workflow Id and Run Id**
   - URL: https://docs.temporal.io/workflow-execution/workflowid-runid.md
   - Publisher: Temporal Technologies, Inc.；类型：官方文档；tier: primary
   - 直接支持：Workflow ID 通常承载业务含义；同一 active Namespace 中同 ID 同时最多一个 Open execution；Run ID 是全局唯一的平台级 execution 标识；闭合后可有相同 Workflow ID 的另一个 Open execution。
   - 用途：C2、业务键与编排关联设计。
   - 限制：Workflow ID 约束不是外部副作用幂等证明。

3. **AWS Step Functions — Handling errors in Step Functions workflows**
   - URL: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
   - Publisher: Amazon Web Services；类型：Developer Guide；tier: primary
   - 直接支持：状态可能运行时出错；Task/Parallel/Map 可用 Retry；可用 Catch；支持退避参数和 jitter；redrive 某些情况下重置 retry attempt count。
   - 用途：C3、重试/补偿编排设计的参考模型。
   - 限制：Step Functions 状态机的 retry/redrive 语义不等于外部副作用 exactly-once。

4. **AWS CloudTrail — CloudTrail concepts**
   - URL: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html
   - Publisher: Amazon Web Services；类型：User Guide；tier: primary
   - 直接支持：event 是 AWS 账户活动记录；包含 API 与非 API 活动历史；CloudTrail log files 不是 public API calls 的 ordered stack trace，events 不按特定顺序出现；event history 是可查看、搜索、下载、不可变的记录；trail 配置向存储/服务交付事件。
   - 用途：C4、日志存在与外部效果分离；查询/审计限制。
   - 限制：CloudTrail 记录不等于特定业务动作已经满足目标状态。

5. **AWS IAM — Troubleshoot IAM**
   - URL: https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot.html
   - Publisher: Amazon Web Services；类型：User Guide；tier: primary
   - 直接支持：IAM 使用 distributed computing model called eventual consistency；设计 global applications 时应 account for potential delays。
   - 用途：C5、最终一致查询的风险边界。
   - 限制：该说明不提供所有 AWS 服务的统一延迟窗口，也不证明某次空查询代表不存在。

6. **Kubernetes — Controllers**
   - URL: https://kubernetes.io/docs/concepts/architecture/controller/
   - Publisher: Kubernetes project；类型：官方文档；tier: primary
   - 直接支持：controller 是 control loop；观察 desired state 与 current state，使 current 接近 desired；Job controller 的工作最终完成；与外部状态交互的 controller 读取外部状态并把状态报告回 API server。
   - 用途：C6、reconciliation 的控制循环抽象。
   - 限制：不是任意外部 API 的成功/幂等保证。

7. **GitHub Docs — Managing environments for deployment**
   - URL: https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments
   - Publisher: GitHub；类型：官方文档；tier: primary
   - 直接支持：environment 可有 deployment protection rules；job 在规则满足前不能运行或访问 environment secrets；可设置 required reviewers、wait timer、部署分支和自定义保护规则；required reviewers 最多 6 人/团队，任一 reviewer 批准即可继续。
   - 用途：C7、人工审核门的官方机制实例。
   - 限制：审核门控制 job 放行，不自动证明外部副作用。

8. **GitHub Docs — Re-running workflows and jobs**
   - URL: https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs
   - Publisher: GitHub；类型：官方文档；tier: primary
   - 直接支持：workflow/all failed jobs/specific jobs 可在初始运行后 30 天内重跑；重跑使用初始触发 actor 的权限、原 GITHUB_SHA/GITHUB_REF；一个 workflow run 最多重跑 50 次。
   - 用途：C8、人工恢复能力及其限制。
   - 限制：重跑限制与权限继承不构成外部动作幂等或结果确认。

## 研究方法与检索记录

- 先读取 `/var/minis/skills/evidence-first-research/SKILL.md` 及其 manifest schema，按“问题契约—主张分解—官方一手来源—逐项证据—对抗性检查”执行。
- 采用直接抓取上述官方文档，并读取其官方 raw Markdown/正文；没有引用搜索摘要、转载、私有页面、登录内容、API 凭据或本地历史研究产物。
- 对 Temporal URL 先核验页面标题/正文，再使用文档声明的 `.md` raw 形式获取直接文本；GitHub 旧路径 404 后使用其当前官方路径，仅使用可访问的当前页面。
- 没有找到同一产品、同一语义和同一适用范围的直接冲突；不同产品保证范围不能拼接为统一 exactly-once 保证。
