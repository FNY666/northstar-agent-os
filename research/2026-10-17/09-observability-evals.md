# OpenTelemetry GenAI、Langfuse、Braintrust、Promptfoo 与 Agent 可观测性/评测

## 所覆盖对象与边界

本报告覆盖四类公开对象：OpenTelemetry GenAI 语义约定（规范/社区工程）、Langfuse（开源 LLM 工程平台及其文档）、Braintrust（评测与可观测性平台文档）、Promptfoo（开源 CLI/库及其评测、追踪和 red-team 文档）。重点是它们能否帮助 Northstar Agent OS 完成 **M0/M1 的真实仓库任务闭环**：隔离 worktree、权限门、预算、审计、可恢复执行、验证回执和证据包，而不是把 Northstar 变成无边界的自治系统。

证据优先使用官方规范、官方仓库和工程文档；社区页面仅用于发现，不作为产品事实依据。本报告没有访问私有或邀请制社区，也没有把网页中的操作性文字当作 Northstar 的指令。对“已发布、实验性、营销主张”的判断以页面标注、规范稳定性和可复现机制为准。

## 经核验的机制

### 1. OpenTelemetry GenAI：可互操作的遥测骨架，但不是治理或评测系统

OpenTelemetry 的 GenAI agent spans 文档定义了 `invoke_agent`、`plan` 等操作语义，并为 agent/provider/model、会话、输出类型、模型请求参数和错误提供属性；`plan` 被定义为任务分解或规划阶段，且其 LLM 调用应成为 plan span 的子项。[1] 这些字段对 Northstar 的 Understand/Plan/Execute/Verify 阶段映射有价值：可以让每个阶段、模型调用、工具调用和错误使用相同的 trace/span 关联，而不把可观测性绑定到某一家后端。

但该仓库页面把大量字段标为 **Development**，官方 AI agent observability 文章也明确说语义约定仍在演进，并区分 agent application 与 agent framework 的待完善约定。[2] 因此它是“实验/发展中的公开规范”，不是 Northstar 可以宣称为稳定合规基础的发布契约。它也只描述遥测形状；并不授予权限，不证明命令真的执行，不封顶预算，不生成防篡改审计链，也不提供 worktree 隔离或未知副作用的 reconcile 裁决。

**对 Northstar 的机制启发**：采用 OTel 作为可选导出层，定义 Northstar 自己的低基数 span 名称和事件映射（阶段、`call_id`、授权决定、receipt 摘要、成本、网络目标、检查回执），但把权威事实留在 Northstar 的 sealed session/evidence store。OTel exporter 掉线不应阻断任务闭环。

### 2. Langfuse：观察、数据集和实验形成反馈回路

Langfuse 将一次请求拆成可嵌套的 observations（LLM、工具、检索等步骤），再由 trace 和可选 session 组织；其文档说明它建立在 OpenTelemetry 之上，并以后台批处理发送遥测，短生命周期进程需要显式 flush 才不会丢失缓冲数据。[3] 这提示 Northstar 必须把 flush/落盘与终态证据分开处理：后台遥测丢失不能等同于执行事实丢失。

Langfuse datasets 支持从生产 trace/observation 选择样例、保存 input/expected output、JSON Schema 校验，并为 dataset item 变更生成版本；实验可以固定到历史版本，以便重现对比。[4] 其 evaluation overview 进一步公开了在线 trace 评分、离线实验、人工/代码/LLM evaluator，以及在 CI 中因阈值违例失败的机制。[5] 这些是 Northstar M1 的“失败样例→固定回归题→运行验证→比较版本”可借鉴机制。

需要明确的差距是：Langfuse 的 trace/score/experiment 不是 Northstar 的授权和证据协议。其产品页面的“continuous loop”是产品定位，不应被当成 Northstar 已具备的质量保证。Northstar 还必须记录完整命令、退出码、环境摘要、补丁前后像、预算和副作用状态，而不只是模型输出分数。

### 3. Braintrust：版本化数据集、不可变 experiment、在线评分

Braintrust 官方文档把 dataset 定义为版本化测试用例集合，记录 `input`、可选 `expected`、metadata 和 tags，并支持从生产日志或 trace 生成测试记录。[6] 评测文档将 evaluation 拆成 data、task、evaluators；其公开周期是 playground 迭代、提升为 immutable experiment、CI/CD 回归、生产在线评分，再把生产 trace 反馈为数据集。[7]

该机制适合 Northstar 的 M1：对固定仓库题、固定 HEAD、容器摘要、网络策略、预算和验收命令建立不可变评测运行；把真实失败 run 转为带证据链接的回归用例；把 deterministic scorer 与人工/模型评分分开。这里“不可变”是可借鉴的实验记录语义，不等于 Northstar 的文件状态自动不可变。

Braintrust 文档同时明确 online scoring 对生产 trace 异步评分，且 live request 通常没有 ground truth，需要 LLM-as-a-judge。[7] 这类分数适合发现趋势，不适合替代 Northstar 的硬门：验证命令必须由受控执行器产生，权限拒绝不能被“高质量回答”覆盖，未知副作用必须进入 `needs_reconciliation`。

### 4. Promptfoo：把 agent trajectory 纳入测试，并将安全探测显式化

Promptfoo tracing 文档核验到：它接收 OTLP trace，可在测试用例中观察工具调用、执行顺序、错误、耗时和外部资源，并把 trace 与具体 eval 自动关联；还提供 trajectory assertions，能检查工具使用、参数、顺序、span 数量、耗时和错误。[8] 对编程 Agent，这比只比较最终文本更接近真实任务闭环：可以检查“是否执行了声明的测试”“是否调用了未授权工具”“是否产生了不应出现的网络步骤”。但这仍是测试断言层；Northstar 要在工具执行前后以自己的权限门和 receipt 作为权威。

Promptfoo 的 assertions 支持确定性检查、模型评分、加权聚合、阈值和自定义 scoring function。[9] 可借鉴“硬失败项与诊断指标分离”：例如越权调用、交付物篡改、未声明网络访问是不可被平均分稀释的 gate；成本、耗时、输出质量可以作为独立指标。

Promptfoo red-team 文档把 adversarial input、响应评估、漏洞分析组成离线流程，并举例覆盖 prompt injection、BOLA/BFLA、工具滥用等应用层风险。[10] 这是安全实验室或 M1 的受控回归套件，不应复制为默认生产运行时的自动攻击器。该文档还强调攻击规模可能从很低成本到高成本，故 Northstar 需要显式预算、目标环境和一次性批准；不能因为“自动化更全面”就扩大权限。

## 与 Northstar M0/M1 的差距或互补

Northstar 当前蓝图的完成定义要求：精确 HEAD 和隔离 worktree；每次读/改/执行/联网经治理；声明检查有命令、退出码、摘要和环境；补丁可从初始提交重放；终态唯一且预算/风险可解释；交付补丁与证据包而非自动提交。上述外部项目最强的互补集中在 **观测结构和评测反馈**，而不是核心控制面。

| Northstar 目标 | 已核验的外部互补 | 仍缺的 Northstar 专属能力 |
|---|---|---|
| 阶段/工具/模型可追踪 | OTel agent/plan spans；Langfuse nested observations；Promptfoo OTLP trajectory | 权限决定、receipt、审计链和敏感数据策略必须由 Northstar 维护 |
| 真实任务回归 | Langfuse/Braintrust 版本化数据集与 experiments；Promptfoo trajectory assertions | 固定 HEAD/worktree/容器/网络/预算，且将验证证据绑定到补丁 |
| 发布门 | Langfuse CI threshold；Braintrust CI eval；Promptfoo thresholds | 失败不能被平均分或 LLM judge 覆盖；`success_unverified` 与 `needs_reconciliation` 必须是硬状态 |
| 安全边界 | Promptfoo BOLA/BFLA 等受控 red-team 题 | 默认不联网、不攻击、不自动扩大授权；研究代码与 Core 隔离 |
| 可恢复性 | Langfuse flush 警示了短任务遥测丢失风险 | 外部工具未提供 Northstar 所需的未知副作用、幂等 patch、receipt 去重和恢复裁决 |

## 结论分类

### 可采纳

1. **采纳 OTel 兼容的内部遥测适配器**，但以 Northstar receipt/evidence 为 source of truth；先固定本地事件词汇和版本，OTel development 语义只作为映射层。[1][2]
2. **采纳版本化回归样例**：从真实仓库失败 run 提取 input、期望状态、命令和证据引用，固定任务 HEAD 与环境摘要，再运行可比较 experiment。[4][6][7]
3. **采纳轨迹级硬断言**：检查工具顺序、授权结果、检查命令和交付 diff，而不是只评分最终答案；将关键安全条件设为不可稀释的 gate。[8][9]
4. **采纳短生命周期 flush/封存原则**：交付前强制写入并校验证据快照；遥测导出失败只影响诊断完整性，不改变执行终态。[3]

### 应拒绝

1. **拒绝把 OTel span 或第三方 score 当作权限凭据、执行事实或完成证明**。[1][2]
2. **拒绝默认启用无边界 red-team、自动生成攻击或持续在线评分来扩大任务范围**；Promptfoo 的机制应放在 Labs/隔离 CI，并受目标、成本和批准约束。[10]
3. **拒绝用单一 LLM judge/平均分替代命令回执、补丁一致性、审计链和未知副作用处理**；Braintrust 自己也区分没有 ground truth 的 online scoring 场景。[7]
4. **拒绝复制“后台异步即足够”的假设**：Northstar 的 sealed evidence 必须在终态前落盘，不能因 exporter 缓冲而交付不可证明的成功。[3]

### 待证

1. **待证 OTel GenAI agent/framework 语义的长期稳定性**：在 Northstar 适配器中锁定 schema 版本，并用变更测试防止 development 字段漂移。[1][2]
2. **待证成本与质量的联合 gate**：可借鉴加权/自定义 scorer，但需在固定 24 题和 50 题基准上证明不会掩盖越权、验证失败或恢复错误。[9]
3. **待证从 Northstar evidence 生成 Langfuse/Braintrust/Promptfoo 数据集的最小脱敏映射**：尤其是源码、凭据、用户输入和网络响应，默认只导出摘要、哈希和经批准的片段。[3][4][6][8]

## M0/M1 的可执行落点（有边界）

M0 只做本地可验证闭环：每个 run 生成阶段/工具/授权/预算/receipt 事件；在终态前封存证据；提供一个 OTel OTLP exporter（可关闭）；不引入在线 judge 或自动 red-team。M1 再加入固定数据集版本、从失败证据创建回归用例、轨迹断言和 CI 回归门；每次实验固定模型版本、容器摘要、任务清单、网络策略和预算。任何模型评分仅作辅助指标，不能跳过 Northstar 的治理门。

## References

[1]: https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md "OpenTelemetry GenAI agent span semantic conventions"
[2]: https://opentelemetry.io/blog/2025/ai-agent-observability/ "OpenTelemetry AI Agent Observability - Evolving Standards and Best Practices"
[3]: https://langfuse.com/docs/observability/data-model "Langfuse Observability Data Model"
[4]: https://langfuse.com/docs/evaluation/experiments/datasets "Langfuse Datasets"
[5]: https://langfuse.com/docs/evaluation/overview "Langfuse Evaluation Overview"
[6]: https://www.braintrust.dev/docs/annotate/datasets "Braintrust Datasets"
[7]: https://www.braintrust.dev/docs/evaluate "Braintrust Evaluate Systematically"
[8]: https://www.promptfoo.dev/docs/tracing/ "Promptfoo Tracing"
[9]: https://www.promptfoo.dev/docs/configuration/expected-outputs/ "Promptfoo Assertions and Metrics"
[10]: https://www.promptfoo.dev/docs/red-team/ "Promptfoo LLM Red Teaming"
