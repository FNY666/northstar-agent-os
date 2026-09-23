# A线审批与证据保全研究切片

- 访问/核验日期：2026-09-22（Asia/Shanghai；官方页面抓取日）
- 范围：仅公开、官方一手文档；Temporal、LangGraph、OpenAI Agents SDK。未运行任何真实服务、未登录、未调用生产系统。
- 结论置信度：对“文档明确写出的平台机制”为 verified；对合规充分性、跨系统真实性和外部效果证明保持 unknown。

## 结论

三者都能表达“暂停—人工决定—恢复”，但“批准回执”不是同一类证据：

1. **Temporal**：推荐把批准决定作为带身份/理由/时间戳的 Signal 数据写入 Workflow Event History。官方 Approval Pattern 明确说 Signal 事件进入历史，并称其为 built-in audit trail；Event History 是可持久、用于 replay/recovery 的生命周期事件日志。Temporal Cloud Audit Logs 另属控制平面访问/资源操作日志，官方明确不记录数据平面 Workflow Start/Terminate 等事件。因此，Temporal Event History 能证明平台工作流接收到/记录了某批准信号（前提是调用者和业务逻辑正确），不能单凭它证明真人身份、权限真实有效、外部系统已实际生效，也不能将 Cloud Audit Logs 当作业务审批日志。
2. **LangGraph**：interrupt() 暂停执行，checkpointer 保存精确 graph state；使用同一 thread_id 以 Command(resume=...) 恢复。checkpoint 是图状态快照/恢复游标，不是平台签发的不可抵赖批准凭证。官方页面建议人工审核/编辑工具调用，但没有证明 reviewer 身份、RBAC、不可篡改审计或外部副作用 read-back 的内置保证。必须由应用持久化审批请求、审批人认证、决定、版本/幂等键以及外部系统回读。
3. **OpenAI Agents SDK**：工具可 needs_approval，RunResult 暴露 interruptions，RunState 可序列化后恢复；官方安全边界尤其明确：from_json/from_string 不认证快照或提交者，必须只接受可信、完整性/归属已验证的服务器快照；服务端应认证 reviewer、仅从服务端 pending items 取出请求，再 approve/reject 并原子消费。RunState 是恢复所需执行状态，不等于独立审计日志。Tracing 是 LLM/tool/handoff/guardrail 等 run 的 trace/span，Sessions 是会话历史；二者不能自动证明人工批准或外部效果。若要把批准纳入合规审计，应在应用审计库/受管日志中追加独立、不可篡改事件，并关联 trace/run/外部事务 ID。

## 权限边界与证据分类

| 证据对象 | 它能证明 | 它不能单独证明 |
|---|---|---|
| 平台批准回执/ACK（如 Signal 调用返回、resume/approve API 的返回） | 请求被平台/API 接收；可能含请求 ID/状态 | 人已授权、业务已完成、外部副作用成功；ACK 不等于最终结果 |
| Temporal Event History | Workflow 生命周期事件、Signal 载荷（若业务写入）、重放/故障恢复依据 | Signal 发送者真人身份、组织权限、外部系统最终状态；也不是 Cloud 控制平面审计日志 |
| LangGraph checkpoint | 指定 thread 的图状态快照、暂停点、恢复依据 | 审批真实性/权限、不可篡改性、工具是否执行成功、外部最终状态 |
| OpenAI RunState | pending interruptions、工具输入、批准/拒绝等 SDK 执行状态及恢复依据 | 快照提交者身份/真实性（官方明确不认证）；独立合规审计、外部系统最终状态 |
| Trace/stream/run event | 运行过程的可观测事件、工具/模型/guardrail 等 span 或流 | 真人批准、授权链、外部提交已落地；trace 采集/导出失败也可能发生 |
| 审计日志 | 由该审计系统定义范围内的谁/何时/做了什么 | 未覆盖的业务数据平面或外部系统效果；Temporal Cloud Audit Logs 明确不覆盖 Workflow Start/Terminate 等数据平面事件 |
| 外部 read-back | 外部系统按事务/幂等 ID 返回的实际状态，可支持“效果已观察到” | 仍需验证回读来源、时点、权限、事务一致性；不能倒推出最初批准合法 |

## 恢复与安全控制建议（设计结论，不冒充平台事实）

- 暂停时生成不可复用 approval_request_id，并绑定 workflow/run 或 thread/run 标识、工具/动作摘要、输入哈希、策略版本、目标外部事务 ID、过期时间。
- 审批服务端认证 reviewer 并做授权/职责分离；客户端只提交 opaque ID + approve/reject + 可选理由，不回传可替换的完整快照、工具名或参数。
- 用原子状态机消费 pending 请求（pending→approved/rejected/expired/consumed），拒绝重放；审批事件追加到独立审计存储，带事件时间、服务器时间、主体、原因、版本和关联 ID。
- 恢复前重新从服务端读取原始请求，校验快照完整性、所有权、策略版本和过期；恢复后不要把“恢复调用成功”当外部成功。
- 工具产生外部副作用时使用幂等键；提交后通过外部系统 API read-back 核验状态/版本/事务 ID，把 read-back 原文摘要及时间写入审计事件。
- benchmark、示例 trace、公开演示只证明示例行为，不能推导 production 可用性、合规性或外部效果；本切片未使用 benchmark 作为证据。

## 平台对照

| 维度 | Temporal | LangGraph | OpenAI Agents SDK |
|---|---|---|---|
| 人工暂停 | Signal + wait/timeout | interrupt() + persistence | needs_approval + interruption |
| 恢复载体 | Event History replay，Signal/Update 等由工作流处理 | checkpointer checkpoint，thread_id + Command(resume) | RunState 序列化，approve/reject 后 resume |
| 平台内批准结果 | 可把批准数据写入 Signal/Event History；Signal 是 fire-and-forget（官方 Approval 文档） | interrupt payload/Command resume 是应用交互，不是“平台批准回执” | interruption/RunState 含 pending/decision 执行状态；不是认证凭证 |
| 审计日志 | Cloud Audit Logs 是控制平面；业务批准仍需 Event History/应用日志 | 官方所查页面未证明内置不可篡改审批审计 | Trace/Session/RunState 各自有不同用途；官方未将其定义为合规审批审计 |
| 外部效果证明 | 需 Activity/外部系统 read-back | 需节点/外部系统 read-back | 需工具/外部系统 read-back |
| 关键权限边界 | 文档建议校验 Signal 数据、approver permissions；实现责任在应用 | 文档描述暂停/恢复，未证明 reviewer auth | 官方明确快照不认证；服务端必须认证并只用服务器拥有的 pending items |

## 未知与限制

- 所有结论是截至访问日官方文档的机制边界，不是对任意部署配置、SDK 版本、SaaS retention、区域合规或真实业务的认证。
- 未把“文档称 built-in audit trail”扩大解释为法律意义上的不可篡改、独立、完整审计；仍需确认 retention、导出、权限、篡改检测和证据链。
- 未证明任何平台自身可以验证批准者在企业目录中的权限，除非应用显式接入认证/授权。
- 未证明任何平台能单独证明外部支付、部署、数据库写入等副作用已发生；只有外部 read-back 才能在具体外部系统范围内提供效果观察证据。
