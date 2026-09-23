# 平台回执、外部 read-back、最终验证与证据分层：可迁移闭环

- 研究切片：A-LINE-READBACK-VERIFY-RESEARCH
- 访问日期（按任务指定）：2026-09-22
- 范围：仅公开官方一手资料；比较 Temporal、LangGraph、OpenAI Agents SDK，并补充 W3C/RFC 规范。
- 结论级别：下面把“官方文档明确写出”的内容标为 `verified`；从多个明确事实推导出的工程设计标为 `inferred`；官方资料没有给出保证的内容标为 `unknown`。

## 0. 先给边界结论

平台的“已记录/已持久化/已导出/已返回 final output”只证明平台内部某一层发生了相应状态变化，不能证明外部 production 系统已经产生目标业务效果。checkpoint、event history、run result、trace/span、benchmark 都是执行平台的内部状态或观测证据；它们不是外部系统的提交回执，也不是独立的 production 效果证明。外部效果必须在外部目标系统中以可定位、可重读的 read-back（例如目标资源版本、服务器生成的 ID、状态/时间/校验值）重新取得，并按预先定义的验收谓词验证。

推荐的可迁移闭环（实现无关）：

`intent + idempotency key → dispatch → capture platform receipt → read external authoritative state → validate predicate → persist evidence bundle → reconcile/retry/compensate`

其中：

1. **Dispatch**：对外部写入使用幂等键/业务唯一键；记录请求摘要、目标、调用时间和 correlation/trace ID，但不要把发送成功当作业务提交成功。
2. **平台回执**：记录 HTTP/SDK 响应、平台 run 状态、工具输出、事件/trace、checkpoint 或 session 写入结果，并标注其证据层（平台层）。
3. **外部 read-back**：使用外部系统的查询 API/读模型，以服务端返回的资源 ID、版本、状态、更新时间、ETag/校验摘要等为准；查询必须独立于本地内存和平台 trace。
4. **最终验证**：用确定的 acceptance predicate 比较 read-back 与 intent（资源身份、字段、版本、业务状态、权限/租户边界、时间窗口）；不满足或无法读回即 `UNKNOWN`，不得升级为成功。
5. **证据分层**：将“平台执行证据”和“外部效果证据”分开保存，带来源 URL/接口、读取时间、request/correlation ID、原始响应摘要或受控留存、哈希和判定理由。
6. **异常闭环**：超时、取消、重复、读回冲突、平台 receipt 缺失均进入 reconcile；按幂等键先 read-back，再决定重试或人工处置。禁止仅凭重复 dispatch 解决 UNKNOWN。

## 1. 三个平台对闭环各层的支持

### Temporal

**verified（官方明确）**

- Temporal Service 响应外部 occurrence 和 Workflow Execution 产生的 Commands 创建 Events，全部 Events 记录在 Event History；Activity 的 scheduled/started/completed/failed/timeout/canceled 等生命周期事件也会写入 history。[S1]
- 官方写明 Event History 由 Temporal Service 持久化，因此应用状态可在 crash/failure 后存活；Service 保存 Workflow Execution 整个生命周期的 complete Event History，并设置数量/大小限制。[S1]
- 这提供了很强的工作流编排、重放/恢复和平台内时间线证据，但它仍是 Temporal 对 workflow/activity 的记录。

**inferred（工程推论）**

- Temporal Activity 可作为“外部写入 + 外部 read-back + 验收谓词”的边界；Activity 的完成事件只应作为平台层 receipt。read-back 应显式实现为后续 Activity，并在同一 workflow 中保存外部资源标识与验证结果。
- 业务唯一键/幂等键以及 reconciliation 仍需由应用和外部系统共同定义；Temporal Event History 不能替代外部系统的资源查询。

**unknown（官方资料未证明）**

- Temporal 官方页面没有证明任意外部系统在 Activity 完成后必然已提交、已可读、或具备业务语义上的最终效果；也没有证明平台 receipt 自动等价于外部 authoritative read-back。
- Event History 的持久化和完整性不等于第三方系统数据的独立证明；本文未把它作为外部 production 效果。

### LangGraph

**verified（官方明确）**

- LangGraph persistence 以 checkpointer 持久化 thread 的 graph state 为 checkpoints；stores 持久化 graph state 之外、由应用定义的跨 thread key-value 数据。[S2]
- 官方明确列出 persistence 用途包括继续对话、interrupt 后 resume、failure recovery、time travel 和 fault tolerance；`thread_id` 是 checkpointer 的线程范围标识。[S2]
- 官方明确区分 checkpointer（graph state snapshots、single thread、short-term）和 store（application-defined key-value、across threads、long-term）。[S2]
- 官方页面还明确指出 InMemorySaver/MemorySaver 在进程重启后丢失 checkpoints，并建议 production 使用持久化 checkpointer；这说明“有 checkpoint”与可靠的外部效果不是同一个命题。[S2]

**inferred（工程推论）**

- graph node 可以把外部 dispatch、独立 read-back 和 predicate validation 分成可重试的节点/步骤；checkpoint 用于恢复控制流和记录应用状态，外部 authoritative read-back 仍必须调用目标系统。
- `thread_id` 适合关联一次线程执行，不应单独作为外部资源身份或成功证明。外部资源 ID、版本和验收结果应成为明确的 state 字段，并与证据层分开。

**unknown（官方资料未证明）**

- LangGraph persistence/checkpoint 文档没有证明 checkpointer snapshot 已被外部 production 系统接受，也没有证明 graph run 完成等于外部业务状态完成。
- persistence 页面不能推出 store 是审计不可变日志、不能推出跨系统 exactly-once，也不能推出 checkpoint 自动具备外部 read-back 能力。

### OpenAI Agents SDK

**verified（官方明确）**

- `RunResultBase` 暴露 `final_output`、`new_items`、`last_agent`、`raw_responses`、`to_state()` 等结果面；官方明确说明 `final_output` 可能为 `None`，例如 run 因 approval interruption 停止且尚未产生最终输出。[S3]
- 官方建议在需要日志/UI/audit 的完整转换历史时使用 `new_items`，需要原始模型 payload 时检查 `raw_responses`；streaming run 只有在迭代器结束后才算完成，摘要属性和 session persistence side effects 可能在最后可见 token 后仍在 settling。[S3]
- Sessions 保存特定 session 的 conversation history；中断审批可用同一 session/backend 恢复。[S4]
- SDK tracing 收集 agent run 中的 LLM generations、tool calls、handoffs、guardrails 和 custom events；trace/span 可配置 processor 导出，`flush_traces()` 会等待当前缓冲 traces/spans export。[S5]
- 官方对 session 写入 ACK 丢失给出了精确恢复边界：若完整 batch 已提交但 ACK 失败，SDK 可识别 exact history tail 避免重复；若 history 不 exact/有并发改写，则 fail closed。官方同时明确该 SDK occurrence guarantee 不是 provider-delivery guarantee；某些 retry 仍可能重发并导致 provider-side work 重复。[S3]
- 官方明确写出：最终输出已接受、guardrails/hooks 完成但持久化失败后，该 RunState 不可恢复，避免重放 terminal effects；应开始新 run。[S3]

**inferred（工程推论）**

- `final_output`、session history、trace export、tool result 都应视为平台/SDK层证据；tool 负责调用外部系统时，必须在 tool 或独立验证步骤中获取外部 read-back，再把 read-back 摘要和 predicate verdict 作为业务结果。
- trace flush 可作为“观测数据已提交到 trace processor”的 receipt，但不能替代外部目标系统 read-back。外部写入的 retry/reconcile 需要幂等键和目标系统查询。

**unknown（官方资料未证明）**

- SDK 的 `final_output`、session persistence 或 trace flush 均不证明任意外部 production action 已生效；官方反而明确 provider-delivery guarantee 不由 SDK occurrence guarantee 提供。
- trace dashboard/导出完整不证明外部资源状态、业务规则或最终可见性；未读回目标系统时应保持 `UNKNOWN`。

## 2. 共同可迁移模型：证据分层

| 层 | 例子 | 可证明 | 不能证明 |
|---|---|---|---|
| L0 意图 | 用户/系统请求、目标资源、业务验收谓词、幂等键 | 想做什么及判定规则 | 已发送、已提交、已生效 |
| L1 dispatch | 客户端发起请求、SDK tool call、HTTP request | 尝试了哪个目标、何时、携带哪个关联键 | 服务端接受、事务提交、业务效果 |
| L2 平台回执 | Temporal Event/Activity event；LangGraph checkpoint；Agents result/session/trace | 编排器/SDK记录了某个内部状态或返回；可恢复/关联的范围 | 外部目标系统最终状态 |
| L3 外部服务回执 | HTTP status、响应体、server resource ID、版本、ETag、异步 job ID | 外部服务对该请求作出的协议层回应 | 异步任务最终业务效果（若仅有 accepted/job ID） |
| L4 外部 read-back | 对目标系统的独立 GET/query/reconcile，服务端 authoritative representation | 读回时刻目标资源的可验证状态与身份 | 永久未来状态、未覆盖的下游系统 |
| L5 最终验证 | predicate 结果、比较细节、时间窗、证据哈希 | 在规定时间/视图下满足或不满足验收条件 | 超出范围的因果/长期效果 |

**规则**：L2 不能跳过 L4/L5；L3 的 `2xx`、`accepted` 或 job ID 不能自动跳成 L5；L4 查询失败、读模型延迟、权限不足、字段缺失和身份不一致均应为 `UNKNOWN` 或 `FAIL`，按策略处理，绝不伪装成成功。

## 3. 外部 read-back 验证记录模板（迁移到任一平台）

```text
verification_id: stable unique id
intent_id: business intent id
idempotency_key: stable key for the external write
platform: temporal | langgraph | openai-agents | other
platform_receipt: event/checkpoint/result/session/trace reference (platform layer only)
dispatch:
  target_system: external authoritative system
  operation: create/update/delete/submit
  request_digest: hash or redacted canonical request
  dispatched_at: timestamp
external_receipt:
  http_status_or_protocol_result: ...
  server_resource_id_or_job_id: ...
  response_digest: ...
read_back:
  query: independent GET/query description
  observed_at: timestamp
  authoritative_source: URL/API/resource
  returned_resource_id: ...
  returned_version_or_etag: ...
  observed_fields_digest: ...
validation:
  predicate_version: ...
  checks: identity / version / business status / required fields / tenant / time window
  verdict: VERIFIED | FAIL | UNKNOWN
  reason: ...
evidence:
  source_urls: ...
  raw_or_redacted_artifact_digest: SHA-256
  retention_and_access: ...
```

`VERIFIED` 在此模板中只表示“外部 read-back 在声明的时间窗内满足 predicate”，而不表示所有下游长期效果；没有外部 read-back 的平台成功只能标记为平台层 `verified`、业务层 `UNKNOWN`。

## 4. 设计选择与风险

- **Temporal**：最适合长生命周期、重试/超时/定时器和确定性编排；把外部 effect 与 read-back 建模为明确 Activity 边界。主要风险是把 durable history 误读成外部提交证明。
- **LangGraph**：最适合图式状态、interrupt/HITL、thread checkpoint 与可见的验证节点；需明确 durable checkpointer，避免内存 checkpoint 在重启丢失。主要风险是把 state snapshot 当作外部事实。
- **OpenAI Agents SDK**：最适合 agent/tool/handoff/approval 与丰富运行证据；必须等待 stream 完成、区分 final output/new_items/raw responses/session/trace，且注意 SDK 明确的 provider-delivery 与 session-ACK 边界。主要风险是把 trace 或自然语言 final output 当成业务效果。
- 三者都不能凭平台内 receipt 消除外部系统的异步可见性、跨服务一致性、权限、下游处理和最终业务语义问题；这些只能靠外部 authoritative read-back、明确 predicate、幂等和 reconcile 闭环补齐。

## 5. 补充规范如何约束闭环

- RFC 9110 说明 HTTP client 根据收到的 response 中的 status code 和 content 作判断；representation 是元数据加数据，语义层明确区分 response 与资源表示。[S6] 这支持把“协议响应”与“独立资源 read-back”分开。
- W3C PROV 将 provenance 定义为涉及产生数据/事物的 entities、activities、people 的信息，并强调发布、交换、访问、验证 provenance 的能力。[S7] 它支持把 intent、dispatch、receipt、read-back、validation 作为带关系的证据图；它不规定某个平台或第三方 API 的提交语义。
- W3C Trace Context 定义 `traceparent`/`tracestate` 以跨服务传播 context，用于 distributed tracing。[S8] trace ID 是关联线索，不是资源状态或业务成功证明；隐私和采样等 trace 限制也不能被忽略。

## 6. 结论

最佳迁移不是选择某个平台的 receipt 作为“真相”，而是把平台执行证据和外部效果证据建模为两个明确层次：平台提供可恢复、可关联、可审计的执行线索；外部系统提供 authoritative read-back；应用用版本化 predicate 进行最终验证，并对 UNKNOWN 走 reconciliation。Temporal 的 Event History、LangGraph 的 checkpoints、OpenAI Agents 的 results/sessions/traces 都有价值，但都不应被描述为外部 production 效果、最终业务提交或 benchmark 之外的真实影响，除非另有外部 read-back 证据。

## 7. 证据状态汇总

- `verified`：各平台官方页面所明确陈述的内部记录、持久化、结果/trace/session 行为，以及 RFC/W3C 规范的定义。
- `inferred`：把这些能力组合成上述 dispatch→receipt→read-back→predicate→reconcile 设计的工程建议；并非平台承诺。
- `unknown`：平台官方文档未承诺、且不能由平台内部 receipt/checkpoint/trace/benchmark 推出的外部生产效果。

所有来源的 URL、访问日期和证明边界见 `sources.md`。
# Sources

访问日期统一按任务要求记录为：**2026-09-22**。所有来源均为公开官方一手资料。`verified` 表示直接读取到官方文本支持；`inferred` 表示基于已验证事实的工程推论；`unknown` 表示该来源没有给出相应保证。

## S1 — Temporal Events and Event History

- URL（完整）：https://docs.temporal.io/workflow-execution/event
- 官方 Markdown URL：https://docs.temporal.io/workflow-execution/event.md
- 访问日期：2026-09-22
- 证据状态：verified
- 关键文本/可证明：页面明确写出 Events 由 Temporal Service 针对 external occurrences 与 Workflow Execution commands 创建；所有 Events 写入 Event History；Event History 由 Temporal Service 持久化，因此应用状态可在 crashes/failures 后存活；Service 保存整个 Workflow Execution 生命周期的 complete Event History，并有大小/数量限制。Activity scheduled/started/completed/failed/timeout/canceled 等事件也会进入 history。
- 能证明：Temporal 平台内部事件历史的记录、持久化、生命周期与限制；平台对 workflow/activity 的内部进展可被关联和恢复。
- 不能证明：任意外部系统已提交、资源已可读、异步下游已完成或业务效果已达成；不能把 Event History 当成外部 authoritative read-back，也不能推出 exactly-once 外部效果。
- 相关报告引用：Temporal 小节及证据层表中的 L2 边界。

## S2 — LangGraph Persistence

- URL（完整）：https://docs.langchain.com/oss/python/langgraph/persistence
- 访问日期：2026-09-22
- 证据状态：verified
- 关键文本/可证明：页面说明 persistence 通过 checkpointers 提供 short-term memory、通过 stores 提供 long-term memory；checkpointer 持久化 thread graph state 为 checkpoints，store 持久化 graph state 外的 application-defined key-value；用途包括继续、interrupt resume、failure recovery、time travel、fault tolerance；`thread_id` 作为线程配置；MemorySaver/InMemorySaver 在进程重启时丢失 checkpoint，production 建议持久化 checkpointer。
- 能证明：LangGraph graph state snapshot 的持久化范围、thread/store 区别、恢复/中断相关的内部状态语义，以及内存实现的重启丢失边界。
- 不能证明：checkpoint 已被外部 production 接受、外部业务状态已写入或已最终可见；不能推出审计不可变性、跨系统 exactly-once、外部 authoritative read-back。
- 备注：官方页面页面元数据的 dateModified 可能随站点更新；本研究只记录访问日期，不把站点发布日期当作访问时间。

## S3 — OpenAI Agents SDK Results

- URL（完整）：https://openai.github.io/openai-agents-python/results/
- 访问日期：2026-09-22
- 证据状态：verified
- 关键文本/可证明：`RunResultBase` 的 result surfaces 包含 `final_output`、`new_items`、`last_agent`、`raw_responses`、`to_state()`；`final_output` 在 approval interruption 等 run 未产出最终结果时可为 `None`；`new_items` 适合完整历史/日志/UI/audit，`raw_responses` 可查看原始模型响应；streaming 必须等迭代器结束后才算完成；session 写入 ACK 失败时有 exact-tail reconciliation；官方明确 occurrence guarantee 不是 provider-delivery guarantee，某些 retry 可能重发 provider-side work；接受 final output 后持久化失败的 RunState 不可恢复。
- 能证明：SDK 对本次 run 的内部结果视图、运行状态、session 写入协调、stream 结束边界和明确的 replay-safe/replay-unsafe 条件。
- 不能证明：`final_output`、`new_items`、session ACK、raw response 或运行完成等于任意外部 production action 成功；不能由 SDK occurrence guarantee 推出 provider delivery 或外部业务效果。

## S4 — OpenAI Agents SDK Sessions

- URL（完整）：https://openai.github.io/openai-agents-python/sessions/
- 访问日期：2026-09-22
- 证据状态：verified
- 关键文本/可证明：Sessions 保存特定 session 的 conversation history；同一 session 可在 approval pause 后以相同 session/backend 恢复；SDK 提供多种 session 实现和持久化选项。
- 能证明：SDK conversation history/session persistence 的内部范围与中断恢复机制。
- 不能证明：外部资源状态、外部服务已接受写入、对话历史是业务系统的 authoritative record；session history 不能替代外部 read-back。

## S5 — OpenAI Agents SDK Tracing

- URL（完整）：https://openai.github.io/openai-agents-python/tracing/
- 访问日期：2026-09-22
- 证据状态：verified
- 关键文本/可证明：built-in tracing 记录 LLM generations、tool calls、handoffs、guardrails、custom events；trace 由 spans 组成；可用 custom processors 推送到其他目的地；默认 processor 后台导出，`flush_traces()` 等待当前缓冲 traces/spans 导出；可配置是否采集潜在敏感数据。
- 能证明：SDK tracing/flush 对平台观测数据的记录与导出边界，以及 trace/span 关联能力。
- 不能证明：trace dashboard/processor 已观察到外部资源的最终状态、业务规则已满足、下游已完成；trace ID 不是外部资源版本或提交回执。

## S6 — RFC 9110 HTTP Semantics

- URL（完整）：https://www.rfc-editor.org/rfc/rfc9110
- 访问日期：2026-09-22
- 证据状态：verified
- 关键文本/可证明：HTTP 消息为 request/response；client 根据 received response 的 status codes 和 content 判断；representation 由 metadata 和 data 构成；RFC 定义 response/status/representation 的协议语义。
- 能证明：协议层 response 与资源 representation 是可区分的；HTTP 客户端可以基于 status/content 进行协议判断。
- 不能证明：某个 2xx/accepted response 自动意味着异步业务完成、跨系统下游生效或永久效果；具体外部资源的最终验证仍需 API 语义和独立 read-back。

## S7 — W3C PROV Overview

- URL（完整）：https://www.w3.org/TR/prov-overview/
- 访问日期：2026-09-22
- 证据状态：verified
- 关键文本/可证明：PROV 是关于参与产生数据/事物的 entities、activities、people 的 provenance 信息；PROV 家族支持在异构环境中发布、交换、访问和验证 provenance。
- 能证明：可将意图、执行活动、实体和验证关系组织为 provenance/evidence graph 的规范化方向。
- 不能证明：任何平台自动符合某种审计级别；不能规定第三方 API 的提交、可见性、幂等或最终业务语义；不把 provenance 本身变成外部效果证明。

## S8 — W3C Trace Context

- URL（完整）：https://www.w3.org/TR/trace-context/
- 访问日期：2026-09-22
- 证据状态：verified
- 关键文本/可证明：规范定义标准 HTTP headers 和 value format 来传播 context，以支持 distributed tracing；`traceparent` 标识请求在 trace graph 中的位置，`tracestate` 可携带 vendor-specific data。
- 能证明：跨服务传播和关联 trace context 的标准字段及其用途。
- 不能证明：traceparent/tracestate 对外部资源做过何种变更、资源当前状态或业务操作已完成；trace correlation 不是外部 read-back。

## 证据层方法注记

- `verified` 仅归于来源直接陈述的事实；报告中的“把后续 read-back 建模为步骤/Activity/node/tool”“用 predicate 和 reconciliation 处理 UNKNOWN”等属于 `inferred` 工程设计。
- 本研究没有使用博客、论坛、第三方 benchmark、非官方教程或真实生产系统。
- 明确排除：平台回执、checkpoint、trace、benchmark 不能单独作为外部 production 效果证明；只有外部 authoritative read-back + 版本化验收 predicate 才能把业务层判定提升为 `VERIFIED`。
# Summary

## 一句话结论

Temporal 的 Event History、LangGraph 的 checkpoint/store、OpenAI Agents SDK 的 result/session/trace 都能提供有价值的平台内执行证据，但都不能单独证明外部 production 效果；可迁移闭环必须是：**dispatch → 平台回执 → 外部 authoritative read-back → 版本化验收 predicate → 证据分层与 reconciliation**。

## 对比

| 平台 | 官方明确提供 | 适合放在闭环的哪里 | 不能替代 |
|---|---|---|---|
| Temporal | Service 生成并持久化 workflow Event History；Activity 生命周期事件 | 长生命周期编排、重试/超时/恢复；把外部写与 read-back 做成明确 Activity | 外部系统提交/可见性/业务最终效果 |
| LangGraph | checkpointer 持久化 thread graph state；store 保存应用定义的跨 thread 数据；支持 interrupt/resume/failure recovery | 图式状态、HITL、验证节点和恢复 | 外部 authoritative state、审计不可变性、exactly-once |
| OpenAI Agents SDK | final_output/new_items/raw_responses/to_state；session；tracing/flush；明确 session ACK 与 provider-delivery 边界 | agent/tool/handoff/approval、运行审计线索、外部 read-back 工具 | provider delivery 和外部 production 效果 |

## 最小证据分层

- **L0**：intent、目标、幂等键、验收规则。
- **L1**：dispatch 尝试与请求摘要。
- **L2**：平台 receipt（event/checkpoint/result/session/trace），只证明内部状态。
- **L3**：外部协议 response（status/resource ID/job ID），不必然是完成。
- **L4**：外部独立 GET/query 的 authoritative read-back。
- **L5**：在时间窗内按 predicate 得出 VERIFIED/FAIL/UNKNOWN。

硬规则：L2 不能跳过 L4/L5；只有“平台 success”而无外部 read-back，业务判定必须是 **UNKNOWN**。平台回执、checkpoint、trace、benchmark 均不写成外部 production 效果。

## 实操验收

对于任何外部写入，至少保存：`intent_id`、稳定 `idempotency_key`、平台 receipt reference、外部 resource/job ID、独立 read-back 时间和 authoritative source、版本/ETag、观察字段摘要、predicate version、verdict、reason、证据 SHA-256。若超时/取消/ACK 丢失/读回延迟/身份冲突，先按幂等键 read-back，再 reconcile；不要盲目重复写入。

## 证据状态

- **verified**：来源直接写出的平台行为与规范定义。
- **inferred**：据此设计的跨平台闭环和工程建议。
- **unknown**：官方未承诺的外部效果；缺少 read-back 时保持 UNKNOWN。

完整 URL、访问日期（2026-09-22）及每个来源的能证明/不能证明边界见 `sources.md`；详细论证见 `report.md`。
