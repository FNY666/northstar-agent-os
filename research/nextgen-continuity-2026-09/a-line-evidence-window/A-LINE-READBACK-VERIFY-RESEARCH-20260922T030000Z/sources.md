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
