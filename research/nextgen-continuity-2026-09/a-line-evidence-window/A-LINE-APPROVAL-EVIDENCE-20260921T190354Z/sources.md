# Sources（仅公开官方一手资料）

访问日期统一：**2026-09-22**。证据等级：**verified** = 官方页面直接陈述/示例明确支持；**inferred** = 从官方机制作出的有边界推论；**unknown** = 页面未证明或本研究未验证。URL 均为完整绝对 URL。

## 1. Temporal — Approval Pattern

- URL: https://docs.temporal.io/design-patterns/approval
- Publisher: Temporal Documentation
- Accessed: 2026-09-22
- Evidence: verified
- Direct support captured: Approval Pattern uses Workflow Signals with custom data to unblock a blocked workflow; data can include approval decision, approver details, comments, identity/reason/timestamp; approval data is recorded in Workflow History as Signal events; timeout/fallback and Query status are described; docs recommend validate Signal data, verify approver permissions/data completeness, log approval events, idempotency.
- Can prove: Temporal’s documented pause/decision pattern; that a Signal event and supplied payload are part of Workflow History; replay-safe workflow record when app follows pattern.
- Cannot prove: caller’s human identity or enterprise entitlement; that the approver actually reviewed content; that a Signal caller is authorized merely because Signal was accepted; external side effect or final business outcome; legal-grade tamper evidence/retention; Cloud control-plane audit coverage. Signal ACK is not final business result (docs’ comparison calls Signals fire-and-forget).
- Notes: official design pattern, normative/example documentation, not a production benchmark or independent efficacy study.

## 2. Temporal — Event History

- URL: https://docs.temporal.io/encyclopedia/event-history/
- Publisher: Temporal Documentation
- Accessed: 2026-09-22
- Evidence: verified
- Direct support captured: Event History is described as a complete and durable log of what happened in a Workflow Execution lifecycle; service durably persists events; Commands map to persisted Events; after worker crash, replay reconstructs state and resumes progress.
- Can prove: platform execution history/replay and crash recovery semantics as documented.
- Cannot prove: independent audit log of all human/organizational actions; reviewer identity/authorization; external system effect; that all application-level facts were recorded unless workflow emits them; legal admissibility or immutable retention beyond documented service semantics.

## 3. Temporal Cloud — Audit Logs

- URL: https://docs.temporal.io/cloud/audit-logs
- Publisher: Temporal Documentation
- Accessed: 2026-09-22
- Evidence: verified
- Direct support captured: Audit Logs provide forensic access information for Temporal Cloud Control Plane operations and answer who/when/what for covered resources; docs explicitly say they do not capture data-plane events such as Workflow Start, Workflow Terminate, Schedule Create, etc., and point to Export for closed Workflow Histories.
- Can prove: covered Temporal Cloud control-plane operations and the documented scope limitation.
- Cannot prove: business approval decision; Workflow Event History; external effect; any data-plane Workflow outcome; reviewer authorization outside the covered control-plane operation.

## 4. Temporal — Workflow ID / Run ID

- URL: https://docs.temporal.io/workflow-execution/workflowid-runid
- Publisher: Temporal Documentation
- Accessed: 2026-09-22
- Evidence: verified
- Direct support captured: Workflow ID and Run ID identify executions; Workflow ID is visible in UI/CLI/Event History/system logs and should not contain sensitive data; one open execution per Workflow ID guarantee and Run ID uniqueness semantics are documented.
- Can prove: documented correlation/identity semantics for Workflow executions and privacy boundary for identifiers.
- Cannot prove: approval authenticity, human identity, authorization, external effect, or a complete audit chain.

## 5. LangGraph — Persistence

- URL: https://docs.langchain.com/oss/python/langgraph/persistence
- Publisher: LangChain Documentation (LangGraph)
- Accessed: 2026-09-22
- Evidence: verified
- Direct support captured: Checkpointers persist thread graph state as checkpoints for short-term/thread-scoped memory, human-in-the-loop, time travel and fault tolerance; Stores persist application-defined data outside graph state for cross-thread data; checkpointer vs store scope and access patterns are distinguished.
- Can prove: checkpoint/state persistence model and distinction between graph snapshots and application-defined Store data.
- Cannot prove: reviewer authentication/authorization; immutable or independent audit; that a checkpoint is a platform-signed approval receipt; external tool side effect or read-back; completeness/retention under an arbitrary deployment.
- Evidence note: official current docs redirected/served under docs.langchain.com; old official URL https://langchain-ai.github.io/langgraph/concepts/durable_execution/ was checked and redirected/obsolete, so current URL is cited.

## 6. LangGraph — Interrupts

- URL: https://docs.langchain.com/oss/python/langgraph/interrupts
- Publisher: LangChain Documentation (LangGraph)
- Accessed: 2026-09-22
- Evidence: verified
- Direct support captured: interrupt() pauses graph for external input; graph state is saved via persistence and waits until resume; Command(resume=...) supplies return value; same thread_id resumes same checkpoint while a new one starts a new thread; stream interrupts expose payload and interrupted status; docs list review/edit tool calls and validation patterns.
- Can prove: documented pause/resume and payload/state mechanics; that same thread_id is the recovery cursor.
- Cannot prove: approval is from an authenticated/authorized human; resume payload is untampered or non-replayed; audit trail is complete/immutable; external action succeeded; platform issues a final approval receipt.
- Notes: public example trace linked by docs is not treated as production evidence or benchmark.

## 7. OpenAI Agents SDK — Human-in-the-loop

- URL: https://openai.github.io/openai-agents-python/human_in_the_loop/
- Publisher: OpenAI Agents SDK Documentation
- Accessed: 2026-09-22
- Evidence: verified
- Direct support captured: tools declare needs_approval; run results surface pending approvals as interruptions; RunState serializes paused runs and resumes after decisions; approval surface is run-wide including handoffs/nested Agent.as_tool; serialized RunState contains execution state, decisions, pending tool calls and arguments; from_json/from_string do not authenticate snapshot or submitting person; server must authenticate reviewer, use server-owned pending items, apply approve/reject, and coordinate atomic consumption against replay/concurrency.
- Can prove: SDK approval interruption and recovery model; explicit application security requirements around snapshot ownership, reviewer auth, server-side pending state and replay protection.
- Cannot prove: that SDK itself authenticates reviewer; that RunState is an independent audit log; external tool effect; legal-grade evidence; that a client-supplied approval is valid without application controls.
- Critical boundary: this source directly warns not to accept replacement tool calls/arguments/approval records/serialized state from client.

## 8. OpenAI Agents SDK — Tracing

- URL: https://openai.github.io/openai-agents-python/tracing/
- Publisher: OpenAI Agents SDK Documentation
- Accessed: 2026-09-22
- Evidence: verified
- Direct support captured: tracing collects records of LLM generations, tool calls, handoffs, guardrails and custom events; traces/spans represent workflow operations; default BatchTraceProcessor exports in background and flush_traces() can be used for immediate delivery guarantee at unit-of-work end; tracing can be disabled and is unavailable under ZDR policy.
- Can prove: configured SDK observability trace model, included run event categories, and documented export/flush behavior.
- Cannot prove: human reviewer identity/authorization; approval authenticity; complete audit/retention; external side effect; that a trace exists if disabled, unavailable, not flushed, or export fails; production compliance.

## 9. OpenAI Agents SDK — Sessions

- URL: https://openai.github.io/openai-agents-python/sessions/
- Publisher: OpenAI Agents SDK Documentation
- Accessed: 2026-09-22
- Evidence: verified
- Direct support captured: Sessions maintain conversation history across runs; SDK offers storage backends and distinguishes session memory from server-managed continuation options.
- Can prove: conversation-history persistence abstraction and storage choices.
- Cannot prove: approval audit; reviewer identity/authorization; tool execution success; external read-back; immutability or legal retention.

## 10. OpenAI Agents SDK — RunState reference

- URL: https://openai.github.io/openai-agents-python/ref/run_state/
- Publisher: OpenAI Agents SDK Documentation
- Accessed: 2026-09-22
- Evidence: verified (reference consulted for API surface; approval/security semantics taken primarily from source 7)
- Can prove: existence/API reference of RunState-related types and operations as documented.
- Cannot prove: independent security or compliance guarantees; reviewer authentication; external effect.

## Source coverage / unknowns

- No private pages, credentials, account data, live services, production systems, benchmark result, or third-party commentary used.
- “Unknown” means not established by these official pages, not that the property can never be implemented.
- No official source in this slice establishes that any of the three platforms alone supplies an authenticated human identity, enterprise RBAC decision, independent immutable approval audit, or external read-back of a business side effect.
