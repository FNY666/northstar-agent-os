# Northstar Unified Agent Interop Plan

日期：2026-09-06
范围：仅本地 Northstar 仓库；不连接真实 Codex、Claude Code、Hermes、Cursor、OpenBot 或任何服务器

## 目标

为多个 Agent 后端建立统一的、可验证的交接边界：

```text
Host Run Authorization
  → Agent Attestation
  → Typed Handoff Request
  → Narrowed Handoff Grant
  → Backend Adapter（后续）
  → Handoff Receipt（后续）
```

本阶段只实现安全的 contract/attestation/delegation 核心，不实现真实后端调用。OpenAI Codex、Claude Code、Hermes、Cursor 和 OpenBot 先被视为未来 adapter 的不可信执行方；它们的产品身份或能力声明不能直接获得权限。

## 不变量

- `task_id/thread_id/run_id/actor_id/workspace_id/policy_revision` 在父授权、Agent Attestation、Handoff Request 和 Handoff Grant 中必须一致。
- Agent profile 的 capability 是“支持声明”，不是授权；真实授权必须来自父级已验证 grant，并且子请求能力只能是父 grant 的子集。
- Handoff 的 expiry 不得晚于父 grant/attestation expiry、request deadline 或 host 设定的 TTL。
- 每次交接必须绑定 source agent、target agent、step、input digest、expected postconditions、delegation depth 和 idempotency key。
- 未知字段、非法 ID、重复 capability、wildcard、过期、错误签名、身份串线、target 未注册、target 不支持能力、scope widening、depth widening 均拒绝。
- token 不携带 secret、prompt、原始工具输出或完整上下文；只携带必要 claims 和摘要。
- 交接 grant 只证明 host 授权的窄委托，不证明目标 Agent 已完成任务；后续必须有 adapter receipt 与独立 verifier。

## 文件计划

- Create: `components/northstar-agent-interop/interop_contract.py` — `AgentProfile`、`AgentRegistry`、`AgentAttestation`、`HandoffRequest`、`HandoffGrant` 结构与严格校验。
- Create: `components/northstar-agent-interop/handoff.py` — attestation 签名/验证、handoff grant 签名/验证、父授权收窄和 depth/expiry 检查。
- Create: `components/northstar-agent-interop/tests/test_interop_contract.py` — contract/registry/identity 测试。
- Create: `components/northstar-agent-interop/tests/test_handoff.py` — attestation、scope narrowing、expiry、tamper、depth 和 target capability 测试。
- Create: `components/northstar-agent-interop/README.md` — 后端中立边界、信任模型和当前非生产范围。
- Modify: `.github/workflows/test.yml` — 加入 interop compile/test。
- Modify: `README.md`、`CHANGELOG.md` — 只增加 local interop candidate 的准确声明。

## TDD 顺序

### Task 1：typed interop contract

先写 RED，验证 `AgentProfile`、`AgentAttestation`、`HandoffRequest` 的严格字段、canonical JSON、ID/摘要/scope/deadline/depth 约束；再实现最小标准库结构。单对象校验和跨对象身份校验分开，避免把一个对象误当成完整授权链。

### Task 2：signed attestation and narrowed handoff

先写 RED，验证：

- 父 Host Authorization + source Agent Attestation 才能产生 grant；
- parent HandoffValidation 可继续委托，但 capability 只能继续收窄；
- target 必须在 registry 中，且声明支持 requested capabilities；
- target profile 不是授权来源；
- actor/run/workspace/policy/step/input digest mismatch fail-closed；
- expiry、deadline、depth、signature、unknown field fail-closed；
- grant payload 不包含 prompt/secret/原始结果。

再实现 canonical compact JSON + base64url + HMAC-SHA256 token。验证失败不返回 claims。

### Task 3：adapter boundary（下一阶段）

在本阶段验证通过后，再为各后端定义相同的 adapter 接口：

```text
receive HandoffGrant
→ verify grant and current policy
→ translate only allowed request fields
→ execute backend-specific action
→ return typed HandoffReceipt
→ independent postcondition verification
```

第一批只做 fake adapter contract，不连接真实服务；随后分别研究 Codex、Claude Code、Hermes、Cursor、OpenBot 的实际协议和许可/登录边界。

## 本阶段验收

- 新 interop 单测先 RED 后 GREEN；
- Host 24/24、Durable Run 59/59、Sidecar 51/51、Run Contract 22/22、文档 3/3 保持通过；
- 新 interop 测试覆盖不少于 30 个行为；
- 至少证明一次 root authorization → attestation → handoff grant 和一次 nested narrowed handoff；
- 能拒绝至少 8 类越权/串线/过期/篡改输入；
- 无真实后端调用、无服务器写入、无生产部署；
- 文档明确：这是组合层安全 contract，不是已经接入任何后端，也不是完整 Agent OS。

## 当前不声称

本阶段不能声称：

- 已经能调用 Codex、Claude Code、Hermes、Cursor 或 OpenBot；
- 已经实现统一 Agent Loop；
- 已经证明跨后端任务成功率；
- 已经具备生产级身份、分布式 fencing、沙箱或团队治理；
- 已经超越任何单一 Agent 产品。
