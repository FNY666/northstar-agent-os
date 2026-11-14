# BackendRouter RouteDecision 持久化与回执计划

日期：2026-09-07
范围：仅 `/var/minis/workspace/northstar-agent-os-local-only`；公开 `main=1e5256f40356945d56ccae9ed8b6d6afbcd8f636` 保持不动

## 目标

在现有 `BackendRouter/RouteRequest/RouteDecision` 之上增加一个 local-only、append-only 的路由账本，证明：

```text
select
→ persist structured RouteDecision
→ record started/succeeded/failed/cancelled RouteReceipt
→ replay route state
→ idempotent retry/fallback
→ expose bounded failure/observability fields
```

该切片不改变当前路由选择规则，不把 RouteDecision 当作授权，不调用真实 Agent 后端。

## 不变量

- RouteDecision 是路由事实，不是授权；账本不保存 token、secret、prompt、原始错误文本或完整工具输出。
- 每条记录绑定 `route_id/task_id/thread_id/run_id/actor_id/workspace_id/policy_revision/step_id/trace_id`；串线、目标变化、provider/version 变化均拒绝。
- RouteDecision 记录必须保存 canonical decision digest、attempt、idempotency key 和 recorded_at。
- RouteReceipt 必须保存结构化 status、attempt、latency、failure_class、error_code、retryable、provider/version 和 decision digest；不得保存 raw error。
- append-only JSONL 是真源；sequence 连续；损坏、乱序、未知字段和 digest 不匹配 fail-closed。
- 同一 `event_type + idempotency_key` 加入完全相同事件时返回原事件；同 key 不同内容或不同 route/step 时拒绝，不能静默覆盖。
- receipt 只能引用已经持久化的 decision；receipt 的身份、target、policy、digest、provider/version 必须与 decision 一致。
- 状态必须合法：`selected → started → succeeded|failed|cancelled`；失败后只能以更高 attempt 重新 `started`，terminal receipt 不得回到旧 attempt 或重复执行。
- 失败分类是有限枚举，不接受任意模型/后端文本；`error_code` 只允许短、受限、无秘密的标识符。
- replay 只从事件历史重建，不信任缓存或最后一条 receipt；重复 replay 必须得到同一结构化状态。

## 计划文件

- Create: `components/northstar-agent-interop/route_ledger.py` — `RouteDecisionRecord`、`RouteReceipt`、`RouteEvent`、`RouteReplay`、`RouteLedger`、失败分类和幂等 append。
- Create: `components/northstar-agent-interop/tests/test_route_ledger.py` — 持久化、回放、幂等、状态机、失败分类和可观测字段测试。
- Modify: `components/northstar-agent-interop/README.md` — 记录 local-only route ledger 边界。
- 不修改公开 checkout；不修改现有 `backend_router.py` 选择逻辑；不添加真实后端配置。

## TDD 顺序

### Task 1：先写 RED

测试必须先导入不存在的 `route_ledger.py` 并正确 RED，覆盖：

1. `RouteDecisionRecord` canonical round-trip、decision digest 和严格未知字段；
2. `RouteReceipt` 的状态、失败枚举、attempt、latency、retryable、error_code 和无 raw error；
3. decision → started → succeeded 的 append/read/replay；
4. failed attempt → higher-attempt retry → succeeded 的合法回放；
5. 相同 event/idempotency key 重放返回原事件；同 key 不同内容拒绝；
6. 乱序 sequence、损坏 JSONL、跨 run/route/step、错误 decision digest 拒绝；
7. terminal 后非法 started/旧 attempt/重复成功拒绝；
8. failure classification 的 retryable 和 bounded error_code；
9. replay 输出 last status、current attempt、selected target、failure counts、latency 汇总等可观测字段；
10. 账本不包含 prompt、secret、token、raw error。

### Task 2：最小实现并 GREEN

1. `RouteDecisionRecord.from_decision(decision, idempotency_key, attempt, persisted_at)` 将现有 immutable `RouteDecision` 包装为严格记录，digest 为 canonical decision 的 SHA-256；
2. `RouteReceipt` 使用严格 schema `northstar.route-receipt.v1`，状态和失败字段 fail-closed；成功 receipt 不带 failure，失败 receipt 必须有枚举 failure_class 和 bounded error_code；
3. `RouteEvent` 使用严格 schema `northstar.route-event.v1`，包含 sequence、event_type、route_id、run_id、idempotency_key、payload_digest 和 typed payload；
4. `RouteLedger` 用 append-only JSONL + fsync 写入；初始化不创建真实后端或网络副作用；
5. `append_decision()` 和 `append_receipt()` 强制 identity/digest/provider/version 检查；相同幂等事件返回既有事件，冲突拒绝；
6. `replay()` 严格按 sequence、decision/receipt 状态转移和 attempt 重建 `RouteReplay`，不读取未验证缓存；
7. 错误只输出有限类别和 error code，不持久化异常文本；
8. 所有 API 只处理结构化对象，不接受 prompt 或任意命令。

### Task 3：独立验证

运行：

```sh
cd /var/minis/workspace/northstar-agent-os-local-only
python3 -m py_compile components/northstar-agent-interop/*.py components/northstar-agent-interop/tests/*.py
PYTHONPATH=components/northstar-agent-interop:components/northstar-host:components/northstar-run-contract \\
  python3 -m unittest discover -s components/northstar-agent-interop/tests -p 'test_*.py' -v
```

随后执行完整 Interop 回归、`git diff --check`、敏感信息扫描；确认公开 checkout 状态未发生变化。

## 验收门槛

- 新增 Route Ledger 测试先 RED 后 GREEN；
- local-only Interop 测试从当前 63/63 增加并全部通过；
- decision、receipt、event、replay 的字段严格且无 raw prompt/secret/token/error；
- 正常选择/启动/成功链可回放；失败重试和 fallback attempt 可回放；
- 重复事件无重复写入，幂等冲突拒绝；
- 非法状态转移、跨身份、过期/旧 digest、损坏历史 fail-closed；
- failure_class、error_code、retryable、latency、attempt、provider/version、trace_id 可被独立读取；
- 不安装、登录、执行 Codex/Claude Code/Hermes/Cursor/OpenBot；不操作 103、104、宿舍或公开 checkout；
- 完成后只创建 local-only commit，并提供 commit、patch 和审查材料；不公开下放 BackendRouter。

## 当前代际定位

`1e5a6a1` 的 BackendRouter 已是 local-only 路由选择代际；本计划是在其上继续构建 Route Ledger/Receipt 代际，仍不等于真实后端质量证明，也不代表公开仓库应立即合并。
