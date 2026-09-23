# S21 Journal / Recovery 状态机研究

- `synthetic_only=true`
- `production_verified=false`
- 研究目录：`/tmp/B-GEMINI-CLI-RESEARCH-20260922-S21/`
- 运行边界：完全离线；只执行本报告目录内的 Python harness 与 JSON fixtures。
- 明确未读取：S1–S20、其他本地研究产物、`shared/P0`、事故目录、D10、L12、D14、canonical、staging、140、tri-line、systemd、真实服务、凭据。

## 1. 问题与模型边界

模型把一次工具操作表示为 `(op_id, attempt)`，并回放以下事件：

`dispatch_intent → tool_response → durable_result → crash/restart → resume → retry → dedup → manual_reconcile`。

状态被有意拆成三层：

1. **本地 journal 事实**：intent、response、durable result 是否被模型记录。
2. **进程生命周期**：crash、restart、resume；restart 后只可恢复 durable 的本地记录。
3. **远端效果命题**：`applied / not_applied / unknown`。除显式人工 reconcile 外，模型不把本地记录推断成远端完成。

`UNKNOWN` 是安全的非终态：它表示本地不能证明远端效果，尤其包括 dispatch 后 crash、response 后尚未形成 durable result、以及 retry 前无法判断首个 attempt 是否已产生远端副作用。

## 2. 协议不变量

- **I1 关联完整性**：tool response 必须有同一 `(op_id, attempt)` 的 dispatch intent。
- **I2 durable 引用一致性**：durable result 必须有对应 response，且 `response_id` 一致；同一 attempt 的 result 不得改写。
- **I3 intent 稳定性**：同一 operation/attempt 的 intent hash 不得冲突。
- **I4 crash 不确定性**：crash 不产生“未应用”或“已应用”结论；恢复后未有 durable result 时保持 UNKNOWN。
- **I5 本地—远端隔离**：dispatch、tool response、durable result、restart/resume 均不单独证明远端副作用已完成。
- **I6 retry 安全闸门**：前一 attempt UNKNOWN 时，没有 dedup key 的 retry 被拒绝；有 key 也只能进入 dedup/reconcile 检查，不能宣称 exactly-once。
- **I7 dedup 前提**：dedup assertion 必须指向已存在的 canonical attempt；`same_result` 不是远端 exactly-once 证明。
- **I8 reconcile 单调一致**：人工 reconcile 是唯一能把远端状态作为显式输入带入模型的通道；互相矛盾的人工结论被拒绝。
- **I9 未知事件拒绝**：不认识的事件类型、非法 effect/status、孤立记录均拒绝。

## 3. 可复现运行方式

```sh
cd /tmp/B-GEMINI-CLI-RESEARCH-20260922-S21
python3 harness.py
python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
(cd /tmp/B-GEMINI-CLI-RESEARCH-20260922-S21 && sha256sum -c SHA256SUMS)
```

harness 和 fixtures 都在本目录：

- `harness.py`：确定性回放器与不变量判定器
- `fixtures/cases.json`：12 个 synthetic cases
- `outputs/results.json`：逐 case 判定、违规/矛盾、残留 UNKNOWN、统计

## 4. 验证输出与统计

实际运行 `python3 harness.py` 的 stdout：

```text
{"by_result": {"CONTRADICTION_REJECTED": 6, "PASS": 5, "UNSAFE_REJECTED": 1}, "failed": 0, "pass": 12, "total": 12}
RESIDUAL_UNKNOWN=["C02-crash-before-response", "C03-retry-with-dedup", "C04-manual-reconcile", "C08-retry-without-dedup", "C10-applied-response-not-proof"]
```

统计解释：

| 结果 | 数量 | 含义 |
|---|---:|---|
| PASS | 5 | 允许该输入序列；其中部分明确保留 UNKNOWN |
| CONTRADICTION_REJECTED | 6 | 结构或事实矛盾，被判定器拒绝 |
| UNSAFE_REJECTED | 1 | 结构未必矛盾，但 UNKNOWN 下无 dedup 的 retry 不安全 |
| 总计 | 12 | 12/12 的 fixture 期望与实际相符 |

逐 case：

- C01：完整本地 durable 流程通过；仍不把 journal 当远端证明。
- C02：dispatch 后 crash/restart/resume，保留 UNKNOWN。
- C03：UNKNOWN 后带 dedup key retry；通过模型门槛，但不能证明 exactly-once。
- C04：只有显式人工 `not_applied` 才输入远端结论；通过。
- C05：无 intent 的 response，矛盾拒绝。
- C06：同 attempt 两个不兼容 response，矛盾拒绝。
- C07：durable 引用错误 response，矛盾拒绝。
- C08：UNKNOWN 下无 dedup retry，安全拒绝。
- C09：同 attempt intent hash 冲突，矛盾拒绝。
- C10：`applied` response 之后 crash 且没有 durable；仍保留 UNKNOWN，防止本地推断远端完成。
- C11：dedup 指向不存在的 canonical attempt，矛盾拒绝。
- C12：人工 reconcile 从 applied 改 not_applied，矛盾拒绝。

残留 UNKNOWN 共 5 个 case（C02、C03、C04、C08、C10）；这是预期的安全结果，不是 harness 失败。C08 同时是 `UNSAFE_REJECTED`，表明拒绝动作并不会消除未知事实。

## 5. 逐条证据状态

状态枚举严格使用：`confirmed / inferred / unverified / conflicting / inaccessible`。

| ID | 命题 | 状态 | 说明 |
|---|---|---|---|
| E1 | 本目录 harness 在离线 fixtures 上执行上述 12 个 case，12/12 期望匹配 | confirmed | 可由本目录脚本、fixtures、outputs 重跑确认 |
| E2 | response 无 intent、durable 错引用、intent hash 冲突会被判为矛盾 | confirmed | C05/C07/C09 的模型输出 |
| E3 | UNKNOWN 下无 dedup key 的 retry 被拒绝 | confirmed | C08 的模型输出 |
| E4 | local journal/durable result 不足以证明 remote side effect | inferred | 这是模型定义的保守协议不变量，不是生产观测 |
| E5 | 显式 manual reconcile 可作为远端状态输入，但矛盾 reconcile 被拒绝 | confirmed | C04/C12 的 synthetic replay |
| E6 | 带 dedup key 的 retry 能保证 exactly-once | unverified | harness 仅验证进入 dedup 门槛，不验证远端执行语义 |
| E7 | Gemini CLI 真实 crash durability / journal fsync 语义 | inaccessible | 本切片禁止读取真实实现、真实服务与既有研究 |
| E8 | Gemini CLI 真实远端状态、exactly-once、远端回滚能力 | inaccessible | 未访问网络、凭据、远端服务；不能从 synthetic 结果推出 |
| E9 | 生产安全性、真实重启时序与跨进程竞态 | unverified | 没有运行生产组件或故障注入 |
| E10 | 任意真实输入均满足这些不变量 | conflicting | 只能说模型拒绝所定义的矛盾；不能把模型约束冒充真实协议事实 |

## 6. 必须保留的否定结论

本 synthetic 模型**不能证明**：Gemini CLI 的真实 crash durability、真实远端状态、exactly-once、远端回滚、生产安全，或任何具体版本的实现承诺。特别是：

- `dispatch_intent` 只证明模型记录了意图；不证明请求到达远端。
- `tool_response` 只证明模型观察到响应；不证明远端提交、持久化或没有重复副作用。
- `durable_result` 只证明本地结果被模型视为可恢复；不证明远端状态。
- dedup key 是输入字段，不是远端幂等执行的证据。
- 人工 reconcile 是显式外部断言；它不是 journal 自动推断，也不等于可审计的生产证明。
- `UNKNOWN` 不应被压扁为 success、failure 或 not_applied。

## 7. 下一独立切片建议

**S22：synthetic adversarial scheduler slice**。继续完全离线、synthetic-only，扩展为多 worker/多进程交错调度（同一 op 的重复 dispatch、response/durable 写入重排、双 restart、并发 retry、dedup key 碰撞、人工 reconcile 与自动 resume 竞争），以状态空间搜索检查线性化点、journal 原子性假设和“UNKNOWN 不被覆盖”为何时失效。仍需明确不得宣称 Gemini CLI 生产 crash durability、远端 exactly-once 或生产安全；输出沿用本切片的 manifest、sources、SHA256SUMS 与可复现验证命令。
