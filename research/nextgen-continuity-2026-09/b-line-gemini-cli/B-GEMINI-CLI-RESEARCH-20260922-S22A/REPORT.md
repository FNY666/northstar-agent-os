# S22-A — 双 worker 事件重排（synthetic-only）

- `synthetic_only=true`
- `production_verified=false`
- 研究目录：`/tmp/B-GEMINI-CLI-RESEARCH-20260922-S22A/`
- 运行日期：2026-09-22
- 模型：单进程、确定性、双 worker 标签（W1/W2），不是多进程；每个 fixture 只含一个 `op_id`。

## 边界与禁止外推

本切片只建模同一 `op_id` 下的 `dispatch_intent`、`tool_response`、`durable_result`、`crash`、`restart`、`resume` 的交错到达。事件通过 `order` 排序；worker 标签只表示事件作者，不启动 OS worker。没有网络、真实 CLI、远端服务、生产凭据、人工 reconcile、状态空间穷举、dedup key 碰撞或旧研究目录读取。

本模型的 `remote_effect` 初值且唯一输出为 `UNKNOWN`。本地 accepted/rejected、crash、restart、resume、response 或 durable 记录均不把它改成 `applied` 或 `not_applied`。这只验证模型规则，不验证 Gemini CLI、生产系统、远端状态、exactly-once、回滚或 crash durability。

## 三项不变量

1. **无 matching intent 的 response/durable 必须拒绝。** matching 指在该事件到达处理前，已有同 `op_id`、同 `attempt` 的 `dispatch_intent`。
2. **同 attempt 相互冲突的 response/durable 必须拒绝。** 同一 `(op_id, attempt)` 的首个值可记录；后续不同值拒绝；相同值可接受。
3. **crash/restart/resume 及任意本地记录不得将远端效果从 UNKNOWN 自动降级为 applied/not_applied。** 本模型从不输出这两种远端结论。

## 运行结果

命令：`python3 harness.py`

```json
{"case_count": 10, "fixture_pass_count": 10, "fixture_fail_count": 0, "decision_counts": {"accepted": 25, "rejected": 6, "UNKNOWN": 10}}
```

- fixture：10
- fixture PASS：10
- fixture FAIL：0
- accepted 本地事件决策：25
- rejected 本地事件决策：6
- `UNKNOWN`：10 个 fixture 的 `remote_effect` 均为 UNKNOWN；这是模型未分类，不是远端观测。
- 不变量结果：10/10 fixture 均满足三项。

## 逐 case 结果

| case | 交错摘要 | accepted | rejected（原因） | remote_effect | 状态 |
|---|---|---:|---|---|---|
| C01-no-intent-response | 无 intent → response | 0 | e1: `no_matching_intent` | UNKNOWN | PASS |
| C02-no-intent-durable | 无 intent → durable | 0 | e1: `no_matching_intent` | UNKNOWN | PASS |
| C03-response-before-intent | response → intent | e2 | e1: `no_matching_intent` | UNKNOWN | PASS |
| C04-matching-same-value | intent → response(ok) → durable(ok) | e1,e2,e3 | 无 | UNKNOWN | PASS |
| C05-response-durable-conflict | intent → response(ok) → durable(error) | e1,e2 | e3: `conflicting_same_attempt_record` | UNKNOWN | PASS |
| C06-durable-response-conflict | intent → durable(error) → response(ok) | e1,e2 | e3: `conflicting_same_attempt_record` | UNKNOWN | PASS |
| C07-crash-restart-resume | intent → crash → restart → resume → response | e1,e2,e3,e4,e5 | 无 | UNKNOWN | PASS |
| C08-crash-before-durable | intent(attempt 2) → crash → restart → resume → durable | e1,e2,e3,e4,e5 | 无 | UNKNOWN | PASS |
| C09-cross-attempts | intent(1), intent(2), response(2), durable(1) | e1,e2,e3,e4 | 无 | UNKNOWN | PASS |
| C10-resume-without-intent | crash → restart → resume → response | e1,e2,e3 | e4: `no_matching_intent` | UNKNOWN | PASS |

## 证据状态逐条标注

状态含义遵循研究 manifest 的枚举；下面的“确认”仅限本地 synthetic harness，不是生产或 Gemini CLI 证据。

1. **[confirmed]** 10 个确定性 fixture 在本地 harness 中为 PASS，决策计数为 accepted=25、rejected=6、UNKNOWN=10。证据：本目录 `outputs/results.json` 与运行输出。限定：仅模型执行结果。
2. **[confirmed]** C01、C02、C03、C10 中无 matching intent 的 response/durable 被拒绝，原因均为 `no_matching_intent`。证据：本目录 fixture 与 results。限定：仅事件到达顺序规则。
3. **[confirmed]** C05、C06 中同 attempt 的不同 response/durable 值被拒绝，原因为 `conflicting_same_attempt_record`。证据：本目录 fixture 与 results。限定：仅模型冲突判定。
4. **[confirmed]** 10 个 fixture 的 `remote_effect` 均保持 `UNKNOWN`，包括 crash/restart/resume 和本地 accepted 记录。证据：本目录 results。限定：UNKNOWN 是模型保守输出，不是远端状态。
5. **[inferred]** 在此模型中，按到达时序拒绝 response 后，稍后到达的 intent 不会追溯接受该 response。依据：C03 的确定性顺序与 harness 的在线处理逻辑。不是通用分布式系统定理。
6. **[unverified]** 该模型是否等价于 Gemini CLI 的实现、协议或生产部署行为：未验证，且本切片明确不作该外推。
7. **[conflicting]** “任意本地 accepted durable/response 记录即可证明远端已 applied”与本切片的保守模型相冲突；模型明确保持 UNKNOWN。该冲突是命题与模型规则的冲突，不是生产现场冲突证据。
8. **[inaccessible]** 真实远端效果、真实 crash durability、exactly-once、回滚能力及生产日志：本切片不访问，因而不可访问/不可评估。

## 校验命令与路径

已运行：

```text
python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py /tmp/B-GEMINI-CLI-RESEARCH-20260922-S22A/research-manifest.json
(cd /tmp/B-GEMINI-CLI-RESEARCH-20260922-S22A && sha256sum -c SHA256SUMS)
```

预期并已获得：manifest PASS；SHA256SUMS 全部 OK。完整机器可读结果见：

- `/tmp/B-GEMINI-CLI-RESEARCH-20260922-S22A/REPORT.md`
- `/tmp/B-GEMINI-CLI-RESEARCH-20260922-S22A/sources.md`
- `/tmp/B-GEMINI-CLI-RESEARCH-20260922-S22A/research-manifest.json`
- `/tmp/B-GEMINI-CLI-RESEARCH-20260922-S22A/SHA256SUMS`
- `/tmp/B-GEMINI-CLI-RESEARCH-20260922-S22A/harness.py`
- `/tmp/B-GEMINI-CLI-RESEARCH-20260922-S22A/fixtures/cases.json`
- `/tmp/B-GEMINI-CLI-RESEARCH-20260922-S22A/outputs/results.json`

## 残留 UNKNOWN

残留 10 个 fixture-level `remote_effect=UNKNOWN`，无任何 `applied` 或 `not_applied` 输出。它们是有意保留的安全不确定性，不能被本报告解释为远端成功、远端失败或已回滚。

## 下一独立切片建议（不停止研究）

下一切片可独立研究“单 worker、单 op_id、同 attempt 的相同值重复到达”这一窄模型，仍 synthetic-only；仅比较重复 response/durable 的本地记录规则与 UNKNOWN 保持规则，不引入生产、真实 CLI、远端查询、dedup key 碰撞或跨 op_id 组合。
