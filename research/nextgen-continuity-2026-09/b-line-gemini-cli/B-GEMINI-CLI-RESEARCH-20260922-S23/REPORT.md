# S23：同 attempt 重复 response/durable 记录（离线 synthetic-only）

- `synthetic_only=true`
- `production_verified=false`
- 独立切片目录：`/tmp/B-GEMINI-CLI-RESEARCH-20260922-S23/`
- 运行日期：2026-09-22（Asia/Shanghai）

## 1. 边界与方法

本切片只执行一个确定性、本地 Python harness：单 worker、每个 fixture 一个 `op_id`、同一 `attempt=1`。输入由 `fixtures/cases.json` 提供，结果写入 `outputs/results.json`。没有网络、真实 Gemini CLI、真实服务、凭据、远端状态或其他研究目录输入。

局部判定规则（**仅为本 synthetic harness 的规则**）：

1. 同一 record kind、同一 attempt 下，相同值重复到达 → `accepted`；
2. 同一 record kind 下不同值 → `rejected`，理由为 `different_value_conflict`；
3. response 与 durable 的引用相同时 → `accepted`；引用不同时 → `rejected`，理由为 `response_durable_reference_mismatch`；
4. 若记录标记为 crash/restart/resume 且先前状态是 `UNKNOWN`，无论重复值是否相同，保持 `UNKNOWN`。

这些是可复现的本地分类规则，不是 Gemini CLI、生产系统、服务端状态机或存储系统的观察结果。

## 2. 确定性 fixture 结果

| fixture | 场景 | 结果 | 证据标签 | 说明 |
|---|---|---:|---|---|
| S23-01 | 单个 response 值 | accepted | confirmed | 基线单记录 |
| S23-02 | response 相同值重复 | accepted | confirmed | `response:ok` → `response:ok` |
| S23-03 | response 不同值冲突 | rejected | confirmed / conflicting | `ok` 与 `other` |
| S23-04 | durable 相同引用重复 | accepted | confirmed | `durable:ref-A` 重复 |
| S23-05 | durable 不同引用冲突 | rejected | confirmed / conflicting | `ref-A` 与 `ref-B` |
| S23-06 | response/durable 引用不一致 | rejected | confirmed / conflicting | `ref-A` 与 `ref-B` |
| S23-07 | response/durable 引用一致 | accepted | confirmed | 两者均为 `ref-A` |
| S23-08 | restart/resume 后 response 相同值重复，先前 UNKNOWN | UNKNOWN | confirmed | 未降级为 applied/not_applied |
| S23-09 | restart/resume 后 durable 相同引用重复，先前 UNKNOWN | UNKNOWN | confirmed | 未降级为 applied/not_applied |
| S23-10 | restart/resume 后 response 不同值，先前 UNKNOWN | UNKNOWN | confirmed | UNKNOWN 优先保持；不作终态推断 |

`confirmed` 仅表示结果由本地确定性 harness 直接产生。标为 `conflicting` 的行表示 fixture 内的两个值/引用相互冲突，不表示外部研究来源冲突。

## 3. 统计

共 10 个 fixture：

- **accepted：4**（S23-01、S23-02、S23-04、S23-07）
- **rejected：3**（S23-03、S23-05、S23-06）
- **UNKNOWN：3**（S23-08、S23-09、S23-10）

残留 UNKNOWN：**S23-08、S23-09、S23-10**。这三个状态是预期保留的未知，不是 harness 失败，也未被本地重复记录降级为 `applied` 或 `not_applied`。

## 4. 证据分级与限制

- **confirmed**：10 个 fixture 的上述分类、统计数字，以及 UNKNOWN 保持规则，均可由本目录 `harness.py` + `fixtures/cases.json` + `outputs/results.json` 直接复跑/核对。
- **inferred**：在该局部规则下，可推断“相同值重复不会新增冲突、不同值会显式冲突、UNKNOWN 标记优先保持”。这只是模型/规则层面的窄推断。
- **unverified**：未验证不同 attempt、不同 op_id、空值/序列化差异、记录顺序敏感性、部分写入、并发、时钟、磁盘故障、真实恢复流程，也未证明规则对更大输入集合成立。
- **conflicting**：S23-03、S23-05、S23-06 是 synthetic 输入中的不同值/不同引用冲突；它们不是生产冲突证据。
- **inaccessible**：真实 Gemini CLI、真实服务、远端状态、生产存储/durability、凭据以及被明确排除的既有目录均不可访问且未访问。

明确不作以下结论：不能把本 harness 外推为 Gemini CLI 行为、生产行为、远端状态、exactly-once、回滚、crash durability，或任何服务端持久化保证。response/durable 一致只说明字符串引用比较规则通过；并不等于实际 durable commit 成功。

## 5. 可复现与校验

已运行：

```text
cd /tmp/B-GEMINI-CLI-RESEARCH-20260922-S23 && python3 harness.py
统计输出：{"accepted": 4, "rejected": 3, "UNKNOWN": 3}
```

随后运行研究清单校验：

```text
python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py /tmp/B-GEMINI-CLI-RESEARCH-20260922-S23/research-manifest.json
PASS: 8 claims; manifest schema is valid (2026-09-22)
```

随后在目录内运行完整性校验：

```text
(cd /tmp/B-GEMINI-CLI-RESEARCH-20260922-S23 && sha256sum -c SHA256SUMS)
```

以上命令的成功输出与当前文件摘要见 `SHA256SUMS`；`outputs/results.json` 是 harness 的完整机器可读输出。

## 6. 下一独立切片建议（不停线）

建议下一切片继续保持 `synthetic_only=true`、`production_verified=false`，只增加一个正交变量：**同一 worker、同一 op_id 下跨 attempt 的重复到达与 attempt 边界**（包括 attempt=1/2 的相同值、不同值、response/durable 引用一致/不一致，以及 UNKNOWN 在 attempt 边界的保持）。仍排除多 worker、穷举、dedup-key 碰撞、人工 reconcile、真实 CLI/服务/凭据，并单独报告 accepted/rejected/UNKNOWN。不要将 S23 的局部规则外推成生产语义。
