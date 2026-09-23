# B 线 Gemini CLI S20：离线 synthetic 故障注入矩阵报告

- `synthetic_only=true`
- `production_verified=false`
- 研究目录：`/tmp/B-GEMINI-CLI-RESEARCH-20260922-S20/`
- 研究性质：判定器/协议规则测试，不是 Gemini CLI、远端服务或生产环境验证。
- 时间：2026-09-22

## 1. 结论

在完全离线的本地 fixture 中，只有 fixture 明确给出的事实可以判定：`not_sent` 可判为 `NOT_DISPATCHED`；显式工具错误可判为 `TOOL_ERROR`；fixture 显式去重可判为 `DEDUPED_IN_FIXTURE`；fixture 显式成功且不跨越未持久化结果边界可判为 `SUCCESS_IN_FIXTURE`。一旦已经记录 `sent`，但响应缺失、丢失、畸形，或者响应存在但结果持久化提交尚未观察到，必须保守保持 `UNKNOWN`。

这不证明 Gemini CLI 的任何实际行为，不证明 exactly-once、幂等、远端副作用回滚、真实 crash/power-loss durability、跨重启恢复能力或生产安全。

## 2. 设计与边界

输入为 `cases.json`，共 16 个 case；`harness.py` 是纯 Python、无网络、无外部依赖的确定性判定器。每个输出含 `synthetic_only=true`、`production_verified=false`。协议说明、不变量与限制见 `README-fixture.md`。

故障维度覆盖：

- clean success
- restart：journal 前、journal 后
- crash：dispatch 后、response 后、恢复 retry 中
- power loss：journal 前、dispatch 后
- network down：dispatch 前、response 丢失
- tool response：missing、malformed、duplicate、explicit error
- recovery retry：无 dedupe、fixture dedupe

## 3. 矩阵结果

| Case | 故障/边界 | Fixture 判定 | 判定理由 |
|---|---|---|---|
| S20-01 | clean / response 后、result commit 前 | NOT_DISPATCHED | fixture dispatch 未发送（规则优先级） |
| S20-02 | restart / journal 前 | NOT_DISPATCHED | 未记录 outbound dispatch |
| S20-03 | restart / journal 后、dispatch 前 | NOT_DISPATCHED | 未记录 outbound dispatch |
| S20-04 | crash / dispatch 后、response 前 | UNKNOWN | 已发送但无权威响应/结果 |
| S20-05 | crash / response 后、result commit 前 | UNKNOWN | 有响应但未观察到 durable result commit |
| S20-06 | power loss / journal 前 | NOT_DISPATCHED | 未记录 outbound dispatch |
| S20-07 | power loss / dispatch 后 | UNKNOWN | 已发送但无权威响应/结果 |
| S20-08 | network down / dispatch 前 | NOT_DISPATCHED | 未记录 outbound dispatch |
| S20-09 | network down / response 丢失 | UNKNOWN | 已发送但响应不可用 |
| S20-10 | tool response missing | UNKNOWN | 已发送但响应不可用 |
| S20-11 | retry / no dedupe | UNKNOWN | 重试前一发送结果仍不可知，不能推断远端未执行 |
| S20-12 | retry / fixture dedupe | UNKNOWN | 当前规则先按 sent + lost 保留未知；dedupe 不制造权威成功 |
| S20-13 | tool error then retry | TOOL_ERROR | fixture 明确提供 tool error |
| S20-14 | duplicate response | DEDUPED_IN_FIXTURE | fixture dedupe 规则抑制重复响应 |
| S20-15 | malformed response | UNKNOWN | 已发送但无权威可用响应 |
| S20-16 | crash during retry | UNKNOWN | 已发送、响应丢失，恢复中断 |

**统计：**总计 16；`NOT_DISPATCHED` 5；`UNKNOWN` 9；`TOOL_ERROR` 1；`DEDUPED_IN_FIXTURE` 1；`SUCCESS_IN_FIXTURE` 0。`UNKNOWN` 残留为 9/16（56.25%）。

注意：S20-01 的输入名是 clean-success，但其 fixture 同时写入 `dispatch=not_sent`，按照 harness 明确的规则顺序，结果为 `NOT_DISPATCHED`；这验证了输入一致性/优先级暴露，而不是模拟真实成功路径。

## 4. 本地可确定 vs 必须 UNKNOWN

### 可由 fixture 确定

1. 本地输入明确 `dispatch=not_sent` → `NOT_DISPATCHED`。
2. 本地输入明确 `response=error` 且命中显式 tool-error 规则 → `TOOL_ERROR`。
3. 本地输入显式 `duplicate_response` 且 `tool_dedup=true` → `DEDUPED_IN_FIXTURE`。
4. 只有在本地规则明确提供 success 且没有未提交 durability 边界时，才可标注 `SUCCESS_IN_FIXTURE`；这仍只代表 fixture。

### 必须保持 UNKNOWN

1. `sent` 后没有响应。
2. `sent` 后网络中断导致响应丢失。
3. 响应畸形或不可验证。
4. 响应出现，但 durable result commit 尚未观察到。
5. 崩溃/断电发生在 dispatch 后而权威结果不可用。
6. 任何恢复重试，其中原始 dispatch 的远端执行状态未知；fixture dedupe 也不等同真实幂等。

根本原因：本地观察不到远端执行与权威提交之间的不可见窗口。将这些状态硬判成功或失败会把未知外推成 Gemini CLI/远端能力。

## 5. 不变量与复现

执行：

```sh
cd /tmp/B-GEMINI-CLI-RESEARCH-20260922-S20
python3 harness.py
sha256sum -c SHA256SUMS
python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
```

已验证不变量：

- 所有 16 个结果均含 `synthetic_only=true`、`production_verified=false`。
- 缺少权威 response/result 的 dispatched case 不被改写为成功或失败。
- 不声明 exactly-once、回滚、crash durability 或生产安全。
- 同一输入重复运行是确定性的。
- SHA256 文件校验通过。

## 6. 官方背景与证据状态

仅使用公开官方资料作为背景，详见 `sources.md`：Gemini CLI 官方 GitHub README、官方文档首页、Google Gemini API function-calling 文档、Google Gemini API troubleshooting 文档。它们不是本地 harness 的运行证据，也没有被用于声称 Gemini CLI 的恢复、重试、持久化或远端副作用语义。

`research-manifest.json` 逐条标记 `confirmed/inferred/unverified/conflicting/inaccessible`：

- `confirmed`：本地 harness 的确定性规则/范围声明（confirmed 仅限合成判定器），以及官方页面作为背景且不支持生产语义的边界。
- `inferred`：`not_sent`、缺失权威响应保持 UNKNOWN、fixture dedupe 的协议推论。
- `unverified`：真实 Gemini CLI 生产故障行为。
- `conflicting`：来源没有讨论本协议，因此无法建立来源层面的同意或冲突；该状态保留以避免伪造一致性。
- `inaccessible`：真实远端副作用、断电/crash durability、凭据与生产环境均未访问。

## 7. 产物

- `cases.json`：16 条 synthetic 输入。
- `harness.py`：可复现本地判定器。
- `outputs.json`：结构化输出。
- `outputs.txt`：逐 case 输出及统计。
- `README-fixture.md`：fixture 协议与不变量。
- `sources.md`：官方背景来源及证据边界。
- `research-manifest.json`：逐条状态 manifest。
- `SHA256SUMS`：产物哈希。
- `REPORT.md`：本报告。

所有报告与 fixture 显式标注 `synthetic_only=true`、`production_verified=false`；不得将合成通过外推为 Gemini CLI 或远端系统能力。

## 8. 完成时验证输出

`python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json`：

```text
PASS: 8 claims; manifest schema is valid (2026-09-22)
```

`(cd /tmp/B-GEMINI-CLI-RESEARCH-20260922-S20 && sha256sum -c SHA256SUMS)`：

```text
cases.json: OK
harness.py: OK
README-fixture.md: OK
outputs.json: OK
outputs.txt: OK
```

运行 harness 的统计输出：

```text
CASE_COUNT 16
UNKNOWN_COUNT 9
INVARIANT_SYNTHETIC_FLAGS True
INVARIANT_NO_EXACTLY_ONCE_CLAIM True
```

## 下一独立切片建议

**S21：离线 journal/recovery 状态机模型检查。** 保持 `synthetic_only=true`、`production_verified=false`，不接触 Gemini CLI、真实服务或既有研究产物；将本 S20 的 16 类边界扩展为显式状态机，使用模型检查/性质测试验证“sent 且无权威结果 ⇒ UNKNOWN”“fixture dedupe 不产生 exactly-once 结论”“恢复重试不覆盖未决原始 dispatch”的不变量，并加入输入矛盾检测（例如 case 名称与 dispatch 字段冲突）及故障序列组合。输出仍必须把所有生产语义标为 `unverified` 或 `inaccessible`。
