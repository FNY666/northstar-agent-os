# NextGen Continuity Research — 2026-09 Snapshot

离线合成（synthetic-only）研究产物快照，来自三条并行研究会话（"新线A/B/C"）在 `/tmp` 下的临时工作目录。`/tmp` 在应用进程重启时会被清空，此次推送是为了把这批内容持久化，供后续（含更高能力模型）读取分析。

## 重要限制（全部适用）

- **synthetic_only = true**：所有 case 均为本地构造的确定性 fixtures，不是真实系统的运行日志或生产数据。
- **production_verified = false**：任何目录都不能证明真实生产系统的耐久性、exactly-once、回滚安全性或外部效果真实性。
- 所有 claims 的 `status` 均为 `inferred`，`sources` 均为 `[]`（C 线）或已在各自 `sources.md` 中列出访问日期与 URL（A/B 线部分切片引用了官方文档）。
- 这是排列组合式的性质测试（property-based fail-closed 状态机验证），不是对某个真实产品的审计结论。

## 三线内容与验证级别声明

### `c-line-trust-continuity/`（S2–S66，共 65 个切片；S67 因产物不完整未收录）

主题：跨系统信任连续性、证据窗口、观察者 quorum、撤销水位、幂等、关联键与冲突隔离等。

**验证级别分三段，请勿混同：**

- **S22–S31**：本会话在生成时逐个独立复验——重新运行 `harness.py`（两轮，`cmp` 字节比较）、`validator.py`、`manifest_validator.py`、官方 `validate_research.py`、`sha256sum -c SHA256SUMS`，全部通过后才生成下一片。
- **S2–S21**：同一研究线更早期产出，未在本会话中重新复验，按各自目录内 `SHA256SUMS` 与 `research-manifest.json` 自证。
- **S32–S66**：由另一条并行会话（"新线C"独立会话）在本会话与该会话协调 S32 命名冲突、随后退出协调期间生成，**本次推送前未经本会话验证**（既未重跑 harness，也未核对 SHA256），仅按其自身目录产物直接收录。这批数量最多，风险也最高，若要引用其结论前应先独立复验。S67 因缺少 `REPORT.md`/`SHA256SUMS`/`research-manifest.json`/`sources.md`（可能是生成中途被中断），未收录进本次推送。

### `a-line-evidence-window/`

主题：审计时间窗、恢复证据、reconciliation、幂等、backpressure、outbox 等，多数引用了 Temporal/AWS/Kubernetes/GitHub Actions/Stripe 等官方文档。

**验证级别：未在本次推送会话中复验**，直接来自其他并行会话（新线A）留在 `/tmp` 的产物，按各自目录内的 `manifest`/`SHA256SUMS` 自证，未经本会话独立重跑确认。

### `b-line-gemini-cli/`

主题：Gemini CLI 官方文档研究（Plan Mode、sandbox、policy engine、MCP 边界、ACP session 等）。

**验证级别：未在本次推送会话中复验**，同上按各自目录自证。已剔除其中克隆的第三方 Gemini CLI 源码仓库（`repo/`、`gemini-cli/`，均为 Google 官方 Apache-2.0 仓库，与本研究产物无关，未纳入本次推送）。

## 推送前安全检查（本会话已执行）

- 全量文件两轮 grep 扫描（覆盖私钥、GitHub token `ghp_`/`gho_`/`github_pat_`、OpenAI 风格 `sk-`、Stripe `sk_test_`/`sk_live_`、AWS `AKIA`、Slack `xox*`、Google `AIza*` 等模式），未发现真实密钥。
- **首次推送被 GitHub secret scanning 拦截**：A 线部分切片保存的官方文档原始抓取文本中，含有 Stripe 官方 API 文档里长期公开使用的标准示例测试密钥（`sk_test_` 前缀 + 20 个字符，Stripe 文档惯用值）——该值不指向任何真实账户，但仍匹配 GitHub 的密钥模式规则并被正确拦截。首轮清理遗漏了 3 个非 `.html` 后缀的文本快照（因初次全量扫描使用了命令行参数展开方式，在约 1460 个文件时发生静默截断，导致漏检；改用 `xargs -0` 管道方式重新扫描后定位到全部 4 处命中，含本文件自身的示例引用）。**已彻底移除所有 `raw/` 原始网页快照目录及散落的抓取文本文件**（无论后缀名），这些是抓取缓存，不是研究结论本身，对应 URL 已记录在各切片的 `sources.md` 中。
- 扫描已知生产服务器标识（104 服务器 IP、vaultwarden、oracle-sniper、nework.uk 域名），未发现命中。
- 未包含任何 `.git` 目录、第三方克隆代码或 `__pycache__`。

## 已知局限

- 本索引由推送执行者（AI 助手）生成，未经人工二次复核内容语义；密钥扫描基于已知模式匹配，不保证穷尽所有可能的敏感信息形式。
- 各切片内部的 "claims"、"结论" 仅在其声明的合成 fixture 范围内成立，不构成对任何真实系统的安全性或正确性认证。
