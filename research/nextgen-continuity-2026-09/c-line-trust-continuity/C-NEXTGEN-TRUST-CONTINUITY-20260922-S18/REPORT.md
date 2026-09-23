# C 线 S18：本地合成审计链完整性与缺口检测矩阵

## 结论范围

本报告仅针对 `/tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S18/` 内的确定性、本地合成输入。所有结论均为 `inferred`；`synthetic_only=true`、`production_verified=false`。没有访问网络、真实日志或审计服务、SDK、凭据、shared/P0、事故目录、D10/L12/D14、canonical/staging/140/tri-line/systemd，也没有读取 S1–S17 或其他既有研究产物。

本实现使用固定本地密钥和 HMAC-SHA-256 计算每条记录的 `record_hash`，记录含 `prev_hash`；规范化输入为 UTF-8、JSON `sort_keys=true`、紧凑 separators。该密钥和算法只用于合成演示，不是生产日志系统。

三态互斥且保守：

- **RECOVERED**：在给定范围内，观察到的记录自哈希、相邻 prev_hash 和连续序号均可验证，且没有阻塞条件。
- **UNKNOWN**：证据不足、不可达锚点、截断、空洞、重复、边界外时间或缺少自身哈希；不会由重复、多数票、重试或“看起来连续”升级。
- **REJECT**：仅当链内能验证矛盾，例如已验证前驱与后继 `prev_hash` 不一致，或同一序号产生不同内容的可验证分叉。

## 检测矩阵

| Case | 场景 | 期望/实际 | 关键处理 |
|---|---|---|---|
| C01 | 完整链 | RECOVERED | 连续且每条 HMAC/prev_hash 可验证 |
| C02 | 同 hash 同序号重复 | RECOVERED | 重复不产生新证据，维持原判定 |
| C03 | 中间 prev_hash 断裂，两端可验证矛盾 | REJECT | 后继 prev_hash 与已验证前驱 hash 矛盾 |
| C04 | 中间断链，无可验证矛盾 | UNKNOWN | gap 和不可验证连接，不臆测 |
| C05 | 头部截断，链内一致 | UNKNOWN | 首块/首锚不可访问，不假设内容 |
| C06 | 尾部截断，未达终块 | UNKNOWN | 终块未观察到 |
| C07 | 同序号不同内容分叉 | REJECT | 同一已验证前驱下的内容冲突 |
| C08 | 同序号同内容分叉 | UNKNOWN | 需外部裁决，不用多数票 |
| C09 | 时间戳在观察窗口内 | RECOVERED | 窗口边界内可用 |
| C10 | 时间戳在观察窗口外 | UNKNOWN | 范围外不作 REJECT |
| C11 | 缺失序号空洞 | UNKNOWN | gap 本身阻塞，不因 hash 形状升级 |
| C12 | 记录缺失自身 hash | UNKNOWN | 无法重建或验证该记录 |
| C13 | 外部锚点不可访问 | UNKNOWN | 链可验证但 provenance 不可证实 |
| C14 | 尾部不足且重复记录 | UNKNOWN | 重复不产生新证据，仍未达终块 |
| C15 | REJECT 断裂且重复 | REJECT | 重复不削弱已验证矛盾 |
| C16 | 完整双记录链 | RECOVERED | 确定性回归链 |
| C17 | 窗口外记录且重复 | UNKNOWN | 边界外阻塞，重复不升级 |
| C18 | 同内容分叉且锚点可达 | UNKNOWN | 锚点可达只证明来源，不证明内容 |
| C19 | 前驱自身 hash 缺失、后继断裂 | UNKNOWN | 不能形成可验证矛盾 |
| C20 | 链完整、外部锚点可达 | RECOVERED | 锚点仅为来源上下文，不充当内容正确性证明 |

运行 oracle 实际计数：`RECOVERED=5`、`UNKNOWN=12`、`REJECT=3`，共 20 个确定性 fixtures。每条输出记录均保留 `chain_id`、`prev_hash`/`prev_hashes`、`record_hash`/`record_hashes`、`gap_location`、`reason`、`blocking_conditions`、`canonical_input_sha256`，并标记 synthetic/prod 状态。

## 可复现与验证

在目录内执行：

```text
$ python3 harness.py
PASS: 20 cases; statuses={RECOVERED:5, UNKNOWN:12, REJECT:3}
OUTPUT /tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S18/outputs/results.json

$ cp outputs/results.json /tmp/results.first && python3 harness.py && cmp -s outputs/results.json /tmp/results.first && echo 'BYTE_IDENTICAL: PASS'
PASS: 20 cases; statuses={RECOVERED:5, UNKNOWN:12, REJECT:3}
OUTPUT /tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S18/outputs/results.json
BYTE_IDENTICAL: PASS

$ python3 validator.py
PASS: local results validator; 20 results; mutually exclusive statuses and fixture expectations valid

$ python3 manifest_validator.py
PASS: S18 manifest local policy; 3 inferred claims; no network scope

$ python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
PASS: 3 claims; manifest schema is valid (2026-09-22)

$ sha256sum -c SHA256SUMS
[见交付时的真实完整输出]
```

`SHA256SUMS` 覆盖本目录交付文件（不自包含校验文件本身，以便 `sha256sum -c SHA256SUMS` 可复现通过）。本次真实校验输出如下：

```text
harness.py: OK
fixtures/cases.json: OK
outputs/results.json: OK
validator.py: OK
manifest_validator.py: OK
research-manifest.json: OK
sources.md: OK
REPORT.md: OK
```

本合成切片不证明真实审计系统、durability、exactly-once、rollback、并发/分布式一致性、密钥管理、时间源可信性、外部锚点内容正确性或 production readiness。它也不代表任何真实日志、事故或审计服务的状态。

## 交付清单

- `REPORT.md`
- `sources.md`
- `research-manifest.json`
- `SHA256SUMS`
- `harness.py`
- `fixtures/cases.json`
- `outputs/results.json`
- `validator.py`
- `manifest_validator.py`

建议：完成本独立切片后，进入下一独立切片，不停线。
