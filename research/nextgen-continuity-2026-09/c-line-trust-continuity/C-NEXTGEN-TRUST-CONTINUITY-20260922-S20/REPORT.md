# C 线 S20：时间证据权威模型

## 结论

本切片建立一个**本地确定性、保守、双轴**的审计事件判定模型。每条事件同时携带 `wall_clock_ms` 与 `seq`；判定只在证据范围内进行，不把 wall clock 或逻辑序号预设为普遍权威。结果严格互斥：`RECOVERED`、`UNKNOWN`、`REJECT`。

- **RECOVERED**：仅限目标事件；权威时钟源已显式声明；目标事件的 wall-clock 与 seq 均存在；时间偏移 `offset <= limit`（含边界）；证据范围不存在排序冲突、共时歧义、seq 空洞或其他阻塞条件。
- **UNKNOWN**：证据不完整或发生任何无法保守消解的歧义。墙钟/seq 冲突时不默认任何一方；缺墙钟、缺 seq、缺权威源、回拨、同墙钟多 seq、seq 空洞、未证实负断言、重试、超过边界，均不升级。
- **REJECT**：仅当 fixture **显式声明不变量**，且记录能够直接验证其矛盾时可达。本切片覆盖 `wall_clock_monotonic` 与 `seq_monotonic` 的显式矛盾；时钟回拨本身不产生 REJECT。

## 结果

20 个确定性 fixtures：

- `RECOVERED=5`
- `UNKNOWN=13`
- `REJECT=2`

其中 RECOVERED 只说明目标事件在该 fixture 的合成证据下可恢复，不能外推到范围外事件。

## 保守规则矩阵

| 场景 | 判定 |
|---|---|
| 墙钟一致且 seq 一致 | RECOVERED，仅限该事件 |
| wall clock 与 seq 顺序冲突 | UNKNOWN，不偏向任何一轴 |
| 仅 seq 存在、墙钟不可达/未记录 | UNKNOWN |
| 时钟回拨、无单调不变量 | UNKNOWN |
| 时钟回拨、显式墙钟单调不变量且可验证矛盾 | REJECT |
| 无权威时钟源声明 | UNKNOWN |
| 同墙钟不同 seq | UNKNOWN，时间不区分先后 |
| seq 空洞且墙钟连续 | UNKNOWN，不用墙钟补全 |
| 显式负断言但无其他证据 | UNKNOWN，负断言不可证 |
| `offset == limit` | 可判定（若其余证据充分） |
| `offset > limit` | UNKNOWN |
| 重试/多事件共时/缺时钟源 | 不升级，不从 UNKNOWN 变为 RECOVERED 或 REJECT |

## 证据可追溯性

`outputs/results.json` 的每条结果保留：

1. `clock_seq_evidence`：目标与证据范围内每个事件的双轴值、时钟源、参考时间、偏移边界；
2. `reason`：判定理由；
3. `blocking_conditions`：阻塞条件；
4. `canonical_input_sha256`：对该 fixture 按 UTF-8、Unicode 保留、递归 key 排序、紧凑 JSON 序列化后的 SHA-256。

## 边界与非主张

本切片全程本地合成，`synthetic_only=true`、`production_verified=false`。它**不证明**真实审计系统、NTP 或任何时钟服务、durability、exactly-once、rollback 实现、生产 readiness；也不测试 SDK、凭据、真实时钟或网络服务。`REJECT` 是合成 fixture 内显式不变量矛盾的分类，不是现实系统拒绝行为的证明。

禁止输入域包括：既有 S1–S19 与其他研究产物、shared/P0、事故目录、D10/L12/D14、canonical/staging/140/tri-line/systemd，以及网络、真实时钟/NTP 服务、SDK、凭据。

## 可复现命令与预期

```sh
python3 harness.py
cp outputs/results.json /tmp/s20-results-first.json
python3 harness.py
cmp -s outputs/results.json /tmp/s20-results-first.json
python3 validator.py
python3 manifest_validator.py
python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
sha256sum -c SHA256SUMS
```

两次 harness 执行必须生成字节一致的 `outputs/results.json`。后续建议：开始下一独立切片，保持不停线；不要把本切片的合成结论升级为生产证据。
