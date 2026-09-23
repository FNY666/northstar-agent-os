# S16 规则版本矩阵：序列化差异 × 多级 provenance 缺口 × 可重复判定

## 结论

本切片是**完全本地合成**的确定性 harness，不访问网络、真实服务、SDK、凭据或既有研究产物。22 个 fixture 均分别在 rule_set **v1**、**v2** 运行一次，输出保留每次运行的 `provenance`、`reason`、`blockers`、canonical SHA-256 输入哈希与 rule_set；v1/v2 差异单独写入 `version_drift`，不会静默覆盖。

判定三态互斥：`RECOVERED` / `UNKNOWN` / `REJECT`。缺失、不可达、无法由规则验证的差异均保守为 `UNKNOWN`；序列化选择、版本切换、多数票、重试不会把 UNKNOWN 升级。`REJECT` 只由规则可验证的矛盾触发（例如父级不匹配、完整性矛盾、显式声明“版本差异即矛盾”、明确要求相等但 canonical hash 不等）。版本切换导致的差异默认标为 `UNKNOWN`（`VERSION_CONFLICT`）；只有 fixture 明确声明该差异是矛盾时才为 `REJECT`。

## 规范化与 hash 判定

canonicalization 规则：对象 key 按 Unicode code point 排序；字符串及 key 先 NFC；对象中的 `null` 省略；数字使用有限 Decimal，去除无意义尾零并输出无指数的 canonical 数字；数组顺序保持显著；NFC 后 key 冲突拒绝 canonicalization。canonical bytes 使用紧凑 UTF-8 JSON，SHA-256 以 `sha256:<hex>` 保存。

- F01：key 顺序差异 → hash 一致。
- F02：NFC/NFD → hash 一致。
- F03：null/省略 → hash 一致。
- F04/F05：1 vs 1.0、尾零 → hash 一致。
- F06/F22：真实数值/数组序列差异 → 规则声明必须相等时 REJECT。
- F14：规范化 key collision → REJECT，不能安全 canonicalize。

## provenance 缺口与版本矩阵

覆盖：L1 完整/L2 缺失（F07、F17、F19、F21）、L1 缺失/L2 完整（F08）、全缺（F09）、缺级不可达（F10/F11），以及完整链（F12）。完整且可达链可 `RECOVERED`；任何必需级缺失或不可达均 `UNKNOWN`。F13/F18 覆盖可验证矛盾的 `REJECT`。

F15/F16/F21 构造规则版本漂移：同一输入分别跑 v1、v2；差异有结构化记录。默认版本冲突 final `UNKNOWN`；F16 的 fixture policy 显式声明冲突，所以 final `REJECT`。F19 验证多数票与重试次数不会升级缺口；F20 验证序列化差异不会升级 provenance UNKNOWN。

## 可重复性与执行结果

运行：

```sh
cd /tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S16
python3 harness.py
python3 validator.py
python3 manifest_validator.py
python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
sha256sum -c SHA256SUMS
```

预期且已在本地执行：22 fixtures、44 runs；两次独立 harness 执行产生相同 canonical hashes、状态、理由、阻塞条件及版本漂移字段；两个本地 validator、通用 manifest validator、SHA256 校验均 PASS。完整机器输出见 `sources.md` 的“真实完整输出”部分及 `SHA256SUMS` 对应文件。

## 边界与非主张

本切片**不证明**真实 durability、远端状态、exactly-once、rollback 或 production readiness；也不推断真实系统的序列化协议、规则实现或 provenance 服务行为。`synthetic_only=true` 且 `production_verified=false`。

## 下一步

建议下一独立切片，保持不停线：针对**规则包签名/撤销与跨实现 canonicalization 互操作**构造全新本地合成矩阵，继续禁止读取 S1–S16 与任何既有研究产物，并先定义可验证的版本冲突策略。
