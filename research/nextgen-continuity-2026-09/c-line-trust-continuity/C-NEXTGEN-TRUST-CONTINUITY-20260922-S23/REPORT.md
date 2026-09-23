# S23 trust-continuity：多快照交叠边界 + 恢复重试矩阵

## 研究边界
本切片是**仅离线合成**的确定性实验：`synthetic_only=true`，`production_verified=false`。不访问网络、真实服务、SDK 或凭据；不读取 S1–S22。每个 fixture 明确模拟平台回执、日志存在性与外部效果确认三类相互独立证据，并携带 epoch/fence token。

## 判定协议（fail-closed）
- `RECOVERED` 仅在平台回执 `ACCEPTED`、日志 `PRESENT`、外部效果 `CONFIRMED`、连续性和分类均为 `VERIFIED_CONTINUITY` 且没有矛盾时产生。
- `REJECT` 用于旧 epoch、过期/缺失/冲突 token，或显式审计拒绝原因；拒绝原因被记录。
- 其余（包括重启窗口、重复恢复重试、延迟、丢弃、查询缺口、保留期过期及证据矛盾）均为 `UNKNOWN`，不能推断成功。

## 覆盖与矩阵
20 个确定性 cases 覆盖：重叠快照（C01–C02）、epoch 旧写者（C03）、旧 token（C04）、token 缺失/冲突（C05–C06）、导出器重启前/后窗口（C07–C08）、恢复重试重复（C09）、NO_EVENT（C10）、DELAYED（C07/C11/C20）、DROPPED（C03/C04/C12）、EXPORTER_FAILURE（C08/C13/C19）、QUERY_GAP（C02/C14/C20）、RETENTION_EXPIRED（C15）、VERIFIED_CONTINUITY（C01/C17/C18）、显式矛盾（C16），以及审计拒绝原因（C03–C06/C19）。

| 状态 | 数量 | 含义 |
|---|---:|---|
| RECOVERED | 3 | 三类独立证据一致，且连续性可验证 |
| UNKNOWN | 12 | 不能排除缺口、延迟、重复或矛盾 |
| REJECT | 5 | fencing/token 或审计明确拒绝 |

`outputs/results.json` 的输出由 harness 对输入按稳定排序序列化；双轮运行通过字节 cmp。

## 明确不可证明事项
本实验不能证明生产耐久性、exactly-once、回滚语义、外部效果真实性、真实故障恢复能力或 production readiness。`RECOVERED` 只是 synthetic fixture 内的证据闭合，不是生产确认。完成本切片不代表停线。

## 复现与验证
```sh
python3 harness.py
cp outputs/results.json /tmp/s23.first.json
python3 harness.py
cmp outputs/results.json /tmp/s23.first.json
python3 validator.py
python3 manifest_validator.py
python3 /path/to/validate_research.py .   # 官方脚本路径由执行环境提供
sha256sum -c SHA256SUMS
sha256sum REPORT.md sources.md research-manifest.json harness.py fixtures/cases.json outputs/results.json validator.py manifest_validator.py > SHA256SUMS
sha256sum -c SHA256SUMS
```
