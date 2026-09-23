# S17 规则包签名/撤销与跨实现 canonicalization 互操作矩阵

## 结论（仅本地合成）

本切片用固定、非真实 HMAC key 对规则包**字节**做 HMAC-SHA256 验证，并用两个本地 JSON canonicalizer 生成 provenance 哈希。25 个确定性 fixtures 全部通过预期判定：RECOVERED 8、UNKNOWN 6、REJECT 11。三态互斥且保守：签名验证失败或撤销命中为 REJECT；撤销列表缺失/不可访问/格式或完整性不可验证、实现分歧为 UNKNOWN；只有所有检查成功才 RECOVERED。实现 A/B 哈希分歧只有在 fixture 明确声明 contradiction 时才 REJECT，否则 UNKNOWN，不使用多数票或重试升级。

## 矩阵与边界

覆盖规则包签名通过、篡改、缺失；撤销命中、未命中、列表缺失、自身篡改；A/B 同哈希与分歧；签名 OK+撤销 OK、签名 OK+已撤销、签名坏+已撤销、撤销不可访问；撤销时间戳与 observation time 恰等边界（按命中处理）、边界前一秒（未命中）、边界后一秒（命中）、有效窗口内（命中）和窗口过期后一秒（未命中）。签名坏优先于撤销不可访问，因此该组合为 REJECT；这是 fixture 规则中的显式优先级。

每条结果保存：implementation A/B 标识、signature_sha256、revocation_sha256、canonical_input_sha256、A/B canonical 哈希、理由和 blocking_condition。所有文件 `synthetic_only=true`、`production_verified=false`。本地 key 仅为 fixture 常量，非真实凭据。

## 可复核运行

```text
$ python3 harness.py   # 第一次
PASS fixtures=25 RECOVERED=8 UNKNOWN=6 REJECT=11
PASS all fixture expectations
OK S17-01 RECOVERED
OK S17-02 REJECT
OK S17-03 REJECT
OK S17-04 REJECT
OK S17-05 RECOVERED
OK S17-06 UNKNOWN
OK S17-07 UNKNOWN
OK S17-08 RECOVERED
OK S17-09 UNKNOWN
OK S17-10 REJECT
OK S17-11 RECOVERED
OK S17-12 REJECT
OK S17-13 REJECT
OK S17-14 UNKNOWN
OK S17-15 REJECT
OK S17-16 RECOVERED
OK S17-17 REJECT
OK S17-18 REJECT
OK S17-19 RECOVERED
OK S17-20 REJECT
OK S17-21 UNKNOWN
OK S17-22 RECOVERED
OK S17-23 UNKNOWN
OK S17-24 RECOVERED
OK S17-25 REJECT
$ python3 harness.py   # 第二次
PASS fixtures=25 RECOVERED=8 UNKNOWN=6 REJECT=11
PASS all fixture expectations
OK S17-01 RECOVERED
OK S17-02 REJECT
OK S17-03 REJECT
OK S17-04 REJECT
OK S17-05 RECOVERED
OK S17-06 UNKNOWN
OK S17-07 UNKNOWN
OK S17-08 RECOVERED
OK S17-09 UNKNOWN
OK S17-10 REJECT
OK S17-11 RECOVERED
OK S17-12 REJECT
OK S17-13 REJECT
OK S17-14 UNKNOWN
OK S17-15 REJECT
OK S17-16 RECOVERED
OK S17-17 REJECT
OK S17-18 REJECT
OK S17-19 RECOVERED
OK S17-20 REJECT
OK S17-21 UNKNOWN
OK S17-22 RECOVERED
OK S17-23 UNKNOWN
OK S17-24 RECOVERED
OK S17-25 REJECT
PASS byte-identical outputs/results.json across the two runs
$ python3 validator.py
PASS validator fixtures=25 statuses=RECOVERED|UNKNOWN|REJECT
$ python3 manifest_validator.py
PASS manifest_validator claims=6 synthetic_only=true production_verified=false
$ python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
PASS: 6 claims; manifest schema is valid (2026-09-22)
$ sha256sum -c SHA256SUMS
PASS: 8 matching files
```

## 不证明的内容

本报告不证明真实签名体系、真实撤销服务、密钥管理或 PKI；不证明 durability、exactly-once、rollback、并发/分布式时序、网络故障恢复、真实 SDK/服务互操作，也不构成 production readiness。建议下一独立切片继续研究真实系统边界（保持本切片独立），不改变生产线、不停线。

## 运行约束

仅使用本地合成输入和 Python 标准库；未访问网络、真实服务、SDK、凭据；未触碰 shared/P0、事故目录、D10/L12/D14、canonical/staging/140/tri-line/systemd。
