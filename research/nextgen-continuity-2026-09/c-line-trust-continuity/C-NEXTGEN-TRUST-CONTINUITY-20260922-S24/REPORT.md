# S24：跨 epoch 恢复重试的幂等键与审计链断裂矩阵

## 边界与声明

本研究切片为**全新、仅离线合成**实验：`synthetic_only=true`，`production_verified=false`。未访问网络、真实服务、SDK、凭据、生产数据或外部 API；未读取 S1–S23，也未访问禁用路径。所有 claim 的 `status=inferred` 且 `sources=[]`。

这不是生产验证，不能证明生产耐久性、exactly-once、回滚、外部效果或 production readiness。完成本切片不代表停线。

## 问题与判定模型

研究问题：当一次请求跨 epoch 恢复并重试时，如何在 token 轮换、重放窗口、提交状态、fencing、幂等键和审计哈希链之间避免把“已接纳”误报成“已生效”？

结果状态严格互斥：`RECOVERED / UNKNOWN / REJECT`。

* `RECOVERED`：仅当 admission/platform receipt、日志存在、外部效果确认三类**独立证据**都已验证，且幂等键有效且参数哈希一致、epoch 一致、token 连续性已证、重放窗口安全、无部分提交、无双重提交、审计哈希链连续、恢复后 fencing 已证时产生。
* `REJECT`：存在明确安全冲突/不接受条件，包括幂等键复用、幂等参数冲突、epoch 不匹配、不安全重放窗口或双重提交。
* `UNKNOWN`：除明确 REJECT 外的任何必要证据缺失、延迟、丢失、查询缺口、导出失败、部分提交、审计链断裂、token 连续性缺失或恢复后 fencing 未证；不得升级为 RECOVERED。

## 矩阵结果

| case | 分类 | 关键扰动 | 状态 | 结论 |
|---|---|---|---|---|
| S24-01 | VERIFIED_CONTINUITY | token 轮换后连续；epoch/fence/审计/三证据闭合 | RECOVERED | 唯一允许恢复确认 |
| S24-02 | NO_EVENT | 无 receipt、日志、外部效果确认；token 连续性缺失 | UNKNOWN | 无事件不等于安全恢复 |
| S24-03 | DELAYED | 外部效果待定；重放窗口不安全 | REJECT | 不安全窗口 fail-closed |
| S24-04 | DROPPED | 部分提交；日志缺失、外部效果未知 | UNKNOWN | 不能推断未提交或已提交 |
| S24-05 | EXPORTER_FAILURE | 审计哈希链断裂 | UNKNOWN | 导出失败不能证明连续性 |
| S24-06 | QUERY_GAP | 幂等键缺失；日志和效果未知 | UNKNOWN | 缺键不能安全重试/确认 |
| S24-07 | RETENTION_EXPIRED | epoch 不匹配、token 连续性不证、窗口不安全、fence 未证 | REJECT | 多重冲突拒绝 |
| S24-08 | UNKNOWN | 幂等键复用、双重提交、窗口超限 | REJECT | 重放/重复效果风险拒绝 |
| S24-09 | UNKNOWN | 幂等参数哈希冲突 | REJECT | 同键不同参数拒绝 |
| S24-10 | UNKNOWN | 恢复后再次 fencing 未证 | UNKNOWN | receipt/log/effect 不能替代 fence |

共 10 cases：`RECOVERED=1`、`UNKNOWN=5`、`REJECT=4`。分类字段覆盖：`NO_EVENT`、`DELAYED`、`DROPPED`、`EXPORTER_FAILURE`、`QUERY_GAP`、`RETENTION_EXPIRED`、`VERIFIED_CONTINUITY`、`UNKNOWN`。

## 审计断裂矩阵要点

| 断裂/冲突 | admission/platform receipt | 日志存在 | 外部效果确认 | 允许 RECOVERED |
|---|---|---|---|---|
| receipt 有、日志无 | 有 | 无 | 任意 | 否，UNKNOWN |
| 日志有、效果待定/未知 | 任意 | 有 | 无 | 否，UNKNOWN |
| 三者有但幂等键缺失/复用/冲突 | 有 | 有 | 有/未知 | 否；冲突/复用为 REJECT |
| 三者有但 epoch 或 token 连续性不闭合 | 有 | 有 | 有 | 否；epoch 冲突为 REJECT |
| 三者有但 audit hash chain 断裂 | 有 | 有但不连续 | 有 | 否，UNKNOWN |
| 三者有但恢复后 fence 未证 | 有 | 有 | 有 | 否，UNKNOWN |
| 三者均有且所有独立 guard 闭合 | 有 | 有 | 有 | 是，RECOVERED |

“有 receipt”只证明 admission/platform receipt；“日志存在”只证明日志可见；“外部效果确认”才是外部效果证据。三者不可互相替代，也不可由单一查询结果推导。

## 可重复性与验证

运行方式：

```sh
python3 harness.py
cp outputs/results.json outputs/results.run1.json
python3 harness.py
cp outputs/results.json outputs/results.run2.json
cmp outputs/results.run1.json outputs/results.run2.json
python3 validator.py
python3 manifest_validator.py
python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
sha256sum -c SHA256SUMS
```

预期：两轮 `results.json` 字节一致；本地验证器、manifest 验证器、官方 `validate_research.py` 和 SHA-256 校验均 PASS。最终 SHA256SUMS 只覆盖交付文件，不覆盖运行时比较副本。

## 下一独立切片建议

建议下一切片单独研究“多区域/多观察者 receipt 与外部效果确认的证据交叉签名及时钟偏差矩阵”，继续 synthetic-only、fail-closed，并保持与 S24 独立目录、独立 fixtures、独立哈希和独立验证；重点覆盖证据新鲜度、观察者分歧和 fence 令牌撤销，而不宣称生产 exactly-once。
