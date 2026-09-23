# S28 trust-continuity：observer membership churn 下的 evidence provenance equivocation

## 范围与限制
本切片**仅本地合成、离线运行**（`synthetic_only=true`），不访问网络、真实服务、SDK、凭据、生产数据或 S1–S27。`production_verified=false`。模型是 fail-closed 三态互斥分类：`RECOVERED` / `UNKNOWN` / `REJECT`。

## 研究问题
当 observer membership 发生增删 epoch 时，如何在成员变更后的 quorum 重算、区域/epoch receipt 冲突、迟延撤销确认、bounded query replay、身份重用、旧成员迟到证据、撤销水位及 epoch/fence 连续性之间保持证据来源可归因？

## 合成规则
`RECOVERED` 只有在以下八个 gate 全部闭合时产生：成员 epoch 闭合；quorum 已重算且重新满足；observer 身份/签名来源无 equivocation；撤销水位已达到；bounded replay 完整；crash/restart 闭合；平台 receipt、持久日志、外部效果三类证据一致。成员变更未收敛、quorum 分裂、迟到旧成员证据、query gap、retention expired、身份重用冲突均阻止升级。明确硬冲突或检测到同一 observer 在同一 conflict scope 签发不兼容 receipt 时进入 `REJECT`；其余证据不足保持 `UNKNOWN`。

## 结果
- 13 个 cases，覆盖 `NO_EVENT`、`DELAYED`、`DROPPED`、`EXPORTER_FAILURE`、`QUERY_GAP`、`RETENTION_EXPIRED`、`VERIFIED_CONTINUITY`、`UNKNOWN`。
- 预期状态分布：`RECOVERED=1`、`UNKNOWN=10`、`REJECT=2`。
- 8 个 gate 的全组合 property sweep：256 组合，违规 0。
- 8 个单门 minimizer：全部找到，单个 gate 缺失均保持 `UNKNOWN`。
- 一个闭合基线可 `RECOVERED`；receipt cross-region equivocation 与明确 hard conflict 可 `REJECT`。

## 证据与可重复性
`fixtures/cases.json` 是全部本地输入；`harness.py` 不产生网络或外部效果。运行两次并对 `outputs/results.json` 做字节级 `cmp`。随后运行 `validator.py`、`manifest_validator.py`、官方 `validate_research.py` 和 `sha256sum -c SHA256SUMS`。所有 manifest claims 均 `status=inferred` 且 `sources=[]`；`sources.md` 明确无外部来源。

## 不可推出的结论
本切片不能证明生产耐久性、exactly-once、回滚能力、外部效果真实性、真实平台 receipt 与持久日志的一致性、跨实现安全性或 production readiness。通过合成 property sweep 不等于生产验证。

## 下一独立切片建议
下一切片可在**新目录、独立输入**中专门研究 epoch/fence 跨 crash 边界的撤销水位单调性与 bounded replay 截断：加入乱序、重复、分叉持久日志以及可审计的 fence 证据，但继续 synthetic-only、fail-closed、三态互斥，并保持与本切片目录及输入隔离。完成本切片不代表停线。
