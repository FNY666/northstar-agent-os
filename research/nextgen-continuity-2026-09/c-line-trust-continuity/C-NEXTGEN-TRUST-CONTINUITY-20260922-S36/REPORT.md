# C 线信任连续性 S36：委托证明、上下文绑定与撤销水位

## 结论（离线合成、推断）

一个有效签名并不自动证明当前 bundle 被正确授权。只有身份域正确、issuer 到 delegate 的证明链完整、签名 scope 覆盖目标、key status 与 revocation watermark 在读取时点可确认、签名绑定 canonical payload 和 tenant/epoch/purpose 上下文、变换/脱敏/重签名链均有授权证明、时间戳仍在 freshness window、issuer epoch 连续且观察者 quorum 闭合时，才可判 `RECOVERED`。签名者 equivocation、授权 scope 冲突、同一 key/时点的撤销状态冲突或身份冲突判 `REJECT`；证明缺失、密钥状态未知、上下文未绑定、未经授权重签名或撤销水位未闭合保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S35 产物。

## 判定门

1. `identity_conflict`、`signer_equivocation`、`scope_conflict` 或 `revocation_conflict` 任一为真，输出 `REJECT`。
2. 身份缺失、root/委托/scope/key/revocation/payload/context/bundle/transform/redaction/resign/timestamp/epoch/quorum 任一门未闭合，输出 `UNKNOWN`。
3. 只有全部证明链、授权边界、上下文绑定、变换链和撤销窗口门闭合，才输出 `RECOVERED`。
4. `NO_EVENT`、只看到签名但看不到 payload/context 绑定、只看到新签名但没有原始 issuer 授权，不能推断授权或未发生，保持 `UNKNOWN`。
5. 重签名、脱敏和格式变换都是新证据边界：必须保留可验证的原始关联、授权和 canonicalization 证明；签名存在本身不是外部效果或业务提交证明。

## 覆盖与确定性验证

- 26 个定向 cases：委托链、上下文绑定、授权重签名、脱敏变换、密钥与 quorum、延迟证明、root/scope/key/revocation/payload/context/bundle/transform/redaction/resign/timestamp/epoch/quorum 缺口、身份冲突、签名 equivocation、scope 冲突及撤销状态冲突。
- 19 个布尔门执行完整 `2^19 = 524,288` 组合，使用流式计数避免一次性保存组合对象，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产 PKI、签名、delegation、密钥撤销、脱敏或授权系统的验证。
- 未证明任何真实系统的证书链、scope 语义、key status API、revocation watermark、canonicalization、重签名授权或 observer quorum 实现。
- 所有布尔门代表“证据是否已获得”，不模拟真实服务返回、密钥轮换时序或撤销传播延迟；生产接入必须独立 read-back、验证 signer scope、payload/context binding、transform provenance 和撤销时点，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的证据门闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
