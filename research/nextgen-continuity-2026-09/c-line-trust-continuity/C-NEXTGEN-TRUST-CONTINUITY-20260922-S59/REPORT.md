# C 线信任连续性 S59：反事实与冲突检验、开放问题状态与证据等级迁移

## 结论（离线合成、推断）

一个 claim 有来源或一个实验有结果，不等于结论已经通过反事实、替代解释和矛盾证据检验。只有 question/claim/evidence window 绑定、counterfactual 已定义并测试、alternative explanation 已检查、negative evidence 边界清楚、矛盾来源被保留、status/grade/inference boundary 明确、开放问题 owner/next test/resolution 完整、source tier/evidence class/scope limit 和状态迁移理由闭合时，才可判 `RECOVERED`。跨项目问题合并或同一问题/范围出现不可调和研究结论冲突判 `REJECT`；反事实、替代解释、矛盾检索、开放问题、证据等级、范围或 resolution 状态未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S58 产物。

## 判定门

1. `identity_conflict` 或 `research_conflict` 任一为真，输出 `REJECT`。
2. question/claim/evidence、counterfactual/alternative/negative evidence、contradiction/status/inference、open question/owner/next test、source tier/class/scope/migration/resolution 任一门未闭合，或 research state unknown，输出 `UNKNOWN`。
3. 只有证据可证伪性、冲突保留、开放问题责任与证据等级迁移全部闭合，才输出 `RECOVERED`。
4. 未找到来源不等于不存在；单一支持性来源、建议性文本或 status 提升本身不能证明结论，必须保留矛盾并记录下一测试/边界。
5. `RECOVERED` 仅表示本片夹具中的 research evidence gate 闭合，不代表结论真实、external effect、exactly-once 或生产决策。

## 覆盖与确定性验证

- 29 个定向 cases：question/claim/evidence、反事实、替代解释、负证据、矛盾检索/保留、status/grade/inference、开放问题owner/next test、source tier/class/scope、迁移理由和resolution，以及各边界缺口、身份冲突和研究冲突。
- 24 个布尔门执行完整 `2^24 = 16,777,216` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产研究方法、实验设计、证据等级治理或知识库状态机的验证。
- 未证明真实系统的反事实实验、替代解释检验、矛盾证据保留、开放问题责任、source tier/evidence class 或结论迁移语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实研究、网络冲突或实验结果；生产接入必须保留反例/冲突、记录 scope 和 next test，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
