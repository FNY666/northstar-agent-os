# C 线信任连续性 S48：security reporting、enterprise controls 与 release rollback/convergence

## 结论（离线合成、推断）

安全报告、release metadata、artifact signature 或 rollback 请求成功不能单独证明安全问题已修复、制品可信或运行实例已收敛。只有报告范围/接收方/finding identity 固定、severity 方法和 triage/remediation 责任闭合、artifact digest/signature/build provenance/release metadata/version pin 均验证、enterprise policy scope/allowlist/required control 有运行时读回、rollback trigger/target/completion/convergence 与 audit trail 全部闭合时，才可判 `RECOVERED`。身份冲突或同一 finding/release 的不可调和安全状态冲突判 `REJECT`；修复、制品来源、策略生效、回退效果或运行收敛未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S47 产物。

## 判定门

1. `identity_conflict` 或 `security_conflict` 任一为真，输出 `REJECT`。
2. 报告、finding、triage/remediation、artifact digest/signature/provenance、metadata/version、enterprise policy/allowlist/control、rollback/convergence、audit 任一门未闭合，或 release state unknown，输出 `UNKNOWN`。
3. 只有安全事实、制品来源、策略生效、回退目标/结果与运行时收敛全部闭合，才输出 `RECOVERED`。
4. 报告提交、tag/version 存在、签名存在或 rollback 请求完成本身不能证明目标状态；必须独立 read-back，并将 artifact、runtime、audit 分轴验收。
5. `RECOVERED` 仅表示本片夹具中的 security/release evidence gate 闭合，不代表漏洞真实修复、生产 rollout、external effect 或业务提交。

## 覆盖与确定性验证

- 28 个定向 cases：security report/finding/severity/triage/remediation、artifact digest/signature/build provenance/release metadata/version pin、enterprise policy/allowlist/required control、rollback/convergence/audit，以及各边界缺口、身份冲突和安全状态冲突。
- 23 个布尔门执行完整 `2^23 = 8,388,608` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产漏洞管理、enterprise policy、release signing、构建 provenance 或 rollback/convergence 系统的验证。
- 未证明真实系统的报告接收、severity/triage、修复状态、artifact digest/signature、构建输入、版本收敛、allowlist、回退原子性、实例收敛或审计完整性。
- 所有布尔门代表“证据是否已获得”，不模拟真实 rollout、漏洞修复、回退副作用或实例分叉；生产接入必须独立 read-back、分别验证 artifact/runtime/audit，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产安全或业务提交。
