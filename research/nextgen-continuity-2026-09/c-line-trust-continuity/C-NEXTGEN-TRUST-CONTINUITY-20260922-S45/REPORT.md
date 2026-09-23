# C 线信任连续性 S45：安全报告、enterprise controls 与 release rollback 边界

## 结论（离线合成、推断）

安全报告已提交、release metadata 存在或 rollback 请求成功，不等于漏洞状态已验证、制品可信、enterprise controls 已加载或运行实例已收敛。只有安全范围和报告通道明确、漏洞分类/triage/severity/remediation 可追溯、release artifact/provenance/signature/version pin 已验证、enterprise policy/allowlist/required controls 有运行时读回、rollback trigger/target/effect/convergence 均闭合且审计记录完整时，才可判 `RECOVERED`。身份冲突、同一 release 不可调和的安全状态冲突判 `REJECT`；修复状态未知、制品/策略/回退/收敛或审计证据缺失保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S44 产物。

## 判定门

1. `identity_conflict` 或 `security_conflict` 任一为真，输出 `REJECT`。
2. security scope/report、triage/severity/remediation、artifact/provenance/signature/version、enterprise policy/allowlist/required control、rollback trigger/target/effect/convergence、audit 任一门未闭合，或 remediation 状态未知，输出 `UNKNOWN`。
3. 只有安全事实、制品可信性、策略生效、回退目标与运行时收敛全部闭合，才输出 `RECOVERED`。
4. 报告已提交、版本号存在、rollback metadata 改变或发布流程退出成功本身不能证明漏洞已修复、制品完整或实例已回退；必须独立 read-back。
5. `RECOVERED` 仅表示本片夹具中的 security/release evidence gate 闭合，不代表漏洞已真实修复、生产 rollout 或业务效果。

## 覆盖与确定性验证

- 27 个定向 cases：安全报告/triage/severity/remediation、制品/provenance/signature/version pin、enterprise policy/allowlist/required control、rollback/convergence/audit，以及各边界缺口、身份冲突和安全状态冲突。
- 22 个布尔门执行完整 `2^22 = 4,194,304` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产漏洞管理、enterprise policy、release signing、npm/GitHub metadata 或 rollback 系统的验证。
- 未证明真实系统的安全报告接收、triage、修复状态、制品签名、构建 provenance、版本收敛、allowlist、回退原子性、实例收敛或审计完整性。
- 所有布尔门代表“证据是否已获得”，不模拟真实 rollout、漏洞修复或回退副作用；生产接入必须独立 read-back、验证 artifact/runtime/audit 三者，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产安全或业务提交。
