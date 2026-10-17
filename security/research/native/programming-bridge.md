# 编程交付—安全 produced 桥

`check-programming-security.py` 是一个**只读、fail-closed**桥接器：它把现有 `code_task` 的交付证据与由安全控制面签名的 `produced` 目录关联起来。它不运行扫描器、normalizer、项目代码或宿主检查；不调用 `seal_release()`；不发布，也不写入任一被验证目录。

## 调用

```bash
python3 security/check-programming-security.py \
  --code-evidence-dir /trusted/evidence/code-run-123 \
  --produced-dir /candidate/produced \
  --trust-store /trusted-control-plane/receipt-trust.json \
  --identity /trusted-control-plane/current-identity.json
```

输出为一行 `northstar.programming-security-bridge.v1` JSON。进程仅在 `verified_success: true` 时返回 **0**；任何不完整、篡改、未验证或未绑定的输入返回 **2**。因此，进程的默认零退出状态、模型文本中的“成功”描述、以及 `success_unverified` 都**不能**替代真正验证成功。

可选的 `--now` 仅用于可重复的本地 fixture 测试，必须是严格 UTC RFC3339 时间；生产调用应让脚本使用宿主 UTC 时钟。

## 输入信任边界

| 输入 | 来源与处理 | 必须满足 |
|---|---|---|
| `--code-evidence-dir` | 现有 `code_task` 证据；仅读取固定文件名 | 不是 symlink；每个关键文件的实际 SHA-256 与 manifest pin 一致 |
| `--produced-dir` | 已签名安全 produced 目录；仅读取 | 不是 symlink；通过父核心 `seal_release._read_produced` 的全部读取、验签、冻结与 fresh-gate 路径 |
| `--trust-store` | 当前、包外的控制面信任根 | 必须是常规文件，且解析路径不在 code evidence 或 produced 目录内；由 `load_trust_store` 以 no-follow 读取并验证 |
| `--identity` | 当前、包外的 CI 身份 | 必须是常规文件，且解析路径不在 code evidence 或 produced 目录内；由合同原语读取、严格解析并 `validate_identity` |

桥不会从 pending/candidate 文件、`produced` 文件或 code evidence 生成 trust/identity。输入中任意一个违反该边界，`external_trust_identity` gate 失败，且不会尝试把候选输入升级为可信事实。

## `code_task` verified-success 门

桥仅接受 `manifest.status == "success"` 且严格整数 `exit_code == 0` 的非 plan-only 任务。它再要求：

1. `task.json` 声明 1–32 条非空、去重的 host checks；
2. `phases.json` 是可达的 `created → … → verifying → success` 状态链，使用 effect journal v1，且不存在 `in_flight`、`unknown` 或 `failed` effect；
3. `verification.json` 恰有一份独立摘要，所有声明检查均已运行、通过且没有 skip；摘要记录 `network: "denied"`；每个结果和对应 `HostCheck` effect 都有相同的索引、已完成状态、`exit_code: 0`、`ok: true` 与 `timed_out: false`；
4. `changes.patch` 的实际字节数和 SHA-256 同时匹配 manifest、`patch-replay.json`、`patch-audit.json` 与 `delivery-seal.json`；补丁重放必须返回两个零退出码，审计无 findings，且 delivery seal 表示 host verification 期间补丁未变；
5. 所有关键 JSON/patch artifact 都由 manifest 的同名 SHA-256 绑定，并以合同的 no-follow 读取原语读取。

这使“模型声称通过”、仅有默认零退出码，或伪造 `ok: true` 但实际 host result 非零，均无法构成桥的 verified-success。

## 已签名安全 produced 门和绑定

在外部信任根和身份已经验证后，桥**直接调用**父核心的 `seal_release._read_produced(produced_dir, trust, identity, now)`。该只读路径会：

- 验证 scan plan、scan capture 与 expectation DSSE receipt 的签名、角色、身份、时间和信任策略；
- 用签名 capture manifest 安全读取完整 produced 文件集；
- 验证 host expectation 只能从签名 plan 与已认证 evidence bytes 确定性导出；
- 重新运行 fresh security gate 校验（不执行扫描器），并要求可交付 `pass`。

桥从**已验签 plan**的 `expectation_template.subject` 读取 `start_commit`、`patch_sha256` 与 `candidate_manifest_sha256`。它只在 code delivery 实际 `start_commit` 和实际 patch bytes 的 SHA-256 同时等于该 signed subject 时通过 `signed_plan_delivery_binding`。

> `candidate_manifest_sha256` 当前只被作为已签名 subject 的 pin 保留并报告。现有输入接口不包含可独立认证的 candidate manifest 及其源码/构建输入，所以桥无法重建该 manifest；报告始终标记 `candidate_manifest_rebuilt: false`。这不是可忽略的成功证明，也不会触发自动 seal/publish。

## 已执行的本地测试

以下测试只创建临时目录、临时 Ed25519 fixture 和虚构安全扫描记录；不访问外部 URL、真实目标、真实凭据或生产签名密钥：

```bash
cd /home/ubuntu/northstar-native-security-dev/security
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest -v native_tests/test_programming_security.py
```

实际结果：**7 tests passed**。

| 场景 | 结果 |
|---|---|
| 内部一致的 code delivery + 临时自签名 produced | 通过 bridge，且 CLI 返回 0 |
| `success_unverified` 但 `exit_code: 0` | 拒绝，CLI 返回 2 |
| 非零 host receipt（即使其他字段可声称成功） | 拒绝 |
| code patch 与 signed plan `subject.patch_sha256` 不同 | 拒绝 |
| 破坏 `plan.dsse.json` | fresh 签名图验证拒绝 |
| trust 文件置入 produced 包内 | 外部 trust/identity 边界拒绝 |

## 限制

- 本地 code evidence 的摘要提供的是内部一致性；没有来自独立远程/物理宿主的认证时，它不能单独证明证据生产者未被恶意控制。
- 桥不重新执行 HostCheck、扫描或构建；它只验证已捕获 receipt 与字节之间的约束。
- fresh gate 证明的是既有已认证扫描证据的当前合同评估，不等于新的实时扫描。
- 通过不证明源码到制品可复现性、物理隔离事实、未知漏洞不存在，或可以自动发布。
