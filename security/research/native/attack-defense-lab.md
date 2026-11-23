# 原生安全攻击—防护证据实验室

## 目的与边界

`run-native-security-lab.py` 是一个**固定的本地契约回归实验室**。它以现有的签名、扫描证据、发布密封和消费核心为被测对象，复用 `tests/sealing_fixtures.py` 的结构，并遵循 `examples/demo_end_to_end.py` 的测试密钥原则。

> 所有攻击仅修改本进程创建的临时 fixture。没有目标、命令、URL、凭据、扫描器参数或输出路径入口；不会执行项目代码、真实扫描器或真实构建。

每个 case 都先完成一个独立的 benign pair：使用内存中临时生成的 Ed25519 测试密钥创建 fixture，调用 `seal_release()`，再调用 `consume_release()`。因此“攻击拒绝”并不取代正常路径验证：正常 pair 若不能密封并消费成功，该 case 会失败。

私钥从不序列化到文件；实验结束时只保留不含信任根、签名、fixture 字节或密钥的 JSON 汇总。实验室会检查临时目录中是否出现 `.pem`、`.key`、`.private` 文件。

## 固定 CLI

```bash
cd /home/ubuntu/northstar-native-security-dev/security
python3 run-native-security-lab.py --list
python3 run-native-security-lab.py --json
```

CLI 只有互斥的 `--list` 与 `--json`：

- `--list` 只返回静态 case 目录，**不创建 fixture**；
- `--json` 执行所有固定 pair，并返回结构化汇总；
- 没有 `--target`、`--command`、`--url`、`--credential`、路径覆写或追加 flag 参数。未知参数由 `argparse` 拒绝。

## 攻击与成对防护

| 固定 case | 仅临时 fixture 上的变更 | 被验证的旧核心防护 | 实际阻止条件 |
|---|---|---|---|
| `scope-laundering` | 将 Semgrep 的已观测路径改为签名输入范围外的 `src/other.py`，并用临时 capture key 重签 capture | `produce_expectation()` 重评估已签 plan 的范围，不能由 capture 改写 scope | 抛出 `EvidenceError`，且不发布 producer 目录 |
| `fake-success` | 令记录为 `exit_code=1`、无 findings，并以临时 key 构造外观为 pass 的历史 gate | `seal_release()` 不信任旧 gate，重新计算 fresh gate；执行合同拒绝“exit 1 无发现” | 抛出 `EvidenceError`，且不发布 sealed 目录 |
| `replay-nonce` | 用 nonce 不同的当前可信 identity 消费旧密封包 | receipt 身份绑定 | `consume_release()` 返回 `eligible_for_publish=false`、`exit_code=2` |
| `replay-attempt` | 用 `run_attempt` 增加后的当前可信 identity 消费旧密封包 | receipt 身份绑定 | consumer 标记为不合格 |
| `wheel-swap` | 密封后替换一个 fixture `.whl` 的字节 | release manifest 与 build capture 的精确字节绑定 | consumer 标记为不合格 |
| `old-gate-tamper` | 修改 `producer-gate.json`（历史 gate） | seal manifest 与 expectation receipt 的 gate hash 绑定 | consumer 标记为不合格 |
| `new-gate-tamper` | 修改 `security-gate.json`（密封时 fresh gate） | seal manifest、binding 与 fresh gate hash 绑定 | consumer 标记为不合格 |
| `context-tamper` | 修改 `host-expectation.json` | release seal 的 expectation hash 与确定性 plan/capture 派生 | consumer 标记为不合格 |
| `source-mismatch` | 以不同 `source_commit` 的当前可信 identity 消费密封包 | receipt、release binding 和 consumer 的外部身份核对 | consumer 标记为不合格 |

`scope-laundering` 特意重签**临时 capture**，证明拒绝来自 plan 对输入 scope 的约束，而不是仅仅因旧 capture hash 过期。`fake-success` 则把临时 capture、expectation 和伪造的 pass-shaped historical gate 均更新为相互一致，证明密封阶段的 fresh re-evaluation 实际参与并阻止该不一致记录。

## 汇总字段的含义

实验结果将三件事分别计数，避免把“构造了攻击”或“抛错”误报为所有防护均有效：

| 字段 | 含义 |
|---|---|
| `mutations_applied` | 攻击变更已经实际施加到临时 artifact 或本次 trusted identity 副本 |
| `attacks_detected` | 旧核心实际返回不合格，或 producer/sealer 实际抛出 `EvidenceError` |
| `attacks_blocked` | 被拒绝后未发布输出（producer/sealer），或 consumer 实际返回 `eligible_for_publish=false, exit_code=2` |
| `artifact_mutations_applied` | 实际改写 fixture 文件字节的攻击数 |
| `trusted_context_mutations_applied` | 实际改写调用方可信 identity 副本的攻击数 |

## 本支线实测

执行：

```bash
python3 -m pytest -q native_tests/test_native_security_lab.py
python3 run-native-security-lab.py --json
```

本次实现后的直接 `--json` 冒烟结果为：**9/9 benign pair 通过，9/9 攻击已施加、被检测且被阻止**；其中 6 个是 artifact 字节篡改，3 个是可信身份上下文变更。结果同时报告：`fixture_only=true`、`real_scanners_executed=false`、`project_code_executed=false`、`real_build_executed=false`、`private_keys_persisted=false`。

## 限制

- 这是签名图、字节绑定、门禁重评估与身份绑定的本地单元/集成实验；**不**证明 native scanner 本身被运行，也不证明扫描规则质量或发现完整性。
- 未启动 runner、bwrap/OCI/VM，也没有测量真实内核隔离、网络拒绝、cgroup 聚合预算、只读挂载或主机凭据隔离。
- 临时测试签名可由本实验构造，不能模拟生产中独立信任根与职责分离的运营保证；它们只用于验证已有核心不会接受彼此矛盾的本地 fixture。
- source、nonce、attempt 的“当前可信身份”由调用方传入；实验仅验证核心对该外部值的绑定，不证明控制平面自身的身份来源。
