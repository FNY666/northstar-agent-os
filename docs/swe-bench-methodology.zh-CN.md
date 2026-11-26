# SWE-bench 评测方法学：如何不把环境问题算成模型失败

> 编制日期：2026-11-26 ｜ 范围：`scripts/solve_swe_bench.py`、`scripts/run_swe_bench_eval.py`、`scripts/record_swe_bench_measurement.py`、`scripts/merge_swe_bench_receipts.py`、`scripts/run_swe_bench_batch.py`
> 目标：记录用真实模型跑 SWE-bench 时**判定层**踩过的坑，以及现在采用的规则与理由。
> 说明：本文讲的是**怎么判定**，不是模型能力报告。实际测量记录在 `benchmarks/swe-bench/measurements/`。

---

## 0. 摘要

跑 SWE-bench 的难点不在"让模型改代码"，而在**把结果判对**。本文记录了五类判错，以及对应的规则：

| 判错 | 表面现象 | 真相 | 现在的规则 |
|---|---|---|---|
| 把模型判决说成「不是判决」 | 补丁明明应用成功，却记成 `patch_not_applied` | 上游 `patch_successfully_applied` 字段指的是**测试输出能否解析**，不是补丁是否应用 | 读 runner 日志里的 `>>>>> Applied Patch` 标记 |
| 把环境崩溃说成模型失败 | `RESOLVED_NO`，像是模型改错了 | 进程被信号杀死（模拟层段错误） | 按 **exit status**（139/134/137/135）判为基础设施失败 |
| 把「没凭据」说成「模型没解出」 | 大量 `no_patch_delivered` | 求解器根本没被调用 | 求解收据记 `real_model_evaluated: false`，编排层读它并拒绝评测 |
| 把「上次跑剩的」说成「已经做完了」 | 实例永远不再被求解 | 无凭据运行留下的收据被当成答案 | 启动时识别「模型未被评估」的陈旧收据，重新求解 |
| 把「条件不同」说成「同一实验」 | 两批结果混在一份记录里 | 模型/温度/沙箱配置不同 | 合并时**逐字段比较**条件，不一致就报出来 |

---

## 1. 判定分层：一个实例有五种结局，不是两种

早期只有「通过 / 失败」两种。真实世界里，一个实例可能根本没有可判定的结果。

现在的 outcome 集合：

| outcome | 含义 | 算模型判决吗 |
|---|---|---|
| `RESOLVED_FULL` | 全部 fail-to-pass 测试通过，且未破坏 pass-to-pass | 是（成功） |
| `RESOLVED_PARTIAL` | 部分 f2p 通过 | 是（部分成功） |
| `RESOLVED_NO` | 补丁应用了，测试跑了，但没过 | 是（失败） |
| `evaluation_inconclusive` | 补丁应用了，但测试输出无法解析出 f2p/p2p 状态 | **否** |
| `evaluation_infrastructure_failure` | 评测过程本身崩了（进程被杀、超时、内存不足） | **否** |
| `evaluation_timeout` | 评测超时 | **否** |
| `patch_not_applied` | 补丁没应用上（与模型能力无关） | **否** |
| `no_patch_delivered` | 模型没产出补丁 | 是（失败） |

**关键点**：只有前三类是模型判决。报告解决率时必须同时给两个口径：

- `resolved_rate` —— 分母是全部实例
- `resolved_rate_over_verdicts` —— 分母是**有判决的**实例

只给一个口径，数字就能被读成两种完全不同的意思。

> **教训（PR #153）**：新增 outcome 时，如果下游的"非判决"集合没同步更新，新 outcome 会**静默变成模型失败**。现在有一条守卫测试列出评测器能产生的每个 outcome 并断言其归属。

---

## 2. 上游字段名会骗人：`patch_successfully_applied`

这是最容易踩的坑。

上游 `swebench/harness/grading.py` 里：

```python
eval_status_map, found = get_logs_eval(test_spec, test_log_path)
if not found:
    ... return report_map          # patch_successfully_applied 仍是 False
report_map[instance_id]["patch_successfully_applied"] = True
```

该字段为 `True` 的条件是「**测试日志被成功解析**」，而不是「补丁应用成功」。

### 实测证据

django-10554：上游日志明写

```
>>>>> Applied Patch:
Checking patch django/db/models/sql/query.py ...
Applied patch django/db/models/sql/query.py cleanly.
```

补丁**干净地应用了**，随后测试因 `DatabaseError` 崩掉 → `get_logs_eval` 解析失败 → 上游字段为 `False` → 早期适配层记成 `patch_not_applied`（声称「这不是模型判决」）。

**但这恰恰是模型判决**——模型把代码改坏了。

### 现在的规则

以 **runner 日志里的标记**为准（`scripts/run_swe_bench_eval.py`）：

| 标记 | 判定 |
|---|---|
| `>>>>> Applied Patch` | 补丁应用成功 → 继续走 grader |
| `>>>>> Patch Apply Failed` | 补丁没应用上 → `patch_not_applied` |
| 两者都没有 | `unknown` → 依据上游字段保守处理 |

标记写在 `run_instance.log` 里，**不在** `test_output.txt` 里。读错文件会让标记永远取不到（这正是修复过程中的一个中间错误）。

> **教训**：读上游源码确认真实语义，不要按字段名推断。字段名是给人看的，实现才是行为。

---

## 3. 区分「机器崩了」与「模型没解出来」

官方环境镜像只发布 `linux/amd64`。在 aarch64 主机上跑要靠 QEMU 用户态模拟，而 numpy / pandas 的 C 扩展在模拟层里会**段错误**。

这种崩溃**与补丁质量毫无关系**，却会表现为「测试没通过」。

### 现在的规则：看 exit status，不看文字

上游 runner 会把测试命令的退出状态写进日志：

```
+ SWEBENCH_TEST_EXIT_CODE=139
```

| 状态 | 含义 | 判定 |
|---|---|---|
| 139 | SIGSEGV | `evaluation_infrastructure_failure` |
| 134 | SIGABRT | 同上 |
| 137 | SIGKILL | 同上 |
| 135 | SIGBUS | 同上 |
| 0 / 1 / 2 | 正常结束 | 走 grader，是模型判决 |

早期版本用文本匹配（找 `"Killed"`、`"out of memory"`）——那会**误伤**只是打印了这些词的测试。现在 exit status 是精确信号，文本匹配降级为兜底。

### 已知无法解决的限制

`QEMU_CPU=max` / `qemu64` / 默认——三种 CPU 模型**同样崩溃**（不是 CPU 特性问题）。原生 x86_64 备选机内存不足，跑不动重测试。

**结论**：这类实例在当前基础设施下无法判定，应如实记为基础设施失败，而不是硬塞进成功或失败。

---

## 4. 「模型未被评估」必须与「模型没解出」分开

求解器在**没有凭据**时不会伪造结果，而是产出：

```json
{"real_model_evaluated": false, "summary": {"reason": "no_provider_credentials"}}
```

这个诚实标记是整套判定的基础。但**编排层必须读它**：

| 场景 | 正确行为 |
|---|---|
| 本次运行中求解后发现无凭据 | 记 `no_credentials`，**不评测**（没有补丁可评） |
| 上一轮运行留下的无凭据收据 | **重新求解**（那次什么都没发生，不能算做过） |

第二种情况是**续跑逻辑的第二层缺陷**：早期只挡住了「无凭据的实例被送去评测」，没处理「无凭据的收据把实例**永久标记为已求解**」——批次脚本的续跑判断是「有 solve 收据就跳过求解」，于是这类实例永远不会有判决。

批次脚本现在在启动时扫一遍已有收据，把「模型未被评估」的挑出来重跑。

> **教训（PR #151）**：修复与既有测试**期望直接冲突**时，先判断哪个期望描述了真实场景，不要为了绿而迁就旧测试。旧测试预置了一份无凭据收据却期望「不评测」——真实行为应该是「重解」。

---

## 5. 收据要能证明自己测的是同一件事

### 求解侧记录什么

`conditions` 里必须包含：`provider`、`model`、`base_url`、`temperature`、`limits`（max_turns / max_tool_calls / wall_time_seconds / max_output_tokens）、`sandbox`（backend / memory / network / landlock / seccomp / capdrop / policy_file / plugins / skills）、`sample`（path / **sample_sha256** / task_count）。

`sample_sha256` 很重要：样本文件被改动后，靠它才能发现「这批结果对应的是另一份样本」。

### 复用旧结果前必须逐字段比较

条件要**展平后逐字段 diff**，不能只看 model 和 temperature 两项——嵌套里的 sandbox、limits、sample_sha256 同样决定结果。

本次实测：早期跑批的 11 个实例与当前批次条件**完全一致**（键集合相同、共同字段零差异），复用后判定与既有 12 题测量**完全吻合**，交叉验证通过。

复用时还有两个细节：

1. 旧收据可能是批量产出的（含多个 instance），要**按 instance_id 过滤 tasks**
2. 旧收据的**判定逻辑版本可能不同**，必须用当前规则**重新判定**，否则旧判定会静默混入

### 空补丁不是补丁

模型改了代码却没改出补丁时，求解器原本仍会保留一个空条目——`patched` 计数声称"补了 1 个补丁"，而且空 diff 会被送进评测器。现在空条目会被丢弃。

---

## 6. 批量编排：测量用的代码不该在仓库外

整个流程（求解 → 评测 → 收据 → 测量）都在仓库内，且每一段都有测试：

| 脚本 | 职责 |
|---|---|
| `scripts/solve_swe_bench.py` | 求解单个实例，产出收据与补丁 |
| `scripts/run_swe_bench_eval.py` | 评测单个实例，按本文件的规则判定 |
| `scripts/run_swe_bench_batch.py` | 批量编排 + 断点续跑 + 镜像拉取 + 凭据前置校验 |
| `scripts/merge_swe_bench_receipts.py` | 合并逐实例收据为整批收据，并比较条件 |
| `scripts/record_swe_bench_measurement.py` | 生成测量记录，区分判决与非判决 |

### 断点续跑的语义

1. 已有评测收据的实例不再求解
2. 补丁文件**只增不截断**
3. 陈旧的「模型未被评估」收据会被识别并重新求解
4. 没有凭据时**直接拒绝启动**，而不是产出一批假结果

### 编排层的两类坑

- **镜像必须显式拉取**：官方镜像只有 amd64，`docker pull` 不带 `--platform` 会拉到 404
- **仓库从实例自己的环境镜像导出**（`docker create` + `docker cp /testbed/.`），不从 GitHub clone——clone 出来的树与评测跑的不是同一份代码

---

## 7. 速查清单

写新的评测判定时，逐条对照：

- [ ] 补丁是否应用，读的是 **runner 日志的标记**，不是上游 report 字段
- [ ] 进程崩溃，读的是 **exit status**，不是日志文字
- [ ] 「模型未被评估」与「模型没解出」是两种状态，且下游统计认识前者
- [ ] 新增 outcome 时，同步更新下游的「非判决」集合，并有守卫测试
- [ ] 解决率给**两个口径**（全体 / 仅有判决）
- [ ] 收据记全条件（含 temperature 与 sample_sha256）
- [ ] 复用旧收据前展平逐字段 diff 条件，并**用当前规则重判**
- [ ] 空补丁丢弃，不进 `patches` 字典
- [ ] 批量作业的编排代码在仓库内，有测试，有凭据前置校验
