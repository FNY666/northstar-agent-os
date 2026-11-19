# `canary_rollout.py` 未覆盖逻辑审计

## 覆盖率基线

来自当前聚焦覆盖率报告：

```text
Statements: 161
Missed: 33
Statement coverage: 76%
Branches: 52
Partial branches: 18
```

因此“未覆盖 24%”对应的是 33 条语句，不是 24% 的核心业务流程全部缺失。当前已覆盖的主要路径包括：

- 计划模式；
- 单 wave 选择；
- 多 worker 并行执行；
- worker 非零失败；
- worker 超时故障注入；
- canary 失败；
- canary 超时；
- evidence manifest 损坏分类；
- `PAUSED`、`OPEN`、`next_wave_eligible=false` 报告；
- 选定 wave 以外的 worker 不被调用。

## 逐行映射

| 行号 | 未覆盖逻辑 | 类型 | 风险/说明 |
|---:|---|---|---|
| 40 | `bounded()` 的输出截断分支 | 防御性输出 | 超长 stdout/stderr 时限制报告大小；不会改变断路判定，但需要单独验证 `[TRUNCATED]` 标记。 |
| 54 | worker 缺少必需字段 | 输入拒绝 | 防止不完整 inventory 进入恢复流程。 |
| 57 | worker 字段非字符串、为空或含换行 | 输入拒绝 | 防止参数边界和命令参数注入。 |
| 59 | worker systemd unit 正则校验失败 | 输入拒绝 | 防止将任意字符串当作 systemd unit 传递。 |
| 61 | worker ID 正则校验失败 | 输入拒绝 | 防止报告标识和 canary 参数污染。 |
| 66 | inventory 是 symlink 或不是普通文件 | 文件边界 | 防止从意外路径或链接读取 rollout inventory。 |
| 70 | `workers` 不是合法列表、为空或超过上限 | 容量/Schema | 防止空 rollout、错误类型和超大并发输入。 |
| 75 | worker entry 不是对象 | Schema | 防止列表元素类型异常。 |
| 78 | worker ID 重复 | 一致性 | 防止同一 worker 被重复恢复或报告覆盖。 |
| 86 | wave size 不在 `1..MAX_WAVE` | 限流 | 防止零分片、负分片或超出并发安全边界。 |
| 91-94 | 真实 `subprocess.run()` 成功路径 | 执行边界 | 当前测试全部 mock 了 `run_command()`，因此没有执行真实子进程并读取合并 stdout/stderr。 |
| 95-96 | `subprocess.TimeoutExpired` 捕获 | 执行异常 | 真实命令超时时转换成 `timeout=true`，随后应触发 `WORKER_TIMEOUT` 或 `CANARY_TIMEOUT`。当前混沌测试直接注入结果字典，未从真实异常对象走过此捕获。 |
| 97-98 | `OSError` 捕获 | 执行异常 | 可处理执行文件不存在、权限或 exec 失败；随后应被识别为 worker/canary failure。 |
| 110 | 可选 `--cgroup-mount` 参数拼接 | 参数分支 | inventory 中提供 cgroup mount 时才走；当前 fixtures 未提供该字段。 |
| 111→113 | `worker_command()` 中 `apply=False` 的分支边界 | 模式分支 | 该函数当前主要从 apply 流程调用，计划模式不会调用 worker command，因此 apply 参数未被单独测 false 分支。 |
| 114 | `--start` 参数拼接 | 恢复阶段 | Phase A `RECOVERING` 命令的 start 选项未被现有 rollout 测试直接覆盖。 |
| 120 | 可执行文件检查失败 | 文件边界 | 拒绝 symlink、非普通文件或不可执行的 unquarantine/canary 文件。 |
| 135-136 | future 内部抛出异常时的防御性收口 | 并发防御 | 避免单个 future 未预期异常使整个 wave 失控；会生成 `returncode=null` 的失败结果。 |
| 170-171 | 非 root 执行拒绝 | 权限边界 | 生产保护路径；当前测试通过 mock `geteuid()` 为 0，因此没有验证真实非 root 返回码 2。 |
| 173-174 | concurrency 或 timeout 越界拒绝 | CLI 校验 | 拒绝 `concurrency<1`、超过 32、timeout<1 或超过 1800 秒。 |
| 176-177 | `--start` 与负 wave 组合拒绝 | CLI 校验 | 防止 Phase A 以无效 wave 运行；当前负 wave 测试未覆盖。 |
| 184 | wave index 超出 inventory | CLI/输入拒绝 | 防止对不存在的 wave 执行操作。 |
| 223-225 | `OSError`、`RolloutError`、JSON decode 异常统一拒绝 | 失败关闭 | 生成 stderr 错误并返回 4；当前测试主要覆盖成功写报告后的业务暂停，没有覆盖入口异常处理。 |
| 229 | `__main__` 启动入口 | 工具入口 | 测试通过 import 调用 `main()`，不会执行模块入口；不属于业务覆盖缺口。 |

## 按类别汇总

### 高优先级：安全边界和 fail-closed 输入路径

这些是建议优先补测的 20 条左右语句：

```text
54, 57, 59, 61,
66, 70, 75, 78,
86,
120,
170-177,
184,
223-225
```

它们覆盖 inventory schema、路径/文件类型、systemd unit、worker ID、权限、限流和异常拒绝。如果这些路径回归失败，可能导致错误输入进入恢复编排，或错误地返回成功。

### 中优先级：真实进程执行异常

```text
91-98
135-136
```

这些路径关系到真实生产执行时的 timeout、exec 失败和 future 异常收口。当前混沌测试已经验证了下游断路逻辑，但通过 mock 结果直接注入，没有验证 `subprocess.TimeoutExpired` 和 `OSError` 的实际转换。

### 中低优先级：功能分支

```text
40
110
111→113
114
```

它们分别是输出截断、cgroup mount 参数、`apply` 参数和 `--start` 参数。`--start` 对 Phase A 有实际意义，应补一个 recover-wave 测试；未使用 cgroup mount 时则不会影响默认路径。

### 非业务覆盖

```text
229
```

模块入口未被覆盖属于测试方式差异，不代表业务逻辑未测试。若要求 CLI 级别覆盖，可使用 subprocess 运行脚本补测。

## 结论

当前 `canary_rollout.py` 的 76% 语句覆盖率并不表示断路机制缺失。现有混沌测试已经覆盖关键故障闭环：

```text
worker timeout
→ PAUSED
→ circuit_breaker=OPEN
→ canary skipped
→ next_wave_eligible=false
```

以及：

```text
canary timeout/failure
→ PAUSED
→ circuit_breaker=OPEN
→ 后续 wave 不自动推进
```

剩余未覆盖逻辑主要是“拒绝错误输入”和“真实执行边界异常”。建议下一步增加以下测试，使编排器自身达到约 90% 以上语句覆盖率：

1. inventory schema 与正则拒绝参数化测试；
2. symlink、不可执行文件和非 root 入口测试；
3. `subprocess.TimeoutExpired` 与 `OSError` 的真实 mock side effect 测试；
4. `--start`、`--cgroup-mount` 和参数越界测试；
5. future 抛出异常及超长输出截断测试；
6. CLI 子进程级别的 `__main__` 入口测试。
