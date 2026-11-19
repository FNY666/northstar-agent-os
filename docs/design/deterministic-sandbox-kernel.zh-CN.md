# Northstar AgentOS 沙箱安全与确定性执行内核设计

## 目标与非目标

本设计把 Northstar 的“决定是否执行”和“在什么内核边界中执行”拆成两个可验证平面：

```text
确定性执行内核
  ├─ 版本化 Run/Step 状态机
  ├─ 追加式、哈希链接事件日志
  ├─ checkpoint / replay / crash recovery
  ├─ 幂等 action key 与未完成副作用人工/接收器对账
  └─ 策略、审批、验证和审计引用

受信宿主沙箱适配器
  ├─ rootless/user namespace
  ├─ cgroup v2 资源边界
  ├─ seccomp / no-new-privileges / capability drop
  ├─ 只读 workspace 与显式临时目录
  ├─ network=none 或精确 egress sidecar
  └─ 超时、进程组回收、证据封存
```

原型只实现策略验证、沙箱启动计划和单主机确定性事件日志。它**不**伪装成容器运行时，不直接写 `/sys/fs/cgroup`，不加载 seccomp，不替代 systemd/bwrap/gVisor/微 VM，也不声称跨主机 exactly-once。

仓库已有的 `tools/seccomp.py`、`tools/os_sandbox.py` 和 `components/northstar-durable-run` 是实际集成点。本设计新增的窄原型位于：

```text
components/northstar-agent-runtime/tools/deterministic_kernel.py
components/northstar-agent-runtime/tests/test_deterministic_kernel.py
components/northstar-agent-runtime/tools/sandbox_evidence.py
components/northstar-agent-runtime/tools/sandbox_evidence_adapter.py
components/northstar-agent-runtime/tests/test_sandbox_evidence.py
```

## 威胁模型

假设模型输出、工具参数、MCP 服务器返回、workspace 文件和外部命令均不可信。攻击者可能尝试：

- 通过工具参数访问 workspace 外路径、符号链接、宿主 socket 或凭据；
- 使用 mount、ptrace、bpf、keyring、io_uring 或进程控制逃逸；
- fork 炸弹、内存耗尽、无限输出或长时间占用 CPU；
- 修改事件日志、checkpoint、结果或恢复顺序；
- 在崩溃重试时重复执行外部写操作；
- 伪造“已完成”、模型版本、策略版本或安全检查结果；
- 利用模型/工具版本升级改变旧 run 的语义。

不把模型当作权限主体。模型产生的 ToolCall 只是提案，宿主策略、授权、审批、沙箱和独立验证器才是控制点。

## 关键不变量

### 沙箱不变量

1. workspace 必须是绝对路径、普通目录且不是 symlink。
2. workspace 只读；原型只允许 `network=none`、`rootless=true` 和 `seccomp=required|auto`。
3. cwd 必须位于 workspace 内；argv 不接受 NUL，环境变量只允许显式列出的合法大写名称。
4. 每次计划固定 memory、pids、CPU、wall-clock 上限，并生成 `plan_digest`。
5. 计划是数据，不是执行授权。只有受信宿主适配器可以把计划翻译成 bwrap/OCI/microVM 参数。
6. 任何策略放宽、未知值、路径越界或资源值异常都拒绝，而不是降级到更宽松模式。

### 执行不变量

1. 同一个 run 的事件 sequence 从 1 连续递增；事件包含 `previous_digest` 和自身 `digest`。
2. 事件日志不含墙钟时间或随机数；需要时间的策略必须由宿主以已记录的逻辑输入提供。
3. run/step/action 的身份必须稳定；相同 `action_key` 的已完成步骤只重放结果，不再调用 effect。
4. `started` 没有 `completed` 时拒绝自动重试，必须由 effect receiver 根据幂等键对账。
5. 所有事件和结果必须是有限、可 canonical JSON 序列化的数据。
6. 事件链、序列、状态转换或结果摘要不一致时，replay fail-closed。
7. `step.completed` 之前必须有与 `plan_digest` 匹配的沙箱证据；成功退出码本身不能绕过证据门禁。

## 组件设计

### `SandboxPolicy` 与 `SandboxPlan`

`SandboxPolicy` 是宿主可审计的输入，包含：

```text
workspace
readonly=true
network=none
seccomp=required|auto
rootless=true
memory_max_bytes
pids_max
cpu_max_percent
timeout_seconds
```

`policy.plan(argv, cwd, env_names)` 返回不可变 `SandboxPlan`。计划内容包含所有资源约束、cwd、workspace、命令和环境变量名称，并通过 SHA-256 生成 `plan_digest`。原型不保留环境变量值，避免把 secret 放进计划或日志。

生产宿主适配器必须在执行前再次校验：

```text
plan_digest
→ policy revision
→ bwrap/OCI/microVM profile digest
→ cgroup subtree ownership
→ seccomp profile digest
→ actual uid/gid/user namespace
→ actual network namespace/egress target
```

任一摘要或实际状态不匹配，必须拒绝执行。

### `SandboxEvidence`

`tools/sandbox_evidence.py` 是宿主适配器与确定性内核之间的窄证据合同。它要求宿主返回并摘要固定字段：

```text
plan_digest
backend / runtime_digest
rootless / workspace_readonly
network_mode
seccomp_loaded / seccomp_profile_digest
cgroup_enforced / cgroup_path
effective_memory_max_bytes / effective_pids_max / effective_cpu_max_percent
descendant_pids
```

验证器拒绝以下情况：计划摘要不匹配、有效资源限制比计划更宽、rootless 或只读挂载未证明、network 不是 `none`、required seccomp 未加载、cgroup 未生效、仍有 descendant PID，或证据自身摘要损坏。证据验证成功也只表示“宿主报告的边界与计划一致”，不替代内核实测；生产 verifier 仍应读取 cgroup、`/proc`、seccomp 状态和运行时返回的 profile 摘要。

`sandbox_evidence_adapter.py` 将 `os_sandbox.SandboxResult` 和 `SandboxRequest` 转换为该合同的原始 JSON。它要求宿主显式提供 runtime/profile 摘要、rootless、只读挂载、cgroup 路径和 descendant 数量，不从退出码猜测这些事实。process backend 可以被记录用于诊断，但 `verify_evidence()` 永远拒绝它作为 OS 沙箱；只有 bwrap 或其他经过批准的强隔离 backend 才能进入 kernel completion gate。

### `DeterministicKernel`

原型事件种类：

```text
run.created
step.planned
step.started
step.completed
step.failed
```

每个事件类似：

```json
{
  "schema": "northstar.kernel-event.v1",
  "run_id": "run-1",
  "sequence": 3,
  "kind": "step.completed",
  "payload": {
    "step_id": "step-1",
    "action_key": "effect-1",
    "result": {"ok": true},
    "result_digest": "sha256:..."
  },
  "previous_digest": "sha256:...",
  "digest": "sha256:..."
}
```

`replay()` 逐行验证 JSON、schema、sequence、previous digest、自身 digest 和状态转换，然后生成 `KernelState`。它不会接受“最后一行看起来成功”的快捷路径。

### 副作用边界

原型使用以下诚实语义：

```text
事件日志至少一次记录
+ effect receiver 以 action_key 去重
= 可实现端到端幂等
```

`run_step()` 在写入 `step.started` 后调用 effect。若进程在 effect 完成后、`step.completed` 落盘前崩溃，新的内核看到 `started`，抛出 `RecoveryRequired`，不会盲目重做。宿主必须向外部 receiver 查询 `action_key`：

```text
receiver.has(action_key)
  ├─ yes: 取得已提交结果，追加 completed/reconciled
  ├─ no: 由 receiver 以相同 action_key 重发，要求其幂等
  └─ unknown/error: 保持暂停，转人工处理
```

这比宣称 exactly-once 更安全。跨数据库、支付系统、云 API 或 shell 的真实 exactly-once 仍取决于接收端去重和事务边界。

## 生产执行流程

```text
1. Host 接收 RunRequest
2. 计算 policy/profile/工具/模型/输入摘要
3. 生成并签名 SandboxPlan
4. Kernel append run.created / step.planned
5. Supervisor 持有 lease，启动受信 sandbox adapter
6. Adapter 创建 rootless namespace 和 cgroup v2 subtree
7. Adapter 加载 seccomp、no_new_privs、capability drop 和只读映射
8. Kernel append step.started
9. Worker 执行；输出限长并只写受控临时目录
10. 独立 verifier 检查 exit、产物、策略和资源证据
11. Kernel append step.completed 或 step.failed
12. Seal service 封存事件、计划、profile、验证和证据摘要
13. 崩溃时 Supervisor 停止心跳；新 worker replay 并执行 receiver reconcile
```

### cgroup v2 最小配置

对每个 run 建立独立子树，至少配置：

```text
memory.max
memory.high
pids.max
cpu.max
io.max（如果块设备边界明确）
```

worker 只能管理自己被委派的子树，不能写父树的 `cgroup.subtree_control`，不能迁移其他 run 的 PID。读取并封存 `memory.events`、`memory.pressure`、`pids.events`、CPU throttling 和最终 PID 清单。

### seccomp 和运行时

复用仓库已有 `tools/seccomp.py` 的架构校验和 denylist/loader，但生产 profile 应由受信构建流程产生并 pin digest。普通任务至少要求：

```text
no_new_privs
capability drop
mount/pivot_root/ptrace/bpf/keyring/io_uring 等高风险 syscall 阻断
setpgid/setsid 与进程组回收策略一致
```

对真正不可信代码按风险选择 rootless OCI、gVisor 或微 VM。seccomp 不是完整隔离；网络、宿主 API、cgroup、文件系统、凭据 broker 和运行时本身必须分别约束。

## 故障与恢复状态

```text
PLANNED
  → STARTED
      → COMPLETED
      → FAILED
      → RECOVERY_REQUIRED

RECOVERY_REQUIRED
  → RECONCILED_COMPLETED
  → RETRY_WITH_SAME_ACTION_KEY
  → PAUSED_MANUAL_REVIEW
```

以下情况必须保持暂停：事件链损坏、profile digest 不一致、cgroup 证据缺失、sandbox 实际不是 rootless、seccomp 未加载、receiver 返回 unknown、checkpoint 落后于事件历史或输出/产物摘要不匹配。

## 原型用法

```python
from pathlib import Path
from tools.deterministic_kernel import DeterministicKernel, SandboxPolicy

policy = SandboxPolicy(Path('/srv/northstar/workspaces/run-1'))
plan = policy.plan(('python3', '-c', 'print("ok")'))

kernel = DeterministicKernel('/var/lib/northstar/runs/run-1/events.ndjson')
kernel.start_run('run-1', 'sha256:input')
kernel.plan_step('run-1', 'step-1', 'effect-1', plan.digest)
evidence = host_adapter.run_and_collect_evidence(plan)
result = kernel.run_step(
    'run-1', 'step-1', 'effect-1', lambda: {'exit_code': 0},
    plan=plan, evidence=evidence,
)
assert kernel.replay('run-1').completed_results['step-1'] == result
```

该示例只演示策略/日志契约。它不会启动命令；生产代码应把 `plan` 交给受信宿主 adapter，用 `verify_evidence(plan, raw_evidence)` 验证 adapter 返回的 sandbox/cgroup/seccomp 证据，再交给内核的 `run_step()`。

## 测试和上线阶段

本原型测试：

```sh
cd components/northstar-agent-runtime
python3 -m unittest tests.test_deterministic_kernel -v
```

上线前必须补充：

- fork/exec、SIGKILL、OOM、pids limit、输出上限和 cgroup 事件的 Linux 实测；
- bwrap/OCI/gVisor/微 VM 的 profile conformance；
- seccomp 在 x86_64/aarch64 的实际加载与拒绝 syscall 测试；
- symlink、特殊文件、宿主 socket、`/proc`、DNS、metadata 和 egress 负向探针；
- receiver durable dedup、崩溃窗口、网络重试和人工 reconcile；
- 事件日志并发写入、fsync/rename、磁盘满、权限变化和跨进程 lease；
- schema migration、历史 replay、策略/profile 版本固定和 canary rollout；
- tenant 隔离、秘密轮换、审计访问控制和封存存储的独立验证。

在这些验证完成前，本原型只能作为本地设计与合同测试，不能作为生产隔离或生产可靠性的证明。
