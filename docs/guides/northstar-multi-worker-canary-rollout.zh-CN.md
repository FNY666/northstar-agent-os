# Northstar 多 worker 并行解除隔离与 Canary Rollout

编排脚本：

```text
components/northstar-agent-runtime/tools/canary_rollout.py
```

该脚本使用“固定 wave、并发上限、canary 通过后才允许继续”的策略。它不会自动推进后续 wave，也不会自行清除 worker 的 quarantine marker。

## 设计原则

```text
选定一个 wave
→ 并行执行该 wave 的 unquarantine
→ 任一 worker 失败则暂停 wave
→ 全部成功后运行 wave canary
→ canary 失败则暂停后续操作
→ 人工/调度器重新调用下一 wave
```

默认模式只生成计划，不执行任何 worker 操作。

## Worker inventory

示例：

```json
{
  "workers": [
    {
      "worker_id": "worker-01",
      "worker_unit": "northstar-build-worker-01.service",
      "state_file": "/var/lib/northstar/quarantine/01/state.json",
      "approval_file": "/var/lib/northstar/quarantine/01/approval.json",
      "health_check": "/usr/local/libexec/check-northstar-worker-v2.sh",
      "incident_id": "INC-20261117-01",
      "cgroup_mount": "/sys/fs/cgroup"
    }
  ]
}
```

inventory 必须是普通文件，不能是 symlink；worker ID 不得重复；最多 256 个 worker；单 wave 最多 32 个 worker。

## 计划模式

```bash
sudo  python3 components/northstar-agent-runtime/tools/canary_rollout.py \
  --inventory /etc/northstar/worker-inventory.json \
  --unquarantine /usr/local/libexec/northstar-unquarantine-worker \
  --canary-check /usr/local/libexec/northstar-worker-canary \
  --output /var/lib/northstar/rollouts/ROL-001-wave-0.json \
  --wave-size 2 \
  --concurrency 2 \
  --wave 0 \
  --rollout-id ROL-20261117-001
```

计划会明确：

- 当前 wave 编号和总 wave 数；
- 当前 worker 列表；
- 并行度；
- 预期状态转换；
- 后续 wave 不会自动推进。

## Phase A：并行进入 RECOVERING

先执行 recover wave。该阶段可以启动 worker，但仍保持 scheduler admission blocked：

```bash
sudo  python3 components/northstar-agent-runtime/tools/canary_rollout.py \
  --inventory /etc/northstar/worker-inventory.json \
  --unquarantine /usr/local/libexec/northstar-unquarantine-worker \
  --canary-check /usr/local/libexec/northstar-worker-canary \
  --output /var/lib/northstar/rollouts/ROL-001-wave-0-recover.json \
  --wave-size 2 \
  --concurrency 2 \
  --wave 0 \
  --rollout-id ROL-20261117-001 \
  --apply --start
```

recover wave 只有在全部 worker 成功后才运行 canary。任一 worker 失败时：

```text
wave_status = PAUSED
next_wave_eligible = false
canary = skipped
```

## Phase B：Canary 通过后提升 READY

确认 RECOVERING worker 的 canary 通过后，再对同一个 wave 执行 promote：

```bash
sudo  python3 components/northstar-agent-runtime/tools/canary_rollout.py \
  --inventory /etc/northstar/worker-inventory.json \
  --unquarantine /usr/local/libexec/northstar-unquarantine-worker \
  --canary-check /usr/local/libexec/northstar-worker-canary \
  --output /var/lib/northstar/rollouts/ROL-001-wave-0-promote.json \
  --wave-size 2 \
  --concurrency 2 \
  --wave 0 \
  --rollout-id ROL-20261117-001 \
  --apply
```

promote 成功后，该 wave 的 worker 才会解除 scheduler block。生产实现中，`--canary-check` 应至少检查：

- worker systemd active；
- worker-owned cgroup v2 health check；
- `memory.pressure` 在稳定阈值内；
- 最近窗口没有新增 `oom_kill`；
- 没有残留 build child；
- seccomp/bwrap/profile pin 正确；
- 一个低并发 build canary 完整通过；
- canary 产物未进入正式发布路径。

## Wave 推进规则

只有以下条件同时满足，人工或上层调度器才可调用下一 wave：

```text
当前 wave 的所有 worker returncode == 0
canary returncode == 0
wave_status == PASSED
next_wave_eligible == true
所有 worker 报告 scheduler_blocked 状态符合预期
```

下一 wave 必须显式指定：

```bash
--wave 1
```

脚本不会根据 `wave_status` 自动启动 wave 1，也不会在单次运行中遍历全部 wave。

## 并发与限流边界

- 最大 inventory：256 workers；
- 最大单 wave：32 workers；
- `--concurrency` 由 operator 显式指定；
- 默认 `--concurrency=1`；
- 每个 worker 的 unquarantine 命令独立超时；
- 某个 worker 失败不会取消其他已经启动的 worker，但整个 wave 会暂停；
- canary 只在整个 wave worker 操作成功后执行；
- canary 失败不自动 rollback，也不推进下一 wave；
- 失败 worker 仍由自身 unquarantine 脚本保持 QUARANTINED 或 RECOVERING 失败关闭语义。

## Rollout report

输出文件包含：

```json
{
  "schema": "northstar.worker-canary-rollout.v1",
  "rollout_id": "ROL-20261117-001",
  "wave_index": 0,
  "wave_count": 4,
  "worker_results": [],
  "canary": {},
  "wave_status": "PASSED",
  "next_wave_eligible": true,
  "circuit_breaker": "CLOSED",
  "pause_reasons": []
}
```

报告必须进入受信运维目录，不允许由候选构建过程写入。建议通过日志系统和对象存储做追加式归档。

## 失败关闭

以下情况停止当前 wave：

- inventory schema 错误；
- worker unit 不安全；
- executable 是 symlink、不可执行或不是普通文件；
- unquarantine returncode 非 0；
- evidence/approval/health check 失败；
- canary returncode 非 0；
- rollout report 无法原子写入；
- 控制器发现未知 wave；
- 控制器身份或路径边界不符合要求。

不要采用：

```text
单个 worker 失败仍继续下一 wave
canary 失败仍开放 scheduler
直接把所有 worker 并发 promote
忽略 OOM 或 pressure 结果
自动删除 quarantine marker
自动回滚并重新打满并发
```

## 集成测试

```bash
PYTHONDONTWRITEBYTECODE=1  \
  python3 -m pytest -q \
  components/northstar-agent-runtime/tests/test_canary_rollout.py \
  components/northstar-agent-runtime/tests/test_canary_rollout_chaos.py
```

当前结果：

```text
10 passed
```

覆盖：

- 计划模式只读取 inventory，不执行命令；
- wave 切分和单 wave 选择；
- 多 worker 并行执行后再运行 canary；
- worker 失败时跳过 canary 并暂停 wave；
- canary 失败时禁止后续 wave 推进；
- worker 超时、canary 超时和 evidence manifest 损坏的稳定原因码。

完整故障演练方案见：

[Northstar canary rollout 混沌工程与故障演练方案](Northstar-canary-rollout-chaos-drill-plan.zh-CN.md)
