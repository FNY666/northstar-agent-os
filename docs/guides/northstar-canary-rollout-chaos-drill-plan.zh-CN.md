# Northstar `canary_rollout.py` 混沌工程与故障演练方案

## 目标

验证生产多 worker 并行恢复期间，以下故障不会导致调度器误开放或后续 wave 误推进：

1. 部分 worker 恢复命令超时；
2. 全部 worker 完成但 wave canary 失败或超时；
3. 证据 manifest 在恢复期间损坏或摘要不匹配；
4. 选定 wave 失败后，未选中的后续 worker 不会被调用。

演练验证对象是编排器的断路机制，不是攻击生产 worker。默认使用 mock command boundary；禁止向真实 systemd、cgroupfs、worker service 或生产 scheduler 注入故障。

## 断路不变量

任何 wave 发生故障时，报告必须满足：

```json
{
  "wave_status": "PAUSED",
  "circuit_breaker": "OPEN",
  "next_wave_eligible": false,
  "pause_reasons": ["<stable reason code>"]
}
```

允许的原因码：

- `WORKER_TIMEOUT`：worker unquarantine 超时；
- `WORKER_FAILED`：worker unquarantine 返回非零；
- `CANARY_TIMEOUT`：canary 检查超时；
- `CANARY_FAILED`：canary 检查返回非零；
- `EVIDENCE_MANIFEST_INVALID`：输出表明证据 manifest 不匹配、无效或损坏。

失败 worker 的 quarantine、evidence 和 scheduler block 由 `unquarantine_worker.py` 继续负责；rollout 控制器不能自行删除 marker 或强制 promote。

## 故障矩阵

| 场景 | 注入点 | 预期结果 | 禁止行为 |
|---|---|---|---|
| 部分节点超时 | 某 worker 返回 `timeout=true, returncode=null` | `PAUSED`、`WORKER_TIMEOUT`、跳过 canary | 继续下一 wave |
| Canary 卡住 | canary 返回 `timeout=true` | `PAUSED`、`CANARY_TIMEOUT` | 开放 scheduler |
| Canary 失败 | canary 返回非零 | `PAUSED`、`CANARY_FAILED` | 自动 promote 后续 wave |
| Manifest 损坏 | worker 输出 manifest mismatch/corrupt 且返回非零 | `PAUSED`、`EVIDENCE_MANIFEST_INVALID` | 忽略摘要错误 |
| 选定 wave 失败 | wave 0 失败、inventory 仍有 wave 1 | 仅调用 wave 0 worker | 自动调用 wave 1 |

## 测试实现

混沌测试文件：

```text
components/northstar-agent-runtime/tests/test_canary_rollout_chaos.py
```

测试通过 monkeypatch `run_command()` 注入故障，不会执行 shell 命令。覆盖：

- 部分 worker 超时并确认 canary 未执行；
- canary 超时并确认所有 worker 已完成后才打开断路；
- evidence manifest 摘要损坏并确认后续 wave worker 没有命令记录；
- 报告中的 `pause_reasons`、`circuit_breaker` 和 `next_wave_eligible` 一致。

执行：

```bash
cd .
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m pytest -q \
  components/northstar-agent-runtime/tests/test_canary_rollout.py \
  components/northstar-agent-runtime/tests/test_canary_rollout_chaos.py
```

## 生产前演练阶段

### 阶段 0：离线单元/集成演练

使用临时目录、mock inventory 和 mock executable。通过标准输出报告和 JSON 断言验证，不需要 root 外的任何生产权限；测试进程中的 root 检查使用 mock。

通过标准：所有场景的返回码为 3，报告写入成功，原因码稳定，后续 wave 无命令记录。

### 阶段 1：隔离 staging 集群

使用与生产相同版本的 `unquarantine_worker.py`、health check 和 canary check，但 inventory 指向专用 staging worker。一次只使用一个 wave，`--concurrency=1` 起步，再逐步提高到目标并发的 25%。

只允许注入：

- staging worker 的可恢复进程级延迟；
- staging canary 的人工失败码；
- staging evidence fixture 的摘要不匹配。

禁止注入真实 OOM kill、真实 cgroup 删除、seccomp 加载破坏或生产证据目录篡改。

### 阶段 2：生产 shadow/暗演练

只生成 plan，不加 `--apply`，将真实 inventory 的选定 wave 做 schema、路径、unit 和并发校验。canary check 必须为只读检查。报告写入独立演练目录，不改变 worker 状态。

### 阶段 3：受控生产 canary

只有变更审批、值班人员和回滚窗口均就绪后，才允许对一个明确 worker wave 使用 `--apply`。故障演练优先使用 canary 自身的受控失败返回，不直接破坏 worker 的内核边界。

## 观测与告警

每次演练至少保存：

- rollout report 原文；
- rollout ID、wave index、inventory digest；
- 每个 worker 的 returncode、timeout 标志和截断后的输出；
- canary returncode、timeout 标志和输出；
- `pause_reasons` 与 `circuit_breaker`；
- scheduler admission 状态；
- worker quarantine/evidence manifest 引用。

建议告警条件：

```text
wave_status == PAUSED
circuit_breaker == OPEN
next_wave_eligible == false
pause_reasons 包含 WORKER_TIMEOUT 或 EVIDENCE_MANIFEST_INVALID
```

## 通过/失败判定

演练通过要求：

- 任意一个 worker 超时都不会触发 canary 或下一 wave；
- canary 失败/超时都不会产生 READY 开放动作；
- manifest 摘要错误被识别为 fail-closed；
- 报告可被机器解析并含稳定原因码；
- 当前 wave 的其他已启动 worker 结果仍被完整记录；
- 不产生未授权的 shell 参数、systemd unit 或路径逃逸；
- 重新执行前必须由操作员显式选择 wave，不能依赖上一次“部分成功”自动续跑。

## 复盘输出

每次演练完成后形成一份事件记录：

```text
演练 ID
注入场景
注入时间窗口
目标 wave / worker
预期原因码
实际原因码
是否执行 canary
是否调用后续 wave
scheduler 是否保持阻断
证据 manifest 是否完整
修复项与责任人
```

若 `PAUSED` 报告缺少原因码、后续 wave 出现命令记录、或 scheduler block 状态不确定，演练判定失败，禁止进入下一阶段。
