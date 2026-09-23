# 摘要

## 研究结论

最完整的可迁移任务闭环不是单一 Agent/CLI 的特性，而是四类机制的组合：Temporal 的持久事件与 replay 恢复；Claude Code 的宿主层权限与工具前后 hook；GitHub Actions 的人工批准和固定身份 rerun；SWE-bench 的唯一 run identity、缓存边界和失败分类。

## 核心原则

- 平台回执、工具成功、日志存在和 benchmark resolved 都不能直接证明外部效果。
- timeout、disconnect、worker crash 或无响应后，目标状态默认为 `UNKNOWN_NEEDS_RECONCILE`，先独立 read-back，再决定 retry、resume、compensate 或人工介入。
- 重试必须由目标服务侧幂等键/条件写支撑；非幂等副作用不能盲重试。
- 最终成功应至少需要目标 read-back + postcondition/invariant + 可追溯证据。
- benchmark 通过不等于 production 通过。

## 证据等级

- verified：各官方原文直接支持对应平台行为。
- inferred：跨平台设计建议由上述事实推导而来。
- unknown：公开资料未证明不可变审计、自动外部 read-back、生产目标健康或统一补偿协议。

## 对象覆盖

Temporal：生命周期、暂停、replay、Activity 重试和幂等；Claude Code：权限、人工提示、PreToolUse/PostToolUse/Failure/Stop hooks；GitHub Actions：环境 reviewer、批准、rerun 的 SHA/ref/权限保持；SWE-bench：run_id+instance_id 缓存、日志重判定与 benchmark 失败分类。

## 下一切片

任务取消/超时/恢复后的 unknown 判定、幂等重试与补偿；需继续只查公开一手资料并写入新的隔离 `/tmp` 目录。
