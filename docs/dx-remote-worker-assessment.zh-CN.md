# 远程/托管 worker 评估（P3-3，T5 已修订）— 中文

> 编制 2026-09-07（P3-3）；**修订 2026-09-07（T5 实质化）**：就绪度 89 → 94，
> ops 缺口由四项收窄为两项实现项；本页为 living 文档，历史基线见
> `docs/dx-benchmark-2026.zh-CN.md` 的 P3-3/P3-4/T5 批次记录。范围：
> **不自建云**——评估把既有 sidecar/执行模型包装为远程 worker 的对接协议与
> 缺口。依据：仓库组件实测 + 可运行的就绪度评估器
> （`northstar-agent-interop/remote_worker.py`，含用例）；分数是便于比较的
> 主观判断，每一分都有下面的文字依据。

## 0. TL;DR

- **就绪度 94/100"可远程化"，0/100"已上云"**（`remote_worker.py --score`
  实算，36 条判据，CI 随 `make test` 重算）：契约、治理、审计、进程边界
  这些"决策内核"五域 100%；**ops 域 67%（4/6）** —— T5 已交付身份签发与
  密钥轮换 story（`docs/concepts/northstar-remote-identity.md`）与部署/监控
  操作指南（`docs/guides/remote-worker-operations.md`）；仍缺的是**完整网络传输就绪**（T20 已加入
  `northstar-agent-interop/ssh_forward.py` 的本地 Profile A lifecycle helper，
  但真实 host-key/worker 验证、Profile B execution transport 仍未完成；T21 仅加入 loopback control/replay slice）与**真实端到端
  canary 实跑**（操作配方：`examples/remote-canary/`，探针在 CI 里对真实 socket
  服务端回路验证，但按设计从未在 CI 触碰真实主机）。
- **推荐路径不是自建云**：短期 = sidecar socket 走 SSH（成本最低、复用现有
  协议）；中期 = durable-run runner 加网络传输 + 容器化（托管 fleets）；
  若 OpenBot 生态成熟则走 interop 托管适配器。
- 红线延续：远程 worker 只是 sidecar 的**传输变体**，不是新的治理面——同一
  套 run contract、host 签名 grant、opaque workspace、事件/审计、可验证收据。

## 1. 现状资产（能直接复用的）

| 层 | 组件 | 对远程化的意义 |
|---|---|---|
| 请求/收据契约 | northstar-run-contract（northstar.run.v1） | 编排方↔worker 的版本化结构边界；schema 版本即失配警报 |
| 授权 | northstar-host | 默认拒绝 + 签名短期 grant（含 policy_revision/expiry/capabilities）；opaque workspace |
| 长跑机制 | northstar-durable-run | 追加式事件史、lease、逐调用 action gate、独立后置校验——托管 worker 崩溃存活与"可验证汇报"的机制 |
| 进程边界 | northstar-agent-interop process_adapter/process_backend | 版本钉死的 CLI worker 边界（无 shell、绝对路径、argv 模板、env 白名单、有界输出、进程组终止）——即"本地进程变体的远程版" |
| 审计 | audit.ndjson/1 | 运行转录/事件/授权统一导出 |
| 沙箱委派先例 | northstar-codex-sidecar | 决策↔执行两分的现存模型，远程化 = 把"doing 半"搬走 |

## 2. 协议映射（远程 worker = sidecar 的传输变体）

```text
orchestrator(决策半) ──run request(northstar.run.v1)──▶ host(授权)
host ──签名 grant(policy_revision/expiry/capabilities)──▶ remote worker(执行半)
remote worker: 绑定先验 → opaque workspace → 有界执行 → action gate → 事件史
remote worker ──run receipt(v1, 结构化, 幂等键)──▶ orchestrator（可对账）
```

六条传输属性（从本地路径原样继承，见
`docs/concepts/northstar-remote-worker.md`）：同一契约 / host 持钥 /
opaque workspace / 有界且版本钉死 / 可审计 / 可验证。

## 3. 传输选型评估

| 选项 | 契合度 | 成本 | 说明 |
|---|---|---|---|
| sidecar socket 走 SSH | 单私有 worker 最高 | 低 | 现协议 + Unix socket over SSH，无新协议 |
| 容器 + durable-run runner 作 sidecar | 托管 fleets 最高 | 中 | 为 runner 加网络传输；需身份/密钥轮换 |
| OpenBot 生态（interop 已铺垫） | 战略性 | 中 | 对齐 A2A 式 interop 边界；取决于生态可用性 |
| 自建新 HTTP 服务 | 最低 | 高 | 否：重复既有契约/host/durable 层 |

## 4. 就绪度评估器（remote_worker.py）与用例

- 评估器覆盖 6 大域 36 条判据，每条判据都对准仓库内可静态核验的真实符号；
  判据质量本身有测试背书（见 test_remote_worker），文档数字跟随实算结果，
  不会与代码漂移。
- 判据只读取仓库内可静态核验的事实（模块是否存在、关键符号是否导出、
  常量/字段/必需项是否定义、互操作函数是否带版本校验等）——CI 里
  `python3 -m remote_worker --score` 与每次 `make test` 都会重算，**评估不
  会与代码漂移**。
- 域得分（/100）：contracts **100**、host **100**、durable-run **100**、
  interop **100**、audit **100**、ops **67**（4/6）。综合 **94**（34/36）。
- 剩余缺口明细（评估器注释与本文档同步）：**完整网络传输就绪**（T20 的
  `ssh_forward.py` 只覆盖本地 Profile A lifecycle，T21 的
  `durable_transport.py` 只覆盖 loopback control/replay；真实 host-key/worker
  验证、Profile B execution transport 仍未做）与**真实 canary 实跑**（配方已交付）——
  需真实主机才能翻转；编排调度、远程 API 面不在当前批范围。

## 5. 结论与后续

- P3-3 交付 = **协议文档 + 评估文档 + 可运行评估器（含 CI）**；零部署、
  零网络、零自建云，未引入任何运行时依赖。
- T5（docs phase）已把四项 ops 缺口实质化两项（story/指南 = 仓库内权威
  工件，计分器随之 89→94）；T20/T21 补上了本地 Profile A lifecycle 与 loopback
  control/replay slices，但仍保留真实主机 canary 与完整 Profile B execution
  transport 的翻转门槛；或按生态路线走 interop 托管适配器。
- 版本仍为对齐 `0.1.0.dev0` **未发布**（守就绪门）。
