# Northstar Agent OS 当前状态

> 状态快照：2026-10-02。本文汇总当前工作区状态；代码、配置和测试输出是最终依据；历史批次、对标报告和设计草案保留原始时间点，不代表今天的实现状态。

## 现在能用什么

- 产品入口：`bin/northstar` 和安装后的 `northstar`，提供 `agent`、`resume`、`sessions`、`doctor`、`bench`、`skills`、`plugin`、`mcp` 等命令。
- 治理 runtime：权限门、hooks、预算上限、子代理、会话与 checkpoint、fork resume、流式输出、重试预算、MCP stdio、Skills 审查、插件 bundle、workspace memory、并行只读工具和审计导出。
- 执行边界：`Shell` 默认拒绝；`--sandbox auto|bwrap|process` 支持 bubblewrap 优先和显式 process 回退。Codex Sidecar 只通过 Unix socket 工作，并使用 read-only、ephemeral 运行约束。
- Provider：离线 scripted provider；Anthropic provider；OpenAI Chat Completions 兼容 provider。真实 provider 的凭据、网络和服务质量属于宿主环境，不由仓库测试代替。
- 程序化入口：Python SDK 已可用；runtime 还提供源代码 TypeScript SDK，Node 22.6 以上可直接运行，不构建、不发布 npm 包。
- 组件：`northstar-run-contract`、`northstar-host`、`northstar-durable-run`、`northstar-agent-interop`、`northstar-agent-runtime` 有 `pyproject.toml`；`northstar-codex-sidecar` 是 shell/systemd 服务组件，不是 pip 包。

## 当前验证结果

```text
既有基线：Python 共收集 1,636 项（含文档测试），其中 runtime 跳过 5 项。
2026-10-21 候选分支 `feat/audit-verified-skill-loads-2026-10-21` 的 GitHub Actions [`Northstar tests`](https://github.com/FNY666/northstar-agent-os/actions/runs/39695887976) 全部通过：runtime `python -m pytest -q tests` 为 28,464 passed、14 skipped、710 subtests passed；guard verification 为 18,707 passed、14 skipped；文档、sidecar、TypeScript、CLI、打包和 benchmark smoke 均通过。该结果来自 Ubuntu/Python 3.12 CI；本轮环境没有本地 shell runner。收集数不等于通过数。
TypeScript SDK：57 项 Node 测试通过
版本：0.1.0.dev0（五个 pip 组件与 runtime _version.py 对齐）
本轮操作：仅本地开发，未创建 tag、Release 或上传包；这不是远端发布历史查询。
```

推荐验证命令：

```sh
make test
make demo
make bench
make release-check
make install-smoke
python3 tests/docbuild.py verify
```

`make install-smoke` 会构建五个本地 wheel，在临时 target 目录中用 `--no-index` 安装，再验证安装内容、CLI、治理基准和公共模块导入；它不会发布或修改 checkout 内的 `.venv`。

## 仍然明确不属于当前实现

- 没有托管云、团队 fleet 或生产级远程 Worker 服务。Profile A 的本地 SSH socket channel helper 已实现；Profile B 的 fleet transport 和真实主机 canary 阶段 2 仍未完成（阶段 1 于 2026-11-06 在 `muse-newapi@140.245.125.82` 实跑通过）。
- `northstar-agent-interop` 提供签名 attestation、handoff grant、process adapter 和 fake/local canary；它没有连接真实 Codex、Claude Code、Cursor、Hermes 或 OpenBot 后端。
- 远程 Worker 静态就绪度为 100/100（36/36，ops 6/6）`. CI 随 `make test` 重算。
  剩余缺口为阶段 2 的真实主机端到端 canary：phase 1 于 2026-11-06 在
  `muse-newapi@140.245.125.82` 实跑通过（证据：
  `examples/remote-canary/runs/2026-11-06-140.md`），phase 2 `FAIL: timed out`
 （worker 侧 `codex` 存在但未配置服务账号凭据，未增加任何凭据），标记为
  open/inconclusive，不构成信道失败。现有 spec、身份/轮换说明、运维指南
  和本地 recipe 不等于已部署服务。
- 没有交互式 TUI、IDE 插件、插件在线市场、浏览器/计算机操作或宿主机 Full Auto shell。
- Sidecar、host、durable-run 和 interop 的本地测试不构成生产隔离、企业身份、密钥管理、队列调度或合规存储保证。

## 文档维护规则

- 入口文档、组件 README 和本文一起对照实现更新；出现冲突时先核对代码与实际验证结果。
- `CHANGELOG.md`、`docs/superpowers/plans/` 和带日期的 benchmark/DX 报告是历史记录；修改实现后，应在本文和入口文档更新状态，并在历史文档顶部补充快照说明，而不是悄悄改写历史叙述。
- `docs/api/*.md` 由 `tests/docbuild.py` 生成，使用 `python3 tests/docbuild.py build` 更新，禁止手工维护。


## 2026-11-25 本地开发与验证补记

- `scripts/record_measurement.py` 的供应商 endpoint 归因现按解析后的 hostname 和 DNS 标签边界判断；`attackeropenai.com`、`openai.com.attacker.example` 及 userinfo 混淆不再被标为官方端点。
- 聚焦回归 `python3 -m unittest tests.test_code_task_measurement tests.test_runtime_module_inventory -v`：9 项通过。`make ts-test`：60 项通过。仓库测试：170 项通过。`python3 tests/docbuild.py verify`：8 个组件 API 页、1,877 个模块及 148 个 Markdown 文件校验通过。
- `make test` 在 `northstar-agent-interop` 中止：3 个子进程测试因子组件导入路径缺失而失败（分别报缺少 `authorization`/`binding`）。另行运行 runtime unittest 收集 19,566 项，25 项跳过、629 项错误；测试环境未安装 `pytest`，导致多个基于 pytest 的测试模块无法导入。上述失败与本轮 endpoint 归因改动无关，当前不据此声称完整 Python 测试套件通过。
- 修复后复验（2026-11-25）：interop 并发/锁测试子进程显式继承 interop、host、run-contract 源码路径；`test_route_ledger.py` 也独立引导 run-contract 路径。隔离 venv 使用仓库已锁定的 `pytest==8.3.4` 执行根目录 `make test`：sidecar 53、egress 33、run-contract 54、run-evidence 94、host 37、durable-run 499（11 skipped）、interop 260、runtime 18,937（24 skipped）、TypeScript 60、仓库文档 177，全部通过。系统 Python 未安装 pytest；依赖仅安装于 `/tmp/northstar-agent-os-test-venv`，未修改系统环境。`git diff --check` 通过。
- 生态扩展扫描与编程闭环加固（2026-11-25）：完成扩展生态雷达（[`docs/research/agent-ecosystem-radar-2026-11-25.zh-CN.md`](research/agent-ecosystem-radar-2026-11-25.zh-CN.md)）并落地三项代码强化：(1) 修复 `sdk.run_code()` 未透传 `check_inputs=task.check_inputs` 给 `CodePhaseMachine` 的契约漂移；(2) 在 `IsolatedCodeWorkspace.prepare()` 新增非执行、零秘密读取的不可信仓库准入回执 `admission.json`（`northstar.repository-admission.v1`）并接入 `manifest.json` 封存与 `scripts/check-code-run-evidence.py` 硬门校验；(3) 在 `audit_delivery_patch()` 新增 BenchJack 级 `python_startup_hook` / `test_runner_hijack`（`conftest.py` 强制通过 hook）与 `agent_config_poisoning`（`.mcp.json` / `.claude/settings.json` 等）交付阻断（24 题基准参考解 0 误报），并将 `code-security-lab` 扩展至 9 对恶意/良性对照用例。
- 薄 ACP v1 适配器原型、隔离 worktree 模式与双向审批 / CaMeL 数据流加固（2026-11-25）：新增零第三方依赖的 `components/northstar-agent-runtime/acp_server.py` 与 `northstar acp` 子命令（说明见 [`docs/guides/acp-adapter.md`](guides/acp-adapter.md)，Zed / Neovim 配置模板与离线冒烟脚本见 [`examples/acp/README.md`](../examples/acp/README.md)），支持 JSON-RPC 2.0 NDJSON stdio 协议（`initialize` / `session/new` / `session/load` / `session/set_mode` / `session/prompt` / `session/cancel`、`session/update` 流式通知、opt-in `--interactive-permissions` 双向 `session/request_permission` 单次绑定审批桥接，以及 `--code-worktree` / `--keep-worktree` 独立 Git worktree + `admission.json` 准入回执 + 每轮 `audit_delivery_patch()` 交付审计与不安全补丁自动降级 `refusal`）；同步在 `dataflow_policy.py`、`permissions.py`、`loop.py`、`sdk.py`、`cli.py` 与 TypeScript SDK（`sdk-ts/src/{options,events,index}.ts`）落地 CaMeL 级不可信输入完整性污点追踪（`DataflowPolicy.camel_default()` / `camel_strict()`、`--dataflow-policy camel|camel-strict`、`sdk.RunOptions.can_use_tool`、TS `dataflowPolicy` 与 `untrusted_tainted` 归一化证据、跨工具与父子 subagent 双向污点传播及 resume 保守置污，污点触发特权 sink 升级审批或 fail-closed 拒绝），并将 `code-security-lab` 扩展至 10 对恶意/良性对照用例（新增第 10 题 `camel-repo-injection-taint`）。
