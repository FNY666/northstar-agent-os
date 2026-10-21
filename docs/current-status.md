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

- 没有托管云、团队 fleet 或生产级远程 Worker 服务。Profile A 的本地 SSH socket channel helper 已实现；Profile B 的 fleet transport 和真实主机 canary 仍未完成。
- `northstar-agent-interop` 提供签名 attestation、handoff grant、process adapter 和 fake/local canary；它没有连接真实 Codex、Claude Code、Cursor、Hermes 或 OpenBot 后端。
- 远程 Worker 静态就绪度为 97/100（35/36，ops 5/6）。剩余缺口是真实主机端到端 canary 实跑；现有 spec、身份/轮换说明、运维指南和本地 recipe 不等于已部署服务。
- 没有交互式 TUI、IDE 插件、插件在线市场、浏览器/计算机操作或宿主机 Full Auto shell。
- Sidecar、host、durable-run 和 interop 的本地测试不构成生产隔离、企业身份、密钥管理、队列调度或合规存储保证。

## 文档维护规则

- 入口文档、组件 README 和本文一起对照实现更新；出现冲突时先核对代码与实际验证结果。
- `CHANGELOG.md`、`docs/superpowers/plans/` 和带日期的 benchmark/DX 报告是历史记录；修改实现后，应在本文和入口文档更新状态，并在历史文档顶部补充快照说明，而不是悄悄改写历史叙述。
- `docs/api/*.md` 由 `tests/docbuild.py` 生成，使用 `python3 tests/docbuild.py build` 更新，禁止手工维护。
