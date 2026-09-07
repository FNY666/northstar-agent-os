# Northstar Agent OS

**面向自主 AI 同事的开放、可靠、可治理运行时组件。**

> 中文名：北辰智能体系统

[English](../README.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [Español](README.es.md) · [한국어](README.ko.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Português (Brasil)](README.pt-BR.md) · [Italiano](README.it.md) · [Türkçe](README.tr.md) · [Tiếng Việt](README.vi.md)

**一句话说明：** Northstar 是一个独立维护的项目，用于把明确的模型路由、本地工具边界、可审计性和可恢复执行组合成受治理的 AI 同事运行时。**目前真正发布的内容是 Northstar Codex Sidecar——一个受限的本地工作器适配器，而不是已经完成的自主智能体操作系统。**

> English is the canonical project entry. Translations mirror its scope and security claims; update them when the canonical README changes.

## 它是什么

Northstar 面向希望 AI 同事在明确边界内运行的开发者，而不是让系统停留在不受约束的“提示词加工具”循环中。项目关注小而可测试的构件：调用方可见的合同、受限执行、结构化结果和可恢复的运维流程。

项目采用渐进式建设方式。单个组件可以独立有用，但组件测试通过，并不证明完整智能体平台安全或适合生产环境。

## 当前发布了什么

本仓库当前提供六个互补组件：

- `../components/northstar-codex-sidecar/` — 本地 Unix socket 服务，负责校验请求，以 read-only 模式运行 Codex，限制输入和输出，脱敏错误，清理超时进程组，并返回结构化状态。
- `../components/northstar-run-contract/` — 版本化的 Run Request/Receipt 合同、带有效期的 HMAC Run Binding，以及把已验证运行交给 Sidecar 的严格适配边界。
- `../components/northstar-agent-runtime/` — 受治理的智能体循环：事件流、十个生命周期钩子、三层权限门、轮次/工具调用/美元预算三项独立上限、子智能体、仅追加会话、路径级 workspace 变更 receipt、有界内容寻址 checkpoint（inspect/diff/rewind/fork）、安全边界压缩、MCP stdio 工具传输、AGENTS.md、策略文件和可移植 `SKILL.md` 技能包。技能只读、默认拒绝，所有工具仍经过权限门和 hooks。
- `../components/northstar-host/` — 主机侧默认拒绝授权与 opaque `0700` 工作区候选实现；它重新验证绑定和授权，但不执行命令。
- `../components/northstar-durable-run/` — Run/Step/Event 合同、追加历史、checkpoint、lease、逐调用授权和独立后置校验的本地纵向切片；不是生产调度器或 sandbox。
- `../components/northstar-agent-interop/` — 后端中立的 Agent attestation、受限 handoff、opaque context 和 typed receipt 边界；尚未连接真实厂商后端。

仓库同时提供确定性离线测试、pip 打包、CLI doctor/dry-run、sessions 审计导出、API 文档、systemd 加固模板、保守的安装脚本和回滚脚本。

## Sidecar 如何工作

Sidecar 为每个 Unix socket 连接接收一个 JSON 请求：

```json
{"request_id":"demo-1","prompt":"Reply with OK","timeout_ms":10000}
```

返回一个有边界的 JSON 响应：

```json
{"request_id":"demo-1","status":"ok","text":"OK"}
```

主要特性：

- 仅使用 Unix socket，不提供 TCP 监听器。
- 严格请求白名单：`request_id`、`prompt`、`timeout_ms`。
- 限制 prompt 和超时时间。
- Codex 使用 `--sandbox read-only` 和 `--ephemeral` 运行。
- 独立进程组，超时时先 TERM、再 KILL 清理。
- 每个连接都有读取截止时间，并使用有上限的工作器池。
- 结构化错误分类和敏感信息脱敏。
- 专用服务用户和 systemd 加固模板。
- 只有主机管理员明确安装并启用服务后，Codex 才会运行。

## 快速开始

零凭据、零网络的离线演示：

```sh
make demo
```

这会运行一个完整的受治理循环（Read、权限门、预算/轮次上限、事件流和
追加式 transcript）。runtime 也可安装并进行环境自检：

```sh
cd components/northstar-agent-runtime
pip install .
python3 -m cli --version
python3 -m cli doctor --workspace .
python3 -m cli skills check --workspace .
```

要求：

- Linux 与 Python 3.10 或更高版本。
- 已单独安装、且服务用户可执行的 `codex` 程序。
- 用于所提供服务单元的 systemd。
- 专用的非特权服务用户和工作区。

在组件目录中运行本地验证：

```sh
cd components/northstar-codex-sidecar
python3 -m py_compile sidecar.py transport.py service.py sidecar_socket.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
sh -n install.sh rollback.sh
```

若要查看并安装保守的服务生命周期：

```sh
sudo ./install.sh
sudo systemctl enable --now northstar-codex-sidecar.service
```

默认从 `PATH` 查找 Codex；主机使用非标准路径时可显式设置 `CODEX_BIN`。启用前请审阅脚本、服务用户、路径和权限。

## 适用对象

Northstar 适合构建本地或自托管 AI 同事运行时的开发者与运维人员，他们需要一个可测试、可审计、可停用、可回滚的窄范围执行组件。它不是托管 AI 产品、不是一键安全保证，也不能替代完整的身份、策略、工作区和可观测性架构。

## 它不是什么

- 它还不是一个完整的多智能体操作系统。
- 它不是托管服务，也不代表已经具备生产就绪性。
- 它不是通用 shell 执行 API。
- 它不会单独完成调用方授权、每次运行隔离或父级取消传播。
- MCP 目前是最小 stdio 工具客户端，不是完整的远程 MCP、插件市场或托管平台。
- 它不包含 Codex 凭据，也不提供 Codex 账号。

**Not a complete autonomous-agent platform.**

## 与 OpenBot 的关系

Northstar 是独立维护、面向 OpenBot 兼容场景的项目。它不隶属于 OpenBot 或 CopilotKit，也未得到它们及其维护者的官方认可。Sidecar 的设计目标是接入 OpenBot 风格的运行时，但不声称属于上游 OpenBot 仓库。

“兼容”只表示集成目标，不表示所有权、背书或安全等价。

## 安全边界

Sidecar 仅通过 Unix 权限认证调用方。生产集成还必须提供：

- 调用方授权和身份绑定；
- 按运行或按参与者隔离工作区；
- 从父运行时传播取消信号；
- 不记录敏感 prompt 的结构化可观测性；
- 健康检查和回滚流程；
- 原生 Linux 并发及进程树验证；
- 对 Codex 自身账号、网络和工具配置进行审查。

不要通过 TCP 代理暴露 Unix socket。不要提交 API key、OAuth token、Codex 登录状态、私钥、生产 `.env` 文件或用户 transcript。

## 项目状态

这是 Northstar 的首个公开组件。更大的 Northstar Agent OS 运行时仍在逐步建设。运行时身份绑定、按运行授权工作区、取消传播、原生 Linux 端到端验证和生产部署集成，仍属于主机侧责任或未来工作。**未完成的自主智能体平台不能被当作已完成项目。**

进程组清理应在目标原生 Linux 发行版上验证；移动 Linux 环境中的信号和 PID 回收行为不一定具有代表性。

## 贡献与维护

请查看 [CONTRIBUTING.md](../CONTRIBUTING.md) 了解证据、测试、安全、兼容性和回滚要求；安全问题请查看 [SECURITY.md](../SECURITY.md)。English is the canonical source for project scope; translations should be updated when it changes.

## 许可证

MIT，见 [LICENSE](../LICENSE)。
