# Northstar Agent OS

**面向自主 AI 同事的开放、可靠、可治理 Agent 操作系统。**

> 中文名：北辰智能体系统

[English](../README.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [Español](README.es.md) · [한국어](README.ko.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Português (Brasil)](README.pt-BR.md) · [Italiano](README.it.md) · [Türkçe](README.tr.md) · [Tiếng Việt](README.vi.md)

**一句话说明：** Northstar 是**次世代 Agent 操作系统**：统一入口 `northstar agent`、可见边界、可审计、可恢复。内核由 runtime / contract / host / durable / sidecar / interop 等子系统组成。**目前还不是已经完成的多智能体平台**（无托管云、无并行舰队）；今天交付的是焊死的产品路径 + 可证明的治理内核、**默认拒绝的沙箱 `Shell`**（有 bubblewrap 时 OS 隔离，否则诚实的 process 回退——见 [concepts/threat-model.md](concepts/threat-model.md)），以及 **Northstar Codex Sidecar**——一个受限的本地工作器适配器（read-only、ephemeral、仅 Unix socket）。
> English is the canonical project entry. Translations mirror its scope and security claims; update them when the canonical README changes.

## 它是什么

Northstar 面向希望**把活交给 AI 同事**、并要求其在明确边界内运行的人——而不是不受约束的「提示词加工具」循环，也不是需要手工拼装的零件目录。

- **产品路径：** `northstar agent "…"` — 默认开启会话落盘与每 turn 检查点  
- **内核路径：** `northstar run …` — 每个默认都显式（嵌入、CI、高阶用法）  
- **不变量：** 每次工具调用穿过权限门、hooks、预算天花板与审计；策略只能收紧  

产品脊梁与路线图：[next-gen-agent-os.zh-CN.md](next-gen-agent-os.zh-CN.md)。  
对标全球顶级 agent：[benchmark-top-agents-2026-09.zh-CN.md](benchmark-top-agents-2026-09.zh-CN.md)。  
执行路径与治理税深挖（第三轮审计，含毫秒数）：[execution-boundary-audit-2026-09.zh-CN.md](execution-boundary-audit-2026-09.zh-CN.md)。

## 当前发布了什么

- **产品入口** `northstar` / `bin/northstar` — Agent OS CLI（`agent` / `resume` + 内核命令）  
- `../components/northstar-agent-runtime/` — 受治理智能体循环（事件、hooks、三层权限门、预算、子智能体、仅追加会话、MCP、skills、插件）  
- `../components/northstar-codex-sidecar/` — 本地 Unix socket 服务：校验请求，以 read-only 模式运行 Codex，限制 I/O，脱敏错误，清理超时进程组  
- `../components/northstar-run-contract/` — 版本化 Run Request/Receipt、HMAC Run Binding、严格适配边界  
- 以及 host / durable-run / agent-interop 等内核子系统（见英文 README 全表）

仓库同时提供确定性测试、systemd 加固模板、保守安装/回滚脚本。

## Sidecar 如何工作

Sidecar 为每个 Unix socket 连接接收一个 JSON 请求：

```json
{"request_id":"demo-1","prompt":"Reply with OK","timeout_ms":10000}
```

返回一个有边界的 JSON 响应：

```json
{"request_id":"demo-1","status":"ok","text":"OK"}
```

主要特性：仅 Unix socket；Codex 使用 `--sandbox read-only` 与 `--ephemeral`；独立进程组，超时时 TERM→KILL；结构化错误与脱敏；专用服务用户与 systemd 加固。只有主机管理员明确安装并启用后，Codex 才会运行。

## 快速开始

**一行离线演示（无 API key、无网络）：**

```sh
make demo
```

**检出即用的产品入口：**

```sh
bin/northstar --version
bin/northstar agent --workspace . --provider scripted --scripted-text "ok" --prompt "hello"
bin/northstar resume latest --workspace . --prompt "continue" --scripted-text "ok"
bin/northstar sessions list --workspace .
bin/northstar bench                  # 公开治理基准（离线）
```

Sidecar 本地验证：

```sh
cd ../components/northstar-codex-sidecar
python3 -m unittest discover -s tests -p 'test_*.py' -v
sudo ./install.sh
```

## 适用对象

构建本地或自托管 AI 同事的开发者与运维：需要可测试、可审计、可停用、可续跑的 Agent OS。它不是托管 AI 产品，也不能单独替代完整的企业身份与隔离架构。

## 它不是什么

- 它**还不是**一个完整的多智能体操作系统（并行舰队、真实多后端 handoff 仍在脊梁路线图上）。OS 沙箱 `Shell` 已落地且**默认拒绝**；生产主机请安装 bubblewrap 以获得真实 OS 隔离。  
- 它不是托管服务，也不代表已经生产就绪。  
- 它不是通用宿主机 shell 执行 API。  
- 它不会单独完成调用方授权、每次运行隔离或父级取消传播。  
- 它不包含 Codex 凭据，也不提供 Codex 账号。  

**Not a complete autonomous-agent platform.**

## 与 OpenBot 的关系

Northstar 是独立维护、面向 OpenBot 兼容场景的项目。它不隶属于 OpenBot 或 CopilotKit，也未得到它们的官方认可。「兼容」只表示集成目标，不表示所有权、背书或安全等价。

## 安全边界

Sidecar 仅通过 Unix 权限认证调用方。生产集成还必须提供：调用方授权与身份绑定；按运行隔离工作区；取消传播；不记录敏感 prompt 的可观测性；健康检查与回滚；原生 Linux 进程树验证；对 Codex 自身配置的审查。

不要通过 TCP 代理暴露 Unix socket。不要提交 API key、OAuth token、Codex 登录状态、私钥、生产 `.env` 或用户 transcript。

## 项目状态

Northstar 正按**次世代 Agent OS** 增量建设。产品入口、治理内核与默认拒绝的沙箱 `Shell` 已真实可用；并行工具批与真实 interop 后端仍是后续脊梁工作。**未完成的自主智能体平台不能被当作已完成项目。**

## 贡献与维护

见 [CONTRIBUTING.md](../CONTRIBUTING.md) 与 [SECURITY.md](../SECURITY.md)。English is the canonical source for project scope; translations should be updated when it changes.

## 许可证

MIT，见 [LICENSE](../LICENSE)。
