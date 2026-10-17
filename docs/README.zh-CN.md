# Northstar Agent OS

**一个带权限门、预算上限和审计日志的小型 agent 运行环境。**

> 中文名：北辰智能体系统

[English](../README.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [Español](README.es.md) · [한국어](README.ko.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Português (Brasil)](README.pt-BR.md) · [Italiano](README.it.md) · [Türkçe](README.tr.md) · [Tiếng Việt](README.vi.md)

**一句话说明：** Northstar 是一个小型的、还在打磨中的 agent 运行环境：统一入口 `northstar agent`、可见边界、可审计、可恢复。内核由 runtime / contract / host / durable / sidecar / interop 等子系统组成。**不是**已经完成的多智能体平台（无托管云、无并行舰队）；今天交付的是实实在在能用的基础件：**默认拒绝的沙箱 `Shell`**（有 bubblewrap 时 OS 隔离，否则诚实的 process 回退——见 [concepts/threat-model.md](concepts/threat-model.md)），以及 **Northstar Codex Sidecar**——一个受限的本地工作器适配器（read-only、ephemeral、仅 Unix socket）。
> English is the canonical project entry. Translations mirror its scope and security claims; update them when the canonical README changes.

## 它是什么

Northstar 面向希望**把活交给 AI 同事**、并要求其在明确边界内运行的人——而不是不受约束的「提示词加工具」循环，也不是需要手工拼装的零件目录。

- **产品路径：** `northstar agent "…"` — 默认开启会话落盘与每 turn 检查点  
- **内核路径：** `northstar run …` — 每个默认都显式（嵌入、CI、高阶用法）  
- **不变量：** 每次工具调用穿过权限门、hooks、预算天花板与审计；策略只能收紧  

产品脊梁与路线图：[next-gen-agent-os.zh-CN.md](next-gen-agent-os.zh-CN.md)。  
对标全球顶级 agent：[benchmark-top-agents-2026-09.zh-CN.md](benchmark-top-agents-2026-09.zh-CN.md)（2026-09 本地实测版）、[benchmark-top-agents-2026-10.zh-CN.md](benchmark-top-agents-2026-10.zh-CN.md)（2026-10 公开资料横向调研版）。

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
bin/northstar security scan --workspace .     # 密钥、Python/JS/TS/Go SAST、依赖与部分部署配置检查
bin/northstar security scan --workspace . --format sarif > northstar.sarif
bin/northstar security scan --workspace . --format sarif --compare-to previous.sarif > current.sarif
bin/northstar security scan --workspace . --format sarif --compare-to previous.sarif --new-findings-only --fail-on high > current.sarif
bin/northstar security probe                  # 临时靶场验证权限与工作区边界
bin/northstar sessions list --workspace .
bin/northstar bench                  # 公开治理基准（离线）
```

独立 `security` 命令由操作者手动启动。agent 运行也可通过 `--enable-security-tools` 显式注册本地工具：`SecurityScan` 只读当前工作区；`SecurityProbe` 还必须出现在 `--allow-tool` 中。探针在临时实验室验证默认权限拒绝、目录穿越读写、越界符号链接读写、`.northstar` 治理文件写保护，以及 Shell 的工作区外写入和治理目录写入边界。Shell 只执行固定的无害 `printf` canary，目标和读泄漏标记都由探针创建在临时目录，运行结束后自动清理；不连接公网、不触碰用户项目，也不是通用渗透测试器。bwrap 可将 `.northstar` 重新挂载为只读并保留 runtime 临时目录；process 回退无法隔离工作区内的子目录，会如实报告并使对应检查失败。探针还会用临时 Python、JS/TS 与 Go 源码验证输入到 Shell / SQL 的 AST 数据流、动态代码执行、Shell 命令、SQL 插值、HTML 注入、请求输入经同文件变量流向出站 URL、Node.js 文件系统 / 文件响应 API 和 Go 网络 / 文件 API、关闭 TLS 校验、弱随机 token 与 JWT `none` 算法，源码只作文本分析、不执行；探针还核对 SARIF 中的规则 ID、相对路径、行列和修复建议；JS URL 与路径流规则只跟踪同一文件内简单变量赋值，不解析 import 别名、多行调用、作用域或清洗函数；`JS009_PATH_TRAVERSAL` 规则覆盖常见 `fs` / `fs.promises` 和 `res.sendFile` / `res.download` API；Python SSRF 规则追踪 Flask / Django / Starlette 常见请求字段经简单赋值流向 requests、httpx、urllib 或命名 session / client 调用；新增 `PY012_PATH_TRAVERSAL` 规则追踪请求值经简单变量流向 `open`、`Path` 读写方法、文件响应及常见删除 / 复制 API；`PY013_COMMAND_INJECTION` 使用 Python AST 跟踪请求字段、`input()`、CLI 参数和环境变量流向 `os` / `subprocess` Shell 执行，支持常见导入别名、多行调用、赋值、f-string 与基础控制流；不跨函数追踪、不识别项目自定义校验器，也不把 Shell 转义当作命令允许列表的证明；`PY014_SQL_INJECTION_FLOW` 跟踪不可信输入进入 `execute` / `executemany` 等 SQL 查询接口，参数化查询将值单独传递时不会触发该数据流规则；现有 `PY004` sink 检查仍可能标记 `cursor.execute()`，且该流规则不跨函数追踪或验证自定义 SQL 标识符构造器。Go 规则 `GO001_UNTRUSTED_SSRF` / `GO002_PATH_TRAVERSAL` 追踪 Go Web 请求值经简单赋值流向 `net/http` 出站调用、`os` / `ioutil` 文件 API 和 `http.ServeFile` / `http.Dir`。Python SSRF、路径和 Go 规则仍是单文件文本启发式，不解析作用域、多行调用或清洗 / 路径包含校验；PY013 使用 Python AST，但不跨函数追踪或识别项目自定义校验器。扫描覆盖密钥、Python / JS/TS / Go SAST、依赖固定 / 来源和部分容器 / CI / Terraform 配置，finding 按严重级别排序并附修复建议；它不查询 CVE 数据库，也不会自动修改文件；CLI 可用 `--format sarif` 将 SARIF 2.1.0 写到 stdout，包含规则、工作区相对路径、行列和修复建议，可重定向导入 CI 代码扫描；添加 `--compare-to previous.sarif` 可对不超过 16 MiB 的 Northstar SARIF 基线标注 `baselineState`（`new` / `unchanged`）、稳定指纹和计数，匹配依据为规则、路径、脱敏消息、严重级别与重复项序号，行号变化不会单独导致 finding 变成新增。`--new-findings-only` 会把退出门禁限定为达到 `--fail-on` 严重级别的新增 finding，旧问题仍保留在 SARIF 中；它要求完整的 Northstar 基线，当前扫描遇到文件数上限或跳过候选文件时返回状态码 2。门禁计入所有扫描结果，即使 SARIF 详情被截断；SARIF 结果级 `baselineState` 只覆盖文档内的结果，`comparisonComplete` 标明这部分比较是否完整。规则可能漏报或误报，干净结果不能证明项目安全。

```sh
# 让 agent 检查当前工作区；只注册只读扫描器
bin/northstar agent --workspace . --enable-security-tools \
  --prompt "调用 SecurityScan 检查本地代码，并总结 findings"

# 同时显式注册并批准临时权限与隔离边界探针
bin/northstar agent --workspace . --enable-security-tools \
  --allow-tool SecurityProbe \
  --prompt "调用 SecurityProbe 验证 Northstar 权限与工作区隔离边界"
```

agent 扫描每次最多读取 1,000 个文本文件、每个文件 256 KiB，最多返回 100 条 finding；CLI 最多输出 1,000 条 finding 明细。模型不能传入目录或 URL。`--read-only` 会拒绝 `SecurityProbe`。

需要修复和复测时，可让 agent 先扫描拿到 `baseline_id`，再经单独授权使用 `Write` / `Edit` 修复，最后调用 `SecurityScan` 并传入 `compare_to`。比较结果列出已消失、新增和仍存在的发现；基线只在本次 agent 运行内有效。扫描器不代替 agent 写文件。

```sh
bin/northstar agent --workspace . --coding-mode --enable-security-tools \
  --allow-tool Write --allow-tool Edit \
  --prompt "先调用 SecurityScan 并保存 baseline_id；审阅发现后修复明确的问题，再用 compare_to 对该基线复测并汇报新增、消失和残留项"
```

编程任务可使用 `--coding-mode` 引导 agent 按“检查仓库 → 制定计划 → 修改 → 运行已授权的检查 → 审阅 diff”工作。运行前后，CLI 会独立比较 Git 工作区状态和脏文件内容，报告净改动文件、HEAD 与暂存区变化；还会汇总主 agent 与委派子 agent 的 Shell 调用结果、退出码、超时和隔离后端，并附委派路径；同时报告 `--verify` / 策略 `[[verify]]` 的主机侧检查 verdict。摘要会区分未配置的检查和已配置但未执行的检查；`contains` 检查的期望文本不会复制到摘要。它不依赖模型自述，也不执行仓库脚本。Git 忽略规则仍然生效；文件数和哈希读取有上限，超出时会标记 `coverage=partial`；非 Git 工作区会标记 `unavailable`。`--json` 在运行结果后追加一条 `type=coding_evidence` 记录。此模式不会自动授予文件写入或 Shell 权限；请只放行本次需要的工具：

```sh
bin/northstar agent --workspace . --coding-mode \
  --allow-tool Write --allow-tool Edit --allow-tool Shell \
  --prompt "修复这个问题，运行相关检查，并汇报 diff"
```

只读的编程审查可以使用 `--coding-mode --read-only`；它仍会输出工作区变化收据，正常情况下应显示 `changed_files=0`。这份收据只说明运行前后的 Git 可见净变化，不证明代码正确，也不证明检查通过；请结合 agent 汇报和实际检查结果审阅。

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

Northstar 还在一点点打磨。产品入口、治理内核与默认拒绝的沙箱 `Shell` 已真实可用；并行工具批与真实 interop 后端仍是后续工作。**没做完的东西不能当做完。**

## 贡献与维护

见 [CONTRIBUTING.md](../CONTRIBUTING.md) 与 [SECURITY.md](../SECURITY.md)。English is the canonical source for project scope; translations should be updated when it changes.

## 许可证

MIT，见 [LICENSE](../LICENSE)。
