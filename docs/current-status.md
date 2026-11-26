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

## 2026-11-25 生态扩展复核与模块盘点改进

- 扩展核对 Goose/oi-kit、OpenHands Software Agent SDK、Hermes Agent、MCP Registry/reference servers、Pi 与 OpenCode 的官方仓库/README；核验公开社区入口。仅记录可公开验证的项目边界与自述，未加入或读取私人群聊，也不声称覆盖全部 AI 项目。
- `scripts/classify-runtime-modules.py` 现在能发现常见 `importlib.import_module`、`builtins.__import__` 与 `importlib.util.spec_from_file_location` 别名形式；加入运行时 trace 后识别出生产路径动态加载 `bash_parser.py`，并将字面量模块名纳入静态图。新增回归覆盖，模块盘点器 3 项、运行时 trace 4 项通过。
- 当前静态复算：1,579 模块、189 个静态可达、1,390 个待人工复核、29 个动态导入站点、0 个解析错误。静态可达不代表 Core 获批；动态计算模块名仍需人工复核。
- 新增显式运行时 import trace 工具。离线 `python3 -m cli bench` 通过 169/169 项；实际观察 161 个 runtime 文件，0 个不在静态可达集，28 个静态可达文件未被这条单一命令导入（不能据此判断为未使用）。结果 JSON 留在 `/tmp`，未纳入 Git。
- 完整报告：[`docs/ecosystem-survey-2026-11-25.zh-CN.md`](ecosystem-survey-2026-11-25.zh-CN.md)；盘点说明：[`docs/architecture/runtime-module-inventory.md`](architecture/runtime-module-inventory.md)。
- 本轮根目录 `make test` 在临时 venv（`pytest==8.3.4`）中收集 18,944 项、24 项跳过；sidecar、egress、run-contract、run-evidence、host、durable-run、interop 均通过，runtime 发现 4 项失败：Landlock TCP 测试收到 `ConnectionRefusedError` 而非预期的拒绝；2 项 provider-temperature 测试本地 endpoint 未被调用；1 项 run-evidence 测试返回 `error_evidence_incomplete`。这 4 项未触及本轮修改的模块盘点器，故不声称本轮全仓测试通过。模块盘点 3 项、文档结构 3 项、TypeScript 60 项、docbuild verify 均通过。
- 后续继续（同日）：新增 `scripts/trace-runtime-imports.py`，对显式命令做有限时的临时 import tracing 与静态差异报告；4 项 tracer + 3 项盘点器回归通过。离线 `python3 -m cli bench` trace 通过 169/169，观察 161 个 runtime 文件，静态图外 0 个、静态未观察到 28 个。运行时发现 `bash_parser.py` 的文件位置加载路径，并补上 `spec_from_file_location` 识别；盘点更新为 1,579 / 189 / 1,390 / 29。报告 JSON 保存在 `/tmp`，不是仓库产物。
- 继续自查后修正两个边界：静态盘点器以前无法将 `import_module(".child", package=...)` 映射到包内依赖；现对字面量包名和 `__package__` 作有限解析，计算包名仍保持未解析。Tracer 现在拒绝 NaN/Infinity/过大的 timeout；静态根缺失或语法错误时不启动目标命令。新增覆盖后，当前聚焦回归为 tracer 6 项 + module inventory 4 项通过。
- 再审发现旧 `inventory_sha256` 只覆盖导入图/分类，没有绑定源文件内容；相同 import 但功能代码变化会保留旧摘要。现将输出升为 schema v2，为每个 `.py` 文件加入 `source_sha256`，并测试“代码变化、依赖不变时总摘要也变化”。本地 v2 digest：`533ad0d4d3d633399fb64809936b9049ee11f9224205c03074cab4cde89b315f`。
- 按承诺进一步对 scripted agent-read、resume、code dry-run 与 code 执行/验证路径做 trace；各路径观察 66–70 个 runtime 文件，观察到的模块均落在静态可达集。五个路径样本合计观察到 71 个不同 runtime 文件；差异主要符合各路径功能（code 路径触达 `code_task.py`、`tools/code.py`、`tools/resource_limits.py`）。单次未加载不等于未使用，trace JSON 留在 `/tmp`。
- 回查上轮测试失败：运行环境 Landlock ABI 为 2，低于 TCP 网络规则所需 ABI 4；TCP deny 测试现在按能力跳过。`openai` 是 runtime 可选依赖，未安装时本地 HTTP provider 测试明确 skip，不再错误报“endpoint 未调用”。`run_evidence` 文件单独复验 8 项通过；完整套件尚未重跑。
- 修正了同一 ABI 边界的状态报告：`tools/os_sandbox.py` 与 `doctor` 以前在 Landlock ABI 2 时仍声称 Landlock 拒绝 TCP；现在按 ABI 分支明确显示“Landlock TCP enforcement unavailable”，并保留 seccomp 独立状态。`test_os_sandbox.py` 63 项（3 skipped）、`test_cli.py` 113 项（4 skipped）、Landlock 21 项（1 skipped）、run-evidence 8 项通过；provider-temperature 2 项因可选 SDK 缺失跳过。

## 2026-11-25 蓝队边界：编码不等于语义（defensive-agent.v2）

- 实测缺陷：`defensive_agent.assess()` 是用户提示、hook 上下文、工具输入、工具输出、压缩摘要与 provider 载荷共同经过的蓝队检查点，但它只匹配明文。同一条 "ignore previous instructions" 的 base64（36 字符，低于 injection detector 的 40 字符载体阈值）、百分号编码、HTML 实体、`\xNN` 转义、西里尔同形字、emoji 拆词六种形式，修复前全部返回 `allow`，明文形式返回 `review`。
- 修复：边界在词法规则之前先检查同一输入的有限、可逆视图——百分号解码、HTML 实体、`\xNN`/`\uNNNN` 转义、可解码的 base64/base32 片段、拉丁骨架折叠（西里尔/希腊同形字、兼容连字），以及词内分隔符折叠（`ig❤nore`）。这让 `evasion_corpus.py` 自己声明的“编码不改变载荷含义、门必须检查解码内容”在真正执行的门上成立。
- 边界：每次评估最多 8 个视图、每视图 8,192 字符、base64 与百分号各 6 段。`D-INJ-003`（编码）按 review 报告，只有解码视图命中越狱时才与明文一起构成 block；仅“削弱信号”的折叠记为 `D-INJ-004`，单独绝不 block。发现项只记录转换名与规则名，不记录解码后的载荷文本。
- 实测开销：2.8 KB 工具结果 +0.9 ms；90 KB 文本 +12 ms（受 `_MAX_ASSESS_CHARS` 约束）。
- 验证：runtime 套件在隔离 venv（`pytest==8.3.4`）中 28,881 passed / 27 skipped / 0 failed；`test_defensive_agent.py` 20 项（新增 7）、`test_loop.py` 86 项（新增端到端编码输入拦截）、其余组件 sidecar 53 / egress 33 / run-contract 54 / run-evidence 94 / host 37 / durable-run 499 / interop 260 全通过；TypeScript 60 项通过；`tests/` 215 项中仅 `test_swe_bench_solver.test_a_missing_instance_raises` 因需要联网抓取 SWE-bench 实例而报错（在干净 `HEAD` 上同样复现，与本轮无关）。离线 `python3 -m cli bench` 由 169/169 升至 **170/170**（新增 `injection.encoding_does_not_change_the_decision`），`BENCH_VERSION` 仍为 v40。`python3 tests/docbuild.py verify` 通过。
- 系统 Python 未安装 pytest，故直接 `make test` 仍会在 629 个 pytest 风格模块上报 import error；该环境缺口在上一节已记录，本轮未修改系统环境。
