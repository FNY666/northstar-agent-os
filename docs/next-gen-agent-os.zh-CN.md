# Northstar 次世代 Agent OS 总纲

> 编制日期：2026-09-09  
> 定位：产品脊梁（Product Spine）。本文件冻结「我们在造什么」；对标与取舍见  
> [benchmark-top-agents-2026-09.zh-CN.md](benchmark-top-agents-2026-09.zh-CN.md) 与  
> [next-gen-agent-blueprint.zh-CN.md](next-gen-agent-blueprint.zh-CN.md)。  
> 本文件**优先于**根 README 里历史的「component-oriented」表述：组件仍是内核子系统，  
> 对外交付的是 **Agent OS**，不是零件目录。

---

## 1. 一句话

**Northstar 是以可证明治理为内核的次世代 Agent 操作系统：默认就能派活，  
在可证明的边界里执行、协作、恢复；每一项能力仍穿过同一道门，且无 key 可回归。**

不是「更多组件」。不是「把 Claude / Codex / Manus / OpenClaw 的功能做并集」。  
次世代 = **能力 AND 门**，整机默认路径焊死，零件降为内核。

---

## 2. 产品 vs 组件（必须选边）

| | 组件库（旧自我定位） | **次世代 Agent OS（现行目标）** |
|---|---|---|
| 用户 | 库作者，自己拼 runtime | **把活交给智能体的人 / 团队** |
| 成功标准 | 单测绿、边界清晰 | **端到端任务完成 + 敢信 + 崩了能续** |
| 入口 | 六个 `cd components/…` | **一个 `northstar` 命令** |
| 默认路径 | 全靠 flags 拼 | **`agent` 路径：会话 + 检查点默认开** |
| 组件角色 | 对外六种安装物 | **内核子系统**（runtime / contract / host / durable / sidecar / interop） |

历史 README 仍诚实写「尚未完成完整多智能体 OS」——那是**范围诚实**，不是产品目标放弃。  
目标就是把那句 disclaimer 一项一项证伪；路径是整机，不是继续打磨孤岛零件。

---

## 3. 不变量（任何能力都不得绕过）

与 [concepts/governance.md](concepts/governance.md) 一致，产品层再强调一次：

1. **权限门** — 可否调用、何种模式  
2. **hooks** — 可否决；否决即终态  
3. **预算天花板** — 轮次 / 工具调用 / 美元；策略只能收紧  
4. **审计** — 每 run 恰好一个 `ResultMessage` + 语义退出码 + 可续会话  

附加产品层不变量：

5. **策略不可自改** — `.northstar/` 默认写保护，且执行路径不得撤销它  
   *文件工具经 `ToolSandbox.resolve` 拒绝写；被批准的 `Shell` **不经过**那条路，所以同一份
   `protected_prefixes` 交给沙箱：bwrap 在工作区写绑定**之后**把 `.northstar`/`.git` 重挂为只读
   （`.northstar/memory`、`.northstar/tmp` 再开回可写），并且**实测探针**——绑定没成立就是配置错误，
   不是静默降级。没有用户命名空间的宿主上，run 启动即冻结治理树摘要、每个 exec 结果之后复核，
   变了就以 `error_governance_drift`（退出码 8）收尾并写 `governance_drift` 审计记录；
   `--no-drift-check` 可关，关掉就在 `system:init` 里落一行。**检测弱于阻断，所以它被写出来而不是被暗示。**
   MCP 子进程仍在待补清单上（[execution-boundary-audit-2026-09.zh-CN.md](execution-boundary-audit-2026-09.zh-CN.md) §4/F5）*  
6. **恢复不洗预算** — checkpoint / resume 继承已消耗计数  
7. **后置条件独立于模型** — agent 说「做完了」不算数  
8. **无 key 可回归** — 吸收的能力若不能进 scripted 测试，就不算吸收成功  

---

## 4. 默认产品路径（焊死，不是高级选项）

```
用户任务
   │
   ▼
northstar agent "…"          ← 唯一推荐入口
   │
   ├─ workspace 策略 (.northstar/config.toml, 只收紧)
   ├─ AGENTS.md / skills / plugins（仍过门）
   ├─ 治理 loop（hooks · 权限 · 预算 · 事件流）
   ├─ 工具面（workspace 沙箱 + OS 沙箱内 Shell；默认 deny）
   ├─ 可选执行面（Codex sidecar / 未来 sandbox worker）
   ├─ 会话默认落盘：<workspace>/.northstar/sessions
   ├─ 检查点默认开启（每 turn 边界）
   └─ 唯一 ResultMessage + 可 northstar resume
```

技术入口 `northstar-agent-runtime` / `python3 -m cli` **保留**，供嵌入、CI、旧脚本；  
新产品文档与 demo **只教** `northstar agent`。

---

## 5. 优先级（按性价比，已按「次世代整机」重排）

| 序 | 主题 | 状态 | 说明 |
|---|---|---|---|
| **0** | 产品脊梁：统一入口 + 默认焊死路径 + 叙事改写 | **已落地** | `northstar` / `agent` / 本总纲 / README 重定位 |
| **1** | 沙箱执行面：OS 隔离 → 受控 Shell/代码 → 威胁模型 | **已落地** | `os_sandbox`（bwrap\|process）+ `Shell`（默认 deny）+ [threat-model](concepts/threat-model.md) |
| **2** | 长任务默认可恢复产品化 | **已落地** | `resume` = checkpoint **fork**（继承预算）；`latest`；sessions 默认产品目录 |
| **3** | 并行工具 + 真多 Agent handoff | **本批落地** | 只读工具可并行（门仍串行）；`interop_bridge` 签名 handoff |
| **4** | 工作区记忆 + 沙箱内 Skills 脚本 | **本批落地** | `.northstar/memory/`（可写 carve-out + digest）；skill `scripts/` 仅经 Shell |
| **5** | 安装/发布/最小交互/治理公开基准 | **本批落地** | `northstar bench` + `make bench`/`install-smoke`；`agent TASK` 位置参数；仍 `0.1.0.dev0` |
| **6** | 闸门之后的路径：执行面写保护、MCP 子进程隔离、指令字节入摘要 | **待做（09-09 审计已给复现与验收）** | F4/F5/F6 → `execution-boundary-audit-2026-09.zh-CN.md` §8 的 P0-5/P0-6/P0-7/P1-5/P1-6 |

### 明确不做（防漂移）

自建云/托管；重型 IDE 插件优先；无签名插件市场；模型微调；浏览器/计算机操控（无隔离前）；  
**宿主机 Full Auto shell**；模型分类器自动**批准**（最多额外否决）；无界工具注入。

---

## 6. 向顶级 Agent 学什么（整机视角）

| 学谁 | 学到哪一层 | 不学什么 |
|---|---|---|
| OpenAI Agents SDK v2 | harness / compute 分离 | 无边界 Full Auto |
| Claude Code / Agent SDK | hooks、权限体感、agent 交互 | 无审计的自由度 |
| LangGraph / Temporal | 长任务 checkpoint / time-travel | 无权限门的编排 |
| Manus | Plan–Execute–Reflect、沙箱任务 | 闭源云、不可定制 planner |
| OpenClaw | 本地 Agent OS 整机感 | 无边界本地权限 |
| Devin / OpenHands | 持久工作区写代码 | 无隔离长自主 |
| CrewAI | 角色团队心智 | 弱治理原型思维 |

吸收判据仍是蓝图那句：**改写成过同一道门；改不动就拒绝。**

---

## 7. 内核子系统地图（对内仍是组件）

| 子系统 | 目录 | 在整机中的职责 |
|---|---|---|
| Runtime | `northstar-agent-runtime` | 治理 loop、CLI/`northstar`、SDK |
| Run Contract | `northstar-run-contract` | 版本化请求/回执、binding |
| Host | `northstar-host` | 授权与 workspace 经纪（本地候选） |
| Durable | `northstar-durable-run` | 事件/租约/verifier 词汇 |
| Sidecar | `northstar-codex-sidecar` | 只读 Codex 执行面（Unix socket） |
| Interop | `northstar-agent-interop` | 签名 handoff（尚未接真实后端） |

用户不应需要记住这张表才能开始干活；开发者扩展内核时才打开它。

---

## 8. 本批交付清单（第 0 刀）

- [x] 本总纲  
- [x] 控制台入口 `northstar`（与 `northstar-agent-runtime` 并存）  
- [x] 产品子命令 `agent`：默认会话目录 + 默认检查点  
- [x] 产品子命令 `resume`：从会话续跑的短路径  
- [x] 仓库内 `bin/northstar`（未 pip install 也可跑）  
- [x] demo / Makefile / 根 README 与中文 README 改叙事  
- [x] 确定性测试覆盖产品默认路径  

**第 1 刀清单（已完成）：**

- [x] `tools/os_sandbox.py` — bwrap 优先、process 回退；显式 bwrap 不可用则硬错误  
- [x] `tools/shell.py` — `Shell`（kind=`exec`）；argv 优先；`command` → 沙箱内 `sh -c`  
- [x] 默认 deny：`--allow-tool Shell` 才放行；`--read-only` / `plan` / `acceptEdits` 均不覆盖  
- [x] CLI `--sandbox auto|bwrap|process`；doctor / dry-run / init 事件诚实标注 isolation  
- [x] [concepts/threat-model.md](concepts/threat-model.md)  

**第 2 刀（本批）清单：**

- [x] 产品 `resume` 默认 **fork**（`--resume-from`）：父 transcript 不变；turns/tool_calls/cost 继承  
- [x] `resume latest` / `@latest` / `.` 解析到产品 session 目录最新 transcript  
- [x] `--in-place` 显式 opt-in 到 append 路径（不继承计数器；低层逃生口）  
- [x] `sessions list|show|…` 默认 `<workspace>/.northstar/sessions`；`show latest`  
- [x] demo 覆盖 agent → resume latest → sessions list  

**第 3 刀（本批）清单：**

- [x] `tools/parallel.py` — 只读非 mutating 才可并行；混有 Write/Edit/Shell/Task 则整 turn 串行  
- [x] loop `--parallel-tools N`（默认 1）；PreToolUse + 权限门仍逐调用串行独立过门  
- [x] `interop_bridge.py` — 签名 attestation → handoff grant；能力只收窄；local-dev 诚实标注  
- [x] 确定性测试：并行重叠 + 顺序保持 + 能力越权拒绝  

**第 4 刀（本批）清单：**

- [x] `memory.py` — workspace-scoped MEMORY.md；digest 标注；`--no-memory` / `--memory-file`
- [x] `.northstar/memory/` 写保护 carve-out（策略/agents/skills 仍锁死）
- [x] `tools/skill_scripts.py` — 发现 skill `scripts/`；listing 进 prompt；执行仍只走 Shell（默认 deny）
- [x] demo 附带 memory + skill script

**本批不做：** 全局/user-scope MEMORY、自动执行 skill 脚本、seccomp 加固（属明确拒绝 / 后续硬化）。


**第 5 刀（本批）清单：**

- [x] `governance_bench.py` — 公开治理基准（denial / injection / budget），离线确定性
- [x] `northstar bench` / `make bench` — 与 CI 同入口的产品面计分
- [x] `make install-smoke` — 干净 venv 链式安装 + `--version` + bench
- [x] 最小交互：`northstar agent "任务"` 位置参数（等价 `--prompt`）；TTY 下裸 `agent` 读一行
- [ ] 正式发版（去掉 `.dev`）— **仍按就绪门**，本批不切 tag

**本批不做：** 上架 PyPI/npm、交互式 TUI、自建云、去掉 `.dev0` 的 tag 发布。


---

## 9. 如何验收「第 0 刀做完了」

```sh
bin/northstar --version          # 打印 northstar <version>
bin/northstar agent --help       # 产品路径存在
bin/northstar bench              # 公开治理基准 14/14（新增的那条正是"shell 不得改写闸门"）
make demo                        # 仍离线全绿
# agent 路径不传 --session-dir 也应写出 <workspace>/.northstar/sessions
# agent 路径 transcript 含 checkpoint 记录（默认每 turn）
# agent 接受位置参数：bin/northstar agent --workspace . "任务" --provider scripted --scripted-text ok
make test                        # 全仓离线测试通过
make install-smoke               # 干净 venv 安装 + version + bench
```

---

## 10. 一句话收束

**组件是发动机；次世代是整车。**  
第 0 刀把方向盘装上并标成唯一驾驶位；第 1 刀装上隔离的动力总成（沙箱+受控执行）。  
治理内核已经是护城河——现在要把它开出停车场。
