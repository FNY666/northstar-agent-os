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

5. **策略不可自改** — `.northstar/` 默认写保护  
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

### 下一阶段产品优先级

前表记录已完成的底座，不代表接下来继续按组件排期。后续产品顺序是：**编程优先，攻防工具成对交付，多模态随后扩展**。

| 顺序 | 产品能力 | 当前底座与交付验收 |
|---|---|---|
| **1** | 编程任务闭环（最高优先级） | 已有 `Read` / `Write` / `Edit` / `ApplyPatch` / `LS` / `Grep` / 受沙箱约束的 `Shell`；完整 UTF-8 文件的 `Read` 提供 SHA-256，`ApplyPatch` 用哈希作多文件乐观版本校验，支持整文件替换、基于精确原文且范围不重叠的局部行编辑，也可用 `expected_sha256: "absent"` 将新文件和已有文件修改放进同一批次。新文件使用原子且不覆盖的发布，父目录必须已存在，整批仍逐次经过普通权限门。每个替换单独原子；后续替换失败时，回滚会先确认目标仍是本工具写入的版本，发现外部修改就保留现场并报告。整个多文件序列不具备断电原子性，提交和回滚仍有最后一次校验后的竞态窗口。`--coding-mode` 提供工作流指引，CLI 独立记录 Git 净变化、主 agent 和委派子 agent 的 Shell 执行结果、`--verify` / 策略 `[[verify]]` 的主机侧 verdict，以及显式启用的 `Stop` 检查脚本 verdict，输出 `coding_evidence` 收据；摘要区分未配置、未启用与未执行的检查，不复制 `contains` 期望文本。`Stop` 收据保留逐轮失败/通过历史，可与同轮 Shell 调用对照；失败会阻止 agent 完成并让其再修复。该模式不授予工具权限，脚本仍需审阅且仅在 `--enable-workspace-hooks` 后执行。 |
| **2** | 攻击测试 + 防护工具（成对建设） | 已有手动 CLI，并可通过 `--enable-security-tools` 在单次 agent 运行中注册本地 `SecurityScan`；临时 runtime 探针 `SecurityProbe` 还要求显式 `--allow-tool SecurityProbe`。扫描器固定当前工作区、只读离线，覆盖密钥 / Python 与 JS/TS SAST、依赖固定与来源、Docker / Compose / Kubernetes / CI / Terraform 部分配置；JS/TS 规则检查动态代码执行、Shell 命令、SQL 插值、HTML 注入、请求输入经同文件变量流向出站 URL、关闭 TLS 校验、弱随机 token 与 JWT `none` 算法；Kubernetes 规则检查 privileged、权限提升、root UID、host namespace、hostPath、ALL capabilities 和浮动 `latest` 镜像标签。finding 按严重度排序并附修复建议，不查询 CVE 库也不自动改文件；CLI 可导出供 CI 导入的 SARIF 2.1.0，包含规则、相对路径、行列和修复建议。agent 可在重新读取受影响文件后，通过显式授权的 `ApplyPatch` 提交哈希绑定的修复，再保存基线比较前后结果；工具不会自动应用扫描建议。探针使用临时靶场覆盖默认权限、目录穿越、符号链接、治理文件写保护、Shell 工作区与治理目录边界，并以固定的易受攻击 / 加固 Kubernetes 清单和 JS/TS 样例核对防护规则；源码样例只作文本分析，不执行；探针还检查 SARIF 导出里的规则 ID、文件行号和修复建议；URL 流规则只跟踪同一文件内简单变量赋值，不理解作用域、清洗函数或跨函数调用。样例和 canary 全在临时目录并自动清理。bwrap 会将 `.northstar` 重新挂载为只读，process 回退会明确报告无法隔离工作区子目录。后续继续扩展语言和配置规则、修复策略校验；真实攻击测试限定隔离靶场或显式 allowlist，并绑定目标、权限、预算和审计。 |
| **3** | 多模态输入与理解 | 编程闭环与攻防工具形成稳定体验后再扩展图片、音频和视频输入；媒体内容仍视为不可信输入，保留来源、文件范围和处理结果的审计信息。 |

攻防工具不开放任意公网目标扫描，也不提供隐蔽驻留、凭据窃取或数据外传能力。红队验证和蓝队扫描使用分开的工具权限；扫描发现本身不自动授权写入或外部操作。

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
bin/northstar bench              # 公开治理基准 16/16
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
