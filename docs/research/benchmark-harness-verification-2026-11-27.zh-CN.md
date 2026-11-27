# 基准与 Harness 架构一手核验（2026-11-27）

> 核验日期：2026-11-27。**方法**：只接受官方 GitHub 仓库、官方文档站、官方博客、arXiv 论文；所有关键数字均通过实际下载或调用一手 artifact 复核过（非仅读 README 声明）。**纪律**：社交媒体转述、新闻聚合站、AI 生成总结站一律未采信；凡未在一手页面看到的内容，一律标注「未一手核验」。
>
> **为什么做这件事**：生态圈里流传着一条看似合理的建议——「OpenAI 已弃用 SWE-bench Verified，改用 SWE-bench Pro」。本文逐条核验后发现：**这条建议本身已被 OpenAI 撤回**。基准迁移是成本最高、影响最远的决策，必须建立在事实而非转述之上。

---

## 1. 结论速览

| 主张 | 核验结论 | 与流传说法的差异 |
|---|---|---|
| SWE-bench Pro 共 1,865 任务 / 41 仓库 | ✅ 属实 | 「41 个专业仓库」是**跨三个子集**的总数，公开集只有 **11 个**仓库 |
| 公开子集 731 个实例 | ⚠️ **已过时** | 现行 default = **V2 642 题**（731 是 `v1` config）；**官方 leaderboard 页仍写 731** —— 引用官方页会拿到过时数字 |
| OpenAI 停止报告 SWE-bench Verified | ✅ 属实（2026-02-23 官方文章） | 无差异 |
| OpenAI 推荐改用 SWE-bench Pro | ❌ **已被撤回**（2026-07-08） | **这是最重要的发现**：约 30% 的 Pro 任务损坏，原文「we retract our earlier recommendation to adopt SWE-Bench Pro」 |
| Terminal-Bench 4.0 任务数 | ✅ **实测 66 题** | 比 3.0（74）与 2.0（89）**更少** —— 方向是主动做减法（剔除饱和任务） |
| Harness「控制面 / 执行面 / Session」三层解耦 | ✅ **三个一手来源逐字对应** | 唯一偏差：二手材料常误引 Anthropic《Effective harnesses》——三层解耦的出处是《Scaling Managed Agents》 |

---

## 2. 关键反转：OpenAI 撤回了对 SWE-bench Pro 的推荐

**2026-02-23**，OpenAI 发布《Why we no longer evaluate SWE-bench Verified》，两条理由：

1. **测试拒绝正确解**：审计 27.6% 子集（138 题，每题 ≥6 名工程师），**59.4% 存在测试设计/问题描述的实质问题**
2. **训练泄漏**：「所有被测前沿模型都能复现 gold patch 或逐字复现问题描述细节」

当时的替代建议是 SWE-bench Pro。

**2026-07-08**，OpenAI 发布《Separating signal from noise in coding evaluations》，审计结论：

> 「Our datapoint analysis pipeline flagged **200 (27.4%)** broken tasks, while the human annotation campaign identified **249 (34.1%)**. … we estimate that **~30% of SWE-bench Pro tasks are broken** … **we retract our earlier recommendation to adopt SWE-Bench Pro.**」

失败模式被命名为四类：`Overly strict tests`、`Underspecified prompts`、`Low-coverage tests`、`A misleading prompt`——与 Verified 的 narrow/wide tests 是**同源问题**。

### 对 Northstar 的含义

**迁到 Pro 不解决同类问题。** 我们的 50 题切片来自 Verified，继承同样的缺陷模式；但 Pro 也有约 30% 损坏，且官方推荐已被撤回。**净负价值。**

同时注意一个未核验点：审计针对的是 **v1 的 731 题**；**V2（642 题）发布于 2026-09-22，晚于审计两个月**。V2 的修订方向（丢弃 89 个、529 条描述重写、176/47/83 个测试集重新生成）与审计发现对应，但**没有任何一手来源确认 OpenAI 已复审 V2**。

---

## 3. SWE-bench Pro 的准确规格

### 3.1 三个子集

论文原文（§3.3）：

> 「SWE-BENCH PRO consists of a total of 1865 human-verified and augmented problems, divided as three subsets: public, commercial, and held-out.」
>
> - **Public**：731 题公开，来源为 copy-left 许可的公开仓库
> - **Commercial**：276 题来自初创公司仓库，因法律原因不公开
> - **Held-Out**：858 题，镜像公开集但用另一批仓库，用于检测过拟合

**41 = 11 (public) + 12 (held-out) + 18 (commercial)**。

### 3.2 现行可用的是 V2（642 题）

HF dataset card：

> 「**V2 (2026-09-22)** is the `default` config: **642 tasks** (go 256, python 237, js 145, ts 4). The `hard` config is the **51-task HARD subset**. The original 731-task release is preserved unchanged as config `v1`.」
>
> 「Starting from the 731 v1 tasks, **89 were dropped after review (invalid or unrepairable tests)**; the 642 that remain were re-validated end to end.」

HF API 实测：`gated: false`、`private: false`、38,032 次下载。容器镜像 `ghcr.io/scaleapi/swe-bench_pro-v2:<instance_id>` **匿名可拉**。

> ⚠️ **官方 leaderboard 页与仓库/HF 不一致**：页面仍写「The Public Set: This set contains **731** instances」。**引用官方 leaderboard 页会拿到过时数字。**

### 3.3 许可证：harness 是 MIT，数据集内容不是

HF dataset card 原文：

> 「The evaluation harness and tooling are released under the **MIT license**. **Task content** (problem statements, patches, tests) is derived from the 11 upstream open-source repositories and **remains subject to their respective licenses**.」

HF 的 `license` 元数据字段为 **`None`**（未声明）。

### 3.4 锁定评测协议（值得借鉴的设计）

V2 全部以 Harbor task 目录发布（`instruction.md` / `task.toml` / `environment/Dockerfile` / `solution/` / `tests/`），并规定严格的 locked protocol：

1. **Agent 阶段离线**：`network_mode = "no-network"`，只白名单模型端点
2. **Verifier 从不在 agent 的 sandbox 内运行**：捕获 `git diff` 为 `model.patch`，在 pristine 镜像上重放
3. **每题 50 分钟预算**（沙箱内超时，部分补丁仍被抓取并评分）
4. **先探测再信任**

`v2/GATE.md` 是发布门禁：参考补丁 642/642 全部 resolved，空补丁 642/642 全部 unresolved。

> **这与我们刚上线的样本完整性探针是同一个思路**（gold 必须过、empty 必须不过），但 Pro 把它做成了**发布门禁**，我们是**事后检查**。门禁更早、更便宜——这是我们该借鉴的地方。

---

## 4. Terminal-Bench 4.0：实测 66 题，且在主动做减法

| 版本 | 任务数 | 关键特征 |
|---|---|---|
| TB 2.0 | 89 | 引入 Harbor 框架，重写评测 harness |
| TB 2.1 | 89 | 修复 28 题，改进外部依赖 |
| TB 3.0 | 74 | 语义化版本 + CI/CD，开始剔除饱和任务 |
| **TB 4.0** | **66** | 统一 8 小时 agent timeout（资源校准）；移除 8 题（饱和 2 / 拒答 2 / 公开解 2 / 质量 2）；修复 19 题 |
| TB 4.1 | 66 | verifier 加固（reward-hack resistant `Worker`） |

TB 4.0 官方博客：

> 「We removed 8 tasks: for saturation (2), refusals (2), public solutions (2), and unresolved quality or platform-compatibility issues (2). Such a task no longer meaningfully differentiates between models.」
>
> 「**All tasks in TB 4.0 are now set to a flat agent timeout of 8 hours.**」

**成本量级**：TB 4.0 榜单单条 330 trials（66 题 × 5 次），推理成本 **$116k**；排名第一 Claude Code + Opus 5.5 = 64.85% ±3.1%。

**执行面隔离已在评测基础设施落地**：`task.toml` 里 `[verifier] environment_mode = "separate"`——verifier 容器 ≠ agent 容器。

---

## 5. Harness 三层解耦：三个一手来源逐字对应

### 5.1 Anthropic《Scaling Managed Agents: Decoupling the brain from the hands》（2026-04-08）

> 「We virtualized the components of an agent: a **session** (the append-only log of everything that happened), a **harness** (the loop that calls Claude and routes Claude's tool calls to the relevant infrastructure), and a **sandbox** (an execution environment where Claude can run code and edit files). **This allows the implementation of each to be swapped without disturbing the others.**」

> 「The harness is **never made aware of any credentials**.」

性能收益：**p50 TTFT 下降约 60%，p95 下降超 90%**。

⚠️ **误引警告**：Anthropic 另一篇《Effective harnesses for long-running agents》**通篇不出现 "sandbox" 一词**（已实测全文关键词检索）。它讲的是 harness **内部**的 initializer/coding agent 两段式与长任务上下文管理，**不是三层解耦**。二手材料把三层解耦引用自这篇是误引。

### 5.2 OpenAI《Sandbox Agents》

> 「**The key split is the boundary between the harness and compute.** The harness is the **control plane** around the model: it owns the agent loop, model calls, tool routing, handoffs, approvals, tracing, recovery, and run state. Compute is the **sandbox execution plane**.」

> 「Running the harness inside the sandbox can be convenient for prototypes, but it puts orchestration and model-directed execution in the same compute boundary.」

### 5.3 AWS AgentCore Harness

> 「**Every agent has an orchestration layer**: a loop that calls the model, picks tools, passes results back, manages context, and handles failures. … Together, they form the agent harness.」

### 5.4 交叉验证：评测基础设施也在做同样的解耦

- Harbor `task.toml`：`[verifier] environment_mode = "separate"`
- SWE-bench Pro locked protocol：「**The verifier never runs in the agent's sandbox**」
- TB 4.1 `Worker`：agent 提交的代码以非特权用户在独立进程执行，「cannot read the tests or change the reward file」

---

## 6. 对 Northstar 的落地判断

### 6.1 现有架构无需改动，但论证可以加强

仓库现有实现与一手文献方向一致：

| Northstar 现状 | 可引用的一手依据 |
|---|---|
| 「reasoning and policy stay in the runtime while execution and sandboxing stay in the sidecar」 | OpenAI：「The harness is the **control plane** … Compute is the **sandbox execution plane**」 |
| runtime 不持有 model credentials、不 spawn model CLI | Anthropic：「**The harness is never made aware of any credentials.**」 |
| 独立进程组 + TERM-to-KILL 清理 + Unix socket 鉴权 | Anthropic：「It called the container the way it called any other tool: `execute(name, input) → string`」 |
| 内置 sandbox（Landlock/seccomp/capdrop/bwrap） | OpenAI Codex：「**The sandbox is the boundary that lets the agent act autonomously without giving it unrestricted access to your machine.**」 |

### 6.2 预算应投入评测可信度，而非基准升级

OpenAI 两篇文章共同指向这一点。可自动化的部分我们已在做：

| 动作 | 状态 |
|---|---|
| 用上游 harness，不自建 grader | ✅ 已做 |
| 冻结 image digest 与样本指纹 | ✅ 已做 |
| 留存收据（provider/model/endpoint/temperature/sandbox/预算） | ✅ 已做 |
| **gold patch / empty patch 双向探针** | ✅ 已上线（3 题冒烟：**1 可信 / 2 不可信**） |
| **报告置信区间而非单点数字** | ✅ 已做（Wilson 区间，50 题 SE ≈ ±6.9%） |
| 逐题审计描述与测试的一致性 | ⬜ 未做 |

### 6.3 迁移成本粗估（基于已核验事实）

| 目标 | 一次性成本 | 稳态成本 | 建议 |
|---|---|---|---|
| **留在 SWE-bench Verified 50** | 0 | 当前量级 | ✅ **推荐** |
| 迁到 SWE-bench Pro V2 642 题 | 适配 Harbor task 格式 + locked protocol | 题目量 ×12.8 | ❌ 不推荐（官方已撤回） |
| 加 Terminal-Bench 4.0（66 题） | Harbor `BaseAgent` 实现 + 多容器/GPU | 单题 8 小时量级 | ⚠️ 独立轨道，不替换代码基准 |
| 借鉴 Pro 的**发布门禁**做法 | 低 | 低 | ✅ **推荐**（把探针前移到样本冻结时） |

---

## 7. 未能核验的部分（诚实清单）

| # | 想核验的事 | 状态 | 原因 |
|---|---|---|---|
| 1 | Pro 官方 leaderboard 页的**当前**公开集题数 | ⚠️ 内部不一致 | 页面写 731，仓库/HF 为 642；**引用官方页会拿到过时数字** |
| 2 | Pro 的 git tag `v1.0` 是否存在于 GitHub | ❌ | tags API 只列 `v2.0.0`；HF card 声称有该 tag |
| 3 | `labs.scale.com` 私有 leaderboard（commercial 276 题） | ❌ | 需登录 |
| 4 | `openai/simple-evals` 移除 SWE-bench 脚本的时间点 | ❌ | 当前文件树已无该脚本，未遍历提交历史 |
| 5 | SWE-bench Verified 500 题当前是否仍被官方推荐 | ❠️ | `swebench.com` 为 JS 渲染，未拿到明文表述 |
| 6 | TB 2.0 数据集本体是否仍可从 Harbor Hub 下载 | ❌ | 实测 not found（仅存 GitHub 仓库） |
| 7 | TB 4.0 与 4.1 的任务集逐题差异 | ⚠️ | 两者均 66 题，4.1 讲的是 verifier 加固，未逐题 diff |
| 8 | Harbor 文档纯文本版 | ⚠️ | 页面 JS 渲染，静态 HTML 无正文；改用实测 `task.toml` 替代 |
| 9 | **Pro V2 是否已修复 OpenAI 指出的问题** | ❌ | 无一手来源。V2 修订方向与审计发现对应，但官方未复审 |
| 10 | **Northstar 50 题中有多少落入 OpenAI 点名的缺陷类别** | ❌ | 未做逐题审计（探针机制已上线，正在全量跑） |

---

## 8. 一手来源清单

**SWE-bench Pro**：[arXiv 论文](https://arxiv.org/abs/2509.16941) · [官方仓库](https://github.com/scaleapi/SWE-bench_Pro-os) · [V2 说明](https://github.com/scaleapi/SWE-bench_Pro-os/tree/main/v2) · [发布门禁](https://raw.githubusercontent.com/scaleapi/SWE-bench_Pro-os/main/v2/GATE.md) · [HF 数据集](https://huggingface.co/datasets/ScaleAI/SWE-bench_Pro) · [官方 leaderboard](https://scale.com/leaderboard/swe_bench_pro_public)

**OpenAI**：[Why we no longer evaluate SWE-bench Verified](https://openai.com/index/why-we-no-longer-evaluate-swe-bench-verified/) · [Separating signal from noise in coding evaluations](https://openai.com/index/separating-signal-from-noise-coding-evaluations/) · [Sandbox Agents](https://developers.openai.com/api/docs/guides/agents/sandboxes) · [Agents API 架构](https://developers.openai.com/api/docs/guides/agents-api/architecture) · [Codex Sandbox](https://learn.chatgpt.com/docs/sandboxing.md)

**Terminal-Bench / Harbor**：[terminal-bench 仓库](https://github.com/harbor-framework/terminal-bench) · [v4.0.0 Release](https://github.com/harbor-framework/terminal-bench/releases/tag/v4.0.0) · [官方博客 4.0](https://www.tbench.ai/news/terminal-bench-4-0) · [官方博客 4.1](https://www.tbench.ai/news/terminal-bench-4-1) · [Harbor 仓库](https://github.com/harbor-framework/harbor) · [Harbor Hub](https://hub.harborframework.com/datasets/terminal-bench/terminal-bench/latest)

**Anthropic**：[Scaling Managed Agents](https://www.anthropic.com/research/managed-agents) · [Effective harnesses for long-running agents](https://www.anthropic.com/research/effective-harnesses-for-long-running-agents)

**AWS**：[AgentCore harness](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness.html) · [harness vs. Runtime](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness-vs-runtime.html)

---

*所有引用的英文原文均来自实际访问的官方页面；所有数字（66 / 642 / 731 / 1,865 / 41 / 89 / 74 / 51 / 200 / 249 / 27.4% / 34.1% / ~30% / 59.4% / 23.3% / 64.85% / 60% / 90%）均经过一手 artifact 复核。*
