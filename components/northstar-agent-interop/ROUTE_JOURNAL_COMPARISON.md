# BackendRouter 与 RouteDecision Journal 独立边界比较

日期：2026-09-07
状态：local-only 审查材料；未吸收研究线提交，未修改公开 checkout

## 被比较对象

| 对象 | 来源 | 当前证据状态 |
|---|---|---|
| BackendRouter | local-only commit `1e5a6a131d8b7a662b23a2f7084877faca4a2b50` | 源码可见；本地测试已验证 |
| RouteDecision Journal 第一切片 | research commit `c03c474` | 研究会话交接可见；worktree/对象当前不可见，源码未独立重跑 |
| RouteDecision Journal 第二切片 | research commit `323da64`，父 `c03c474` | 研究会话交接可见；worktree/对象当前不可见，源码未独立重跑 |
| local-only Route Ledger 草稿 | 当前 local-only 未提交文件 | 源码可见；当前 Interop 全套已验证 |

公开稳定基线保持用户指定版本，不作为本次写入目标。

## BackendRouter 1e5a6a1 的边界

BackendRouter 是**选择与适配器解析层**。它接收严格的 `RouteRequest`，根据：

- requested capabilities；
- backend profile capability support；
- enabled/disabled；
- healthy/degraded/cooldown/unhealthy；
- priority；
- preferred/excluded agent IDs；
- policy revision；
- stable agent ID tie-break；

输出 immutable `RouteDecision`，并在 adapter lookup 时重新检查目标 profile、provider、version、health、enabled 和 capability support。它还能检查 RouteDecision 与 Handoff Request 的身份一致性，并允许 Handoff deadline 进一步收窄。

它解决：

```text
现在应该把这一步交给哪个候选后端？
```

它不负责：

- 持久化选择事实；
- 记录候选快照；
- 记录 route started/succeeded/failed/cancelled；
- 失败分类与可重试性历史；
- 跨进程幂等写入；
- 重启后 replay；
- 路由回执和历史证据链。

## RouteDecision Journal c03c474 的边界

根据研究线交接摘要，第一切片新增：

- 严格 `RouteJournalRecord` schema；
- append-only JSONL + flush/fsync；
- 截断末行跳过；
- idempotency key 重复返回、冲突拒绝；
- 候选后端快照；
- 决策 fingerprint；
- 路由失败分类；
- record/replay；
- 候选快照、策略版本、请求摘要变化检查；
- Handoff identity/deadline 兼容检查；
- 不记录 prompt、secret、opaque context 或后端原始输出。

它解决：

```text
当时 RouteDecision 是什么、依据是什么、后来发生了什么、能否回放？
```

它不替代 BackendRouter 的候选筛选算法，也不自动改变选择结果。若不调用 Router 或接收真实候选输入，Journal 只能记录一个决策，不负责产生决策。

## RouteDecision Journal 323da64 的边界

根据研究线交接摘要，第二切片在 c03c474 上新增：

- Unix `flock` 临界区；
- 跨进程幂等 check → conflict → append + fsync 的临界流程；
- 两个独立 multiprocessing 进程竞争同一 idempotency key 的测试；
- stale lock file 恢复测试；
- 保留已有 replay、候选快照、fingerprint、Handoff identity/deadline 检查。

它解决的是第一切片的一个可靠性缺口：

```text
两个进程同时写同一个路由事件时，不能产生重复记录或丢失冲突。
```

它没有改变：

- Router 的 capability/health/priority selection；
- Handoff 的权限授权来源；
- Agent adapter 的执行协议；
- 最终任务 postcondition 验证。

因此 323da64 更准确地称为：

> **RouteDecision Journal 的跨进程可靠性配套代际。**

## local-only Route Ledger 草稿的独立边界

当前 local-only 已独立写入并通过测试的 Route Ledger 草稿覆盖：

- `RouteDecisionRecord` 严格 schema 与决策 digest；
- `RouteReceipt` 的 started/succeeded/failed/cancelled、attempt、latency、failure class、error code、retryable；
- `RouteEvent` 严格 schema、payload digest、typed payload；
- append-only JSONL + flush/fsync；
- 截断尾行忽略并在下次 append 前截断恢复；
- idempotency 重复返回与冲突拒绝；
- sequence 连续性、跨 run/route、decision digest、payload digest 检查；
- terminal 状态、retryable failure 后 attempt+1 重试；
- replay 的状态、attempt、receipt count、retry count、latency 和 failure counts；
- select → persist → receipt → replay 与 Handoff deadline narrowing 集成；
- 不保存 prompt、secret、token、raw error。

当前 local-only Route Ledger 尚未实现研究线第二切片的 Unix flock/锁文件恢复语义；其跨进程测试改用两个独立子进程和文件结果以适配当前 iSH 缺少 POSIX semaphore 的环境，并且当前实现没有锁，因此该测试不应被误报为跨进程安全证明。

## 代际判定

### 结论一：c03c474 不是 BackendRouter 的替代

它们属于不同边界：

```text
BackendRouter = decision producer / adapter selector
RouteJournal = decision evidence / durable record
```

把 c03c474 合并进 Router 可能形成更完整的“路由子系统”，但不会自动使 Router 的选择能力升级。

### 结论二：323da64 不是 BackendRouter 的完整更高代际

它仍然只强化 Journal 的写入可靠性，未改变 Router 的决策语义。它可以作为：

```text
Route subsystem reliability sub-generation
```

但不能单独计为：

```text
BackendRouter G2
```

### 结论三：两次 Journal 合在一起，才接近 Route Evidence 子系统的完整下一代

若将“路由子系统”定义为：

```text
candidate selection
+ durable decision record
+ execution receipt
+ replay
+ failure classification
+ cross-process idempotency
```

那么：

- `1e5a6a1` 提供 selection；
- `c03c474` 提供 record/replay/decision evidence；
- `323da64` 提供 cross-process write reliability；
- 三者合起来才接近一个完整的 Route Evidence/Decision Runtime。

但由于研究源码当前在本环境不可见，且没有把三者在同一工作树中独立整合并回归，不能正式宣布完整下一代已经验收。

## 当前推荐动作

不自动吸收 `c03c474` 或 `323da64`。继续保持：

```text
公开 main：稳定基线，不动
BackendRouter 1e5a6a1：local-only，不下放
研究 Journal c03c474/323da64：研究参考，不自动合并
local-only Route Ledger：独立实现，继续 TDD
```

local-only 下一步应优先补：

1. 使用真实 `BackendRouter.select()` 产生并持久化候选快照，而不是手工 RouteDecision；
2. 引入 candidate snapshot fingerprint，回放时检测 backend/profile/health/priority 变化；
3. 引入 Unix `flock` 或明确的跨平台锁抽象；
4. 测试 stale/corrupt lock 恢复，证明不会误删活跃锁；
5. 把 fallback route lineage 与 RouteReceipt 绑定；
6. 将当前 Route Ledger 接入 `RouteDecision → Handoff → AdapterReceipt` 的完整兼容检查；
7. 再以独立任务集测量失败恢复、fallback 成功率、重复副作用率和回放一致性。

## 证据等级

- **Verified**：local-only `1e5a6a1` 源码、当前 Route Ledger 草稿、local-only 新鲜测试结果。
- **Handoff-verified but not source-verified here**：研究线 `c03c474`、`323da64` 的功能摘要、提交关系和研究线测试报告；其 worktree/对象在本环境不可见。
- **Inferred**：上述三者的系统边界与代际关系；这是架构比较，不是性能排名或真实后端质量证明。
