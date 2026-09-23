# S5：跨来源 freshness / watermark / replay 窗口与可安全重试决策表

**研究切片**：A 线独立公开研究 S5  
**截止/访问日期**：2026-09-22（Asia/Shanghai）  
**边界**：仅使用 AWS、Temporal、Kubernetes、GitHub 官方公开文档；没有读取既有 A 线目录、其他研究产物或任何本地服务/凭据。本文不是生产系统观测，也不证明 exactly-once、无重复副作用或任何外部效果。

## 1. 结论（校准后的答案）

1. **`event_time` 不是 `observed_at`，也不是 watermark。** CloudTrail 的 `eventTime` 是请求在服务 API endpoint 完成的 UTC 时间；它可晚交付，且官方记录可能出现 addendum 解释延迟。`observed_at` 应由消费者在实际观测/接收记录时自行写入；本次官方材料没有定义一个跨平台统一的 observed_at 字段，因此跨来源比较只能使用各自明确的服务时间、接收时间和查询时间。**verified（平台定义）/ inferred（跨源规则）**。
2. **watermark 必须是带来源与语义的边界，而不是“最新记录的时间”。** Kubernetes watch 可用 `resourceVersion`/bookmark 表示已同步到的版本；GitHub REST 分页用 `Link: rel="next"` 继续，而 workflow run 对象有 `created_at`、`updated_at`；AWS Step Functions 历史有 `nextToken`。这些游标/版本是各平台自己的完整性机制，不能互换或拼成一个跨源 watermark。**verified + inferred**。
3. **分页完成与结果新鲜不是同一件事。** 收到“无 next page/空 continue”只说明一次读取按该 API 的分页语义完成；不保证下游副作用已经发生，也不证明此前不存在延迟、旧事件、更新中的记录或跨源一致快照。
4. **自动重试只有在“请求效果可判定，且重复不会造成不可接受副作用”时安全。** Step Functions STANDARD `StartExecution` 对相同 name+input 的运行中执行幂等；EXPRESS 不幂等。Temporal Event History/Side Effect replay 是工作流历史确定性的机制，不是外部 Activity 效果的 exactly-once 证明。GitHub/Kubernetes/AWS 的读接口若响应丢失，单凭客户端 UNKNOWN 不得把“未收到响应”当作“未发生”。**verified（文档行为）+ inferred（控制规则）**。
5. **UNKNOWN 的默认处理是先恢复可判定性，再决定重试。** 以同一幂等键/执行 ID、读取服务状态/历史、校验输入哈希与来源版本、检查响应页边界；若无法排除已发生的外部效果，禁止盲目重试，转入人工升级或补偿流程。

## 2. 证据与术语对照

|概念|官方可核验事实|可安全转移的含义|不可转移/仍未知|
|---|---|---|---|
|事件时间|CloudTrail `eventTime` 是请求完成时间，来自提供 API endpoint 的 AWS 主机；CloudTrail 还说明事件交付可能延迟并用 addendum 解释|保存 `event_time` 与 `observed_at` 两列；以来源定义解释偏差|不能把它当客户端看到时间、全局排序或 watermark；延迟分布未由本切片测量|
|来源 watermark|Kubernetes bookmark 表示同步到某 resource version；列表响应含 `resourceVersion`，continue token 用于后续页|把 `(source, scope, version/cursor, observed_at)` 作为来源边界|不同 API 的 resourceVersion、nextToken、Link page 不可比较；没有统一跨源水位|
|分页/游标|GitHub 使用 HTTP Link header 的 `rel="next"`；AWS Step Functions `GetExecutionHistory` 有 `nextToken`；Kubernetes continue token 可过期并返回 410 Gone|必须逐页消费、保存原始游标与请求参数，直到平台声明结束|页与页之间是否是跨页一致快照、结果是否包含未来迟到事件，必须按平台单独判断|
|最终一致/读模型|Kubernetes 文档定义 resourceVersion 语义、consistent read 及 watch cache；CloudTrail 明确存在交付延迟|把读模型标为 `as_of`/`observed_at`，而不是伪造实时|本次材料未为 AWS/GitHub 读 API 给出可跨平台的“已追平”承诺|
|历史/重放|Temporal Service 追加 Event History；Side Effect replay 返回历史结果；可失败的 Side Effect 应改用 Activity|历史可帮助判断工作流状态与重放确定性|历史事件不等于 Activity 的外部副作用已成功、未重复或可撤销|

## 3. 可安全重试决策表（执行前）

先记录：`source`、API/版本、scope、请求参数、幂等键、输入哈希、客户端开始/结束时间、首次响应（若有）、重试次数、`observed_at`。任何不满足“已知”条件的项进入 UNKNOWN。

|条件/检查|结论|动作|状态与理由|
|---|---|---|---|
|纯读请求；没有副作用；游标/分页参数未变；响应明确可重放|SAFE-RETRY|按官方分页协议重试；保存页内容、Link/nextToken/continue|verified 的 API 读取性质；不能因此声称快照一致|
|Step Functions STANDARD；相同 stateMachine、相同 name、相同 input；执行仍运行或可查到相同执行|SAFE-RECONCILE（不是重新创建）|优先 `DescribeExecution`/`GetExecutionHistory` 确认原执行；不要生成新 name|verified：`StartExecution` 文档的幂等条件|
|Step Functions STANDARD 相同 name 但 input 不同，或原执行已关闭|BLOCK-RETRY|不得把它当同一执行；记录 `ExecutionAlreadyExists`/输入冲突并人工审查|verified：文档规定可能 400；重试语义不安全|
|Step Functions EXPRESS，或不确定是否 STANDARD|UNKNOWN→BLOCK|先查询/人工判定；没有证据时不重发 StartExecution|verified：EXPRESS `StartExecution` 不幂等；unknown 不能假定安全|
|Kubernetes LIST 的 continue token 仍有效|SAFE-CONTINUE|使用原请求边界与原 token；直到 `continue` 为空|verified：官方分页语义|
|Kubernetes continue token 过期、HTTP 410 Gone|RESTART-SNAPSHOT|从头 LIST；按新 `resourceVersion` 建立新边界，之后 WATCH；去重并标记 gap 风险|verified：token 默认短期有效、410 时需从头或省略 limit；完整性是推论，旧边界无法继续|
|Kubernetes WATCH 收到 410 / resource version 不可用|RECONCILE REQUIRED|重新 LIST 建立当前状态，再从返回版本继续 watch；不要从旧版本盲重放|verified：官方 “410 Gone” 语义；外部副作用未知|
|Temporal workflow task/worker 崩溃，已有 Event History 可读|SAFE-REPLAY（工作流层）|让 Temporal 以历史恢复；核验 Activity 的业务幂等键/结果记录|verified 仅限 history/replay；Activity 外部效果仍 UNKNOWN|
|Temporal Side Effect 已写入 history|不重执行该 Side Effect|依历史结果恢复；不要把 Side Effect 当可失败外部操作|verified；官方警告可失败 Side Effect 可能执行多次|
|GitHub REST 列表响应丢失，但请求是 GET|SAFE-RETRY-READ|按相同 URL、版本/授权范围重读；重新沿 Link 分页，去重稳定 ID|读请求可重试是方法推论；官方只规定分页，不保证全局快照|
|GitHub Actions workflow run `status`/`conclusion` 可查且 run ID 相同|RECONCILE|以 run ID、更新时间和日志/attempt 继续核对；不要因为客户端超时另触发 workflow|对象字段是 verified；“不另触发”是保守推论|
|写入/触发/删除请求的响应丢失，且无服务端幂等键或可查询唯一 ID|UNKNOWN→MANUAL|先查询效果/审计/目标状态；不能确认前不自动重发|通用安全规则；本次官方文档没有跨平台 exactly-once 承诺|
|发现旧 `event_time`、重复 event ID、迟到 addendum|RECONCILE/DEDUPE|按 `(source,event_id)` 去重；保留首次/最近 observed_at 与版本；按事件时间窗口回补|event ID/addendum 等平台事实 verified；窗口大小需业务确定|
|多来源都显示“最新”，但各自 watermark/observed_at 不相容|UNKNOWN|不要做跨源因果结论或触发补偿；扩大读取窗口并人工审查|inferred：无共同一致点/水位时不可判定|

## 4. freshness / watermark 记录模型

建议每条输入保存如下不可变元数据（示例是数据模型，不是官方平台字段）：

```text
source = aws_cloudtrail | sfn | temporal | kubernetes | github
source_scope = region / account / namespace / repo / workflow / execution
source_event_id = 官方 eventID、run_id、resource UID 等（若该源提供）
event_time = 源定义的事件/请求时间（可空）
observed_at = 本消费者成功收到并持久化记录的 UTC 时间
source_watermark = resourceVersion / nextToken / Link-next 完成点 / execution history boundary
query_started_at, query_finished_at
cursor_state = initial | page(n) | complete | expired | gap_detected
replay_window = [lower_bound, upper_bound] + reason
idempotency_key, input_digest, effect_status = confirmed | absent | unknown
```

**排序规则**：同一来源可在其文档语义允许时按版本/ID排序；跨来源只按 `observed_at` 做消费者观测顺序，不能用它证明事件发生顺序。事件时间倒退、重复或迟到不是异常证明；先去重、再按来源水位补读。窗口上界应是“读取完成时刻”减安全迟延余量，余量由测量/业务 SLA 设定；官方文档未给出本系统可直接采用的统一数值，因此数值是 **unknown**。

## 5. UNKNOWN 判定与人工升级

以下任一情况即 UNKNOWN，而不是失败：

- 网络超时/连接断开发生在写请求响应之前，且没有可查询的服务端请求 ID、执行 ID 或幂等键；
- 查询游标过期、响应跨页边界不明、来源发生 410/gap，尚未完成重建 LIST/历史；
- 只有 event_time，没有 observed_at 或来源 watermark；
- “历史显示已完成”但没有外部效果确认（例如付款、邮件、下游写入）；
- 事件 ID 缺失/重复冲突，或同一 ID 的 payload/input 不一致；
- 多个来源时钟/范围不一致，无法证明覆盖同一个切片；
- 重试将改变业务输入、生成新执行 ID，或可能触发不可逆/非幂等外部副作用。

**必须人工升级**：不可逆写入/删除/通知/财务/权限变化；输入冲突；检测到水位 gap；重复事件可能已造成第二次外部效果；服务端状态与审计/历史矛盾；超过业务定义的 replay window；自动补偿可能扩大影响。升级包应包含：原始请求（去秘密）、源与范围、所有时间字段、游标/版本、ID/幂等键、响应和错误码、已采取的只读核对、影响假设、建议“重试/不重试/补偿”三选一。

## 6. 来源边界、冲突与覆盖

- **已验证（verified）**：仅指官方文字直接说明的平台行为（见 `sources.md` 与 manifest）。
- **推断（inferred）**：安全决策、跨源数据模型、去重/回补规则；它们是保守工程建议，不是平台保证。
- **未知（unknown/unverified）**：本次未获得统一 freshness SLA、跨页快照保证、跨源 watermark、外部 Activity exactly-once 或副作用完成证明。
- **冲突（conflicting）**：没有发现同一官方文档之间对上述核心语义的直接矛盾；但“Temporal history 可重放”与“外部 Activity 效果可重放/ exactly-once”不能合并，这是**边界差异**，不是冲突。AWS CloudTrail 事件历史的可见性/保留描述与实时、跨区域、所有事件覆盖也不是同一命题。

检索范围为上述四类官方文档及其 API reference，使用公开 HTTPS 页面；未访问私有 API、账户、仓库或凭据。发布日期/更新时间在页面未稳定暴露的条目在 `sources.md` 记为“页面日期未核实”，不是编造日期。
