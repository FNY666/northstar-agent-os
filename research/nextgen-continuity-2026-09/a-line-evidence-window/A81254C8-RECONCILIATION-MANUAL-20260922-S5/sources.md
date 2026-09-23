# S5 来源台账

仅列公开官方一手来源。访问日：2026-09-22。页面未稳定暴露发布日期/更新时间时明确标记，未猜测。

|ID|官方来源|直接支持|状态|
|---|---|---|---|
|S1|AWS CloudTrail, *CloudTrail record contents* — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html|`eventTime` 是请求完成 UTC 时间，时间戳来自提供 service API endpoint 的 AWS host；事件交付延迟可由 addendum 说明|verified；页面日期未核实|
|S2|AWS CloudTrail, *Working with CloudTrail event history* — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html|Event history 是过去 90 天 management events 的可查看、搜索、下载、immutable 记录；该范围/历史视图不等于全源实时水位|verified（范围）；后半为 inferred caveat|
|S3|AWS Step Functions API, *StartExecution* — https://docs.aws.amazon.com/step-functions/latest/apireference/API_StartExecution.html|STANDARD execution：同 name+input 且运行中时幂等并返回相同 response；关闭或 input 不同会 `ExecutionAlreadyExists`；关闭后 90 天可复用 name；EXPRESS 不幂等|verified；页面日期未核实|
|S4|AWS Step Functions API, *GetExecutionHistory* — https://docs.aws.amazon.com/step-functions/latest/apireference/API_GetExecutionHistory.html|Execution history API 的响应分页，使用 `nextToken` 继续|verified；页面日期未核实|
|S5|Temporal, *Events and Event History* — https://docs.temporal.io/workflow-execution/event|Temporal Service 为 workflow execution 追加 Event History，用于 crash recovery/durable execution；Side Effect replay 返回 history 中记录结果；可失败 Side Effect 可能执行多次，应使用 Activity|verified（历史/replay）；外部 Activity exactly-once 未被支持|
|S6|Kubernetes, *API Concepts* — https://kubernetes.io/docs/reference/using-api/api-concepts/|官方定义 resourceVersion、LIST/WATCH、bookmark/consistent read、watch cache、continue token；continue token 默认短期过期，不能继续时 HTTP 410 Gone；应从头开始或省略 limit|verified；页面日期未核实|
|S7|GitHub Docs, *Using pagination in the REST API* — https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api|分页响应使用 HTTP Link header；`rel="next"` 指向下一页；逐页直到无 next|verified；页面显示 API Version 2026-03-10，访问日记录为 2026-09-22|
|S8|GitHub Docs, *Actions workflow runs REST API* — https://docs.github.com/en/rest/actions/workflow-runs|workflow run 资源含 status/conclusion、run id、created_at、updated_at、attempt 等，列表 endpoint 有 page/per_page（max 100）|verified；页面日期未核实|

## 证据等级与限制

上述均为 primary（官方产品文档/API reference）。`verified` 仅覆盖页面明确陈述；决策表中的 SAFE/UNKNOWN/人工升级是基于这些事实的保守工程推断（inferred），并不声称平台保证。未使用搜索摘要、博客、论坛、第三方复述。没有发现同一官方来源对核心语义的直接冲突；Temporal history 的可恢复性与外部副作用的完成/唯一性属于不同命题。

## 关键摘录（短引，便于审计）

- CloudTrail：“The date and time the request was completed”以及 endpoint host timestamp；“If an event delivery was delayed … an addendum field…”（S1）。
- Step Functions：STANDARD “is idempotent”; EXPRESS “isn't idempotent”且相同 name+input 运行中返回 same response（S3）。
- Temporal：Event History 使 execution 从 crash “recover … and continue”; Side Effect “does not re-execute upon replay”且失败可能导致多次执行（S5）。
- Kubernetes：continue value 用于 next chunk；过期时 “410 Gone”，client “need to start from the beginning or omit the limit parameter”（S6）。
- GitHub：分页时用 response 的 “link header” 请求 additional pages，`rel="next"` 是 next URL（S7）。

## 未获取/不主张

没有查询任何真实 AWS account、Temporal namespace、Kubernetes cluster、GitHub private/public repository endpoint；没有凭据，也没有把平台 Event History、workflow status、CloudTrail record 解释为外部业务效果。没有官方材料支持一个跨 AWS/Temporal/Kubernetes/GitHub 的共同 watermark、统一 replay window 或 exactly-once 结论。
