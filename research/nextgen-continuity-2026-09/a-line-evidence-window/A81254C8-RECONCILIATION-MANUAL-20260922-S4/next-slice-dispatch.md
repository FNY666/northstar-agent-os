# 下一独立切片建议（S5）

## 建议主题
**跨来源证据的 freshness / watermark / replay 窗口与“可安全重试”决策表**。

## 为什么独立
S4 已定义证据 envelope 的字段和状态机，但没有测定或验证不同来源（CloudTrail、Step Functions、Temporal、Kubernetes、GitHub）在延迟、分页、watch 断线、历史保留和事件乱序下的统一重conciliation 窗口。S5 应只研究这一时间/水位问题，不读取或改写 S4 以外任何本地研究产物。

## 公开官方一手资料范围

- AWS CloudTrail 官方文档：事件交付/可用性、event history 时间范围、Lake 查询时间语义。
- AWS Step Functions 官方 API：GetExecutionHistory 分页、反序、历史事件 timestamp。
- Temporal 官方文档/API：history 分页、continue-as-new、workflow/activity retry 与 replay 边界。
- Kubernetes 官方 API Concepts：resourceVersion、watch bookmarks、410 Gone、list/watch consistency、事件对象字段/保留说明。
- GitHub 官方 Actions/REST/Webhooks：run/deployment 时间字段、状态中间态、environment approval/review 事件与重试。

## 预期交付

1. 一张“source → watermark/sequence → max staleness → query completeness → retry decision”矩阵。
2. 明确区分 `not_observed`、`not_found_in_window`、`no_match`、`stale` 和 `source_incomplete`。
3. 仅提出可证据支持的 retry gate；不得声称 exactly-once、零重复副作用或跨源全序。
4. 用官方文档的直接字段/语义支撑每一行；不能用生产经验替代来源证据。

## 安全边界

使用全新目录；不读取、复制或修改 `shared/P0`、事故目录、D10、L12、D14、canonical、staging、140、tri-line、systemd、真实服务或凭据。完成后运行 manifest validator 与 `sha256sum -c SHA256SUMS`，在回报中粘贴完整输出。
