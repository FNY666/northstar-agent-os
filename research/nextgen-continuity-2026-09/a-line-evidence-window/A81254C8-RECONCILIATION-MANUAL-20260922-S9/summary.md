# S9 摘要

## 研究对象
Stripe `PaymentIntent` 单一目标资源；仅使用官方公开文档，未调用 API、未接触凭据/真实服务。

## 核心校准

- **verified**：状态枚举是 `requires_payment_method`、`requires_confirmation`、`requires_action`、`processing`、`requires_capture`、`canceled`、`succeeded`。`processing`/`requires_action`/`requires_capture` 均不能直接当作已完成支付。
- **verified**：retrieve=`GET /v1/payment_intents/:id`；update=`POST /v1/payment_intents/:id` 且不确认；PaymentIntent 不做常规 DELETE，使用 cancel=`POST /v1/payment_intents/:id/cancel`。cancel 允许若干状态，`processing` 仅少数情况允许。
- **inferred**：内部四段状态机：`accepted`（请求层明确结果）→`observed`（同 ID read-back）→`settled`（Stripe 终态 succeeded/canceled）→`external_effect_committed`（本地/外部副作用经 effect key 去重并事务提交）。这些不是 Stripe 字段。
- **verified**：live webhook 失败自动重试最多三天、指数退避；sandbox 数小时三次；Dashboard 可重发 15 天、CLI 30 天；事件不保证顺序；重试/重发可重复。
- **inferred/unknown**：投递窗口不等于业务 read-back 窗口。官方未规定统一 read-back 秒数、轮询次数或成功标准。单次 2xx、单次 query、单个 webhook 都不足以证明最终业务完成。
- **verified**：POST 支持 `Idempotency-Key`，保存首次 status/body，参数不一致报错，GET/DELETE 无效果；这不等于 exactly-once，也不覆盖本地 webhook/外部副作用。
- **conflict**：API response version、webhook endpoint event version、账户默认/历史 event version 可能不同；必须记录运行时 version，不能从当前 docs 页推断具体账户版本。

## 操作底线

遇网络不确定性，用同一个 key + 完全相同参数重试，并 retrieve 同一 ID；webhook 先验签、记录 event ID/版本/投递尝试，快速返回 2xx，异步幂等合并；终态和金额/对象绑定经 read-back 校验后才进入 settled；副作用单独 outbox/ledger 去重提交。不得声称 production、exactly-once 或无重复副作用。

完整证据与 URL 见 `report.md`、`sources.md`。
