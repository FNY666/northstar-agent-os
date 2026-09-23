# S10 Sources (Stripe official only)

访问日期：2026-09-22。以下均为公开官方文档；未执行 API 调用。

| ID | URL | 直接支持的要点 | 状态 |
|---|---|---|---|
| S1 | https://docs.stripe.com/webhooks | 2xx/快速响应、投递状态、live 三天重试、sandbox 几小时三次、手动重放窗口、重复事件/事件排序、API version、endpoint version、retrieve 缺失对象、签名与异步队列 | verified |
| S2 | https://docs.stripe.com/api/events | Event `api_version` 静态；data 内容不变；data.object 与直接 retrieve 的关系；30 天 Event retrieve/list；list 按创建时版本渲染 | verified |
| S3 | https://docs.stripe.com/api/payment_intents/retrieve | PaymentIntent 状态枚举、字段、每个 PI 最多一个成功 charge 的生命周期描述；retrieve 对象边界 | verified |
| S4 | https://docs.stripe.com/api/payment_intents/update | update 不确认；某些更新需再次 confirm；payment_method 更新总是需再次 confirm；API 返回 PI | verified |
| S5 | https://docs.stripe.com/api/payment_intents/cancel | 可取消状态；取消后无额外扣款且后续操作报错；requires_capture 自动退款；非法状态返回错误 | verified |
| S6 | https://docs.stripe.com/api/versioning | 2xx/4xx/5xx；幂等键结果复用、参数比较、至少 24 小时后可清理；API version 概览 | verified |
| S7 | https://docs.stripe.com/payments/paymentintents/lifecycle | processing 可持续数日（异步方式）；succeeded 与履约指引；取消窗口/特定异步方式限制 | verified |
| S8 | https://docs.stripe.com/webhooks/process | 页面返回 404，未作为证据使用 | inaccessible |

## 证据纪律
没有使用搜索摘要、第三方材料、登录页面、Stripe API 调用或真实账户数据。S1/S2 对 event 与 retrieve 的表述形成“同对象定义/最新读取”的时间边界，而非冲突：它们适用于不同时间语义；没有发现可直接解决统一强一致 SLA 的官方声明，因此标为 unknown。
