# S11 来源台账

访问日期：2026-09-22（UTC）。Publisher 均为 Stripe；仅使用官方公开文档。

| ID | 官方 URL | 直接支持范围 |
|---|---|---|
| S1 | https://docs.stripe.com/api/events/types | 当前 snapshot event catalog；`payment_intent.*` 事件名、触发描述与 `data.object=payment_intent`；`charge.captured/expired/failed/pending/refunded/succeeded/updated` 的触发描述与 `data.object=charge`。也证明 dispute/refund 子事件不是 Charge 对象。 |
| S2 | https://docs.stripe.com/api/payment_intents/object | PI object 的完整 status enum：requires_payment_method / requires_confirmation / requires_action / processing / requires_capture / canceled / succeeded；每个 enum 定义；`capture_method`、`latest_charge` 等字段。 |
| S3 | https://docs.stripe.com/api/charges/object | Charge object；`payment_intent` 关联字段；Charge `status` 仅 succeeded/pending/failed；Charge 字段语义。 |
| S4 | https://docs.stripe.com/payments/payment-intents/verifying-status | PI 状态到 Dashboard 状态和描述；processing 的异步支付方式/数日/不保证；succeeded 的 funds-in-account 与可履约措辞；requires_capture；失败回到 requires_payment_method；webhook 履约、processing 等事件处理；polling 比 webhook 不可靠；Charge 退款/争议不改变 PI succeeded；列出全部关联 Charge 的说明。 |
| S5 | https://docs.stripe.com/payments/payment-methods | 即时/延迟成功通知；卡示例与 ACH 借记示例；processing 期间 pending、不履约；延迟方式应配置 webhook。 |
| S6 | https://docs.stripe.com/payments/place-a-hold-on-a-payment-method | 手动捕获：支持示例 cards/Affirm/Afterpay/Cash App Pay/Klarna/PayPal，不支持 ACH/iDEAL；授权后 requires_capture；amount_capturable_updated；授权过期释放资金并 canceled；捕获/取消边界。 |
| S7 | https://docs.stripe.com/webhooks | webhook endpoint：snapshot `data.object` 为事件时点对象并可 retrieve 最新资源；Stripe 不保证投递顺序；event ID 去重；可 retrieve 缺失对象；自动/手动重试范围。 |
| S8 | https://docs.stripe.com/payments/payment-intents | PaymentIntent 跟踪支付生命周期；创建/确认；服务端监控 webhooks；一个 PI 可有多个 Charge；metadata/order_id 关联仅用于对账。 |

## 直接证据摘录（短引）

- S4："A PaymentIntent with a `succeeded` status means the corresponding payment flow is complete. The funds are in your account and you can fulfill the order."
- S4："Don’t attempt to handle order fulfillment on the client side ... use webhooks to monitor the `payment_intent.succeeded` event."
- S4：processing："Only applicable to payment methods with delayed success confirmation"；Next steps："Wait for the initiated payment to succeed or fail."
- S5：延迟通知方式的 PI "will be `processing` until the payment status is either successful or failed"；"not fulfilling the order until the payment is successful."
- S6："After the payment method is authorized, the PaymentIntent status transitions to `requires_capture`."
- S6："Only some payment methods support separate authorization and capture"；明确示例与不支持示例见上表。
- S7："Stripe doesn’t guarantee the delivery of events in the order that they’re generated"；"You can also use the API to retrieve any missing objects."
- S1：`payment_intent.processing`："Occurs when a PaymentIntent has started processing."；`payment_intent.succeeded`："Occurs when a PaymentIntent has successfully completed payment."；`charge.pending`："Occurs whenever a pending charge is created."；`charge.updated`："...or upon an asynchronous capture."

## 访问与可复核说明

文档页面在访问日可通过上述 URL 公开读取。页面带有动态 Markdoc 渲染，但本研究同时读取了 Stripe 官方公开 `.md` 内容镜像路径（同一 docs.stripe.com 域），以保留可检索的直接文本。没有引用搜索摘要、第三方转述或不可访问页面。没有发现官方冲突；“完整支付方式清单”“事件顺序保证”“retrieve 重建历史事件/最终性承诺”等保持 unknown。
