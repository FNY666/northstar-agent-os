# S11 摘要

## 一句话结论

以 `payment_intent.succeeded`（服务端 webhook）作为支付完成/履约输入；`processing` 等待成功或失败，`requires_capture` 只触发捕获动作，`canceled` 不履约。Charge 事件用于观察、捕获与对账，不是 PI 成功履约信号的无条件替代。

## 状态—事件最小图

```text
created
  -> requires_payment_method / requires_confirmation  [事件级对应未承诺]
  -> requires_action       --完成客户动作--> processing 或 succeeded
  -> processing            --延迟方式结果--> succeeded 或 payment_failed
  -> requires_capture      --capture--> 成功（事件/迁移细节需按流程读取）
  -> canceled              [取消/授权过期；不履约]

payment_intent.succeeded -> 服务端履约
payment_intent.payment_failed -> 通知/换支付方式
payment_intent.amount_capturable_updated -> 捕获
```

## 三条不可越界规则

1. 不用客户端返回作为唯一履约依据；监听 `payment_intent.succeeded`。
2. 不把 `processing` 或 Charge `pending` 当成功；异步方式不保证付款期间不履约。
3. 不假设事件有序或会完整到达；event ID 去重，缺失时 retrieve 当前对象，但不要声称 retrieve 能重建历史事件/提供最终性。

## 关键未知

官方未给出一份永久穷举的异步支付方式清单；未承诺 retrieve 补发事件/保存中间状态/最终性；未找到 `requires_payment_method` 或 `requires_confirmation` 对应 PI webhook。以上均按 unknown/unverified 处理。
