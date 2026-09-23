# S10 Summary

- **核心判断（verified + inferred）**：Webhook 2xx 只证明投递成功，不证明业务或外部支付效果完成。必须保存原始事件并异步处理。
- **去重**：`event.id` 是官方明确建议的重复投递键；不同 event.id 的同 PI/type 不能无条件丢弃。
- **版本**：Event `api_version` 在创建时固定，data 不随当前版本追溯变化；事件与 retrieve 必须版本感知。
- **一致性边界**：Event data.object 代表事件时对象；retrieve 代表读取时最新对象。官方未给强一致或统一时延 SLA。
- **窗口**：live 自动重试尽量三天；sandbox 新事件几小时重试三次。业务收敛窗口按支付方式/内部队列定义，不能从上述运输窗口直接推导。
- **人工门**：update/cancel 错误、版本/对象/关键状态 diff、冲突事件、超出组织定义的收敛窗口，均应人工复核。证据包须包含 event、去重、版本、retrieve、错误/request id 和履约/账务证据。
- **未知/不可访问**：无统一最终结算 SLA、人工阈值、逐字段跨版本映射；`/webhooks/process` 本次访问 404，未引用。
