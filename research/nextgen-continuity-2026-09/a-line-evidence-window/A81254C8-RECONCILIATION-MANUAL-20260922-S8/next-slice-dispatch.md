# 下一独立切片派发建议

## S9（独立，不读取 S8 之外的既有材料）

**主题：Stripe 目标资源单类状态机与 webhook/read-back 窗口校准**

- 范围：仅 Stripe 官方资料；选择一个具体资源（建议 PaymentIntent 或 Subscription），覆盖 retrieve/update/delete（若该资源支持）、对象状态字段、事件类型、API version、idempotency、错误码、webhook 重试与事件重放。
- 交付：按状态机列出 `accepted/observed/settled/external_effect_committed`，给出每一步的直接官方证据；把投递窗口与业务 read-back 窗口明确拆开；预算按 API call、webhook attempt、manual review 计数。
- 必须验证：目标资源完整状态枚举及终态；更新后 retrieve 的字段；是否有 ETag/Last-Modified/条件更新；删除/取消准确语义；Webhook event `data.object` 与 retrieve 的差异；同一事件重复与不同 Event 对象重复的处理。
- 必须保持：所有声明逐条标 `[verified]`/`[inferred]`/`[unknown]`/`[conflict]`；不把 2xx、单 query、单 webhook 当完成证据；不声称 production/exactly-once/无重复副作用；仅官方一手资料。
- 禁止：不得读取或修改既有 A 线目录及任何受限目录（shared/P0、事故、D10、L12、D14、canonical、staging、140、tri-line、systemd），不得访问真实服务或凭据。
- 预算假设：任何未由官方文档给出的秒数、金额或 SLA 必须标系统推断或 unknown，不能伪造供应商保证。

## 备选 S10

仅选 AWS EC2 `RunInstances → DescribeInstances → TerminateInstances`，建立 Region/Zonal client-token 幂等域与实例状态 read-back/取消状态机；不得与 S9 并行写同一目录。
