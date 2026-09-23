# C 线信任连续性 S62：多渠道通知投递、recipient coverage 与 ACK/retry/escalation

## 结论（离线合成、推断）

通知发送请求、渠道成功或单个 ack 不能单独证明所有应通知对象都收到正确版本的最终决定。只有 notification/decision/recipient identity、recipient set、channel、payload digest、delivery attempt/receipt、retry/dedup、ack 语义/时间、deadline/escalation/fallback、coverage、通知顺序、最终 read-back 和 audit 全部闭合时，才可判 `RECOVERED`。跨项目通知身份合并或同一 recipient/version 出现不可调和 delivered/failed 终态冲突判 `REJECT`；recipient 集合、渠道、receipt、ack、deadline、升级、重试、覆盖率或最终传播状态未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S61 产物。

## 判定门

1. `identity_conflict` 或 `notification_conflict` 任一为真，输出 `REJECT`。
2. notification/decision/recipient/version、channel/payload/attempt/receipt/retry/dedup、ack/deadline/escalation/fallback/coverage/order/readback/audit 任一门未闭合，或 delivery state unknown，输出 `UNKNOWN`。
3. 只有通知覆盖、投递证据、确认语义、升级策略、重试去重和最终状态全部闭合，才输出 `RECOVERED`。
4. 发送成功、渠道返回 2xx、单个 ack 或升级请求本身不能证明所有 recipient 已收到并采用正确版本；必须逐recipient对账和最终 read-back。
5. `RECOVERED` 仅表示本片夹具中的 notification evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。

## 覆盖与确定性验证

- 29 个定向 cases：notification/decision/recipient、channel/payload/attempt/receipt、retry/dedup、ack/deadline/escalation/fallback、coverage/order/read-back/audit，以及各边界缺口、身份冲突和通知终态冲突。
- 24 个布尔门执行完整 `2^24 = 16,777,216` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产邮件/IM/webhook/通知中心、delivery receipt、ack 或升级系统的验证。
- 未证明真实系统的 recipient coverage、渠道fallback、重试去重、已读/已接收语义、deadline/escalation、通知顺序或目标状态传播。
- 所有布尔门代表“证据是否已获得”，不模拟真实网络、用户行为或外部效果；生产接入必须逐recipient独立 read-back、保留payload/version/delivery audit，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
