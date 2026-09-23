# C 线信任连续性 S38：logs/metrics/traces/OTLP 多信号一致性与 export/drop

## 结论（离线合成、推断）

单个 log、metric、trace 或 OTLP export ack 不能证明跨信号连续性。只有身份域和 trace context 正确、logs/metrics/traces 均有明确的存在/缺失语义、跨信号关联键闭合、sequence 完整、export attempt 与 ack 可关联、exporter queue 与 retry 历史闭合、drop counter 已对账、OTLP scope/resource identity 一致、时间窗口闭合、sampling 策略已知、重复信号已去重且 export 状态不存在未知时，才可判 `RECOVERED`。身份冲突或同一 identity 的信号内容冲突判 `REJECT`；信号缺失、关联缺口、export ack 缺失、drop/retry 未对账、sampling 未知或远端状态未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S37 产物。

## 判定门

1. `identity_conflict` 或 `signal_conflict` 任一为真，输出 `REJECT`。
2. 身份、trace context、三信号存在性、跨信号关联、sequence、export attempt/ack、queue、drop counter、retry、OTLP scope、resource identity、时间窗口、sampling、去重任一门未闭合，或 export 状态未知，输出 `UNKNOWN`。
3. 只有全部信号、传输、对账和时间窗口门闭合，才输出 `RECOVERED`。
4. `NO_EVENT`、一个信号缺失、没有 export ack、只看到 exporter queue 空闲或只能看到 sampling 配置，都不能推出其它信号未发生，保持 `UNKNOWN`。
5. `RECOVERED` 仅表示本片夹具中的跨信号证据门闭合，不代表 telemetry 完整、export exactly-once、业务外部效果或生产可观测性。

## 覆盖与确定性验证

- 27 个定向 cases：三信号闭合、OTLP ack、drop 对账、采样边界、重复去重、resource 绑定，以及各信号/trace context/关联/sequence/export/queue/drop/retry/scope/resource/time/sampling/去重/远端状态缺口、身份冲突和信号冲突。
- 20 个布尔门执行完整 `2^20 = 1,048,576` 组合，使用流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产 OpenTelemetry、OTLP exporter、collector、队列、sampling 或 telemetry backend 的验证。
- 未证明真实系统的 signal correlation、resource/scope identity、drop/retry counters、export ack、queue drain、sampling semantics、duplicate dedup 或远端持久化语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实网络、collector 崩溃、后端查询或丢弃概率；生产接入必须独立 read-back、按 signal/attempt/batch 对账，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的证据门闭合，不代表 external effect、exactly-once、生产连续性或业务提交。
