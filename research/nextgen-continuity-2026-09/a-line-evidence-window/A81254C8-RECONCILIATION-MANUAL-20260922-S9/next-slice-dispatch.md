# 下一独立切片建议（S10）

## 建议主题
**Stripe PaymentIntent 事件快照 vs retrieve 当前对象的版本/字段漂移与对账规则**

## 独立性与边界
仅使用 Stripe 官方公开资料；新建独立目录，不读取 A 线既有目录或其他本地研究产物；不得调用真实 Stripe API、访问凭据或生产系统。不得访问/修改 shared/P0、事故目录、D10、L12、D14、canonical、staging、140、tri-line、systemd。

## 研究问题
1. 在不同 webhook endpoint API version、账户默认 API version、请求级 `Stripe-Version` 下，Event.data.object（snapshot）与 retrieve 返回对象有哪些官方记录的结构/字段差异？
2. 官方对 thin/snapshot event、事件 `api_version`、event retrieval、重复/乱序事件的定义分别是什么？
3. 如何只依据 event ID、object ID、created 时间、status、金额字段和 read-back 结果构造可审计的版本兼容对账记录，而不把 snapshot 当作当前真相？
4. 哪些字段差异可以标为 verified，哪些只能 inferred/unknown/conflict？

## 预期交付物
`report.md`、`sources.md`、`summary.md`、`research-manifest.json`、`SHA256SUMS`、`next-slice-dispatch.md`；逐条标注 verified/inferred/unknown/conflict；运行结构 validator（若存在）和 `sha256sum -c SHA256SUMS`；不声称 production、exactly-once 或无重复副作用。

## 建议验收点
- 明确区分事件生成时的对象快照、API retrieve 当前对象、事件 envelope 版本。
- 给出至少一个乱序/重放/版本漂移的纯文档推理例子，并显式标为 inferred。
- 不能以一次 2xx、一次 query 或一次 webhook 推导完成。
