# Sources

访问日期：2026-09-22（Asia/Shanghai）。仅列公开一手官方文档/官方源码。`verified`=来源明确陈述；`inferred`=由官方陈述组合出的工程判断；`unknown`=该来源不承诺。

## Apache Kafka

1. **Apache Kafka 官方源码：ProducerConfig.java（trunk）**
   URL: https://raw.githubusercontent.com/apache/kafka/trunk/clients/src/main/java/org/apache/kafka/clients/producer/ProducerConfig.java
   状态：verified
   证明：`acks=0` 不等待 broker 且不能保证 server 收到；`acks=1` 仅 leader 本地写入且 leader 故障可能丢失；`acks=all/-1` 等待 ISR，是最强可用保证；`enable.idempotence` 在约束满足时防 producer 重试写入重复。
   不能证明：consumer 已取到、业务代码已执行、外部数据库/工具调用已提交；“exactly one copy in stream”不是业务 exactly-once。
   限制：trunk 是滚动开发分支，不等于固定发行版；生产应按实际 Kafka 版本核验。源码/文档表达的是 Kafka 记录写入边界。

2. **Apache Kafka 官方源码：ConsumerConfig.java（trunk）**
   URL: https://raw.githubusercontent.com/apache/kafka/trunk/clients/src/main/java/org/apache/kafka/clients/consumer/ConsumerConfig.java
   状态：verified + inferred
   证明：auto commit 是后台周期性提交 consumer offset；`max.poll.interval.ms` 是 poll 间隔约束。
   不能证明：offset commit 与业务事务原子；commit 不等于下游业务完成。后者是从 offset 定义与分布式边界得出的 inferred。
   限制：trunk 滚动版本；默认值、消费者协议与 offset 行为需按发行版复核。

3. **Apache Kafka 官方文档：Semantics**
   URL: https://kafka.apache.org/documentation/#semantics
   状态：verified/unknown（本次直接抓取动态页面未返回可引用正文，链接作为官方规范入口）
   证明：官方语义入口用于 producer/consumer delivery、ordering、transactions 的版本化说明。
   不能证明：在未核对具体版本与配置时，不可声称通用 exactly-once 或固定 retention/overload 阈值。
   限制：动态页面、版本滚动；应锁定发行版文档。

## Amazon SQS

4. **Amazon SQS Developer Guide：Visibility timeout**
   URL: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
   Markdown URL（本次读取）：https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.md
   状态：verified
   证明：Receive 后消息仍在队列但暂时不可见；默认 30 秒；未及时 Delete 则再次可见；标准队列 at-least-once，visibility 内也不保证不重复；in-flight 约 120,000；short polling 达限 `OverLimit`，long polling 不返回新消息；FIFO 同 MessageGroupId 顺序受 in-flight/delete/timeout 控制。
   不能证明：业务处理成功、外部副作用提交、Delete 与外部事务原子。
   限制：`latest` 文档；in-flight/吞吐依 queue type、region、账号和服务更新；约数不是 SLA。

5. **Amazon SQS Developer Guide：At-least-once delivery**
   URL: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/standard-queues-at-least-once-delivery.html
   状态：verified（本次页面 meta/官方页面可访问）
   证明：standard queue at-least-once 语义与重复处理注意事项。
   不能证明：SendMessage 成功后已消费或业务 commit；不能把 API success 当 execution receipt。
   限制：latest 文档；standard queue 语义，不能代替 FIFO 配置审查。

6. **Amazon SQS Developer Guide：Quotas related to messages**
   URL: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html
   Markdown URL：https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.md
   状态：verified
   证明：message retention 默认 4 天、最小 60 秒、最大 14 天；FIFO throughput/批量和 message group 相关配额。
   不能证明：消息在 retention 内一定已执行或业务结果；配额不是 admission receipt。
   限制：latest、region/type dependent；数字随 AWS 更新。

7. **Amazon SQS API Reference：SendMessage**
   URL: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html
   状态：verified/inferred
   证明：官方 API 成功响应/MessageId 是发送 API 的服务响应边界。
   不能证明：consumer receive、业务处理或下游 commit；该不能证明项是 inferred 的分层结论。
   限制：API latest；成功响应不应被解释为跨系统事务。

8. **Amazon SQS API Reference：DeleteMessage**
   URL: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_DeleteMessage.html
   状态：verified/inferred
   证明：DeleteMessage 是消费者删除消息的 API 控制点。
   不能证明：外部业务事务与删除原子；调用成功不提供业务 commit 证明。
   限制：standard queue 可能有多副本/重复可见等服务语义；需按 queue type 复核。

## NATS JetStream

9. **NATS 官方 GitHub 文档源码：Streams**
   URL: https://raw.githubusercontent.com/nats-io/nats.docs/master/nats-concepts/jetstream/streams.md
   状态：verified
   证明：JetStream publish ack 表示成功存储；MaxAge/MaxBytes/MaxMsgs/MaxMsgSize；DiscardOld 删除旧消息，DiscardNew 拒绝新消息并由 publish 返回错误；`Nats-Msg-Id` 滑动窗口去重；WorkQueue/Interest ack 后删除规则与 limits 始终适用。
   不能证明：publish ack 后 consumer 已执行；去重窗口外或业务副作用 exactly-once；limits 不会导致过期。
   限制：master 滚动文档；字段版本表以文档为准但部署需按 nats-server 版本核验。

10. **NATS 官方 GitHub 文档源码：Consumers**
    URL: https://raw.githubusercontent.com/nats-io/nats.docs/master/nats-concepts/jetstream/consumers.md
    状态：verified
    证明：consumer 是 stream 的 stateful view；JetStream consumer 至少一次；未 ack/nack 自动 redelivery；AckWait 到期重投；MaxAckPending 流控；pull 客户端驱动流控；FlowControl 与 RateLimit；MaxDeliver advisory。
    不能证明：consumer ack 是下游事务 commit；redelivery 表示业务绝未执行；平台 exactly-once external side effect。
    限制：master 文档；字段标注版本（如 2.2.0、2.14）但客户端/服务器组合要复核。

11. **NATS 官方 GitHub 文档源码：JetStream overview/README**
    URL: https://raw.githubusercontent.com/nats-io/nats.docs/master/nats-concepts/jetstream/README.md
    状态：verified
    证明：stream storage 与 consumer consumption 分离；limits/discard；replication；非复制 file stream 默认 sync interval 可能使最近 acknowledged 消息在 OS 故障后丢失；WorkQueue 的 exactly-once consumption 描述范围。
    不能证明：跨外部系统 exactly-once；“exactly-once consumption”不能当业务完成证明。
    限制：master 滚动页面；sync_interval、复制因子、存储类型和 OS 故障模型必须记录。

12. **NATS 官方文档：JetStream pull consumers in depth**
    URL: https://docs.nats.io/learn/jetstream/pull-consumers
    状态：verified（页面 canonical）
    证明：pull consumer 以 batch/请求形式控制消费，适合 scalability、flow control、error handling。
    不能证明：fetch/response 是业务 completion；取到消息不等于 commit。
    限制：页面当前 docs 2.15 latest，客户端行为/版本需复核。

## RabbitMQ

13. **RabbitMQ 官方 GitHub 网站源码：Consumer Acknowledgements and Publisher Confirms**
    URL: https://raw.githubusercontent.com/rabbitmq/rabbitmq-website/main/docs/confirms.md
    官方页面 URL: https://www.rabbitmq.com/docs/confirms
    状态：verified
    证明：publisher confirms 覆盖 publisher 与连接 node/queue(or stream) leader；consumer acknowledgements 覆盖 RabbitMQ 到 consumer 的 delivery；两者正交、互不知晓；consumer ack 是应用告知 delivery 已成功接收/处理的 broker 边界；连接/通道故障及 requeue 是可靠性路径。
    不能证明：publisher confirm 后 consumer 已收到或业务完成；consumer ack 后外部事务原子/唯一；broker ack 不能替代 execution receipt。
    限制：本次 rabbitmq.com 直接访问被 Cloudflare challenge；引用同域官方仓库 main 的页面源码。main 滚动；具体 RabbitMQ release、AMQP 协议与 queue type 需锁定。

14. **RabbitMQ 官方 GitHub 网站源码：Queues**
    URL: https://raw.githubusercontent.com/rabbitmq/rabbitmq-website/main/docs/queues.md
    官方页面 URL: https://www.rabbitmq.com/docs/queues
    状态：unknown（本次 direct fetch 被 Cloudflare challenge，未采纳未验证细节）
    证明：仅作为官方队列文档入口记录。
    不能证明：本报告未从本次抓取结果引用具体 queue overflow/ordering 数字。
    限制：Cloudflare、main 滚动；勿把未抓取正文当已核验。

15. **RabbitMQ 官方 GitHub 网站源码：TTL**
    URL: https://raw.githubusercontent.com/rabbitmq/rabbitmq-website/main/docs/ttl.md
    官方页面 URL: https://www.rabbitmq.com/docs/ttl
    状态：unknown（本次 direct fetch被 Cloudflare challenge）
    证明：仅记录 RabbitMQ 官方 TTL 资料入口。
    不能证明：本报告不据此断言具体 TTL/过期顺序。
    限制：需未来按固定 release 重新验证。

## 交叉规范边界

16. **CloudEvents specification（CNCF 官方规范仓库）**
    URL: https://github.com/cloudevents/spec/blob/main/cloudevents/spec.md
    状态：unknown / 未用于核心事实
    证明：可作为事件标识/幂等键设计的规范入口。
    不能证明：任何 broker admission、ack、retention 或 execution semantics。
    限制：本报告核心结论不依赖该入口。

## 证据使用规则

- 只引用官方页面、官方文档仓库或官方源码；未采用博客、benchmark、营销比较或私有账号资料。
- “平台成功响应”全部按平台定义的相邻边界记录，不升级成 Agent 的业务完成。
- 所有数字（SQS 约 120k、4 天/14 天、Kafka/NATS/Rabbit 参数）都受版本、配置、region/集群与文档滚动更新限制。
