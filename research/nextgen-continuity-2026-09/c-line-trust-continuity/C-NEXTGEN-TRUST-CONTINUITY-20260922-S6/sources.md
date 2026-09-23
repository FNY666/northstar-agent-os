# S6 官方一手来源

> 访问/核验日期：2026-09-22。仅列公开官方文档；未使用本地既有研究产物、shared/P0、事故目录、D10、L12、D14、canonical、staging、140、tri-line、systemd、真实服务或凭据。

1. Kubernetes, **API Concepts — Updates to existing resources; Resource versions; Efficient detection of changes**  
   URL: https://kubernetes.io/docs/reference/using-api/api-concepts/  
   Publisher: Kubernetes Documentation  
   直接证据：PUT 客户端带 `resourceVersion`；API server 用其检测 stale/lost update，过期时返回 HTTP 409 Conflict；可使 PUT/PATCH 条件于 resourceVersion；资源版本也用于 watch/change tracking；官方区分对象最近更新版本与 collection snapshot。  
   用途：C1、C8、C10–C12；resourceVersion fencing 与 read-back 限制。

2. Kubernetes, **Server-Side Apply**  
   URL: https://kubernetes.io/docs/reference/using-api/server-side-apply/  
   Publisher: Kubernetes Documentation  
   直接证据：SSA 追踪 field managers/`managedFields`；Apply 必须有 `fieldManager`；未指定 force 时，改变另一 manager 所管理字段的 Apply 遇 conflict 失败；文档描述 conflict 解决方式及 force。  
   用途：C2、C13；SSA field fencing 与版本 fencing 的区分。

3. Microsoft Azure, **Concurrency control in Azure Storage**  
   URL: https://learn.microsoft.com/en-us/azure/storage/blobs/concurrency-manage  
   Publisher: Microsoft Learn / Azure Storage  
   直接证据：Blob ETag 在写操作后更新；客户端将读到的 ETag 放入 `If-Match`；当前 ETag 不同则返回 HTTP 412 Precondition Failed，表示其它进程在首次读取后更新过 blob；文档还列出 If-None-Match 等条件 header，并说明 lease 保护操作的 precondition failure 示例。  
   用途：C3、C8、C10–C12。

4. Amazon Web Services, **Add preconditions to S3 operations with conditional requests**  
   URL: https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-requests.html  
   Publisher: AWS Documentation  
   直接证据：条件请求在 API header 中声明，不满足即使 S3 操作失败；支持按 ETag 的条件读/写，条件写可保证 PUT 时同 key 不存在（`If-None-Match` 语义）。  
   用途：C4、C8、C10–C12。

5. Google Cloud, **Request preconditions**  
   URL: https://cloud.google.com/storage/docs/request-preconditions  
   Publisher: Google Cloud Documentation  
   直接证据：使用 precondition 时请求仅在目标资源符合条件才继续；用于 upload/delete/metadata update 的竞态防护；generation-match 示例要求已有对象 generation 与给定值匹配；`if-generation-match:0` 适合已知对象不存在的情况；文档讨论 pre-read、成本和并发竞态。  
   用途：C5、C8、C10–C12。

6. Google Cloud, **Object metadata — Generation and metageneration numbers**  
   URL: https://cloud.google.com/storage/docs/metadata  
   Publisher: Google Cloud Documentation  
   直接证据：每个 Cloud Storage object 有 numeric `generation` 与 `metageneration`；generation 标识对象版本且每个对象都有；generation 在对象替换时改变。  
   用途：C5、C9、C12。

7. AWS Step Functions, **What is Step Functions? / Standard and Express workflows**  
   URL: https://docs.aws.amazon.com/step-functions/latest/dg/what-is-step-functions.html  
   Publisher: AWS Documentation  
   直接证据：Standard workflows 文档称 exactly-once workflow execution；Express workflows 文档称 at-least-once workflow execution；同页说明 Retry/Catch 可重试失败任务或转 alternative path。  
   用途：C6、C14；工作流语义不得外推为下游资源 exactly-once。

8. Microsoft Azure, **Handle errors and exceptions in workflows — Retry policies**  
   URL: https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-exception-handling  
   Publisher: Microsoft Learn / Azure Logic Apps  
   直接证据：支持 retry 的 trigger/action 在原始请求 timeout 或 408/429/5xx 失败时按策略重发；文档描述 Default、None、fixed、exponential 等 retry policy。  
   用途：C7、C11、C14；timeout/failure 是重试输入，不是提交结论。

## 证据等级与冲突说明

- 上述来源全部为 **primary / 官方一手**，但其产品文档是规范/使用语义而不是本研究的生产实验证据；本文没有将其误写成生产测试结果。
- 官方文档没有为所有 API 操作统一规定同一错误字符串/错误码；因此 S3/GCS 的条件失败在报告中要求保存完整 HTTP/JSON 响应，而不臆造跨 API 统一码。
- “条件拒绝 ⇒ 该条件操作未提交”是由各文档的条件检查语义作出的 **inferred** 协议结论；它不等于“旧 writer 没有此前副作用”。
- “精确 read-back ⇒ 新 writer 已提交”只有在 marker、版本、读新鲜度和并发歧义均被绑定时才是强证据；否则仍为 inferred/unknown。
