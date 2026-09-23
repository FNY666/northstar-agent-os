# Sources｜S3 官方一手来源

访问日期均为 2026-09-22。网页更新日期未记录/不在本次提取页面可读元数据中时，标为“页面未注明”。

1. **Google Cloud Workflows — Creating callback endpoints**，页面未注明更新日期。https://docs.cloud.google.com/workflows/docs/creating-callback-endpoints  
   直接支持：workflow 创建 callback endpoint URL、await callback 及教程示例；教程后文指出生产应用中前端直接请求 callback endpoint 时进行认证。教程示例不能泛化为默认强制认证。
2. **Google Cloud Workflows — Create a human-in-the-loop workflow using callbacks**，页面未注明更新日期。https://docs.cloud.google.com/workflows/docs/tutorials/callbacks-firestore  
   直接支持：callback workflow 的人工审批流程及认证发生位置说明（生产应用通常在 callback endpoint 请求时认证）。
3. **Google Cloud Workflows — Function: events.await_callback**，页面未注明更新日期。https://docs.cloud.google.com/workflows/docs/reference/stdlib/events/await_callback  
   直接支持：函数等待 callback 被接收；用于控制流恢复语义，不支持推断对原始人类身份重认证。
4. **AWS Step Functions API Reference — StopExecution**，页面未注明更新日期。https://docs.aws.amazon.com/step-functions/latest/apireference/API_StopExecution.html  
   直接支持：StopExecution “Stops an execution.”、参数及 EXPRESS 不支持范围；页面未规定已派发外部副作用撤销和旧 callback token 的精确失效响应。
5. **AWS Step Functions Developer Guide — Connect to a resource / Wait for a Callback with Task Token**，页面未注明更新日期。https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html#connect-wait-token  
   直接支持：task token callback 等待；task 超时生成新随机 token；token 要由同 AWS account principal 传回。
6. **IETF RFC 6749 — The OAuth 2.0 Authorization Framework**, §6、§7，2012-10。https://www.rfc-editor.org/rfc/rfc6749.html  
   直接支持：授权服务器 MAY 发行新 refresh token，客户端收到后 MUST 替换旧 token，服务器 MAY 撤销旧 token；resource server MUST 验证 access token 的有效期和 scope。
7. **IETF RFC 7009 — OAuth 2.0 Token Revocation**, §2.1，2013-08。https://www.rfc-editor.org/rfc/rfc7009.html  
   直接支持：撤销 refresh token 时 SHOULD 撤销同 grant 的 access tokens（如支持）；撤销 access token 时 MAY 撤销 refresh token；传播延迟可能存在，成功响应后客户端不得再使用 token。
8. **Google Cloud Run — Configure request timeout for services**，页面未注明更新日期。https://docs.cloud.google.com/run/docs/configuring/request-timeout  
   直接支持：超时后连接关闭/504，处理请求的 container 不终止，代码可能继续；重连为新请求且不保证同一实例，长请求要求重试容错/幂等或可恢复。
9. **Google Cloud Run — Service identity / Authenticate service-to-service**，页面未注明更新日期。https://docs.cloud.google.com/run/docs/securing/service-identity 及 https://docs.cloud.google.com/run/docs/authenticating/service-to-service  
   直接支持：Cloud Run 配置服务身份、运行时从 metadata server 获取 access/ID token。仅说明工作负载身份获取路径，不说明业务旧 writer 在超时后被资源拒绝。
10. **Microsoft Azure Functions — Function app timeout duration (Functions scale)**，页面未注明更新日期。https://learn.microsoft.com/en-us/azure/azure-functions/functions-scale#timeout  
    直接支持：超出 function timeout 会产生 timeout error、重启语言 worker；in-process C# host 也重启；HTTP-trigger response 有 230 秒限制说明。
11. **Microsoft Azure Functions — App Service managed identities**，页面未注明更新日期。https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity  
    直接支持：managed identity token endpoint、平台轮换 `IDENTITY_HEADER` 以及通过 endpoint 申请资源 token。未据此推断旧执行被取消或访问凭证即时吊销。
12. **Kubernetes Documentation — Server-Side Apply**，页面未注明更新日期。https://kubernetes.io/docs/reference/using-api/server-side-apply/  
    直接支持：managed fields 及 manager 的字段所有权、冲突拒绝/force 转移；SSA client 要提供 field manager。manager 标签不等同认证主体或授权决策。
13. **Kubernetes API Reference — ObjectMeta / managedFields**，页面未注明更新日期。https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/object-meta/#ObjectMeta  
    作为 managedFields 结构参照；本切片的冲突/manager 结论主要依据上一条 SSA 指南。

## 来源质量及限制

以上官方来源均为 primary。RFC 属标准文本；厂商文档为各服务提供者的产品行为说明，但不是跨厂商一致性保证。页面当前状态按访问日记录，内容可能后续更新。未使用搜索摘要作为材料依据；搜索仅用于找到官方页面。没有其他来源冲突被发现；对缺少明确行为承诺的部分按 unknown，而非把文档沉默解释成不存在行为。
