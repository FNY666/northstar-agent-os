# C 线恢复授权研究｜独立公开切片 S3

**研究日期：** 2026-09-22（Asia/Shanghai）  
**范围：** 仅公开官方一手资料与 IETF RFC；不是生产环境验证，也不覆盖任何私有研究材料。

## 结论摘要

恢复/重试语义并不自动等于重新授权。现有资料支持的最强结论是：GCP Workflows callback 请求到达 callback endpoint 才推进等待中的 workflow；官方 human-in-the-loop 示例明确指出，生产应用通常由前端直接请求 callback endpoint，并在该请求发生时执行认证。资料没有说明暂停/恢复时引擎会重新验证原始用户/调用方身份，也没有证明 callback URL 本身的持有者验证可替代业务身份校验。AWS Step Functions `StopExecution` 是停止执行的 API；callback task 在等待时有 task token，task 超时会产生新随机 token，但官方资料没有明确描述停止瞬间已发出的外部工作是否能被撤销、或旧 token 对已停止执行的具体响应，故拒绝/失效只能谨慎推断，不能当作保证。

RFC 6749 对 refresh token rotation 仅规定授权服务器 **MAY** 发行新 refresh token；发行时客户端 **MUST** 丢弃旧 token，而服务端 **MAY** 撤销旧 token。RFC 7009 对撤销 refresh token 后使同一授权 grant 下 access token 失效使用 **SHOULD**，且撤销传播可能有延迟；不是全局即时级联保证。Cloud Run 的 504/断连不终止处理该请求的 container，旧代码可能继续运行；客户端重连是新请求且不保证落到同一实例。Azure Functions 超时导致语言 worker 重启（部分场景 host 也重启），这不等于生产系统里的身份/租约/写入被撤销。Kubernetes SSA `managedFields` 记录字段 manager 名称及字段所有权并在所有权冲突时拒绝非强制 apply；manager 名称由客户端提供，不是 API 服务器认证出的 principal，不能视作授权或 fencing。

## 逐项证据与状态

### S3.1 GCP Workflows callback 暂停/恢复与身份

- **Verified — callback 的控制流语义：** `events.create_callback_endpoint` 创建 callback endpoint URL；`events.await_callback` 等待收到 callback。官方文档表明收到 callback 后等待流程继续。它是正在等待的 workflow execution 的控制流继续，不是由资料所述的“重新启动一个新 workflow execution”。
- **Verified — callback 请求认证位置：** 官方 human-in-the-loop 文档写明，生产应用中 frontend 很可能直接请求 callback endpoint，认证会在那时发生；示例也将 callback endpoint 请求与认证步骤分开描述。
- **Unknown — 恢复时重新验证原身份：** 未找到官方材料说明 Workflow 引擎在 callback 恢复瞬间重新验证最初触发 workflow 的用户/调用方身份，或把身份快照重新作授权判断。
- **Inferred — callback endpoint credential 不是当然的业务授权：** endpoint URL/请求能触发继续这一控制流事实，不证明持有该 URL 的客户端已被业务层授权，也不证明该机制能阻止过期客户端写资源。必须由 callback 接入层/业务端进行适当认证、授权、重放控制；这是安全设计推论而非 GCP 提供 fencing 的承诺。
- **不作结论：** 不声称 callback token/URL 的格式、可猜测性、单次性/重放属性；本切片引用材料不足以断言这些性质。

### S3.2 AWS Step Functions `StopExecution` 与 in-flight callback/task

- **Verified — 停止 API：** `StopExecution` API 的定义是停止 execution，并提供 execution ARN、error/cause 参数；API 不支持 EXPRESS state machines。
- **Verified — callback 等待与 task token：** `.waitForTaskToken` 使 Task 暂停等待带 token 的 `SendTaskSuccess`/`SendTaskFailure`；task 超时时产生新的随机 token；task token 必须由同一 AWS account 的 principal 传回。
- **Unknown — `StopExecution` 对外部 in-flight 工作：** 资料没有说停止 execution 会取消已派发到外部系统的工作，也未在所查 API 页面说明已停止 execution 的旧 task token 回调会得到什么响应/错误。因此不能假设外部副作用已回滚或被停止。
- **Inferred（非保证）—执行终结与 token 是否可用：** execution 被停止后不应把其旧 callback 当作合法业务授权继续推进；但旧 token 的精确服务端拒绝语义、竞态窗口以及外部 worker 停止情况都需按相应接口约定/实测确认，文档证据不足以宣称“必然即时失效”。

### S3.3 OAuth refresh-token rotation / revocation cascade

- **Verified — rotation 是可选：** RFC 6749 §6：授权服务器 **MAY** 发行新 refresh token；客户端若收到新 token，**MUST** 丢弃并替换旧 token；服务端 **MAY** 撤销旧 refresh token。故标准没有要求每个 refresh 都旋转，也没有绝对规定旧 token 一定被服务端立即撤销。
- **Verified — 撤销级联为 SHOULD/MAY 且可能延迟：** RFC 7009 §2.1 建议（SHOULD）在撤销 refresh token 时也使同一授权 grant 下所有 access token 失效（前提是授权服务器支持 access-token 撤销）；反向地，撤销 access token 时可（MAY）撤销关联 refresh token。RFC 7009 同时承认传播延迟；客户端收到成功撤销响应后不得继续使用该 token。
- **Conflict/边界 — “cascade”不是一致性事务：** RFC 7009 的 MUST/SHOULD/MAY 用词及传播延迟，不能被概括成任意授权服务器、所有 resource server 上的即时全量撤销保证。RFC 6749 §6 的 rotation 也不构成单写者锁或资源端过期 writer 拒绝。

### S3.4 Cloud Run / Azure Functions 超时后服务身份

- **Verified — Cloud Run 超时与存活旧处理：** 请求超时后网络连接关闭并返回 504；Cloud Run 明确说服务该请求的 container instance 不会因此终止，代码可能继续处理已超时请求。重新连接时发起新 request，且不保证连到同一 instance。超长请求指南建议重试时保证容错（例如幂等或可恢复）。
- **Verified — Azure Functions 超时与进程：** `functionTimeout` 超时会发生 timeout error 并重启 language worker；in-process C# 场景 host process 本身也重启。HTTP trigger response 的平台连接限制另有 230 秒约束。
- **Verified — 服务身份的机制（Cloud Run）：** 官方文档展示运行时通过 metadata server 获取服务 identity 的 access token/ID token，并配置服务身份；这是平台工作负载身份能力，不是某次业务操作持有的用户授权/租约证明。
- **Verified — managed identity（Azure）：** Azure App Service/Functions managed identity 文档说明 app 经本地 identity endpoint 请求 token，platform 提供并轮换 SSRF 防护 header；平台能在重新启动的 worker 中提供该接口是合理的运行模型，但这一点本身不代表原请求副作用取消。
- **Inferred — 重建不等于旧 writer 失效：** worker/服务实例再启动后可再次向平台请求身份 token（Cloud Run/Azure 托管身份模型），但厂商的超时资料没有表明 timeout 会撤销此前已签发 token、终止另一实例的旧处理，或在资源端隔离 stale writer。Cloud Run 更明确给出旧处理可能继续。身份凭证重新获取 ≠ 对同一业务操作重新授权。

### S3.5 Kubernetes Server-Side Apply / `managedFields`

- **Verified — 管理字段与冲突：** Kubernetes API server 跟踪新建对象的 managed fields。SSA 申请更改另一个 manager 管理且值不同的字段会冲突并拒绝，除非请求强制覆盖；force 会覆盖冲突值并转移所有权。所有权归属变化取决于 field manager 的 apply/声明行为。
- **Verified — manager identity 边界：** SSA patch 要求客户端提供 field manager，`managedFields` 保存 field manager 对字段的管理记录。该字符串说明“哪个 manager 声称/维护字段”，本身不是经过认证的 human/service principal；API authorization/RBAC 是独立层。
- **Inferred — 对 stale-writer 的有限保护：** 若旧 writer 使用不同 manager 且其旧值与当前字段值冲突，SSA 可能拒绝；同 manager 复用、相同值共同拥有、force apply、普通更新路径或 API 权限允许的其他写法均不能由 `managedFields` 证明已被 fencing。manager ownership 是协作冲突检测，不是通用 epoch/fencing token，也不提供 exactly-once。

## 横向判断：可依赖与不可依赖

1. **已证实：** 超时/取消可与请求断开、worker 重启或 workflow execution 停止同时发生；远端处理或已发出的副作用不一定同步撤销（Cloud Run 官方明确如此）。
2. **已证实：** 凭证生命周期和资源写入生命周期不是同一概念。OAuth 撤销传播存在延迟；Cloud workload identity 可获取平台 token；SSA manager 记录字段管理者。
3. **未知/不可推导：** 上述 token、callback URL/task token、refresh-token rotation、服务身份 token、managedFields 记录，都不单独证明资源端对旧 writer 的生产授权已撤销、租约已过期、stale writer 必然被拒绝，或副作用 exactly-once。
4. **设计推论（非厂商承诺）：** 若业务要求恢复后阻止旧 writer，需在具体资源侧实现可原子检查的 generation/epoch/fencing 条件，并将其绑定到资源写入授权路径；要求幂等键/去重时还需明确其原子性及持久化范围。此处仅是由证据边界推出的待验证设计方向，不是声称任何被研究平台已提供该保证。

## 覆盖、限制与审计口径

- 截止 2026-09-22；仅检索及读取公开官方 docs 与 IETF RFC。来源均属规范发布者/平台官方一手资料。RFC 按规范原文的 MUST/SHOULD/MAY 解释。
- Workflows callback：读取 callback endpoint 文档及 human-in-the-loop 官方教程；后一文是教程例子，不应扩大为所有部署默认都已认证。对“resume 时是否重新验证原始身份”的明确平台行为未找到。
- Step Functions：读取 `StopExecution` API 与 callback/task token 集成文档；停止后旧 token 行为和下游取消不是 API 页面明确规定的事实，列为 unknown。
- Cloud Run / Azure Functions：聚焦 HTTP/request 与函数执行超时、服务/托管身份文档；未覆盖所有 plan、触发器、重试配置及各资源 API 的授权细节。
- Kubernetes：聚焦当前 Server-Side Apply 官方文档；未测试具体版本、请求路径或集群 RBAC 配置。
- **没有**访问真实服务/生产环境/凭据、私有账号、C 线既有目录或指定禁止区域；没有执行生产验证、故障注入或服务端行为测试。状态标签解释：verified=来源明确支持；inferred=由明确事实谨慎推得但非来源保证；unknown=官方材料未能判定；conflict=资料规范强度/边界不支持更强泛化（此处单列于 RFC 段）。

## 下一独立切片建议（S4）

**建议：资源侧 fencing 的公开规范映射与最小可验证设计。** 仅用官方数据库/云 API 一手规范，比较条件写（CAS/ETag/条件更新）、单调 epoch/fencing token、幂等键与 dedup ledger 在并发过期 writer 下的明确原子性边界；每项列清“服务器端拒绝条件、线性化点、重试语义、保留/过期窗口、exactly-once 不可推断部分”。不做真实资源操作，不把 lease/log 当授权或 fencing 证明。
