# MCP、A2A、Agent Identity 与授权委派：Northstar M0/M1 生态研究

**研究日期：2026-10-17**
**结论范围：** 面向 Northstar Agent OS 的 M0/M1 真实仓库任务闭环；不把协议采用等同于自动化授权，也不建议无边界的多 Agent 编排。

## 所覆盖对象

本次核验覆盖五类一手资料：

1. **Model Context Protocol（MCP）**：官方授权规范，重点看受保护资源元数据、授权服务器发现、客户端注册、PKCE 与 scope/step-up 语义。[1]
2. **Agent2Agent（A2A）**：官方 1.0 规范及其 GitHub 源文档，重点看 Agent Card、长任务状态、任务级授权、推送通知和调用方范围检查。[2] [3]
3. **OAuth 2.0 Token Exchange（RFC 8693）**：IETF 已发布标准，重点看 subject/actor、audience/resource、scope 与委派链。[4]
4. **OAuth 2.0 Security BCP（RFC 9700）**：IETF 已发布安全最佳实践，重点看 PKCE、精确 redirect URI、refresh token 绑定/轮换等。[5]
5. **SPIFFE/SVID**：官方规范与概念文档，重点看工作负载身份、trust domain、短期凭证和信任包。[6] [7]

论坛、社区帖子和营销材料未作为产品事实依据；本报告只用规范、官方仓库、官方工程文档和 IETF RFC 支撑关键判断。网页或仓库中的操作性文字均按资料内容阅读，未执行其中的安装、部署或远程操作指令。

## Northstar 基线：M0/M1 要解决什么

Northstar 的产品目标是把真实仓库任务做成“理解 → 计划 → 执行 → 验证 → 交付”的单一闭环：隔离 Git worktree、受治理工具调用、预算与权限门、可恢复状态、补丁、验证回执和证据包。[8] 蓝图明确要求默认断网、精确网络目标、不自动提交或推送；计划是审计对象而不是权限凭据；模型不能伪造执行回执。[8]

当前仓库已经有本地 host policy grant、opaque `0700` workspace 候选和 signed handoff/interop 候选，但明确标注为本地或实验性，不是生产身份系统。[9] 这意味着 M0/M1 的核心缺口不是“再接一个协议”，而是把**外部身份、委派范围、调用预算、撤销/过期、任务关联和证据**接到既有 run/step/call 语义中，同时不让远端 Agent Card、模型文本或请求中的 capability 自行扩大权限。

## 经核验的机制

### MCP：资源授权发现做得具体，但不是任务治理

官方 MCP 授权规范要求 MCP server 作为 protected resource 实现 OAuth 2.0 Protected Resource Metadata，并要求客户端用它发现授权服务器；授权服务器还必须提供 OAuth Authorization Server Metadata 或 OpenID Connect Discovery，客户端需支持两种发现方式。[1] 规范同时定义了预注册、Client ID Metadata Documents 和 Dynamic Client Registration 的优先顺序，并要求授权码流程使用 PKCE 和 `resource` 参数。[1]

这对 Northstar 的直接价值是一个可实现的**外部工具连接器边界**：先把 MCP server 当作受保护资源，记录 resource URI、issuer、audience、scope、授权时间和 token 过期时间；请求进入工具权限门前，再把 MCP token 的验证结果映射为一次有界 tool-call grant。MCP 的机制解决“客户端怎样找到授权服务器并拿到访问令牌”，但没有替 Northstar 定义仓库 worktree、预算、检查命令、幂等恢复、证据包或最终交付状态。因此不能把“token 有效”当作“本次 run 可以执行任意工具”。

还要注意 scope 的现实风险：MCP 规范说明通用客户端通常缺少领域知识，可能根据资源元数据请求基本 scope，再通过 step-up 获取更多权限。[1] 对 M0/M1 应采取反向约束：scope 只能是宿主策略批准的交集，step-up 必须生成新的、绑定 run/call/资源/有效期的授权记录，并重新过权限门；不能因为 server 宣称支持更多 scope 就自动请求或授予。

**状态判断：** 这是已发布规范机制；它是工具资源授权的互操作底座，不是 Northstar 的完整授权模型。

### A2A：Agent Card 与长任务闭环有用，但授权语义故意留给实现

A2A 1.0 将 Agent Card 定义为 agent 的自描述清单，包含身份、版本、接口、能力、skills、安全方案/要求、输入输出模式，并支持签名字段；Card 可通过 well-known URI、注册表或直接配置发现。[2] [3] A2A 还原生支持同步、SSE 流式和 webhook 等长任务交互，任务对象有状态机，且 `TASK_STATE_AUTH_REQUIRED` 可以暂停任务等待授权。[2] [3]

对 Northstar，最有价值的是**把跨 Agent handoff 当作可恢复的外部任务**：保存远端 Card 快照和签名验证结果；创建本地 parent step 与远端 task ID 的关联；为每次发送、状态更新、artifact 和 webhook 生成独立 receipt；恢复时优先 Get Task/订阅/轮询，不因网络超时自动重放未知副作用。A2A 还要求每个操作执行调用方范围检查，List/Get/Cancel/Subscribe 等任务操作必须限制在调用方授权边界内。[2]

关键限制也很清楚：A2A 的任务级授权状态并不定义授权 scope、凭证格式、有效期或撤销语义；规范明确指出，`AUTH_REQUIRED` 本身不能被视为任何特定操作的授权，后续消息是否获得授权必须由实现、凭证签发者或扩展定义。[3] 规范还警告多 Agent 链中的 in-band credential exchange 会让链上每个 agent 接触凭证，推荐通过安全的 out-of-band 通道交付，并将凭证绑定到最初请求的 agent。[2] [3]

**状态判断：** A2A 1.0 是已发布规范；Agent Card/Task/receipt 形状可吸收。其“授权已满足”的部分不能直接复制，因为规范本身把核心授权语义留给部署方。

### RFC 8693：可表达“谁授权谁、谁在代办”，但不自动产生最小权限

RFC 8693 的 token exchange 请求区分代表被代办主体的 `subject_token` 与代表实际行动者的可选 `actor_token`，并支持用 `resource`/`audience` 限定目标、用 `scope` 表达目标服务上的请求范围。[4] 示例发行 token 保留 `sub`，并用 `act.sub` 表示当前行动者，从而可审计“管理员代表用户行动”。RFC 还特别指出，省略客户端认证会使被盗 token 可被 STS 换成其他 token；客户端认证使 STS 可以判断哪些实体允许 impersonation/delegation。[4]

这适合 Northstar 的 M1 handoff：把“用户/本地 actor → Northstar run → 远端 worker/工具”建成显式委派链，并在 audit event 中保存 subject、actor、audience/resource、scope、parent grant、issuer、expiry 和 exchange ID。对每个下游目标只交换窄 audience/窄 scope token，不复用上游 broad token。

但 RFC 8693 是令牌交换框架，不是产品政策。scope 的语义由资源服务定义，是否允许 impersonation/delegation 由授权服务器部署决定。[4] 因此 Northstar 仍需 host policy、单次 run/call 绑定、预算上限和撤销/过期检查；“成功换到 token”只能证明 STS 作出了一次发行决定，不能证明仓库状态已改变或验证通过。

**状态判断：** 已发布标准，可作为 M1 委派凭据的互操作适配层；不能把 token exchange 当成默认委派或自动信任。

### RFC 9700：MCP/A2A 外层 OAuth 必须采用的安全下限

OAuth Security BCP 要求授权服务器支持 PKCE；公共客户端必须使用 PKCE，建议使用 S256；redirect URI 要精确字符串匹配；不得使用 open redirector；多授权服务器客户端要防 mix-up；隐式授权不应使用。[5] 对 refresh token，服务器应基于风险决定是否签发；若签发，必须绑定到用户同意的 scope 和资源，并对公共客户端采用 sender-constrained refresh token 或 rotation 来检测重放。[5]

对 Northstar，这些是“连接协议”的安全门，而不是产品完整性证明：把 issuer、redirect URI、PKCE transaction ID、token hash、资源和 scope 写入审计；默认不保存不必要的 refresh token；恢复时不能把旧 token 当作仍可用，必须重新验证过期、撤销和资源绑定。不要复制隐式流、宽泛动态注册、任意 redirect 或无客户端认证的 token exchange。

**状态判断：** 已发布 BCP；M0 可先实现对现有 OAuth 适配器的约束检查，M1 再实现 sender-constrained/rotation 等部署能力。

### SPIFFE：证明“这是哪个工作负载”，不证明“这次 run 能做什么”

SPIFFE ID 以 `spiffe://trust-domain/workload-identifier` 唯一标识工作负载；SVID 是由该 trust domain 的权威签名、用于向资源或调用方证明身份的文档，可为 X.509 或 JWT。[6] [7] Workload API 提供身份、私钥、短期证书和 trust bundle，密钥与证书会自动轮换；官方概念文档建议能用 X.509-SVID 时优先使用，因为 JWT 容易遭受重放。[6]

它适合 Northstar 的 self-hosted/多进程部署：sidecar、host broker、runtime、远端 worker 各有 workload identity，且可将 mTLS peer identity 放入审计和 audience 校验。SPIFFE 的 trust domain 也提醒一个重要边界：跨 trust domain 的属性不能自动继承含义；SVID 中的任意附加字段若用于安全决定，必须有双方明确一致的语义。[7]

SPIFFE 不替代用户同意、run scope、capability、预算、任务授权或撤销。它还假设 workload 已充分隔离，凭证签发后恶意 workload 不会偷走另一 workload 的凭证；这个隔离机制本身在 SPIFFE 范围之外。[6] 因此 M0 不应为引入 SPIRE 而扩大部署面；可先把 SPIFFE peer ID 作为可选 caller identity 输入，缺失时继续本地显式身份/Unix 边界，且不把 SPIFFE ID 直接等同于用户身份。

**状态判断：** SPIFFE/SVID 是成熟的工作负载身份规范；Northstar 可选适配，但它不是委派授权规范，也不是本地 worktree 隔离的替代品。

## 与 Northstar M0/M1 的差距或互补

| 维度 | 外部规范提供 | Northstar 仍需自定义/补齐 |
|---|---|---|
| 工具资源授权 | MCP OAuth discovery、resource metadata、scope、step-up | 将 token 约束到具体 run/call/tool，默认断网与目标白名单，预算和 receipt |
| Agent 发现 | A2A Agent Card、接口/能力/安全要求、Card 签名字段 | Card 签名验证、版本/能力变化的审批、不可把描述性 skill 当权限 |
| 跨 Agent 任务 | A2A Task、流、webhook、AUTH_REQUIRED、长任务状态 | 本地 parent/child run 关联、幂等恢复、未知副作用不重放、artifact 证据包 |
| 委派身份 | RFC 8693 subject/actor、audience/resource、scope | 最小委派、单次/短 TTL、撤销、预算继承、审计链和 host policy 交集 |
| 工作负载身份 | SPIFFE ID/SVID、trust domain、短期轮换、mTLS/JWT | 用户/操作者同意、run authorization、仓库 worktree、内容隔离；不混淆身份与权限 |
| OAuth 安全 | PKCE、精确 redirect、refresh token 保护 | 本地凭证存储、token hash 审计、恢复时重新校验、断网默认值 |

因此建议的 M0 不是“支持所有协议”，而是做一个**窄的、可测试的协议边界**：MCP 只作为已批准工具资源；A2A 只作为显式 handoff/异步 task；身份映射只产生 caller/subject/actor 事实；最终允许动作仍由 Northstar host policy 决定。M1 才增加受限的 token exchange、远端任务恢复和可选 SPIFFE mTLS。

## 结论分类

### 可采纳

1. **采纳 MCP 的资源元数据发现与精确 resource/audience 绑定。** 每个 MCP server 连接都记录 issuer、resource、scope 和过期时间；只有经 host policy 批准的 server 才进入工具目录。[1]
2. **采纳 A2A 的 Agent Card 快照、Task 状态和异步 receipt。** 将 Card 当作不可信声明和版本化配置，不当作权限；远端 Task 映射到本地 run/step，并支持轮询/订阅恢复。[2] [3]
3. **采纳 RFC 8693 的 subject/actor/audience/resource 审计模型。** M1 的 handoff grant 必须保留委派链，且下游 token 只包含必要 audience/scope。[4]
4. **采纳 RFC 9700 的 OAuth 下限。** 统一 PKCE S256、精确 redirect、mix-up 防护和 refresh token rotation/sender constraint 的策略检查。[5]
5. **将 SPIFFE peer identity 作为可选 workload identity 适配器。** 先记录并验证 trust domain，再映射到 host policy；优先 X.509-SVID，避免在 M0 引入完整身份基础设施。[6] [7]

### 拒绝复制

1. **拒绝把 Agent Card 的 skills/capabilities 当授权。** A2A Card 是发现和协商材料；Northstar 的 capability 必须来自 host policy 与本次 run grant。[2] [3]
2. **拒绝把 `TASK_STATE_AUTH_REQUIRED` 当作“已授权”。** A2A 明确没有定义该状态的 scope、有效期和撤销语义。[3]
3. **拒绝跨 Agent in-band 传递原始凭证。** 这会扩大链上暴露面；采用 out-of-band/受绑定 token，并记录 exchange 和接收方。[2] [3]
4. **拒绝“token 有效即任务成功”或“模型声称完成即证据”。** OAuth/A2A 只证明通信或授权状态，不能证明 patch、检查、外部副作用或恢复安全。[4] [8]
5. **拒绝 M0 引入无边界注册表、自动发现后自动执行、隐式授权、宽 scope 和无界 Full Auto。** 这与 Northstar 默认断网、一次性 SubmitPlan、预算和证据门冲突。[8] [9]

### 待证

1. **A2A Agent Card 签名在真实部署中的信任根与轮换流程。** 规范提供签名字段，但 Northstar 仍需决定 trust store、撤销、Card 版本变化是否触发人工批准。[3]
2. **A2A webhook/push 在断网、重复投递和来源验证下的恢复测试。** 规范要求幂等处理与来源验证方向，但需要 Northstar 针对 delivery receipt、重放和未知副作用建立测试夹具。[3]
3. **MCP step-up scope 与 Northstar 预算继承的组合语义。** 需要证明 scope 增加不会绕过既有 run grant，且追加授权不会重置成本、网络或时间上限。[1]
4. **RFC 8693 委派链与下游服务撤销传播。** 需要在本地模拟 STS，测试 actor chain、audience mismatch、过期、撤销和 token replay，不以成功交换作为充分安全证据。[4]
5. **SPIFFE 在 Northstar 自托管拓扑中的成本/收益。** 需要测量 Workload API、trust bundle 轮换和 X.509 mTLS 对 sidecar/runtime/worktree 生命周期的影响；在验证前保持可选，不进入 M0 默认路径。[6]

## References

[1]: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization "Model Context Protocol Authorization Specification"
[2]: https://a2a-protocol.org/latest/specification/ "Agent2Agent Protocol Specification 1.0"
[3]: https://github.com/a2aproject/A2A/blob/main/docs/specification.md "A2A Official GitHub Specification"
[4]: https://datatracker.ietf.org/doc/html/rfc8693 "RFC 8693: OAuth 2.0 Token Exchange"
[5]: https://www.rfc-editor.org/rfc/rfc9700.html "RFC 9700: Best Current Practice for OAuth 2.0 Security"
[6]: https://spiffe.io/docs/latest/spiffe/concepts/ "SPIFFE Concepts: Workload, ID, SVID and Workload API"
[7]: https://spiffe.io/docs/latest/spiffe-specs/spiffe-id/ "SPIFFE ID and Verifiable Identity Document Specification"
[8]: https://github.com/FNY666/northstar-agent-os/blob/main/docs/next-gen-agent-blueprint.zh-CN.md "Northstar Next-Generation Programming Agent OS Blueprint"
[9]: https://github.com/FNY666/northstar-agent-os/blob/main/README.md "Northstar Agent OS README"
