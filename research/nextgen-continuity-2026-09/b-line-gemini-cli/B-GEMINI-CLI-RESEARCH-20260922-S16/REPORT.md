# S16 缺口矩阵：官方证据不能证明的恢复/审计能力

- 研究时间：2026-09-22（Asia/Shanghai）
- 研究范围：仅 `google-gemini/gemini-cli` 官方公开 GitHub 文档、源码、测试、API；未 clone 仓库。
- 研究边界：本报告只判断公开材料是否证明下列能力；不把 Gemini CLI 的本地控制流外推为外部服务、分布式系统或合规审计保证。
- 结论标签：`verified` = 官方材料直接支持的局部事实；`inferred` = 对局部事实的保守推断；`unknown` = 未找到足以证明该能力的官方证据；`conflict` = 官方材料中存在相互冲突的证据。
- 重要说明：`unknown` 不是“没有实现”，而是本轮公开证据不足以证明目标性质。

## 总览

| 缺口 | 结论 | 已有本地控制证据 | 为什么不能推出目标结论 | 需要补充的证据 |
|---|---|---|---|---|
| 授权快照 | **unknown** | 工具审批由 policy engine 按规则、模式和优先级计算；checkpoint 保存会话、工具调用和项目 Git snapshot。[S1][S2] | 快照描述项目/会话状态，不是“执行时生效的授权决策、主体、规则输入、版本”的不可变快照；未见恢复时授权复核或快照绑定规范。 | 官方设计/测试证明每个副作用请求记录并冻结主体、策略输入/决策、时间、版本，并在恢复/重放时强制复核；含篡改/崩溃测试。 |
| 策略版本 pinning | **unknown** | policy engine 有分层位置和优先级，workspace policy 还有完整性检查；政策更新可触发确认。[S3][S4] | 优先级和完整性检查不等于按提交/内容哈希 pin 到一次工具执行；公开文档没有执行记录中的策略版本/哈希，也没证明恢复使用旧策略还是当前策略。 | 官方规范与测试：策略内容哈希/版本进入每次决策记录，恢复、重试、并发更新下均固定或明确失败。 |
| 完整审批日志 | **unknown** | hooks 提供 BeforeTool/AfterTool 等事件，包含 session_id、transcript_path、hook_event_name；会话保存工具执行输入输出。[S5][S6] | hook/会话记录是可扩展的本地事件与 transcript，不等于完整、不可抵赖、不可丢失的审批日志；未证明 deny/ask/allow、审批者、策略匹配、时间序列和失败事件全部持久化。 | 官方审计事件 schema、覆盖矩阵（允许/拒绝/超时/崩溃/策略变更）、持久化原子性与导出/校验测试。 |
| 工具去重/幂等键 | **unknown** | ToolRegistry 按名称注册，重复名称会覆盖并输出警告；列表去重；模型循环有 loop detection 设置。[S7][S8] | 工具名称去重/循环检测不等于副作用调用去重；未见每次调用唯一键、服务端幂等语义、重试去重或跨进程协调。 | 官方协议定义 call-id/idempotency-key 生命周期，并测试相同键重试、并发、进程重启、部分成功。 |
| 远端状态 read-back | **unknown** | 工具执行后有 AfterTool hook；某些工具输出会进入会话记录。[S5][S6] | hook 收到工具结果不证明 CLI 会向远端系统读取并核对最终状态，更不证明写入成功、提交可见性或一致性。 | 官方工具契约明确写后 read-back、资源版本/ETag 或状态证明，并有远端故障与最终一致性测试。 |
| 副作用回滚 | **inferred（仅限受支持的本地文件 checkpoint）** | 文件修改前可创建 shadow Git checkpoint；`/restore` 可恢复项目文件、会话，并重新提出原工具调用。[S2] | 证据只覆盖本地文件和会话；文档没有证明外部 API、数据库、云资源、shell 副作用可补偿，也没有原子跨资源回滚。 | 官方按工具类型声明回滚/补偿语义；外部副作用的可重复恢复、失败中断、补偿失败和审计测试。 |
| exactly-once | **unknown** | 会话自动保存；checkpoint 保存工具调用；hooks 测试可验证某些 agent hook 每轮一次。[S5][S9] | 单轮 hook “exactly once”不等于工具副作用 exactly-once；崩溃窗口、重试、恢复、并发、远端提交均未被证明。 | 端到端故障注入测试，证明每个副作用事务在重试/恢复/多进程下 exactly-once，或明确 at-least-once/去重语义。 |
| 跨进程身份 | **unknown** | session 有 UUID/`session_id`；UI 可显示登录用户身份；checkpoint 测试隔离 Git identity。[S5][S10][S11] | 会话 ID、显示邮箱或 Git identity 都不是跨进程、不可伪造、可验证的执行主体凭证；未见进程间身份传递/绑定/撤销。 | 官方身份模型与协议：主体凭证、进程/会话绑定、签名/验证、权限变化和跨进程重启测试。 |
| fencing token | **unknown** | policy 与工作区信任/完整性检查能阻断部分不合规工具操作；worktree 可隔离会话。[S3][S12] | 隔离和拒绝规则不等于单调 fencing token；未见持有旧 token 的进程在资源侧被拒绝，也没有租约/epoch 语义。 | 官方并发控制设计：每次副作用携带单调 token，资源端校验，旧 token 被拒绝；含暂停、恢复、进程失联测试。 |
| 事件持久送达 | **unknown** | hooks 定义 SessionStart/SessionEnd/BeforeTool/AfterTool 等事件；会话落盘，且有磁盘满时禁用记录的明确告警。[S5][S6][S13] | 事件存在与 transcript 落盘不证明事件 durable delivery、顺序、重放、ack 或崩溃后补发；“磁盘满则禁用”反而说明不能据此推出无损送达。 | 官方事件队列/存储语义、ack 与重放协议、顺序和崩溃/磁盘满测试，以及丢失告警与恢复证明。 |
| 长期审计保存 | **conflict（局部保存与自动删除并存；目标能力仍未证明）** | 会话默认保存完整对话、工具执行和 token 数据；默认 30 天清理，可按 maxAge/maxCount 配置；删除会连同相关 artifacts。[S6][S14] | “本地保存”与“长期审计保存”不是同一性质；默认自动清理、手动删除和磁盘不足禁用记录，与无期限/合规保全保证不相容。官方未定义不可篡改存档、法定 hold、导出完整性或跨设备备份。 | 官方 retention/保全规范、不可变存储和 legal hold 机制、完整性校验、备份恢复、删除/保留冲突测试。 |

## 逐项证据边界

1. **授权与策略**：S3 明确规则匹配、优先级、approval mode；S4/S3 的完整性保护只说明配置安全检查/更新确认，不产生“执行授权快照”或“版本 pinning”。
2. **会话、checkpoint 与回滚**：S2 明确本地文件修改前 shadow Git snapshot、会话和工具调用；其作用范围不能扩展到远端副作用。S6 明确会话 JSON/JSONL 本地存储和恢复。
3. **hooks 与审计**：S5 定义事件和 transcript 路径；S9 的 exactly-once 测试文字针对 BeforeAgent/AfterAgent 每轮事件，不能替代副作用 exactly-once 或完整审批审计。
4. **工具注册与去重**：S7 的“deduplicated”是工具列表/注册结果层面；没有 idempotency key 或服务端去重契约。
5. **保留与可靠性**：S6/S13/S14 证明有本地记录、自动清理和磁盘满处理，但没有 durable event delivery 或长期审计保全。

## 研究结论

本切片没有把缺失的分布式保证改写成“未发现实现”，而是保留为 `unknown`；唯一标 `conflict` 的是长期保存：官方材料同时证明了会话本地保存和默认自动删除，因此不能声称长期审计保存。局部的 `inferred` 仅限 checkpoint 文档明确覆盖的本地文件恢复范围。
