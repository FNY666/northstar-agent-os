# UNKNOWN 判定、幂等重试与补偿：公开一手资料研究报告

- 研究目录：`/tmp/A81254C8-UNKNOWN-IDEMPOTENCY-20260922-023840/`
- 访问日期（所有材料）：2026-09-22
- 资料范围：仅公开官方文档/官方仓库；不访问账号、凭据、真实服务或共享目标。
- 明确排除：`/var/minis/shared`、P0/事故目录、D10/L12/D14、canonical、140、tri-line、systemd；未读取上一切片目录。

## 结论（校准后的答案）

1. **取消请求不是外部副作用的撤销证明。** Temporal 将取消建模为可传播、可处理的请求；Activity 需要 heartbeat 才能收到取消，Workflow 收到请求后可能通过清理逻辑正常完成，也可能以取消错误结束。Temporal 文档明确允许“请求已发出”与“最终 Workflow 状态”分离。GitHub Actions 官方“Cancel workflow”只证明平台接受取消操作/对运行中的 jobs、steps 执行取消流程，不能证明脚本已停止，更不能证明脚本已经回滚云资源、付款、邮件或其他外部效果。
2. **超时、断连、Worker 崩溃都应先进入 UNKNOWN，而不是直接判定未发生。** 连接错误发生在服务端执行前后均可能失联；Stripe 的官方幂等语义正是允许在连接错误后用同一 key 重试，但它只对接受该 key 的 API 端点提供结果缓存。Temporal 会在失败后重试 Activity；每次 attempt 默认从初始状态开始，heartbeat detail 可作为检查点。上述机制降低重复风险，但没有为任意非幂等外部系统自动推导“副作用不存在”。
3. **可重试/不可重试必须是显式分类，不是按“请求失败”一刀切。** Temporal 区分 ApplicationError、NonRetryableApplicationError、TimeoutError（含 ScheduleToStart、StartToClose、Heartbeat）和 CanceledError，允许 Retry Policy 按错误类型控制；Stripe 对同一 idempotency key 返回首次状态码和 body（成功或失败），而参数不一致会报错；验证失败或并发冲突未启动 endpoint 时不保存结果，可以重试。GitHub 的 `continue-on-error` 是工作流控制，不是副作用幂等或安全重试证明。
4. **幂等目标应在外部副作用边界实现。** 使用业务唯一键/idempotency key，让服务端保存 key→结果（并校验重试参数）；或使用条件写（例如 DynamoDB `attribute_not_exists` / 版本条件），令重复提交变成“条件不满足”而非第二次写入。读后写并不天然安全：read-back/reconcile 应独立于发起请求，依据外部系统事实判断 `committed / absent / ambiguous`，再决定重试、补偿或人工介入。
5. **补偿不是回滚。** Temporal 的取消清理 Activity 和 reset 可支持业务补偿，但 reset 会终止当前 Execution、从指定 Event History 点启动新 Execution，并丢弃 reset 点之后的 Workflow 进度；它不是外部系统事务回滚。补偿只能针对已知成功且可逆的业务步骤，并须幂等；对 UNKNOWN 步骤，先 read-back/reconcile，不能盲目做“反向操作”。
6. **恢复/重放只恢复编排事实，不自动证明外部世界。** Temporal replay 从最后记录的 Event History 恢复 Workflow；这证明的是平台历史/命令一致性。Claude Code 官方 CLI 提供 `--resume`/`--continue`，但公开 CLI 参考没有承诺任意工具调用、shell 写入或外部服务调用的 exactly-once、幂等或自动 reconcile。SWE-bench 官方仓库明确是评测 LLM 解决 GitHub issue 的 benchmark、用 Docker 做可复现评测；它不能作为生产 Agent runtime 的取消/重试/UNKNOWN 行为证据。

## 统一状态机建议（由上述一手材料支持的工程推论）

`REQUESTED_CANCEL`（仅记录取消意图） → `CANCEL_ACKED`（平台确认请求/终止流程，不代表外部效果） → `RECONCILE_REQUIRED`（断连、超时、Worker 崩溃、无最终 receipt） → 独立 read-back：

- `COMMITTED`：外部事实确认已提交；不重做；若用户取消则走幂等补偿或人工决策。
- `ABSENT`：外部事实确认未提交；可用同一幂等 key 安全重试，或标记取消成功。
- `AMBIGUOUS`：读不到、结果冲突或目标不提供可验证查询；保持 UNKNOWN，禁止盲重试/盲补偿，进入退避、告警和人工队列。
- `FAILED_BEFORE_EXECUTION`：只有当平台/外部服务明确证明 endpoint 未开始（如 Stripe 文档所述 validation failure / concurrent conflict）才可按可重试处理。

每个副作用应记录：`operation_id`、稳定 `idempotency_key`、参数摘要、attempt、平台 receipt、外部资源 ID、开始/完成/取消时间、最后 heartbeat/checkpoint、read-back 证据、补偿状态和人工处置人。平台回执只能证明平台层事实，不能代替外部 read-back。

## 证据矩阵

| ID | 明确对象与一手材料 | 直接可证明（verified） | 不能证明 / UNKNOWN 边界 | 状态 |
|---|---|---|---|---|
| T1 | Temporal Activities，https://docs.temporal.io/activities （Temporal Documentation，访问 2026-09-22） | 官方建议 Activity 幂等以支持 retry；Activity 失败会按 Retry Policy 重试；每次 attempt 从初始状态开始，heartbeat details 可在下一次 attempt 取回用于 checkpoint。 | 没有证明任意外部 API 已 exactly-once；heartbeat 不是外部提交 receipt；未提供任意第三方系统的回滚。 | verified（平台行为）；inferred（需外部幂等） |
| T2 | Temporal Workflow Execution，https://docs.temporal.io/workflow-execution （Temporal Documentation，访问 2026-09-22） | Workflow 状态在失败/故障后从 Event History 最新记录 replay/resume；Workflow Execution 有 Completed、Canceled、Terminated、Timed Out 等平台状态。 | replay 只证明 Event History/编排恢复；不证明 Activity 外部副作用未发生或已撤销。 | verified；外部效果 unknown |
| T3 | Temporal Go cancellation，https://docs.temporal.io/develop/go/workflows/cancellation （Temporal Documentation，访问 2026-09-22） | 取消是 request；Activity heartbeat 才能接收传播的取消；取消后可运行清理 Activity；若优雅处理/无跳过 Activity，Workflow 甚至可 Complete，业务也可返回取消错误形成 Canceled；reset 会终止当前执行并从 Event History 点新起，reset 点后的进度丢弃。 | CancelWorkflow 调用成功不等于 Activity 已停止；清理/补偿是否完成取决于业务代码；reset 不回滚外部世界。 | verified；回滚结论为边界推论 |
| T4 | Temporal Go error handling，https://docs.temporal.io/develop/go/best-practices/error-handling （Temporal Documentation，访问 2026-09-22） | 官方区分 ApplicationError、NonRetryableApplicationError、TimeoutError（ScheduleToStart/StartToClose/Heartbeat）、CanceledError、PanicError；可按类型处理。 | 文档分类不替应用决定某个业务错误是否安全重试；超时仍可能发生外部写入。 | verified；业务分类需 inferred |
| G1 | GitHub Actions cancel，https://docs.github.com/en/actions/how-tos/manage-workflow-runs/cancel-a-workflow-run （GitHub Docs，访问 2026-09-22） | UI 可取消 queued 或 in-progress run；文档说可取消包括所有 jobs、steps 的进行中 workflow run。 | 未证明进程已在外部副作用前停止，未证明 shell/action 的取消清理完成，未提供通用外部回滚/幂等协议。 | verified；外部效果 unknown |
| G2 | GitHub Actions workflow syntax，https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax （GitHub Docs，访问 2026-09-22） | `jobs.<job_id>.timeout-minutes`、step/job `continue-on-error` 等控制存在；超时和允许失败是 workflow orchestration 语义。 | timeout/continue-on-error 不等于业务事务结论，不是 retry-safe 证明；workflow result 不能代替目标系统 read-back。 | verified；边界为 inferred |
| G3 | GitHub Actions concurrency，https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency （GitHub Docs，访问 2026-09-22） | 同一 concurrency group 最多一个运行中的 job/workflow；`cancel-in-progress: true` 可取消已有运行；pending run 默认可被新 run 替换/取消。 | 取消旧 run 不证明旧 run 的外部部署/写入已撤销；也不是 idempotency key。 | verified；外部效果 unknown |
| C1 | Claude Code CLI reference，https://docs.anthropic.com/en/docs/claude-code/cli-reference （Anthropic Documentation，访问 2026-09-22） | 官方 CLI 参考列出 `--resume`、`--continue`、后台 session 的恢复/重连相关命令；`--timeout <minutes>`（文档上下文为 print 模式）和退出码/错误等 CLI 控制。 | 未找到官方承诺：tool/shell/API 调用 exactly-once、取消后的外部状态、幂等 key、自动 read-back/reconcile、补偿事务。不能把恢复 session 当外部操作恢复证明。 | verified（CLI 选项）；unknown（语义保证） |
| S1 | SWE-bench 官方仓库，https://github.com/SWE-bench/SWE-bench （SWE-bench，访问 2026-09-22） | 官方 README 定义其为评测 LLM 解决 GitHub 软件 issue 的 benchmark；官方推荐 Docker 可复现评测，并有 patch/test/evaluation harness。 | 它不是生产运行时；未证明取消/超时/Worker 崩溃后的 UNKNOWN、幂等重试或外部补偿。benchmark 结果严禁外推 production。 | verified（benchmark 范围）；not evidence for production |
| I1 | Stripe Idempotent requests，https://docs.stripe.com/api/idempotent_requests （Stripe API Reference，访问 2026-09-22） | 服务端保存给定 key 第一次请求的 status/body（成功或失败）；相同 key 后续返回相同结果；参数不一致报错；key 至少 24h 后可清理并可被视为新请求；validation 失败或并发冲突（endpoint 未开始）不保存结果、可重试。连接错误场景可用同 key 重试。 | 这是 Stripe API 的明确契约，不是所有 HTTP/Agent 工具的通用性质；key 过期后不能保证去重；不能证明下游第三方已完成。 | verified（Stripe 范围） |
| D1 | Amazon DynamoDB condition expressions，https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html （AWS Documentation，访问 2026-09-22） | Put/Update/Delete 可附 condition expression；条件为 false 时写失败；`attribute_not_exists` 可防止同主键覆盖；条件更新可防止不满足当前值时重复/并发更新。 | 条件失败本身不说明上一次 UNKNOWN 请求是否已提交，必须结合业务查询/版本/operation record；不是跨系统事务或补偿。 | verified；reconcile 边界为 inferred |

## 取消、超时、断连、崩溃的判定表

| 事件 | 仅凭平台观察能判定什么 | 正确下一步 | 禁止的错误推断 |
|---|---|---|---|
| Cancel API/UI 返回成功 | 取消请求已被平台受理/进入取消流程（具体 receipt 依平台） | 等最终平台状态；对有副作用步骤做独立 read-back | “外部动作一定没发生/已经回滚” |
| Activity 收到 canceled context | 该 attempt 收到取消传播 | 执行幂等清理；read-back 外部系统 | “cancel context 到达前没有写入” |
| Start/heartbeat/overall timeout | 平台达到对应时间界限；可能产生 retry/failure | 若无外部 receipt，UNKNOWN；查询；按错误类别与幂等契约重试 | “超时=未执行” |
| 客户端断连/API 连接错误 | 客户端没拿到确定响应 | 用同一 key 重试（仅当目标服务契约支持）；否则查询/人工 | “服务端没收到”或“服务端一定成功” |
| Worker 崩溃/进程被杀 | 当前 worker 未继续报告；Temporal 可从历史恢复/重试 | checkpoint/heartbeat + 外部 read-back；非幂等操作保持 UNKNOWN | “崩溃自动回滚” |
| replay/resume/reset | 编排可从历史/新起点恢复 | 对每个副作用以 operation_id 去重并 reconcile | “历史 replay 等于重放外部副作用安全” |

## 对 Agent runtime 的落地要求

- **默认安全状态：** 任意未收到最终外部 receipt 的副作用为 `UNKNOWN`，不是 `FAILED`、`CANCELED` 或 `ABSENT`。
- **稳定键：** 由业务 operation_id 派生幂等 key，跨 attempt、断连、Worker 重启、恢复保持不变；参数摘要绑定 key，防止 key 错配。
- **结果账本：** 在 Agent 自己可控的 durable store 记录 intent、attempt、receipt 和 reconcile 证据；平台 job/run 状态单独存储，不冒充外部真相。
- **两阶段式处理（非分布式事务承诺）：** 先持久化 intent，再调用目标；返回不明则 read-back；仅外部确认 absent 才可新建，confirmed committed 则不重做，ambiguous 则冻结并人工。
- **补偿边界：** 对明确 committed 且可逆的步骤调用补偿；补偿也必须有自己的幂等 key、状态机和 read-back。对 UNKNOWN 不做盲目反向操作。
- **人工介入条件：** 目标无查询 API、key 已过期、参数冲突、read-back 多次不可达/冲突、补偿不可逆或高风险时，升级人工；保留操作和证据链。

## 覆盖与限制

已覆盖 Temporal、GitHub Actions、Claude Code、SWE-bench，以及用于具体幂等/条件写契约的 Stripe、AWS DynamoDB。所有材料为公开官方文档/官方仓库，访问日期固定为 2026-09-22。未访问 Claude 私有 session、GitHub 私有仓库、真实生产服务、任何凭据或共享目标。

- Claude Code 的 CLI 参考可证明命令/选项存在，但本次公开材料不足以证明其外部副作用语义，故明确标为 unknown。
- GitHub Actions 公开取消页没有给出通用“终止已完成/正在执行的 shell 副作用”的保证，故不把 workflow 状态作为外部效果。
- Temporal 官方文档建议 Activity 幂等并提供 retry/heartbeat/replay，但不把任意第三方副作用纳入 Temporal 事务；补偿与 reconcile 是应用责任。
- 未将 SWE-bench 的 benchmark 运行结果或 harness 语义外推成生产 Agent runtime 可靠性。

## 下一独立公开研究切片（已派发主题）

**主题：Agent runtime 的 lease/租约过期、心跳与 fencing token：如何防止 Worker 重启后旧执行者继续写入。**

边界：只查 Temporal、Kubernetes Jobs/Leases、AWS Step Functions 或同类官方文档/源码；重点是 lease expiry 与实际停止的差别、split-brain/stale worker、fencing/版本条件、恢复交接和人工处理；不重复本片的取消/幂等补偿主线，不接触任何真实集群或共享目标。
