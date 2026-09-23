# S11 — Stripe PaymentIntent 事件族与状态转移证据图

- 研究切片：A 线独立公开研究 S11
- 访问日期：2026-09-22（UTC；所有链接均为 Stripe 官方公开文档）
- 方法边界：只读取公开文档；未调用 Stripe API、未使用凭据、未访问真实服务。未读取任何既有 A 线目录或其他研究产物。
- 证据标记：`verified` = 官方文本直接支持；`inferred` = 由官方多个字段/规则推导；`unknown` = 官方资料在本切片未给出；`conflicting`/`inaccessible` = 未发现适用项。manifest 使用通用 validator 的允许值：`confirmed`≈verified，`inferred`，`unverified`≈unknown。

## 1. 结论（可执行边界）

1. **履约输入**：Stripe 明确建议服务端监听 `payment_intent.succeeded`，并在该事件异步完成履约；`succeeded` 表示支付流程完成、资金在账户中。客户端状态不能作为唯一履约触发器。
2. **异步支付**：`payment_intent.processing` 只适用于延迟成功通知的支付方式（例如银行借记/ACH 类），意味着已成功提交但尚未保证付款；应等待成功或失败，不履约。官方没有在总览页给出完整、永久的支付方式清单，因此“例如 bank debits”不可扩大为穷尽清单。
3. **分离授权/捕获**：`payment_intent.amount_capturable_updated` 表示有可捕获资金；授权后 PaymentIntent 进入 `requires_capture`，该事件适合驱动“捕获”动作而不是履约。官方明确支持示例为 cards、Affirm、Afterpay、Cash App Pay、Klarna、PayPal；明确不支持示例为 ACH、iDEAL。全量兼容性应以 Stripe 的 payment-method-support 页面/动态返回为准。
4. **失败/取消**：失败尝试后 PaymentIntent 回到 `requires_payment_method`，可重试；`payment_intent.canceled` 表示取消，不能作为成功履约输入。授权过期会释放资金并使支付状态变为 `canceled`，但具体 Charge 事件到 PI 状态的关联在事件类型页并未逐字承诺，见推断标记。
5. **Charge 族**：事件的 `data.object` 类型由官方事件目录直接给出：上述 PaymentIntent 事件为 `payment_intent`，`charge.*` 事件依事件目录给出 `charge`（dispute/refund 子事件除外，本文仅纳入直接 `charge.*`）。Charge 有 `succeeded`、`pending`、`failed` 三种状态；Charge 与 PaymentIntent 通过 `charge.payment_intent` 关联。Charge 事件通常适合作为对账/捕获/退款观察输入，不能替代 `payment_intent.succeeded` 作为订单履约信号。
6. **缺失事件补偿**：Stripe 明确不保证事件按生成顺序投递，建议以 event ID 去重并可通过 API retrieve 缺失对象；snapshot event 的 `data.object` 是事件时点快照，而 retrieve 可得到最新资源。官方没有承诺 retrieve 能重建缺失的历史事件、补发 webhook，或让状态读取具备某种“最终性”时间保证；这些均标 `unknown`。

## 2. 状态与订单动作证据图

| PI 状态/事件 | 官方直接映射与触发 | 可能支付方式/时序 | 订单动作输入 | 证据级别 |
|---|---|---|---|---|
| `payment_intent.created` | 新建 PaymentIntent；`data.object=payment_intent`。创建事件本身不规定状态迁移。 | 任何可用方式；常见初始状态可为 `requires_payment_method`，但本事件页未将其写成必然映射。 | 仅建单/关联 intent，不履约。 | verified（事件与对象）；状态映射 unknown |
| `payment_intent.requires_action` | PI 转入 `requires_action`；对象为 PI。 | 需要额外动作的方式，如 3DS、redirect/其他 next_action；官方说具体 next actions 随方式变化。 | 通知/引导客户完成动作；不履约。 | verified |
| `payment_intent.processing` | PI 开始处理；对象为 PI。状态为 `processing`。 | 仅适用于延迟成功确认/通知的方式；例如银行借记；可能需数日。 | 等待 `succeeded` 或 `payment_failed`；不履约。 | verified |
| `payment_intent.payment_failed` | PI 付款尝试失败；对象为 PI。官方状态页说失败后回到 `requires_payment_method`。 | 卡网络拒绝或其他失败/过期；失败后可换方式重试。 | 通知客户、请求另一支付方式；不履约。 | verified |
| `payment_intent.amount_capturable_updated` | PI 有资金可捕获；检查 `amount_capturable`。对象为 PI。手动捕获授权后状态转 `requires_capture`。 | 仅适用于支持分离授权/捕获的方式。 | 可作为“捕获资金”动作输入；捕获完成后再以成功状态决定履约。 | verified（捕获）；履约链为 inferred |
| `payment_intent.succeeded` | PI 成功完成支付；对象为 PI；状态 `succeeded`。 | 即时通知方式通常直接 succeeded；延迟方式在 processing 后成功。 | **唯一官方明确的支付履约输入**：服务端 webhook 异步履约。 | verified |
| `payment_intent.canceled` | PI 被取消；对象为 PI；状态 `canceled`。 | 手动取消、授权过期等；过期释放资金并变 canceled。 | 终止/关闭订单或人工处理；不履约。 | verified（状态/过期规则）；过期事件关联 inferred |
| `payment_intent.partially_funded` | customer_balance PI 收到资金且 `amount_remaining` 变化；对象为 PI。 | customer_balance 特定路径；不是普遍成功。 | 更新待付余额；不履约。 | verified（触发）；订单动作 unknown |
| `charge.captured` | 先前未捕获 Charge 被捕获；对象为 `charge`。 | 需要授权后捕获的方式。 | 捕获/对账输入；不单独作为订单履约输入。 | verified（事件）；履约边界 inferred |
| `charge.expired` | 未捕获 Charge 过期；对象为 `charge`。 | 授权窗口结束。官方另述授权过期会释放资金且支付状态变 canceled。 | 关闭/补救输入，不履约。 | verified（各自事实）；Charge→PI 映射 inferred |
| `charge.failed` | 失败 Charge 尝试；对象为 `charge`；Charge status 可为 `failed`。 | 失败的方式/尝试。 | 对账、通知、重试线索；不履约。 | verified（Charge 事实）；PI 状态 inferred |
| `charge.pending` | 创建 pending Charge；对象为 `charge`；Charge status 可为 `pending`。 | 延迟结算/通知方式可能出现；事件目录未承诺等同所有 `processing` PI。 | 等待/对账；不履约。 | verified（Charge 事实）；PI 映射 unknown/inferred |
| `charge.succeeded` | Charge 成功；对象为 `charge`；Charge status 可为 `succeeded`。 | 已成功 Charge。 | 对账/支付记录输入；订单履约仍以 PI succeeded webhook 为准。 | verified（Charge 事实）；订单替代关系 inferred |
| `charge.refunded` | Charge 被退款（含部分退款）；对象为 `charge`。 | 成功后或部分退款路径。PI 仍可保持 succeeded；退款/争议反映在 Charge。 | 售后退款/订单逆向动作；不是初始履约输入。 | verified |
| `charge.updated` | Charge 描述/metadata 更新，或异步捕获；对象为 `charge`。 | 变更/异步捕获。 | 对账刷新；具体 PI 状态与动作 unknown。 | verified（触发）；状态 unknown |

### 允许出现但本切片不声称穷举的 PI 状态

官方 PaymentIntent 对象列出的状态枚举为：`requires_payment_method`、`requires_confirmation`、`requires_action`、`processing`、`requires_capture`、`canceled`、`succeeded`。状态枚举不是事件全集：事件目录没有列出 `requires_payment_method` 或 `requires_confirmation` 对应的 snapshot webhook。官方明确说失败尝试会回到 `requires_payment_method`；未找到一条同等直接的“requires_confirmation 事件”承诺，故该事件缺口为 **unknown**。

### `charge.*` 与 PI 的边界

Charge 对象的 `payment_intent` 字段是关联 PI ID（可为空）；Charge 自身的 status enum 是 `succeeded`、`pending`、`failed`。因此不能把 Charge status 字符串机械替换为 PI status：例如 Charge `pending` 可提示支付仍在推进，但官方事件目录没有逐事件保证它必然对应 PI `processing`；Charge `refunded` 也不会把 PI status 改为退款状态，官方明确后续退款/争议在 Charge 反映且 PI 仍保持 `succeeded`。

## 3. 关键限制核验

### `processing`

- **verified**：只适用于延迟成功确认的支付方式；PaymentIntent 处于 processing，直到成功或失败；Stripe 说此类支付方式可能要几天确认，期间付款不能保证。
- **履约措辞**：官方建议企业在 pending 中持有订单，支付成功前不履约；webhook 表格要求等待 initiated payment 成功或失败。
- **方式范围**：官方示例为 ACH debits/银行借记；没有在该页面提供固定穷举表，故“全部异步方式”= unknown。

### `succeeded`

- **verified**：支付流程完成，资金在账户中，可以履约；`payment_intent.succeeded` 是官方给出的 webhook 履约路径。
- **最终性边界**：这是对当前支付流程/资金可履约的强业务信号，不是“永不退款/争议”的保证；退款、争议和其他结果由 Charge 反映，PI 仍可能保持 succeeded。

### `requires_capture`

- **verified**：分离授权/捕获时，授权后 PI 转 `requires_capture`；`amount_capturable` 代表可捕获金额；PI 事件为 `amount_capturable_updated`。
- **方式限制**：支持示例 cards、Affirm、Afterpay/Clearpay、Cash App Pay、Klarna、PayPal；不支持示例 ACH、iDEAL。Stripe 明确说只有部分方式支持，不能把支持示例当穷举。
- **动作**：捕获，而非履约；捕获后应由支付成功信号决定履约。授权过期则资金释放、支付状态 canceled。

### `canceled`

- **verified**：取消状态；授权过期未捕获会释放资金并使支付状态变 canceled。
- **unknown**：本文没有找到一条官方总则，列出每个支付方式所有可取消/不可取消条件，或保证取消事件在所有方式中均按同一时序出现。

## 4. 顺序、重复、最终性、补偿读取

- **顺序**：verified negative claim — Stripe 不保证事件按生成顺序投递；不要依赖顺序，也不要用 `created` 判序/去重；使用 event ID 去重。
- **重复/重试**：verified — live 会指数退避重试最多三天；sandbox 三次、几小时内；手动 Dashboard resend 最多事件创建后 15 天，CLI 最多 30 天。每次重试会生成新的签名/时间戳。本文不把这些期限外推为事件永远可取。
- **缺失读取**：verified — Stripe 说可以用 API retrieve 缺失对象；snapshot handler 可读取事件时点 `data.object`，也可 retrieve 最新 API 资源。`thin` handler 可 fetch related object。**本研究没有执行任何 API 请求**。
- **读取边界**：inferred/unknown — retrieve 是当前对象读取，不是历史事件重建；官方没有承诺 retrieve 会补发事件、保留每次中间状态、或在指定时间内达到最终状态。需要历史证据时必须保留事件 ID/原始 payload，并把当前 retrieve 与事件快照区分。
- **最终性**：unknown（严格意义）。官方给出 `succeeded` 可履约及 funds-in-account 的业务措辞，但未找到“事件最终不可逆”“绝不发生后续状态/资金逆向变化”的承诺；Charge 退款/争议事实反而说明不能把 succeeded 当作永远无退款争议。

## 5. 覆盖与未决项

已覆盖当前官方 snapshot event catalog 中直接相关的 `payment_intent.*`（含 `partially_funded`）以及直接 `charge.*`：`captured`、`expired`、`failed`、`pending`、`refunded`、`succeeded`、`updated`；未将 `charge.dispute.*`、`charge.refund.updated` 伪装成直接 Charge 对象事件，它们的 `data.object` 分别是 dispute/refund。未找到 `payment_intent.requires_payment_method`、`payment_intent.requires_confirmation` 事件，标 unknown 而非补造。

Stripe 文档是持续演进的，支付方式、事件目录和 API 版本可能变化；结论只表示访问日公开文档范围。`sources.md` 给出逐条直接支持和 URL；`research-manifest.json` 给出可验证 claim ledger。
