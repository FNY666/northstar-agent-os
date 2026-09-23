# S4：Evidence envelope 与 durable reconciliation 状态机数据契约

## 0. 研究边界与结论

- **切片**：A 线 S4；仅研究可执行数据契约，不实现服务、不读取任何既有 A 线或本地研究产物。
- **资料边界**：仅使用 AWS、Temporal、Kubernetes、GitHub 官方公开一手文档；访问日期 2026-09-22（Asia/Shanghai）。没有访问私有账户、真实服务、凭据或受限环境。
- **直接结论（verified）**：官方系统分别提供了可重放/可排序的事件或状态证据（CloudTrail 的 eventTime/eventID/resources 等；Step Functions 的有序 HistoryEvent 与 timestamp/previousEventId；Temporal 的持久 Event History；Kubernetes 的 resourceVersion/watch/list 语义；GitHub 的 run_id/status/conclusion 与 environment protection/deployment status）。这些能力足以作为本契约的**证据输入**，但没有一个来源单独证明任意外部副作用已经发生。
- **设计结论（inferred）**：reconciliation 必须把“请求生命周期”和“外部效果”分开建模；`accepted` 只表示请求被受理或已进入编排，不能被提升为 `applied`。只有带有资源身份、目标版本/代际、来源时间/新鲜度和可定位的外部观察/关单证据，才可关闭。
- **硬限制（verified + contract policy）**：schema 完整性不等于外部效果证明；本切片不声称 production-ready、exactly-once、无重复副作用或任意平台自动提供幂等。重试、超时和重复交付仍需通过 key、attempt、观察、冲突与人工处置来显式收敛。

## 1. 状态机：持久化请求事实，不把中间信号当外部事实

```text
RECEIVED
  -> ACCEPTED_UNKNOWN       # 已接受/已排队；效果未知，允许超时重试但不应盲目重做
  -> RECONCILING            # 依据 idempotency_key + 目标身份 + generation 查询/比对
       -> APPLIED            # 外部对象和目标意图匹配，有 effect proof
       -> REJECTED           # 明确拒绝/失败，有拒绝证据
       -> CONFLICT            # 证据互相矛盾、代际冲突、意图冲突或无法安全选择
       -> EXPIRED            # 证据窗口或业务 TTL 到期；不是成功
RECONCILING -> ACCEPTED_UNKNOWN  # 查询不完整、来源过旧或效果仍未知
APPLIED|REJECTED|CONFLICT|EXPIRED -> CLOSED  # 仅在 closure evidence 完整时
```

`CLOSED` 是审计/流程终态，不是独立效果状态。关闭记录必须引用终态证据；`EXPIRED`、人工批准或“已接受”都不能单独作为 `APPLIED` 的证据。

### 1.1 状态转移的执行规则

| 规则 | 标签 | 可执行要求 |
|---|---|---|
| 新请求去重 | inferred | `(tenant/namespace, operation, resource_ref, idempotency_key)` 为逻辑去重域；不能只用全局 key。保存 canonical intent hash，key 重用但 intent 不同必须 `CONFLICT/divergent_intent`。 |
| 重试 | inferred | 每次传输/执行记录递增 `attempt_no`，保留 started/accepted/finished 时间、worker/actor 和结果；attempt 是尝试，不是版本，也不证明副作用次数。 |
| 代际控制 | verified input + inferred policy | Kubernetes `metadata.resourceVersion` 可作为观察到的并发版本输入；reconciliation 还应记录平台/业务 `generation`（若平台没有则显式 null），禁止把一次 attempt 当 generation。 |
| 时间排序 | verified input + inferred policy | 同时存 `event_time`（来源事件发生时间）与 `observed_at`（本系统观察到时间）；不能用 ingestion time 替代事件发生时间。跨源顺序用 source watermark/sequence；时钟不一致标为 unknown。 |
| 新鲜度 | inferred | 每个来源声明 `as_of`、watermark、max_age、`stale`；过期观察可辅助调查，不能单独关单。 |
| 受理但未知 | verified semantics from workflow histories + inferred state | 任何 2xx/accepted/queued、编排已记录但无外部 effect proof 的结果只能是 `ACCEPTED_UNKNOWN`。 |
| 关单 | inferred | `closure.evidence_refs` 非空、每条 evidence 可定位且校验通过；closure actor/reason/time/version 必填。 |

## 2. 最小可执行 schema

以下 JSON 不是某一个供应商的 API 响应，而是跨平台的**最小交接/持久化契约**。`required` 字段用于防止“有 envelope、无可验证事实”。所有时间为 RFC 3339 UTC；ID 不应包含秘密。

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "EvidenceEnvelope.S4",
  "type": "object",
  "required": [
    "schema_version", "evidence_id", "correlation_id", "idempotency_key",
    "operation", "attempt", "state", "effect", "observed_at", "source",
    "query", "conflicts", "approvals", "closure"
  ],
  "properties": {
    "schema_version": {"type":"string"},
    "evidence_id": {"type":"string"},
    "correlation_id": {"type":"string"},
    "idempotency_key": {"type":"string"},
    "operation": {
      "type":"object", "required":["name","resource_ref","intent_hash"],
      "properties": {
        "name":{"type":"string"}, "resource_ref":{"type":"string"},
        "intent_hash":{"type":"string"},
        "actor_ref":{"type":["string","null"]},
        "tenant_or_namespace":{"type":["string","null"]}
      }
    },
    "attempt": {
      "type":"object", "required":["attempt_no","started_at"],
      "properties": {
        "attempt_no":{"type":"integer","minimum":1},
        "started_at":{"type":"string","format":"date-time"},
        "accepted_at":{"type":["string","null"],"format":"date-time"},
        "finished_at":{"type":["string","null"],"format":"date-time"},
        "executor_ref":{"type":["string","null"]},
        "transport_result":{"type":["string","null"]}
      }
    },
    "version": {
      "type":"object",
      "properties": {
        "expected_generation":{"type":["string","integer","null"]},
        "observed_generation":{"type":["string","integer","null"]},
        "resource_version":{"type":["string","null"]},
        "source_revision":{"type":["string","null"]}
      }
    },
    "state":{"enum":["RECEIVED","ACCEPTED_UNKNOWN","RECONCILING","APPLIED","REJECTED","CONFLICT","EXPIRED","CLOSED"]},
    "effect": {
      "type":"object", "required":["status"],
      "properties": {
        "status":{"enum":["not_requested","requested","accepted","applied","rejected","unknown"]},
        "effect_proof_refs":{"type":"array","items":{"type":"string"}},
        "external_object_ref":{"type":["string","null"]},
        "result_digest":{"type":["string","null"]}
      }
    },
    "event": {
      "type":"object",
      "properties": {
        "event_id":{"type":["string","null"]}, "event_type":{"type":["string","null"]},
        "event_time":{"type":["string","null"],"format":"date-time"},
        "sequence":{"type":["integer","string","null"]}
      }
    },
    "observed_at":{"type":"string","format":"date-time"},
    "source": {
      "type":"object", "required":["system","evidence_ref","observed_at"],
      "properties": {
        "system":{"type":"string"}, "kind":{"type":["string","null"]},
        "evidence_ref":{"type":"string"}, "observed_at":{"type":"string","format":"date-time"},
        "as_of":{"type":["string","null"],"format":"date-time"},
        "watermark":{"type":["string","integer","null"]},
        "max_age_seconds":{"type":["integer","null"]}, "stale":{"type":"boolean"},
        "completeness":{"enum":["complete","partial","unknown"]}
      }
    },
    "query": {
      "type":"object", "required":["status","result_count"],
      "properties": {
        "status":{"enum":["not_run","complete","partial","failed","unknown"]},
        "result_count":{"type":"integer","minimum":0},
        "empty_meaning":{"enum":["no_match","not_observed","not_found_in_window","source_incomplete","unknown"]},
        "query_ref":{"type":["string","null"]}, "snapshot_or_watermark":{"type":["string","integer","null"]}
      }
    },
    "conflicts": {
      "type":"array", "items":{"type":"object", "required":["type","status"],
        "properties":{"type":{"enum":["duplicate","stale_generation","divergent_intent","source_disagreement","missing_evidence","approval_mismatch","out_of_order"]},"status":{"enum":["open","resolved","waived"]},"evidence_refs":{"type":"array","items":{"type":"string"}},"resolution_ref":{"type":["string","null"]}}}
    },
    "approvals": {
      "type":"array", "items":{"type":"object", "required":["approval_id","decision","actor_ref","decided_at"],
        "properties":{"approval_id":{"type":"string"},"decision":{"enum":["approved","rejected","revoked"]},"actor_ref":{"type":"string"},"decided_at":{"type":"string","format":"date-time"},"scope_hash":{"type":["string","null"]},"reason":{"type":["string","null"]},"evidence_ref":{"type":["string","null"]}}}
    },
    "closure": {
      "type":"object", "required":["status","evidence_refs"],
      "properties":{"status":{"enum":["open","closed"]},"evidence_refs":{"type":"array","items":{"type":"string"}},"closed_at":{"type":["string","null"],"format":"date-time"},"closed_by":{"type":["string","null"]},"reason":{"type":["string","null"]}}
    }
  }
}
```

### 2.1 “请求已接受但效果未知”的最小实例

```json
{
  "schema_version":"s4-1",
  "evidence_id":"ev-01",
  "correlation_id":"corr-01",
  "idempotency_key":"idem-01",
  "operation":{"name":"desired-update","resource_ref":"system/object/123","intent_hash":"sha256:..."},
  "attempt":{"attempt_no":1,"started_at":"2026-09-22T07:00:00Z","accepted_at":"2026-09-22T07:00:01Z"},
  "version":{"expected_generation":"7","observed_generation":null,"resource_version":null,"source_revision":null},
  "state":"ACCEPTED_UNKNOWN",
  "effect":{"status":"unknown","effect_proof_refs":[],"external_object_ref":null,"result_digest":null},
  "event":{"event_id":"orchestrator-event-1","event_type":"request_accepted","event_time":"2026-09-22T07:00:01Z","sequence":1},
  "observed_at":"2026-09-22T07:00:02Z",
  "source":{"system":"orchestrator","kind":"execution-history","evidence_ref":"history://execution/1#event/1","observed_at":"2026-09-22T07:00:02Z","as_of":"2026-09-22T07:00:02Z","watermark":1,"max_age_seconds":60,"stale":false,"completeness":"complete"},
  "query":{"status":"not_run","result_count":0,"empty_meaning":"not_observed","query_ref":null,"snapshot_or_watermark":null},
  "conflicts":[], "approvals":[],
  "closure":{"status":"open","evidence_refs":[],"closed_at":null,"closed_by":null,"reason":null}
}
```

此实例明确表示：可以安全地持久化请求和受理事实，但**不能**声称目标对象已变更；重试前应先用同一去重域/意图 hash 查询和 reconciliation。

## 3. 证据字段与平台映射

| 契约关注点 | 官方一手事实 | 转译到契约 | 标签 |
|---|---|---|---|
| correlation / idempotency | AWS CloudTrail 提供事件标识和关联资源字段；但资料不把 `eventID` 定义成业务幂等 key | 外部 `idempotency_key` 与平台 `event_id` 分开；不能把 eventID 猜成幂等键 | verified + inferred |
| attempt | Temporal Event History 描述 workflow/activity 的 scheduled/started/completed 等生命周期；Step Functions history 是事件序列 | attempt_no 记录本契约执行尝试；平台事件引用作为证据，不由事件数量推断副作用次数 | verified + inferred |
| version/generation | Kubernetes API 文档定义 resourceVersion、list/watch 和 410 Gone 语义；它是观察/并发语义，不是通用业务 generation | 保存 expected/observed generation 与 resourceVersion，各自可为空并注明平台 | verified + inferred |
| event_time / observed_at | CloudTrail `eventTime` 是事件记录字段；Step Functions HistoryEvent 有 timestamp；本系统还需记录 observed_at | 双时钟必存；乱序或时钟不可信时标 unknown/out_of_order | verified + inferred |
| source freshness | Step Functions GetExecutionHistory 使用 nextToken 分页且可反序，Kubernetes watch/list 有 resourceVersion 及缓存/窗口限制 | completeness、watermark、as_of、max_age、stale 必填，分页未收齐不得标 complete | verified input + inferred |
| 空查询 | Kubernetes field selector 官方说明空 selector 表示不筛选；这不等于“没找到对象” | query.result_count=0 必须带 empty_meaning；未执行/失败/部分窗口绝不编码成 no_match | verified + inferred |
| 冲突 | GitHub environment protection 可能要求 reviewer、wait timer、custom rules；管理员可 bypass（若未禁用） | approval_mismatch / source_disagreement 等作为一等冲突，不覆盖历史批准 | verified + inferred |
| 人工批准 | GitHub 官方规定 required reviewer 通过后 job 才能继续访问环境 secrets；一个 required reviewer 可批准 | approval 记录 actor、decision、scope_hash、time、evidence_ref；批准不等于外部效果 | verified + inferred |
| 关单 | GitHub deployment 状态对象有 state/environment 等字段；AWS/Temporal/K8s 历史能提供事件证据 | closure 必须引用可定位证据；“流程 completed”不能替代 external_object_ref/效果观察 | verified + inferred |

## 4. 空查询、冲突与人工处置语义

### 4.1 空查询不可压缩为 false

- `status=complete,result_count=0,empty_meaning=no_match`：在指定 query、时间窗、watermark 和权限范围内完成查询，确认没有匹配记录；只说明该范围，不证明全世界不存在。
- `status=complete,result_count=0,empty_meaning=not_found_in_window`：查询完成但窗口有限；不能关单。
- `status=partial|failed|unknown` 或 `empty_meaning=source_incomplete|not_observed`：无观察，不是 negative proof；状态保持 `ACCEPTED_UNKNOWN/RECONCILING`。
- 无 query 运行时使用 `status=not_run, empty_meaning=not_observed`，不能写 `no_match`。

### 4.2 冲突分类与优先级

1. `divergent_intent`：相同去重域/ key 的 canonical intent hash 不同；阻断自动重试。
2. `stale_generation`：观察到的对象版本落后于 expected/当前版本；重新读取，不覆盖较新对象。
3. `source_disagreement`：两个来源对同一对象/状态给出不能同时成立的结论；保留两条 evidence，进入人工或更强来源判定。
4. `approval_mismatch`：批准的 scope hash、资源、版本或 actor 不匹配；批准不可移植。
5. `out_of_order`：event_time/sequence 与观察顺序冲突；以来源定义的顺序/水位重建，未知则不关单。
6. `duplicate`：同一 event/evidence 重复到达；去重记录，不把重复事件计成两次成功。
7. `missing_evidence`：状态声称终态但 proof refs 缺失/不可读；降级为 unknown。

人工解决必须新增一条不可变 resolution/approval evidence，不删除或覆写原始冲突；`waived` 仍需 reason、actor、scope_hash 和时间。

## 5. 不能由资料证明的事项（unknown / conflict）

- **unknown**：官方文档没有给出一个跨 AWS/Temporal/Kubernetes/GitHub 通用的 idempotency-key 语义；必须由业务契约定义 key 域、保留期和 key 重用规则。
- **unknown**：事件历史、deployment 状态、Kubernetes object observation 都不能单独证明任意外部系统副作用的原子完成；必须有目标系统可验证的 effect proof。
- **unknown**：没有统一的跨平台 event_time 全序；仅凭本地时间戳不能断言因果顺序。
- **unknown**：空列表不能在未声明查询窗口、权限、分页/水位和一致性时证明“不存在”。
- **conflict（语义边界）**：平台“执行成功/工作流完成”与目标外部资源“已达到期望状态”是不同命题；若下游观察与编排完成信号相反，保留冲突，不平均、不猜测。
- **unknown**：本文没有实测任何生产实例、失败率、延迟、重复副作用或 exactly-once 性质，不能外推性能/可靠性。

## 6. 实施检查清单（契约级，不是生产认证）

- [ ] 每条请求有 correlation_id、idempotency_key、canonical intent_hash 和资源身份。
- [ ] 每个 attempt 独立编号、时间和执行者；重试不覆盖前次记录。
- [ ] expected/observed generation、resourceVersion/source_revision 分离；缺失显式 null。
- [ ] event_time 与 observed_at 分离；来源水位、分页完整性和 freshness 可审计。
- [ ] 空结果携带 query status、窗口/snapshot/watermark 与 empty_meaning。
- [ ] accepted/queued/completed 不自动转 applied；effect proof refs 与 external_object_ref 必须存在。
- [ ] 冲突不可静默覆盖；批准绑定 actor、scope_hash、时间和证据。
- [ ] 关单只在 closure evidence refs 可验证时发生；过期为 expired，不是成功。
- [ ] 以故障注入验证：超时后重试、重复事件、乱序、过期观察、版本冲突、空/部分查询、撤回批准、目标已变更。

## 7. 证据等级声明

“verified”仅表示官方文档直接描述了该字段/行为；“inferred”是把多个官方机制组合成契约规则；“unknown”表示资料不足；“conflict”表示命题或来源不能安全合并。这里的 schema 是可执行的完整性门槛，不是外部世界状态的证明，更不是 exactly-once 或无重复副作用的承诺。
