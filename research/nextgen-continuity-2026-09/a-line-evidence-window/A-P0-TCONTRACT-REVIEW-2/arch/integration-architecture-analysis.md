# Northstar Bundle + Experience Layering 集成架构分析

## 一、Bundle 核心组件

### 1. BackendRouter（准入决策点）
**位置**：`northstar-agent-interop/backend_router.py`
**核心方法**：`select(request: RouteRequest) -> RouteDecision`

**功能**：
- 从多个 backend 中选择一个执行请求
- 检查 backend 健康状态（healthy/degraded/cooldown/unhealthy）
- 应用优先级、能力匹配、排除列表
- **这里是准入决策的关键点！**

**当前逻辑**：
```python
def select(self, request: RouteRequest, *, now: int, current_policy_revision: str | None = None) -> RouteDecision:
    # 1. 检查请求有效性
    # 2. 检查 policy revision 是否过期
    # 3. 过滤候选 backends（enabled + not excluded + capability match + health check）
    # 4. 按优先级排序
    # 5. 选择第一个候选
    # 6. 返回 RouteDecision
```

**集成点 #1**：在 `select()` 方法开始时，查询 Experience 历史并评估策略

---

### 2. RouteDecision（决策数据结构）
**包含字段**：
- `route_id`, `task_id`, `thread_id`, `run_id`（唯一标识）
- `input_digest`（请求指纹，可作为 Experience 的 fingerprint）
- `target_agent_id`（选中的 backend）
- `provider`, `backend_version`
- `priority`, `selected_at`

**关键**：`input_digest` 可以作为 Experience 的 `fingerprint`

---

### 3. RouteLedger（事件记录）
**位置**：`northstar-agent-interop/route_ledger.py`
**功能**：
- 记录 decision/started/succeeded/failed/cancelled 事件
- 失败类别：`backend_timeout`, `backend_process_exit`, `backend_malformed_output`, `backend_unavailable`, `adapter_error`, `policy_denied`, `route_no_candidate`, `cancelled_by_parent`, `stale_policy`

**集成点 #2**：在记录 `failed` 事件时，同时调用 `experience.record_lost()`

---

## 二、Experience Layering 接口

### 核心接口
1. `query_statistics(fingerprint)` → 查询历史
2. `evaluate_policy(fingerprint, total, success, lost)` → 策略评估
3. `record_lost(fingerprint, reason, run_id, fencing_token)` → 记录失败
4. `query_lost_events(fingerprint, limit)` → 查询失败历史

---

## 三、集成方案

### 方案 A：最小侵入式集成（推荐）

**步骤 1**：扩展 `BackendRouter` 添加 Experience 支持
```python
class BackendRouter:
    def __init__(self, experience: ExperienceLayering | None = None) -> None:
        self._backends: dict[str, _Backend] = {}
        self._experience = experience  # 新增
    
    def select(self, request: RouteRequest, *, now: int, current_policy_revision: str | None = None) -> RouteDecision:
        # 【集成点 #1】在选择前检查 Experience
        if self._experience is not None:
            fingerprint = request.input_digest
            stats = self._experience.query_statistics(fingerprint)
            
            # 评估策略
            from experience_layering import evaluate_policy
            policy_result = evaluate_policy(
                fingerprint,
                stats['total_runs'],
                stats['success_count'],
                stats['lost_count']
            )
            
            # 如果策略拒绝，抛出异常或返回特殊决策
            if policy_result.decision == "block":
                raise PolicyDeniedError(policy_result.reason)
        
        # 原有的 select 逻辑...
        ...
```

**步骤 2**：扩展 `RouteLedger` 添加失败上报
```python
class RouteLedger:
    def __init__(self, ledger_path: Path, experience: ExperienceLayering | None = None):
        self._ledger_path = ledger_path
        self._experience = experience  # 新增
    
    def record_event(self, event: RouteEvent):
        # 原有记录逻辑...
        ...
        
        # 【集成点 #2】失败时记录到 Experience
        if self._experience is not None and event.status == "failed":
            self._experience.record_lost(
                fingerprint=event.decision_digest,  # 或其他合适的标识
                reason=event.failure_class,
                run_id=event.run_id,
                timestamp=event.recorded_at
            )
```

---

### 方案 B：独立的 Experience Gateway（更解耦）

创建一个新文件 `experience_gateway.py`：
```python
class ExperienceGateway:
    def __init__(self, experience: ExperienceLayering):
        self._experience = experience
    
    def check_admission(self, request: RouteRequest) -> tuple[bool, str]:
        """返回 (是否允许, 原因)"""
        stats = self._experience.query_statistics(request.input_digest)
        policy_result = evaluate_policy(...)
        
        if policy_result.decision == "block":
            return (False, policy_result.reason)
        return (True, "admitted")
    
    def report_failure(self, decision: RouteDecision, failure_class: str):
        """上报失败到 Experience"""
        self._experience.record_lost(
            fingerprint=decision.input_digest,
            reason=failure_class,
            run_id=decision.run_id
        )
```

然后在 `BackendRouter` 中调用：
```python
if self._experience_gateway:
    allowed, reason = self._experience_gateway.check_admission(request)
    if not allowed:
        raise PolicyDeniedError(reason)
```

---

## 四、集成测试计划

### 测试用例 1：首次请求（无历史）
- 输入：新的 input_digest
- 预期：Experience 返回 total_runs=0，Policy 返回 admit
- 验证：请求被允许

### 测试用例 2：高成功率请求
- 输入：有 10 次成功历史的 input_digest
- 预期：success_rate=100%，Policy 返回 admit
- 验证：请求被允许

### 测试用例 3：高失败率请求
- 输入：有 8 次失败/2 次成功的 input_digest
- 预期：success_rate=20% < 70%，Policy 返回 block
- 验证：请求被拒绝，抛出 PolicyDeniedError

### 测试用例 4：失败上报
- 输入：执行失败的 RouteEvent
- 预期：Experience.record_lost() 被调用
- 验证：lost_events.jsonl 中有新记录

---

## 五、实施步骤（2-3 小时）

### Phase 1：代码修改（1h）
1. ✅ 复制 bundle 到工作目录
2. ⏱️ 修改 `BackendRouter.__init__` 添加 experience 参数
3. ⏱️ 修改 `BackendRouter.select` 添加准入检查
4. ⏱️ 修改 `RouteLedger` 添加失败上报
5. ⏱️ 添加必要的 import 和异常类

### Phase 2：集成测试（1h）
1. ⏱️ 编写 4 个集成测试用例
2. ⏱️ 本地运行验证
3. ⏱️ 修复发现的问题

### Phase 3：140 部署（30min）
1. ⏱️ 打包修改后的 bundle + Experience
2. ⏱️ 传输到 140
3. ⏱️ 运行集成测试
4. ⏱️ 验证端到端流程

---

## 六、关键决策

### fingerprint 映射
- **选择**：使用 `input_digest`（SHA256）作为 Experience 的 fingerprint
- **理由**：已经是请求内容的哈希，具有唯一性和稳定性

### 失败原因映射
- RouteLedger 失败类别 → Experience reason
- 直接使用 `failure_class`（backend_timeout 等）

### Policy 参数
- 使用默认值：`min_success_rate=0.7`, `min_samples=3`
- 可配置化（后续优化）

---

## 七、预期效果

集成完成后，系统将具备：
1. ✅ **基于历史的准入决策**：高失败率的请求被自动拒绝
2. ✅ **失败记录与追踪**：所有失败自动记录到 Experience
3. ✅ **动态恢复能力**：失败后恢复会自动解除阻断
4. ✅ **完整的数据流**：Route → Experience → Policy → Decision

---

**下一步**：开始 Phase 1 代码修改？
