# Northstar Run Contract v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 Northstar 从单一 Codex Sidecar 推进为具有明确 run、actor、workspace、deadline、receipt 与身份边界的可编排执行底座。

**Architecture:** 新增一个仅依赖 Python 标准库的 `northstar-run-contract` 组件，负责结构化 Run Request、Run Receipt 以及 HMAC 签名的 Run Binding。第一阶段只建立可验证的公共协议，不宣称 caller-supplied actor_id 已经完成认证；第二阶段再用已验证 binding 接入 Sidecar。现有 Codex Sidecar 保持向后兼容，不把未经验证的身份字段直接当成授权依据。

**Tech Stack:** Python 3.10+、标准库 `dataclasses`/`json`/`hmac`/`hashlib`/`base64`、`unittest`、GitHub Actions。

## Global Constraints

- 不修改 103、104、宿舍或任何生产服务。
- 第一阶段不接入真实凭据，不把密钥写入仓库、测试夹具、日志或记忆。
- `actor_id`、`workspace_id` 等请求字段在 binding 验证前只能视为声明，不是授权证明。
- 保持现有 Sidecar 请求协议兼容；现有 51 个 Sidecar 测试和 3 个文档测试不得回归。
- 所有新行为必须先写 RED 测试，再写最小实现。
- 所有完成声明必须有本轮新运行的验证命令作为证据。

---

### Task 1: 建立版本化 Run Request 契约

**Files:**
- Create: `components/northstar-run-contract/contract.py`
- Create: `components/northstar-run-contract/tests/test_contract.py`
- Create: `components/northstar-run-contract/README.md`
- Modify: `.github/workflows/test.yml`

**Interfaces:**
- `validate_run_request(value: object) -> Validation`
- `decode_run_request(line: str) -> tuple[dict[str, object] | None, Validation]`
- `make_receipt(run_id: str, status: str, *, text: str | None = None, error_class: str | None = None, postconditions: list[dict[str, str]] | None = None) -> dict[str, object]`
- `fallback_allowed(status: str) -> bool`

Run Request 的允许字段固定为：

```json
{
  "schema_version": "northstar.run.v1",
  "run_id": "run-001",
  "actor_id": "actor-001",
  "workspace_id": "workspace-001",
  "task_kind": "research",
  "prompt": "...",
  "timeout_ms": 10000,
  "requested_capabilities": [],
  "parent_run_id": null
}
```

约束：
- `schema_version` 必须等于 `northstar.run.v1`。
- `run_id`、`actor_id`、`workspace_id` 使用非空且不含 `/`、`\\` 或空白的 ID，最长 128 字符。
- `task_kind` 只允许 `research`、`analysis`、`implementation`、`review`。
- `prompt` 非空，最长 100,000 字符。
- `timeout_ms` 必须是整数且位于 1,000–300,000；布尔值不得作为整数接受。
- `requested_capabilities` 是最多 16 个唯一字符串的列表，每项最长 64 字符；它表示请求，不表示已授权。
- `parent_run_id` 可为 `null`，非空时服从同一 ID 规则。
- 未知字段、重复 capability、非法 JSON、超长 JSON 都拒绝。
- Receipt 状态至少包括 `accepted`、`started`、`ok`、`rejected`、`timeout`、`cancelled`、`protocol_error`、`internal_error`、`business_error`、`transport_unavailable`。
- 只有 `transport_unavailable` 和 `timeout` 允许 fallback；取消、协议、业务和内部错误不得静默 fallback。
- Receipt 中的 postcondition 必须明确为 `verified`、`failed` 或 `unknown`，不能把未验证结果伪装成已完成。

- [ ] **Step 1: Write the failing tests**

```python
# test_contract.py 的最小行为覆盖

def test_accepts_versioned_run_request():
    result = validate_run_request(valid_request())
    self.assertTrue(result.ok)


def test_rejects_unknown_fields_and_path_like_ids():
    request = valid_request()
    request["shell"] = "rm -rf /"
    request["workspace_id"] = "../other-run"
    result = validate_run_request(request)
    self.assertFalse(result.ok)
    self.assertIn("unknown request fields", result.errors)
    self.assertTrue(any("workspace_id" in error for error in result.errors))


def test_rejects_boolean_timeout_and_duplicate_capabilities():
    request = valid_request()
    request["timeout_ms"] = True
    request["requested_capabilities"] = ["browser", "browser"]
    result = validate_run_request(request)
    self.assertFalse(result.ok)


def test_receipt_marks_only_transport_and_timeout_as_fallbackable():
    self.assertTrue(fallback_allowed("timeout"))
    self.assertTrue(fallback_allowed("transport_unavailable"))
    self.assertFalse(fallback_allowed("cancelled"))
    self.assertFalse(fallback_allowed("internal_error"))
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```sh
cd components/northstar-run-contract
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Expected: FAIL because the new module and functions do not yet exist.

- [ ] **Step 3: Write the minimal implementation**

Use only standard-library types. Return a frozen `Validation(ok, errors)` object. Validate the complete allowlist before accepting the request. Use canonical compact JSON in `decode_run_request`, but do not normalize or silently repair invalid input. Keep receipt output bounded and deterministic.

- [ ] **Step 4: Run the focused and full tests**

Run:

```sh
cd components/northstar-run-contract
python3 -m unittest discover -s tests -p 'test_*.py' -v
cd ../..
python3 -m py_compile components/northstar-run-contract/contract.py
python3 -m unittest discover -s components/northstar-codex-sidecar/tests -p 'test_*.py' -v
python3 -m unittest tests.test_documentation -v
```

Expected: new contract tests pass; existing Sidecar 51/51 and documentation 3/3 remain green.

- [ ] **Step 5: Document the trust boundary**

`README.md` for the component must state that structural validation is not caller authentication, requested capabilities are not grants, and an authenticated binding verifier is required before routing or workspace authorization.

- [ ] **Step 6: Commit**

```sh
git add components/northstar-run-contract .github/workflows/test.yml
git commit -m "feat: add versioned Northstar run contract"
```

---

### Task 2: Add authenticated Run Binding

**Files:**
- Create: `components/northstar-run-contract/binding.py`
- Modify: `components/northstar-run-contract/tests/test_contract.py`
- Modify: `components/northstar-run-contract/README.md`

**Interfaces:**
- `sign_binding(binding: dict[str, object], secret: bytes) -> str`
- `verify_binding(token: str, secret: bytes, *, now: int) -> BindingValidation`
- `BindingValidation(ok: bool, binding: dict[str, object] | None, errors: tuple[str, ...])`

Binding payload fields are `schema_version`, `run_id`, `actor_id`, `workspace_id`, and integer `expires_at`. The token is canonical JSON payload plus HMAC-SHA256 signature, encoded with URL-safe base64. The verifier must use `hmac.compare_digest`, reject malformed tokens, unknown payload fields, invalid IDs, wrong secrets, and expired bindings. The secret is supplied by the host and is never serialized into the token.

- [ ] **Step 1: Add RED tests for round-trip, tamper, expiry, and no-secret leakage.**
- [ ] **Step 2: Run the focused tests and confirm the expected failures.**
- [ ] **Step 3: Implement canonical signing and constant-time verification.**
- [ ] **Step 4: Run binding tests plus the full repository suite.**
- [ ] **Step 5: Add a short security note documenting that HMAC proves possession of the host key, not user intent.**
- [ ] **Step 6: Commit with `feat: add signed Northstar run bindings`.**

---

### Task 3: Define the Sidecar adapter boundary without enabling production

**Files:**
- Create: `components/northstar-run-contract/adapter.py`
- Create: `components/northstar-run-contract/tests/test_adapter.py`
- Modify: `components/northstar-codex-sidecar/README.md`

**Interfaces:**
- `to_sidecar_request(run: dict[str, object], binding: dict[str, object]) -> dict[str, object]`
- `receipt_from_sidecar_response(run_id: str, response: dict[str, object]) -> dict[str, object]`

The adapter may translate a verified Run Contract to the existing compatible Sidecar request (`request_id`, `prompt`, `timeout_ms`) and translate Sidecar statuses into versioned receipts. It must reject an unverified binding, never forward arbitrary fields as shell commands, never turn `codex_error` or `protocol_error` into fallback-eligible statuses, and never claim workspace isolation until a host workspace broker is present.

- [ ] **Step 1: Write RED tests for strict field translation and status mapping.**
- [ ] **Step 2: Run focused tests and confirm RED.**
- [ ] **Step 3: Implement the minimal pure adapter.**
- [ ] **Step 4: Run the adapter, contract, Sidecar, and documentation suites.**
- [ ] **Step 5: Document that this is a local adapter candidate, not a production deployment.**
- [ ] **Step 6: Commit with `feat: add run contract sidecar adapter`.**

---

### Task 4: Integration gate and release evidence

**Files:**
- Modify: `.github/workflows/test.yml`
- Modify: `CHANGELOG.md`
- Modify: `README.md`
- Create: `components/northstar-run-contract/tests/test_integration_contract.py`

- [ ] **Step 1: Add a deterministic contract → binding → adapter → receipt test.**
- [ ] **Step 2: Run it first against the current implementation and confirm it exercises the intended boundary.**
- [ ] **Step 3: Add CI steps for compile, contract tests, binding tests, adapter tests, and existing Sidecar tests.**
- [ ] **Step 4: Run the complete local CI-equivalent command and a sensitive-marker scan.**
- [ ] **Step 5: Verify the working tree, commit ancestry, and remote coordination state before any push.**
- [ ] **Step 6: Publish only after all results are fresh and independently confirmed.**

## Definition of Done

- The public repository has a versioned Run Request and Run Receipt contract.
- Structural validation, authentication, and authorization are explicitly separate.
- HMAC binding verification is deterministic and tested for tamper and expiry.
- Existing Sidecar behavior remains compatible and all previous tests remain green.
- The adapter cannot claim workspace isolation or authorization it does not implement.
- No production server or private workflow is changed in this milestone.
