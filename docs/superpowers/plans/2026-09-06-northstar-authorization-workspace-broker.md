# Northstar Host Authorization and Workspace Broker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在不改动现有 Sidecar、Run Contract v1 或任何生产环境的前提下，为 Northstar 增加一个本地可验证的 host-side policy authorization 与 opaque workspace broker。

**Architecture:** 新增独立的 `northstar-host` 标准库组件。`authorization.py` 只负责验证结构化 Run Request、消费已经验证的 HMAC Run Binding、按显式 HostPolicy 默认拒绝能力，并签发绑定 actor/run/workspace/capabilities/policy revision/expiry 的授权 grant；它不创建目录、不执行任务。`workspace.py` 只在 host 边界重新验证 Run Binding 与授权 grant，检查二者和当前 policy revision 与 Run Request 一致后，使用 host-held derivation secret 派生不含用户 ID 的 opaque workspace key，并创建/复用严格 `0700` 的目录；它不执行命令、不接触 Sidecar。

**Tech Stack:** Python 3.10+、标准库 `dataclasses`/`pathlib`/`stat`/`hmac`/`hashlib`/`base64`/`json`、`unittest`、GitHub Actions。

## Global Constraints

- 仅修改本地 `/var/minis/workspace/northstar-agent-os` 工作副本；不连接、不写入 103、104、宿舍、生产 OpenBot 或任何生产服务。
- 不修改现有 `components/northstar-run-contract` 和 `components/northstar-codex-sidecar` 的运行协议；新组件通过现有公开函数消费它们。
- 不使用真实凭据；测试 secret 只存在于进程内夹具，不写入日志、文件、记忆或仓库。
- `validate_run_request`、Run Binding 验证、HostPolicy 授权、workspace 创建和未来的执行/postcondition 必须保持可单独测试的边界。
- 任何 requested capability 都是请求而非权限；HostPolicy 不显式列出 actor 或 capability 时必须拒绝，不能使用 wildcard、空策略放行或 UI/模型声明作为授权依据。
- 授权 grant 必须严格绑定 `actor_id`、`run_id`、`workspace_id`、完整 capability 集、`policy_revision` 和 `expires_at`；grant 过期、签名错误、字段未知、ID 不一致或 policy revision 过期均 fail-closed。
- workspace 路径只能由 host-held secret 对已验证 claims 做 HMAC 派生；不能把 `actor_id`、`run_id` 或 `workspace_id` 直接拼接进目录名，不能接受调用者提供的路径。
- workspace 根目录、`runs` 目录和每个 run 目录必须实际为 `0700` 普通目录；现有路径权限不正确、是符号链接、是普通文件或目录创建失败时拒绝，不自动放宽权限。
- 每个新行为必须遵守 RED → GREEN → REFACTOR；必须实际看到测试先因缺少实现而失败，再写生产代码。
- 宣称测试、构建、完成或安全边界成立前，必须在本消息中运行新鲜验证命令并读取退出状态与失败数。

---

## File Map

- Create: `components/northstar-host/authorization.py` — HostPolicy、授权 grant schema、签发与验证、`authorize_run()`；不包含文件系统操作。
- Create: `components/northstar-host/workspace.py` — `WorkspaceBroker`、opaque key 派生、目录权限/符号链接检查与 `WorkspaceAllocation`；不包含策略决策或命令执行。
- Create: `components/northstar-host/README.md` — 组件 API、信任边界、默认拒绝、密钥职责和当前非生产范围。
- Create: `components/northstar-host/tests/test_authorization.py` — 授权 policy/grant 单元测试。
- Create: `components/northstar-host/tests/test_workspace.py` — workspace 分配、权限、opaque path 和攻击面测试。
- Create: `components/northstar-host/tests/test_integration_host.py` — Run Request → verified binding → authorization grant → workspace allocation 集成测试。
- Modify: `.github/workflows/test.yml` — 加入 host 组件 compile 和 unittest，不改变已有 Sidecar/Run Contract 命令。
- Modify: `CHANGELOG.md` — 记录本地 host 候选的边界，明确尚未生产部署。
- Modify: `README.md` — 将“host-level responsibility”更新为已发布的本地候选组件，但不把它描述成生产隔离或完整 Agent OS。

## Interfaces

Run Contract 组件保持不变，host 组件在 CI 中通过 `PYTHONPATH=components/northstar-run-contract` 导入 `contract.py` 与 `binding.py`。新增接口固定如下：

```python
# components/northstar-host/authorization.py
@dataclass(frozen=True)
class HostPolicy:
    revision: str
    actor_capabilities: Mapping[str, frozenset[str]]

    @classmethod
    def from_mapping(
        cls, revision: str, actor_capabilities: Mapping[str, Iterable[str]]
    ) -> "HostPolicy":
        raise NotImplementedError

@dataclass(frozen=True)
class AuthorizationValidation:
    ok: bool
    authorization: dict[str, Any] | None = None
    errors: tuple[str, ...] = ()

def authorize_run(
    run: dict[str, Any],
    binding: BindingValidation,
    policy: HostPolicy,
    *,
    now: int,
    secret: bytes,
    grant_ttl_seconds: int = 300,
) -> str:
    raise NotImplementedError

def sign_authorization(authorization: dict[str, Any], secret: bytes) -> str:
    raise NotImplementedError

def verify_authorization(
    token: str, secret: bytes, *, now: int
) -> AuthorizationValidation:
    raise NotImplementedError
```

`authorize_run()` 只接受 `BindingValidation`，不接受原始 token；这样调用方必须在认证边界先执行 `verify_binding()`. `authorize_run()` 要求 actor 在 policy 中显式存在，即使 requested capabilities 为空；请求的 capability 集必须是 actor grant 的精确集合。授权 token 是 host 内部跨边界凭据，不把 secret 序列化进 token。

```python
# components/northstar-host/workspace.py
@dataclass(frozen=True)
class WorkspaceAllocation:
    workspace_key: str
    path: Path

class WorkspaceBroker:
    def __init__(
        self,
        root: str | Path,
        *,
        binding_secret: bytes,
        authorization_secret: bytes,
        derivation_secret: bytes,
    ) -> None:
        raise NotImplementedError

    def allocate(
        self,
        run: dict[str, Any],
        binding_token: str,
        authorization_token: str,
        *,
        current_policy_revision: str,
        now: int,
    ) -> WorkspaceAllocation:
        raise NotImplementedError
```

`allocate()` 在自己的 host 边界重新验证 binding 与 grant，而不是信任调用方传入的“已授权”布尔值。它要求 grant 的 actor/run/workspace 和 binding、Run Request 完全一致，grant capabilities 与 requested capabilities 集合完全一致，grant policy revision 等于调用方提供的当前 revision，且所有 expiry 在 `now` 后。返回的 path 由 HMAC 派生 key 组成，不接受 caller path。

---

### Task 1: Add the HostPolicy and signed authorization grant

**Files:**
- Create: `components/northstar-host/authorization.py`
- Create: `components/northstar-host/tests/test_authorization.py`

**Step 1: Write the failing tests**

建立最小但有安全含义的真实行为夹具。测试文件将 `northstar-run-contract` 和 `northstar-host` 放入 `sys.path`，复用现有 `valid_request()` 和 `sign_binding()/verify_binding()`，不 mock HMAC 或 policy。首轮必须包含这些测试：

```python
class HostAuthorizationTests(unittest.TestCase):
    SECRET = b"authorization-test-secret"

    def verified_binding(self, run=None):
        run = run or valid_request()
        raw = {
            "schema_version": run["schema_version"],
            "run_id": run["run_id"],
            "actor_id": run["actor_id"],
            "workspace_id": run["workspace_id"],
            "expires_at": 2_000_000_000,
        }
        return verify_binding(
            sign_binding(raw, b"binding-test-secret"),
            b"binding-test-secret",
            now=1_999_999_999,
        )

    def test_unknown_actor_is_denied_even_when_no_capability_is_requested(self):
        policy = HostPolicy.from_mapping("policy-1", {})
        with self.assertRaises(ValueError):
            authorize_run(
                valid_request(), self.verified_binding(), policy,
                now=1_000, secret=self.SECRET,
            )

    def test_unlisted_capability_is_denied_by_default(self):
        policy = HostPolicy.from_mapping("policy-1", {"actor-001": []})
        run = valid_request()
        run["requested_capabilities"] = ["browser"]
        with self.assertRaises(ValueError):
            authorize_run(
                run, self.verified_binding(run), policy,
                now=1_000, secret=self.SECRET,
            )

    def test_authorization_grant_binds_exact_claims_and_round_trips(self):
        run = valid_request()
        run["requested_capabilities"] = ["browser", "search"]
        policy = HostPolicy.from_mapping(
            "policy-7", {"actor-001": ["browser", "search"]}
        )
        token = authorize_run(
            run, self.verified_binding(run), policy,
            now=1_000, secret=self.SECRET, grant_ttl_seconds=120,
        )
        result = verify_authorization(token, self.SECRET, now=1_119)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(
            result.authorization,
            {
                "schema_version": "northstar.authorization.v1",
                "actor_id": "actor-001",
                "run_id": "run-001",
                "workspace_id": "workspace-001",
                "capabilities": ["browser", "search"],
                "policy_revision": "policy-7",
                "expires_at": 1_120,
            },
        )

    def test_grant_tampering_expiry_and_unknown_fields_fail_closed(self):
        run = valid_request()
        policy = HostPolicy.from_mapping("policy-1", {"actor-001": []})
        token = authorize_run(
            run, self.verified_binding(run), policy,
            now=1_000, secret=self.SECRET, grant_ttl_seconds=100,
        )
        payload, signature = token.split(".", 1)
        changed = "A" if signature[0] != "A" else "B"
        self.assertFalse(
            verify_authorization(
                payload + "." + changed + signature[1:],
                self.SECRET, now=1_001,
            ).ok
        )
        self.assertFalse(
            verify_authorization(token, self.SECRET, now=1_100).ok
        )
        with self.assertRaises(ValueError):
            sign_authorization(
                {
                    "schema_version": "northstar.authorization.v1",
                    "actor_id": "actor-001",
                    "run_id": "run-001",
                    "workspace_id": "workspace-001",
                    "capabilities": [],
                    "policy_revision": "policy-1",
                    "expires_at": 2_000,
                    "unexpected": "reject-me",
                },
                self.SECRET,
            )
```

`test_grant_tampering_expiry_and_unknown_fields_fail_closed` 必须实际构造合法 token 后改变 signature、在 `now == expires_at` 验证过期，并调用 `sign_authorization()` 传入额外字段；每种情况都断言拒绝。补充 binding actor/run/workspace 不一致、布尔 now/ttl、空 secret、重复 capability 和 policy revision 非法的测试。测试中的 `...` 仅是计划展示的测试分组名，落盘实现时不得保留省略号。

**Step 2: Run the focused tests to verify RED**

运行：

```sh
cd /var/minis/workspace/northstar-agent-os
PYTHONPATH=components/northstar-run-contract:components/northstar-host \
  python3 -m unittest components/northstar-host/tests/test_authorization.py -v
```

预期：测试收集成功但因 `authorization.py` 不存在或接口不存在而失败；如果出现 import 语法错误，先修正测试路径直到得到针对缺失生产接口的 RED，而不是跳过测试。

**Step 3: Implement the minimal authorization boundary**

在 `authorization.py` 中实现：

1. `HostPolicy.from_mapping()` 将输入复制为不可变 `dict[str, frozenset[str]]`；revision、actor ID、capability 名称服从现有 ID/capability 长度约束；字符串不得被当作 capability iterable；actor 未列出时返回空但 `authorize_run()` 必须拒绝。
2. `authorize_run()` 先调用 `validate_run_request()`，再要求 `BindingValidation` 类型、`ok is True` 且 binding 非空，并逐项比较 actor/run/workspace；检查 `now < binding.expires_at`；检查 requested capability 是 policy 中该 actor 的子集；计算 `expires_at=min(binding.expires_at, now+grant_ttl_seconds)`。
3. 授权 payload 只允许 `schema_version`, `actor_id`, `run_id`, `workspace_id`, `capabilities`, `policy_revision`, `expires_at`；capabilities 排序、唯一且有上限；未知字段、错误类型、过期、空 secret 和错误 base64url 统一拒绝。
4. `sign_authorization()` 使用 canonical compact JSON + URL-safe base64 无填充 + HMAC-SHA256；`verify_authorization()` 用 `hmac.compare_digest`，先验证签名再验证 payload/schema/expiry，并返回 `AuthorizationValidation` 而不是把异常泄漏给调用方。

只实现测试要求的行为，不添加通配 capability、scope widening、文件系统或执行功能。

**Step 4: Run the focused tests to verify GREEN**

运行同一 focused unittest 命令，并确认所有授权测试通过；随后单独执行：

```sh
python3 -m py_compile components/northstar-host/authorization.py
```

如果失败，修正生产代码而不是放宽安全断言；不要在此步修改旧 Run Contract 测试以适配新实现。

**Step 5: Refactor only while green**

删除重复的 token 编码辅助函数、统一错误边界和类型注解；再次运行 focused tests，确保重构不改变未知字段、过期、精确 capability 集合和 binding mismatch 的行为。

**Step 6: Commit the independently testable component**

```sh
git add components/northstar-host/authorization.py components/northstar-host/tests/test_authorization.py
git commit -m "feat: add host authorization grants"
```

这是本地 commit，不推送远端；推送属于后续明确发布动作。

---

### Task 2: Add the opaque workspace broker

**Files:**
- Create: `components/northstar-host/workspace.py`
- Create: `components/northstar-host/tests/test_workspace.py`

**Interfaces:**
- Consumes `validate_run_request`, `verify_binding`, `verify_authorization`, and the exact token schemas from Task 1.
- Produces `WorkspaceAllocation(workspace_key: str, path: pathlib.Path)` and `WorkspaceBroker.allocate(...)`.

**Step 1: Write the failing tests**

先追加只针对 workspace 行为的测试，不写 `workspace.py`：

```python
class WorkspaceBrokerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "northstar-state"
        self.broker = WorkspaceBroker(
            self.root,
            binding_secret=b"binding-secret",
            authorization_secret=b"authorization-secret",
            derivation_secret=b"derivation-secret",
        )

    def test_allocates_private_opaque_workspace(self):
        run = valid_request()
        binding_token = make_binding_token(run, b"binding-secret")
        grant = authorize_run(
            run,
            verify_binding(binding_token, b"binding-secret", now=1_000),
            HostPolicy.from_mapping("policy-1", {"actor-001": []}),
            now=1_000,
            secret=b"authorization-secret",
        )
        allocation = self.broker.allocate(
            run, binding_token, grant,
            current_policy_revision="policy-1", now=1_001,
        )
        self.assertRegex(allocation.workspace_key, r"^[0-9a-f]{64}$")
        self.assertTrue(allocation.path.is_dir())
        self.assertEqual(stat.S_IMODE(allocation.path.stat().st_mode), 0o700)
        self.assertNotIn(run["actor_id"], str(allocation.path))
        self.assertNotIn(run["run_id"], str(allocation.path))
        self.assertNotIn(run["workspace_id"], str(allocation.path))

    def test_same_verified_claims_reuse_same_path_without_relaxing_permissions(self):
        first = self.allocate_valid()
        before = stat.S_IMODE(first.path.stat().st_mode)
        second = self.allocate_valid()
        self.assertEqual(second.workspace_key, first.workspace_key)
        self.assertEqual(second.path, first.path)
        self.assertEqual(stat.S_IMODE(second.path.stat().st_mode), before)

    def test_binding_or_grant_mismatch_and_stale_policy_revision_are_rejected(self):
        run = valid_request()
        binding_token = make_binding_token(run, b"binding-secret")
        grant = make_grant(run, binding_token, "policy-1")
        with self.assertRaises(ValueError):
            self.broker.allocate(
                run, binding_token, grant,
                current_policy_revision="policy-2", now=1_001,
            )
        altered = dict(run)
        altered["run_id"] = "run-002"
        with self.assertRaises(ValueError):
            self.broker.allocate(
                altered, binding_token, grant,
                current_policy_revision="policy-1", now=1_001,
            )

    def test_existing_symlink_file_or_non_private_directory_is_rejected(self):
        first = self.allocate_valid()
        first.path.chmod(0o755)
        with self.assertRaises(ValueError):
            self.broker.allocate(
                valid_request(), self.binding_token, self.grant_token,
                current_policy_revision="policy-1", now=1_002,
            )
```

测试必须覆盖：不能由 caller 传 path；改变 run actor/run/workspace 任一字段拒绝；伪造 grant 或未验证/过期 token 拒绝；grant capabilities 比 request 多或少拒绝；`current_policy_revision` 不一致拒绝；root、runs、workspace 是符号链接/文件/非 0700 时拒绝；同一 claims 的重复 allocate 返回同一 opaque key。对 symlink 测试使用派生 key（由测试调用一个 public deterministic helper 或先成功分配再替换为 symlink），不要依赖猜测 actor ID 目录名。

**Step 2: Run the focused workspace tests to verify RED**

```sh
cd /var/minis/workspace/northstar-agent-os
PYTHONPATH=components/northstar-run-contract:components/northstar-host \
  python3 -m unittest components/northstar-host/tests/test_workspace.py -v
```

预期为针对缺失 `workspace.py`/`WorkspaceBroker` 的 RED；测试收集错误不算 RED，必须修到正确失败。

**Step 3: Implement minimal fail-closed allocation**

在 `workspace.py` 中实现：

1. 构造函数要求三个非空 bytes secret，并把 root 转成绝对 `Path`；不接受 workspace path 或 user-supplied directory name。
2. `allocate()` 先验证 Run Request；用 binding secret 调 `verify_binding(binding_token, ..., now=now)`，用 authorization secret 调 `verify_authorization(authorization_token, ..., now=now)`；任一失败都抛出不含 token/secret 的 `ValueError`。
3. 严格比较 run、binding、grant 的 actor/run/workspace；严格比较 `set(grant.capabilities)` 与 `set(run.requested_capabilities)`；要求 grant policy revision 等于 `current_policy_revision`，并验证 revision 是合法非空 ID。
4. 用 canonical JSON claims `{actor_id, run_id, workspace_id}` 作为 HMAC message，以 derivation secret 生成 64 位小写十六进制 `workspace_key`；目录只使用这个 key：`<root>/runs/<workspace_key>`。
5. 以 `lstat`/`stat` 检查 root、runs、workspace。目录不存在时逐级以 mode `0700` 创建；已存在时必须是普通目录且实际 mode 精确为 `0700`；符号链接、文件、权限不一致、创建失败均拒绝。不要通过 `chmod` 把不安全的既有目录“修好”，避免替管理员修复共享路径。
6. 返回 `WorkspaceAllocation`；重复请求复用同一路径。当前组件只分配目录，不在目录内写 prompt、凭据、日志或执行产物。

**Step 4: Run workspace tests to verify GREEN**

运行 focused workspace tests，并检查临时目录清理；再运行：

```sh
python3 -m py_compile components/northstar-host/workspace.py
```

要求测试实际观察到 `0700`、opaque key、token/claim mismatch、symlink/file/permission fail-closed，而不是只检查返回值。

**Step 5: Refactor only while green**

仅在测试全绿后抽取 `_ensure_private_directory()`、`_derive_workspace_key()` 等小函数；保留 `lstat` 检查和精确权限断言，再重跑 focused workspace tests。

**Step 6: Commit the independently testable broker**

```sh
git add components/northstar-host/workspace.py components/northstar-host/tests/test_workspace.py
git commit -m "feat: add opaque Northstar workspace broker"
```

仍只创建本地 commit，不部署、不推送。

---

### Task 3: Prove the host chain and publish the local-only boundary

**Files:**
- Create: `components/northstar-host/tests/test_integration_host.py`
- Create: `components/northstar-host/README.md`
- Modify: `.github/workflows/test.yml`
- Modify: `README.md`
- Modify: `CHANGELOG.md`

**Step 1: Write the failing integration test**

在实现已有时，先写一个能识别错误接线的集成测试，然后暂时以“撤回待接线代码”的方式确认它不是无条件通过。集成测试必须覆盖真实顺序：

```python
def test_run_binding_authorization_and_workspace_chain(self):
    run = valid_request()
    binding_token = sign_binding(binding_for(run), BINDING_SECRET)
    verified = verify_binding(binding_token, BINDING_SECRET, now=1_000)
    self.assertTrue(verified.ok, verified.errors)

    policy = HostPolicy.from_mapping(
        "policy-9", {"actor-001": ["search"]}
    )
    run["requested_capabilities"] = ["search"]
    binding_token = sign_binding(binding_for(run), BINDING_SECRET)
    verified = verify_binding(binding_token, BINDING_SECRET, now=1_000)
    grant_token = authorize_run(
        run, verified, policy, now=1_000,
        secret=AUTHORIZATION_SECRET, grant_ttl_seconds=60,
    )
    allocation = WorkspaceBroker(...).allocate(
        run, binding_token, grant_token,
        current_policy_revision="policy-9", now=1_001,
    )
    self.assertEqual(allocation.path, ...)
```

同时写负向链路：过期 binding 不得签 grant；合法 grant 配错误 current policy revision 不得分配；改变 run workspace_id 不得到达目录创建；合法授权不应把 `requested_capabilities` 或 prompt 写入 Sidecar 或 workspace（通过检查组件源代码/返回对象边界，不执行 side effect）。落盘代码必须将 `...` 替换为具体临时目录、secret 和断言，不能保留占位符。

**Step 2: Run the integration test and verify its failure mode**

使用：

```sh
PYTHONPATH=components/northstar-run-contract:components/northstar-host \
  python3 -m unittest components/northstar-host/tests/test_integration_host.py -v
```

每一个负向测试都必须因对应安全门拒绝而通过；对于新增的正向链路，先临时删除/隔离 broker 的最小接线，观察测试失败，再恢复接线并进入 GREEN，保留 RED 的命令输出作为本轮证据，不允许用 `assert True` 或 mock 绕过。

**Step 3: Add the component documentation**

`components/northstar-host/README.md` 必须明确：

- structural validation、binding authentication、policy authorization、workspace allocation 是四个不同阶段；组件不执行 Sidecar。
- HostPolicy 是显式 actor → capability allowlist；未列出的 actor/capability 默认拒绝；requested capability 不是 grant。
- binding secret、authorization secret、derivation secret 的职责不同；任何 secret 不进入 token 或 path。
- authorization grant 的字段与 expiry/policy revision 检查；workspace key 是 HMAC hex，不是 actor/run/workspace ID 编码。
- 现有目录若为 symlink、文件或非 0700，组件拒绝而不自动 chmod；真实 Linux 上仍需并发、进程、容器/系统权限与部署验证。
- 当前是本地候选，不是生产 workspace broker、不是完整 Agent OS、不是已部署到 103/104/OpenBot 的功能。

根 `README.md` 和 `CHANGELOG.md` 只能增加准确范围：已加入可测试的 host authorization/workspace candidate；不能删除“未生产”“不执行命令”“需 native Linux/host integration”这些限制，也不能把本地测试写成生产安全证明。

**Step 4: Extend CI without weakening existing gates**

在 `.github/workflows/test.yml` 增加：

```yaml
      - name: Compile host component
        working-directory: components/northstar-host
        run: PYTHONPATH=../northstar-run-contract python -m py_compile authorization.py workspace.py tests/test_authorization.py tests/test_workspace.py tests/test_integration_host.py
      - name: Host component tests
        working-directory: components/northstar-host
        run: PYTHONPATH=../northstar-run-contract python -m unittest discover -s tests -p 'test_*.py' -v
```

保留已有 Sidecar compile/tests、Run Contract compile/tests、shell syntax 三组命令。CI 只用测试 secret 和临时目录，不从环境读取或打印凭据。

**Step 5: Run the complete local CI-equivalent verification**

在提交前运行完整命令，并记录每组真实结果：

```sh
cd /var/minis/workspace/northstar-agent-os
python3 -m py_compile components/northstar-codex-sidecar/sidecar.py components/northstar-codex-sidecar/transport.py components/northstar-codex-sidecar/service.py components/northstar-codex-sidecar/sidecar_socket.py components/northstar-codex-sidecar/tests/test_sidecar.py
python3 -m unittest discover -s components/northstar-codex-sidecar/tests -p 'test_*.py' -v
PYTHONPATH=components/northstar-run-contract python3 -m py_compile components/northstar-run-contract/contract.py components/northstar-run-contract/binding.py components/northstar-run-contract/adapter.py components/northstar-run-contract/tests/test_contract.py components/northstar-run-contract/tests/test_integration_contract.py
PYTHONPATH=components/northstar-run-contract python3 -m unittest discover -s components/northstar-run-contract/tests -p 'test_*.py' -v
PYTHONPATH=components/northstar-run-contract:components/northstar-host python3 -m py_compile components/northstar-host/authorization.py components/northstar-host/workspace.py components/northstar-host/tests/test_authorization.py components/northstar-host/tests/test_workspace.py components/northstar-host/tests/test_integration_host.py
PYTHONPATH=components/northstar-run-contract:components/northstar-host python3 -m unittest discover -s components/northstar-host/tests -p 'test_*.py' -v
python3 -m unittest tests.test_documentation -v
sh -n components/northstar-codex-sidecar/install.sh components/northstar-codex-sidecar/rollback.sh
```

另外执行确定性边界扫描：

```sh
git diff --check
grep -RInE 'AKIA[0-9A-Z]{16}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|Bearer[[:space:]]+[A-Za-z0-9._-]{20,}|-----BEGIN' components/northstar-host README.md CHANGELOG.md || true
git status --short --branch
git diff --stat HEAD~2..HEAD
```

扫描命中需逐项人工判定；测试 fixture 中的短字符串不是生产凭据，但不得把任何真实 secret 写入文件。若 iSH 的权限/临时目录行为与 native Linux 不同，明确记录为环境限制，不能宣称 native Linux 验证。

**Step 6: Commit documentation and CI locally**

```sh
git add components/northstar-host .github/workflows/test.yml README.md CHANGELOG.md
git commit -m "docs: define Northstar host authorization boundary"
```

提交后重新运行 `git status --short --branch`、`git rev-parse HEAD`、`git rev-parse origin/main`。本计划不包含 push、部署或生产 OpenBot 操作；只有用户另行授权发布时才进行远端动作，并在动作前重新执行多会话协调。

---

## Definition of Done

- `northstar-host` 是独立、标准库、可测试的本地组件；现有 Run Contract 与 Sidecar 文件协议未改变。
- 未显式列入 HostPolicy 的 actor 或 capability 无法获得 grant；grant 不能扩大 requested capability 集。
- grant 的 actor/run/workspace/capabilities/policy revision/expiry 均经过签名和严格验证；binding 未验证、过期或 ID 不匹配时链路 fail-closed。
- WorkspaceBroker 在自己的边界重新验证 token 与 claims，并只创建 HMAC 派生的 opaque 目录名；用户 ID 不直接出现在 path 中。
- root、runs 和 run workspace 的实际权限均为 `0700`；symlink、file、非私有目录、stale policy、过期 token 均拒绝，且不执行 chmod 修复。
- 新授权、workspace、集成测试先有 RED 再 GREEN；已有 Sidecar、Run Contract、文档测试保持通过。
- README、CHANGELOG、CI 准确说明这是 host-side local candidate，不是生产 broker、不是完整 Agent OS、没有部署到 103/104/OpenBot。
- 所有完成结论均有本轮新鲜的测试、编译、shell、diff 和状态输出支持；远端仍不推送。

## Self-review checklist

- Spec coverage: policy default deny（Task 1）、exact signed grant and expiry（Task 1）、opaque `0700` allocation（Task 2）、independent re-verification（Task 2）、end-to-end separation（Task 3）、existing suite/CI/documentation（Task 3）均有明确任务。
- Placeholder scan: 本计划中的 `...` 只出现在说明“落盘测试不得保留省略号”的示例位置；执行时必须替换为具体代码，计划本身不允许把它误当作实现。
- Type consistency: Task 1 输出 `AuthorizationValidation`/`verify_authorization`，Task 2 以 token 和 `current_policy_revision` 消费；Task 3 使用同一签名与字段，不引入未定义函数。
- Deliberate ceiling: 该 broker 只分配 host 目录，不提供 sandbox、执行、网络隔离、清理、租约、并发原子文件操作或 native Linux 进程验证；这些属于后续独立项目，不在本 milestone 虚假宣称。
