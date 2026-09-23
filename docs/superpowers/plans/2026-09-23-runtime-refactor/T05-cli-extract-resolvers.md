# T05：`cli._run()` 抽出“解析”步骤

> 总方案与全局规则：[README](README.md)。参考补丁：[`patches/T05.patch`](patches/T05.patch)。依赖 T04 已合入。

**目标：** 把权限模式、工具访问、agent、MCP 服务器和上限这五块“多个来源合并、只能收紧”的逻辑搬进独立函数。这里是治理规则最集中的地方，拆开后每条规则都能单独审查和测试。行为完全不变。

**分支：** `refactor/T05-cli-resolvers`

**要改的文件：** `components/northstar-agent-runtime/cli.py`

## 新函数

全部放在 `def _run(` 之前、T04 新增的函数之后，按下表顺序排列。函数体逐字复制原代码。

| 新函数 | 原代码起点（含） | 原代码终点（不含） | 返回 |
| --- | --- | --- | --- |
| `_resolve_permission_mode(args, policy, plugins) -> str` | `    cli_mode = "plan" if args.plan …` | `    allowed_cli, denied_cli = _tool_lists(` | `mode`；`from permissions import validate_mode` 搬进函数 |
| `_resolve_tool_access(args, registry, policy, plugins) -> tuple[allowed, denied]` | `    allowed_cli, denied_cli = _tool_lists(` | `    definition = None` | `allowed, denied` |
| `_resolve_agent(args, policy, agents, registry, allowed) -> tuple[definition, registry, allowed]` | `    definition = None` | `    if (args.mcp_servers or (plugins and …` | `definition, registry, allowed` |
| `_resolve_mcp_servers(args, plugins, definition) -> tuple[servers, launch, report]` | `    if (args.mcp_servers or (plugins and …` | `    def tighten(` | `mcp_servers, mcp_launch, mcp_report` |
| `_tighten(cli_value, file_value)` | 原来 `_run()` 里的嵌套函数 `def tighten(...)` | — | 提升为模块级函数，改名 `_tighten`，docstring 不变 |
| `_resolve_ceilings(args, definition, policy, plugins) -> _Ceilings` | `    base_turns = definition.max_turns …` | `    try:\n        from provider_retry import` | `_Ceilings(...)`；函数内的 `tighten(` 全部改为 `_tighten(` |

`_resolve_permission_mode` 上方原有的注释块（“The file may pin 'plan'…”）改写成它的 docstring。`_resolve_tool_access`、`_resolve_mcp_servers` 里的行内注释保持原位。

新增冻结 dataclass `_Ceilings`，放在 `_resolve_ceilings` 前面。它的 docstring 是 T02 那个缺陷的教训，必须保留：

```python
@dataclass(frozen=True)
class _Ceilings:
    """The run's ceilings after every source (flags, agent, policy file, plugins) tightened them.

    Anything that later rebuilds a ceiling - a checkpoint resume, for one - must start from
    these values, never from the flags: the flags are only one of the sources.
    """

    max_turns: int
    max_tool_calls: int | None
    max_budget_usd: float | None
    compaction_threshold: int | None
    halt_on_denial: bool
```

## `_run()` 里的替换

从 `    cli_mode = "plan" if args.plan else args.permission_mode` 开始，到 `    try:` / `        from provider_retry import RetryConfigurationError` 之前结束的整段，替换为：

```python
    mode = _resolve_permission_mode(args, policy, plugins)
    allowed, denied = _resolve_tool_access(args, registry, policy, plugins)
    definition, registry, allowed = _resolve_agent(args, policy, agents, registry, allowed)
    mcp_servers, mcp_launch, mcp_report = _resolve_mcp_servers(args, plugins, definition)
    ceilings = _resolve_ceilings(args, definition, policy, plugins)

```

然后把 `_run()` 后面对 5 个上限局部变量的引用改成 `ceilings.` 前缀。一共 9 处，逐一对照：

| 原文 | 改为 |
| --- | --- |
| `"max_turns": max_turns,` | `"max_turns": ceilings.max_turns,` |
| `"max_tool_calls": max_tool_calls,` | `"max_tool_calls": ceilings.max_tool_calls,` |
| `"max_budget_usd": max_budget_usd,` | `"max_budget_usd": ceilings.max_budget_usd,` |
| `"compaction_threshold_tokens": compaction_threshold or None,` | `"compaction_threshold_tokens": ceilings.compaction_threshold or None,` |
| `"halt_on_denial": halt_on_denial,` | `"halt_on_denial": ceilings.halt_on_denial,` |
| `if args.checkpoint_turns and args.checkpoint_turns > max_turns:` | `… > ceilings.max_turns:` |
| `exceeds the run's max_turns {max_turns}, ` | `exceeds the run's max_turns {ceilings.max_turns}, ` |
| `config_kwargs["max_turns"] = max(max_turns, checkpoint.turns)` | `… = max(ceilings.max_turns, checkpoint.turns)` |
| `max_budget_usd=max_budget_usd,`（在 `_Budget(` 里） | `max_budget_usd=ceilings.max_budget_usd,` |

最后删除 `_run()` 顶部的 `from permissions import validate_mode`。

**自查**：改完后，在 `_run()` 里搜索不带前缀的 `max_turns`、`max_budget_usd`、`max_tool_calls`、`halt_on_denial`、`compaction_threshold`。它们只应以 `args.` 或 `ceilings.` 开头，或者作为字典的键出现。如果有漏改的，Python 会在运行时报 `NameError`，测试也会失败。

## 步骤

- [ ] 1. 记录基线。
- [ ] 2. 应用 `patches/T05.patch`，失败时按上文手工完成。
- [ ] 3. 核对：`_run()` 里不再有嵌套的 `def tighten`；`git diff --stat` 只涉及 `cli.py`。
- [ ] 4. 验证：`make test` 全绿；`cli_golden.py check` 输出 `all 48 cases identical`。重点看 `policy_tight`、`resume_from_checkpoint_policy`、`dry_run_agent` 这几个用例。
- [ ] 5. 提交：`refactor(cli): extract permission, tool, agent, MCP and ceiling resolution from _run`。开 PR，更新状态表。
