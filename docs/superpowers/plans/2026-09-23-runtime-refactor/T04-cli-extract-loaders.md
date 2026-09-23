# T04：`cli._run()` 抽出提示词读取和“加载”步骤

> 总方案与全局规则：[README](README.md)。参考补丁：[`patches/T04.patch`](patches/T04.patch)。依赖 T03 已合入。

**目标：** 把 `_run()` 开头读取提示词、加载工作区声明的那一段（约 135 行）搬进 6 个新函数。`_run()` 里的对应部分缩成 16 行调用。行为完全不变。

**分支：** `refactor/T04-cli-loaders`

**要改的文件：** `components/northstar-agent-runtime/cli.py`（只改这一个文件）

## 新函数

全部放在 `cli.py` 里，紧挨在 `def _run(` 之前，按下表顺序排列。表中的“原代码”指 `_run()` 里的对应片段，从“起点”那一行开始，到“终点”之前结束。函数体**逐字复制**原代码，只做“改动”列写明的调整。

| 新函数 | 起点（含） | 终点（不含） | 返回 | 改动 |
| --- | --- | --- | --- | --- |
| `_read_prompt(args) -> str` | `    prompt = args.prompt` | `        if not prompt.strip():` 里第二层的 `print("no prompt: …` | `prompt` | 最后那个“no prompt”打印和 `return USAGE_ERROR` **不搬**，留在 `_run()`，因为它的输出没有 `configuration error:` 前缀 |
| `_load_plugins(args, registry) -> Any` | `    plugins: Any = None` | `    # Repository-defined subagents` | `plugins` 或 `None` | `if not args.no_plugins:` 改成开头的 `if args.no_plugins: return None`，其余代码缩进减一级 |
| `_load_workspace_agents(args, agents, registry, plugins) -> tuple` | `    workspace_agents: tuple[Any, ...] = ()` | `    # Workspace policy file` | 注册的定义元组 | 同上：`if args.no_workspace_agents: return ()`；`from agent_files import …` 搬进函数 |
| `_load_policy(args, registry, agents) -> Any` | `    policy = None` | `    # Repository-declared lifecycle hooks` | policy 或 `None` | 同上；`from policy_file import PolicyFileError, load_policy_file` 搬进函数 |
| `_load_hooks(args, policy, plugins, registry) -> _HookSetup` | `    hook_registry = None` | `    # Postconditions are checked` | `_HookSetup` | 末尾 `return _HookSetup(registry=hook_registry, command_hooks=command_hooks, plugin_hook_count=len(plugin_hook_tables))` |
| `_load_postconditions(args, policy) -> tuple` | `    postconditions: tuple[Any, ...] = ()` | `    cli_mode = "plan"` | postconditions 元组 | `if not declared_checks: return ()` |

每段代码上方原有的注释块（例如 `# Installed plugin bundles (.northstar/plugins/). A bundle is a *packaging* format…`）改写成对应函数的 docstring，内容保持不变。

`_HookSetup` 是新增的冻结 dataclass，放在 `_load_hooks` 前面。需要在文件顶部加 `from dataclasses import dataclass`，位置在 `from pathlib import Path` 之前。

```python
@dataclass(frozen=True)
class _HookSetup:
    """What `_load_hooks()` decided: the registry to run (or None) and what fed it."""

    registry: Any
    command_hooks: tuple[Any, ...]
    plugin_hook_count: int
```

在第一个新函数前面加一段分节注释：

```python
# ---------------------------------------------------------------------------------------
# The steps of `_run()`, in the order it calls them. Each step either returns what the next
# steps need or raises RunConfigurationError; none of them prints a configuration error
# itself, so the order of stderr lines is exactly the order of the calls in `_run()`.
# ---------------------------------------------------------------------------------------
```

## `_run()` 里的替换

从 `    prompt = args.prompt` 开始，到 `    cli_mode = "plan" if args.plan else args.permission_mode` 之前结束的整段，替换为：

```python
    prompt = _read_prompt(args)
    if not prompt.strip():
        print(
            "no prompt: pass a task string, --prompt, --prompt-file, or --probe-sidecar "
            "(on a TTY, bare `agent` also reads one line)",
            file=sys.stderr,
        )
        return USAGE_ERROR

    registry = build_default_registry()
    agents = builtin_registry()
    plugins = _load_plugins(args, registry)
    workspace_agents = _load_workspace_agents(args, agents, registry, plugins)
    policy = _load_policy(args, registry, agents)
    hooks = _load_hooks(args, policy, plugins, registry)
    postconditions = _load_postconditions(args, policy)

```

然后更新 `_run()` 后面引用旧局部变量的两处：
- `_hooks_note(policy, command_hooks, …, plugin_hooks=len(plugin_hook_tables))` 改为 `_hooks_note(policy, hooks.command_hooks, enabled=args.enable_workspace_hooks, plugin_hooks=hooks.plugin_hook_count)`；
- `AgentRuntime(…, hooks=hook_registry, …)` 改为 `hooks=hooks.registry`。

最后删除 `_run()` 顶部已经用不到的导入：`from agent_files import AgentFileError, register_workspace_agents` 整行删除；`from policy_file import …` 只保留 `append_project_context, discover_project_context`。

## 步骤

- [ ] 1. 记录基线。
- [ ] 2. `git apply --check …/patches/T04.patch && git apply …/patches/T04.patch`；失败时按上文手工完成。
- [ ] 3. 核对：`git diff --stat` 只涉及 `cli.py`。`_run()` 里不再出现 `hook_registry`、`plugin_hook_tables`、`declared_checks`。
- [ ] 4. 验证：`make test` 全绿；`cli_golden.py check` 输出 `all 48 cases identical`。
- [ ] 5. 提交：`refactor(cli): extract the prompt and workspace-loading steps of _run`。开 PR，更新状态表。
