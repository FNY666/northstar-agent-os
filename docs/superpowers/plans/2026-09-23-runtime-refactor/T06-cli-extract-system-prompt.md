# T06：`cli._run()` 抽出系统提示词拼接

> 总方案与全局规则：[README](README.md)。参考补丁：[`patches/T06.patch`](patches/T06.patch)。依赖 T05 已合入。

**目标：** 系统提示词由 6 个来源按固定顺序拼接而成。本卡把这约 75 行代码搬进 `_compose_system_prompt()`。**这是整个 CLI 拆分中最容易出错的一步**：顺序一变、分隔符一变，模型看到的指令就变了，而 dry-run 输出里根本看不到提示词。`cli_golden.py` 记录了每个用例的完整系统提示词，专门用来发现这类问题。

**拼接顺序（不能变）：**
1. `--system-prompt`；如果以 agent 身份运行，则由 agent 定义自己的提示词**覆盖**它；
2. 项目说明（AGENTS.md）；
3. 工作区技能列表；
4. 技能脚本列表；
5. 工作区记忆（MEMORY.md）；
6. 插件上下文。

每一步都追加在“当前提示词”后面。如果前面还没有任何提示词，就从 `DEFAULT_SYSTEM_PROMPT` 开始。

**一个必须保留的细节：** 原代码用 `config_kwargs.get("system_prompt", DEFAULT_SYSTEM_PROMPT)` 取“当前提示词”。如果 6 个来源都没有内容，`config_kwargs` 里**根本不会有** `system_prompt` 这个键，`RuntimeConfig` 会使用它自己的默认值。新函数用 `None` 表示“没有设置”，调用方只在值不是 `None` 时才写入 `config_kwargs`。

**分支：** `refactor/T06-cli-system-prompt`

**要改的文件：** `components/northstar-agent-runtime/cli.py`

## 新代码

放在 `def _run(` 之前、T05 新增的函数之后：

```python
@dataclass(frozen=True)
class _PromptSetup:
    """The assembled system prompt and what went into it (for the dry-run notes).

    ``system_prompt`` is None when nothing replaced or extended the runtime's default, so
    ``RuntimeConfig`` keeps its own default exactly as before.
    """

    system_prompt: str | None
    context: Any
    skills: tuple[Any, ...]
    memory_note: str


def _compose_system_prompt(args: argparse.Namespace, definition: Any, policy: Any, plugins: Any) -> _PromptSetup:
    """Build the system prompt in its fixed order.

    Order: --system-prompt (or the agent definition's own prompt, which wins) -> project
    instructions (AGENTS.md) -> workspace skills listing -> skill scripts listing ->
    workspace memory -> plugin context. Each part is appended to whatever came before it,
    starting from the runtime's DEFAULT_SYSTEM_PROMPT when nothing replaced it.
    """
    from loop import DEFAULT_SYSTEM_PROMPT
    from policy_file import append_project_context, discover_project_context
    from skills import SkillError, discover_skills, skill_listing

    system_prompt: str | None = None
    if args.system_prompt:
        system_prompt = args.system_prompt
    if definition:
        system_prompt = definition.system_prompt(parent_cwd=args.workspace)

    # ……（下面逐字复制原来从 “# Project instructions (AGENTS.md by default” 注释开始，
    #     到插件上下文那段 `config_kwargs["system_prompt"] = (...)` 结束的全部代码，
    #     只做下面“替换规则”里的两种替换）……

    return _PromptSetup(system_prompt=system_prompt, context=context, skills=skills, memory_note=memory_note)
```

**替换规则**（在复制过来的代码里）：
- `config_kwargs.get("system_prompt", DEFAULT_SYSTEM_PROMPT)` → `system_prompt if system_prompt is not None else DEFAULT_SYSTEM_PROMPT`（共 5 处）；
- `config_kwargs["system_prompt"] = ` → `system_prompt = `（共 5 处）。

完整的函数体见参考补丁。

## `_run()` 里的替换

原来是这样的（从 `if args.system_prompt:` 开始，到插件上下文那段结束）：

```python
    if args.system_prompt:
        config_kwargs["system_prompt"] = args.system_prompt
    if definition:
        config_kwargs["system_prompt"] = definition.system_prompt(parent_cwd=args.workspace)
        config_kwargs["agent"] = definition.name
        config_kwargs["allow_delegation"] = definition.allow_delegation and args.max_subagent_depth > 0

    # Project instructions ...
    ...（一直到插件上下文那段的最后一个右括号）
```

整段替换为：

```python
    if definition:
        config_kwargs["agent"] = definition.name
        config_kwargs["allow_delegation"] = definition.allow_delegation and args.max_subagent_depth > 0
    prompt_setup = _compose_system_prompt(args, definition, policy, plugins)
    if prompt_setup.system_prompt is not None:
        config_kwargs["system_prompt"] = prompt_setup.system_prompt
    context = prompt_setup.context
    skills = prompt_setup.skills
    memory_note = prompt_setup.memory_note

```

`context`、`skills`、`memory_note` 这三行是为了让 `_run()` 后面生成 dry-run 说明的代码暂时不用改，T07 会删掉它们。

最后清理 `_run()` 顶部的导入：`from loop import …` 里去掉 `DEFAULT_SYSTEM_PROMPT`；删除整行 `from policy_file import append_project_context, discover_project_context`；删除整行 `from skills import SkillError, discover_skills, skill_listing`。

## 步骤

- [ ] 1. 记录基线。
- [ ] 2. 应用 `patches/T06.patch`，失败时按上文手工完成。
- [ ] 3. 核对：`_run()` 里不再出现 `DEFAULT_SYSTEM_PROMPT`；`_compose_system_prompt` 里的 5 处 `base_prompt = …` 都已改用 `system_prompt if system_prompt is not None else DEFAULT_SYSTEM_PROMPT`。
- [ ] 4. 验证：`make test` 全绿；`cli_golden.py check` 输出 `all 48 cases identical`。`rich_workspace` 用例的 `runtime_built[0].system_prompt` 包含 AGENTS.md、技能和记忆三段，它是最直接的检验。
- [ ] 5. 提交：`refactor(cli): extract system prompt composition from _run`。开 PR，更新状态表。
