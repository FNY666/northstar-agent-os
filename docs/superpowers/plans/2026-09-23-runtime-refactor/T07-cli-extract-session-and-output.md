# T07：`cli._run()` 抽出会话、dry-run 说明和事件输出

> 总方案与全局规则：[README](README.md)。参考补丁：[`patches/T07.patch`](patches/T07.patch)。依赖 T06 已合入。

**目标：** 把 `_run()` 剩下的四大块搬走：会话参数校验、会话解析（含检查点恢复）、dry-run 说明文字、事件流输出。完成后 `_run()` 约 155 行，其中约 40 行是 `config_kwargs` 字典，读起来就是一份按顺序排列的步骤清单。行为完全不变。

**分支：** `refactor/T07-cli-session-output`

**要改的文件：** `components/northstar-agent-runtime/cli.py`

## 新函数

放在 `def _run(` 之前、T06 新增的函数之后：

| 新函数 | 原代码起点（含） | 原代码终点（不含） | 说明 |
| --- | --- | --- | --- |
| `_validate_session_flags(args, ceilings: _Ceilings) -> None` | `    if args.checkpoint_turns < 0:` | `    from budget import Budget as _Budget` | 纯校验，出错时 raise |
| `_SessionSetup`（冻结 dataclass） | — | — | 字段：`store: Any`、`resume_budget: Any`、`config_updates: dict[str, Any]` |
| `_resolve_session(args, ceilings: _Ceilings) -> _SessionSetup` | `    from budget import Budget as _Budget` | `    try:\n        config = RuntimeConfig(**config_kwargs)` | 函数开头新建局部变量 `config_kwargs: dict[str, Any] = {}`，原代码里写入 `config_kwargs[...]` 的语句一字不改。`from sessions import SessionStore` 搬进函数。最后 `return _SessionSetup(store=store, resume_budget=resume_budget, config_updates=config_kwargs)` |
| `_setup_notes(args, *, policy, prompt_setup, workspace_agents, hooks, plugins, mcp_servers, mcp_report) -> dict[str, str]` | `    if args.no_policy_file:\n        policy_note = ` | `    provider = _build_provider(args)` | 函数开头 `context = prompt_setup.context`、`skills = prompt_setup.skills`。返回字典的 8 个键正好是 `_print_dry_run()` 的 8 个关键字参数：`policy_note`、`hooks_note`、`context_note`、`memory_note`（取 `prompt_setup.memory_note`）、`workspace_agents_note`、`skills_note`、`plugin_note`、`mcp_note` |
| `_stream_events(args, runtime, store, prompt) -> int` | `        if args.resume_from:\n            resume = store.transcript(` | `    finally:` | 原来是 `try:` 块的内容，缩进减一级；最后的 `return exit_code` 保留 |

## `_run()` 里的替换

1. 会话部分：从 `    if args.checkpoint_turns < 0:` 开始，到 `    try:` / `        config = RuntimeConfig(**config_kwargs)` 之前结束，替换为：
   ```python
       _validate_session_flags(args, ceilings)
       session = _resolve_session(args, ceilings)
       config_kwargs.update(session.config_updates)
   ```
2. 说明部分：从 `    if args.no_policy_file:` 开始，到 `    provider = _build_provider(args)` 之前结束，替换为：
   ```python
       notes = _setup_notes(
           args,
           policy=policy,
           prompt_setup=prompt_setup,
           workspace_agents=workspace_agents,
           hooks=hooks,
           plugins=plugins,
           mcp_servers=mcp_servers,
           mcp_report=mcp_report,
       )

   ```
3. 删除 T06 留下的三行临时变量：`context = prompt_setup.context`、`skills = prompt_setup.skills`、`memory_note = prompt_setup.memory_note`（连同它们后面的空行）。
4. `AgentRuntime(...)` 里的 `sessions=store` 改为 `sessions=session.store`，`budget=resume_budget` 改为 `budget=session.resume_budget`。
5. dry-run 分支里 10 行的 `_print_dry_run(args, runtime, policy_note=…, …, mcp_note=mcp_note,)` 改为一行：`return _print_dry_run(args, runtime, **notes)`。
6. 最后的 `try:` 块改为：
   ```python
       try:
           return _stream_events(args, runtime, session.store, prompt)
       finally:
           for client in mcp_clients:
               client.close()
   ```
7. 删除 `_run()` 顶部的 `from sessions import SessionStore`。

**为什么顺序不能调整：** `_setup_notes` 仍然放在构建 provider **之前**，`_validate_session_flags` 仍然放在提示词拼接**之后**。多个错误同时存在时，先报哪一个取决于这个顺序。把参数校验提前会更合理，但那属于行为变化，不在本卡范围内。如果你认为值得做，写进 PR 的“发现的问题”一节。

## 步骤

- [ ] 1. 记录基线。
- [ ] 2. 应用 `patches/T07.patch`，失败时按上文手工完成。
- [ ] 3. 核对：`_run()` 约 155 行（`awk '/^def _run\(/,/^def _print_event/' cli.py | wc -l` 在参考实现里是 156）；`_run()` 里不再出现 `SessionStore`、`policy_note =`、`stream_open`。
- [ ] 4. 验证：`make test` 全绿；`cli_golden.py check` 输出 `all 48 cases identical`。重点看所有 `resume_*`、`real_run_*` 和 `dry_run_*` 用例。
- [ ] 5. 提交：`refactor(cli): extract session resolution, dry-run notes and event output from _run`。开 PR，更新状态表。
