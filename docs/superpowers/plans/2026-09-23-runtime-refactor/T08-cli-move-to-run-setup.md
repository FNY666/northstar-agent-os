# T08：把运行组装步骤移到新模块 `run_setup.py`

> 总方案与全局规则：[README](README.md)。参考补丁：[`patches/T08.patch`](patches/T08.patch)。依赖 T07 已合入。

**目标：** T04–T07 抽出的步骤里，与终端输出无关的部分搬到新模块 `components/northstar-agent-runtime/run_setup.py`，并去掉名字前的下划线，成为这个模块的公开 API。完成后：`cli.py` 从约 1,870 行降到约 1,380 行；“如何从标志、策略文件和插件组装一次运行”有了一个可以单独阅读、单独测试的地方；以后 `sdk.py` 也能复用它（见 T13）。行为完全不变。

**分支：** `refactor/T08-run-setup-module`

**要改的文件：**
- 新建 `components/northstar-agent-runtime/run_setup.py`
- `components/northstar-agent-runtime/cli.py`
- `components/northstar-agent-runtime/pyproject.toml`（登记新模块）
- `tests/docbuild.py`（登记新模块）
- `docs/api/northstar-agent-runtime.md`（重新生成）

## 搬移清单

按下表顺序，把这些定义从 `cli.py` **剪切**到 `run_setup.py`，并按“新名字”一列改名。每个定义上方紧挨着的 `#` / `#:` 注释行要一起搬走。

| `cli.py` 里的名字 | `run_setup.py` 里的名字 |
| --- | --- |
| `RunConfigurationError` | `RunConfigurationError` |
| `MUTATING_TOOLS`（连同上面两行 `#:` 注释） | `MUTATING_TOOLS` |
| `_tool_lists` | `tool_lists` |
| `checkpoint_usage` | `checkpoint_usage` |
| `_load_plugins` | `load_plugins` |
| `_load_workspace_agents` | `load_workspace_agents` |
| `_load_policy` | `load_policy` |
| `_HookSetup` | `HookSetup` |
| `_load_hooks` | `load_hooks` |
| `_load_postconditions` | `load_postconditions` |
| `_resolve_permission_mode` | `resolve_permission_mode` |
| `_resolve_tool_access` | `resolve_tool_access` |
| `_resolve_agent` | `resolve_agent` |
| `_tighten` | `tighten` |
| `_Ceilings` | `Ceilings` |
| `_resolve_ceilings` | `resolve_ceilings` |
| `_PromptSetup` | `PromptSetup` |
| `_compose_system_prompt` | `compose_system_prompt` |
| `_validate_session_flags` | `validate_session_flags` |
| `_SessionSetup` | `SessionSetup` |
| `_resolve_session` | `resolve_session` |

改名要同时改**定义处**和**所有引用处**，包括这些函数之间的互相调用（例如 `resolve_tool_access` 里调用 `tool_lists`，`resolve_ceilings` 里调用 `tighten`），以及类型注解（例如 `ceilings: Ceilings`）。

**留在 `cli.py` 不搬的**：`_read_prompt`（读 stdin/TTY）、`_resolve_mcp_servers`（依赖 `cli._mcp_launch`）、`_setup_notes`、`_stream_events`（终端输出），以及 T04 加的那段分节注释。

## `run_setup.py` 的文件头

```python
"""Assembling one governed run from its configuration sources, before anything runs.

``cli run`` (and anything else that starts a run from flags, a workspace policy file and
installed plugins) goes through the same steps, in this order:

1. load what the workspace declares - plugins, repository agents, the policy file, hooks,
   postconditions (``load_*``);
2. resolve what the run may do - permission mode, tool access, the agent it runs as, and
   its ceilings, where every source can only tighten (``resolve_*``, ``tighten``);
3. compose the system prompt in its fixed order (``compose_system_prompt``);
4. validate the session flags and resolve the session store, including a checkpoint
   resume that carries the parent's spend (``validate_session_flags``, ``resolve_session``).

Every step either returns what the next one needs or raises ``RunConfigurationError``
(a ``ValueError``), which the CLI reports as ``configuration error: ...`` with exit code 64.
Nothing here prints a configuration error, starts a provider, or connects to a server.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from typing import Any, Sequence
```

**`run_setup.py` 绝对不能 `import cli`**，否则会形成循环导入。上面的搬移清单已经把它需要的 `MUTATING_TOOLS`、`tool_lists`、`checkpoint_usage` 一起搬了过来。

## `cli.py` 的调整

1. 在 `from governance_bench import add_bench_arguments` 之后加：
   ```python
   from run_setup import (  # noqa: F401 - MUTATING_TOOLS and checkpoint_usage stay importable from cli
       MUTATING_TOOLS,
       HookSetup,
       PromptSetup,
       RunConfigurationError,
       checkpoint_usage,
       compose_system_prompt,
       load_hooks,
       load_plugins,
       load_policy,
       load_postconditions,
       load_workspace_agents,
       resolve_agent,
       resolve_ceilings,
       resolve_permission_mode,
       resolve_session,
       resolve_tool_access,
       validate_session_flags,
   )
   from run_setup import tool_lists as _tool_lists  # re-exported: tests import it from here
   ```
   保留 `_tool_lists`、`MUTATING_TOOLS`、`checkpoint_usage`、`RunConfigurationError` 从 `cli` 导入的能力：`tests/test_cli.py` 里有 `from cli import … _tool_lists …`，外部脚本也可能在用另外几个名字。
2. `_run()`、`_setup_notes()` 里对上表各名字的调用和注解，全部改用新名字（例如 `_load_plugins(` → `load_plugins(`，`hooks: _HookSetup` → `hooks: HookSetup`）。
3. 删除文件顶部的 `from dataclasses import dataclass`，`cli.py` 里已经没有 dataclass 了。

## 登记新模块（全局规则第 7 条）

- `components/northstar-agent-runtime/pyproject.toml`：在 `py-modules` 列表的 `"provider_retry",` 之后加 `"run_setup",`；
- `tests/docbuild.py`：在 `MANIFEST["northstar-agent-runtime"]` 的 `"provider_retry",` 之后加 `"run_setup",`；
- 运行 `python3 tests/docbuild.py build`，提交生成的 `docs/api/northstar-agent-runtime.md`。

## 步骤

- [ ] 1. 记录基线。
- [ ] 2. 应用 `patches/T08.patch`（它包含新文件 `run_setup.py`），失败时按上文手工完成。补丁不含 `docs/api/`，所以无论如何都要执行第 4 步。
- [ ] 3. 核对：
  ```sh
  cd components/northstar-agent-runtime
  grep -n "^import cli\|^from cli" run_setup.py                       # 应无输出
  grep -c "^def \|^class " run_setup.py                                # 参考实现为 20（MUTATING_TOOLS 是常量，不计入）
  python3 -c "import run_setup, cli; print(cli._tool_lists is run_setup.tool_lists)"   # True
  cd -
  ```
- [ ] 4. `python3 tests/docbuild.py build`
- [ ] 5. 验证：`make test` 全绿（`test_module_layout` 会检查打包登记，`test_docbuild` 会检查 API 文档）；`cli_golden.py check` 输出 `all 48 cases identical`；`make install-smoke` 通过（它会在干净的 venv 里安装并运行 `northstar`，能发现漏登记的模块；需要能访问 PyPI）。
- [ ] 6. 提交：`refactor(runtime): move run assembly steps into run_setup`。开 PR，更新状态表。

完成后，`cli._run()` 读起来就是一次运行的完整流程，每一步都有名字。T09–T12 转向 `loop.py`。
