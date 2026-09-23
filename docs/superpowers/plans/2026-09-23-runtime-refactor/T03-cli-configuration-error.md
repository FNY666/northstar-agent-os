# T03：`cli._run()` 引入 `RunConfigurationError`

> 总方案与全局规则：[README](README.md)。参考补丁：[`patches/T03.patch`](patches/T03.patch)。

**目标：** `_run()` 里有 23 处相同的模式：先 `print("configuration error: …", file=sys.stderr)`，再 `return USAGE_ERROR`。这是 `_run()` 无法拆分的主要原因，因为任何子步骤都需要能“提前退出”。本卡把这 23 处改成 `raise RunConfigurationError("…")`，**输出逐字节不变**。

**为什么输出不会变：** `main()` 已经这样处理 `_run()` 抛出的 `ValueError`：

```python
    try:
        return _run(args)
    except ValueError as error:
        print(f"configuration error: {error}", file=sys.stderr)
        return USAGE_ERROR
```

`RunConfigurationError` 继承 `ValueError`，消息里**不带** `configuration error: ` 前缀，由 `main()` 统一补上。所以 stderr 文本和退出码 64 都与原来完全相同。

**分支：** `refactor/T03-cli-configuration-error`

**要改的文件：** `components/northstar-agent-runtime/cli.py`，以及重新生成的 `docs/api/northstar-agent-runtime.md`。

## 步骤

- [ ] **1. 记录基线**（README 全局规则第 2 条），并先运行一次第 5 步里的“插件被阻止”脚本，记下它的 md5。

- [ ] **2. 应用参考补丁：**
  ```sh
  git apply --check docs/superpowers/plans/2026-09-23-runtime-refactor/patches/T03.patch && \
  git apply docs/superpowers/plans/2026-09-23-runtime-refactor/patches/T03.patch
  ```
  如果 `--check` 失败，说明 `main` 上的 `cli.py` 在 T02 之后被改过。先试 `git apply -3 <补丁>`；如果仍然失败，就按第 3 步手工完成。

- [ ] **3. 核对改动（用补丁也要逐条核对）。** `git diff` 应该恰好做了下面这些事，没有别的改动：
  1. 在 `USAGE_ERROR = 64` 下面新增：
     ```python
     class RunConfigurationError(ValueError):
         """A run cannot start because its configuration is invalid.

         ``main()`` already turns every ``ValueError`` escaping ``_run()`` into
         ``configuration error: <message>`` on stderr and exit code 64 (``USAGE_ERROR``), so
         raising this is byte-for-byte the same as printing that line and returning 64 - but it
         lets the steps of ``_run()`` live in their own functions. The message never repeats the
         ``configuration error:`` prefix; ``main()`` adds it.
         """
     ```
  2. `_run()` 里每一处“打印 `configuration error: …` 再 `return USAGE_ERROR`”都按下面三条规则改写：
     - 在 `except X as error:` 里打印的是 `f"configuration error: {error}"` → 改为 `raise RunConfigurationError(str(error)) from error`；
     - 消息里还有别的文字并引用了 `{error}` → 去掉 `configuration error: ` 前缀，保留其余文字，末尾加 ` from error`。例如：`raise RunConfigurationError(f"cannot resume from {args.resume_from!r}: {error}") from error`；
     - 普通消息 → 去掉 `configuration error: ` 前缀，同时删掉 `file=sys.stderr` 参数和紧随其后的 `return USAGE_ERROR`。多行字符串的其它行一字不改。
  3. **一处特殊情况：插件被阻止。** 原代码连续打印两次再返回，要合并成一个异常。第二次打印的内容前面加 `\n` 接到消息末尾：
     ```python
         if plugins.blocked:
             raise RunConfigurationError(
                 "installed plugins are not loadable:\n  - "
                 + "\n  - ".join(str(item) for item in plugins.blocked)
                 + f"\n  run `python3 -m cli plugin verify --workspace {args.workspace}` to see the reviewed set, "
                 "and `plugin list` to see what is installed"
             )
     ```
  4. **下面三处保持不变**：它们的输出没有 `configuration error:` 前缀，不能交给 `main()`。
     - `"no prompt: pass a task string, …"` 的打印加返回；
     - `--probe-sidecar` 分支里的 `print(message, file=sys.stderr)` 加返回；
     - `print("--probe-sidecar needs --sidecar-socket", file=sys.stderr)` 加返回。
  5. 原有的 `raise ValueError(...)`（未知 agent，以及 `--mcp-server` 与 `--agent` 同时使用）不改。

  自查命令（在 `components/northstar-agent-runtime/` 下运行）：
  ```sh
  awk '/^def _run\(/,/^def _print_event/' cli.py | grep -c 'return USAGE_ERROR'             # 应为 3
  awk '/^def _run\(/,/^def _print_event/' cli.py | grep -c 'print(.*configuration error'    # 应为 0
  awk '/^def _run\(/,/^def _print_event/' cli.py | grep -c 'raise RunConfigurationError'    # 应为 23
  ```

- [ ] **4. 重新生成 API 文档**（`RunConfigurationError` 是公开类）：`python3 tests/docbuild.py build`

- [ ] **5. 验证：** `make test` 全绿；`cli_golden.py check` 输出 `all 48 cases identical`。
  插件被阻止的路径不在快照里，可以用下面的脚本在改动前后各跑一次，两次的 md5 必须相同：
  ```sh
  cd components/northstar-agent-runtime && python3 - <<'EOF' | md5sum
  import io, contextlib, sys
  import plugin_load
  class C: blocked = ["a: invalid - bad", "b: missing"]; notes = []
  plugin_load.load_contributions = lambda *a, **k: C()
  import cli
  err = io.StringIO()
  with contextlib.redirect_stderr(err):
      code = cli.main(["run", "--workspace", "/tmp", "--prompt", "x", "--scripted-text", "y", "--dry-run"])
  sys.stdout.write(repr(code) + "\n" + err.getvalue())
  EOF
  cd -
  ```

- [ ] **6. 提交**：一个 commit，`refactor(cli): raise RunConfigurationError instead of print-and-return in _run`。按模板开 PR，并更新 README 状态表。
