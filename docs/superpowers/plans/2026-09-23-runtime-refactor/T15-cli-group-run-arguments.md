# T15（可选）：按主题拆分 `cli._add_run_arguments()`

> 总方案与全局规则：[README](README.md)。**本卡没有参考补丁**，需要手工完成。依赖 T08 已合入。

**目标：** `_add_run_arguments()` 是一个 225 行的函数，里面是约 70 个 `parser.add_argument(...)` 调用。本卡按主题把它拆成几个 `_add_<主题>_arguments(parser)` 函数，`_add_run_arguments()` 只负责按顺序调用它们。**argparse 解析树和 `--help` 输出必须逐字节不变。**

**分支：** `refactor/T15-cli-run-arguments`

**要改的文件：** `components/northstar-agent-runtime/cli.py`

## 为什么这件事可以安全地做

- argparse 的参数顺序就是 `add_argument` 的调用顺序。只要按原顺序切成连续的几段，再按原顺序调用，解析树就完全相同；
- `tests/test_typescript_sdk.py` 会从实时的 argparse 树读出 `run` 的全部参数，与 TypeScript 端的镜像逐一比对。参数有任何增减或改名，这个测试都会失败。

## 做法

1. 通读 `_add_run_arguments()`，按主题把**连续的**一段 `add_argument` 划成一组。建议的主题是：提示词与 provider/模型、上限与重试、工作区与权限、agent 与委托、工作区内容（策略文件、技能、记忆、插件、钩子、上下文）、MCP、sidecar 与沙箱、输出、会话与检查点、dry-run。**不允许为了归类而调换任何两个 `add_argument` 的先后顺序。** 如果某个主题的参数在原代码里是分散的，就把它们分到相邻的几组，而不是挪到一起。
2. 每组变成一个 `def _add_<主题>_arguments(parser: argparse.ArgumentParser) -> None:`，函数体逐字复制那一段。段落之间原有的注释跟着代码走。
3. `_add_run_arguments(parser)` 的函数体改为按原顺序调用这些函数。
4. 如果原函数里有局部变量跨段使用（例如先定义一个默认值，后面几个参数都用它），那么这些段必须放进同一组，或者把该变量作为参数传递。可以先用 `grep` 检查函数内所有 `=` 赋值语句。

## 验证

改动前后各运行一次下面的命令，输出必须逐字节相同：

```sh
cd components/northstar-agent-runtime
COLUMNS=100 python3 -m cli run --help > /tmp/run-help.before     # 改动前
COLUMNS=100 python3 -m cli run --help > /tmp/run-help.after      # 改动后
diff /tmp/run-help.before /tmp/run-help.after && echo "help identical"
python3 -c "
import cli
p = cli.build_parser()
sub = next(a for a in p._actions if a.__class__.__name__ == '_SubParsersAction').choices['run']
print([(a.dest, a.option_strings, a.default, a.type.__name__ if callable(a.type) else a.type, a.choices, a.nargs, a.required) for a in sub._actions])
" > /tmp/run-tree.after   # 改动前也生成一份 run-tree.before，然后 diff
cd -
```

然后运行 `make test`（包括 `tests/test_typescript_sdk.py` 的镜像检查）和 `cli_golden.py check`，都必须通过。

## 步骤

- [ ] 1. 记录基线，包括上面的 help 输出和解析树。
- [ ] 2. 按“做法”完成改动。
- [ ] 3. 验证：help 输出和解析树均无差异；`make test` 全绿；`cli_golden.py check` 一致；`_add_run_arguments` 不超过 20 行。
- [ ] 4. 提交：`refactor(cli): group run arguments by topic`。开 PR，更新状态表。
