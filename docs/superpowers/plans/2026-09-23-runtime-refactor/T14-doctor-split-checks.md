# T14（可选）：拆分 `doctor._checks()`

> 总方案与全局规则：[README](README.md)。**本卡没有参考补丁**，需要手工完成，但结构很规整。依赖 T01 已合入，与 T02–T13 互不影响。

**目标：** `components/northstar-agent-runtime/doctor.py` 里的 `_checks()` 有 290 行，但它其实是 12 项互相独立的环境检查，每项前面都有一行 `# -- 名称 ----` 分节注释。本卡把每一节搬进一个 `_check_<名称>()` 函数，`_checks()` 只负责按顺序调用。行为不变：`northstar doctor` 的输出（包括顺序）逐字节相同。

**分支：** `refactor/T14-doctor-checks`

**要改的文件：** `components/northstar-agent-runtime/doctor.py`

## 已经核实过的结构

- 12 个分节依次是：python、optional SDKs、workspace、session dir、sidecar、OS sandbox、workspace policy file / agents / skills / context、skill supply chain、installed plugin bundles、provider/model pair、scripted script、model pricing；
- 除了最后的 `return findings`，中间没有提前 `return`；
- 分节之间只共享两个局部变量：
  - `workspace = Path(args.workspace)`：在 “workspace” 一节定义，被 “workspace policy file…”、“skill supply chain”、“installed plugin bundles” 三节使用；
  - `resolved_model`：在 “provider/model pair” 一节定义，被 “model pricing” 一节使用。

## 做法

1. 每一节变成一个函数，签名是 `def _check_<snake_name>(args: argparse.Namespace, findings: list[Finding]) -> None:`，函数体是该节原代码（缩进不变，因为 `_checks` 的函数体本来就是 4 格缩进）。分节注释改成 docstring。
2. 共享变量这样处理：
   - `workspace`：用到它的三个函数各自在开头写 `workspace = Path(args.workspace)`。这个计算没有副作用，重复计算不改变行为；
   - `resolved_model`：`_check_provider_model(args, findings) -> str` 返回它；`_check_pricing(args, findings, resolved_model: str) -> None` 接收它。
3. `_checks()` 改为：
   ```python
   def _checks(args: argparse.Namespace) -> list[Finding]:
       findings: list[Finding] = []
       _check_python(args, findings)
       _check_sdks(args, findings)
       _check_workspace(args, findings)
       _check_session_dir(args, findings)
       _check_sidecar(args, findings)
       _check_sandbox(args, findings)
       _check_workspace_config(args, findings)
       _check_skill_supply_chain(args, findings)
       _check_plugins(args, findings)
       resolved_model = _check_provider_model(args, findings)
       _check_scripted_script(args, findings)
       _check_pricing(args, findings, resolved_model)
       return findings
   ```
   **顺序必须与原分节顺序完全一致。**
4. 新函数都以下划线开头，不会进入 API 文档，不需要运行 `docbuild build`。

## 验证

在**改动前**记录几组 doctor 输出，改动后逐字节比较：

```sh
cd components/northstar-agent-runtime
for extra in "" "--provider openai" "--provider anthropic" "--session-dir /tmp/x" "--sandbox bwrap"; do
  python3 -m cli doctor --workspace ../../examples/demo/workspace $extra > /tmp/doctor-$(echo "$extra" | tr -c 'a-z' '_').before 2>&1; echo "exit=$?" >> /tmp/doctor-$(echo "$extra" | tr -c 'a-z' '_').before
done
cd -
```

改完后用同样的循环生成 `.after` 文件，再用 `diff` 比较每一对文件，必须没有差异。然后运行 `make test`（`test_cli` 里有 doctor 的测试），必须全绿。

## 步骤

- [ ] 1. 记录基线，包括上面的 doctor 输出。
- [ ] 2. 按“做法”完成改动。
- [ ] 3. 验证：doctor 输出无差异；`make test` 全绿；`_checks` 不超过 20 行。
- [ ] 4. 提交：`refactor(doctor): one function per environment check`。开 PR，更新状态表。
