# T02：修复 `--resume-from` 丢失策略文件上限的问题

> 总方案与全局规则：[README](README.md)。**这是唯一一张有意改变行为的卡。**全局规则第 3 条（“只移动，不改写”）在本卡不适用，但仍然只能改下面列出的三处代码。

**目标：** 从检查点分叉恢复（`--resume-from`）时，轮次上限和费用上限必须使用**经过策略文件和插件收紧后**的值，而不是命令行参数的原值。

**缺陷（已复现）：**

| # | 位置（`components/northstar-agent-runtime/cli.py`，`_run()` 内） | 现象 |
| --- | --- | --- |
| 1 | `config_kwargs["max_turns"] = max(args.max_turns, checkpoint.turns)` | 策略文件写 `max_turns = 1`，恢复后的运行照样执行了第 2 轮 |
| 2 | `resume_budget = _Budget(max_budget_usd=args.max_budget_usd, ...)` | 策略文件写 `max_budget_usd = 1.0`，父会话已花 6 美元，恢复后仍然继续生成（退出码 0 而不是 4） |
| 3 | `if args.checkpoint_turns and args.checkpoint_turns > args.max_turns:` | 策略文件把轮次压到 2 时，`--checkpoint-turns 5` 仍被接受，但永远写不出检查点 |

在 `_run()` 里，更早的位置已经用 `tighten()` 算出了局部变量 `max_turns` 和 `max_budget_usd`（搜索 `max_turns = tighten(` 可以找到）。修复方法就是在上面三处改用这两个局部变量。`max_turns` 总是整数，不会是 `None`。

**分支：** `refactor/T02-resume-ceilings`

**要改的文件：**
- `components/northstar-agent-runtime/cli.py`（只改上面三处）
- `components/northstar-agent-runtime/tests/test_checkpoints.py`（只新增测试）

## 步骤

- [ ] **1. 先记录基线**（见 README 全局规则第 2 条），包括 `cli_golden.py record /tmp/cli-golden.json`。

- [ ] **2. 先写回归测试，确认它们在旧代码上失败。** 在 `components/northstar-agent-runtime/tests/test_checkpoints.py` 中找到下面三行。它们是 `CliCheckpointTests.test_a_resumed_run_cannot_spend_a_second_budget` 的结尾，全文件只有一处：
  ```python
          self.assertEqual(code, 4, "error_max_budget_usd: the parent's spend carried over")
          self.assertIn("error_max_budget_usd", out)
          self.assertNotIn("one more thing", out)
  ```
  紧接其后，保持类内缩进（4 个空格），追加：
  ```python

      # --- policy-file ceilings must survive a checkpoint resume -----------------------
      # A policy file (and a plugin) may only tighten. A resume that rebuilt its ceilings from
      # the command-line values alone would silently loosen them, which is the exact failure
      # the tighten-only rule exists to prevent.

      _POLICY = 'schema_version = "northstar.policy.v1"\n'

      def _fork_parent(self, root: Path, sessions: Path, script_body: list[dict]) -> str:
          code, _, err = self.invoke(
              "run", "--workspace", str(root), "--session-dir", str(sessions),
              "--script", str(self._script(script_body)), "--checkpoint-turns", "1", "--prompt", "go",
          )
          self.assertEqual(code, 0, err)
          return next(path.name[: -len(".jsonl")] for path in sessions.glob("*.jsonl"))

      def test_a_policy_file_budget_still_binds_a_resumed_run(self):
          root = self.workspace({".northstar/config.toml": self._POLICY + "max_budget_usd = 1.0\n"})
          sessions = Path(self.temp_dir()) / "sessions"
          # The parent spends more than the policy's cap in its only turn; the cap is checked
          # before each generation, so the parent itself still ends normally.
          parent = self._fork_parent(root, sessions, [{"text": "costly", "usage": {"input_tokens": 2_000_000}}])
          code, out, err = self.invoke(
              "run", "--workspace", str(root), "--session-dir", str(sessions),
              "--script", str(self._script([{"text": "one more thing"}])),
              "--resume-from", parent, "--prompt", "continue",
          )
          self.assertEqual(code, 4, f"error_max_budget_usd expected; stdout={out!r} stderr={err!r}")
          self.assertNotIn("one more thing", out)

      def test_a_policy_file_turn_ceiling_still_binds_a_resumed_run(self):
          root = self.workspace({".northstar/config.toml": self._POLICY + "max_turns = 1\n"})
          sessions = Path(self.temp_dir()) / "sessions"
          parent = self._fork_parent(root, sessions, [{"text": "first answer"}])
          code, out, err = self.invoke(
              "run", "--workspace", str(root), "--session-dir", str(sessions),
              "--script", str(self._script([{"text": "one more thing"}])),
              "--resume-from", parent, "--prompt", "continue",
          )
          # The lineage already used its one turn: the resumed run may not start another.
          self.assertEqual(code, 2, f"error_max_turns expected; stdout={out!r} stderr={err!r}")
          self.assertNotIn("one more thing", out)

      def test_a_cadence_the_policy_ceiling_makes_unreachable_is_refused(self):
          root = self.workspace({".northstar/config.toml": self._POLICY + "max_turns = 2\n"})
          code, _, err = self.invoke(
              "run", "--workspace", str(root), "--checkpoint-turns", "5", "--prompt", "x", "--scripted-text", "y",
          )
          self.assertEqual(code, 64)
          self.assertIn("no checkpoint could ever be written", err)
  ```
  运行：
  ```sh
  cd components/northstar-agent-runtime/tests && python3 -m unittest test_checkpoints -k policy; cd -
  ```
  **必须看到 `FAILED (failures=3)`。** 失败信息应该分别是 `0 != 64`、`0 != 4`（stdout 里能看到 `one more thing` 和 `cost=$6.000000`）和 `0 != 2`。如果测试一开始就通过了，说明缺陷已被别人修复：停下来报告，不要继续。

- [ ] **3. 修复第 3 处（检查点频率校验）。** 在 `cli.py` 中找到：
  ```python
      if args.checkpoint_turns and args.checkpoint_turns > args.max_turns:
          # A cadence that can never fire would leave the operator believing the run
          # was resumable when no record was ever written.
          print(
              f"configuration error: --checkpoint-turns {args.checkpoint_turns} exceeds --max-turns {args.max_turns}, "
              "so no checkpoint could ever be written",
  ```
  替换为：
  ```python
      if args.checkpoint_turns and args.checkpoint_turns > max_turns:
          # A cadence that can never fire would leave the operator believing the run
          # was resumable when no record was ever written. Compared with the effective
          # ceiling (after the policy file and plugins tightened it), not the flag alone.
          print(
              f"configuration error: --checkpoint-turns {args.checkpoint_turns} exceeds the run's max_turns {max_turns}, "
              "so no checkpoint could ever be written",
  ```
  后面的 `file=sys.stderr,`、`)` 和 `return USAGE_ERROR` 保持不变。

- [ ] **4. 修复第 1 处（轮次上限）。** 找到这一行（全文件只有一处）：
  ```python
          config_kwargs["max_turns"] = max(args.max_turns, checkpoint.turns)
  ```
  替换为：
  ```python
          # Start from the tightened ceiling, never from the flag: a policy file or plugin
          # that lowered max_turns must keep binding the lineage after a resume.
          config_kwargs["max_turns"] = max(max_turns, checkpoint.turns)
  ```

- [ ] **5. 修复第 2 处（费用上限）。** 找到：
  ```python
          resume_budget = _Budget(
              max_budget_usd=args.max_budget_usd,
  ```
  把第二行改为 `            max_budget_usd=max_budget_usd,`，其余不变。

- [ ] **6. 验证。**
  ```sh
  cd components/northstar-agent-runtime/tests && python3 -m unittest test_checkpoints; cd -   # Ran 29 tests ... OK
  make test                                                                                    # 全绿；runtime 为 Ran 1297 tests
  python3 docs/superpowers/plans/2026-09-23-runtime-refactor/cli_golden.py check /tmp/cli-golden.json
  ```
  `cli_golden.py check` 在本卡**应该恰好报告 2 个用例变化**，最后一行是 `2 of 48 case(s) changed`：
  - `checkpoint_over_max`：stderr 从 `exceeds --max-turns 25` 变为 `exceeds the run's max_turns 25`；
  - `resume_from_checkpoint_policy`：`max_turns` 从 25 变为 3，`budget_max_usd` 从 `null` 变为 `0.5`，dry-run 输出中的 `max_turns=25` 变为 `max_turns=3`。

  如果还有其它用例变化，或者这两个用例的变化与上面描述不同，就停下来报告。

- [ ] **7. 提交并开 PR。** 分两个 commit：
  1. `test(runtime): policy-file ceilings must survive --resume-from`（只含新测试；这个 commit 上测试是红的，属于预期情况）
  2. `fix(runtime): resume from a checkpoint under the tightened ceilings, not the flags`

  PR 描述里写明：这是一次有意的行为修复；附上第 2 步的失败输出和第 6 步的通过输出；说明 `checkpoint_over_max` 的错误文字变了，如有脚本匹配旧文字需要更新。在 README 任务表中把 T02 标为已完成。

## 完成标准

- 三个新测试在修复前失败、修复后通过；
- `make test` 全绿；
- `cli_golden.py` 只有上面两个预期变化；
- **合入后，后续每张卡都要在新的 `main` 上重新 `record` 基线**（全局规则第 2 条本来就要求这样做）。
