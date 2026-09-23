# T01：文档链接检查跳过 `research/`

> 总方案与全局规则：[README](README.md)。本卡只改测试工具，不碰任何组件代码。

**目标：** 让 `make test` 恢复全绿。当前 70 个仓库文档测试中有 1 个失败：
`test_docbuild.MarkdownLinkTests.test_all_internal_markdown_links_resolve`。它报告了 364 个失效链接，全部位于 `research/nextgen-continuity-2026-09/` 下。

**原因：** `research/` 目录保存的是第三方网页的原样抓取。里面的链接（例如 `/oss/python/langgraph/checkpointers`）指向原网站，而不是本仓库里的文件。`tests/docbuild.py` 的 `markdown_files()` 会扫描整个仓库的所有 `.md` 文件，所以把这些链接都当成了失效链接。快照内容不应修改，这个目录也不属于项目文档。

**分支：** `refactor/T01-link-check`

**要改的文件：**
- `tests/docbuild.py`
- `tests/test_docbuild.py`

**不要改：** `research/` 下的任何文件，以及任何组件代码。

## 步骤

- [ ] **1. 确认失败现状。** 运行下面的命令，应该看到 `FAILED (failures=1)`，而且失败的是上面那个测试：
  ```sh
  cd tests && python3 -m unittest discover -s . -p 'test_*.py' 2>&1 | tail -3; cd ..
  ```
  再运行这条命令，统计失效链接按顶层目录的分布。应该输出 `364 Counter({'research': 364})`。如果数字不同，或者出现了 `research` 以外的目录，就停下来报告：
  ```sh
  python3 -c "import sys, collections; sys.path.insert(0, 'tests'); import docbuild; b = docbuild.broken_links(); print(len(b), collections.Counter(x.split('/')[0] for x in b))"
  ```

- [ ] **2. 修改 `tests/docbuild.py`。** 找到下面这个函数（全文件只有一处）：
  ```python
  def markdown_files() -> list[Path]:
      return sorted(
          path
          for path in ROOT.rglob("*.md")
          if ".git" not in path.parts and "node_modules" not in path.parts
      )
  ```
  整体替换为：
  ```python
  # Top-level directories whose markdown is not this repository's documentation. `research/`
  # holds verbatim captures of third-party pages (their links point at the original sites, not
  # at files here), so checking them would report the source site's navigation as broken links.
  LINK_CHECK_EXCLUDED_ROOTS: frozenset[str] = frozenset({"research"})


  def markdown_files() -> list[Path]:
      return sorted(
          path
          for path in ROOT.rglob("*.md")
          if ".git" not in path.parts
          and "node_modules" not in path.parts
          and path.relative_to(ROOT).parts[0] not in LINK_CHECK_EXCLUDED_ROOTS
      )
  ```

- [ ] **3. 在 `tests/test_docbuild.py` 加一条测试，防止排除规则写得太宽。** 找到：
  ```python
  class MarkdownLinkTests(unittest.TestCase):
      def test_all_internal_markdown_links_resolve(self):
          broken = docbuild.broken_links()
          self.assertEqual(broken, [], "broken internal markdown links:\n  " + "\n  ".join(broken))
  ```
  在最后那行 `self.assertEqual(...)` 之后，保持类内缩进，追加：
  ```python

      def test_only_third_party_captures_are_excluded_from_the_link_check(self):
          checked = {path.relative_to(docbuild.ROOT).as_posix() for path in docbuild.markdown_files()}
          self.assertFalse(any(name.startswith("research/") for name in checked))
          # The exclusion must stay narrow: the project's own documentation is still checked.
          self.assertIn("README.md", checked)
          self.assertTrue(any(name.startswith("docs/") for name in checked))
          self.assertTrue(any(name.startswith("components/") for name in checked))
  ```

- [ ] **4. 验证。** 下面三条命令都要成功：
  ```sh
  python3 tests/docbuild.py verify          # 最后一行：documentation build OK (fresh + links resolve)
  (cd tests && python3 -m unittest discover -s . -p 'test_*.py')   # Ran 71 tests ... OK
  make test                                  # 所有组件 OK，最后的文档测试也 OK
  ```

- [ ] **5. 提交并开 PR。** 单个 commit，提交信息：`docs(test): skip research/ captures in the markdown link check`。PR 描述按 README 的模板填写，并在 README 的任务表中把 T01 的状态改为 `已完成（#PR 号）`。

## 完成标准

- `make test` 全绿（这是后续所有卡的前提）；
- `git diff --stat` 只涉及 `tests/docbuild.py`、`tests/test_docbuild.py` 和本方案的 README 状态表。
