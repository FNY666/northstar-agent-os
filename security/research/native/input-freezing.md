# 本地扫描输入冻结

## 目的与范围

`freeze_inputs.py` 只实现**本地、显式路径、字节级**的扫描输入视图：

```python
freeze_inputs(source_dir, output_dir, paths: list[str]) -> dict
```

它不执行候选项目代码，不接受 glob、include/exclude、配置文件、远程 URL、命令或附加参数，也不产生 Git 工作树已停止被外部写入者修改的证明。Git commit 的只读导出属于后续可选能力，本首版没有实现。

返回值为：

| 字段 | 含义 |
|---|---|
| `files` | 按相对路径字典序排列的描述列表；每项严格为 `path`、`sha256`、`bytes` |
| `manifest_sha256` | `sha(wire({"files": files}))`；`wire` 为项目既有确定性 JSON 编码 |
| `output_dir` | 成功原子发布后的输出目录绝对路径 |
| `input_bytes` | 相同已读取字节的相对路径→`bytes` 映射，供 `native_contract.validated_inputs` 之类的调用方核对 |

冻结输入树中**不写入 manifest 文件**，避免一个不在签名 scope 内的控制文件被扫描器当作候选输入。调用方需要持久化描述时，应在扫描输入树外保存返回值中的 `files` 和 `manifest_sha256`。

## 安全读取和发布规则

1. `paths` 必须是 1–128 个唯一、相对、无空组件、无 `.`/`..`/反斜杠/NUL 的路径；不接受目录路径。
2. 源目录、每一个中间目录和最终文件均使用目录 FD 加 `O_NOFOLLOW` 逐级打开。最终对象必须是 `st_nlink == 1` 的普通文件；符号链接、硬链接、FIFO、设备和目录均失败关闭。
3. 读取时逐文件最多 **64 MiB**、总计最多 **512 MiB**，并在读取前后比较 inode、link count、长度、mtime、ctime，检测普通的并发变更。所有字节在完成读取和校验后才开始发布。
4. 路径中含 `.env`/`.env.*`、常见私钥名或私钥后缀，或按保守基名规则识别为 credential/secret/password/token/API-key 的文件会被拒绝。该规则是防止误纳入凭据，不是秘密检测或 DLP 证明。
5. 输出通过同父目录私有 staging tree 写入，单文件 `fsync`，然后调用 Linux `renameat2(RENAME_NOREPLACE)` 发布。目标已存在（包括 file、directory、symlink）时拒绝且不覆盖；嵌套候选路径在 staging tree 内逐级创建。
6. 发布前文件会改为 `0400`、目录改为 `0500`。这是降低意外写入的访问模式，不是 WORM、不可变存储、快照或“工作树不再被写入”的证明。

若发布后的父目录 `fsync` 发生底层 I/O 错误，目录 rename 可能已经完成但持久化确认失败；调用方必须按失败处理且不得把此情况表述为已得到持久化保证。

## requirements 首版受限语法

`validate_requirements(raw) -> list[dict[str, str]]` 接受 UTF-8 `bytes` 或 `str`，返回按输入顺序的：

```python
[{"name": "Example_Pkg", "version": "1.2.3"}]
```

仅允许空行、以首字符 `#` 开始的整行注释，以及无前后空白的普通精确 pin：

```text
distribution-name==exact-version
```

distribution name 使用 ASCII 字母数字起始，后续只允许 ASCII 字母数字、`.`、`_`、`-`；version 只允许 ASCII 字母数字、`.`、`!`、`+`、`_`、`-`。规范化后重复的包名失败关闭。首版明确拒绝 extras、markers、URL/direct reference、editable/install options、`-r` include、constraints、hash options、内联注释和任何范围/比较运算符。

`freeze_inputs` 对基名为 `requirements.txt`、`requirements-*.txt` 或 `requirements_*.txt` 的已选文件，以及 `requirements/` 目录下的已选 `.txt` 文件自动调用该验证器；其它文件按显式字节输入处理。它不调用 pip，也不解析或执行项目元数据。

## 已覆盖的本地单元测试

`native_tests/test_freeze_inputs.py` 仅在 `TemporaryDirectory` 内构造正常与攻击 fixture，覆盖：

- 正常的嵌套精确复制、确定性 manifest 与只读模式；
- `..`、绝对路径、空路径组件、凭据名、symbolic link、hard link、FIFO 的拒绝；
- 精确 requirements pin 的正例，以及 extras、范围、marker、URL、include/constraint、内联注释和重复包名的拒绝；
- 不合法 requirements 发布前失败；
- 已存在输出目录绝不覆盖；
- 仅复制调用方指定的文件，并验证候选 Python 文件没有被执行。

这些单元测试不能证明真实扫描器、物理隔离、外部写入者停止、生产目录耐久性或凭据检测完整性；父任务仍需把返回的 `input_bytes` 与经签名 scan-plan 的 `expected_inputs` 做精确核对。
