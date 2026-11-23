# 安全合同 CI 入口

## 目的与边界

`.github/workflows/security-contract-tests.yml` 是**低权限回归入口**，用于在 `pull_request`、`push` 和 `merge_group` 上运行安全合同的本地单元测试。三个事件均没有 `paths` 或 `paths-ignore` 过滤，避免将其设为 required check 后因改动路径而被跳过。

该工作流不是扫描、签名、发布或部署管道：它不安装 Semgrep/OSV，不准备漏洞数据库，不调用真实原生工具，不产生或使用生产签名材料，也不上传或发布产物。`security/native_contract.py` 的闭合数据接口由单元测试覆盖；运行时执行和隔离字段仍只能由实际宿主监督器提供，不能由本工作流或扫描输出推断。

## 权限与供应链约束

工作流及唯一 job 均显式限定为：

```yaml
permissions:
  contents: read
```

它不请求 `id-token`，不引用 `secrets.*`，也没有发布、部署、证明或上传步骤。所有外部 GitHub Action 使用固定的已核验提交 SHA：

| 用途 | 固定引用 |
|---|---|
| 检出 | `actions/checkout@11d5960a326750d5838078e36cf38b85af677262` |
| Python | `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065` |

运行时为 Python **3.12**。编写时实际读取到本地已安装版本为 `pytest 9.1.1`，因此工作流明确安装 `pytest==9.1.1`，而非使用浮动版本。它还安装 `security/requirements.txt` 中已有的合同测试依赖；该 requirements 文件不包含扫描器、模型 SDK 或私钥。

## 测试选择与固定实验室

工作流先始终运行已有的 `security/tests`，再在 `security/native_tests` 存在时收集其 `test_*.py`。这使旧合同测试和后续各原生支线的合同单测进入同一个 pytest 调用，同时在本地攻击/防护实验室文件尚未合入时，不会以缺失路径造成错误或伪造成功。

固定实验室入口只能是仓库内、无参数的：

```text
security/run-native-security-lab.py
```

若该文件存在，工作流仅执行 `python security/run-native-security-lab.py`；不接受 URL、目标或附加命令。若尚未存在，工作流发出 GitHub notice，明确表示**只运行了已有合同单测**，并且**没有**声称 native scan、物理/进程隔离、网络拒绝或签名结果已经通过。该 notice 不是实验室通过的替代品。

## 静态回归护栏

`security/native_tests/test_ci_workflow.py` 只读取工作流文本并验证：

1. 三个 required-check 事件均存在且没有路径过滤；
2. 顶层与 job 层权限均只有 `contents: read`，且不存在 OIDC 或 secrets 引用；
3. 仅使用上述两个固定 SHA 的外部 Action；
4. Python 3.12、`pytest==9.1.1`、核心/原生单测目录与固定本地实验室入口均被明确指定；
5. 工作流没有网络下载命令、容器启动、签名、证明、发布、部署或 artifact 上传步骤。

该静态测试不运行任何扫描器、实验室、签名或其他支线文件，因此可由本支线独立执行。父任务仍须在真实工具、数据库与监督隔离准备就绪后，另行进行原生 smoke、扫描和证据验证。
