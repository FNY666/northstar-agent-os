# B-S47-OFFICIAL — Gemini CLI 官方评测/集成测试与证据边界

- 访问日期：2026-09-22
- 范围：Google Gemini CLI 官方 GitHub 仓库公开文档；只读。
- 快照：`/tmp/B-GEMINI-CLI-OFFICIAL-20260922-S36/repo`，提交 `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`。

## 结论

1. **verified**：官方 behavioral eval 以 agent 行为为断言对象（工具调用、顺序、避免破坏性命令），而不是最终 prose；官方说明模型文本具有非确定性，因此精确文本匹配脆弱。
2. **verified**：eval validator 要求静态元数据、有效 policy、非空 prompt、工具引用合法、至少一个工具调用断言、workspace 文件声明等；错误阻断 CI 并返回 1，部分 warning 不阻断。
3. **verified**：官方要求新 behavioral eval 本地至少运行 3 次去抖；新 integration test 至少运行 5 次去抖；integration suite 必须显式运行，不属于默认 `npm run test`。
4. **verified**：integration 测试可覆盖 no sandbox/docker/podman 矩阵；memory/performance 测试有独立入口和 baseline/tolerance 机制。
5. **inferred**：这些门禁能提高行为回归、重复性和安全边界的可观察性，但不能把测试通过提升为所有部署、所有模型、生产外部效果已验证。
6. **unknown**：官方这些文档不证明 exactly-once、副作用提交、超时/断连后状态、完整审计、生产流量成功或测试环境与生产环境等价。

## 证据窗口与不能证明边界

### `docs/behavioral-evals.md`
- 证据窗口：behavioral eval 定义、EDK inventory/validate/report、校验规则、贡献者流程、去抖次数、断言方式与工作区边界。
- 不能证明：任何单次 eval 的外部业务效果、真实生产环境安全、所有模型均通过、工具副作用恰好一次。

### `docs/integration-tests.md`
- 证据窗口：bundle 前置、显式 integration 命令、单测筛选、golden 重新生成警告、5 次 deflake、sandbox 矩阵、memory/performance baseline 与诊断输出。
- 不能证明：CI/本地通过等于生产通过；golden、baseline 或 test artifact 不能单独证明外部状态已经提交。

## 可迁移判定

测试证据至少拆为：测试定义/静态校验、运行回执、目标 read-back、独立业务不变量。缺目标 read-back 或发生 timeout/disconnect 时，外部效果保持 `UNKNOWN_NEEDS_RECONCILE`，禁止仅凭 test pass 或日志存在判定已提交。

## 研究限制

未运行 Gemini CLI、未访问真实服务、未使用凭据、未触碰 shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line、systemd 或真实生产。
