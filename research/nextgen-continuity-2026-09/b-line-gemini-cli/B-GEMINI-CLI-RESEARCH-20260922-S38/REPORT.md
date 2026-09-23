# B-S38 Official — Gemini CLI Hooks 与 Policy Engine 的阻断、优先级和边界

- 研究日期：2026-09-22（Asia/Shanghai）。
- 主题：官方资料对 Hooks 与 Policy Engine 的同步执行、JSON/退出码、阻断语义、配置优先级、决策优先级、interactive/headless 边界和安全限制作了什么直接陈述？
- 范围：仅 Google Gemini CLI 官方仓库文档的只读快照与官方 raw URL 可访问性检查；未运行 CLI、未安装 hook/policy、未触碰真实服务或凭据。
- 本目录：`/tmp/B-GEMINI-CLI-RESEARCH-20260922-S38/`。

## 结论

1. **Hooks 是 agent loop 中的同步拦截点，但同步并不等于无限阻塞或成功保证。** 官方 index 说 CLI 会等待匹配 hooks 完成；hook event 覆盖 session、agent、model、tool、压缩和通知阶段。reference 规定 hook 可对若干阶段阻断、改写、隐藏结果或触发重试。[verified]
2. **Hook 的 stdout 是严格 JSON 通道。** 官方要求除最终 JSON 外不得向 stdout 输出普通文本；污染会导致解析失败，CLI 默认 Allow 并把整段输出当 systemMessage。stderr 用于日志/调试。退出码 0 解析 JSON；2 是 system block；其他非零码是 warning，交互继续并使用原参数。[verified]
3. **Hook 的阻断强度取决于事件与输出字段。** `decision=deny/block` 可在 BeforeTool、BeforeAgent、BeforeModel、AfterTool/AfterModel 等对应事件阻断或隐藏/拒绝；`continue=false` 是终止 agent loop 的不同语义。SessionStart、SessionEnd、Notification 是 advisory/observability 事件，不能用来授予权限或阻断。[verified]
4. **Hook 配置存在明确层级，项目高于用户、系统和扩展配置。** 官方列出的优先级为 Project > User > System > Extensions；不能从此推出所有重复 hook 的执行顺序、去重方式或最终合并结果。[verified/边界]
5. **Policy Engine 通过匹配条件、decision 和 priority 选择规则；`deny` 阻止工具，`ask_user` 在非交互模式按 deny 处理。** 对无 argsPattern 的全局 deny，工具从模型可见选项中排除；官方将 policy deny 推荐为替代旧 `tools.exclude`。[verified]
6. **Policy tier 和 TOML priority 分离。** 官方描述 tier base 与 priority 的组合，Admin 高于 User/Workspace/Default；但官方同时标出 Workspace policy 当前 non-functional，不能把文档中的理论层级当作该层当前运行效果。[verified + explicit unknown]
7. **Policy 不能证明外部副作用、完整审计、exactly-once、回滚或生产安全。** 本切片只核验官方规范文本，没有 CLI 运行、远端目标 read-back、攻击测试或部署验证。[unknown]

## 逐项证据

### S38-C1：Hooks 的同步生命周期与事件范围
- 状态：verified（官方文档直接陈述；非运行态验证）。
- 来源：`https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/index.md`；raw `https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/hooks/index.md`。
- 证据窗口：`index.md` lines 3–5、9–21、34–50；访问日期 2026-09-22；官方仓库快照 commit `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`。
- 能证明：hooks 是 CLI 在 agentic loop 特定点执行的脚本/程序；匹配 hooks 完成前 CLI 等待；事件和预期影响范围如官方表格所列。
- 不能证明：具体 hook 是否执行、实际耗时、并发/顺序、异常重试、外部状态变化或部署效果。

### S38-C2：stdout JSON、stderr 和 exit code
- 状态：verified。
- 来源同 S38-C1；`index.md` lines 52–79；raw URL 同上。
- 能证明：stdout 只应有最终 JSON；非 JSON 污染会导致解析失败并默认 Allow/systemMessage；exit 0、2、其他非零码的官方处理语义。
- 不能证明：所有版本/平台实现完全一致、脚本崩溃时所有边缘路径、默认 Allow 是否适合安全部署。

### S38-C3：事件级阻断与 advisory 边界
- 状态：verified。
- 来源：`https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md`；raw `https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/hooks/reference.md`。
- 证据窗口：`reference.md` lines 62–75、92–108、114–139、143–239、243–288；访问日期 2026-09-22。
- 能证明：decision、reason、tool_input 等字段及各事件的阻断/隐藏/重试/ advisory 语义；Notification 不能阻断 alert 或授予权限。
- 不能证明：阻断覆盖所有工具链、能阻止 hook 自身副作用、或能撤销已经发出的外部请求。

### S38-C4：Hooks 配置层级与风险
- 状态：verified as documented configuration; operational merge behavior otherwise unknown。
- 来源：`index.md` lines 92–136、138–162；raw `https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/hooks/index.md`；`best-practices.md` lines 397–450。
- 能证明：Project/User/System/Extensions 的文档优先级和官方 threat model；官方明确 hooks 以用户身份运行，任意代码执行/文件访问/网络请求等风险属于设计风险。
- 不能证明：某层一定覆盖/合并另一层的每个字段、权限沙箱、审计不可抵赖性或第三方 hook 安全。

### S38-C5：Policy decision、interactive/headless 和 deny 可见性
- 状态：verified。
- 来源：`https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md`；raw `https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/reference/policy-engine.md`。
- 证据窗口：`policy-engine.md` lines 39–65、67–123；访问日期 2026-09-22。
- 能证明：规则由条件/decision/priority 构成；allow 自动执行，deny 不执行且全局 deny 可让工具不再进入模型记忆，ask_user 在非交互模式按 deny 处理；deny 被推荐替代旧 exclude。
- 不能证明：策略配置已被加载、具体工具实际被阻断、调用前后目标状态、审计完整性或策略绕过不存在。

### S38-C6：Tier、priority、approval mode 与 Workspace 缺口
- 状态：verified for documentation; workspace runtime status explicitly documented as non-functional。
- 来源：同 S38-C5；`policy-engine.md` lines 125–202、220–280；GitHub issue `https://github.com/google-gemini/gemini-cli/issues/18186` 仅作为官方文档链接，不单独当作本切片运行证据。
- 能证明：官方给出 Default/Extension/Workspace/User/Admin tier、priority 计算和 approval mode 语义；文档警告 Workspace policy 当前 non-functional，并建议 User/Admin。
- 不能证明：当前未捕获的版本修复、企业部署实际配置、重复规则的所有 tie-break 行为或 policy 完整安全性。

## 总体边界

- `verified` 在本报告中表示官方原文直接支持该文档事实；不等于 CLI 本机运行验证。
- `inferred`：可合理推断 hook/policy 是控制平面而非目标系统事务；这不是官方对 exactly-once、回滚或外部效果的保证。
- `unknown`：真实安装/运行、权限配置、恶意 hook、崩溃恢复、并发、审计完整性、外部 read-back、生产安全和跨版本行为。
- 未使用第三方资料、搜索摘要或私有内容；未访问凭据、真实服务或受保护路径。
