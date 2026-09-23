# B-S50-OFFICIAL — Gemini CLI 身份认证、配额与模型路由边界

- 访问日期：2026-09-22
- 来源：Google Gemini CLI 官方 GitHub 文档，固定快照 `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`；只读。

## 结论

1. **verified**：官方支持 Google 登录、Gemini API key、Vertex AI 多种认证路径；headless 使用已有缓存凭据，否则需环境变量。官方明确要求把 API key 和 service-account key 当作敏感凭据保护。
2. **verified**：不同认证方式对应不同配额/计费/隐私条件；官方给出了按用户/日、按分钟与模型/账户差异的限制，并建议用 `/stats model` 查看会话用量与适用上限。
3. **verified**：模型路由默认启用；模型失败（如 quota/server error）时可触发 fallback，是否静默切换取决于失败类型和 policy，默认可能提示用户；批准后 fallback 作用于当前 turn。
4. **verified**：模型选择优先级为 `--model` → `GEMINI_MODEL` → `settings.json model.name` → local router（experimental）→ default `auto`；`/model` 或 `--model` 不覆盖 sub-agent 使用的模型。
5. **inferred**：模型 fallback/retry 能提高可用性，但会改变请求实际使用的模型与成本/隐私边界；它不是外部副作用幂等或业务提交证明。
6. **unknown**：配额耗尽、路由切换、认证过期或网络错误后的请求是否已被服务端接受、是否产生外部效果、是否重复执行、完整 usage 账单收敛，文档没有统一保证。

## 不能证明边界

- authentication success ≠ authorization for every model/resource；
- quota snapshot ≠ billing finality；
- fallback selection ≠ original request not accepted；
- exit/usage report ≠ server-side business commit；
- documented precedence ≠ every subprocess/sub-agent sharing the same model。

## 研究限制

未登录、未使用 API key/凭据、未调用真实模型或服务、未访问生产，未触碰 shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line、systemd。
