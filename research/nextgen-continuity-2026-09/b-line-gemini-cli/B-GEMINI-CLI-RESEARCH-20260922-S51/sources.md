# S51 sources

访问日期：2026-09-22；公开一手官方来源。

| ID | 完整官方 URL | 证据窗口 | 等级 | 不能证明 |
|---|---|---|---|---|
| S51-1 | https://github.com/google-gemini/gemini-cli/blob/main/docs/resources/tos-privacy.md | 按认证方式区分服务条款/隐私通知；usage statistics opt-out | verified | 逐事件数据流、运行时合规 |
| S51-2 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/telemetry.md | telemetry settings/env、云/本地 target、prompt logging、logs/metrics/traces 字段 | verified | 完整审计、exporter 投递、最终持久化 |
| S51-3 | https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/settings.md | user/workspace settings、workspace override、env override、security/billing/model/hooks/telemetry | verified | 所有子进程与外部服务一致应用 |

`verified`=官方原文直接给出；`inferred`=边界推导；`unknown`=没有统一保证。
