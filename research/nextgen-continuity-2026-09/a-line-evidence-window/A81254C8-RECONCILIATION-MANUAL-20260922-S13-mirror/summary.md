# S13 摘要

## 结论

Stripe 官方公开文档显示，各支付方式在退款时限、失败延迟和最终性上不可互换：ACH/SEPA/Bacs 是延迟通知 bank debit；iDEAL 是即时通知的 bank redirect；Konbini 的退款依赖客户补充收款账户；Klarna 退款通常 5–7 个工作日且会取消剩余分期。

## 已确认的高价值差异

- **ACH**：成功/失败确认最多 4 个工作日；退款异步最多 3 个工作日、不可取消，失败会有 `refund.failed`，资金回 Stripe balance。
- **SEPA**：大多数失败在 6 个工作日内，5 个工作日 refusal window；退款通常 3–4 个工作日处理、5 个工作日到账。
- **Bacs**：已有 mandate 4 个工作日、新 mandate 最多 7 个工作日；成功标记后仍可能转为银行 dispute；processing 状态下原 Charge 失败会取消 pending refund。
- **iDEAL**：支付成功/失败即时通知；退款 pending 最多 7 天，无 failure signal 后视为成功；不支持 manual capture。
- **Konbini**：完成通知在客户便利店付款后触发；退款需要客户提供收款账户，时间和失败语义未公开。
- **Klarna**：退款通常 5–7 个工作日，取消剩余分期并退回已付金额；支持 manual capture，但仅在通用授权说明中对特定授权场景给出未 capture 退款/30 天 capture 条件。

## 不应过度推断

Direct-debit 的“dispute final/no appeal”是争议流程最终性，不是所有支付成功后绝对不可逆。官方没有说出的退款失败、最终性或 capture 自动取消行为保持 unknown。

完整逐方式矩阵与来源 URL 见 `report.md`、`sources.md`；可审计 claims 见 `research-manifest.json`。
