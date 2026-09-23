# Sources

访问日期：2026-09-22。以下全部为 Stripe 官方公开文档（`docs.stripe.com`），未调用 API。

1. https://docs.stripe.com/payments/ach-direct-debit
   - ACH Direct Debit：delayed notification，成功/失败确认最多 4 个工作日；退款提交窗口 180 天、异步最多 3 个工作日、不可取消；退款为客户银行账户单独 credit；`refund.updated`/`refund.failed` 最终状态通知；mandate 授权与取消；ACH dispute final/no appeal；capture 逐项自动取消语义未陈述。
   - 访问日期：2026-09-22。
2. https://docs.stripe.com/payments/sepa-debit
   - SEPA mandate、delayed notification、失败通常 6 个工作日内/5 个工作日 refusal window、failure code/message、mandate cancellation；退款 3–4 个工作日处理、5 个工作日到账、180 天窗口；dispute final/no appeal；Manual capture support = No。
   - 访问日期：2026-09-22。
3. https://docs.stripe.com/payments/bacs-debit
   - Bacs DDI/mandate；已有 mandate 4 个工作日、新 mandate 7 个工作日确认；成功后仍可银行失败并成为 dispute；退款 180 天窗口、3–4 个工作日、scheme 外 Stripe 提供；processing 时退款待 Charge 成功，Charge 失败取消 pending refund；dispute 无限期且 final/no appeal；失败最多自动 retry 2 次、30 天内；capture 自动取消未明确。
   - 访问日期：2026-09-22。
4. https://docs.stripe.com/payments/ideal
   - iDEAL | Wero 银行跳转与二次认证；支付成功/失败即时通知；Manual capture support = No；退款 180 天内、pending 最多 7 天、无 failure signal 则 7 天后视为成功；后续失败处理未陈述。
   - 访问日期：2026-09-22。
5. https://docs.stripe.com/payments/konbini
   - Konbini 现金型支付；客户在便利店支付后收到完成通知；Manual capture support = No；支持 full/partial refunds，但客户须提供收款账户，Stripe 通过确认时 email 索取并自动处理；退款时限/失败语义未陈述。
   - 访问日期：2026-09-22。
6. https://docs.stripe.com/payments/klarna
   - Klarna：Manual capture support = Yes；退款 180 天内，通常 5–7 个工作日，取消剩余分期并退已付金额；支持 full/partial/multiple partial；已升级 dispute 的支付不支持退款；一般失败通知/最终性未陈述。
   - 访问日期：2026-09-22。
7. https://docs.stripe.com/payments/place-a-hold-on-a-payment-method
   - 通用 manual authorization/capture 说明；授权过期未 capture 时资金释放、支付变 canceled；表中特别说明 Klarna 某些授权：若大额需首付款，授权时收取并在未 capture 时退款，30 天内 capture balance；该页面未声明适用于全部 Klarna 配置。
   - 访问日期：2026-09-22。

## 访问与证据方法

以页面正文、payment-method properties 表格和退款/争议段落为准；搜索结果片段、第三方资料及 Stripe API 调用均未使用。官方表格没有给出逐项值处保持 unknown；本文件的摘要不替代逐字页面，具体 claim 与 caveat 见 `research-manifest.json`。
