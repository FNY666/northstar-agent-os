# S13 下一窄范围独立切片

只查 Stripe 官方公开每个 payment method detail/terms/API reference；选 bank debit、bank redirect、voucher、BNPL 各 3–5 个代表方式，核实 refund、delayed failure、mandate/退回、processing 最终性与方式事件。未明示保持 unknown；不调用 API、不用凭据、不读既有产物。独立生成同样五件产物并验证。