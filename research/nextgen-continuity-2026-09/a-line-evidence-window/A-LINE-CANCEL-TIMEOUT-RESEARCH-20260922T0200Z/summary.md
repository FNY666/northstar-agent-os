# 摘要

取消、超时、断连和恢复窗口都可能留下“外部动作已发生但平台未收到结果”的不确定状态。默认不得把 timeout/cancel/retry success 当作 NOT_EXECUTED 或唯一成功证明。

推荐：稳定 operation_id/idempotency key；目标侧 read-back/reconcile；已确认完成则收敛 VERIFIED_DONE；确认未完成且可幂等才重试；目标不可查询或状态矛盾则 UNKNOWN/HUMAN_REVIEW；补偿必须是目标支持的、可验证且自身幂等的逆操作。

本片只使用公开官方资料，未使用 benchmark 证明 production。
