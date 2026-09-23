# 下一独立切片派发记录

- 主题：Agent runtime 的 lease/租约过期、心跳与 fencing token：如何防止 Worker 重启后旧执行者继续写入。
- 公开对象候选：Temporal、Kubernetes Lease/Jobs、AWS Step Functions（只查官方文档/源码）。
- 重点：lease expiry 与实际停止差别；stale worker/split-brain；fencing/版本条件；恢复交接；人工介入。
- 不重复：本报告的取消/超时/幂等补偿主线。
- 安全边界：不访问私有账号、凭据、真实服务、共享目标，不读写任何禁止目录。
