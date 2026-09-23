# S19 summary

S19 固化了 QUERY_GAP、RETENTION_EXPIRED、DELAYED 与 NO_EVENT 的互斥门：空结果只有在查询完整、窗口仍可见、无分页/权限/版本错误时才可判 NO_EVENT；否则保持 QUERY_GAP/UNKNOWN。`VERIFIED_CONTINUITY` 必须由完整查询、原始证据摘要和独立 postcondition 共同支持。
